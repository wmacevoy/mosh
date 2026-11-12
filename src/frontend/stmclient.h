/*
    Mosh: the mobile shell
    Copyright 2012 Keith Winstein

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations including
    the two.

    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do
    so, delete this exception statement from your version. If you delete
    this exception statement from all source files in the program, then
    also delete it here.
*/

#ifndef STM_CLIENT_HPP
#define STM_CLIENT_HPP

#include <memory>
#include <string>

#include <sys/ioctl.h>
#include <termios.h>

#include "src/frontend/terminaloverlay.h"
#include "src/network/networktransport.h"
#include "src/statesync/completeterminal.h"
#include "src/network/forwarding.h"
#include "src/statesync/user.h"

class STMClient
{
private:
  std::string ip;
  std::string port;
  std::string key;

  int escape_key;
  int escape_pass_key;
  int escape_pass_key2;
  bool escape_requires_lf;
  std::wstring escape_key_help;

  struct termios saved_termios, raw_termios;

  struct winsize window_size;

  Terminal::Framebuffer local_framebuffer, new_state;
  Overlay::OverlayManager overlays;
  using NetworkType = Network::Transport<Network::UserStream, Terminal::Complete>;
  using NetworkPointer = std::shared_ptr<NetworkType>;
  NetworkPointer network;
  Terminal::Display display;

  std::vector<std::string> udp_forwards, udp_remote_forwards, tcp_forwards, tcp_remote_forwards;
  std::string fragment_parity;
  std::unique_ptr<Network::Forwarding> forwarder;

  std::wstring connecting_notification;
  bool repaint_requested, lf_entered, quit_sequence_started;
  bool clean_shutdown;
  unsigned int verbose;

  /* No terminal: just hold the session and its forwards open, like "ssh -N". */
  bool headless;
  bool announced;

  /* a stream between a process here and one at the server (streamchild.h) */
  std::vector<std::string> stream_words;
  pid_t stream_pid;      /* 0 before it starts, -1 once it has finished */
  int stream_status;     /* how it finished */
  uint64_t stream_ended; /* when */
  void tend_stream( void );

  /* Reaching the server through ssh when UDP will not get there (see src/network/relay.h). */
  enum RelayMode
  {
    RELAY_NEVER,
    RELAY_AUTO,  /* when nothing is heard from the server */
    RELAY_ALWAYS /* from the start, and nothing by UDP */
  };
  RelayMode relay_mode;
  std::vector<std::string> relay_command;
  bool relay_engaged;
  int relay_keep_alive;
  uint64_t started_at;

  void engage_relay( void );
  void consider_relay( void );

  void main_init( void );
  void process_network_input( void );
  bool process_user_input( int fd );
  bool process_resize( void );

  void output_new_frame( void );

  bool still_connecting( void ) const
  {
    /* Initially, network == NULL */
    return network && ( network->get_remote_state_num() == 0 );
  }

  void resume( void ); /* restore state after SIGCONT */

public:
  STMClient( const char* s_ip,
             const char* s_port,
             const char* s_key,
             const char* predict_mode,
             unsigned int s_verbose,
             const char* predict_overwrite,
             const std::vector<std::string>& s_udp_forwards = std::vector<std::string>(),
             const std::vector<std::string>& s_tcp_forwards = std::vector<std::string>(),
             const std::string& s_fragment_parity = "auto",
             const std::vector<std::string>& s_tcp_remote_forwards = std::vector<std::string>(),
             const std::vector<std::string>& s_udp_remote_forwards = std::vector<std::string>(),
             bool s_headless = false )
    : ip( s_ip ? s_ip : "" ), port( s_port ? s_port : "" ), key( s_key ? s_key : "" ), escape_key( 0x1E ),
      escape_pass_key( '^' ), escape_pass_key2( '^' ), escape_requires_lf( false ), escape_key_help( L"?" ),
      saved_termios(), raw_termios(), window_size(), local_framebuffer( 1, 1 ), new_state( 1, 1 ), overlays(),
      network(), display( !s_headless ) /* use TERM environment var to initialize display */,
      udp_forwards( s_udp_forwards ), udp_remote_forwards( s_udp_remote_forwards ),
      tcp_forwards( s_tcp_forwards ),
      tcp_remote_forwards( s_tcp_remote_forwards ),
      fragment_parity( s_fragment_parity ), forwarder(),
      connecting_notification(),
      repaint_requested( false ), lf_entered( false ), quit_sequence_started( false ), clean_shutdown( false ),
      verbose( s_verbose ), headless( s_headless ), announced( false ), stream_words(), stream_pid( 0 ),
      stream_status( 1 ), stream_ended( 0 ),
      relay_mode( RELAY_NEVER ), relay_command(), relay_engaged( false ), relay_keep_alive( -1 ), started_at( 0 )
  {
    if ( predict_mode ) {
      if ( !strcmp( predict_mode, "always" ) ) {
        overlays.get_prediction_engine().set_display_preference( Overlay::PredictionEngine::Always );
      } else if ( !strcmp( predict_mode, "never" ) ) {
        overlays.get_prediction_engine().set_display_preference( Overlay::PredictionEngine::Never );
      } else if ( !strcmp( predict_mode, "adaptive" ) ) {
        overlays.get_prediction_engine().set_display_preference( Overlay::PredictionEngine::Adaptive );
      } else if ( !strcmp( predict_mode, "experimental" ) ) {
        overlays.get_prediction_engine().set_display_preference( Overlay::PredictionEngine::Experimental );
      } else {
        fprintf( stderr, "Unknown prediction mode %s.\n", predict_mode );
        exit( 1 );
      }
    }
    if ( predict_overwrite && !strcmp( predict_overwrite, "yes" ) ) {
      overlays.get_prediction_engine().set_predict_overwrite( true );
    }
  }

  void init( void );
  void shutdown( void );
  bool main( void );

  /*
   * How to get to the server when UDP does not: "command" starts the
   * remote relay (typically through ssh), and "mode" is "auto" to use
   * it when the server cannot be heard, or "always".
   */
  /* The session is for a stream between this process and one the server starts.  (Needs headless.) */
  void set_stream( const std::vector<std::string>& words ) { stream_words = words; }
  /* How the process at this end of the stream finished, as an exit status; 1 if it never ran. */
  int stream_exit_status( void ) const { return stream_pid == -1 ? stream_status : 1; }

  void set_relay( const std::string& mode, const std::vector<std::string>& command )
  {
    relay_command = command;
    relay_mode = command.empty() ? RELAY_NEVER : ( mode == "always" ? RELAY_ALWAYS : RELAY_AUTO );
  }

  /* unused */
  STMClient( const STMClient& );
  STMClient& operator=( const STMClient& );
};

#endif
