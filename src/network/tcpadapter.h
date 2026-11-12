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

#ifndef TCPADAPTER_HPP
#define TCPADAPTER_HPP

#include <cstdint>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "src/crypto/prng.h"
#include "src/network/tcpforward.h"

/*
 * The socket adapter: a SegmentPort for when there is no TUN device.
 *
 * Without a TUN device the kernel will not give us TCP segments, only
 * byte streams.  So this is a TCP endpoint of our own, just enough of
 * one to be a correct peer for a real TCP (or for another adapter) at
 * the far end of the tunnel, joined back to back with an ordinary
 * socket on this machine:
 *
 *   application <-- kernel TCP --> socket | AdapterPort <== segments ==> other end
 *
 * On the client it listens, and opens a connection through the tunnel
 * for each one it accepts.  On the server it answers a SYN from the
 * tunnel by connecting to the forward's target, and completes the
 * handshake only if that works (a refused connection is refused all the
 * way back to the application).
 *
 * What it does: the three-way handshake in both roles, cumulative
 * acknowledgment, reassembly of segments that arrive out of order,
 * retransmission with an adaptive, backed-off timeout (RFC 6298), fast
 * retransmit and recovery (NewReno, RFC 6582), slow start and
 * congestion avoidance, flow control in both directions including
 * zero-window probes, independent half-close of each direction, and
 * resets.
 *
 * What it leaves out, which costs speed but not correctness: selective
 * acknowledgment, window scaling, timestamps, delayed acknowledgments
 * and urgent data.
 */

namespace Network {

class AdapterPort : public SegmentPort
{
public:
  static constexpr size_t MAX_CONNECTIONS = 64;
  static constexpr size_t SEND_BUFFER = 256 * 1024;
  static constexpr size_t RECV_BUFFER = 256 * 1024;

  static constexpr uint32_t DEFAULT_MSS = 536;
  static constexpr uint32_t INITIAL_WINDOW_SEGMENTS = 10;

  static constexpr uint32_t RTO_INITIAL = 1000; /* ms */
  static constexpr uint32_t RTO_MIN = 200;
  static constexpr uint32_t RTO_MAX = 30000;
  static constexpr unsigned int MAX_RETRIES = 10;
  static constexpr unsigned int MAX_SYN_RETRIES = 5;
  static constexpr uint64_t CONNECT_TIMEOUT = 10000;
  static constexpr int POLL_INTERVAL = 10; /* ms, while waiting to write to a socket */

private:
  enum State
  {
    CONNECTING,  /* server: waiting for our socket to reach the target */
    SYN_SENT,    /* client: waiting for the other end to accept */
    SYN_RCVD,    /* server: accepted; waiting for the handshake to finish */
    ESTABLISHED, /* including after either direction has closed */
  };

  struct Listener
  {
    uint8_t forward;
    int fd;
  };

  struct Target
  {
    Addr addr;
    socklen_t len;
    bool present;

    Target() : addr(), len( 0 ), present( false ) {}
  };

  struct Conn
  {
    uint8_t forward;
    uint16_t port; /* client-side port: names this connection in the tunnel */
    int fd;
    State state;
    bool dead; /* finished with; to be removed */

    uint32_t mss; /* largest payload we send */

    /* sending: bytes read from the socket, on their way to the other end */
    std::string send_buf; /* everything from snd_una on, sent or not */
    uint32_t iss;
    uint32_t snd_una; /* oldest unacknowledged */
    uint32_t snd_nxt; /* next to send (falls back to snd_una on a timeout) */
    uint32_t snd_max; /* highest ever sent, plus one */
    uint32_t snd_wnd; /* what the other end will accept */
    uint32_t cwnd, ssthresh;
    unsigned int dupacks;
    bool recovering;  /* repairing a loss found by duplicate acknowledgments... */
    uint32_t recover; /* ...which is over when this much is acknowledged */
    bool local_eof;    /* the socket has no more to send */
    bool fin_sent;     /* our FIN lies before snd_nxt */
    bool fin_was_sent; /* ...or did once, at fin_seq */
    bool fin_acked;
    uint32_t fin_seq;

    /* retransmission */
    uint64_t rto_deadline; /* 0 when the timer is off */
    uint32_t rto;
    unsigned int retries;
    bool rtt_timing;
    uint32_t rtt_seq;
    uint64_t rtt_start;
    bool rtt_valid;
    double srtt, rttvar;

    /* receiving: bytes from the other end, on their way to the socket */
    std::string recv_buf;
    uint32_t rcv_nxt;
    std::map<uint32_t, std::string> early; /* segments from beyond rcv_nxt, by sequence number */
    size_t early_bytes;
    bool fin_received;
    bool shut_wr; /* we have passed their FIN on to the socket */
    uint16_t last_window;

    uint64_t connect_deadline;

    Conn()
      : forward( 0 ), port( 0 ), fd( -1 ), state( CONNECTING ), dead( false ), mss( DEFAULT_MSS ), send_buf(),
        iss( 0 ),
        snd_una( 0 ), snd_nxt( 0 ), snd_max( 0 ), snd_wnd( 0 ), cwnd( 0 ), ssthresh( 0xFFFFFFFF ), dupacks( 0 ),
        recovering( false ), recover( 0 ),
        local_eof( false ), fin_sent( false ), fin_was_sent( false ), fin_acked( false ), fin_seq( 0 ),
        rto_deadline( 0 ), rto( RTO_INITIAL ), retries( 0 ), rtt_timing( false ), rtt_seq( 0 ), rtt_start( 0 ),
        rtt_valid( false ), srtt( 0 ), rttvar( 0 ), recv_buf(), rcv_nxt( 0 ), early(), early_bytes( 0 ),
        fin_received( false ),
        shut_wr( false ), last_window( 0 ), connect_deadline( 0 )
    {}
  };

  SegmentSink* sink;
  bool client;

  std::vector<Listener> listeners;
  std::vector<Target> targets; /* by forward index */
  std::list<Conn> conns;
  uint16_t next_port;
  PRNG prng;

  Conn* find( uint8_t forward, uint16_t port );
  Conn* new_conn( uint8_t forward, uint16_t port, int fd );
  void sweep( void );

  uint32_t local_mss( void ) const;
  uint16_t window( const Conn& c ) const;
  void emit( Conn& c, uint16_t flags, uint32_t seq, const std::string& payload, bool with_mss = false );
  void reply_reset( uint8_t forward, uint16_t port, const TCPInUDP& to );

  void accept_from( const Listener& listener, uint64_t now );
  void passive_open( uint8_t forward, uint16_t port, const TCPInUDP& syn, uint64_t now );
  void connected( Conn& c, uint64_t now );
  void abort( Conn& c, bool tell_peer );

  void established_input( Conn& c, const TCPInUDP& segment, uint64_t now );
  void accept_data( Conn& c, uint32_t seq, const std::string& payload, bool fin );
  void process_ack( Conn& c, const TCPInUDP& segment, uint64_t now );
  void output( Conn& c, uint64_t now );
  void retransmit_one( Conn& c );
  void timeout( Conn& c, uint64_t now );
  void flush( Conn& c );
  void read_socket( Conn& c, uint64_t now );
  void maybe_finish( Conn& c );

  /* unused */
  AdapterPort( const AdapterPort& );
  AdapterPort& operator=( const AdapterPort& );

public:
  AdapterPort( SegmentSink* s_sink, bool s_client );
  ~AdapterPort();

  /* Client: start listening.  Returns the address, for the user.  Throws NetworkException. */
  std::string add_listener( uint8_t forward, const ForwardSpec& spec );

  /* Server: where connections on this forward go. */
  void add_target( uint8_t forward, const Addr& addr, socklen_t len );

  std::vector<int> fds( void ) const;
  void read_fd( int fd );
  void tick( uint64_t now );
  int wait_time( uint64_t now ) const;
  void from_network( uint8_t forward, const TCPInUDP& segment );

  size_t connection_count( void ) const { return conns.size(); }
};

}

#endif
