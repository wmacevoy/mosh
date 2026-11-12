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

/*
 * Fuzzes the socket adapter, mosh's own TCP endpoint for forwarded
 * connections, in both roles: as the end that listens (and opens
 * connections through the tunnel) and as the end that connects to the
 * target (and accepts them).
 *
 * The other end of the tunnel is the fuzzer.  It can send any segment
 * at all; and so that it can get past the handshake, which needs the
 * adapter's own sequence numbers echoed back, one kind of record builds
 * a segment relative to the last one the adapter sent.  Other records
 * let time pass (for retransmission) and work the application's end of
 * the local socket.
 *
 * It uses real sockets on the loopback interface, since the adapter does.
 */

#include <vector>

#include "src/fuzz/forward_fuzz.h"
#include "src/network/tcpadapter.h"
#include "src/util/timestamp.h"

using namespace Network;
using namespace ForwardFuzz;

namespace {

class Sink : public SegmentSink
{
public:
  size_t limit;
  bool any;
  TCPInUDP last;
  unsigned int count;

  Sink() : limit( 1200 ), any( false ), last(), count( 0 ) {}

  bool segment_ready( void ) const { return true; }
  size_t max_datagram( void ) const { return limit; }
  void to_network( uint8_t, const TCPInUDP& segment )
  {
    /* whatever it sends must be a sound segment that fits */
    require( segment.to_datagram().size() <= limit );
    any = true;
    last = segment;
    count++;
  }
};

/* the forwarding target, for when the adapter is the connecting end */
int listener = -1;
uint16_t listener_port;
struct sockaddr_in listener_addr;

/* where the adapter listens, when it is the listening end */
uint16_t adapter_port;

const uint16_t FIRST_PORT = 32768; /* what the listening adapter calls its first connection */
const uint16_t OUR_PORT = 4242;    /* what we call ours, when we open it */

}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  if ( listener < 0 ) {
    listener = loopback_socket( SOCK_STREAM, listener_port, listener_addr );
    require( listen( listener, 64 ) == 0 );
    set_nonblocking( listener );

    struct sockaddr_in unused;
    close( loopback_socket( SOCK_STREAM, adapter_port, unused ) );
  }

  Input in( data, size );
  freeze_timestamp();

  const bool listening = in.byte() & 1;
  Sink sink;
  sink.limit = 100 + in.byte() * 5;

  int app = -1; /* the application's end of the adapter's local socket */
  uint64_t later = 0;
  char buf[4096];

  {
    AdapterPort adapter( &sink, listening );

    if ( listening ) {
      char spec[64];
      snprintf( spec, sizeof( spec ), "%d:127.0.0.1:1", adapter_port );
      try {
        adapter.add_listener( 0, ForwardSpec( spec ) );
      } catch ( const NetworkException& ) {
        return 0; /* the port was taken in the meantime; nothing to learn from that */
      }

      /* an application connects, and the adapter opens a connection through the tunnel */
      struct sockaddr_in to = listener_addr;
      to.sin_port = htons( adapter_port );
      app = socket( AF_INET, SOCK_STREAM, 0 );
      require( app >= 0 );
      if ( connect( app, reinterpret_cast<struct sockaddr*>( &to ), sizeof( to ) ) == 0 ) {
        set_nonblocking( app );
        adapter.read_fd( adapter.fds().at( 0 ) );
      }
    } else {
      Addr target;
      memset( &target, 0, sizeof( target ) );
      target.sin = listener_addr;
      adapter.add_target( 0, target, sizeof( listener_addr ) );
    }

    unsigned int kind;
    std::string body;
    while ( in.record( kind, body ) ) {
      switch ( kind ) {
        case 0: { /* any segment at all */
          TCPInUDP segment;
          if ( TCPInUDP::from_datagram( listening ? 0 : OUR_PORT, listening ? FIRST_PORT : 0, body, segment ) ) {
            adapter.from_network( 0, segment );
          }
          break;
        }

        case 1: { /* a segment that follows on from the adapter's last one, more or less */
          TCPInUDP segment;
          ( listening ? segment.dest_port : segment.source_port ) = listening ? FIRST_PORT : OUR_PORT;
          segment.flags = at( body, 0 ) & 0xDF; /* (not URG) */
          if ( sink.any ) {
            segment.seq = sink.last.ack;
            segment.ack = sink.last.seq + sink.last.payload.size() + ( sink.last.has( TCPInUDP::SYN ) ? 1 : 0 )
                          + ( sink.last.has( TCPInUDP::FIN ) ? 1 : 0 );
          }
          segment.seq += static_cast<int8_t>( at( body, 1 ) );
          segment.ack += static_cast<int8_t>( at( body, 2 ) );
          segment.window = at( body, 3 ) * 257;
          if ( at( body, 4 ) & 1 ) {
            const char mss[4] = { 2, 4, static_cast<char>( at( body, 5 ) ), static_cast<char>( at( body, 6 ) ) };
            segment.options.assign( mss, sizeof( mss ) );
          }
          segment.payload = body.substr( body.size() < 7 ? body.size() : 7 );
          adapter.from_network( 0, segment );
          break;
        }

        case 2: /* time passes */
          later += at( body, 0 ) * 25;
          adapter.tick( timestamp() + later );
          adapter.wait_time( timestamp() + later );
          break;

        case 3: { /* the application does something, and the adapter notices */
          if ( app < 0 && !listening ) {
            app = accept( listener, NULL, NULL );
            if ( app >= 0 ) {
              set_nonblocking( app );
            }
          }
          if ( app >= 0 ) {
            switch ( at( body, 0 ) % 4 ) {
              case 0:
                if ( body.size() > 1 ) {
                  send( app, body.data() + 1, body.size() - 1, MSG_NOSIGNAL );
                }
                break;
              case 1:
                while ( recv( app, buf, sizeof( buf ), 0 ) > 0 ) {
                }
                break;
              case 2:
                shutdown( app, SHUT_WR );
                break;
              case 3:
                close( app );
                app = -1;
                break;
            }
          }
          const std::vector<int> fds = adapter.fds();
          for ( size_t i = 0; i < fds.size(); i++ ) {
            adapter.read_fd( fds[i] );
          }
          break;
        }
      }
      require( adapter.connection_count() <= AdapterPort::MAX_CONNECTIONS );
    }
  } /* the adapter closes its sockets */

  if ( app >= 0 ) {
    close( app );
  }
  /* clear away connections to the target that nobody accepted */
  int waiting;
  while ( ( waiting = accept( listener, NULL, NULL ) ) >= 0 ) {
    close( waiting );
  }
  return 0;
}
