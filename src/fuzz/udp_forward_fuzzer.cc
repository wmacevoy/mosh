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
 * Fuzzes the UDP forwarder as the connecting end sees it: everything
 * that can arrive on the side channel (frames, fragments, replays,
 * junk), and replies of every size from the forwarding target, which
 * it must fragment to send back.
 *
 * It uses real sockets on the loopback interface, since the forwarder
 * does.  Nothing reads what it sends to the "target", which is fine.
 */

#include <vector>

#include "src/fuzz/forward_fuzz.h"
#include "src/network/udpforward.h"
#include "src/util/timestamp.h"

using namespace Network;
using namespace ForwardFuzz;

namespace {

class Link : public SideChannelLink
{
public:
  size_t limit;
  double loss;
  std::vector<std::string> sent;

  Link() : limit( 1200 ), loss( 0 ), sent() {}

  bool sidechannel_ready( void ) const { return true; }
  size_t sidechannel_max_payload( void ) const { return limit; }
  double sidechannel_loss( void ) const { return loss; }
  bool sidechannel_connected( void ) const { return true; }
  void sidechannel_send( const std::string& payload )
  {
    /* whatever it sends must fit, and must be a frame */
    require( payload.size() <= limit && payload.size() >= UDPForwarder::HEADER_LEN );
    require( static_cast<uint8_t>( payload[0] ) == SIDECHANNEL_MAGIC );
    if ( sent.size() < 64 ) {
      sent.push_back( payload );
    }
  }
};

int target = -1;
uint16_t target_port;
struct sockaddr_in target_addr;

}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  if ( target < 0 ) {
    target = loopback_socket( SOCK_DGRAM, target_port, target_addr );
    set_nonblocking( target );
  }

  Input in( data, size );
  freeze_timestamp();

  Link link;
  link.limit = UDPForwarder::HEADER_LEN + DatagramAssembly::FRAGMENT_HEADER_LEN + 8 + in.byte() * 5;
  link.loss = in.byte() / 255.0;
  const unsigned int mode = in.byte() % 3;

  char spec[64];
  snprintf( spec, sizeof( spec ), "1:127.0.0.1:%d", target_port );
  UDPForwarder forwarder( &link, UDPForwarder::CONNECT, std::vector<std::string>( 2, spec ) );
  forwarder.set_parity_mode( mode == 0 ? UDPForwarder::PARITY_AUTO
                                       : mode == 1 ? UDPForwarder::PARITY_ALWAYS : UDPForwarder::PARITY_NEVER );

  uint64_t seq = 1000;
  char buf[65536];

  unsigned int kind;
  std::string body;
  while ( in.record( kind, body ) ) {
    switch ( kind ) {
      case 0: /* anything at all */
        forwarder.sidechannel_recv( body );
        break;

      case 1: { /* a frame that at least looks like one */
        seq += static_cast<int8_t>( at( body, 3 ) );
        const std::string payload = body.substr( body.size() < 4 ? body.size() : 4 );
        forwarder.sidechannel_recv(
          UDPForwarder::encode_frame( at( body, 0 ) % 7, at( body, 1 ) % 3, at( body, 2 ) % 80, seq, payload ) );
        break;
      }

      case 2: { /* a whole datagram, cut into fragments as a real sender would (and maybe short of one) */
        const std::string datagram = body + std::string( at( body, 0 ) * 16, 'd' );
        const std::vector<std::string> fragments
          = DatagramAssembly::split( datagram, link.limit - UDPForwarder::HEADER_LEN, at( body, 1 ) & 1 );
        for ( size_t i = 0; i < fragments.size(); i++ ) {
          if ( ( at( body, 1 ) & 2 ) && i == at( body, 2 ) % fragments.size() ) {
            seq++;
            continue;
          }
          forwarder.sidechannel_recv( UDPForwarder::encode_frame(
            UDPForwarder::TYPE_UDP_FRAGMENT, 0, at( body, 3 ) % 4, seq++, fragments[i] ) );
        }
        break;
      }

      case 3: { /* the target answers whoever last sent to it, and the forwarder relays the answer */
        struct sockaddr_in from;
        socklen_t len = sizeof( from );
        if ( recvfrom( target, buf, sizeof( buf ), 0, reinterpret_cast<struct sockaddr*>( &from ), &len ) >= 0 ) {
          const std::string reply( at( body, 0 ) * 40 + at( body, 1 ), 'r' );
          sendto( target, reply.data(), reply.size(), 0, reinterpret_cast<struct sockaddr*>( &from ), len );
        }
        const std::vector<int> fds = forwarder.fds();
        for ( size_t i = 0; i < fds.size(); i++ ) {
          forwarder.read_fd( fds[i] );
        }
        break;
      }
    }
    require( forwarder.flow_count() <= UDPForwarder::MAX_FLOWS );
    require( forwarder.partial_count() <= UDPForwarder::MAX_PARTIALS );
  }

  /* don't let one input's datagrams reach the next */
  while ( recv( target, buf, sizeof( buf ), 0 ) >= 0 ) {
  }
  return 0;
}
