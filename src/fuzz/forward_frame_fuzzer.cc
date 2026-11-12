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
 * Fuzzes the parts of UDP forwarding that are pure computation: the
 * frame header, fragment reassembly, parity, and the replay window.
 *
 * Besides looking for crashes, it checks what must always be true:
 * a datagram that is split and put back together comes back unchanged,
 * with any one fragment per parity group missing; a frame that is
 * encoded decodes to the same thing; and the replay window never
 * accepts a sequence number twice.
 */

#include <set>
#include <vector>

#include "src/fuzz/forward_fuzz.h"
#include "src/network/udpforward.h"

using namespace Network;
using namespace ForwardFuzz;

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  Input in( data, size );

  const size_t max_fragment = DatagramAssembly::FRAGMENT_HEADER_LEN + 1 + in.byte() * 6;
  const bool parity = in.byte() & 1;

  DatagramAssembly assembly; /* fed whatever the input says are fragments */
  ReplayWindow window;
  std::set<uint64_t> accepted;
  uint64_t seq = 0;

  unsigned int kind;
  std::string body;
  while ( in.record( kind, body ) ) {
    switch ( kind ) {
      case 0: { /* an arbitrary "fragment" */
        std::string out;
        bool used_parity = false;
        if ( assembly.add( body, out, used_parity ) == DatagramAssembly::COMPLETE ) {
          require( !out.empty() && out.size() <= DatagramAssembly::MAX_DATAGRAM );
        }
        unsigned int index;
        DatagramAssembly::index_of( body, index );
        break;
      }

      case 1: { /* split a datagram, lose a fragment, and rebuild it */
        const unsigned int lost = at( body, 0 );
        const std::string datagram = body.substr( body.empty() ? 0 : 1 ) + std::string( at( body, 0 ) * 3, 'x' );
        const std::vector<std::string> fragments = DatagramAssembly::split( datagram, max_fragment, parity );
        if ( fragments.empty() ) {
          break;
        }
        const unsigned int count = DatagramAssembly::piece_count( datagram.size(), max_fragment );
        require( count >= 2 && fragments.size() >= count );

        DatagramAssembly rebuilt;
        std::string out;
        bool used_parity = false;
        bool complete = false;
        for ( size_t i = 0; i < fragments.size() && !complete; i++ ) {
          require( fragments[i].size() <= max_fragment );
          if ( parity && i == lost % fragments.size() ) {
            continue; /* with parity, any one fragment can go missing */
          }
          const DatagramAssembly::Result r = rebuilt.add( fragments[i], out, used_parity );
          require( r != DatagramAssembly::REJECTED );
          complete = r == DatagramAssembly::COMPLETE;
        }
        require( complete && out == datagram );
        break;
      }

      case 2: { /* a frame: arbitrary bytes, and a round trip */
        uint8_t type, forward;
        uint16_t flow;
        uint64_t frame_seq;
        std::string payload;
        UDPForwarder::decode_frame( body, type, forward, flow, frame_seq, payload );

        const uint16_t a_flow = at( body, 2 ) * 257;
        const std::string frame = UDPForwarder::encode_frame( at( body, 0 ), at( body, 1 ), a_flow, seq, body );
        require( UDPForwarder::decode_frame( frame, type, forward, flow, frame_seq, payload ) );
        require( type == at( body, 0 ) && forward == at( body, 1 ) && flow == a_flow && frame_seq == seq
                 && payload == body );
        break;
      }

      case 3: /* sequence numbers, in any order and from anywhere */
        for ( size_t i = 0; i + 1 < body.size(); i += 2 ) {
          /* mostly near where we are, but sometimes far away */
          seq += static_cast<int8_t>( body[i] );
          if ( at( body, i + 1 ) == 0xFF ) {
            seq += uint64_t( 1 ) << ( at( body, i ) % 64 );
          }
          if ( window.accept( seq ) ) {
            require( accepted.insert( seq ).second );
          }
        }
        break;
    }
  }

  return 0;
}
