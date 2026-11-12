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
 * Fuzzes the TCP-in-UDP header transformation: parsing a segment in
 * each of its forms, and checking that whatever parses can be written
 * out again and read back to the same segment.
 */

#include "src/fuzz/forward_fuzz.h"
#include "src/network/tcpinudp.h"

using namespace Network;
using namespace ForwardFuzz;

static bool same( const TCPInUDP& a, const TCPInUDP& b )
{
  return a.source_port == b.source_port && a.dest_port == b.dest_port && a.seq == b.seq && a.ack == b.ack
         && a.flags == b.flags && a.window == b.window && a.options == b.options && a.payload == b.payload;
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  Input in( data, size );

  Addr from4, to4, from6, to6;
  memset( &from4, 0, sizeof( from4 ) );
  memset( &to4, 0, sizeof( to4 ) );
  memset( &from6, 0, sizeof( from6 ) );
  memset( &to6, 0, sizeof( to6 ) );
  from4.sin.sin_family = to4.sin.sin_family = AF_INET;
  from6.sin6.sin6_family = to6.sin6.sin6_family = AF_INET6;
  from4.sin.sin_addr.s_addr = in.byte() * 0x01010101u;
  to4.sin.sin_addr.s_addr = in.byte() * 0x01000001u;
  from6.sin6.sin6_addr.s6_addr[0] = in.byte();
  to6.sin6.sin6_addr.s6_addr[15] = in.byte();
  const bool v6 = in.byte() & 1;
  const Addr& from = v6 ? from6 : from4;
  const Addr& to = v6 ? to6 : to4;
  const uint16_t source_port = in.byte() * 257, dest_port = in.byte() * 257;

  const std::string rest = in.bytes( 60000 ); /* (a segment can't be longer than an IP packet) */

  TCPInUDP a, b;

  /* as it arrives in a forwarded datagram */
  if ( TCPInUDP::from_datagram( source_port, dest_port, rest, a ) ) {
    require( TCPInUDP::from_datagram( source_port, dest_port, a.to_datagram(), b ) && same( a, b ) );
    require( TCPInUDP::from_tcp( a.to_tcp( from, to ), b ) && same( a, b ) );
    if ( rest.size() + TCPInUDP::UDP_HEADER_LEN <= 0xFFFF ) {
      const std::string udp = a.to_udp( from, to );
      require( udp.size() == a.to_tcp( from, to ).size() ); /* no bytes added: that is the point */
      require( TCPInUDP::from_datagram( source_port, dest_port, udp.substr( TCPInUDP::UDP_HEADER_LEN ), b )
               && same( a, b ) );
    }
  }

  /* as a real TCP would send it */
  if ( TCPInUDP::from_tcp( rest, a ) ) {
    require( TCPInUDP::from_tcp( a.to_tcp( from, to ), b ) && same( a, b ) );
    require( TCPInUDP::from_datagram( a.source_port, a.dest_port, a.to_datagram(), b ) && same( a, b ) );
  }

  TCPInUDP::max_segment_size( rest.size() );
  return 0;
}
