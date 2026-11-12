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

/* Tests the TCP-in-UDP header transformation: both directions, the
   checksums against independently computed values, and rejection of
   segments that are malformed or cannot be represented. */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "src/network/tcpinudp.h"
#include "src/network/udpforward.h"

using namespace Network;

#define CHECK( x )                                                                                                 \
  do {                                                                                                             \
    if ( !( x ) ) {                                                                                                \
      fprintf( stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #x );                                      \
      exit( EXIT_FAILURE );                                                                                        \
    }                                                                                                              \
  } while ( 0 )

static Addr addr4( const char* s )
{
  Addr a;
  memset( &a, 0, sizeof( a ) );
  a.sin.sin_family = AF_INET;
  CHECK( inet_pton( AF_INET, s, &a.sin.sin_addr ) == 1 );
  return a;
}

static Addr addr6( const char* s )
{
  Addr a;
  memset( &a, 0, sizeof( a ) );
  a.sin6.sin6_family = AF_INET6;
  CHECK( inet_pton( AF_INET6, s, &a.sin6.sin6_addr ) == 1 );
  return a;
}

static std::string bytes( const unsigned char* p, size_t n )
{
  return std::string( reinterpret_cast<const char*>( p ), n );
}

static unsigned int word( const std::string& s, size_t at )
{
  return ( static_cast<unsigned char>( s[at] ) << 8 ) | static_cast<unsigned char>( s[at + 1] );
}

/* IPv4 SYN carrying an MSS option, 192.0.2.1:12345 -> 198.51.100.2:80 */
static const unsigned char syn_tcp[]
  = { 0x30, 0x39, 0x00, 0x50,                         /* ports */
      0x01, 0x02, 0x03, 0x04,                         /* seq */
      0x00, 0x00, 0x00, 0x00,                         /* ack */
      0x60, 0x02, 0xFF, 0xFF,                         /* offset 6, SYN; window */
      0x77, 0x60, 0x00, 0x00,                         /* checksum; urgent pointer */
      0x02, 0x04, 0x05, 0xB4 };                       /* MSS 1460 */
static const unsigned char syn_udp[]
  = { 0x30, 0x39, 0x00, 0x50,                         /* ports */
      0x00, 0x18, 0x77, 0x3D,                         /* length 24; checksum */
      0x60, 0x02, 0xFF, 0xFF,                         /* offset 6, SYN; window */
      0x01, 0x02, 0x03, 0x04,                         /* seq */
      0x00, 0x00, 0x00, 0x00,                         /* ack */
      0x02, 0x04, 0x05, 0xB4 };                       /* MSS 1460 */

static void test_syn( void )
{
  const Addr src = addr4( "192.0.2.1" ), dst = addr4( "198.51.100.2" );
  const std::string tcp = bytes( syn_tcp, sizeof( syn_tcp ) );
  const std::string udp = bytes( syn_udp, sizeof( syn_udp ) );

  TCPInUDP s;
  CHECK( TCPInUDP::from_tcp( tcp, s ) );
  CHECK( s.source_port == 12345 && s.dest_port == 80 );
  CHECK( s.seq == 0x01020304 && s.ack == 0 && s.window == 0xFFFF );
  CHECK( s.flags == TCPInUDP::SYN && s.has( TCPInUDP::SYN ) && !s.has( TCPInUDP::ACK ) );
  CHECK( s.data_offset() == 6 && s.options == std::string( "\x02\x04\x05\xB4" ) && s.payload.empty() );

  /* TCP -> UDP: same bytes rearranged, same length */
  CHECK( s.to_udp( src, dst ) == udp );
  CHECK( s.to_datagram() == udp.substr( TCPInUDP::UDP_HEADER_LEN ) );
  CHECK( udp.size() == tcp.size() );

  /* UDP -> TCP, as a socket would see it: the payload plus the datagram's ports */
  TCPInUDP r;
  CHECK( TCPInUDP::from_datagram( 12345, 80, udp.substr( TCPInUDP::UDP_HEADER_LEN ), r ) );
  CHECK( r.to_tcp( src, dst ) == tcp );

  /* The forwarder acts as a NAT: other addresses and ports, another (valid) checksum. */
  r.source_port = 40000;
  const std::string natted = r.to_tcp( addr4( "10.0.0.1" ), dst );
  CHECK( natted != tcp && natted.size() == tcp.size() );
  std::string zeroed = natted;
  zeroed[16] = zeroed[17] = 0;
  CHECK( TCPInUDP::checksum( IPPROTO_TCP, addr4( "10.0.0.1" ), dst, zeroed ) == word( natted, 16 ) );
}

static void test_data_ipv6( void )
{
  /* PSH|ACK with an odd-length payload, [2001:db8::1]:443 -> [2001:db8::2]:50000 */
  const Addr src = addr6( "2001:db8::1" ), dst = addr6( "2001:db8::2" );

  TCPInUDP s;
  s.source_port = 443;
  s.dest_port = 50000;
  s.seq = 0xDEADBEEF;
  s.ack = 0x00C0FFEE;
  s.flags = TCPInUDP::PSH | TCPInUDP::ACK;
  s.window = 1024;
  s.payload = "hello";

  const std::string tcp = s.to_tcp( src, dst );
  const std::string udp = s.to_udp( src, dst );
  CHECK( tcp.size() == 25 && udp.size() == 25 );
  CHECK( word( tcp, 16 ) == 0xA928 ); /* computed independently */
  CHECK( word( udp, 6 ) == 0xA904 );
  CHECK( word( udp, 4 ) == 25 );
  CHECK( word( tcp, 12 ) == 0x5018 && word( udp, 8 ) == 0x5018 );

  /*
   * The kernel translator never recomputes a checksum; it only adjusts
   * it for what changed: the protocol number (6 -> 17) in the
   * pseudo-header, and the UDP length taking the place of a zero
   * urgent pointer.  The two forms must agree with that.
   */
  unsigned int sum = ( ~word( tcp, 16 ) & 0xFFFF ) + ( IPPROTO_UDP - IPPROTO_TCP ) + udp.size();
  sum = ( sum & 0xFFFF ) + ( sum >> 16 );
  CHECK( ( ~sum & 0xFFFF ) == word( udp, 6 ) );

  TCPInUDP r;
  CHECK( TCPInUDP::from_tcp( tcp, r ) );
  CHECK( r.to_udp( src, dst ) == udp );
  CHECK( TCPInUDP::from_datagram( 443, 50000, udp.substr( 8 ), r ) );
  CHECK( r.payload == "hello" && r.options.empty() && r.to_tcp( src, dst ) == tcp );

  /* a checksum needs one address family */
  bool threw = false;
  try {
    s.to_tcp( src, addr4( "192.0.2.1" ) );
  } catch ( const NetworkException& ) {
    threw = true;
  }
  CHECK( threw );
}

static void test_rejects( void )
{
  const std::string tcp = bytes( syn_tcp, sizeof( syn_tcp ) );
  const std::string datagram = bytes( syn_udp, sizeof( syn_udp ) ).substr( 8 );
  TCPInUDP s;

  /* truncated */
  CHECK( !TCPInUDP::from_tcp( tcp.substr( 0, 19 ), s ) );
  CHECK( !TCPInUDP::from_datagram( 1, 2, datagram.substr( 0, 11 ), s ) );
  CHECK( !TCPInUDP::from_datagram( 1, 2, "", s ) );

  /* header claims options that are not there */
  CHECK( !TCPInUDP::from_tcp( tcp.substr( 0, 20 ), s ) );
  CHECK( !TCPInUDP::from_datagram( 1, 2, datagram.substr( 0, 12 ), s ) );

  /* data offset smaller than a TCP header */
  std::string bad = tcp;
  bad[12] = 0x40;
  CHECK( !TCPInUDP::from_tcp( bad, s ) );
  bad = datagram;
  bad[0] = 0x40;
  CHECK( !TCPInUDP::from_datagram( 1, 2, bad, s ) );

  /* urgent data has nowhere to go */
  bad = tcp;
  bad[13] |= 0x20;
  CHECK( !TCPInUDP::from_tcp( bad, s ) );
  /* ...and a stray URG bit arriving in a datagram is dropped, not believed */
  bad = datagram;
  bad[1] |= 0x20;
  CHECK( TCPInUDP::from_datagram( 1, 2, bad, s ) );
  CHECK( !s.has( TCPInUDP::URG ) && s.has( TCPInUDP::SYN ) );

  /* can't serialize what can't be represented */
  const char* unrepresentable[] = { "urg", "ragged options", "too many options" };
  for ( size_t i = 0; i < 3; i++ ) {
    TCPInUDP x;
    if ( i == 0 ) {
      x.flags = TCPInUDP::URG;
    } else if ( i == 1 ) {
      x.options = "abc";
    } else {
      x.options = std::string( 44, '\x01' );
    }
    bool threw = false;
    try {
      x.to_datagram();
    } catch ( const NetworkException& ) {
      threw = true;
    }
    if ( !threw ) {
      fprintf( stderr, "accepted: %s\n", unrepresentable[i] );
    }
    CHECK( threw );
  }
}

static void test_sizes( void )
{
  /* a full-sized segment with full options exactly fills the budget */
  const size_t budget = 1200 - UDPForwarder::HEADER_LEN;
  const size_t mss = TCPInUDP::max_segment_size( budget );
  CHECK( mss == budget - 12 - 40 );

  TCPInUDP s;
  s.flags = TCPInUDP::ACK;
  s.options = std::string( TCPInUDP::MAX_OPTIONS_LEN, '\x01' ); /* NOPs */
  s.payload = std::string( mss, 'x' );
  CHECK( s.data_offset() == 15 );
  CHECK( s.to_datagram().size() == budget );

  CHECK( TCPInUDP::max_segment_size( 52 ) == 0 && TCPInUDP::max_segment_size( 0 ) == 0 );

  /* and it survives the forwarder's own framing untouched */
  const std::string wire = UDPForwarder::encode( 0, 1, 2, s.to_datagram() );
  CHECK( wire.size() == 1200 );
  uint8_t forward;
  uint16_t flow;
  uint64_t seq;
  std::string datagram;
  TCPInUDP r;
  CHECK( UDPForwarder::decode( wire, forward, flow, seq, datagram ) );
  CHECK( TCPInUDP::from_datagram( 0, 0, datagram, r ) );
  CHECK( r.payload == s.payload && r.options == s.options && r.flags == s.flags );
}

int main()
{
  test_syn();
  test_data_ipv6();
  test_rejects();
  test_sizes();
  return EXIT_SUCCESS;
}
