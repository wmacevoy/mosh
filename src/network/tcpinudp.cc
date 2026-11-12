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

#include "src/include/config.h"

#include <cstring>

#include <netinet/in.h>

#include "src/network/tcpinudp.h"

using namespace Network;

static uint16_t get16( const std::string& s, size_t at )
{
  return ( static_cast<uint8_t>( s[at] ) << 8 ) | static_cast<uint8_t>( s[at + 1] );
}

static uint32_t get32( const std::string& s, size_t at )
{
  return ( static_cast<uint32_t>( get16( s, at ) ) << 16 ) | get16( s, at + 2 );
}

static void put16( std::string& s, uint16_t x )
{
  s.push_back( static_cast<char>( x >> 8 ) );
  s.push_back( static_cast<char>( x & 0xFF ) );
}

static void put32( std::string& s, uint32_t x )
{
  put16( s, x >> 16 );
  put16( s, x & 0xFFFF );
}

bool TCPInUDP::valid( void ) const
{
  return options.size() % 4 == 0 && options.size() <= MAX_OPTIONS_LEN && !( flags & ~0xFFF ) && !( flags & URG );
}

/* Reads "data offset, flags" at one offset and takes options and payload from after the fixed header. */
static bool parse_variable_part( const std::string& s,
                                 size_t offset_flags_at,
                                 size_t fixed_len,
                                 uint16_t& flags,
                                 std::string& options,
                                 std::string& payload )
{
  const uint16_t offset_flags = get16( s, offset_flags_at );
  const size_t header_words = offset_flags >> 12;
  flags = offset_flags & 0xFFF;

  if ( header_words * 4 < TCPInUDP::TCP_HEADER_LEN ) {
    return false;
  }
  const size_t options_len = header_words * 4 - TCPInUDP::TCP_HEADER_LEN;
  if ( fixed_len + options_len > s.size() ) {
    return false;
  }

  options.assign( s, fixed_len, options_len );
  payload.assign( s, fixed_len + options_len, std::string::npos );
  return true;
}

bool TCPInUDP::from_datagram( uint16_t source_port, uint16_t dest_port, const std::string& datagram, TCPInUDP& out )
{
  if ( datagram.size() < DATAGRAM_HEADER_LEN ) {
    return false;
  }

  out.source_port = source_port;
  out.dest_port = dest_port;
  out.window = get16( datagram, 2 );
  out.seq = get32( datagram, 4 );
  out.ack = get32( datagram, 8 );

  if ( !parse_variable_part( datagram, 0, DATAGRAM_HEADER_LEN, out.flags, out.options, out.payload ) ) {
    return false;
  }

  out.flags &= ~URG; /* meaningless without an urgent pointer */
  return true;
}

std::string TCPInUDP::to_datagram( void ) const
{
  if ( !valid() ) {
    throw NetworkException( "TCP-in-UDP: segment cannot be represented", 0 );
  }

  std::string ret;
  ret.reserve( DATAGRAM_HEADER_LEN + options.size() + payload.size() );
  put16( ret, ( data_offset() << 12 ) | flags );
  put16( ret, window );
  put32( ret, seq );
  put32( ret, ack );
  ret += options;
  ret += payload;
  return ret;
}

bool TCPInUDP::from_tcp( const std::string& segment, TCPInUDP& out )
{
  if ( segment.size() < TCP_HEADER_LEN ) {
    return false;
  }

  out.source_port = get16( segment, 0 );
  out.dest_port = get16( segment, 2 );
  out.seq = get32( segment, 4 );
  out.ack = get32( segment, 8 );
  out.window = get16( segment, 14 );
  /* checksum (16) is recomputed on the way out; urgent pointer (18) is lost */

  if ( !parse_variable_part( segment, 12, TCP_HEADER_LEN, out.flags, out.options, out.payload ) ) {
    return false;
  }

  return !( out.flags & URG );
}

static const size_t TCP_CHECKSUM_AT = 16;
static const size_t UDP_CHECKSUM_AT = 6;

std::string TCPInUDP::to_tcp( const Addr& source, const Addr& dest ) const
{
  if ( !valid() ) {
    throw NetworkException( "TCP-in-UDP: segment cannot be represented", 0 );
  }

  std::string ret;
  ret.reserve( TCP_HEADER_LEN + options.size() + payload.size() );
  put16( ret, source_port );
  put16( ret, dest_port );
  put32( ret, seq );
  put32( ret, ack );
  put16( ret, ( data_offset() << 12 ) | flags );
  put16( ret, window );
  put16( ret, 0 ); /* checksum, below */
  put16( ret, 0 ); /* urgent pointer */
  ret += options;
  ret += payload;

  const uint16_t sum = checksum( IPPROTO_TCP, source, dest, ret );
  ret[TCP_CHECKSUM_AT] = static_cast<char>( sum >> 8 );
  ret[TCP_CHECKSUM_AT + 1] = static_cast<char>( sum & 0xFF );
  return ret;
}

std::string TCPInUDP::to_udp( const Addr& source, const Addr& dest ) const
{
  const std::string datagram = to_datagram();
  if ( UDP_HEADER_LEN + datagram.size() > 0xFFFF ) {
    throw NetworkException( "TCP-in-UDP: segment too long", 0 );
  }

  std::string ret;
  ret.reserve( UDP_HEADER_LEN + datagram.size() );
  put16( ret, source_port );
  put16( ret, dest_port );
  put16( ret, UDP_HEADER_LEN + datagram.size() );
  put16( ret, 0 ); /* checksum, below */
  ret += datagram;

  uint16_t sum = checksum( IPPROTO_UDP, source, dest, ret );
  if ( sum == 0 ) {
    sum = 0xFFFF; /* zero would mean "no checksum" */
  }
  ret[UDP_CHECKSUM_AT] = static_cast<char>( sum >> 8 );
  ret[UDP_CHECKSUM_AT + 1] = static_cast<char>( sum & 0xFF );
  return ret;
}

static void sum_bytes( uint32_t& sum, const void* data, size_t len )
{
  const uint8_t* p = static_cast<const uint8_t*>( data );
  for ( size_t i = 0; i + 1 < len; i += 2 ) {
    sum += ( p[i] << 8 ) | p[i + 1];
    sum = ( sum & 0xFFFF ) + ( sum >> 16 );
  }
  if ( len % 2 ) {
    sum += p[len - 1] << 8;
    sum = ( sum & 0xFFFF ) + ( sum >> 16 );
  }
}

uint16_t TCPInUDP::checksum( uint8_t protocol, const Addr& source, const Addr& dest, const std::string& segment )
{
  uint32_t sum = 0;

  /* pseudo-header */
  if ( source.sa.sa_family == AF_INET && dest.sa.sa_family == AF_INET ) {
    if ( segment.size() > 0xFFFF ) {
      throw NetworkException( "TCP-in-UDP: segment too long", 0 );
    }
    sum_bytes( sum, &source.sin.sin_addr, 4 );
    sum_bytes( sum, &dest.sin.sin_addr, 4 );
  } else if ( source.sa.sa_family == AF_INET6 && dest.sa.sa_family == AF_INET6 ) {
    sum_bytes( sum, &source.sin6.sin6_addr, 16 );
    sum_bytes( sum, &dest.sin6.sin6_addr, 16 );
  } else {
    throw NetworkException( "TCP-in-UDP: addresses must both be IPv4 or both be IPv6", 0 );
  }
  /* both families: the upper-layer length and the protocol, each as a 32-bit quantity */
  const uint8_t tail[8] = { static_cast<uint8_t>( segment.size() >> 24 ),
                            static_cast<uint8_t>( segment.size() >> 16 ),
                            static_cast<uint8_t>( segment.size() >> 8 ),
                            static_cast<uint8_t>( segment.size() ),
                            0,
                            0,
                            0,
                            protocol };
  sum_bytes( sum, tail, sizeof( tail ) );

  sum_bytes( sum, segment.data(), segment.size() );

  return ~sum & 0xFFFF;
}

size_t TCPInUDP::max_segment_size( size_t max_datagram )
{
  const size_t overhead = DATAGRAM_HEADER_LEN + MAX_OPTIONS_LEN;
  return max_datagram > overhead ? max_datagram - overhead : 0;
}
