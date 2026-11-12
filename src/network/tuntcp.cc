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

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#include "src/network/tuntcp.h"

using namespace Network;

static Addr addr_of( uint32_t host_order )
{
  Addr a;
  memset( &a, 0, sizeof( a ) );
  a.sin.sin_family = AF_INET;
  a.sin.sin_addr.s_addr = htonl( host_order );
  return a;
}

static std::string dotted( uint32_t host_order )
{
  char buf[INET_ADDRSTRLEN];
  struct in_addr in;
  in.s_addr = htonl( host_order );
  return inet_ntop( AF_INET, &in, buf, sizeof( buf ) ) ? buf : "?";
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

static uint16_t get16( const std::string& s, size_t at )
{
  return ( static_cast<uint8_t>( s[at] ) << 8 ) | static_cast<uint8_t>( s[at + 1] );
}

static uint32_t get32( const std::string& s, size_t at )
{
  return ( static_cast<uint32_t>( get16( s, at ) ) << 16 ) | get16( s, at + 2 );
}

std::string TunPort::ip_packet( uint32_t source, uint32_t dest, uint16_t id, const std::string& tcp_segment )
{
  std::string p;
  p.reserve( IP_HEADER_LEN + tcp_segment.size() );
  put16( p, 0x4500 ); /* version 4, 5 words of header; no special service */
  put16( p, IP_HEADER_LEN + tcp_segment.size() );
  put16( p, id );
  put16( p, 0x4000 ); /* don't fragment */
  put16( p, ( 64 << 8 ) | IPPROTO_TCP ); /* time to live; protocol */
  put16( p, 0 ); /* checksum, below */
  put32( p, source );
  put32( p, dest );

  uint32_t sum = 0;
  for ( size_t i = 0; i < IP_HEADER_LEN; i += 2 ) {
    sum += get16( p, i );
  }
  sum = ( sum & 0xFFFF ) + ( sum >> 16 );
  sum = ( sum & 0xFFFF ) + ( sum >> 16 );
  const uint16_t check = ~sum & 0xFFFF;
  p[10] = static_cast<char>( check >> 8 );
  p[11] = static_cast<char>( check & 0xFF );

  p += tcp_segment;
  return p;
}

bool TunPort::parse_ip_packet( const std::string& packet,
                               uint32_t& source,
                               uint32_t& dest,
                               std::string& tcp_segment )
{
  if ( packet.size() < IP_HEADER_LEN || ( static_cast<uint8_t>( packet[0] ) >> 4 ) != 4 ) {
    return false;
  }
  const size_t header_len = ( static_cast<uint8_t>( packet[0] ) & 0x0F ) * 4;
  const size_t total_len = get16( packet, 2 );
  if ( header_len < IP_HEADER_LEN || total_len < header_len || total_len > packet.size() ) {
    return false;
  }
  if ( static_cast<uint8_t>( packet[9] ) != IPPROTO_TCP ) {
    return false;
  }
  if ( get16( packet, 6 ) & 0x3FFF ) {
    return false; /* a fragment (more to come, or a nonzero offset) */
  }

  source = get32( packet, 12 );
  dest = get32( packet, 16 );
  tcp_segment.assign( packet, header_len, total_len - header_len );
  return true;
}

#ifdef __linux__

TunPort::TunPort( SegmentSink* s_sink, bool s_client )
  : sink( s_sink ), client( s_client ), fd( -1 ), ifname(), subnet( s_client ? CLIENT_SUBNET : SERVER_SUBNET ),
    next_id( 0 ), forwards()
{
  fd = open( "/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC );
  if ( fd < 0 ) {
    throw NetworkException( "/dev/net/tun", errno );
  }

  struct ifreq ifr;
  memset( &ifr, 0, sizeof( ifr ) );
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy( ifr.ifr_name, "mosh%d", IFNAMSIZ - 1 );
  if ( ioctl( fd, TUNSETIFF, &ifr ) < 0 ) {
    const int saved_errno = errno;
    close( fd );
    throw NetworkException( "creating TUN device", saved_errno );
  }
  ifname = ifr.ifr_name;

  try {
    /* a whole IPv4 packet is 28 bytes longer than its segment in TCP-in-UDP datagram form */
    configure( sink->max_datagram() + IP_HEADER_LEN + TCPInUDP::UDP_HEADER_LEN );
  } catch ( ... ) {
    close( fd );
    throw;
  }
}

void TunPort::configure( size_t mtu )
{
  int s = socket( AF_INET, SOCK_DGRAM, 0 );
  if ( s < 0 ) {
    throw NetworkException( "socket", errno );
  }

  struct ifreq ifr;
  const char* failed = NULL;

#define IFREQ( request, what )                                                                                     \
  if ( !failed && ioctl( s, request, &ifr ) < 0 ) {                                                                \
    failed = what;                                                                                                 \
  }

  memset( &ifr, 0, sizeof( ifr ) );
  strncpy( ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1 );

  const Addr address = addr_of( subnet | INTERFACE_HOST );
  memcpy( &ifr.ifr_addr, &address.sa, sizeof( address.sin ) );
  IFREQ( SIOCSIFADDR, "setting address" );

  const Addr netmask = addr_of( NETMASK );
  memcpy( &ifr.ifr_netmask, &netmask.sa, sizeof( netmask.sin ) );
  IFREQ( SIOCSIFNETMASK, "setting netmask" );

  ifr.ifr_mtu = mtu;
  IFREQ( SIOCSIFMTU, "setting MTU" );

  IFREQ( SIOCGIFFLAGS, "reading flags" );
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  IFREQ( SIOCSIFFLAGS, "bringing interface up" );

#undef IFREQ

  const int saved_errno = errno;
  close( s );
  if ( failed ) {
    throw NetworkException( std::string( failed ) + " of " + ifname, saved_errno );
  }
}

#else /* !__linux__ */

TunPort::TunPort( SegmentSink* s_sink, bool s_client )
  : sink( s_sink ), client( s_client ), fd( -1 ), ifname(), subnet( 0 ), next_id( 0 ), forwards()
{
  throw NetworkException( "TUN devices are only supported on Linux", 0 );
}

void TunPort::configure( size_t ) {}

#endif

TunPort::~TunPort()
{
  if ( fd >= 0 ) {
    close( fd ); /* the interface goes with it */
  }
}

std::string TunPort::add_listener( uint8_t forward, const ForwardSpec& spec )
{
  Forward f;
  f.index = forward;
  f.port = atoi( spec.bind_port.c_str() );
  f.target = 0;

  for ( std::vector<Forward>::const_iterator i = forwards.begin(); i != forwards.end(); i++ ) {
    if ( i->port == f.port ) {
      throw NetworkException( "port " + spec.bind_port + " is already forwarded", 0 );
    }
  }
  forwards.push_back( f );
  return dotted( subnet | FIRST_PEER_HOST ) + ":" + spec.bind_port;
}

std::string TunPort::add_target( uint8_t forward, const Addr& target )
{
  if ( target.sa.sa_family != AF_INET ) {
    throw NetworkException( "a TUN device can only reach IPv4 targets", 0 );
  }

  Forward f;
  f.index = forward;
  f.port = ntohs( target.sin.sin_port );
  f.target = ntohl( target.sin.sin_addr.s_addr );

  if ( ( f.target >> 24 ) == 127 ) {
    /* Loopback addresses are normally refused from any other interface.  Ask for this one to be let in. */
    const std::string path = "/proc/sys/net/ipv4/conf/" + ifname + "/route_localnet";
    FILE* file = fopen( path.c_str(), "w" );
    const bool ok = file && fputs( "1\n", file ) >= 0;
    if ( ( file && fclose( file ) != 0 ) || !ok ) {
      throw NetworkException( "cannot route " + dotted( f.target ) + " to " + ifname, 0 );
    }
  }

  forwards.push_back( f );
  return dotted( f.target );
}

std::vector<int> TunPort::fds( void ) const
{
  return std::vector<int>( 1, fd );
}

void TunPort::write_segment( uint32_t source, uint32_t dest, const TCPInUDP& segment )
{
  const std::string packet
    = ip_packet( source, dest, next_id++, segment.to_tcp( addr_of( source ), addr_of( dest ) ) );
  /* If the kernel won't take it, it is lost, like any other packet. */
  ssize_t unused __attribute( ( unused ) ) = write( fd, packet.data(), packet.size() );
}

/* A segment from the other end: give it to the kernel. */
void TunPort::from_network( uint8_t forward, const TCPInUDP& segment )
{
  for ( std::vector<Forward>::const_iterator i = forwards.begin(); i != forwards.end(); i++ ) {
    if ( i->index != forward ) {
      continue;
    }

    TCPInUDP s = segment;
    if ( client ) {
      /* from the service address and port, to the application */
      s.source_port = i->port;
      write_segment( subnet | FIRST_PEER_HOST, subnet | INTERFACE_HOST, s );
    } else {
      /* from this forward's stand-in for the client, to the target */
      s.dest_port = i->port;
      write_segment( subnet | ( FIRST_PEER_HOST + forward ), i->target, s );
    }
    return;
  }
}

/* A packet from the kernel: send its segment to the other end. */
void TunPort::handle_packet( const std::string& packet )
{
  uint32_t source, dest;
  std::string tcp;
  TCPInUDP segment;
  if ( !parse_ip_packet( packet, source, dest, tcp ) || !TCPInUDP::from_tcp( tcp, segment ) ) {
    return; /* not TCP over IPv4 (the kernel sends other things unprompted), or urgent data */
  }

  for ( std::vector<Forward>::const_iterator i = forwards.begin(); i != forwards.end(); i++ ) {
    if ( client ) {
      if ( source == ( subnet | INTERFACE_HOST ) && dest == ( subnet | FIRST_PEER_HOST )
           && segment.dest_port == i->port ) {
        sink->to_network( i->index, segment ); /* source_port names the connection */
        return;
      }
    } else {
      if ( source == i->target && segment.source_port == i->port
           && dest == ( subnet | ( FIRST_PEER_HOST + i->index ) ) ) {
        sink->to_network( i->index, segment ); /* dest_port names the connection */
        return;
      }
    }
  }

  /* Nothing is forwarded from there.  Refuse, so the application isn't left waiting. */
  if ( !segment.has( TCPInUDP::RST ) ) {
    TCPInUDP reset;
    reset.source_port = segment.dest_port;
    reset.dest_port = segment.source_port;
    if ( segment.has( TCPInUDP::ACK ) ) {
      reset.flags = TCPInUDP::RST;
      reset.seq = segment.ack;
    } else {
      reset.flags = TCPInUDP::RST | TCPInUDP::ACK;
      reset.ack = segment.seq + segment.payload.size() + ( segment.has( TCPInUDP::SYN ) ? 1 : 0 )
                  + ( segment.has( TCPInUDP::FIN ) ? 1 : 0 );
    }
    write_segment( dest, source, reset );
  }
}

void TunPort::read_fd( int which )
{
  if ( which != fd ) {
    return;
  }

  char buf[65536];
  for ( int n = 0; n < MAX_READS_PER_WAKEUP; n++ ) {
    ssize_t len = read( fd, buf, sizeof( buf ) );
    if ( len <= 0 ) {
      return;
    }
    handle_packet( std::string( buf, len ) );
  }
}
