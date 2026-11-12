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
#include <cstring>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/network/tcpadapter.h"
#include "src/network/tcpforward.h"
#include "src/network/tuntcp.h"
#include "src/util/timestamp.h"

using namespace Network;

/* Is this an address of the machine we are running on? */
static bool is_local_address( const Addr& addr, socklen_t len )
{
  int fd = socket( addr.sa.sa_family, SOCK_DGRAM, 0 );
  if ( fd < 0 ) {
    return false;
  }
  Addr any_port = addr;
  if ( addr.sa.sa_family == AF_INET ) {
    any_port.sin.sin_port = 0;
  } else {
    any_port.sin6.sin6_port = 0;
  }
  const bool ret = bind( fd, &any_port.sa, len ) == 0;
  close( fd );
  return ret;
}

TCPForwarder::TCPForwarder( SideChannelLink* s_link,
                            Role s_role,
                            const std::vector<std::string>& specs,
                            Device device,
                            uint8_t s_frame_type )
  : link( s_link ), role( s_role ), frame_type( s_frame_type ), verbose( 0 ), adapter(), tun(), port_of(), notes(),
    next_seq( 0 ), replay(), dropped_oversize( 0 )
{
  if ( specs.size() > MAX_FORWARDS ) {
    throw NetworkException( "TCP forwarding: too many forwarding specifications", 0 );
  }

  adapter.reset( new AdapterPort( this, role == LISTEN ) );

  bool tun_failed = false;

  for ( size_t i = 0; i < specs.size(); i++ ) {
    const ForwardSpec spec( specs[i] );

    /* the connecting end needs to know where to connect */
    Addr target;
    socklen_t target_len = 0;
    memset( &target, 0, sizeof( target ) );
    if ( role == CONNECT ) {
      struct addrinfo hints, *res = NULL;
      memset( &hints, 0, sizeof( hints ) );
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_NUMERICSERV;
      int errcode = getaddrinfo( spec.target_host.c_str(), spec.target_port.c_str(), &hints, &res );
      if ( errcode != 0 ) {
        throw NetworkException( "TCP forwarding: " + spec.target_host + ":" + spec.target_port + ": "
                                  + gai_strerror( errcode ),
                                0 );
      }
      target_len = res->ai_addrlen;
      memcpy( &target, res->ai_addr, target_len );
      freeaddrinfo( res );
    }

    /*
     * A TUN device makes the kernel on this machine the TCP endpoint.
     * At the listening end that is always possible.  At the connecting
     * end it only reaches targets that are this machine itself (and
     * only over IPv4); anywhere else would need this machine to route
     * and translate addresses, which is the administrator's business,
     * not ours.
     */
    bool want_tun = device == TUN && !tun_failed;
    if ( want_tun && role == CONNECT
         && !( target.sa.sa_family == AF_INET && is_local_address( target, target_len ) ) ) {
      want_tun = false;
      notes.push_back( "TCP " + specs[i] + ": not an IPv4 address of this machine itself; using sockets" );
    }

    if ( want_tun && !tun ) {
      try {
        tun.reset( new TunPort( this, role == LISTEN ) );
      } catch ( const NetworkException& e ) {
        tun_failed = true;
        want_tun = false;
        notes.push_back( std::string( "No TUN device (" ) + e.what() + "); using sockets" );
      }
    }

    if ( want_tun ) {
      try {
        const std::string where = ( role == LISTEN ) ? tun->add_listener( i, spec ) : tun->add_target( i, target );
        notes.push_back( "TCP " + specs[i] + ": " + tun->name()
                         + ( role == LISTEN ? ", connect to " + where : "" ) );
        port_of.push_back( tun.get() );
        continue;
      } catch ( const NetworkException& e ) {
        notes.push_back( "TCP " + specs[i] + ": " + e.what() + "; using sockets" );
      }
    }

    if ( role == LISTEN ) {
      const std::string where = adapter->add_listener( i, spec );
      notes.push_back( "TCP " + specs[i] + ": listening on " + where );
    } else {
      adapter->add_target( i, target, target_len );
    }
    port_of.push_back( adapter.get() );
  }
}

TCPForwarder::~TCPForwarder() {}

std::vector<int> TCPForwarder::fds( void ) const
{
  std::vector<int> ret = adapter->fds();
  if ( tun ) {
    const std::vector<int> more = tun->fds();
    ret.insert( ret.end(), more.begin(), more.end() );
  }
  return ret;
}

void TCPForwarder::read_fd( int fd )
{
  /* each port ignores descriptors that aren't its own */
  adapter->read_fd( fd );
  if ( tun ) {
    tun->read_fd( fd );
  }
}

void TCPForwarder::tick( void )
{
  const uint64_t now = timestamp();
  adapter->tick( now );
  if ( tun ) {
    tun->tick( now );
  }
}

int TCPForwarder::wait_time( void ) const
{
  const uint64_t now = timestamp();
  int ret = adapter->wait_time( now );
  if ( tun ) {
    ret = std::min( ret, tun->wait_time( now ) );
  }
  return ret;
}

size_t TCPForwarder::max_datagram( void ) const
{
  const size_t limit = link->sidechannel_max_payload();
  return limit > UDPForwarder::HEADER_LEN ? limit - UDPForwarder::HEADER_LEN : 0;
}

void TCPForwarder::to_network( uint8_t forward, const TCPInUDP& segment )
{
  if ( !link->sidechannel_ready() ) {
    return; /* the endpoints' retransmission will cope, or give up */
  }

  const std::string datagram = segment.to_datagram();
  if ( datagram.size() > max_datagram() ) {
    /* The ports hold the endpoints to a suitable MSS, so this is not expected. */
    if ( verbose && !dropped_oversize ) {
      fprintf( stderr,
               "TCP forwarding: dropping oversize segment (%d bytes)\n",
               static_cast<int>( datagram.size() ) );
    }
    dropped_oversize++;
    return;
  }

  const uint16_t listener_port = ( role == LISTEN ) ? segment.source_port : segment.dest_port;
  link->sidechannel_send(
    UDPForwarder::encode_frame( frame_type, forward, listener_port, next_seq++, datagram ) );
}

void TCPForwarder::sidechannel_recv( const std::string& payload )
{
  uint8_t type, forward;
  uint16_t listener_port;
  uint64_t seq;
  std::string datagram;

  if ( !UDPForwarder::decode_frame( payload, type, forward, listener_port, seq, datagram ) || type != frame_type
       || forward >= port_of.size() ) {
    return;
  }

  /* TCP would shrug off most replayed segments, but not, say, an old RST for a reused port. */
  if ( !replay.accept( seq ) ) {
    return;
  }

  TCPInUDP segment;
  const bool from_listener = ( role == CONNECT );
  if ( !TCPInUDP::from_datagram(
         from_listener ? listener_port : 0, from_listener ? 0 : listener_port, datagram, segment ) ) {
    return;
  }

  port_of[forward]->from_network( forward, segment );
}
