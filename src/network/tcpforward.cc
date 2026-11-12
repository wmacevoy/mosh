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
#include "src/util/timestamp.h"

using namespace Network;

TCPForwarder::TCPForwarder( SideChannelLink* s_link,
                            Role s_role,
                            const std::vector<std::string>& specs,
                            uint8_t s_frame_type )
  : link( s_link ), role( s_role ), frame_type( s_frame_type ), verbose( 0 ), adapter(), forwards( 0 ),
    next_seq( 0 ), replay(), dropped_oversize( 0 )
{
  if ( specs.size() > MAX_FORWARDS ) {
    throw NetworkException( "TCP forwarding: too many forwarding specifications", 0 );
  }

  adapter.reset( new AdapterPort( this, role == LISTEN ) );

  for ( size_t i = 0; i < specs.size(); i++ ) {
    const ForwardSpec spec( specs[i] );

    if ( role == LISTEN ) {
      adapter->add_listener( i, spec );
    } else {
      /* the connecting end needs to know where to connect */
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
      Addr target;
      memset( &target, 0, sizeof( target ) );
      const socklen_t target_len = res->ai_addrlen;
      memcpy( &target, res->ai_addr, target_len );
      freeaddrinfo( res );

      adapter->add_target( i, target, target_len );
    }
    forwards++;
  }
}

TCPForwarder::~TCPForwarder() {}

void TCPForwarder::stream_spawner( const std::function<int()>& spawn )
{
  adapter->add_spawner( 0, spawn );
  forwards = 1;
}

bool TCPForwarder::stream_open( int fd )
{
  forwards = 1;
  return adapter->open_with( 0, fd, timestamp() );
}

size_t TCPForwarder::connection_count( void ) const
{
  return adapter->connection_count();
}

std::vector<int> TCPForwarder::fds( void ) const
{
  return adapter->fds();
}

void TCPForwarder::read_fd( int fd )
{
  adapter->read_fd( fd ); /* which ignores descriptors that aren't its own */
}

void TCPForwarder::tick( void )
{
  adapter->tick( timestamp() );
}

int TCPForwarder::wait_time( void ) const
{
  return adapter->wait_time( timestamp() );
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
    /* The adapter keeps its segments small enough, so this is not expected. */
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
       || forward >= forwards ) {
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

  adapter->from_network( forward, segment );
}
