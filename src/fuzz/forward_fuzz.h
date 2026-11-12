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

#ifndef FORWARD_FUZZ_HPP
#define FORWARD_FUZZ_HPP

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Shared by the port-forwarding fuzzers.
 *
 * Their input is a short header and then a series of records, each a
 * kind byte, a length byte and that many bytes of body.  The kinds mean
 * different things to each fuzzer, but always include "these bytes, raw,
 * as if from the network" alongside better-formed input, so that the
 * fuzzer can both throw junk and get deep into the state machines.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace ForwardFuzz {

class Input
{
private:
  const uint8_t* data;
  size_t size;

public:
  Input( const uint8_t* s_data, size_t s_size ) : data( s_data ), size( s_size ) {}

  bool empty( void ) const { return size == 0; }

  uint8_t byte( void )
  {
    if ( size == 0 ) {
      return 0;
    }
    size--;
    return *data++;
  }

  std::string bytes( size_t n )
  {
    n = n < size ? n : size;
    const std::string ret( reinterpret_cast<const char*>( data ), n );
    data += n;
    size -= n;
    return ret;
  }

  /* The next record's kind (0-3) and body.  False when the input is used up. */
  bool record( unsigned int& kind, std::string& body )
  {
    if ( size < 2 ) {
      return false;
    }
    kind = byte() & 3;
    body = bytes( byte() );
    return true;
  }
};

/* What is wrong is a bug in what is being fuzzed, not in the input. */
inline void require( bool ok )
{
  if ( !ok ) {
    abort();
  }
}

inline uint8_t at( const std::string& s, size_t i )
{
  return i < s.size() ? static_cast<uint8_t>( s[i] ) : 0;
}

inline void set_nonblocking( int fd )
{
  const int flags = fcntl( fd, F_GETFL );
  fcntl( fd, F_SETFL, flags | O_NONBLOCK );
}

/* A socket on the loopback interface, bound to a port of the system's choosing. */
inline int loopback_socket( int type, uint16_t& port, struct sockaddr_in& addr )
{
  const int fd = socket( AF_INET, type, 0 );
  require( fd >= 0 );
  const int on = 1;
  setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof( on ) );
  memset( &addr, 0, sizeof( addr ) );
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  require( bind( fd, reinterpret_cast<struct sockaddr*>( &addr ), sizeof( addr ) ) == 0 );
  socklen_t len = sizeof( addr );
  require( getsockname( fd, reinterpret_cast<struct sockaddr*>( &addr ), &len ) == 0 );
  port = ntohs( addr.sin_port );
  return fd;
}

}

#endif
