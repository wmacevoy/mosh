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
#include <csignal>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/crypto/prng.h"
#include "src/network/punch.h"

using namespace Network;

const char Network::PUNCH_MARK[8] = { 0, 'M', 'O', 'S', 'H', 'P', 'C', 'H' };

static const uint32_t STUN_COOKIE = 0x2112A442;
static const uint64_t DIRECTION = uint64_t( 1 ) << 63; /* set in the numbers of probes from the end that did not make the key */

std::string Network::stun_request( const char* txid )
{
  /* a Binding Request with no attributes */
  std::string m;
  m.push_back( 0x00 );
  m.push_back( 0x01 );
  m.push_back( 0x00 );
  m.push_back( 0x00 );
  for ( int shift = 24; shift >= 0; shift -= 8 ) {
    m.push_back( static_cast<char>( ( STUN_COOKIE >> shift ) & 0xFF ) );
  }
  m.append( txid, 12 );
  return m;
}

bool Network::stun_parse( const char* data, size_t len, Addr& mapped )
{
  const unsigned char* p = reinterpret_cast<const unsigned char*>( data );
  /* a Binding Success Response, with our cookie in it */
  if ( len < 20 || p[0] != 0x01 || p[1] != 0x01 || p[4] != 0x21 || p[5] != 0x12 || p[6] != 0xA4 || p[7] != 0x42 ) {
    return false;
  }
  const size_t body = ( static_cast<size_t>( p[2] ) << 8 ) | p[3];
  if ( body > len - 20 ) {
    return false;
  }
  bool found = false;
  for ( size_t at = 20; at + 4 <= 20 + body; ) {
    const unsigned int type = ( p[at] << 8 ) | p[at + 1];
    const size_t size = ( static_cast<size_t>( p[at + 2] ) << 8 ) | p[at + 3];
    if ( at + 4 + size > 20 + body ) {
      break;
    }
    const unsigned char* v = p + at + 4;
    /* XOR-MAPPED-ADDRESS, or (from servers of an older kind) MAPPED-ADDRESS; for IPv4 */
    if ( ( type == 0x0020 || type == 0x0001 ) && size >= 8 && v[1] == 0x01 && !( found && type == 0x0001 ) ) {
      uint16_t port = ( v[2] << 8 ) | v[3];
      uint32_t ip = ( static_cast<uint32_t>( v[4] ) << 24 ) | ( v[5] << 16 ) | ( v[6] << 8 ) | v[7];
      if ( type == 0x0020 ) {
        port ^= STUN_COOKIE >> 16;
        ip ^= STUN_COOKIE;
      }
      memset( &mapped, 0, sizeof( mapped ) );
      mapped.sin.sin_family = AF_INET;
      mapped.sin.sin_port = htons( port );
      mapped.sin.sin_addr.s_addr = htonl( ip );
      found = true;
    }
    at += 4 + ( ( size + 3 ) & ~static_cast<size_t>( 3 ) );
  }
  return found;
}

bool Network::parse_ip_port( const std::string& text, Addr& addr )
{
  const size_t colon = text.rfind( ':' );
  if ( colon == std::string::npos || colon == 0 || colon + 1 >= text.size() || text.size() - colon > 6
       || text.find_first_not_of( "0123456789", colon + 1 ) != std::string::npos ) {
    return false;
  }
  const long port = atol( text.c_str() + colon + 1 );
  memset( &addr, 0, sizeof( addr ) );
  if ( port < 1 || port > 65535 || inet_pton( AF_INET, text.substr( 0, colon ).c_str(), &addr.sin.sin_addr ) != 1 ) {
    return false;
  }
  addr.sin.sin_family = AF_INET;
  addr.sin.sin_port = htons( port );
  return true;
}

std::string Network::format_ip_port( const Addr& addr )
{
  char ip[INET_ADDRSTRLEN];
  if ( addr.sa.sa_family != AF_INET || !inet_ntop( AF_INET, &addr.sin.sin_addr, ip, sizeof( ip ) ) ) {
    return std::string();
  }
  return std::string( ip ) + ":" + std::to_string( ntohs( addr.sin.sin_port ) );
}

static bool same( const Addr& a, const Addr& b )
{
  return a.sin.sin_addr.s_addr == b.sin.sin_addr.s_addr && a.sin.sin_port == b.sin.sin_port;
}

/*
 * Ask the servers where datagrams from this socket appear to come from.
 * Looking their names up can take a while, and we have datagrams to
 * carry meanwhile, so another process does the asking; the answers come
 * to the socket, which is still ours to read.
 */
static void ask_stun( int sock, const std::vector<std::string>& servers )
{
  if ( servers.empty() ) {
    return;
  }
  char txid[12];
  PRNG().fill( txid, sizeof( txid ) );
  const std::string request = stun_request( txid );

  const pid_t pid = fork();
  if ( pid < 0 ) {
    return;
  }
  if ( pid > 0 ) {
    int status;
    waitpid( pid, &status, 0 ); /* (it leaves at once: see below) */
    return;
  }
  if ( fork() != 0 ) {
    _exit( 0 ); /* nobody need wait for the one that does the work */
  }
  signal( SIGALRM, SIG_DFL );
  alarm( 10 );
  for ( int round = 0; round < 2; round++ ) { /* (twice: a datagram can be lost) */
    for ( size_t i = 0; i < servers.size(); i++ ) {
      const size_t colon = servers[i].rfind( ':' );
      if ( colon == std::string::npos ) {
        continue;
      }
      struct addrinfo hints, *res = NULL;
      memset( &hints, 0, sizeof( hints ) );
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      if ( getaddrinfo( servers[i].substr( 0, colon ).c_str(), servers[i].substr( colon + 1 ).c_str(), &hints, &res )
           != 0 ) {
        continue;
      }
      sendto( sock, request.data(), request.size(), 0, res->ai_addr, res->ai_addrlen );
      freeaddrinfo( res );
    }
    usleep( 400000 );
  }
  _exit( 0 );
}

Punch::Punch( bool s_initiator, const std::string& key, const std::vector<std::string>& stun_servers, uint64_t now )
  : sock( socket( AF_INET, SOCK_DGRAM, 0 ) ), initiator( s_initiator ),
    session( new Crypto::Session( Crypto::Base64Key( key ) ) ), send_seq( 0 ), heard_seq( 0 ), candidates(),
    local_new(), local_all(), peer(), locked( false ), heard( 0 ), started( now ), last_probe( 0 )
{
  struct sockaddr_in any;
  memset( &any, 0, sizeof( any ) );
  any.sin_family = AF_INET;
  if ( sock < 0 || bind( sock, reinterpret_cast<struct sockaddr*>( &any ), sizeof( any ) ) < 0 ) {
    if ( sock >= 0 ) {
      close( sock );
    }
    throw NetworkException( "punch: socket", errno );
  }
  fcntl( sock, F_SETFL, fcntl( sock, F_GETFL ) | O_NONBLOCK );
  fcntl( sock, F_SETFD, FD_CLOEXEC );

  /*
   * Where we are on our own network, too.  If the other end is on the
   * same one (two machines in a room, behind one NAT), that is the way
   * to it: the outside address of a NAT is seldom any use from inside.
   */
  struct ifaddrs* interfaces = NULL;
  if ( getifaddrs( &interfaces ) == 0 ) {
    for ( struct ifaddrs* i = interfaces; i; i = i->ifa_next ) {
      if ( !i->ifa_addr || i->ifa_addr->sa_family != AF_INET || !( i->ifa_flags & IFF_UP )
           || ( i->ifa_flags & IFF_LOOPBACK ) ) {
        continue;
      }
      Addr mine;
      memset( &mine, 0, sizeof( mine ) );
      memcpy( &mine.sin, i->ifa_addr, sizeof( mine.sin ) );
      mine.sin.sin_port = htons( local_port() );
      const std::string text = format_ip_port( mine );
      if ( !text.empty() && local_all.size() < MAX_CANDIDATES / 2 ) {
        local_all.push_back( text );
        local_new.push_back( text );
      }
    }
    freeifaddrs( interfaces );
  }

  ask_stun( sock, stun_servers );
}

Punch::~Punch()
{
  close( sock );
}

uint16_t Punch::local_port( void ) const
{
  struct sockaddr_in sin;
  socklen_t len = sizeof( sin );
  if ( getsockname( sock, reinterpret_cast<struct sockaddr*>( &sin ), &len ) < 0 ) {
    return 0;
  }
  return ntohs( sin.sin_port );
}

void Punch::add_candidate( const std::string& ip_port )
{
  Addr addr;
  if ( !parse_ip_port( ip_port, addr ) || candidates.size() >= MAX_CANDIDATES ) {
    return;
  }
  for ( size_t i = 0; i < candidates.size(); i++ ) {
    if ( same( candidates[i], addr ) ) {
      return;
    }
  }
  candidates.push_back( addr );
  last_probe = 0; /* try it now */
}

std::vector<std::string> Punch::take_local_candidates( void )
{
  std::vector<std::string> ret;
  ret.swap( local_new );
  return ret;
}

void Punch::probe( char type, const Addr& to )
{
  const uint64_t seq = ( ++send_seq ) | ( initiator ? 0 : DIRECTION );
  std::string packet( PUNCH_MARK, sizeof( PUNCH_MARK ) );
  packet += session->encrypt( Crypto::Message( Crypto::Nonce( seq ), std::string( 1, type ) ) );
  sendto( sock, packet.data(), packet.size(), 0, &to.sa, sizeof( to.sin ) );
}

void Punch::tick( uint64_t now )
{
  if ( open( now ) ) {
    if ( now - last_probe >= OPEN_EVERY ) {
      last_probe = now;
      probe( '?', peer );
    }
    return;
  }
  /* No way through, that we know of.  Try everywhere the other end might be. */
  const uint64_t every = ( now - started < FAST_FOR ) ? FAST_EVERY : SLOW_EVERY;
  if ( now - last_probe >= every ) {
    last_probe = now;
    for ( size_t i = 0; i < candidates.size(); i++ ) {
      probe( '?', candidates[i] );
    }
    if ( locked ) {
      probe( '?', peer );
    }
  }
}

Punch::Got Punch::receive( uint64_t now, std::string& datagram )
{
  char buf[65536];
  Addr from;
  socklen_t from_len = sizeof( from );
  const ssize_t n = recvfrom( sock, buf, sizeof( buf ), 0, &from.sa, &from_len );
  if ( n < 0 ) {
    return ( errno == EAGAIN || errno == EWOULDBLOCK ) ? NOTHING : OTHER;
  }
  if ( from.sa.sa_family != AF_INET ) {
    return OTHER;
  }

  if ( static_cast<size_t>( n ) > sizeof( PUNCH_MARK ) && memcmp( buf, PUNCH_MARK, sizeof( PUNCH_MARK ) ) == 0 ) {
    /* A probe.  Only the other end can have sealed it, and only once. */
    try {
      const Crypto::Message m = session->decrypt( buf + sizeof( PUNCH_MARK ), n - sizeof( PUNCH_MARK ) );
      const uint64_t seq = m.nonce.val();
      const bool theirs = ( ( seq & DIRECTION ) != 0 ) == initiator;
      if ( !theirs || ( seq & ~DIRECTION ) <= heard_seq || m.text.size() != 1 ) {
        return OTHER;
      }
      heard_seq = seq & ~DIRECTION;
      peer = from; /* wherever it is now, it is there */
      locked = true;
      heard = now;
      if ( m.text[0] == '?' ) {
        probe( '!', peer );
      } else if ( m.text[0] == '.' ) {
        return GOODBYE;
      }
    } catch ( const Crypto::CryptoException& e ) {
      /* not from the other end */
    }
    return OTHER;
  }

  Addr mapped;
  if ( stun_parse( buf, n, mapped ) ) {
    const std::string text = format_ip_port( mapped );
    bool known = text.empty();
    for ( size_t i = 0; i < local_all.size(); i++ ) {
      known = known || local_all[i] == text;
    }
    if ( !known && local_all.size() < MAX_CANDIDATES ) {
      local_all.push_back( text );
      local_new.push_back( text );
    }
    return OTHER;
  }

  if ( locked && same( from, peer ) ) {
    heard = now;
    datagram.assign( buf, n );
    return DATA;
  }
  return OTHER;
}

void Punch::send( const std::string& datagram )
{
  if ( locked ) {
    sendto( sock, datagram.data(), datagram.size(), 0, &peer.sa, sizeof( peer.sin ) );
  }
}

void Punch::goodbye( void )
{
  if ( locked ) {
    probe( '.', peer );
  }
}
