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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

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

#include <map>
#include <set>

#include "src/crypto/prng.h"
#include "src/network/punch.h"

using namespace Network;

const char Network::PUNCH_MARK[8] = { 0, 'M', 'O', 'S', 'H', 'P', 'C', 'H' };
const char Network::FORWARD_MARK[8] = { 0, 'M', 'O', 'S', 'H', 'F', 'W', 'D' };

static const uint32_t STUN_COOKIE = 0x2112A442;
static const uint64_t DIRECTION = uint64_t( 1 ) << 63; /* set in the numbers of probes from the end that did not make the key */

static bool same( const Addr& a, const Addr& b )
{
  return a.sin.sin_addr.s_addr == b.sin.sin_addr.s_addr && a.sin.sin_port == b.sin.sin_port;
}

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

/* The eight bytes that the key gives for four. */
static std::string stun_mark( const char* four, const std::string& key )
{
  uint64_t n = 0;
  for ( int i = 0; i < 4; i++ ) {
    n = ( n << 8 ) | static_cast<unsigned char>( four[i] );
  }
  Crypto::Session session( ( Crypto::Base64Key( key ) ) );
  /* (sealing nothing, under a number: what comes back is the number and a tag that only the key makes) */
  const std::string sealed = session.encrypt( Crypto::Message( Crypto::Nonce( n ), "" ) );
  return sealed.substr( sealed.size() - 8 );
}

std::string Network::stun_keyed_txid( const std::string& key )
{
  char four[4];
  PRNG().fill( four, sizeof( four ) );
  return std::string( four, 4 ) + stun_mark( four, key );
}

bool Network::stun_txid_has_key( const char* txid, const std::string& key )
{
  const std::string mark = stun_mark( txid, key );
  unsigned char difference = 0;
  for ( size_t i = 0; i < 8; i++ ) {
    difference |= static_cast<unsigned char>( mark[i] ^ txid[4 + i] );
  }
  return difference == 0;
}

int Network::stun_serve( const char* port, const std::string& key )
{
  struct addrinfo hints, *res = NULL;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  if ( getaddrinfo( NULL, port, &hints, &res ) != 0 ) {
    fprintf( stderr, "mosh-server stun: %s is not a port\n", port );
    return 1;
  }
  const int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if ( sock < 0 || bind( sock, res->ai_addr, res->ai_addrlen ) < 0 ) {
    perror( "mosh-server stun: bind" );
    return 1;
  }
  freeaddrinfo( res );
  if ( !key.empty() ) {
    try {
      stun_keyed_txid( key );
    } catch ( const std::exception& e ) {
      fprintf( stderr, "mosh-server stun: MOSH_STUN_KEY is not a key (mosh-server stun-key makes one)\n" );
      return 1;
    }
  }

  /* The pairs of ends we pass datagrams between: for each, the two addresses that have lately named it. */
  struct End
  {
    Addr addr;
    time_t heard;
  };
  struct Pair
  {
    End ends[2];
  };
  std::map<std::string, Pair> pairs;
  std::set<std::string> proofs; /* ones already found good, to save working them out again */
  const size_t MAX_PAIRS = 4096;
  const time_t PAIR_IDLE = 120;
  time_t swept = 0;

  const unsigned int PER_SECOND = 200;
  time_t second = 0;
  unsigned int answered = 0;
  while ( true ) {
    char request[65536];
    Addr from;
    socklen_t from_len = sizeof( from );
    const ssize_t n = recvfrom( sock, request, sizeof( request ), 0, &from.sa, &from_len );
    if ( n < 0 ) {
      if ( errno == EINTR ) {
        continue;
      }
      return 1;
    }

    /* To be passed on?  Only for those with the key. */
    if ( !key.empty() && static_cast<size_t>( n ) >= FORWARD_HEADER && from.sa.sa_family == AF_INET
         && memcmp( request, FORWARD_MARK, sizeof( FORWARD_MARK ) ) == 0 ) {
      const std::string proof( request + 8, 12 );
      if ( proofs.find( proof ) == proofs.end() ) {
        try {
          if ( !stun_txid_has_key( proof.data(), key ) ) {
            continue;
          }
        } catch ( const std::exception& e ) {
          continue;
        }
        if ( proofs.size() >= MAX_PAIRS ) {
          proofs.clear();
        }
        proofs.insert( proof );
      }
      const time_t now = time( NULL );
      if ( now - swept > 30 ) {
        swept = now;
        for ( std::map<std::string, Pair>::iterator i = pairs.begin(); i != pairs.end(); ) {
          if ( now - std::max( i->second.ends[0].heard, i->second.ends[1].heard ) > PAIR_IDLE ) {
            pairs.erase( i++ );
          } else {
            i++;
          }
        }
      }
      const std::string name( request + 20, 16 );
      std::map<std::string, Pair>::iterator found = pairs.find( name );
      if ( found == pairs.end() ) {
        if ( pairs.size() >= MAX_PAIRS ) {
          continue;
        }
        Pair fresh;
        memset( &fresh, 0, sizeof( fresh ) );
        found = pairs.insert( std::make_pair( name, fresh ) ).first;
      }
      Pair& pair = found->second;
      /* Which end is this?  One we know; or a new one, in place of whichever has been quiet longest. */
      int which = -1;
      for ( int i = 0; i < 2; i++ ) {
        if ( pair.ends[i].heard && same( pair.ends[i].addr, from ) ) {
          which = i;
        }
      }
      if ( which < 0 ) {
        which = pair.ends[0].heard <= pair.ends[1].heard ? 0 : 1;
        pair.ends[which].addr = from;
      }
      pair.ends[which].heard = now;
      const End& other = pair.ends[1 - which];
      if ( other.heard && now - other.heard <= PAIR_IDLE ) {
        sendto( sock, request, n, 0, &other.addr.sa, sizeof( other.addr.sin ) );
      }
      continue;
    }
    /* a Binding Request, with the cookie: and nothing longer than one need be */
    const unsigned char* p = reinterpret_cast<const unsigned char*>( request );
    if ( n < 20 || n > 200 || p[0] != 0x00 || p[1] != 0x01 || p[4] != 0x21 || p[5] != 0x12 || p[6] != 0xA4
         || p[7] != 0x42 || from.sa.sa_family != AF_INET ) {
      continue;
    }
    const time_t now = time( NULL );
    if ( now != second ) {
      second = now;
      answered = 0;
    }
    if ( ++answered > PER_SECOND ) {
      continue;
    }
    try {
      if ( !key.empty() && !stun_txid_has_key( request + 8, key ) ) {
        continue; /* not one of ours: and no answer says so, or that we are here at all */
      }
    } catch ( const std::exception& e ) {
      continue;
    }

    /* XOR-MAPPED-ADDRESS: where it came from, disguised from anything in between that rewrites addresses it sees */
    const uint16_t port_x = ntohs( from.sin.sin_port ) ^ ( STUN_COOKIE >> 16 );
    const uint32_t ip_x = ntohl( from.sin.sin_addr.s_addr ) ^ STUN_COOKIE;
    std::string answer;
    answer.push_back( 0x01 );
    answer.push_back( 0x01 );
    answer.push_back( 0x00 );
    answer.push_back( 0x0c );
    answer.append( request + 4, 16 );
    const char attribute[4] = { 0x00, 0x20, 0x00, 0x08 };
    answer.append( attribute, 4 );
    answer.push_back( 0x00 );
    answer.push_back( 0x01 );
    answer.push_back( static_cast<char>( port_x >> 8 ) );
    answer.push_back( static_cast<char>( port_x & 0xFF ) );
    for ( int shift = 24; shift >= 0; shift -= 8 ) {
      answer.push_back( static_cast<char>( ( ip_x >> shift ) & 0xFF ) );
    }
    sendto( sock, answer.data(), answer.size(), 0, &from.sa, from_len );
  }
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

/*
 * Ask the servers where datagrams from this socket appear to come from.
 * Looking their names up can take a while, and we have datagrams to
 * carry meanwhile, so another process does the asking; the answers come
 * to the socket, which is still ours to read.
 */
static void ask_stun( int sock, const std::vector<std::string>& servers, const std::string& key )
{
  if ( servers.empty() ) {
    return;
  }
  char txid[12];
  PRNG().fill( txid, sizeof( txid ) );
  std::string request = stun_request( txid );
  if ( !key.empty() ) {
    try {
      request = stun_request( stun_keyed_txid( key ).data() );
    } catch ( const std::exception& e ) {
      /* not a key: then ask as anyone would */
    }
  }

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

Punch::Punch( bool s_initiator,
              const std::string& key,
              const std::vector<std::string>& stun_servers,
              uint64_t now,
              const std::string& stun_key )
  : sock( socket( AF_INET, SOCK_DGRAM, 0 ) ), initiator( s_initiator ),
    session( new Crypto::Session( Crypto::Base64Key( key ) ) ), send_seq( 0 ), heard_seq( 0 ), candidates(),
    local_new(), local_all(), peer(), peer_via( false ), locked( false ), heard( 0 ), started( now ),
    last_probe( 0 ), last_direct_probe( 0 ), forward_proof(), forward_pair(), forwarders()
{
  if ( !stun_key.empty() ) {
    /*
     * A server that wants a key will also pass datagrams on for us.  What
     * shows it the key; and a name for the two of us, which is something
     * both ends can work out and nobody else: the seal on nothing at all.
     */
    try {
      forward_proof = stun_keyed_txid( stun_key );
      const std::string sealed = session->encrypt( Crypto::Message( Crypto::Nonce( 0 ), "" ) );
      forward_pair = sealed.substr( sealed.size() - 16 );
    } catch ( const std::exception& e ) {
      forward_proof.clear();
    }
  }

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

  ask_stun( sock, stun_servers, stun_key );
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

/* Straight to an address; or to a server there, to be passed on to the other end. */
void Punch::transmit( const std::string& packet, const Addr& to, bool via )
{
  if ( via ) {
    const std::string wrapped = std::string( FORWARD_MARK, sizeof( FORWARD_MARK ) ) + forward_proof + forward_pair + packet;
    sendto( sock, wrapped.data(), wrapped.size(), 0, &to.sa, sizeof( to.sin ) );
  } else {
    sendto( sock, packet.data(), packet.size(), 0, &to.sa, sizeof( to.sin ) );
  }
}

void Punch::probe( char type, const Addr& to, bool via )
{
  const uint64_t seq = ( ++send_seq ) | ( initiator ? 0 : DIRECTION );
  std::string packet( PUNCH_MARK, sizeof( PUNCH_MARK ) );
  packet += session->encrypt( Crypto::Message( Crypto::Nonce( seq ), std::string( 1, type ) ) );
  transmit( packet, to, via );
}

void Punch::tick( uint64_t now )
{
  if ( open( now ) ) {
    if ( now - last_probe >= OPEN_EVERY ) {
      last_probe = now;
      probe( '?', peer, peer_via );
    }
    /* By way of a server is second best: go on looking, now and then, for a way straight there. */
    if ( peer_via && now - last_direct_probe >= SLOW_EVERY ) {
      last_direct_probe = now;
      for ( size_t i = 0; i < candidates.size(); i++ ) {
        probe( '?', candidates[i], false );
      }
    }
    return;
  }
  /* No way through, that we know of.  Try everywhere the other end might be, and by way of whoever will pass it on. */
  const uint64_t every = ( now - started < FAST_FOR ) ? FAST_EVERY : SLOW_EVERY;
  if ( now - last_probe >= every ) {
    last_probe = now;
    for ( size_t i = 0; i < candidates.size(); i++ ) {
      probe( '?', candidates[i], false );
    }
    for ( size_t i = 0; i < forwarders.size(); i++ ) {
      probe( '?', forwarders[i], true );
    }
    if ( locked && !peer_via ) {
      probe( '?', peer, false );
    }
  }
}

Punch::Got Punch::receive( uint64_t now, std::string& datagram )
{
  char whole[65536];
  Addr from;
  socklen_t from_len = sizeof( from );
  ssize_t n = recvfrom( sock, whole, sizeof( whole ), 0, &from.sa, &from_len );
  if ( n < 0 ) {
    return ( errno == EAGAIN || errno == EWOULDBLOCK ) ? NOTHING : OTHER;
  }
  if ( from.sa.sa_family != AF_INET ) {
    return OTHER;
  }

  /* Passed on by a server, from the other end?  Then what matters is what is inside. */
  const char* buf = whole;
  bool via = false;
  if ( !forward_proof.empty() && static_cast<size_t>( n ) >= FORWARD_HEADER
       && memcmp( whole, FORWARD_MARK, sizeof( FORWARD_MARK ) ) == 0 ) {
    if ( memcmp( whole + 20, forward_pair.data(), 16 ) != 0 ) {
      return OTHER;
    }
    via = true;
    buf = whole + FORWARD_HEADER;
    n -= FORWARD_HEADER;
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
      /*
       * Wherever it is now, it is there: except that while there is a way
       * straight to it, hearing from it by way of a server as well is no
       * reason to go the long way round.
       */
      if ( !( via && locked && !peer_via && now - heard < OPEN_FOR ) ) {
        peer = from;
        peer_via = via;
        locked = true;
        heard = now;
      }
      if ( m.text[0] == '?' ) {
        probe( '!', from, via ); /* (answered the way it came) */
      } else if ( m.text[0] == '.' ) {
        return GOODBYE;
      }
    } catch ( const Crypto::CryptoException& e ) {
      /* not from the other end */
    }
    return OTHER;
  }
  if ( via ) {
    if ( locked && peer_via && same( from, peer ) ) {
      heard = now;
      datagram.assign( buf, n );
      return DATA;
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
    /* A server that took our key will pass datagrams on, too. */
    if ( !forward_proof.empty() ) {
      bool have = false;
      for ( size_t i = 0; i < forwarders.size(); i++ ) {
        have = have || same( forwarders[i], from );
      }
      if ( !have && forwarders.size() < 4 ) {
        forwarders.push_back( from );
        last_probe = 0;
      }
    }
    return OTHER;
  }

  if ( locked && !peer_via && same( from, peer ) ) {
    heard = now;
    datagram.assign( buf, n );
    return DATA;
  }
  return OTHER;
}

void Punch::send( const std::string& datagram )
{
  if ( locked ) {
    transmit( datagram, peer, peer_via );
  }
}

void Punch::goodbye( void )
{
  if ( locked ) {
    probe( '.', peer, peer_via );
  }
}
