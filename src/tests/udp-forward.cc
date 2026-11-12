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

/* Tests UDP forwarding: specification parsing, the wire format,
   duplicate suppression, and a round trip through a pair of forwarders
   joined by an in-memory side channel. */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/network/forwarding.h"
#include "src/network/relay.h"
#include "src/network/udpforward.h"
#include "src/util/timestamp.h"

using namespace Network;

#define CHECK( x )                                                                                                 \
  do {                                                                                                             \
    if ( !( x ) ) {                                                                                                \
      fprintf( stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #x );                                      \
      exit( EXIT_FAILURE );                                                                                        \
    }                                                                                                              \
  } while ( 0 )

static bool spec_ok( const char* s )
{
  try {
    ForwardSpec spec( s );
    return true;
  } catch ( const NetworkException& ) {
    return false;
  }
}

static void test_spec( void )
{
  ForwardSpec a( "5353:ns.example.com:53" );
  CHECK( a.bind_host == "127.0.0.1" && a.bind_port == "5353" );
  CHECK( a.target_host == "ns.example.com" && a.target_port == "53" );

  ForwardSpec b( "[::1]:5353:[2001:db8::1]:53" );
  CHECK( b.bind_host == "::1" && b.bind_port == "5353" );
  CHECK( b.target_host == "2001:db8::1" && b.target_port == "53" );

  ForwardSpec c( "*:1:h:65535" );
  CHECK( c.bind_host == "*" && c.bind_port == "1" && c.target_port == "65535" );

  CHECK( !spec_ok( "" ) );
  CHECK( !spec_ok( "53" ) );
  CHECK( !spec_ok( "53:host" ) );
  CHECK( !spec_ok( "0:host:53" ) );
  CHECK( !spec_ok( "53:host:65536" ) );
  CHECK( !spec_ok( "53:host:dns" ) );
  CHECK( !spec_ok( "53::53" ) );
  CHECK( !spec_ok( "a:b:1:host:2" ) );
  CHECK( !spec_ok( "[::1:5353:host:53" ) );
}

static void test_wire( void )
{
  const std::string datagram( "hello\0world", 11 );
  std::string wire = UDPForwarder::encode( 7, 0xBEEF, 0x0102030405060708ULL, datagram );
  CHECK( wire.size() == UDPForwarder::HEADER_LEN + datagram.size() );
  CHECK( static_cast<uint8_t>( wire[0] ) == SIDECHANNEL_MAGIC );

  uint8_t forward;
  uint16_t flow;
  uint64_t seq;
  std::string out;
  CHECK( UDPForwarder::decode( wire, forward, flow, seq, out ) );
  CHECK( forward == 7 && flow == 0xBEEF && seq == 0x0102030405060708ULL && out == datagram );

  /* an empty datagram is a legitimate datagram */
  CHECK( UDPForwarder::decode( UDPForwarder::encode( 0, 0, 0, "" ), forward, flow, seq, out ) );
  CHECK( out.empty() );

  CHECK( !UDPForwarder::decode( wire.substr( 0, UDPForwarder::HEADER_LEN - 1 ), forward, flow, seq, out ) );
  wire[0] = 0;
  CHECK( !UDPForwarder::decode( wire, forward, flow, seq, out ) );
}

static void test_replay( void )
{
  const uint64_t W = ReplayWindow::WINDOW;

  ReplayWindow w;
  CHECK( w.accept( 5 ) );
  CHECK( !w.accept( 5 ) );
  CHECK( w.accept( 3 ) ); /* reordering is fine */
  CHECK( !w.accept( 3 ) );
  CHECK( w.accept( 6 ) );
  CHECK( w.accept( 4 ) );
  CHECK( !w.accept( 4 ) && !w.accept( 5 ) && !w.accept( 6 ) );

  /* everything is accepted exactly once across many windows */
  ReplayWindow x;
  for ( uint64_t i = 0; i < 5 * W; i++ ) {
    CHECK( x.accept( i ) );
    CHECK( !x.accept( i ) );
    if ( i >= 10 ) {
      CHECK( !x.accept( i - 10 ) );
    }
  }

  /* skipped numbers stay acceptable only while inside the window */
  ReplayWindow y;
  CHECK( y.accept( 0 ) );
  CHECK( y.accept( 2 ) );
  CHECK( y.accept( W ) );
  CHECK( y.accept( 1 ) ); /* W - 1 behind: still inside */
  CHECK( !y.accept( 0 ) );
  CHECK( y.accept( W + 2 ) );
  CHECK( !y.accept( 1 ) && !y.accept( 2 ) );
  CHECK( y.accept( 3 ) ); /* W - 1 behind */
  CHECK( y.accept( W + 3 ) );
  CHECK( !y.accept( 3 ) ); /* W behind: too old, and already seen anyway */

  /* a large jump forgets everything older */
  ReplayWindow z;
  CHECK( z.accept( 1 ) );
  CHECK( z.accept( 100 * W ) );
  CHECK( !z.accept( 1 ) );
  CHECK( !z.accept( 100 * W ) );
  CHECK( z.accept( 100 * W - 1 ) );
}

static std::string varied( size_t n )
{
  std::string s( n, '\0' );
  for ( size_t i = 0; i < n; i++ ) {
    s[i] = static_cast<char>( ( i * 2654435761u ) >> 11 );
  }
  return s;
}

/* Puts fragments back together, leaving out those listed.  True if that rebuilt the datagram. */
static bool reassembles( const std::vector<std::string>& fragments,
                         const std::string& expect,
                         int skip_a = -1,
                         int skip_b = -1,
                         bool backwards = false,
                         bool* used_parity = NULL )
{
  DatagramAssembly assembly;
  std::string out;
  bool parity = false;
  bool complete = false;
  for ( size_t n = 0; n < fragments.size(); n++ ) {
    const int i = backwards ? fragments.size() - 1 - n : n;
    if ( i == skip_a || i == skip_b ) {
      continue;
    }
    const DatagramAssembly::Result r = assembly.add( fragments[i], out, parity );
    CHECK( r != DatagramAssembly::REJECTED );
    if ( r == DatagramAssembly::COMPLETE ) {
      CHECK( out == expect );
      complete = true;
      break;
    }
  }
  if ( used_parity ) {
    *used_parity = parity;
  }
  return complete;
}

static void test_fragments( void )
{
  const size_t H = DatagramAssembly::FRAGMENT_HEADER_LEN;

  /* pieces are as equal as possible, and never over the limit */
  const std::string d = varied( 2500 );
  std::vector<std::string> f = DatagramAssembly::split( d, 1000 + H, false );
  CHECK( f.size() == 3 );
  CHECK( f[0].size() == 834 + H && f[1].size() == 833 + H && f[2].size() == 833 + H );
  CHECK( reassembles( f, d ) && reassembles( f, d, -1, -1, true ) );
  CHECK( !reassembles( f, d, 0 ) && !reassembles( f, d, 1 ) && !reassembles( f, d, 2 ) );

  /* one parity fragment, as long as the longest piece; any one fragment can go missing */
  f = DatagramAssembly::split( d, 1000 + H, true );
  CHECK( f.size() == 4 && f[3].size() == 834 + H );
  for ( int lost = 0; lost < 4; lost++ ) {
    bool parity;
    CHECK( reassembles( f, d, lost, -1, false, &parity ) && parity == ( lost < 3 ) );
    CHECK( reassembles( f, d, lost, -1, true ) );
  }
  CHECK( !reassembles( f, d, 0, 1 ) && !reassembles( f, d, 1, 3 ) && !reassembles( f, d, 0, 2 ) );

  /* every length around a boundary, with every single loss */
  for ( size_t len = 195; len <= 405; len++ ) {
    const std::string x = varied( len );
    f = DatagramAssembly::split( x, 100 + H, true );
    CHECK( f.size() == ( len + 99 ) / 100 + 1 || len <= 100 );
    for ( size_t i = 0; i < f.size(); i++ ) {
      CHECK( f[i].size() <= 100 + H );
      CHECK( reassembles( f, x, i ) );
    }
  }

  /* more than eight pieces: a parity fragment for each group of eight */
  const std::string big = varied( 20 * 500 );
  f = DatagramAssembly::split( big, 500 + H, true );
  CHECK( f.size() == 20 + 3 );
  CHECK( reassembles( f, big ) );
  CHECK( reassembles( f, big, 0, 8 ) );   /* one from each of two groups */
  CHECK( reassembles( f, big, 7, 19 ) );
  CHECK( !reassembles( f, big, 0, 7 ) );  /* two from one group */
  CHECK( !reassembles( f, big, 16, 19 ) );
  CHECK( !reassembles( f, big, 3, 20 ) ); /* a piece and its own group's parity */
  CHECK( reassembles( f, big, 3, 21 ) );  /* a piece and another group's parity */

  /* when parity is worth sending: when the datagram would otherwise be lost 2% of the time or more */
  CHECK( !UDPForwarder::parity_worthwhile( 0.0, 2 ) && !UDPForwarder::parity_worthwhile( 0.0, 200 ) );
  CHECK( !UDPForwarder::parity_worthwhile( 0.01, 2 ) && UDPForwarder::parity_worthwhile( 0.01, 3 ) );
  CHECK( !UDPForwarder::parity_worthwhile( 0.001, 20 ) && UDPForwarder::parity_worthwhile( 0.001, 21 ) );
  CHECK( UDPForwarder::parity_worthwhile( 0.05, 2 ) && UDPForwarder::parity_worthwhile( 1.0, 2 ) );

  /*
   * The most pieces a datagram can have is 226, with or without parity,
   * because the receiver keeps indexes free for parity either way.
   * (Found by fuzzing: the sender used to allow up to 255 without
   * parity, which the receiver would then refuse to put together.)
   */
  for ( int with_parity = 0; with_parity < 2; with_parity++ ) {
    const std::string most = varied( 226 * 10 );
    f = DatagramAssembly::split( most, 10 + H, with_parity );
    CHECK( f.size() == 226u + ( with_parity ? 29 : 0 ) );
    CHECK( reassembles( f, most ) );
    CHECK( DatagramAssembly::split( most + "x", 10 + H, with_parity ).empty() );
    CHECK( DatagramAssembly::piece_count( most.size(), 10 + H ) == 226 );
    CHECK( DatagramAssembly::piece_count( most.size() + 1, 10 + H ) == 0 );
  }

  /* what can't be done */
  CHECK( DatagramAssembly::split( d, H, false ).empty() );
  CHECK( DatagramAssembly::split( varied( 65507 ), 100 + H, false ).empty() ); /* too many fragments */
  CHECK( DatagramAssembly::split( varied( 65507 ), 500 + H, true ).size() == 132 + 17 );

  /* junk, and fragments of something else, are refused without disturbing what is there */
  f = DatagramAssembly::split( d, 1000 + H, true );
  const std::vector<std::string> other = DatagramAssembly::split( varied( 2400 ), 1000 + H, true );
  DatagramAssembly a;
  std::string out;
  bool parity;
  CHECK( a.empty() );
  CHECK( a.add( "", out, parity ) == DatagramAssembly::REJECTED );
  /* the wrong length for its place */
  CHECK( a.add( f[0].substr( 0, f[0].size() - 1 ), out, parity ) == DatagramAssembly::REJECTED );
  /* an index beyond the pieces and parity */
  CHECK( a.add( std::string( "\x05\x03\x09\xC4", 4 ) + std::string( 834, 'x' ), out, parity )
         == DatagramAssembly::REJECTED );
  /* a count of one: not fragmented at all */
  CHECK( a.add( std::string( "\x00\x01\x00\x05hello", 9 ), out, parity ) == DatagramAssembly::REJECTED );
  CHECK( a.empty() );
  CHECK( a.add( f[0], out, parity ) == DatagramAssembly::INCOMPLETE && !a.empty() );
  CHECK( a.add( other[1], out, parity ) == DatagramAssembly::REJECTED );
  CHECK( a.add( f[0], out, parity ) == DatagramAssembly::INCOMPLETE ); /* a duplicate changes nothing */
  CHECK( a.add( f[2], out, parity ) == DatagramAssembly::INCOMPLETE );
  CHECK( a.add( f[3], out, parity ) == DatagramAssembly::COMPLETE && out == d && parity );
}

/* Joins two forwarders, standing in for an established mosh session. */
class TestLink : public SideChannelLink
{
public:
  SideChannelSink* peer;
  bool ready;
  size_t max_payload;
  std::deque<std::string> sent; /* everything that crossed, for replaying */
  int lose;                     /* lose the datagram this many sends from now (0 is the next); -1 for none */
  double loss;                  /* what the peer is said to be missing of what we send */

  TestLink() : peer( NULL ), ready( true ), max_payload( 1200 ), sent(), lose( -1 ), loss( 0 ) {}

  bool sidechannel_ready( void ) const { return ready; }
  size_t sidechannel_max_payload( void ) const { return max_payload; }
  double sidechannel_loss( void ) const { return loss; }
  bool sidechannel_connected( void ) const { return true; }
  void sidechannel_send( const std::string& payload )
  {
    sent.push_back( payload );
    if ( lose >= 0 && lose-- == 0 ) {
      return;
    }
    peer->sidechannel_recv( payload );
  }

private:
  TestLink( const TestLink& );
  TestLink& operator=( const TestLink& );
};

static int udp_socket( uint16_t& port )
{
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  CHECK( fd >= 0 );
  struct sockaddr_in sin;
  memset( &sin, 0, sizeof( sin ) );
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  CHECK( bind( fd, reinterpret_cast<struct sockaddr*>( &sin ), sizeof( sin ) ) == 0 );
  socklen_t len = sizeof( sin );
  CHECK( getsockname( fd, reinterpret_cast<struct sockaddr*>( &sin ), &len ) == 0 );
  port = ntohs( sin.sin_port );
  return fd;
}

/* Some systems (macOS, the BSDs) won't send a UDP datagram anywhere near the protocol's limit. */
static size_t largest_datagram( void )
{
  uint16_t port;
  const int receiver = udp_socket( port );
  const int sender = udp_socket( port );
  struct sockaddr_in to;
  socklen_t len = sizeof( to );
  CHECK( getsockname( receiver, reinterpret_cast<struct sockaddr*>( &to ), &len ) == 0 );
  const std::string most( 65507, 'x' );
  const bool ok = sendto( sender, most.data(), most.size(), 0, reinterpret_cast<struct sockaddr*>( &to ), len )
                  == static_cast<ssize_t>( most.size() );
  close( sender );
  close( receiver );
  return ok ? most.size() : 9000;
}

static bool readable( int fd, int timeout_ms = 2000 )
{
  struct pollfd p;
  p.fd = fd;
  p.events = POLLIN;
  p.revents = 0;
  return poll( &p, 1, timeout_ms ) == 1;
}

static void send_to_port( int fd, uint16_t port, const std::string& s )
{
  struct sockaddr_in sin;
  memset( &sin, 0, sizeof( sin ) );
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  sin.sin_port = htons( port );
  CHECK( sendto( fd, s.data(), s.size(), 0, reinterpret_cast<struct sockaddr*>( &sin ), sizeof( sin ) )
         == static_cast<ssize_t>( s.size() ) );
}

static std::string receive( int fd, struct sockaddr_in* from = NULL )
{
  char buf[65536];
  struct sockaddr_in sin;
  socklen_t len = sizeof( sin );
  ssize_t n = recvfrom( fd, buf, sizeof( buf ), 0, reinterpret_cast<struct sockaddr*>( &sin ), &len );
  CHECK( n >= 0 );
  if ( from ) {
    *from = sin;
  }
  return std::string( buf, n );
}

static void test_relay( void )
{
  /* the service being forwarded to */
  uint16_t target_port;
  int target = udp_socket( target_port );

  /* find a free port for the client end to listen on */
  uint16_t listen_port;
  close( udp_socket( listen_port ) );

  char spec[64];
  snprintf( spec, sizeof( spec ), "%d:127.0.0.1:%d", listen_port, target_port );
  std::vector<std::string> specs( 1, spec );

  TestLink to_server, to_client;
  UDPForwarder client( &to_server, UDPForwarder::LISTEN, specs );
  UDPForwarder server( &to_client, UDPForwarder::CONNECT, specs );
  to_server.peer = &server;
  to_client.peer = &client;

  CHECK( client.fds().size() == 1 && server.fds().empty() );
  const int listen_fd = client.fds().at( 0 );

  /* two local applications, so two flows */
  uint16_t app_port[2];
  int app[2] = { udp_socket( app_port[0] ), udp_socket( app_port[1] ) };
  struct sockaddr_in server_side[2];

  for ( int i = 0; i < 2; i++ ) {
    const std::string request = i ? "request from app 1" : "request from app 0";
    send_to_port( app[i], listen_port, request );
    CHECK( readable( listen_fd ) );
    client.read_fd( listen_fd );

    CHECK( readable( target ) );
    CHECK( receive( target, &server_side[i] ) == request );
  }
  CHECK( client.flow_count() == 2 && server.flow_count() == 2 );
  CHECK( server_side[0].sin_port != server_side[1].sin_port ); /* each flow has its own socket */

  /* replies go back to the right application, in either order */
  for ( int i = 1; i >= 0; i-- ) {
    const std::string reply = i ? "reply to app 1" : "reply to app 0";
    CHECK( sendto( target,
                   reply.data(),
                   reply.size(),
                   0,
                   reinterpret_cast<struct sockaddr*>( &server_side[i] ),
                   sizeof( server_side[i] ) )
           == static_cast<ssize_t>( reply.size() ) );

    std::vector<int> fds = server.fds();
    CHECK( fds.size() == 2 );
    struct pollfd p[2] = { { fds[0], POLLIN, 0 }, { fds[1], POLLIN, 0 } };
    CHECK( poll( p, 2, 2000 ) == 1 );
    server.read_fd( p[0].revents ? fds[0] : fds[1] );

    CHECK( readable( app[i] ) );
    struct sockaddr_in from;
    CHECK( receive( app[i], &from ) == reply );
    CHECK( ntohs( from.sin_port ) == listen_port ); /* the reply comes from where the request went */
    CHECK( !readable( app[1 - i], 50 ) );
  }

  /* a replayed datagram is not delivered twice */
  CHECK( to_server.sent.size() == 2 );
  server.sidechannel_recv( to_server.sent[0] );
  server.sidechannel_recv( to_server.sent[1] );
  CHECK( !readable( target, 100 ) );

  /* the largest datagram that fits goes through whole */
  const size_t limit = to_server.max_payload - UDPForwarder::HEADER_LEN;
  size_t crossed = to_server.sent.size();
  send_to_port( app[0], listen_port, std::string( limit, 'x' ) );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( readable( target ) );
  CHECK( receive( target ) == std::string( limit, 'x' ) );
  CHECK( to_server.sent.size() == crossed + 1 && client.get_fragmented() == 0 );

  /* one byte more goes in two fragments, and arrives as one datagram */
  crossed = to_server.sent.size();
  send_to_port( app[0], listen_port, std::string( limit + 1, 'y' ) );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( readable( target ) );
  CHECK( receive( target ) == std::string( limit + 1, 'y' ) );
  CHECK( !readable( target, 50 ) );
  CHECK( to_server.sent.size() == crossed + 2 && client.get_fragmented() == 1 );
  CHECK( server.get_reassembled() == 1 && server.get_recovered() == 0 && server.partial_count() == 0 );

  /* replaying the fragments does not deliver it again */
  server.sidechannel_recv( to_server.sent[crossed] );
  server.sidechannel_recv( to_server.sent[crossed + 1] );
  CHECK( !readable( target, 50 ) && server.partial_count() == 0 );

  /* the largest datagram there is (or that this system will send), there and back */
  const std::string huge = varied( largest_datagram() );
  send_to_port( app[0], listen_port, huge );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( readable( target ) );
  struct sockaddr_in huge_from;
  CHECK( receive( target, &huge_from ) == huge );
  CHECK( sendto( target,
                 huge.data(),
                 huge.size(),
                 0,
                 reinterpret_cast<struct sockaddr*>( &huge_from ),
                 sizeof( huge_from ) )
         == static_cast<ssize_t>( huge.size() ) );
  {
    std::vector<int> fds = server.fds();
    struct pollfd p[2] = { { fds[0], POLLIN, 0 }, { fds[1], POLLIN, 0 } };
    CHECK( poll( p, 2, 2000 ) == 1 );
    server.read_fd( p[0].revents ? fds[0] : fds[1] );
  }
  CHECK( readable( app[0] ) );
  CHECK( receive( app[0] ) == huge );
  CHECK( client.get_reassembled() == 1 && client.get_dropped_oversize() == 0 );

  /* without parity, a lost fragment loses the datagram... */
  const std::string big = varied( 3000 ); /* three fragments */
  to_server.lose = 1;
  send_to_port( app[0], listen_port, big );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( !readable( target, 100 ) );
  CHECK( server.partial_count() == 1 && server.get_abandoned() == 0 );

  /* ...and what did arrive is forgotten after a while */
  usleep( ( UDPForwarder::REASSEMBLY_TIMEOUT + 100 ) * 1000 );
  freeze_timestamp();
  send_to_port( app[0], listen_port, big );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( readable( target ) );
  CHECK( receive( target ) == big );
  CHECK( server.partial_count() == 0 && server.get_abandoned() == 1 );

  /* with parity there is one more fragment, and losing any one of them does no harm */
  client.set_parity_mode( UDPForwarder::PARITY_ALWAYS );
  for ( int lost = 0; lost < 4; lost++ ) {
    const uint64_t recovered_before = server.get_recovered();
    crossed = to_server.sent.size();
    to_server.lose = lost;
    send_to_port( app[0], listen_port, big );
    CHECK( readable( listen_fd ) );
    client.read_fd( listen_fd );
    CHECK( to_server.sent.size() == crossed + 4 );
    CHECK( readable( target ) );
    CHECK( receive( target ) == big );
    CHECK( !readable( target, 20 ) );
    /* parity was needed unless it was the parity that got lost */
    CHECK( server.get_recovered() == recovered_before + ( lost < 3 ? 1 : 0 ) );
    CHECK( server.partial_count() == 0 );
  }

  /* losing two is still too many */
  to_server.lose = 0;
  send_to_port( app[0], listen_port, big );
  CHECK( readable( listen_fd ) );
  to_server.sent.clear();
  client.read_fd( listen_fd ); /* the first fragment is lost here... */
  CHECK( to_server.sent.size() == 4 );
  CHECK( readable( target ) ); /* ...so parity rebuilt it */
  CHECK( receive( target ) == big );
  UDPForwarder lonely( &to_client, UDPForwarder::CONNECT, specs ); /* a receiver that sees only half of them */
  lonely.sidechannel_recv( to_server.sent[1] );
  lonely.sidechannel_recv( to_server.sent[3] );
  CHECK( lonely.partial_count() == 1 && lonely.get_reassembled() == 0 );
  lonely.sidechannel_recv( to_server.sent[2] ); /* a third makes it whole */
  CHECK( lonely.partial_count() == 0 && lonely.get_reassembled() == 1 && lonely.get_recovered() == 1 );
  CHECK( readable( target ) );
  CHECK( receive( target ) == big );

  /*
   * Left to decide for itself, the sender goes by how much the session
   * is losing and how many fragments the datagram needs.
   */
  client.set_parity_mode( UDPForwarder::PARITY_AUTO );
  const std::string two = varied( 2000 ); /* two fragments; "big" is three */
  const struct
  {
    double loss;
    const std::string* datagram;
    bool parity;
  } cases[] = { { 0.0, &big, false },  { 0.0, &huge, false }, /* a clean path: never */
                { 0.01, &two, false }, { 0.01, &big, true },  /* 1%: from three fragments up */
                { 0.05, &two, true },  { 0.001, &big, false },
                { 0.001, &huge, huge.size() > 21 * 1200 } }; /* 0.1%: from 21 fragments up */
  for ( size_t i = 0; i < sizeof( cases ) / sizeof( cases[0] ); i++ ) {
    const uint64_t parity_before = client.get_with_parity();
    to_server.loss = cases[i].loss;
    send_to_port( app[0], listen_port, *cases[i].datagram );
    CHECK( readable( listen_fd ) );
    client.read_fd( listen_fd );
    CHECK( readable( target ) && receive( target ) == *cases[i].datagram );
    CHECK( client.get_with_parity() == parity_before + ( cases[i].parity ? 1 : 0 ) );
  }

  /* and small datagrams are sent whole as ever */
  crossed = to_server.sent.size();
  send_to_port( app[0], listen_port, "small" );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( readable( target ) && receive( target ) == "small" );
  CHECK( to_server.sent.size() == crossed + 1 );
  to_server.loss = 0;

  client.set_parity_mode( UDPForwarder::PARITY_NEVER );

  /* nothing is sent until the peer is known to support forwarding */
  to_server.ready = false;
  const size_t sent_before = to_server.sent.size();
  send_to_port( app[0], listen_port, "too early" );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( to_server.sent.size() == sent_before );
  CHECK( !readable( target, 100 ) );

  /* junk from the network is ignored */
  server.sidechannel_recv( "" );
  server.sidechannel_recv( std::string( 1, static_cast<char>( SIDECHANNEL_MAGIC ) ) );
  server.sidechannel_recv( UDPForwarder::encode( 9, 0, 1000, "no such forward" ) );
  client.sidechannel_recv( UDPForwarder::encode( 0, 999, 1000, "no such flow" ) );
  CHECK( client.flow_count() == 2 && server.flow_count() == 2 );

  close( target );
  close( app[0] );
  close( app[1] );
}

/* Datagrams on a stream, for the relay: each with its length before it. */
static void test_relay_frames( void )
{
  const std::string a = "hello", b = "", c = varied( 65535 );
  const std::string stream = relay_frame( a ) + relay_frame( b ) + relay_frame( c );
  CHECK( stream.size() == 5 + 0 + 65535 + 3 * 2 );
  CHECK( stream.substr( 0, 2 ) == std::string( "\x00\x05", 2 ) );

  /* however the stream is cut up on the way, the same datagrams come out */
  for ( size_t step = 1; step < 70000; step = step * 7 + 1 ) {
    RelayFrameParser parser;
    std::vector<std::string> out;
    std::string datagram;
    for ( size_t at = 0; at < stream.size(); at += step ) {
      parser.append( stream.data() + at, std::min( step, stream.size() - at ) );
      while ( parser.next( datagram ) ) {
        out.push_back( datagram );
      }
    }
    CHECK( out.size() == 3 && out[0] == a && out[1] == b && out[2] == c );
    CHECK( !parser.next( datagram ) );
  }
}

/* A remote forward (-RU) is a forward with the ends exchanged: the server listens, the client relays. */
static void test_remote( void )
{
  uint16_t target_port;
  const int target = udp_socket( target_port );
  uint16_t local_port, remote_port;
  close( udp_socket( local_port ) );
  close( udp_socket( remote_port ) );

  char spec[64];
  snprintf( spec, sizeof( spec ), "%d:127.0.0.1:%d", local_port, target_port );
  const std::vector<std::string> local_specs( 1, spec );
  snprintf( spec, sizeof( spec ), "%d:127.0.0.1:%d", remote_port, target_port );
  const std::vector<std::string> remote_specs( 1, spec );
  const std::vector<std::string> none;

  /* each end has both kinds, sharing one side channel */
  TestLink to_server, to_client;
  Forwarding client( &to_server, true, local_specs, none, none, remote_specs );
  Forwarding server( &to_client, false, local_specs, none, none, remote_specs );
  to_server.peer = server.sink();
  to_client.peer = client.sink();

  /* the client listens for the local forward and the server for the remote one */
  CHECK( client.fds().size() == 1 && server.fds().size() == 1 );

  uint16_t app_port;
  const int app = udp_socket( app_port );

  for ( int remote = 1; remote >= 0; remote-- ) {
    Forwarding& listener = remote ? server : client;
    Forwarding& relay = remote ? client : server;
    TestLink& outward = remote ? to_client : to_server;
    const int listen_fd = listener.fds().at( 0 );

    for ( int large = 0; large < 2; large++ ) {
      const std::string request
        = large ? varied( 5000 ) : std::string( remote ? "to the remote port" : "to the local port" );
      const size_t crossed = outward.sent.size();
      send_to_port( app, remote ? remote_port : local_port, request );
      CHECK( readable( listen_fd ) );
      listener.read_fd( listen_fd );
      CHECK( outward.sent.size() == crossed + ( large ? 5 : 1 ) );
      CHECK( readable( target ) );
      struct sockaddr_in from;
      CHECK( receive( target, &from ) == request );

      /* and back again */
      const std::string reply = large ? varied( 4000 ) : std::string( "reply" );
      CHECK( sendto( target,
                     reply.data(),
                     reply.size(),
                     0,
                     reinterpret_cast<struct sockaddr*>( &from ),
                     sizeof( from ) )
             == static_cast<ssize_t>( reply.size() ) );
      const std::vector<int> fds = relay.fds();
      std::vector<struct pollfd> polls( fds.size() );
      for ( size_t i = 0; i < fds.size(); i++ ) {
        polls[i].fd = fds[i];
        polls[i].events = POLLIN;
        polls[i].revents = 0;
      }
      CHECK( poll( polls.data(), polls.size(), 2000 ) == 1 );
      for ( size_t i = 0; i < fds.size(); i++ ) {
        if ( polls[i].revents ) {
          relay.read_fd( fds[i] );
        }
      }
      CHECK( readable( app ) );
      struct sockaddr_in back;
      CHECK( receive( app, &back ) == reply );
      CHECK( ntohs( back.sin_port ) == ( remote ? remote_port : local_port ) );
    }
  }
  CHECK( !readable( target, 50 ) && !readable( app, 50 ) );

  close( target );
  close( app );
}

/*
 * A connection works out how much of what is sent to it goes missing,
 * from the sequence numbers.  All connections in a process draw their
 * numbers from one counter, so here every datagram the server sends
 * leaves a gap in what the client sends, just as a lost one would.
 */
static void test_loss_measurement( void )
{
  Connection server( "127.0.0.1", NULL );
  Connection client( server.get_key().c_str(), "127.0.0.1", server.port().c_str() );
  CHECK( server.get_recv_loss() == 0 && client.get_recv_loss() == 0 );

  struct
  {
    int one_in; /* the share that goes "missing"; 0 for none */
    double low, high;
  } const phases[]
    = { { 0, 0.0, 0.0 }, { 10, 0.04, 0.06 }, { 10, 0.07, 0.08 }, { 0, 0.03, 0.04 }, { 4, 0.13, 0.15 } };
  /* (each measurement is averaged with what went before: 0, 10%/2, (5+10)/2, 7.5/2, (3.75+25)/2) */

  for ( size_t phase = 0; phase < sizeof( phases ) / sizeof( phases[0] ); phase++ ) {
    for ( int i = 1; i <= 200; i++ ) {
      if ( phases[phase].one_in && i % phases[phase].one_in == 0 ) {
        server.send( "this takes a sequence number" );
        CHECK( readable( client.fds().at( 0 ) ) );
        client.recv();
      } else {
        client.send( "hello" );
        CHECK( readable( server.fds().at( 0 ) ) );
        CHECK( server.recv() == "hello" );
      }
    }
    /* a measurement is taken when a datagram arrives after enough time has passed */
    usleep( 1050 * 1000 );
    freeze_timestamp();
    client.send( "hello" );
    CHECK( readable( server.fds().at( 0 ) ) );
    CHECK( server.recv() == "hello" );

    if ( !( server.get_recv_loss() >= phases[phase].low && server.get_recv_loss() <= phases[phase].high ) ) {
      fprintf( stderr, "phase %d: measured %f\n", static_cast<int>( phase ), server.get_recv_loss() );
    }
    CHECK( server.get_recv_loss() >= phases[phase].low && server.get_recv_loss() <= phases[phase].high );
  }
}

int main()
{
  test_spec();
  test_wire();
  test_replay();
  test_fragments();
  test_relay_frames();
  test_loss_measurement();
  test_relay();
  test_remote();
  return EXIT_SUCCESS;
}
