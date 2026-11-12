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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/network/udpforward.h"

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

/* Joins two forwarders, standing in for an established mosh session. */
class TestLink : public SideChannelLink
{
public:
  SideChannelSink* peer;
  bool ready;
  size_t max_payload;
  std::deque<std::string> sent; /* everything that crossed, for replaying */

  TestLink() : peer( NULL ), ready( true ), max_payload( 1200 ), sent() {}

  bool sidechannel_ready( void ) const { return ready; }
  size_t sidechannel_max_payload( void ) const { return max_payload; }
  void sidechannel_send( const std::string& payload )
  {
    sent.push_back( payload );
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

  /* the largest datagram that fits goes through; one byte more is dropped */
  const size_t limit = to_server.max_payload - UDPForwarder::HEADER_LEN;
  send_to_port( app[0], listen_port, std::string( limit, 'x' ) );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( readable( target ) );
  CHECK( receive( target ) == std::string( limit, 'x' ) );
  CHECK( client.get_dropped_oversize() == 0 );

  send_to_port( app[0], listen_port, std::string( limit + 1, 'y' ) );
  CHECK( readable( listen_fd ) );
  client.read_fd( listen_fd );
  CHECK( !readable( target, 100 ) );
  CHECK( client.get_dropped_oversize() == 1 );

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

int main()
{
  test_spec();
  test_wire();
  test_replay();
  test_relay();
  return EXIT_SUCCESS;
}
