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

/* Tests TCP forwarding: real TCP connections through a pair of
   forwarders joined by an in-memory side channel that can lose
   datagrams. */

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/network/forwarding.h"
#include "src/network/tcpadapter.h"
#include "src/network/tcpforward.h"
#include "src/util/timestamp.h"

using namespace Network;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define CHECK( x )                                                                                                 \
  do {                                                                                                             \
    if ( !( x ) ) {                                                                                                \
      fprintf( stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #x );                                      \
      exit( EXIT_FAILURE );                                                                                        \
    }                                                                                                              \
  } while ( 0 )

/* One direction of an established mosh session.  Delivery is deferred, as it is over a network. */
class TestLink : public SideChannelLink
{
public:
  std::deque<std::string> queue;
  bool ready;
  size_t max_payload;
  unsigned int lose_one_in; /* 0 for none */
  unsigned int sent, lost;
  uint32_t random_state;

  TestLink()
    : queue(), ready( true ), max_payload( 1200 ), lose_one_in( 0 ), sent( 0 ), lost( 0 ), random_state( 1 )
  {}

  bool sidechannel_ready( void ) const { return ready; }
  size_t sidechannel_max_payload( void ) const { return max_payload; }
  double sidechannel_loss( void ) const { return 0; }
  void sidechannel_send( const std::string& payload )
  {
    CHECK( payload.size() <= max_payload );
    sent++;
    random_state = random_state * 1103515245 + 12345;
    if ( lose_one_in && ( random_state >> 16 ) % lose_one_in == 0 ) {
      lost++;
      return;
    }
    queue.push_back( payload );
  }

  void deliver_to( SideChannelSink& sink )
  {
    while ( !queue.empty() ) {
      const std::string payload = queue.front();
      queue.pop_front();
      sink.sidechannel_recv( payload );
    }
  }
};

static int listening_socket( uint16_t& port )
{
  int fd = socket( AF_INET, SOCK_STREAM, 0 );
  CHECK( fd >= 0 );
  struct sockaddr_in sin;
  memset( &sin, 0, sizeof( sin ) );
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  CHECK( bind( fd, reinterpret_cast<struct sockaddr*>( &sin ), sizeof( sin ) ) == 0 );
  CHECK( listen( fd, 8 ) == 0 );
  socklen_t len = sizeof( sin );
  CHECK( getsockname( fd, reinterpret_cast<struct sockaddr*>( &sin ), &len ) == 0 );
  port = ntohs( sin.sin_port );
  return fd;
}

static uint16_t unused_port( void )
{
  uint16_t port;
  close( listening_socket( port ) );
  return port;
}

static char pattern( size_t i )
{
  return static_cast<char>( ( i * 2654435761u ) >> 13 );
}

static bool write_all( int fd, const std::string& s )
{
  size_t done = 0;
  while ( done < s.size() ) {
    ssize_t n = send( fd, s.data() + done, s.size() - done, MSG_NOSIGNAL );
    if ( n <= 0 ) {
      return false;
    }
    done += n;
  }
  return true;
}

static std::string read_to_end( int fd )
{
  std::string ret;
  char buf[65536];
  ssize_t n;
  while ( ( n = recv( fd, buf, sizeof( buf ), 0 ) ) > 0 ) {
    ret.append( buf, n );
  }
  return ret;
}

/* The service being forwarded to: reads a whole stream, then answers with its complement. */
static pid_t start_target( int listener )
{
  pid_t pid = fork();
  CHECK( pid >= 0 );
  if ( pid == 0 ) {
    alarm( 120 );
    while ( true ) {
      int fd = accept( listener, NULL, NULL );
      if ( fd < 0 ) {
        _exit( 1 );
      }
      std::string data = read_to_end( fd );
      for ( size_t i = 0; i < data.size(); i++ ) {
        data[i] = ~data[i];
      }
      write_all( fd, data );
      close( fd );
    }
  }
  return pid;
}

enum Outcome
{
  DELIVERED = 10, /* everything went there and came back intact */
  CORRUPTED,
  REFUSED, /* could not connect, or the connection was closed or reset with nothing received */
};

/* The local application: sends a stream, closes its side, and checks what comes back. */
static pid_t start_application( uint16_t port, size_t size )
{
  pid_t pid = fork();
  CHECK( pid >= 0 );
  if ( pid == 0 ) {
    alarm( 120 );
    int fd = socket( AF_INET, SOCK_STREAM, 0 );
    struct sockaddr_in sin;
    memset( &sin, 0, sizeof( sin ) );
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
    sin.sin_port = htons( port );
    if ( connect( fd, reinterpret_cast<struct sockaddr*>( &sin ), sizeof( sin ) ) < 0 ) {
      _exit( REFUSED );
    }

    std::string data( size, 0 );
    for ( size_t i = 0; i < size; i++ ) {
      data[i] = pattern( i );
    }
    const bool wrote = write_all( fd, data );
    shutdown( fd, SHUT_WR );
    const std::string back = read_to_end( fd );
    if ( back.empty() ) {
      _exit( REFUSED );
    }
    if ( !wrote || back.size() != size ) {
      _exit( CORRUPTED );
    }
    for ( size_t i = 0; i < size; i++ ) {
      if ( back[i] != static_cast<char>( ~pattern( i ) ) ) {
        _exit( CORRUPTED );
      }
    }
    _exit( DELIVERED );
  }
  return pid;
}

static SideChannelSink& sink_of( TCPForwarder& f )
{
  return f;
}

static SideChannelSink& sink_of( Forwarding& f )
{
  return *f.sink();
}

/* Runs both ends' event loops until the application exits; returns its exit status. */
template<class End>
static int pump( End& client, TestLink& to_server, End& server, TestLink& to_client, pid_t app )
{
  for ( int rounds = 0; rounds < 200000; rounds++ ) {
    freeze_timestamp();

    std::vector<int> fds = client.fds();
    const size_t client_fds = fds.size();
    const std::vector<int> more = server.fds();
    fds.insert( fds.end(), more.begin(), more.end() );

    std::vector<struct pollfd> polls( fds.size() );
    for ( size_t i = 0; i < fds.size(); i++ ) {
      polls[i].fd = fds[i];
      polls[i].events = POLLIN;
      polls[i].revents = 0;
    }
    const bool traffic = !to_server.queue.empty() || !to_client.queue.empty();
    const int wait = traffic ? 0 : std::min( 20, std::min( client.wait_time(), server.wait_time() ) );
    poll( polls.data(), polls.size(), wait );
    freeze_timestamp();

    for ( size_t i = 0; i < polls.size(); i++ ) {
      if ( polls[i].revents ) {
        ( i < client_fds ? client : server ).read_fd( polls[i].fd );
      }
    }
    client.tick();
    server.tick();
    to_server.deliver_to( sink_of( server ) );
    to_client.deliver_to( sink_of( client ) );

    int status;
    if ( waitpid( app, &status, WNOHANG ) == app ) {
      CHECK( WIFEXITED( status ) );
      return WEXITSTATUS( status );
    }
  }
  CHECK( !"transfer did not finish" );
  return -1;
}

static void test_transfers( void )
{
  uint16_t target_port;
  const int listener = listening_socket( target_port );
  const pid_t target = start_target( listener );
  close( listener );

  const uint16_t listen_port = unused_port(), refused_listen_port = unused_port(), dead_port = unused_port();
  char spec[2][64];
  snprintf( spec[0], sizeof( spec[0] ), "%d:127.0.0.1:%d", listen_port, target_port );
  snprintf( spec[1], sizeof( spec[1] ), "%d:127.0.0.1:%d", refused_listen_port, dead_port );
  const std::vector<std::string> specs( spec, spec + 2 );

  TestLink to_server, to_client;
  TCPForwarder client( &to_server, TCPForwarder::LISTEN, specs );
  TCPForwarder server( &to_client, TCPForwarder::CONNECT, specs );

  /* a clean path */
  CHECK( pump( client, to_server, server, to_client, start_application( listen_port, 300000 ) ) == DELIVERED );
  CHECK( to_server.lost == 0 && to_client.lost == 0 );

  /* nothing at all to send is still a connection, opened and closed in order */
  CHECK( pump( client, to_server, server, to_client, start_application( listen_port, 1 ) ) == DELIVERED );

  /* one datagram in twenty lost, each way: slower, but every byte still arrives, once and in order */
  to_server.lose_one_in = to_client.lose_one_in = 20;
  CHECK( pump( client, to_server, server, to_client, start_application( listen_port, 300000 ) ) == DELIVERED );
  CHECK( to_server.lost > 5 && to_client.lost > 5 );
  to_server.lose_one_in = to_client.lose_one_in = 0;

  /* a small MTU means small segments, never oversize ones (the link checks) */
  to_server.max_payload = to_client.max_payload = 300;
  CHECK( pump( client, to_server, server, to_client, start_application( listen_port, 50000 ) ) == DELIVERED );
  CHECK( client.get_dropped_oversize() == 0 && server.get_dropped_oversize() == 0 );
  to_server.max_payload = to_client.max_payload = 1200;

  /* the target refuses, so the application is refused */
  CHECK( pump( client, to_server, server, to_client, start_application( refused_listen_port, 1000 ) ) == REFUSED );

  /* no forwarding at the other end (an older server, say): refused at once */
  to_server.ready = false;
  CHECK( pump( client, to_server, server, to_client, start_application( listen_port, 1000 ) ) == REFUSED );
  to_server.ready = true;

  /* and it all still works afterwards */
  CHECK( pump( client, to_server, server, to_client, start_application( listen_port, 10000 ) ) == DELIVERED );

  kill( target, SIGTERM );
  waitpid( target, NULL, 0 );
}

/* A remote forward (-R) is a forward with the ends exchanged: the server listens, the client connects. */
static void test_remote( void )
{
  uint16_t target_port;
  const int listener = listening_socket( target_port );
  const pid_t target = start_target( listener );
  close( listener );

  const uint16_t local_port = unused_port(), remote_port = unused_port();
  char spec[64];
  snprintf( spec, sizeof( spec ), "%d:127.0.0.1:%d", local_port, target_port );
  const std::vector<std::string> local_specs( 1, spec );
  snprintf( spec, sizeof( spec ), "%d:127.0.0.1:%d", remote_port, target_port );
  const std::vector<std::string> remote_specs( 1, spec );
  const std::vector<std::string> none;

  /* each end has both kinds, sharing one side channel */
  TestLink to_server, to_client;
  Forwarding client( &to_server, true, none, local_specs, remote_specs );
  Forwarding server( &to_client, false, none, local_specs, remote_specs );

  /* the client listens for the local forward and the server for the remote one, not the other way about */
  CHECK( client.fds().size() == 1 && server.fds().size() == 1 );

  CHECK( pump( client, to_server, server, to_client, start_application( remote_port, 200000 ) ) == DELIVERED );
  CHECK( pump( client, to_server, server, to_client, start_application( local_port, 200000 ) ) == DELIVERED );

  /* both at once, with loss: the two directions' segments must not be confused */
  to_server.lose_one_in = to_client.lose_one_in = 25;
  const pid_t other = start_application( local_port, 100000 );
  CHECK( pump( client, to_server, server, to_client, start_application( remote_port, 100000 ) ) == DELIVERED );
  CHECK( pump( client, to_server, server, to_client, other ) == DELIVERED );
  CHECK( to_server.lost > 0 && to_client.lost > 0 );

  kill( target, SIGTERM );
  waitpid( target, NULL, 0 );
}

/* The far end of the tunnel, played by the test: it just notes what the adapter sends. */
class RecordingSink : public SegmentSink
{
public:
  std::vector<TCPInUDP> sent;

  RecordingSink() : sent() {}

  bool segment_ready( void ) const { return true; }
  size_t max_datagram( void ) const { return 1200; }
  void to_network( uint8_t, const TCPInUDP& segment ) { sent.push_back( segment ); }
};

/*
 * A peer may ask for segments as small as it likes, including of no
 * bytes at all.  (Found by fuzzing: the adapter used to oblige, sending
 * empty segments for ever.)
 */
static void test_tiny_mss( void )
{
  uint16_t target_port;
  const int listener = listening_socket( target_port );
  Addr target;
  memset( &target, 0, sizeof( target ) );
  target.sin.sin_family = AF_INET;
  target.sin.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  target.sin.sin_port = htons( target_port );

  RecordingSink sink;
  AdapterPort adapter( &sink, false );
  adapter.add_target( 0, target, sizeof( target.sin ) );

  /* open a connection, asking for a maximum segment size of zero */
  TCPInUDP syn;
  syn.source_port = 1;
  syn.flags = TCPInUDP::SYN;
  syn.seq = 100;
  syn.window = 0xFFFF;
  syn.options = std::string( "\x02\x04\x00\x00", 4 );
  freeze_timestamp();
  adapter.from_network( 0, syn );
  for ( int i = 0; i < 200 && sink.sent.empty(); i++ ) {
    usleep( 10000 );
    freeze_timestamp();
    adapter.tick( frozen_timestamp() );
  }
  CHECK( sink.sent.size() == 1 && sink.sent[0].has( TCPInUDP::SYN ) && sink.sent[0].has( TCPInUDP::ACK ) );

  TCPInUDP ack;
  ack.source_port = 1;
  ack.flags = TCPInUDP::ACK;
  ack.seq = 101;
  ack.ack = sink.sent[0].seq + 1;
  ack.window = 0xFFFF;
  adapter.from_network( 0, ack );

  /* the target has plenty to say */
  const int app = accept( listener, NULL, NULL );
  CHECK( app >= 0 );
  CHECK( write_all( app, std::string( 1000, 'x' ) ) );
  usleep( 50000 );
  sink.sent.clear();
  const std::vector<int> fds = adapter.fds();
  CHECK( fds.size() == 1 );
  adapter.read_fd( fds[0] ); /* this used never to return */

  /* it is sent in pieces that are small, but not nothing */
  CHECK( !sink.sent.empty() );
  for ( size_t i = 0; i < sink.sent.size(); i++ ) {
    CHECK( !sink.sent[i].payload.empty() && sink.sent[i].payload.size() <= AdapterPort::MIN_MSS );
  }

  close( app );
  close( listener );
}

int main()
{
  test_tiny_mss();
  test_transfers();
  test_remote();
  return EXIT_SUCCESS;
}
