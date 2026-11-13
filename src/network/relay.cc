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
#include <ctime>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/network/punch.h"
#include "src/network/relay.h"

#include <cstdarg>
#include <cstdio>
#include <memory>

using namespace Network;

static const size_t MAX_DATAGRAM = 65535;

/* how long without an answer by UDP before the stream is brought in */
static const uint64_t DIRECT_QUIET_MS = 2500;
/* how long the stream may go unneeded before it is closed */
static const uint64_t STREAM_IDLE_MS = 60000;
/* how long without an answer by UDP before trying from a fresh socket */
static const uint64_t DIRECT_HOP_MS = 10000;
/* between attempts to start the remote relay: doubling from, up to */
static const uint64_t RESPAWN_MIN_MS = 1000;
static const uint64_t RESPAWN_MAX_MS = 30000;
/*
 * ...and up to this while it has never yet worked.  Then the likeliest
 * reason is that ssh cannot log in without asking, which will not get
 * better, and a server may take repeated failed logins amiss.
 */
static const uint64_t RESPAWN_HOPELESS_MAX_MS = 300000;
/* how much may wait to go down a stream that is not taking it */
static const size_t STREAM_BACKLOG = 256 * 1024;
/* how long the remote relay stays, its stream gone, for a way through that has gone quiet */
static const uint64_t PUNCH_LINGER_MS = 60000;
/* the servers asked where we appear to be from outside, unless MOSH_STUN says otherwise */
static const char DEFAULT_STUN[] = "stun.l.google.com:19302,stun.cloudflare.com:3478";

/* What the relays are doing, for whoever sets MOSH_RELAY_LOG to a file to hear of it. */
static const char* relay_log_who = "";
static void say( const char* format, ... )
{
  const char* path = getenv( "MOSH_RELAY_LOG" );
  if ( !path || !*path ) {
    return;
  }
  FILE* f = fopen( path, "a" );
  if ( !f ) {
    return;
  }
  fprintf( f, "%s: ", relay_log_who );
  va_list args;
  va_start( args, format );
  vfprintf( f, format, args );
  va_end( args );
  fputc( '\n', f );
  fclose( f );
}

/*
 * Between the relays, on the stream, besides the session's datagrams:
 * frames that begin with the mark and are words for the other relay.
 * (No datagram of mosh's begins so.  A relay from before these existed
 * passes them on as datagrams, to be thrown away for making no sense;
 * and the local relay says nothing of the kind until the remote one
 * has, so an old remote relay is never sent any.)
 *
 *   HELLO 1          remote: I know about these
 *   STUN a:p b:p     local: servers to ask where you appear to be
 *   STUNKEY k        local: ...and the key to show them, if they want one
 *   KEY k            local: seal probes with this; start
 *   PORT n           either: the port of my end of the way through
 *   CAND a.b.c.d:p   either: where I may be reached (on my own network, or as seen from outside)
 */
static std::string control( const std::string& text )
{
  return relay_frame( std::string( PUNCH_MARK, sizeof( PUNCH_MARK ) ) + text );
}

static bool is_control( const std::string& frame, std::vector<std::string>& words )
{
  if ( frame.size() < sizeof( PUNCH_MARK ) || memcmp( frame.data(), PUNCH_MARK, sizeof( PUNCH_MARK ) ) != 0 ) {
    return false;
  }
  words.clear();
  std::string word;
  for ( size_t i = sizeof( PUNCH_MARK ); i <= frame.size(); i++ ) {
    if ( i == frame.size() || frame[i] == ' ' ) {
      if ( !word.empty() ) {
        words.push_back( word );
      }
      word.clear();
    } else {
      word.push_back( frame[i] );
    }
  }
  return true;
}

static std::vector<std::string> comma_list( const std::string& text )
{
  std::vector<std::string> ret;
  std::string item;
  for ( size_t i = 0; i <= text.size(); i++ ) {
    if ( i == text.size() || text[i] == ',' ) {
      if ( !item.empty() && item != "none" ) {
        ret.push_back( item );
      }
      item.clear();
    } else {
      item.push_back( text[i] );
    }
  }
  return ret;
}

static bool is_ipv4( const std::string& text )
{
  Addr addr;
  return parse_ip_port( text + ":1", addr );
}

std::string Network::relay_frame( const std::string& datagram )
{
  std::string ret;
  ret.reserve( 2 + datagram.size() );
  ret.push_back( static_cast<char>( datagram.size() >> 8 ) );
  ret.push_back( static_cast<char>( datagram.size() & 0xFF ) );
  ret += datagram;
  return ret;
}

bool RelayFrameParser::next( std::string& datagram )
{
  if ( pending.size() < 2 ) {
    return false;
  }
  const size_t len = ( static_cast<uint8_t>( pending[0] ) << 8 ) | static_cast<uint8_t>( pending[1] );
  if ( pending.size() < 2 + len ) {
    return false;
  }
  datagram.assign( pending, 2, len );
  pending.erase( 0, 2 + len );
  return true;
}

/*
 * For a process started from the mosh client, which keeps most signals
 * blocked and takes them when it chooses: a new process should not
 * inherit that, or a signal sent to stop it waits for ever.
 */
static void own_signals( void )
{
  sigset_t none;
  sigemptyset( &none );
  sigprocmask( SIG_SETMASK, &none, NULL );
  const int signals[] = { SIGINT, SIGTERM, SIGHUP, SIGCHLD, SIGWINCH, SIGCONT, SIGUSR1, SIGUSR2 };
  for ( size_t i = 0; i < sizeof( signals ) / sizeof( signals[0] ); i++ ) {
    signal( signals[i], SIG_DFL );
  }
}

static uint64_t now_ms( void )
{
  struct timespec t;
#ifdef CLOCK_MONOTONIC
  clock_gettime( CLOCK_MONOTONIC, &t );
#else
  clock_gettime( CLOCK_REALTIME, &t );
#endif
  return static_cast<uint64_t>( t.tv_sec ) * 1000 + t.tv_nsec / 1000000;
}

static bool write_all( int fd, const std::string& s )
{
  size_t done = 0;
  while ( done < s.size() ) {
    ssize_t n = write( fd, s.data() + done, s.size() - done );
    if ( n < 0 ) {
      if ( errno == EINTR ) {
        continue;
      }
      return false;
    }
    done += n;
  }
  return true;
}

/* A UDP socket for talking to one address and port, or -1. */
static int udp_to( const std::string& address, const char* port )
{
  struct addrinfo hints, *res = NULL;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  if ( getaddrinfo( address.c_str(), port, &hints, &res ) != 0 ) {
    return -1;
  }
  int fd = socket( res->ai_family, SOCK_DGRAM, 0 );
  if ( fd >= 0 && connect( fd, res->ai_addr, res->ai_addrlen ) != 0 ) {
    close( fd );
    fd = -1;
  }
  freeaddrinfo( res );
  return fd;
}

int Network::relay_remote( const char* address, const char* port )
{
  /*
   * Where is the server, from here?  We are on its machine, and are
   * told the address the client uses for it.  But that can be an address
   * this machine does not know as its own, when something between
   * translates addresses, and then a datagram sent to it has to leave
   * and come back, past whatever was in UDP's way to begin with.  So try
   * also the address ssh reached this machine at, which is the one the
   * server usually listens on, and this machine's address for itself;
   * and stay with whichever answers.
   */
  std::vector<std::string> addresses;
  if ( const char* ssh_connection = getenv( "SSH_CONNECTION" ) ) {
    /* "client-address client-port server-address server-port" */
    const std::string s( ssh_connection );
    const size_t first = s.find( ' ' );
    const size_t second = first == std::string::npos ? first : s.find( ' ', first + 1 );
    const size_t third = second == std::string::npos ? second : s.find( ' ', second + 1 );
    if ( third != std::string::npos ) {
      addresses.push_back( s.substr( second + 1, third - second - 1 ) );
    }
  }
  addresses.push_back( address );
  addresses.push_back( "127.0.0.1" );
  addresses.push_back( "::1" );

  std::vector<int> sockets;
  for ( size_t i = 0; i < addresses.size(); i++ ) {
    bool repeated = false;
    for ( size_t j = 0; j < i; j++ ) {
      repeated = repeated || addresses[j] == addresses[i];
    }
    const int fd = repeated ? -1 : udp_to( addresses[i], port );
    if ( fd >= 0 ) {
      sockets.push_back( fd );
    }
  }
  if ( sockets.empty() ) {
    return 1;
  }

  /*
   * We may be wanted after the connection that started us has gone: if a
   * way straight through to the other relay is found (punch.h), that
   * connection is let go, and we are one end of the way through.
   */
  setsid();
  signal( SIGHUP, SIG_IGN );
  signal( SIGPIPE, SIG_IGN );
  relay_log_who = "remote";

  /* the client's address as ssh saw it: where its relay may be found, for all we know */
  std::string client_ip;
  if ( const char* ssh_connection = getenv( "SSH_CONNECTION" ) ) {
    const std::string c( ssh_connection );
    client_ip = c.substr( 0, c.find( ' ' ) );
  }

  RelayFrameParser parser;
  char buf[MAX_DATAGRAM + 1];
  std::string datagram;
  std::vector<struct pollfd> fds;
  std::vector<std::string> words, stun;
  std::string stun_key;
  std::unique_ptr<Punch> punch;
  bool stream_open = true, was_open = false;
  uint64_t stream_heard = 0, stream_closed = 0;

  if ( !write_all( STDOUT_FILENO, control( "HELLO 1" ) ) ) {
    return 0;
  }

  while ( true ) {
    fds.clear();
    const struct pollfd in = { stream_open ? STDIN_FILENO : -1, POLLIN, 0 };
    fds.push_back( in );
    const struct pollfd through = { punch ? punch->fd() : -1, POLLIN, 0 };
    fds.push_back( through );
    for ( size_t i = 0; i < sockets.size(); i++ ) {
      const struct pollfd udp = { sockets[i], POLLIN, 0 };
      fds.push_back( udp );
    }
    if ( poll( fds.data(), fds.size(), punch ? 250 : -1 ) < 0 ) {
      if ( errno == EINTR ) {
        continue;
      }
      return 1;
    }
    const uint64_t now = now_ms();
    bool stream_ended = false;

    if ( fds[0].revents ) {
      ssize_t n = read( STDIN_FILENO, buf, sizeof( buf ) );
      if ( n == 0 || ( n < 0 && errno != EINTR && errno != EAGAIN ) ) {
        stream_ended = true; /* the connection that brought us here has gone */
      }
      if ( n > 0 ) {
        parser.append( buf, n );
        while ( parser.next( datagram ) ) {
          if ( !is_control( datagram, words ) ) {
            stream_heard = now;
            for ( size_t i = 0; i < sockets.size(); i++ ) {
              /* if it can't go, it is lost, like any datagram */
              send( sockets[i], datagram.data(), datagram.size(), MSG_DONTWAIT );
            }
          } else if ( words.size() >= 1 && words[0] == "STUN" ) {
            stun.assign( words.begin() + 1, words.end() );
          } else if ( words.size() == 2 && words[0] == "STUNKEY" ) {
            stun_key = words[1];
          } else if ( words.size() == 2 && words[0] == "KEY" ) {
            try {
              punch.reset( new Punch( false, words[1], stun, now, stun_key ) );
              stream_ended = stream_ended || !write_all( STDOUT_FILENO, control( "PORT " + std::to_string( punch->local_port() ) ) );
              say( "looking for a way through, from port %d", static_cast<int>( punch->local_port() ) );
            } catch ( const std::exception& e ) {
              punch.reset();
            }
          } else if ( words.size() == 2 && words[0] == "PORT" && punch && is_ipv4( client_ip ) ) {
            punch->add_candidate( client_ip + ":" + words[1] );
          } else if ( words.size() == 2 && words[0] == "CAND" && punch ) {
            punch->add_candidate( words[1] );
          }
        }
      }
    }

    if ( punch ) {
      Punch::Got got;
      while ( ( got = punch->receive( now, datagram ) ) != Punch::NOTHING ) {
        if ( got == Punch::GOODBYE ) {
          say( "the other end has finished" );
          return 0;
        }
        if ( got == Punch::DATA ) {
          for ( size_t i = 0; i < sockets.size(); i++ ) {
            send( sockets[i], datagram.data(), datagram.size(), MSG_DONTWAIT );
          }
        }
      }
      punch->tick( now );
      const std::vector<std::string> mine = punch->take_local_candidates();
      for ( size_t i = 0; i < mine.size(); i++ ) {
        say( "we may be reached at %s", mine[i].c_str() );
        if ( stream_open && !stream_ended ) {
          stream_ended = !write_all( STDOUT_FILENO, control( "CAND " + mine[i] ) );
        }
      }
      if ( punch->open( now ) != was_open ) {
        was_open = punch->open( now );
        say( was_open ? "a way through is open, to %s" : "the way through to %s has closed", punch->where().c_str() );
      }
    }

    for ( size_t i = 0; i < sockets.size(); i++ ) {
      if ( !( fds[2 + i].revents & POLLIN ) ) {
        /* (an error on one of them, such as nobody being there, is read off and forgotten) */
        if ( fds[2 + i].revents ) {
          recv( sockets[i], buf, sizeof( buf ), MSG_DONTWAIT );
        }
        continue;
      }
      ssize_t n = recv( sockets[i], buf, sizeof( buf ), MSG_DONTWAIT );
      if ( n < 0 ) {
        continue;
      }
      /* From the server, for the client: by the way through if there is one, and by the stream if that is in use. */
      const std::string answer( buf, n );
      const bool through_open = punch && punch->open( now );
      if ( through_open ) {
        punch->send( answer );
      }
      if ( stream_open && !stream_ended && ( !through_open || now - stream_heard < DIRECT_QUIET_MS + 500 ) ) {
        stream_ended = !write_all( STDOUT_FILENO, relay_frame( answer ) );
      }
      if ( sockets.size() > 1 ) {
        /* The server is at this one.  The others can go. */
        const int found = sockets[i];
        for ( size_t j = 0; j < sockets.size(); j++ ) {
          if ( sockets[j] != found ) {
            close( sockets[j] );
          }
        }
        sockets.assign( 1, found );
        break;
      }
    }

    if ( stream_ended && stream_open ) {
      stream_open = false;
      stream_closed = now;
      if ( !( punch && punch->open( now ) ) ) {
        return 0;
      }
      /*
       * Stay, as one end of the way through: but not as the process that
       * was started, which whoever started it (sshd, say) may be waiting
       * to see finish.  The stream's descriptors are no more use.
       */
      say( "the stream has ended; staying for the way through" );
      if ( fork() > 0 ) {
        _exit( 0 );
      }
      const int null = open( "/dev/null", O_RDWR );
      if ( null >= 0 ) {
        dup2( null, STDIN_FILENO );
        dup2( null, STDOUT_FILENO );
        dup2( null, STDERR_FILENO );
        if ( null > STDERR_FILENO ) {
          close( null );
        }
      }
    }
    if ( !stream_open && now - std::max( punch->last_heard(), stream_closed ) > PUNCH_LINGER_MS ) {
      say( "nothing heard for a minute: finished" );
      return 0;
    }
  }
}

namespace {

/* The local relay, once it is a process of its own. */
class LocalRelay
{
private:
  RelayOptions options;
  int client_fd; /* UDP, on loopback: the mosh client talks to this */
  int direct_fd; /* UDP, to the server */
  int alive_fd;  /* reads as ended when the client has gone */

  Addr client;
  socklen_t client_len;

  /* the remote relay, reached through a child process (ssh) */
  pid_t child;
  int to_child, from_child;
  std::string backlog;
  RelayFrameParser parser;
  uint64_t respawn_after, respawn_delay;
  bool ever_worked;

  uint64_t direct_heard, direct_hopped, stream_wanted;

  /* a way straight through to the remote relay, when both ends are behind NATs (punch.h) */
  uint64_t stream_idle;
  bool punching;
  std::vector<std::string> stun;
  std::string stun_key; /* for STUN servers that answer only those who have it */
  std::unique_ptr<Punch> punch;
  bool was_open;

  void open_direct( void )
  {
    if ( direct_fd >= 0 ) {
      close( direct_fd );
    }
    direct_fd = options.stream_only ? -1 : socket( options.server.sa.sa_family, SOCK_DGRAM, 0 );
  }

  void stop_child( void )
  {
    if ( child > 0 ) {
      close( to_child );
      close( from_child );
      /* With its stream gone it should go of itself; then it is told to; then it is made to. */
      for ( int tries = 0; tries < 60; tries++ ) {
        if ( waitpid( child, NULL, WNOHANG ) != 0 ) {
          child = -1;
          break;
        }
        if ( tries == 20 ) {
          kill( child, SIGTERM );
        }
        usleep( 10000 );
      }
      if ( child > 0 ) {
        kill( child, SIGKILL );
        waitpid( child, NULL, 0 );
      }
      child = -1;
      to_child = from_child = -1;
      backlog.clear();
      parser = RelayFrameParser();
    }
  }

  void start_child( uint64_t now )
  {
    if ( child > 0 || now < respawn_after || options.command.empty() ) {
      return;
    }
    /* (What we had of a way through is no use, or we would not be here.  The new relay will have a new one.) */
    punch.reset();
    was_open = false;
    say( "starting the stream" );
    respawn_after = now + respawn_delay;
    const uint64_t most = ever_worked ? RESPAWN_MAX_MS : RESPAWN_HOPELESS_MAX_MS;
    respawn_delay = respawn_delay * 2 > most ? most : respawn_delay * 2;

    int in[2], out[2];
    if ( pipe( in ) < 0 ) {
      return;
    }
    if ( pipe( out ) < 0 ) {
      close( in[0] );
      close( in[1] );
      return;
    }

    std::vector<char*> argv;
    for ( size_t i = 0; i < options.command.size(); i++ ) {
      argv.push_back( const_cast<char*>( options.command[i].c_str() ) );
    }
    argv.push_back( NULL );

    child = fork();
    if ( child == 0 ) {
      own_signals();
      dup2( in[0], STDIN_FILENO );
      dup2( out[1], STDOUT_FILENO );
      const long limit = sysconf( _SC_OPEN_MAX );
      for ( int fd = 3; fd < ( limit > 0 && limit < 4096 ? limit : 4096 ); fd++ ) {
        close( fd );
      }
      execvp( argv[0], argv.data() );
      _exit( 127 );
    }
    close( in[0] );
    close( out[1] );
    if ( child < 0 ) {
      close( in[1] );
      close( out[0] );
      return;
    }
    to_child = in[1];
    from_child = out[0];
    fcntl( to_child, F_SETFL, fcntl( to_child, F_GETFL ) | O_NONBLOCK );
  }

  void flush( void )
  {
    while ( to_child >= 0 && !backlog.empty() ) {
      ssize_t n = write( to_child, backlog.data(), backlog.size() );
      if ( n > 0 ) {
        backlog.erase( 0, n );
      } else if ( n < 0 && ( errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ) ) {
        break;
      } else {
        stop_child(); /* it has gone; it will be started again when it is wanted */
        break;
      }
    }
  }

  void to_client( const char* data, size_t len )
  {
    if ( client_len ) {
      sendto( client_fd, data, len, MSG_DONTWAIT, &client.sa, client_len );
    }
  }

  void from_client( const std::string& datagram, uint64_t now )
  {
    if ( direct_fd >= 0 ) {
      sendto( direct_fd, datagram.data(), datagram.size(), MSG_DONTWAIT, &options.server.sa, options.server_len );
    }
    if ( punch && punch->open( now ) ) {
      punch->send( datagram );
    }

    /* Is either route by UDP answering?  If not, by the stream as well. */
    const uint64_t udp_heard = std::max( direct_heard, punch ? punch->last_heard() : 0 );
    if ( options.stream_only || now - udp_heard > DIRECT_QUIET_MS ) {
      stream_wanted = now;
      start_child( now );
      if ( to_child >= 0 && backlog.size() + datagram.size() <= STREAM_BACKLOG ) {
        backlog += relay_frame( datagram );
        flush();
      }
      if ( direct_fd >= 0 && now - direct_heard > DIRECT_HOP_MS && now - direct_hopped > DIRECT_HOP_MS ) {
        direct_hopped = now;
        open_direct(); /* a new port sometimes gets through where an old one has stopped */
      }
    }
  }

  /* Words from the remote relay (see control(), above). */
  void from_remote( const std::vector<std::string>& words, uint64_t now )
  {
    if ( words.size() == 2 && words[0] == "HELLO" && punching && !punch ) {
      /* It knows how to look for a way through.  So: a key for the two of us, and where to ask. */
      try {
        const std::string key = Crypto::Base64Key().printable_key();
        punch.reset( new Punch( true, key, stun, now, stun_key ) );
        std::string servers;
        for ( size_t i = 0; i < stun.size(); i++ ) {
          servers += " " + stun[i];
        }
        backlog += control( "STUN" + servers ) + ( stun_key.empty() ? "" : control( "STUNKEY " + stun_key ) )
                   + control( "KEY " + key )
                   + control( "PORT " + std::to_string( punch->local_port() ) );
        say( "looking for a way through, from port %d", static_cast<int>( punch->local_port() ) );
      } catch ( const std::exception& e ) {
        punch.reset();
      }
    } else if ( words.size() == 2 && words[0] == "PORT" && punch && options.server.sa.sa_family == AF_INET ) {
      /* at the server's own address, if nothing in between changes the port */
      const std::string server = format_ip_port( options.server );
      punch->add_candidate( server.substr( 0, server.rfind( ':' ) ) + ":" + words[1] );
    } else if ( words.size() == 2 && words[0] == "CAND" && punch ) {
      punch->add_candidate( words[1] );
    }
  }

  void tend_punch( uint64_t now )
  {
    if ( !punch ) {
      return;
    }
    std::string datagram;
    Punch::Got got;
    while ( ( got = punch->receive( now, datagram ) ) != Punch::NOTHING ) {
      if ( got == Punch::DATA ) {
        to_client( datagram.data(), datagram.size() );
      }
    }
    punch->tick( now );
    const std::vector<std::string> mine = punch->take_local_candidates();
    for ( size_t i = 0; i < mine.size(); i++ ) {
      say( "we may be reached at %s", mine[i].c_str() );
      if ( to_child >= 0 ) {
        backlog += control( "CAND " + mine[i] );
      }
    }
    if ( punch->open( now ) != was_open ) {
      was_open = punch->open( now );
      say( was_open ? "a way through is open, to %s" : "the way through to %s has closed", punch->where().c_str() );
    }
  }

  /* unused */
  LocalRelay( const LocalRelay& );
  LocalRelay& operator=( const LocalRelay& );

public:
  LocalRelay( const RelayOptions& s_options, int s_client_fd, int s_alive_fd )
    : options( s_options ), client_fd( s_client_fd ), direct_fd( -1 ), alive_fd( s_alive_fd ), client(),
      client_len( 0 ), child( -1 ), to_child( -1 ), from_child( -1 ), backlog(), parser(), respawn_after( 0 ),
      respawn_delay( RESPAWN_MIN_MS ), ever_worked( false ), direct_heard( 0 ), direct_hopped( 0 ), stream_wanted( 0 ),
      stream_idle( STREAM_IDLE_MS ), punching( false ), stun(), stun_key(), punch(), was_open( false )
  {
    open_direct();
    /* (for tests, which cannot wait a minute to see the stream let go) */
    if ( const char* idle = getenv( "MOSH_RELAY_STREAM_IDLE_MS" ) ) {
      if ( atol( idle ) >= 1000 ) {
        stream_idle = atol( idle );
      }
    }
    /* Look for a way through unless told not to; and not when told to use the stream and nothing else. */
    const char* wanted = getenv( "MOSH_PUNCH" );
    punching = !options.stream_only && !( wanted && strcmp( wanted, "never" ) == 0 );
    const char* servers = getenv( "MOSH_STUN" );
    stun = comma_list( servers ? servers : DEFAULT_STUN );
    if ( const char* key = getenv( "MOSH_STUN_KEY" ) ) {
      stun_key = key;
    }
  }

  void run( void )
  {
    char buf[MAX_DATAGRAM + 1];
    std::string datagram;

    while ( true ) {
      /* (poll ignores a negative descriptor, so the absent ones need no special care) */
      struct pollfd fds[6] = { { alive_fd, POLLIN, 0 },
                               { client_fd, POLLIN, 0 },
                               { direct_fd, POLLIN, 0 },
                               { from_child, POLLIN, 0 },
                               { backlog.empty() ? -1 : to_child, POLLOUT, 0 },
                               { punch ? punch->fd() : -1, POLLIN, 0 } };
      if ( poll( fds, 6, punch ? 250 : 1000 ) < 0 && errno != EINTR ) {
        break;
      }
      const uint64_t now = now_ms();

      if ( fds[0].revents ) {
        /* the client has gone, and so should we: and the far end of the way through, without waiting to wonder */
        if ( punch ) {
          punch->goodbye();
        }
        break;
      }

      tend_punch( now );

      if ( fds[1].revents & POLLIN ) {
        Addr from;
        socklen_t from_len = sizeof( from );
        ssize_t n = recvfrom( client_fd, buf, sizeof( buf ), MSG_DONTWAIT, &from.sa, &from_len );
        if ( n >= 0 ) {
          client = from; /* it changes its port from time to time */
          client_len = from_len;
          from_client( std::string( buf, n ), now );
        }
      }

      if ( direct_fd >= 0 && ( fds[2].revents & POLLIN ) ) {
        ssize_t n = recv( direct_fd, buf, sizeof( buf ), MSG_DONTWAIT );
        if ( n >= 0 ) {
          direct_heard = now;
          to_client( buf, n );
        }
      }

      if ( from_child >= 0 && fds[3].revents ) {
        ssize_t n = read( from_child, buf, sizeof( buf ) );
        if ( n > 0 ) {
          respawn_delay = RESPAWN_MIN_MS; /* it works */
          ever_worked = true;
          parser.append( buf, n );
          std::vector<std::string> words;
          while ( parser.next( datagram ) ) {
            if ( is_control( datagram, words ) ) {
              from_remote( words, now );
            } else {
              to_client( datagram.data(), datagram.size() );
            }
          }
        } else if ( n == 0 || ( errno != EINTR && errno != EAGAIN ) ) {
          say( "the stream has ended" );
          stop_child();
        }
      }

      flush();

      /* The direct route has been enough for a while: let the other one go. */
      if ( child > 0 && !options.stream_only && now - stream_wanted > stream_idle ) {
        say( "the stream has not been needed for a while: closing it" );
        stop_child();
        respawn_after = 0;
      }
    }

    stop_child();
  }
};

}

int Network::relay_start_local( const RelayOptions& options, int& keep_alive_fd, pid_t& pid )
{
  /* where the client will find us */
  const int client_fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if ( client_fd < 0 ) {
    return 0;
  }
  struct sockaddr_in sin;
  memset( &sin, 0, sizeof( sin ) );
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  socklen_t len = sizeof( sin );
  int alive[2];
  if ( bind( client_fd, reinterpret_cast<struct sockaddr*>( &sin ), sizeof( sin ) ) < 0
       || getsockname( client_fd, reinterpret_cast<struct sockaddr*>( &sin ), &len ) < 0 || pipe( alive ) < 0 ) {
    close( client_fd );
    return 0;
  }

  pid = fork();
  if ( pid < 0 ) {
    close( client_fd );
    close( alive[0] );
    close( alive[1] );
    return 0;
  }

  if ( pid == 0 ) {
    /*
     * A process apart: nothing typed at the terminal should reach it or
     * the ssh it runs (an interrupt, say, while the client still has a
     * goodbye to send through them), and it has no business with the
     * terminal or anything else the client has open.
     */
    own_signals();
    setsid();
    signal( SIGPIPE, SIG_IGN );
    const int null = open( "/dev/null", O_RDWR );
    if ( null >= 0 ) {
      dup2( null, STDIN_FILENO );
      dup2( null, STDOUT_FILENO );
      dup2( null, STDERR_FILENO );
    }
    const long limit = sysconf( _SC_OPEN_MAX );
    for ( int fd = 3; fd < ( limit > 0 && limit < 4096 ? limit : 4096 ); fd++ ) {
      if ( fd != client_fd && fd != alive[0] ) {
        close( fd );
      }
    }
    relay_log_who = "local";
    LocalRelay relay( options, client_fd, alive[0] );
    relay.run();
    _exit( 0 );
  }

  close( client_fd );
  close( alive[0] );
  keep_alive_fd = alive[1];
  fcntl( keep_alive_fd, F_SETFD, FD_CLOEXEC );
  return ntohs( sin.sin_port );
}
