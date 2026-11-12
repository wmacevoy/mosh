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

#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/network/filecopy.h"
#include "src/network/streamchild.h"

std::vector<std::string> Network::stream_words( const std::string& joined )
{
  std::vector<std::string> words;
  std::string word;
  for ( size_t i = 0; i < joined.size(); i++ ) {
    if ( joined[i] == '\x1f' ) {
      words.push_back( word );
      word.clear();
    } else {
      word.push_back( joined[i] );
    }
  }
  words.push_back( word );
  return words;
}

bool Network::stream_words_valid( const std::vector<std::string>& words )
{
  if ( words.empty() ) {
    return false;
  }
  if ( words[0] == "@copy" ) {
    FileCopy::Options options;
    return FileCopy::parse( std::vector<std::string>( words.begin() + 1, words.end() ), options );
  }
  return ( words[0] == "@stdio" && words.size() == 1 ) || ( words[0] == "@sh" && words.size() == 2 );
}

/* Copies between our own standard input and output and the socket, until the other end has finished. */
static int stdio_pump( int sock )
{
  std::string to_sock, to_out;
  bool in_open = true, in_shut = false, sock_open = true;
  char buf[65536];
  fcntl( sock, F_SETFL, fcntl( sock, F_GETFL ) | O_NONBLOCK );

  while ( sock_open || !to_out.empty() ) {
    const bool read_in = in_open && to_sock.size() < sizeof( buf );
    const bool read_sock = sock_open && to_out.size() < sizeof( buf );
    struct pollfd fds[3] = {
      { read_in ? STDIN_FILENO : -1, POLLIN, 0 },
      { ( read_sock || !to_sock.empty() ) ? sock : -1,
        static_cast<short>( ( read_sock ? POLLIN : 0 ) | ( to_sock.empty() ? 0 : POLLOUT ) ), 0 },
      { to_out.empty() ? -1 : STDOUT_FILENO, POLLOUT, 0 }
    };
    if ( poll( fds, 3, -1 ) < 0 ) {
      if ( errno == EINTR ) {
        continue;
      }
      return 1;
    }
    if ( fds[0].revents ) {
      ssize_t n = read( STDIN_FILENO, buf, sizeof( buf ) );
      if ( n > 0 ) {
        to_sock.append( buf, n );
      } else if ( n == 0 || ( errno != EINTR && errno != EAGAIN ) ) {
        in_open = false;
      }
    }
    if ( read_sock && ( fds[1].revents & ( POLLIN | POLLHUP | POLLERR ) ) ) {
      ssize_t n = read( sock, buf, sizeof( buf ) );
      if ( n > 0 ) {
        to_out.append( buf, n );
      } else if ( n == 0 || ( errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK ) ) {
        sock_open = false;
      }
    }
    if ( !to_sock.empty() && ( fds[1].revents & POLLOUT ) ) {
      ssize_t n = write( sock, to_sock.data(), to_sock.size() );
      if ( n > 0 ) {
        to_sock.erase( 0, n );
      } else if ( n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK ) {
        return 1; /* nobody at the other end any more */
      }
    }
    if ( !in_open && !in_shut && to_sock.empty() ) {
      shutdown( sock, SHUT_WR ); /* our input has ended, and so the other end's */
      in_shut = true;
    }
    if ( fds[2].revents ) {
      ssize_t n = write( STDOUT_FILENO, to_out.data(), to_out.size() );
      if ( n > 0 ) {
        to_out.erase( 0, n );
      } else if ( n < 0 && errno != EINTR && errno != EAGAIN ) {
        return 1;
      }
    }
  }
  return 0;
}

/* In the new process: become what the words say.  Does not return. */
static void become( const std::vector<std::string>& words, bool local, int sock )
{
  /* The program we came from has its own ideas about signals. */
  sigset_t none;
  sigemptyset( &none );
  sigprocmask( SIG_SETMASK, &none, NULL );
  const int signals[] = { SIGINT, SIGTERM, SIGHUP, SIGPIPE, SIGCHLD, SIGWINCH, SIGCONT, SIGUSR1 };
  for ( size_t i = 0; i < sizeof( signals ) / sizeof( signals[0] ); i++ ) {
    signal( signals[i], SIG_DFL );
  }

  if ( !local ) {
    /* Nobody is at this end to read what we might say.  Paths are relative to home, as over ssh. */
    const int null = open( "/dev/null", O_RDWR );
    if ( null >= 0 ) {
      dup2( null, STDERR_FILENO );
    }
    const char* home = getenv( "HOME" );
    if ( home && chdir( home ) < 0 ) {
      /* then from wherever this is */
    }
  }

  const bool own_stdio = words[0] == "@stdio";
  if ( !own_stdio ) {
    dup2( sock, STDIN_FILENO );
    dup2( sock, STDOUT_FILENO );
  }
  const long limit = sysconf( _SC_OPEN_MAX );
  for ( int fd = 3; fd < ( limit > 0 && limit < 4096 ? limit : 4096 ); fd++ ) {
    if ( !( own_stdio && fd == sock ) ) {
      close( fd );
    }
  }

  if ( words[0] == "@copy" ) {
    FileCopy::Options options;
    if ( !FileCopy::parse( std::vector<std::string>( words.begin() + 1, words.end() ), options ) ) {
      _exit( 2 );
    }
    options.local = local;
    _exit( FileCopy::run( options, STDIN_FILENO, STDOUT_FILENO ) );
  }
  if ( own_stdio ) {
    _exit( stdio_pump( sock ) );
  }

  /* a command, for the user's shell */
  const char* shell = getenv( "SHELL" );
  if ( !shell || !*shell ) {
    const struct passwd* pw = getpwuid( getuid() );
    shell = ( pw && pw->pw_shell && *pw->pw_shell ) ? pw->pw_shell : "/bin/sh";
  }
  execl( shell, shell, "-c", words[1].c_str(), static_cast<char*>( NULL ) );
  _exit( 127 );
}

int Network::stream_child( const std::vector<std::string>& words, bool local, pid_t* pid )
{
  if ( !stream_words_valid( words ) ) {
    return -1;
  }
  int pair[2];
  if ( socketpair( AF_UNIX, SOCK_STREAM, 0, pair ) < 0 ) {
    return -1;
  }

  const pid_t child = fork();
  if ( child < 0 ) {
    close( pair[0] );
    close( pair[1] );
    return -1;
  }
  if ( child == 0 ) {
    close( pair[0] );
    if ( !pid ) {
      /* nobody will wait for us: so be nobody's child */
      const pid_t again = fork();
      if ( again != 0 ) {
        _exit( again < 0 );
      }
    }
    become( words, local, pair[1] );
  }
  close( pair[1] );
  if ( pid ) {
    *pid = child;
  } else {
    int status;
    waitpid( child, &status, 0 );
  }
  return pair[0];
}
