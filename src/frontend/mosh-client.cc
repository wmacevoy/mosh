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
#include "src/include/version.h"

#include <cstdlib>

#include <unistd.h>

#include "src/crypto/crypto.h"
#include "src/util/fatal_assert.h"
#include "src/util/locale_utils.h"
#include "stmclient.h"

/* These need to be included last because of conflicting defines. */
/*
 * stmclient.h includes termios.h, and that will break termio/termios pull in on Solaris.
 * The solution is to include termio.h also.
 * But Mac OS X doesn't have termio.h, so this needs a guard.
 */
#ifdef HAVE_TERMIO_H
#include <termio.h>
#endif

#if defined HAVE_NCURSESW_CURSES_H
#include <ncursesw/curses.h>
#include <ncursesw/term.h>
#elif defined HAVE_NCURSESW_H
#include <ncursesw.h>
#include <term.h>
#elif defined HAVE_NCURSES_CURSES_H
#include <ncurses/curses.h>
#include <ncurses/term.h>
#elif defined HAVE_NCURSES_H
#include <ncurses.h>
#include <term.h>
#elif defined HAVE_CURSES_H
#include <curses.h>
#include <term.h>
#else
#error "SysV or X/Open-compatible Curses header file required"
#endif

static void print_version( FILE* file )
{
  fputs( "mosh-client (" PACKAGE_STRING ") [build " BUILD_VERSION "]\n"
         "Copyright 2012 Keith Winstein <mosh-devel@mit.edu>\n"
         "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
         "This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n",
         file );
}

static void print_usage( FILE* file, const char* argv0 )
{
  print_version( file );
  fprintf( file,
           "\nUsage: %s [-# 'ARGS'] [-L|-R|-LU|-RU [BIND:]PORT:HOST:HOSTPORT]\n"
           "       [-F auto|always|never] [-N] IP PORT\n"
           "       %s -c\n",
           argv0,
           argv0 );
}

static void print_colorcount( void )
{
  /* check colors */
  setupterm( (char*)0, 1, (int*)0 );

  char colors_name[] = "colors";
  int color_val = tigetnum( colors_name );
  if ( color_val == -2 ) {
    fprintf( stderr, "Invalid terminfo numeric capability: %s\n", colors_name );
  }

  printf( "%d\n", color_val );
}

int main( int argc, char* argv[] )
{
  unsigned int verbose = 0;
  std::vector<std::string> udp_forwards, udp_remote_forwards, tcp_forwards, tcp_remote_forwards;
  std::string fragment_parity = "auto";
  bool headless = false;
  /* For security, make sure we don't dump core */
  Crypto::disable_dumping_core();

  /* Detect edge case */
  fatal_assert( argc > 0 );

  /* Get arguments */
  for ( int i = 1; i < argc; i++ ) {
    if ( 0 == strcmp( argv[i], "--help" ) ) {
      print_usage( stdout, argv[0] );
      exit( 0 );
    }
    if ( 0 == strcmp( argv[i], "--version" ) ) {
      print_version( stdout );
      exit( 0 );
    }
  }

  int opt;
  while ( ( opt = getopt( argc, argv, "#:cvL:R:F:N" ) ) != -1 ) {
    switch ( opt ) {
      case '#':
        // Ignore the original arguments to mosh wrapper
        break;
      case 'c':
        print_colorcount();
        exit( 0 );
        break;
      case 'v':
        verbose++;
        break;
      case 'L':
      case 'R': {
        /*
         * -L and -R forward TCP as ssh's do: from a local port to
         * HOST:HOSTPORT at the server, or from a port on the server to
         * HOST:HOSTPORT here.  -LU and -RU do the same for UDP; getopt
         * sees those as -L or -R with the argument "U", and the
         * specification is the word after.
         */
        const bool udp = strcmp( optarg, "U" ) == 0;
        if ( udp && optind >= argc ) {
          fprintf( stderr, "%s: -%cU needs a forwarding specification\n\n", argv[0], opt );
          print_usage( stderr, argv[0] );
          exit( 1 );
        }
        const std::string spec( udp ? argv[optind++] : optarg );
        if ( opt == 'L' ) {
          ( udp ? udp_forwards : tcp_forwards ).push_back( spec );
        } else {
          ( udp ? udp_remote_forwards : tcp_remote_forwards ).push_back( spec );
        }
        break;
      }
      case 'F':
        /* when to protect fragmented UDP datagrams with parity */
        fragment_parity = optarg;
        break;
      case 'N':
        /* no terminal: hold the session and its forwards open until told to stop, like "ssh -N" */
        headless = true;
        break;
      default:
        print_usage( stderr, argv[0] );
        exit( 1 );
        break;
    }
  }

  char *ip, *desired_port;

  if ( argc - optind != 2 ) {
    print_usage( stderr, argv[0] );
    exit( 1 );
  }

  ip = argv[optind];
  desired_port = argv[optind + 1];

  /* Sanity-check arguments */
  if ( desired_port && ( strspn( desired_port, "0123456789" ) != strlen( desired_port ) ) ) {
    fprintf( stderr, "%s: Bad UDP port (%s)\n\n", argv[0], desired_port );
    print_usage( stderr, argv[0] );
    exit( 1 );
  }

  /* Read key from environment */
  char* env_key = getenv( "MOSH_KEY" );
  if ( env_key == NULL ) {
    fputs( "MOSH_KEY environment variable not found.\n", stderr );
    exit( 1 );
  }

  /*
   * How to reach the server if UDP will not get there: a command that
   * starts "mosh-server relay" on it (through ssh, as a rule), given as
   * its words separated by the character 0x1F so that no shell is needed
   * to take it apart; and whether to use it when needed or from the start.
   */
  std::vector<std::string> relay_command;
  if ( const char* command = getenv( "MOSH_RELAY_COMMAND" ) ) {
    std::string word;
    for ( const char* c = command; *c; c++ ) {
      if ( *c == '\x1f' ) {
        relay_command.push_back( word );
        word.clear();
      } else {
        word.push_back( *c );
      }
    }
    relay_command.push_back( word );
  }
  const std::string relay_mode( getenv( "MOSH_RELAY" ) ? getenv( "MOSH_RELAY" ) : "auto" );

  /* Read prediction preference */
  char* predict_mode = getenv( "MOSH_PREDICTION_DISPLAY" );
  /* can be NULL */

  /* Read prediction insertion preference */
  char* predict_overwrite = getenv( "MOSH_PREDICTION_OVERWRITE" );
  /* can be NULL */

  std::string key( env_key );

  if ( unsetenv( "MOSH_KEY" ) < 0 ) {
    perror( "unsetenv" );
    exit( 1 );
  }

  /* Adopt native locale */
  set_native_locale();

  bool success = false;
  try {
    STMClient client( ip,
                      desired_port,
                      key.c_str(),
                      predict_mode,
                      verbose,
                      predict_overwrite,
                      udp_forwards,
                      tcp_forwards,
                      fragment_parity,
                      tcp_remote_forwards,
                      udp_remote_forwards,
                      headless );
    if ( relay_mode != "never" ) {
      client.set_relay( relay_mode, relay_command );
    }
    client.init();

    try {
      success = client.main();
    } catch ( ... ) {
      client.shutdown();
      throw;
    }

    client.shutdown();
  } catch ( const Network::NetworkException& e ) {
    fprintf( stderr, "Network exception: %s\r\n", e.what() );
    success = false;
  } catch ( const Crypto::CryptoException& e ) {
    fprintf( stderr, "Crypto exception: %s\r\n", e.what() );
    success = false;
  } catch ( const std::exception& e ) {
    fprintf( stderr, "Error: %s\r\n", e.what() );
    success = false;
  }

  if ( headless ) {
    fputs( "mosh: exiting.\n", stderr ); /* (standard output is not ours to write on) */
  } else {
    printf( "[mosh is exiting.]\n" );
  }

  return !success;
}
