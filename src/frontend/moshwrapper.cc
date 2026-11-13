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

#include <map>
#include <string>
#include <vector>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif

#include "src/frontend/moshwrapper.h"
#include "src/include/version.h"

using namespace MoshWrapper;

namespace {

const char USAGE[] = R"USAGE(Usage: %s [options] [--] [user@]host [command...]
        --client=PATH        mosh client on local machine
                                (default: "mosh-client")
        --server=COMMAND     mosh server on remote machine
                                (default: "mosh-server")

        --predict=adaptive      local echo for slower links [default]
-a      --predict=always        use local echo even on fast links
-n      --predict=never         never use local echo
        --predict=experimental  aggressively echo even when incorrect

-o      --predict-overwrite     prediction overwrites instead of inserting

-4      --family=inet        use IPv4 only
-6      --family=inet6       use IPv6 only
        --family=auto        autodetect network type for single-family hosts only
        --family=all         try all network types
        --family=prefer-inet use all network types, but try IPv4 first [default]
        --family=prefer-inet6 use all network types, but try IPv6 first
-p PORT[:PORT2]
        --port=PORT[:PORT2]  server-side UDP port or range
                                (No effect on server-side SSH port)
        --bind-server={ssh|any|IP}  ask the server to reply from an IP address
                                       (default: "ssh")

-LU [BIND_ADDRESS:]PORT:HOST:HOSTPORT
        --udp-forward=[BIND_ADDRESS:]PORT:HOST:HOSTPORT
                             forward UDP datagrams sent to local PORT
                                to HOST:HOSTPORT as seen from the server
                                (may be repeated; needs support on the server)
-RU [BIND_ADDRESS:]PORT:HOST:HOSTPORT
        --udp-remote-forward=[BIND_ADDRESS:]PORT:HOST:HOSTPORT
                             forward UDP datagrams sent to PORT on the
                                server to HOST:HOSTPORT as seen from here

        --fragment-parity={auto|always|never}
                             whether to add parity to forwarded UDP
                                datagrams too large to send whole, so that
                                they survive the loss of one fragment
                                (default: "auto", when the network is
                                losing enough to make it worthwhile)

-L [BIND_ADDRESS:]PORT:HOST:HOSTPORT
        --tcp-forward=[BIND_ADDRESS:]PORT:HOST:HOSTPORT
                             forward TCP connections made to local PORT
                                to HOST:HOSTPORT as seen from the server,
                                as "ssh -L" does
                                (may be repeated; needs support on the server)
-R [BIND_ADDRESS:]PORT:HOST:HOSTPORT
        --tcp-remote-forward=[BIND_ADDRESS:]PORT:HOST:HOSTPORT
                             forward TCP connections made to PORT on the
                                server to HOST:HOSTPORT as seen from here,
                                as "ssh -R" does
                                (may be repeated; needs support on the server)

-N                           no terminal: just keep the session, and the
                                forwards given with it, open until
                                interrupted (as "ssh -N" does)

        --stdio              no terminal: run the command on the server
                                with its input and output here, as
                                "ssh host command" does

        --copy               copy files: see "mocp --help"

        --relay={auto|always|never}
                             carry the session over ssh when UDP cannot
                                reach the server: when needed (default),
                                from the start and nothing else, or never

        --ssh=COMMAND        ssh command to run when setting up session
                                (example: "ssh -p 2222")
                                (default: "ssh")

        --no-ssh-pty         do not allocate a pseudo tty on ssh connection

        --no-init            do not send terminal initialization string

        --local              run mosh-server locally without using ssh

        --experimental-remote-ip=(local|remote|proxy)  select the method for
                             discovering the remote IP address to use for mosh
                             (default: "proxy")

        --help               this message
        --version            version and copyright information

This is mosh with experimental port forwarding (https://wmacevoy.github.io/mosh/).
Please report bugs in it at https://github.com/wmacevoy/mosh/issues,
not to the mosh project.  Mosh home page: https://mosh.org\n};

my $copy_usage =
qq{Usage: mocp [options] SOURCE... DESTINATION

Copies files to or from another machine through a mosh session, so that the
copy survives losing the network, changing networks, and sleep, and carries
on where it left off. Exactly one end is remote: [user@]host:path

  mocp report.pdf server:docs/         to the server
  mocp -r server:build/out .           from it, with what is inside
  mocp --auto -r server:build/out .    and then keep ./out up to date

-r                  directories, and everything in them
        --auto      when the copy is done, stay, and copy again whatever
                       changes at the source (until interrupted)
        --delete    also remove from the destination what is no longer
                       at the source (within the directories copied)
        --interval=SECONDS
                    how often --auto looks for changes (default: 2)
-q                  say only what goes wrong

A file is replaced only when the whole of it has arrived. Files that are
already the same (by size and time) are not sent again. Options of mosh
that concern the connection (--ssh, --relay, -p, --server, ...) work here.
)USAGE";

const char COPY_USAGE[] = R"USAGE(Usage: mocp [options] SOURCE... DESTINATION

Copies files to or from another machine through a mosh session, so that the
copy survives losing the network, changing networks, and sleep, and carries
on where it left off. Exactly one end is remote: [user@]host:path

  mocp report.pdf server:docs/         to the server
  mocp -r server:build/out .           from it, with what is inside
  mocp --auto -r server:build/out .    and then keep ./out up to date

-r                  directories, and everything in them
        --auto      when the copy is done, stay, and copy again whatever
                       changes at the source (until interrupted)
        --delete    also remove from the destination what is no longer
                       at the source (within the directories copied)
        --interval=SECONDS
                    how often --auto looks for changes (default: 2)
-q                  say only what goes wrong

A file is replaced only when the whole of it has arrived. Files that are
already the same (by size and time) are not sent again. Options of mosh
that concern the connection (--ssh, --relay, -p, --server, ...) work here.
)USAGE";

/* The server, unless told otherwise: mosh-server, looked for in ~/.local/bin as well (see scripts/mosh.pl). */
const char DEFAULT_SERVER[] = R"(sh -c 'PATH="$HOME/.local/bin:$PATH"; export PATH; exec mosh-server "$@"' mosh-server)";

struct Failure
{
  std::string message;
  bool with_usage;
  explicit Failure( const std::string& s_message, bool s_with_usage = false )
    : message( s_message ), with_usage( s_with_usage )
  {}
};

/* ---- options, as Getopt::Long took them: -name or --name, a value after "=" or as the next word */

struct Option
{
  const char* names; /* separated by | */
  bool takes_value;
  bool negatable;
};

const Option OPTIONS[] = {
  { "client", true, false },
  { "server", true, false },
  { "predict", true, false },
  { "predict-overwrite|o", false, true },
  { "port|p", true, false },
  { "a", false, false },
  { "n", false, false },
  { "family", true, false },
  { "4", false, false },
  { "6", false, false },
  { "ssh", true, false },
  { "ssh-pty", false, true },
  { "init", false, true },
  { "local", false, false },
  { "help", false, false },
  { "version", false, false },
  { "bind-server", true, false },
  { "udp-forward|LU", true, false },
  { "udp-remote-forward|RU", true, false },
  { "tcp-forward|L", true, false },
  { "tcp-remote-forward|R", true, false },
  { "fragment-parity", true, false },
  { "no-fragment-parity", false, false },
  { "N", false, false },
  { "relay", true, false },
  { "copy", false, false },
  { "r", false, false },
  { "auto", false, false },
  { "delete", false, false },
  { "q", false, false },
  { "interval", true, false },
  { "stdio", false, false },
  { "l", true, false },
  { "experimental-remote-ip", true, false },
};

std::vector<std::string> split( const std::string& s, char at )
{
  std::vector<std::string> parts;
  size_t start = 0;
  while ( true ) {
    const size_t end = s.find( at, start );
    parts.push_back( s.substr( start, end == std::string::npos ? end : end - start ) );
    if ( end == std::string::npos ) {
      return parts;
    }
    start = end + 1;
  }
}

/* The option a word names (by its first name), and whether it was negated; NULL if none or several. */
const Option* find_option( const std::string& word, bool double_dash, bool& negated )
{
  negated = false;
  const Option* prefix_match = NULL;
  int prefix_matches = 0;
  for ( size_t i = 0; i < sizeof( OPTIONS ) / sizeof( OPTIONS[0] ); i++ ) {
    const std::vector<std::string> names = split( OPTIONS[i].names, '|' );
    for ( size_t j = 0; j < names.size(); j++ ) {
      if ( word == names[j] ) {
        return &OPTIONS[i];
      }
      if ( OPTIONS[i].negatable && ( word == "no" + names[j] || word == "no-" + names[j] ) ) {
        negated = true;
        return &OPTIONS[i];
      }
      /* a long name may be cut short, if what is left is still only one */
      if ( double_dash && names[j].size() > 1 && word.size() > 1 && names[j].compare( 0, word.size(), word ) == 0 ) {
        if ( prefix_match != &OPTIONS[i] ) {
          prefix_match = &OPTIONS[i];
          prefix_matches++;
        }
      }
    }
  }
  return prefix_matches == 1 ? prefix_match : NULL;
}

struct Settings
{
  std::map<std::string, std::vector<std::string> > values; /* by an option's first name */
  std::map<std::string, bool> flags;
  std::vector<std::string> rest;

  Settings() : values(), flags(), rest() {}

  bool flag( const char* name, bool otherwise = false ) const
  {
    std::map<std::string, bool>::const_iterator it = flags.find( name );
    return it == flags.end() ? otherwise : it->second;
  }
  bool has( const char* name ) const { return values.find( name ) != values.end(); }
  std::string value( const char* name, const std::string& otherwise = "" ) const
  {
    std::map<std::string, std::vector<std::string> >::const_iterator it = values.find( name );
    return it == values.end() ? otherwise : it->second.back();
  }
  std::vector<std::string> all( const char* name ) const
  {
    std::map<std::string, std::vector<std::string> >::const_iterator it = values.find( name );
    return it == values.end() ? std::vector<std::string>() : it->second;
  }
};

void parse_options( const std::vector<std::string>& args, bool in_order, Settings& settings )
{
  for ( size_t i = 0; i < args.size(); i++ ) {
    const std::string& arg = args[i];
    if ( arg == "--" ) {
      /* (kept, in order: with --stdio it may stand between the host and the command) */
      if ( in_order ) {
        settings.rest.insert( settings.rest.end(), args.begin() + i, args.end() );
      } else {
        settings.rest.insert( settings.rest.end(), args.begin() + i + 1, args.end() );
      }
      return;
    }
    if ( arg.size() < 2 || arg[0] != '-' ) {
      if ( in_order ) {
        settings.rest.insert( settings.rest.end(), args.begin() + i, args.end() );
        return;
      }
      settings.rest.push_back( arg );
      continue;
    }
    const bool double_dash = arg[1] == '-';
    std::string word = arg.substr( double_dash ? 2 : 1 );
    std::string value;
    const size_t equals = word.find( '=' );
    const bool has_value = equals != std::string::npos;
    if ( has_value ) {
      value = word.substr( equals + 1 );
      word = word.substr( 0, equals );
    }
    bool negated;
    const Option* option = find_option( word, double_dash, negated );
    if ( !option ) {
      throw Failure( "Unknown option: " + word, true );
    }
    const std::string name = split( option->names, '|' )[0];
    if ( option->takes_value ) {
      if ( !has_value ) {
        if ( i + 1 >= args.size() ) {
          throw Failure( "Option " + word + " requires an argument", true );
        }
        value = args[++i];
      }
      settings.values[name].push_back( value );
    } else {
      if ( has_value ) {
        throw Failure( "Option " + word + " does not take an argument", true );
      }
      settings.flags[name] = !negated;
    }
  }
}

bool one_of( const std::string& word, const char* choices )
{
  const std::vector<std::string> all = split( choices, ' ' );
  for ( size_t i = 0; i < all.size(); i++ ) {
    if ( word == all[i] ) {
      return true;
    }
  }
  return false;
}

std::string lower( std::string s )
{
  for ( size_t i = 0; i < s.size(); i++ ) {
    s[i] = static_cast<char>( tolower( static_cast<unsigned char>( s[i] ) ) );
  }
  return s;
}

bool all_digits( const std::string& s )
{
  return !s.empty() && s.find_first_not_of( "0123456789" ) == std::string::npos;
}

void check_port_request( const std::string& request, const std::string& name )
{
  const size_t colon = request.find( ':' );
  const std::string low = request.substr( 0, colon );
  const std::string high = colon == std::string::npos ? "" : request.substr( colon + 1 );
  if ( !all_digits( low ) || low.size() > 6 || ( colon != std::string::npos && ( !all_digits( high ) || high.size() > 6 ) ) ) {
    throw Failure( name + ": Server-side port or range (" + request + ") is not valid." );
  }
  const long l = atol( low.c_str() ), h = atol( high.c_str() );
  if ( l > 65535 ) {
    throw Failure( name + ": Server-side (low) port (" + low + ") must be within valid range [0..65535]." );
  }
  if ( colon != std::string::npos ) {
    if ( h <= 0 || h > 65535 ) {
      throw Failure( name + ": Server-side high port (" + high + ") must be within valid range [1..65535]." );
    }
    if ( l == 0 ) {
      throw Failure( name + ": Server-side port ranges may not be used with starting port 0 (" + request + ")." );
    }
    if ( l > h ) {
      throw Failure( name + ": Server-side port range (" + request + "): low port greater than high port." );
    }
  }
}

/* The addresses of a host, as --family would have them.  Throws Failure. */
struct Address
{
  int family;
  struct sockaddr_storage addr;
  socklen_t len;
  std::string text;
  Address() : family( 0 ), addr(), len( 0 ), text() {}
};

std::vector<Address> resolve( const std::string& host, const std::string& port, const std::string& family,
                              const std::string& name )
{
  int af = AF_UNSPEC;
  if ( family == "inet" ) {
    af = AF_INET;
  } else if ( family == "inet6" ) {
    af = AF_INET6;
  }

  struct addrinfo hints, *res = NULL;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = af;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICHOST;
  int err = getaddrinfo( host.c_str(), port.c_str(), &hints, &res );
  if ( err ) {
    hints.ai_flags = 0;
    err = getaddrinfo( host.c_str(), port.c_str(), &hints, &res );
    if ( err ) {
      throw Failure( name + ": could not resolve " + host + ": " + gai_strerror( err ) );
    }
  }

  std::vector<Address> found;
  for ( struct addrinfo* ai = res; ai; ai = ai->ai_next ) {
    char text[NI_MAXHOST];
    if ( getnameinfo( ai->ai_addr, ai->ai_addrlen, text, sizeof( text ), NULL, 0, NI_NUMERICHOST ) != 0 ) {
      continue;
    }
    Address a;
    a.family = ai->ai_family;
    memcpy( &a.addr, ai->ai_addr, ai->ai_addrlen );
    a.len = ai->ai_addrlen;
    a.text = text;
    found.push_back( a );
  }
  freeaddrinfo( res );

  if ( family.compare( 0, 7, "prefer-" ) == 0 ) {
    const int preferred = family == "prefer-inet6" ? AF_INET6 : AF_INET;
    std::vector<Address> ordered;
    for ( int pass = 0; pass < 2; pass++ ) {
      for ( size_t i = 0; i < found.size(); i++ ) {
        if ( ( found[i].family == preferred ) == ( pass == 0 ) ) {
          ordered.push_back( found[i] );
        }
      }
    }
    found = ordered;
  } else if ( af == AF_UNSPEC && family != "all" ) {
    /* "auto": for hosts with addresses of one kind only */
    for ( size_t i = 1; i < found.size(); i++ ) {
      if ( found[i].family != found[0].family ) {
        throw Failure( name + ": host has both IPv4 and IPv6 addresses, use --family to specify behavior" );
      }
    }
  }
  return found;
}

/* Where this program is, for ssh to run it again as its ProxyCommand. */
std::string self_path( const std::string& argv0 )
{
  char buf[4096];
#ifdef __APPLE__
  uint32_t size = sizeof( buf );
  if ( _NSGetExecutablePath( buf, &size ) == 0 ) {
    return buf;
  }
#else
  const ssize_t n = readlink( "/proc/self/exe", buf, sizeof( buf ) - 1 );
  if ( n > 0 ) {
    buf[n] = '\0';
    return buf;
  }
#endif
  if ( argv0.find( '/' ) != std::string::npos ) {
    if ( argv0[0] == '/' ) {
      return argv0;
    }
    if ( getcwd( buf, sizeof( buf ) ) ) {
      return std::string( buf ) + "/" + argv0;
    }
    return argv0;
  }
  const char* path = getenv( "PATH" );
  const std::vector<std::string> dirs = split( path ? path : "", ':' );
  for ( size_t i = 0; i < dirs.size(); i++ ) {
    const std::string candidate = ( dirs[i].empty() ? "." : dirs[i] ) + "/" + argv0;
    if ( access( candidate.c_str(), X_OK ) == 0 ) {
      return candidate;
    }
  }
  return argv0;
}

/* That path as something ssh can be given to run. */
std::string proxy_command( const std::string& self, const std::string& family )
{
#ifdef __CYGWIN__
  /* ssh may be Windows's own, which runs this with cmd.exe: a Windows path, in double quotes */
  char windows[4096];
  std::string path = self;
  if ( cygwin_conv_path( CCP_POSIX_TO_WIN_A | CCP_ABSOLUTE, self.c_str(), windows, sizeof( windows ) ) == 0 ) {
    path = windows;
  }
  return "\"" + path + "\" --mosh-fake-proxy " + family + " %h %p";
#else
  return shell_quote( std::vector<std::string>( 1, self ) ) + " --mosh-fake-proxy " + family + " %h %p";
#endif
}

std::string strip_end( std::string s )
{
  while ( !s.empty() && ( s[s.size() - 1] == '\r' || s[s.size() - 1] == '\n' || s[s.size() - 1] == ' ' ) ) {
    s.erase( s.size() - 1 );
  }
  return s;
}

std::string join( const std::vector<std::string>& words, const std::string& with )
{
  std::string s;
  for ( size_t i = 0; i < words.size(); i++ ) {
    s += ( i ? with : "" ) + words[i];
  }
  return s;
}

void exec_words( const std::vector<std::string>& words )
{
  std::vector<char*> argv;
  for ( size_t i = 0; i < words.size(); i++ ) {
    argv.push_back( const_cast<char*>( words[i].c_str() ) );
  }
  argv.push_back( NULL );
  execvp( argv[0], argv.data() );
}

}

std::vector<std::string> MoshWrapper::shell_words( const std::string& line )
{
  std::vector<std::string> words;
  std::string word;
  bool in_word = false;
  char quote = 0;
  for ( size_t i = 0; i < line.size(); i++ ) {
    const char c = line[i];
    if ( quote ) {
      if ( c == quote ) {
        quote = 0;
      } else if ( c == '\\' && quote == '"' && i + 1 < line.size() ) {
        word.push_back( line[++i] );
      } else {
        word.push_back( c );
      }
    } else if ( c == '\'' || c == '"' ) {
      quote = c;
      in_word = true;
    } else if ( c == '\\' && i + 1 < line.size() ) {
      word.push_back( line[++i] );
      in_word = true;
    } else if ( c == ' ' || c == '\t' || c == '\n' ) {
      if ( in_word ) {
        words.push_back( word );
        word.clear();
        in_word = false;
      }
    } else {
      word.push_back( c );
      in_word = true;
    }
  }
  if ( in_word ) {
    words.push_back( word );
  }
  return words;
}

std::string MoshWrapper::shell_quote( const std::vector<std::string>& words )
{
  std::string s;
  for ( size_t i = 0; i < words.size(); i++ ) {
    s += i ? " '" : "'";
    for ( size_t j = 0; j < words[i].size(); j++ ) {
      if ( words[i][j] == '\'' ) {
        s += "'\\''";
      } else {
        s.push_back( words[i][j] );
      }
    }
    s += "'";
  }
  return s;
}

bool MoshWrapper::remote_place( const std::string& word, std::string& host, std::string& path )
{
  /* [user@]host:path.  A colon after a slash, or after a single letter (a Windows drive), is part of a local name. */
  const size_t colon = word.find( ':' );
  if ( colon == std::string::npos || colon < 2 || word.find( '/' ) < colon ) {
    return false;
  }
  host = word.substr( 0, colon );
  path = word.substr( colon + 1 );
  return true;
}

int MoshWrapper::fake_proxy( const std::string& family, const std::string& host, const std::string& port )
{
  std::vector<Address> addresses;
  try {
    addresses = resolve( host, port, family, "mosh" );
  } catch ( const Failure& f ) {
    fprintf( stderr, "%s\n", f.message.c_str() );
    return 1;
  }

  int sock = -1;
  std::string tried, why = "no addresses";
  for ( size_t i = 0; i < addresses.size() && sock < 0; i++ ) {
    tried = addresses[i].text;
    sock = socket( addresses[i].family, SOCK_STREAM, IPPROTO_TCP );
    if ( sock >= 0
         && connect( sock, reinterpret_cast<const struct sockaddr*>( &addresses[i].addr ), addresses[i].len ) < 0 ) {
      why = strerror( errno );
      close( sock );
      sock = -1;
    }
  }
  if ( sock < 0 ) {
    fprintf( stderr, "mosh: Could not connect to %s, last tried %s: %s\n", host.c_str(), tried.c_str(), why.c_str() );
    return 1;
  }
  fprintf( stderr, "MOSH IP %s\n", tried.c_str() );
  fflush( stderr );

  /* Act like netcat */
  signal( SIGHUP, SIG_IGN );
  signal( SIGPIPE, SIG_IGN );
  std::string to_sock, to_out;
  bool in_open = true, in_shut = false, sock_open = true;
  char buf[16384];
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
      const ssize_t n = read( STDIN_FILENO, buf, sizeof( buf ) );
      if ( n > 0 ) {
        to_sock.append( buf, n );
      } else if ( n == 0 || errno != EINTR ) {
        in_open = false;
      }
    }
    if ( read_sock && ( fds[1].revents & ( POLLIN | POLLHUP | POLLERR ) ) ) {
      const ssize_t n = recv( sock, buf, sizeof( buf ), 0 );
      if ( n > 0 ) {
        to_out.append( buf, n );
      } else if ( n == 0 || errno != EINTR ) {
        sock_open = false;
      }
    }
    if ( !to_sock.empty() && ( fds[1].revents & POLLOUT ) ) {
      const ssize_t n = send( sock, to_sock.data(), to_sock.size(), 0 );
      if ( n > 0 ) {
        to_sock.erase( 0, n );
      } else if ( n < 0 && errno != EINTR ) {
        return 1;
      }
    }
    if ( !in_open && !in_shut && to_sock.empty() ) {
      shutdown( sock, SHUT_WR );
      in_shut = true;
    }
    if ( fds[2].revents ) {
      const ssize_t n = write( STDOUT_FILENO, to_out.data(), to_out.size() );
      if ( n > 0 ) {
        to_out.erase( 0, n );
      } else if ( n < 0 && errno != EINTR ) {
        return 1;
      }
    }
  }
  return 0;
}

bool MoshWrapper::run( const std::vector<std::string>& args,
                       bool copy,
                       const std::string& name,
                       const std::string& self,
                       void ( *print_colors )( void ),
                       std::vector<std::string>& client_args,
                       int& status )
{
  status = 1;
  try {
    Settings s;
    bool stdio = false;
    for ( size_t i = 0; i < args.size() && args[i] != "--"; i++ ) {
      stdio = stdio || args[i] == "--stdio";
    }
    /*
     * With --stdio we stand where ssh would, for a program such as rsync
     * that runs "ssh [-l user] host command -with --options": what follows
     * the host is the command's, not ours.
     */
    parse_options( args, stdio, s );
    copy = copy || s.flag( "copy" );
    stdio = s.flag( "stdio" );

    if ( s.flag( "help" ) ) {
      if ( copy ) {
        fputs( COPY_USAGE, stdout );
      } else {
        printf( USAGE, name.c_str() );
      }
      status = 0;
      return false;
    }
    if ( s.flag( "version" ) ) {
      printf( "%s [build %s]\n"
              "Copyright 2012 Keith Winstein <mosh-devel@mit.edu>\n"
              "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
              "This is free software: you are free to change and redistribute it.\n"
              "There is NO WARRANTY, to the extent permitted by law.\n",
              PACKAGE_STRING, BUILD_VERSION );
      status = 0;
      return false;
    }

    std::string fragment_parity = s.value( "fragment-parity" );
    if ( s.flag( "no-fragment-parity" ) ) {
      fragment_parity = "never";
    }
    if ( !fragment_parity.empty() && !one_of( fragment_parity, "auto always never" ) ) {
      throw Failure( name + ": Unknown fragment parity mode \"" + fragment_parity + "\".", true );
    }
    const std::string relay = s.value( "relay", "auto" );
    if ( !one_of( relay, "auto always never" ) ) {
      throw Failure( name + ": Unknown relay mode \"" + relay + "\".", true );
    }

    std::string predict = s.value( "predict" );
    if ( s.flag( "a" ) ) {
      predict = "always";
    }
    if ( s.flag( "n" ) ) {
      predict = "never";
    }
    if ( predict.empty() ) {
      const char* from_env = getenv( "MOSH_PREDICTION_DISPLAY" );
      predict = from_env ? from_env : "adaptive";
    }
    if ( !one_of( predict, "adaptive always never experimental" ) ) {
      throw Failure( name + ": Unknown mode \"" + predict + "\".", true );
    }

    const std::string remote_ip = s.value( "experimental-remote-ip", "proxy" );
    if ( !one_of( remote_ip, "local remote proxy" ) ) {
      throw Failure( "Unknown parameter " + remote_ip );
    }

    std::string family = lower( s.value( "family", "prefer-inet" ) );
    if ( s.flag( "4" ) ) {
      family = "inet";
    }
    if ( s.flag( "6" ) ) {
      family = "inet6";
    }
    if ( !one_of( family, "inet inet6 auto all prefer-inet prefer-inet6" ) ) {
      throw Failure( name + ": Invalid family " + family );
    }

    if ( s.has( "port" ) ) {
      check_port_request( s.value( "port" ), name );
    }

    /* ---- what the session is for */

    bool headless = s.flag( "N" );
    std::vector<std::string> rest = s.rest;
    std::vector<std::string> stream_local, stream_remote;

    if ( copy ) {
      /* Copying files: work out which end is which, and what each is to do. */
      if ( rest.size() < 2 ) {
        throw Failure( COPY_USAGE );
      }
      std::vector<std::string> flags;
      if ( s.flag( "r" ) ) {
        flags.push_back( "-r" );
      }
      if ( s.flag( "auto" ) ) {
        flags.push_back( "--auto" );
      }
      if ( s.flag( "delete" ) ) {
        flags.push_back( "--delete" );
      }
      if ( s.has( "interval" ) ) {
        const double seconds = atof( s.value( "interval" ).c_str() );
        if ( seconds < 0.1 ) {
          throw Failure( name + ": --interval must be at least 0.1 (seconds)." );
        }
        char word[40];
        snprintf( word, sizeof( word ), "--interval=%d", static_cast<int>( seconds * 1000 ) );
        flags.push_back( word );
      }
      std::vector<std::string> here = flags;
      if ( s.flag( "q" ) ) {
        here.push_back( "-q" );
      }

      std::vector<std::string> hosts, paths;
      for ( size_t i = 0; i < rest.size(); i++ ) {
        std::string host, path = rest[i];
        remote_place( rest[i], host, path );
        if ( path.find( '\x1f' ) != std::string::npos ) {
          throw Failure( name + ": a file name cannot contain the character with code 31." );
        }
        hosts.push_back( host );
        paths.push_back( path );
      }
      const std::string dest_host = hosts.back(), dest_path = paths.back();
      hosts.pop_back();
      paths.pop_back();

      std::string host;
      stream_local.push_back( "@copy" );
      stream_remote.push_back( "@copy" );
      if ( !dest_host.empty() ) {
        for ( size_t i = 0; i < hosts.size(); i++ ) {
          if ( !hosts[i].empty() ) {
            throw Failure( name + ": one end of a copy has to be this machine." );
          }
        }
        host = dest_host;
        stream_local.push_back( "send" );
        stream_local.insert( stream_local.end(), here.begin(), here.end() );
        stream_local.push_back( "--" );
        stream_local.insert( stream_local.end(), paths.begin(), paths.end() );
        stream_remote.push_back( "receive" );
        stream_remote.insert( stream_remote.end(), flags.begin(), flags.end() );
        stream_remote.push_back( "--" );
        stream_remote.push_back( dest_path.empty() ? "." : dest_path );
      } else {
        host = hosts[0];
        if ( host.empty() ) {
          throw Failure( name + ": one end of a copy has to be another machine: [user@]host:path" );
        }
        for ( size_t i = 0; i < hosts.size(); i++ ) {
          if ( hosts[i] != host ) {
            throw Failure( name + ": the sources have to be on one machine." );
          }
          if ( paths[i].empty() ) {
            throw Failure( name + ": what is to be copied from " + host + "?" );
          }
        }
        /* (patterns are for the other end to expand, as a shell there would) */
        stream_remote.push_back( "send" );
        stream_remote.insert( stream_remote.end(), flags.begin(), flags.end() );
        stream_remote.push_back( "--glob" );
        stream_remote.push_back( "--" );
        stream_remote.insert( stream_remote.end(), paths.begin(), paths.end() );
        stream_local.push_back( "receive" );
        stream_local.insert( stream_local.end(), here.begin(), here.end() );
        stream_local.push_back( "--" );
        stream_local.push_back( dest_path );
      }
      rest.assign( 1, host );
      headless = true;
    } else if ( stdio ) {
      /* (the command may be set off with "--") */
      if ( rest.size() > 1 && rest[1] == "--" ) {
        rest.erase( rest.begin() + 1 );
      }
      if ( rest.size() < 2 ) {
        throw Failure( name + ": --stdio needs a command to run on the server.", true );
      }
      /* as ssh would: the words joined, for the shell at the other end */
      stream_remote.push_back( "@sh" );
      stream_remote.push_back( join( std::vector<std::string>( rest.begin() + 1, rest.end() ), " " ) );
      stream_local.push_back( "@stdio" );
      if ( s.has( "l" ) && rest[0].find( '@' ) == std::string::npos ) {
        rest[0] = s.value( "l" ) + "@" + rest[0];
      }
      rest.resize( 1 );
      headless = true;
    }

    if ( rest.empty() ) {
      throw Failure( "", true );
    }
    std::string userhost = rest[0];
    std::vector<std::string> command( rest.begin() + 1, rest.end() );
    const bool local = s.flag( "local" );

    std::vector<std::string> bind_arguments;
    const std::string bind = s.value( "bind-server" );
    if ( bind.empty() || lower( bind ) == "ssh" ) {
      if ( local ) {
        bind_arguments.push_back( "-i" );
        bind_arguments.push_back( userhost );
      } else {
        bind_arguments.push_back( "-s" );
      }
    } else if ( lower( bind ) != "any" ) {
      bind_arguments.push_back( "-i" );
      bind_arguments.push_back( bind );
    }

    /* ---- how many colors the terminal has, for the server to know */

    std::string colors = "0";
    if ( headless ) {
      /* There is no terminal to have any.  Nor anything to run in it: so, unless told, something that waits. */
      if ( command.empty() ) {
        command.push_back( "sh" );
        command.push_back( "-c" );
        command.push_back( "while :; do sleep 86400; done" );
      }
    } else {
      /* (asked of another process, as the script asked "mosh-client -c": the terminal is set up once, later) */
      int fds[2];
      if ( pipe( fds ) < 0 ) {
        throw Failure( name + ": pipe: " + strerror( errno ) );
      }
      fflush( NULL );
      const pid_t pid = fork();
      if ( pid == 0 ) {
        close( fds[0] );
        dup2( fds[1], STDOUT_FILENO );
        print_colors();
        fflush( stdout );
        _exit( 0 );
      }
      close( fds[1] );
      std::string said;
      char buf[64];
      ssize_t n;
      while ( ( n = read( fds[0], buf, sizeof( buf ) ) ) > 0 ) {
        said.append( buf, n );
      }
      close( fds[0] );
      if ( pid > 0 ) {
        waitpid( pid, NULL, 0 );
      }
      said = strip_end( said );
      if ( all_digits( said ) ) {
        colors = said;
      }
    }

    /* ---- the server's address, if it is for us to find */

    std::string ip;
    if ( remote_ip == "local" ) {
      const size_t at = userhost.rfind( '@' );
      const std::string user = at == std::string::npos ? "" : userhost.substr( 0, at + 1 );
      const std::string host = at == std::string::npos ? userhost : userhost.substr( at + 1 );
      const std::vector<Address> found = resolve( host, "22", family, name );
      if ( found.empty() ) {
        throw Failure( "could not find address for " + host );
      }
      ip = found[0].text;
      userhost = user + ip;
    }

    /* ---- start the server, by ssh, and hear from it */

    const std::string server = s.value( "server", DEFAULT_SERVER );
    const std::vector<std::string> ssh = shell_words( s.value( "ssh", "ssh" ) );
    if ( ssh.empty() ) {
      throw Failure( name + ": --ssh needs a command." );
    }

    std::vector<std::string> server_args;
    server_args.push_back( "new" );
    server_args.push_back( "-c" );
    server_args.push_back( colors );
    server_args.insert( server_args.end(), bind_arguments.begin(), bind_arguments.end() );
    if ( s.has( "port" ) ) {
      server_args.push_back( "-p" );
      server_args.push_back( s.value( "port" ) );
    }
    const char* const locale_names[] = { "LANG", "LANGUAGE", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE",
                                         "LC_MONETARY", "LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS",
                                         "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION", "LC_ALL" };
    for ( size_t i = 0; i < sizeof( locale_names ) / sizeof( locale_names[0] ); i++ ) {
      if ( const char* value = getenv( locale_names[i] ) ) {
        server_args.push_back( "-l" );
        server_args.push_back( std::string( locale_names[i] ) + "=" + value );
      }
    }
    const char* const forward_options[][2] = { { "udp-forward", "-LU" }, { "udp-remote-forward", "-RU" },
                                               { "tcp-forward", "-L" }, { "tcp-remote-forward", "-R" } };
    std::vector<std::string> forward_args;
    for ( size_t i = 0; i < 4; i++ ) {
      const std::vector<std::string> specs = s.all( forward_options[i][0] );
      for ( size_t j = 0; j < specs.size(); j++ ) {
        forward_args.push_back( forward_options[i][1] );
        forward_args.push_back( specs[j] );
      }
    }
    if ( !fragment_parity.empty() ) {
      forward_args.push_back( "-F" );
      forward_args.push_back( fragment_parity );
    }
    server_args.insert( server_args.end(), forward_args.begin(), forward_args.end() );
    if ( !stream_remote.empty() ) {
      server_args.push_back( "-X" );
      server_args.push_back( join( stream_remote, "\x1f" ) );
    }
    if ( !command.empty() ) {
      server_args.push_back( "--" );
      server_args.insert( server_args.end(), command.begin(), command.end() );
    }
    const std::string server_command = server + " " + shell_quote( server_args );

    int fds[2];
    if ( pipe( fds ) < 0 ) {
      throw Failure( name + ": pipe: " + strerror( errno ) );
    }
    fflush( NULL );
    const pid_t pid = fork();
    if ( pid < 0 ) {
      throw Failure( name + ": fork: " + strerror( errno ) );
    }
    if ( pid == 0 ) {
      close( fds[0] );
      dup2( fds[1], STDOUT_FILENO );
      dup2( fds[1], STDERR_FILENO );
      close( fds[1] );

      if ( local ) {
        unsetenv( "SSH_CONNECTION" );
        const char* home = getenv( "HOME" );
        if ( home && chdir( home ) < 0 ) {
          /* then from here */
        }
        const std::string line = "MOSH IP " + userhost + "\n";
        if ( write( STDOUT_FILENO, line.data(), line.size() ) < 0 ) {
          _exit( 1 );
        }
        execl( "/bin/sh", "sh", "-c", server_command.c_str(), static_cast<char*>( NULL ) );
        const std::string why = "Cannot exec " + server + ": " + strerror( errno ) + "\n";
        if ( write( STDOUT_FILENO, why.data(), why.size() ) < 0 ) {
          _exit( 1 );
        }
        _exit( 1 );
      }

      std::vector<std::string> words = ssh;
      words.push_back( "-n" );
      if ( s.flag( "ssh-pty", true ) ) {
        words.push_back( "-tt" );
      }
      std::string ask_address;
      if ( remote_ip == "remote" ) {
        /* Ask the server for its address.  The login shell may not be a Bourne shell, so say which. */
        ask_address = "sh -c "
                      + shell_quote( std::vector<std::string>(
                        1, "[ -n \"$SSH_CONNECTION\" ] && printf \"\\nMOSH SSH_CONNECTION %s\\n\" \"$SSH_CONNECTION\"" ) )
                      + " ; ";
        if ( family == "inet" ) {
          words.push_back( "-4" );
        } else if ( family == "inet6" ) {
          words.push_back( "-6" );
        }
      } else if ( remote_ip == "proxy" ) {
        /* Unusual shells, and what they are told to do at start, break a ProxyCommand mysteriously. */
        setenv( "SHELL", "/bin/sh", 1 );
        words.push_back( "-S" );
        words.push_back( "none" );
        words.push_back( "-o" );
        words.push_back( "ProxyCommand=" + proxy_command( self_path( self ), family ) );
      }
      words.push_back( userhost );
      words.push_back( "--" );
      words.push_back( ask_address + server_command );
      exec_words( words );
      const std::string why = "Cannot exec ssh: " + std::string( strerror( errno ) ) + "\n";
      if ( write( STDOUT_FILENO, why.data(), why.size() ) < 0 ) {
        _exit( 1 );
      }
      _exit( 1 );
    }

    close( fds[1] );
    std::string port, key, ssh_ip, pending;
    bool bad_port = false, done = false;
    char buf[4096];
    ssize_t n;
    while ( !done && ( n = read( fds[0], buf, sizeof( buf ) ) ) != 0 ) {
      if ( n < 0 ) {
        if ( errno == EINTR ) {
          continue;
        }
        break;
      }
      pending.append( buf, n );
      size_t end;
      while ( !done && ( end = pending.find( '\n' ) ) != std::string::npos ) {
        const std::string raw = pending.substr( 0, end );
        pending.erase( 0, end + 1 );
        const std::string line = strip_end( raw );
        const std::vector<std::string> words = shell_words( line );
        if ( line.compare( 0, 8, "MOSH IP " ) == 0 ) {
          if ( !ip.empty() ) {
            throw Failure( name + " error: detected attempt to redefine MOSH IP." );
          }
          if ( words.size() != 3 ) {
            throw Failure( "Bad MOSH IP string: " + line );
          }
          ip = words[2];
        } else if ( line.compare( 0, 20, "MOSH SSH_CONNECTION " ) == 0 ) {
          if ( words.size() != 6 ) {
            throw Failure( "Bad MOSH SSH_CONNECTION string: " + line );
          }
          ssh_ip = words[4];
        } else if ( line.compare( 0, 13, "MOSH CONNECT " ) == 0 ) {
          if ( words.size() != 4 || !all_digits( words[2] ) || words[3].size() != 22
               || words[3].find_first_not_of( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+" )
                    != std::string::npos ) {
            throw Failure( "Bad MOSH CONNECT string: " + line );
          }
          port = words[2];
          key = words[3];
          done = true;
        } else {
          if ( s.has( "port" ) && s.value( "port" ).find( ':' ) != std::string::npos
               && line.find( "Bad UDP port" ) != std::string::npos ) {
            bad_port = true;
          }
          /* what ssh or the login had to say (not on our output if that is carrying data) */
          if ( !stream_local.empty() ) {
            if ( !line.empty() ) {
              fprintf( stderr, "%s\n", raw.c_str() );
            }
          } else {
            printf( "%s\n", raw.c_str() );
            fflush( stdout );
          }
        }
      }
    }
    close( fds[0] );
    waitpid( pid, NULL, 0 );

    if ( ip.empty() ) {
      if ( ssh_ip.empty() ) {
        throw Failure( name + ": Did not find remote IP address (is SSH ProxyCommand disabled?)." );
      }
      fprintf( stderr, "%s: Using remote IP address %s from $SSH_CONNECTION for hostname %s\n", name.c_str(),
               ssh_ip.c_str(), userhost.c_str() );
      ip = ssh_ip;
    }
    if ( key.empty() || port.empty() ) {
      if ( bad_port ) {
        throw Failure( name + ": Server does not support UDP port range option." );
      }
      throw Failure( name + ": Did not find mosh server startup message. (Have you installed mosh on your server?)" );
    }

    /* ---- become the client */

    setenv( "MOSH_KEY", key.c_str(), 1 );
    setenv( "MOSH_PREDICTION_DISPLAY", predict.c_str(), 1 );
    if ( !s.flag( "init", true ) ) {
      setenv( "MOSH_NO_TERM_INIT", "1", 1 );
    }
    if ( s.flag( "predict-overwrite" ) ) {
      setenv( "MOSH_PREDICTION_OVERWRITE", "yes", 1 );
    }

    /*
     * If UDP will not reach the server, the client can carry the session
     * over ssh instead, by running a relay on the server.  ssh must not ask
     * for anything, because the terminal will be the session's by then.
     */
    if ( relay != "never" ) {
      const std::string remote = server + " relay " + shell_quote( std::vector<std::string>( 1, ip ) ) + " "
                                 + shell_quote( std::vector<std::string>( 1, port ) );
      std::vector<std::string> words;
      if ( local ) {
        words.push_back( "sh" );
        words.push_back( "-c" );
        words.push_back( remote );
      } else {
        words = ssh;
        words.push_back( "-T" );
        words.push_back( "-o" );
        words.push_back( "BatchMode=yes" );
        words.push_back( userhost );
        words.push_back( "--" );
        words.push_back( remote );
      }
      setenv( "MOSH_RELAY_COMMAND", join( words, "\x1f" ).c_str(), 1 );
      setenv( "MOSH_RELAY", relay.c_str(), 1 );
    } else {
      setenv( "MOSH_RELAY", "never", 1 );
    }

    client_args.clear();
    client_args.push_back( "mosh-client" );
    client_args.push_back( "-# " + join( args, " " ) + " |" ); /* (for whoever lists processes: what was asked) */
    client_args.insert( client_args.end(), forward_args.begin(), forward_args.end() );
    if ( !stream_local.empty() ) {
      client_args.push_back( "-X" );
      client_args.push_back( join( stream_local, "\x1f" ) );
    } else if ( headless ) {
      client_args.push_back( "-N" );
    }
    client_args.push_back( ip );
    client_args.push_back( port );
    return true;
  } catch ( const Failure& f ) {
    if ( !f.message.empty() ) {
      fprintf( stderr, "%s\n", f.message.c_str() );
    }
    if ( f.with_usage ) {
      fputs( "\n", stderr );
      if ( copy ) {
        fputs( COPY_USAGE, stderr );
      } else {
        fprintf( stderr, USAGE, name.c_str() );
      }
    }
    return false;
  }
}
