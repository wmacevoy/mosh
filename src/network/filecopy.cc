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
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "src/network/filecopy.h"

using namespace FileCopy;

void Hash::add( const char* data, size_t len )
{
  uint64_t x = a, y = b;
  for ( size_t i = 0; i < len; i++ ) {
    const uint8_t c = static_cast<uint8_t>( data[i] );
    x = ( x ^ c ) * 0x100000001b3ULL; /* FNV-1a */
    y = ( ( y << 5 ) | ( y >> 59 ) ) ^ c;
    y *= 0xff51afd7ed558ccdULL;
  }
  a = x;
  b = y;
}

bool FileCopy::safe_relative_path( const std::string& path )
{
  if ( path.empty() || path[0] == '/' || path.find( '\0' ) != std::string::npos ) {
    return false;
  }
  size_t start = 0;
  bool first = true;
  while ( start <= path.size() ) {
    size_t end = path.find( '/', start );
    if ( end == std::string::npos ) {
      end = path.size();
    }
    const std::string part = path.substr( start, end - start );
    /* "." may lead, meaning the destination itself; nothing may climb out */
    if ( part.empty() || part == ".." || ( part == "." && !first ) ) {
      return false;
    }
    first = false;
    start = end + 1;
  }
  return true;
}

bool FileCopy::parse( const std::vector<std::string>& words, Options& options )
{
  if ( words.empty() || ( words[0] != "send" && words[0] != "receive" ) ) {
    return false;
  }
  options.sender = words[0] == "send";
  size_t i = 1;
  for ( ; i < words.size() && words[i] != "--"; i++ ) {
    const std::string& w = words[i];
    if ( w == "-r" ) {
      options.recursive = true;
    } else if ( w == "--auto" ) {
      options.automatic = true;
    } else if ( w == "--delete" ) {
      options.remove = true;
    } else if ( w == "--glob" ) {
      options.glob = true;
    } else if ( w == "-q" ) {
      options.quiet = true;
    } else if ( w.compare( 0, 11, "--interval=" ) == 0 ) {
      options.interval = atoi( w.c_str() + 11 );
      if ( options.interval < 100 ) {
        return false;
      }
    } else {
      return false;
    }
  }
  if ( i >= words.size() ) {
    return false;
  }
  options.paths.assign( words.begin() + i + 1, words.end() );
  return options.sender ? !options.paths.empty() : options.paths.size() == 1;
}

namespace {

enum MessageType
{
  HELLO = 1,
  LIST,
  LIST_END,
  WANT,
  PLAN_END,
  FILE_BEGIN,
  DATA,
  FILE_END,
  RESULT,
  ROUND_END,
  ROUND_DONE,
  NOTE,
  BYE
};

const char MAGIC[] = "mocp-1";
const size_t CHUNK = 32768;
const size_t MAX_MESSAGE = 1024 * 1024;
const size_t OUT_HIGH = 256 * 1024; /* how much may wait to be written before we wait for it */
const size_t LIST_BATCH = 64 * 1024;

/* The other end has gone. */
struct Closed : public std::runtime_error
{
  Closed() : std::runtime_error( "the connection was closed" ) {}
};

/* The other end made no sense. */
struct Malformed : public std::runtime_error
{
  Malformed() : std::runtime_error( "the other end sent something that could not be understood" ) {}
};

uint64_t now_ms( void )
{
  struct timespec t;
#ifdef CLOCK_MONOTONIC
  clock_gettime( CLOCK_MONOTONIC, &t );
#else
  clock_gettime( CLOCK_REALTIME, &t );
#endif
  return static_cast<uint64_t>( t.tv_sec ) * 1000 + t.tv_nsec / 1000000;
}

void put8( std::string& s, uint8_t v )
{
  s.push_back( static_cast<char>( v ) );
}

void put32( std::string& s, uint32_t v )
{
  for ( int shift = 24; shift >= 0; shift -= 8 ) {
    s.push_back( static_cast<char>( ( v >> shift ) & 0xFF ) );
  }
}

void put64( std::string& s, uint64_t v )
{
  for ( int shift = 56; shift >= 0; shift -= 8 ) {
    s.push_back( static_cast<char>( ( v >> shift ) & 0xFF ) );
  }
}

void put_string( std::string& s, const std::string& v )
{
  put32( s, v.size() );
  s += v;
}

class Reader
{
private:
  const std::string& s;
  size_t at;

  void need( size_t n ) const
  {
    if ( s.size() - at < n ) {
      throw Malformed();
    }
  }

public:
  explicit Reader( const std::string& s_s ) : s( s_s ), at( 0 ) {}

  uint8_t u8( void )
  {
    need( 1 );
    return static_cast<uint8_t>( s[at++] );
  }
  uint32_t u32( void )
  {
    uint32_t v = 0;
    for ( int i = 0; i < 4; i++ ) {
      v = ( v << 8 ) | u8();
    }
    return v;
  }
  uint64_t u64( void )
  {
    uint64_t v = 0;
    for ( int i = 0; i < 8; i++ ) {
      v = ( v << 8 ) | u8();
    }
    return v;
  }
  std::string str( void )
  {
    const uint32_t len = u32();
    need( len );
    at += len;
    return s.substr( at - len, len );
  }
  bool done( void ) const { return at == s.size(); }
};

/*
 * Messages both ways over a pair of descriptors.  Nothing here waits to
 * write without also reading, so the two ends cannot each be stuck
 * waiting for the other to take what it has sent.
 */
class Channel
{
private:
  int in, out;
  std::string inbox, outbox;

  /* Waits (up to timeout, ms; -1 for as long as it takes) for something to do, and does it. */
  void turn( int timeout )
  {
    struct pollfd fds[2] = { { in, POLLIN, 0 }, { outbox.empty() ? -1 : out, POLLOUT, 0 } };
    if ( poll( fds, 2, timeout ) < 0 ) {
      if ( errno == EINTR ) {
        return;
      }
      throw Closed();
    }
    if ( fds[1].revents ) {
      ssize_t n = write( out, outbox.data(), outbox.size() );
      if ( n > 0 ) {
        outbox.erase( 0, n );
      } else if ( n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR ) {
        throw Closed();
      }
    }
    if ( fds[0].revents ) {
      char buf[65536];
      ssize_t n = read( in, buf, sizeof( buf ) );
      if ( n > 0 ) {
        inbox.append( buf, n );
      } else if ( n == 0 || ( errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR ) ) {
        throw Closed();
      }
    }
  }

public:
  Channel( int s_in, int s_out ) : in( s_in ), out( s_out ), inbox(), outbox()
  {
    fcntl( in, F_SETFL, fcntl( in, F_GETFL ) | O_NONBLOCK );
    fcntl( out, F_SETFL, fcntl( out, F_GETFL ) | O_NONBLOCK );
  }

  void send( uint8_t type, const std::string& payload )
  {
    put8( outbox, type );
    put32( outbox, payload.size() );
    outbox += payload;
    while ( outbox.size() > OUT_HIGH ) {
      turn( -1 );
    }
  }

  /* False if no message came within timeout (ms; -1 to wait for one, 0 not to wait). */
  bool recv( uint8_t& type, std::string& payload, int timeout )
  {
    const uint64_t deadline = now_ms() + ( timeout > 0 ? timeout : 0 );
    while ( true ) {
      if ( inbox.size() >= 5 ) {
        const size_t len = ( static_cast<size_t>( static_cast<uint8_t>( inbox[1] ) ) << 24 )
                           | ( static_cast<uint8_t>( inbox[2] ) << 16 ) | ( static_cast<uint8_t>( inbox[3] ) << 8 )
                           | static_cast<uint8_t>( inbox[4] );
        if ( len > MAX_MESSAGE ) {
          throw Malformed();
        }
        if ( inbox.size() >= 5 + len ) {
          type = static_cast<uint8_t>( inbox[0] );
          payload.assign( inbox, 5, len );
          inbox.erase( 0, 5 + len );
          return true;
        }
      }
      if ( timeout < 0 ) {
        turn( -1 );
      } else {
        const uint64_t now = now_ms();
        if ( timeout == 0 ) {
          /* whatever is there already, and no more */
          struct pollfd fd = { in, POLLIN, 0 };
          if ( poll( &fd, 1, 0 ) <= 0 ) {
            return false;
          }
          turn( 0 );
          timeout = 1; /* (and then look at what came, once) */
          continue;
        }
        if ( now >= deadline ) {
          return false;
        }
        turn( static_cast<int>( deadline - now ) );
      }
    }
  }

  void flush( void )
  {
    while ( !outbox.empty() ) {
      turn( -1 );
    }
  }
};

struct Entry
{
  char kind; /* F a file, D a directory, X something that is no longer there */
  std::string path;
  uint64_t size;
  int64_t mtime;
  uint32_t mode;
  bool force;         /* known to have changed, whatever its size and time say */
  long nsec;          /* (sender's own use: the rest of the time) */
  std::string source; /* (sender's own use: where it is) */

  Entry() : kind( 'F' ), path(), size( 0 ), mtime( 0 ), mode( 0 ), force( false ), nsec( 0 ), source() {}

  bool same( const Entry& x ) const
  {
    return kind == x.kind && size == x.size && mtime == x.mtime && mode == x.mode && nsec == x.nsec;
  }
};

long nanoseconds( const struct stat& st )
{
#if defined( __APPLE__ )
  return st.st_mtimespec.tv_nsec;
#elif defined( __linux__ ) || defined( __CYGWIN__ ) || defined( __FreeBSD__ ) || defined( __OpenBSD__ )            \
  || defined( __NetBSD__ )
  return st.st_mtim.tv_nsec;
#else
  (void)st;
  return 0;
#endif
}

std::string expand_home( const std::string& path )
{
  const char* home = getenv( "HOME" );
  if ( home && ( path == "~" || path.compare( 0, 2, "~/" ) == 0 ) ) {
    return std::string( home ) + path.substr( 1 );
  }
  return path;
}

std::string human( uint64_t bytes )
{
  char buf[32];
  if ( bytes < 10000 ) {
    snprintf( buf, sizeof( buf ), "%u bytes", static_cast<unsigned int>( bytes ) );
  } else if ( bytes < 10000ULL * 1024 ) {
    snprintf( buf, sizeof( buf ), "%.1f KB", bytes / 1024.0 );
  } else if ( bytes < 10000ULL * 1024 * 1024 ) {
    snprintf( buf, sizeof( buf ), "%.1f MB", bytes / 1048576.0 );
  } else {
    snprintf( buf, sizeof( buf ), "%.1f GB", bytes / 1073741824.0 );
  }
  return buf;
}

bool make_directories( const std::string& path )
{
  struct stat st;
  if ( stat( path.c_str(), &st ) == 0 ) {
    if ( S_ISDIR( st.st_mode ) ) {
      return true;
    }
    errno = ENOTDIR;
    return false;
  }
  const size_t slash = path.rfind( '/' );
  if ( slash != std::string::npos && slash > 0 && !make_directories( path.substr( 0, slash ) ) ) {
    return false;
  }
  return mkdir( path.c_str(), 0777 ) == 0 || errno == EEXIST;
}

void remove_tree( const std::string& path )
{
  struct stat st;
  if ( lstat( path.c_str(), &st ) < 0 ) {
    return;
  }
  if ( S_ISDIR( st.st_mode ) ) {
    std::vector<std::string> names;
    if ( DIR* dir = opendir( path.c_str() ) ) {
      while ( struct dirent* d = readdir( dir ) ) {
        const std::string name = d->d_name;
        if ( name != "." && name != ".." ) {
          names.push_back( name );
        }
      }
      closedir( dir );
    }
    for ( size_t i = 0; i < names.size(); i++ ) {
      remove_tree( path + "/" + names[i] );
    }
    rmdir( path.c_str() );
  } else {
    unlink( path.c_str() );
  }
}

/* What the two ends have in common. */
class End
{
protected:
  const Options& options;
  Channel channel;
  unsigned int errors; /* things that went wrong, at either end */
  unsigned int round;
  bool progress_shown;
  uint64_t progress_at;

  /* unused */
  End( const End& );
  End& operator=( const End& );

  void clear_progress( void )
  {
    if ( progress_shown ) {
      fputs( "\r\033[K", stderr );
      progress_shown = false;
    }
  }

  void print( const std::string& line )
  {
    clear_progress();
    fprintf( stderr, "%s\n", line.c_str() );
    fflush( stderr );
  }

  /* Something the user should hear.  It is said here if they are here, and sent to them if not. */
  void say( bool error, const std::string& text )
  {
    if ( error ) {
      errors++;
    }
    if ( options.local ) {
      if ( error || !options.quiet ) {
        print( "mocp: " + text );
      }
    } else {
      std::string m;
      put8( m, error );
      put_string( m, text );
      channel.send( NOTE, m );
    }
  }

  void heard( const std::string& payload )
  {
    Reader r( payload );
    const bool error = r.u8();
    const std::string text = r.str();
    if ( error ) {
      errors++;
    }
    if ( options.local && ( error || !options.quiet ) ) {
      print( "mocp: " + text );
    }
  }

  /* A file has arrived, or gone: said at the user's end. */
  void report( const char* what, const std::string& path, uint64_t size )
  {
    if ( !options.local || options.quiet ) {
      return;
    }
    std::string line;
    if ( options.automatic && round > 0 ) {
      char stamp[16];
      const time_t now = time( NULL );
      struct tm tm;
      localtime_r( &now, &tm );
      strftime( stamp, sizeof( stamp ), "%H:%M:%S ", &tm );
      line = stamp;
    }
    line += what;
    line += path.compare( 0, 2, "./" ) == 0 ? path.substr( 2 ) : path;
    if ( what[0] != 'r' ) {
      line += "  (" + human( size ) + ")";
    }
    print( line );
  }

  /* How far along a large file is, if someone is watching. */
  void progress( const std::string& path, uint64_t done, uint64_t total )
  {
    if ( !options.local || options.quiet || total < 4 * CHUNK || !isatty( STDERR_FILENO ) ) {
      return;
    }
    const uint64_t now = now_ms();
    if ( now - progress_at < 250 ) {
      return;
    }
    progress_at = now;
    const std::string name = path.size() > 50 ? "..." + path.substr( path.size() - 47 ) : path;
    fprintf( stderr, "\r\033[K%s  %3u%% of %s", name.c_str(), static_cast<unsigned int>( done * 100 / total ),
             human( total ).c_str() );
    fflush( stderr );
    progress_shown = true;
  }

  void hello( void )
  {
    std::string m( MAGIC );
    channel.send( HELLO, m );
    uint8_t type;
    std::string payload;
    channel.recv( type, payload, -1 );
    if ( type != HELLO || payload != MAGIC ) {
      throw Malformed();
    }
  }

public:
  End( const Options& s_options, int in, int out )
    : options( s_options ), channel( in, out ), errors( 0 ), round( 0 ), progress_shown( false ), progress_at( 0 )
  {}
  virtual ~End() {}
  virtual void run( void ) = 0;

  int status( void )
  {
    clear_progress();
    return errors ? 1 : 0;
  }

  void failed( const std::string& why )
  {
    errors++;
    if ( options.local ) {
      print( "mocp: " + why );
    }
  }
};

class Sender : public End
{
private:
  std::map<std::string, Entry> known; /* what the other end has been told of, as it then was */
  std::vector<Entry> entries;         /* this round's */
  std::vector<int> state;             /* of each: see below */
  bool plan_complete, round_complete;
  size_t copied, current;

  enum
  {
    UP_TO_DATE,
    WANTED,
    SENT_OK,
    SENT_BAD
  };

  struct Want
  {
    uint32_t index;
    uint64_t offset;
    Hash prefix;
    Want() : index( 0 ), offset( 0 ), prefix() {}
  };
  std::vector<Want> wants;

  void look_at( const std::string& source, const std::string& path, bool top, std::map<std::string, Entry>& found )
  {
    const bool complain = round == 0;
    struct stat st;
    if ( stat( source.c_str(), &st ) < 0 ) {
      if ( complain && top ) {
        say( true, source + ": " + strerror( errno ) );
      }
      return; /* (inside a directory, it has just gone: nothing to remark on) */
    }
    Entry e;
    e.path = path;
    e.source = source;
    e.mtime = st.st_mtime;
    e.nsec = nanoseconds( st );
    e.mode = st.st_mode & 0777;
    if ( S_ISREG( st.st_mode ) ) {
      e.kind = 'F';
      e.size = st.st_size;
      found[path] = e;
    } else if ( S_ISDIR( st.st_mode ) ) {
      if ( !options.recursive ) {
        if ( complain ) {
          say( true, source + " is a directory (not copied: use -r)" );
        }
        return;
      }
      e.kind = 'D';
      e.mtime = 0; /* a directory is the same directory whenever it was last touched */
      e.nsec = 0;
      found[path] = e;
      std::vector<std::string> names;
      DIR* dir = opendir( source.c_str() );
      if ( !dir ) {
        if ( complain ) {
          say( true, source + ": " + strerror( errno ) );
        }
        return;
      }
      while ( struct dirent* d = readdir( dir ) ) {
        const std::string name = d->d_name;
        if ( name != "." && name != ".." ) {
          names.push_back( name );
        }
      }
      closedir( dir );
      for ( size_t i = 0; i < names.size(); i++ ) {
        const std::string child = source + "/" + names[i];
        struct stat link;
        if ( lstat( child.c_str(), &link ) == 0 && S_ISLNK( link.st_mode ) && stat( child.c_str(), &st ) == 0
             && S_ISDIR( st.st_mode ) ) {
          if ( complain ) {
            say( false, child + " is a link to a directory (not followed)" );
          }
          continue;
        }
        look_at( child, path + "/" + names[i], false, found );
      }
    } else if ( complain ) {
      say( false, source + " is not a file or a directory (not copied)" );
    }
  }

  /* The sources as given, with patterns expanded if they are patterns. */
  std::vector<std::string> sources( void )
  {
    std::vector<std::string> ret;
    for ( size_t i = 0; i < options.paths.size(); i++ ) {
      const std::string path = expand_home( options.paths[i] );
      if ( options.glob ) {
        glob_t matches;
        memset( &matches, 0, sizeof( matches ) );
        if ( glob( path.c_str(), GLOB_NOCHECK, NULL, &matches ) == 0 ) {
          for ( size_t j = 0; j < matches.gl_pathc; j++ ) {
            ret.push_back( matches.gl_pathv[j] );
          }
        } else {
          ret.push_back( path );
        }
        globfree( &matches );
      } else {
        ret.push_back( path );
      }
    }
    return ret;
  }

  /* The name something goes by at the other end: its own, without where it was found. */
  static std::string top_name( std::string source )
  {
    while ( source.size() > 1 && source[source.size() - 1] == '/' ) {
      source.erase( source.size() - 1 );
    }
    const size_t slash = source.rfind( '/' );
    const std::string name = slash == std::string::npos ? source : source.substr( slash + 1 );
    /* "the directory I am in", and such: what is in it, not it */
    return ( name.empty() || name == "." || name == ".." ) ? "." : name;
  }

  void scan( void )
  {
    std::map<std::string, Entry> found;
    const std::vector<std::string> from = sources();
    for ( size_t i = 0; i < from.size(); i++ ) {
      look_at( from[i], top_name( from[i] ), true, found );
    }

    entries.clear();
    for ( std::map<std::string, Entry>::iterator it = found.begin(); it != found.end(); it++ ) {
      std::map<std::string, Entry>::const_iterator was = known.find( it->first );
      if ( was == known.end() || !was->second.same( it->second ) ) {
        it->second.force = round > 0 && it->second.kind == 'F';
        entries.push_back( it->second );
      }
    }
    std::vector<std::string> gone;
    for ( std::map<std::string, Entry>::const_iterator it = known.begin(); it != known.end(); it++ ) {
      if ( found.find( it->first ) == found.end() ) {
        gone.push_back( it->first );
      }
    }
    for ( size_t i = 0; i < gone.size(); i++ ) {
      known.erase( gone[i] );
      if ( options.remove ) {
        Entry e;
        e.kind = 'X';
        e.path = gone[i];
        entries.push_back( e );
      }
    }
  }

  void incoming( uint8_t type, const std::string& payload )
  {
    Reader r( payload );
    switch ( type ) {
      case WANT: {
        Want w;
        w.index = r.u32();
        w.offset = r.u64();
        w.prefix.a = r.u64();
        w.prefix.b = r.u64();
        if ( w.index >= entries.size() || entries[w.index].kind != 'F' || state[w.index] != UP_TO_DATE ) {
          throw Malformed();
        }
        state[w.index] = WANTED;
        wants.push_back( w );
        break;
      }
      case PLAN_END:
        plan_complete = true;
        break;
      case RESULT: {
        const uint32_t index = r.u32();
        const bool ok = r.u8();
        const std::string why = r.str();
        if ( index >= entries.size() ) {
          throw Malformed();
        }
        state[index] = ok ? SENT_OK : SENT_BAD;
        if ( ok ) {
          copied++;
          report( "", entries[index].path, entries[index].size );
        } else {
          errors++;
          if ( options.local && !why.empty() ) {
            print( "mocp: " + entries[index].path + ": " + why );
          }
        }
        break;
      }
      case ROUND_DONE:
        round_complete = true;
        break;
      case NOTE:
        heard( payload );
        break;
      default:
        throw Malformed();
    }
  }

  void drain( void )
  {
    uint8_t type;
    std::string payload;
    while ( channel.recv( type, payload, 0 ) ) {
      incoming( type, payload );
    }
  }

  void send_file( const Want& want )
  {
    const Entry& e = entries[want.index];
    bool ok = true;
    uint64_t offset = want.offset;
    Hash hash;
    char buf[CHUNK];

    const int fd = open( e.source.c_str(), O_RDONLY );
    if ( fd < 0 ) {
      say( true, e.source + ": " + strerror( errno ) );
      errors--; /* (it will be counted when the other end says it did not get it) */
      ok = false;
      offset = 0;
    }

    /* If they hold the start of it already, is it the start of this? */
    if ( ok && offset > 0 ) {
      uint64_t done = 0;
      while ( done < offset && offset <= e.size ) {
        ssize_t n = read( fd, buf, std::min<uint64_t>( sizeof( buf ), offset - done ) );
        if ( n <= 0 ) {
          break;
        }
        hash.add( buf, n );
        done += n;
      }
      if ( done != offset || !( hash == want.prefix ) ) {
        offset = 0;
        hash = Hash();
        lseek( fd, 0, SEEK_SET );
      }
    }

    std::string m;
    put32( m, want.index );
    put64( m, offset );
    channel.send( FILE_BEGIN, m );

    uint64_t at = offset;
    while ( ok && at < e.size ) {
      ssize_t n = read( fd, buf, std::min<uint64_t>( sizeof( buf ), e.size - at ) );
      if ( n <= 0 ) {
        ok = false; /* shorter than it was */
        break;
      }
      hash.add( buf, n );
      at += n;
      channel.send( DATA, std::string( buf, n ) );
      progress( e.path, at, e.size );
      drain();
    }
    if ( fd >= 0 ) {
      struct stat st;
      if ( fstat( fd, &st ) < 0 || static_cast<uint64_t>( st.st_size ) != e.size || st.st_mtime != e.mtime
           || nanoseconds( st ) != e.nsec ) {
        ok = false; /* written to while we were reading it */
      }
      close( fd );
    }

    m.clear();
    put8( m, ok );
    put64( m, hash.a );
    put64( m, hash.b );
    channel.send( FILE_END, m );
  }

  void one_round( void )
  {
    state.assign( entries.size(), UP_TO_DATE );
    wants.clear();
    plan_complete = round_complete = false;
    copied = 0;

    std::string m;
    for ( size_t i = 0; i < entries.size(); i++ ) {
      const Entry& e = entries[i];
      put8( m, e.kind );
      put8( m, e.force );
      put_string( m, e.path );
      put64( m, e.size );
      put64( m, static_cast<uint64_t>( e.mtime ) );
      put32( m, e.mode );
      if ( m.size() > LIST_BATCH ) {
        channel.send( LIST, m );
        m.clear();
      }
    }
    if ( !m.empty() ) {
      channel.send( LIST, m );
    }
    m.clear();
    put8( m, round == 0 ); /* the first is everything there is */
    channel.send( LIST_END, m );

    uint8_t type;
    std::string payload;
    while ( !plan_complete ) {
      channel.recv( type, payload, -1 );
      incoming( type, payload );
    }
    for ( current = 0; current < wants.size(); current++ ) {
      send_file( wants[current] );
    }
    channel.send( ROUND_END, "" );
    while ( !round_complete ) {
      channel.recv( type, payload, -1 );
      incoming( type, payload );
    }
    clear_progress();

    /* Whatever became of each, it is not offered again until it changes. */
    for ( size_t i = 0; i < entries.size(); i++ ) {
      if ( entries[i].kind == 'X' ) {
        report( "removed ", entries[i].path, 0 );
      } else {
        known[entries[i].path] = entries[i];
      }
    }
  }

public:
  Sender( const Options& s_options, int in, int out )
    : End( s_options, in, out ), known(), entries(), state(), plan_complete( false ), round_complete( false ),
      copied( 0 ), current( 0 ), wants()
  {}

  void run( void )
  {
    std::string m( MAGIC );
    channel.send( HELLO, m );
    m.clear();
    /* (more than one thing to copy means the destination is a directory to put them in) */
    put8( m, sources().size() > 1 );
    channel.send( HELLO, m );
    uint8_t type;
    std::string payload;
    channel.recv( type, payload, -1 );
    if ( type != HELLO || payload != MAGIC ) {
      throw Malformed();
    }
    scan();

    while ( true ) {
      if ( round == 0 || !entries.empty() ) {
        one_round();
        if ( round == 0 && options.local && !options.quiet ) {
          if ( copied == 0 && errors == 0 ) {
            print( "mocp: everything is up to date already." );
          }
          if ( options.automatic ) {
            print( "mocp: watching for changes. Interrupt (Ctrl-C) to stop." );
          }
        }
        round++;
      }
      if ( !options.automatic ) {
        break;
      }
      /* wait a while, listening in case the other end has something to say, or goes */
      const uint64_t until = now_ms() + options.interval;
      while ( now_ms() < until ) {
        if ( channel.recv( type, payload, static_cast<int>( until - now_ms() ) ) ) {
          incoming( type, payload );
        }
      }
      scan();
    }
    channel.send( BYE, "" );
    channel.flush();
  }
};

class Receiver : public End
{
private:
  std::string dest;
  bool many, into, into_known;

  struct Plan
  {
    Entry entry;
    std::string target, part;
    bool wanted;
    uint64_t offset;
    Hash prefix;
    Plan() : entry(), target(), part(), wanted( false ), offset( 0 ), prefix() {}
  };
  std::vector<Plan> plans;
  size_t copied;

  /* the file arriving now */
  int fd;
  uint32_t index;
  bool ok;
  std::string trouble;
  Hash hash;
  uint64_t at;

  /* Where something from the other end goes here. */
  std::string target_of( const std::string& path ) const
  {
    const std::string base = dest == "/" ? "" : dest;
    if ( path == "." ) {
      return dest;
    }
    if ( path.compare( 0, 2, "./" ) == 0 ) {
      return base + path.substr( 1 );
    }
    if ( into ) {
      return base + "/" + path;
    }
    /* the one thing being copied takes the destination's name */
    const size_t slash = path.find( '/' );
    return slash == std::string::npos ? dest : dest + path.substr( slash );
  }

  static std::string part_name( const std::string& target )
  {
    const size_t slash = target.rfind( '/' );
    return slash == std::string::npos ? "." + target + ".mocp-part"
                                      : target.substr( 0, slash + 1 ) + "." + target.substr( slash + 1 ) + ".mocp-part";
  }

  void result( uint32_t which, bool good, const std::string& why )
  {
    if ( good ) {
      copied++;
      report( "", plans[which].entry.path, plans[which].entry.size );
    } else {
      errors++;
      if ( options.local && !why.empty() ) {
        print( "mocp: " + plans[which].target + ": " + why );
      }
    }
    std::string m;
    put32( m, which );
    put8( m, good );
    put_string( m, why );
    channel.send( RESULT, m );
  }

  void plan_one( uint32_t which )
  {
    Plan& p = plans[which];
    const Entry& e = p.entry;
    struct stat st;

    if ( e.kind == 'X' ) {
      if ( options.remove && p.target != dest ) {
        remove_tree( p.target );
        unlink( p.part.c_str() );
        report( "removed ", e.path, 0 );
      }
      return;
    }
    if ( e.kind == 'D' ) {
      if ( !make_directories( p.target ) ) {
        say( true, p.target + ": " + strerror( errno ) );
      }
      return;
    }

    const size_t slash = p.target.rfind( '/' );
    if ( slash != std::string::npos && slash > 0 && !make_directories( p.target.substr( 0, slash ) ) ) {
      result( which, false, strerror( errno ) );
      return;
    }
    if ( stat( p.target.c_str(), &st ) == 0 ) {
      if ( S_ISDIR( st.st_mode ) ) {
        result( which, false, "is a directory here" );
        return;
      }
      if ( !e.force && S_ISREG( st.st_mode ) && static_cast<uint64_t>( st.st_size ) == e.size
           && st.st_mtime == e.mtime ) {
        if ( ( st.st_mode & 0777 ) != ( e.mode & ~process_umask() ) ) {
          chmod( p.target.c_str(), e.mode & ~process_umask() );
        }
        return; /* we have it */
      }
    }

    /* We need it.  Is there some of it here from last time? */
    p.wanted = true;
    if ( stat( p.part.c_str(), &st ) == 0 && S_ISREG( st.st_mode ) && st.st_size > 0
         && static_cast<uint64_t>( st.st_size ) <= e.size ) {
      const int part = open( p.part.c_str(), O_RDONLY );
      if ( part >= 0 ) {
        char buf[CHUNK];
        ssize_t n;
        while ( ( n = read( part, buf, sizeof( buf ) ) ) > 0 ) {
          p.prefix.add( buf, n );
          p.offset += n;
        }
        close( part );
      }
    }
    std::string m;
    put32( m, which );
    put64( m, p.offset );
    put64( m, p.prefix.a );
    put64( m, p.prefix.b );
    channel.send( WANT, m );
  }

  static mode_t process_umask( void )
  {
    const mode_t mask = umask( 0 );
    umask( mask );
    return mask;
  }

  /* With everything listed, what is here and was not listed is to go. */
  void prune( void )
  {
    std::set<std::string> listed;
    for ( size_t i = 0; i < plans.size(); i++ ) {
      listed.insert( plans[i].target );
      if ( plans[i].wanted ) {
        listed.insert( plans[i].part );
      }
    }
    for ( size_t i = 0; i < plans.size(); i++ ) {
      if ( plans[i].entry.kind != 'D' ) {
        continue;
      }
      std::vector<std::string> names;
      if ( DIR* dir = opendir( plans[i].target.c_str() ) ) {
        while ( struct dirent* d = readdir( dir ) ) {
          const std::string name = d->d_name;
          if ( name != "." && name != ".." ) {
            names.push_back( name );
          }
        }
        closedir( dir );
      }
      for ( size_t j = 0; j < names.size(); j++ ) {
        const std::string path = plans[i].target + "/" + names[j];
        if ( listed.find( path ) == listed.end() ) {
          remove_tree( path );
          report( "removed ", plans[i].entry.path + "/" + names[j], 0 );
        }
      }
    }
  }

  void plan( bool complete )
  {
    if ( !into_known ) {
      /* Is the destination a place to put things, or the name for the one thing? */
      struct stat st;
      const std::string& given = options.paths[0];
      into = many || ( !given.empty() && given[given.size() - 1] == '/' )
             || ( stat( dest.c_str(), &st ) == 0 && S_ISDIR( st.st_mode ) );
      into_known = true;
      if ( into && !make_directories( dest ) ) {
        say( true, dest + ": " + strerror( errno ) );
      }
    }
    for ( size_t i = 0; i < plans.size(); i++ ) {
      plans[i].target = target_of( plans[i].entry.path );
      plans[i].part = part_name( plans[i].target );
    }
    for ( size_t i = 0; i < plans.size(); i++ ) {
      plan_one( i );
    }
    if ( complete && options.remove ) {
      prune();
    }
    channel.send( PLAN_END, "" );
  }

  void begin( const std::string& payload )
  {
    Reader r( payload );
    index = r.u32();
    const uint64_t offset = r.u64();
    if ( fd >= 0 || index >= plans.size() || !plans[index].wanted
         || ( offset != 0 && offset != plans[index].offset ) ) {
      throw Malformed();
    }
    const Plan& p = plans[index];
    hash = offset ? p.prefix : Hash();
    at = offset;
    ok = true;
    trouble.clear();
    fd = open( p.part.c_str(), O_WRONLY | O_CREAT, 0600 );
    if ( fd < 0 || ftruncate( fd, offset ) < 0 || lseek( fd, offset, SEEK_SET ) < 0 ) {
      ok = false;
      trouble = strerror( errno );
    }
    if ( fd < 0 ) {
      fd = open( "/dev/null", O_WRONLY ); /* (somewhere for it to go, all the same) */
    }
  }

  void data( const std::string& payload )
  {
    if ( fd < 0 ) {
      throw Malformed();
    }
    hash.add( payload.data(), payload.size() );
    at += payload.size();
    size_t done = 0;
    while ( ok && done < payload.size() ) {
      ssize_t n = write( fd, payload.data() + done, payload.size() - done );
      if ( n < 0 ) {
        if ( errno == EINTR ) {
          continue;
        }
        ok = false;
        trouble = strerror( errno );
        break;
      }
      done += n;
    }
    progress( plans[index].entry.path, at, plans[index].entry.size );
  }

  void end( const std::string& payload )
  {
    Reader r( payload );
    const bool sender_ok = r.u8();
    Hash theirs;
    theirs.a = r.u64();
    theirs.b = r.u64();
    if ( fd < 0 ) {
      throw Malformed();
    }
    const Plan& p = plans[index];
    if ( close( fd ) < 0 && ok ) {
      ok = false;
      trouble = strerror( errno );
    }
    fd = -1;

    if ( !sender_ok ) {
      /* It changed under the sender, or could not be read.  What came may yet be a start. */
      if ( at == 0 ) {
        unlink( p.part.c_str() );
      }
      result( index, false, ok ? "it changed while it was being copied, or could not be read" : trouble );
      return;
    }
    if ( ok && ( !( hash == theirs ) || at != p.entry.size ) ) {
      ok = false;
      trouble = "what arrived was not what was sent";
      unlink( p.part.c_str() );
    }
    if ( ok ) {
      struct timeval times[2];
      times[0].tv_sec = times[1].tv_sec = p.entry.mtime;
      times[0].tv_usec = times[1].tv_usec = 0;
      chmod( p.part.c_str(), p.entry.mode & ~process_umask() );
      utimes( p.part.c_str(), times );
      if ( rename( p.part.c_str(), p.target.c_str() ) < 0 ) {
        ok = false;
        trouble = strerror( errno );
      }
    }
    result( index, ok, trouble );
  }

public:
  Receiver( const Options& s_options, int in, int out )
    : End( s_options, in, out ), dest( expand_home( s_options.paths[0] ) ), many( false ), into( false ),
      into_known( false ), plans(), copied( 0 ), fd( -1 ), index( 0 ), ok( false ), trouble(), hash(), at( 0 )
  {
    while ( dest.size() > 1 && dest[dest.size() - 1] == '/' ) {
      dest.erase( dest.size() - 1 );
    }
  }

  ~Receiver()
  {
    if ( fd >= 0 ) {
      close( fd );
    }
  }

  void run( void )
  {
    hello();
    uint8_t type;
    std::string payload;
    channel.recv( type, payload, -1 );
    if ( type != HELLO ) {
      throw Malformed();
    }
    many = Reader( payload ).u8();

    while ( true ) {
      channel.recv( type, payload, -1 );
      switch ( type ) {
        case LIST: {
          Reader r( payload );
          while ( !r.done() ) {
            Plan p;
            p.entry.kind = r.u8();
            p.entry.force = r.u8();
            p.entry.path = r.str();
            p.entry.size = r.u64();
            p.entry.mtime = static_cast<int64_t>( r.u64() );
            p.entry.mode = r.u32() & 0777;
            if ( ( p.entry.kind != 'F' && p.entry.kind != 'D' && p.entry.kind != 'X' )
                 || !safe_relative_path( p.entry.path ) ) {
              throw Malformed();
            }
            plans.push_back( p );
          }
          break;
        }
        case LIST_END:
          copied = 0;
          plan( Reader( payload ).u8() );
          break;
        case FILE_BEGIN:
          begin( payload );
          break;
        case DATA:
          data( payload );
          break;
        case FILE_END:
          end( payload );
          break;
        case ROUND_END:
          if ( fd >= 0 ) {
            throw Malformed();
          }
          clear_progress();
          if ( round == 0 && options.local && !options.quiet ) {
            if ( copied == 0 && errors == 0 ) {
              print( "mocp: everything is up to date already." );
            }
            if ( options.automatic ) {
              print( "mocp: watching for changes. Interrupt (Ctrl-C) to stop." );
            }
          }
          round++;
          plans.clear();
          channel.send( ROUND_DONE, "" );
          break;
        case NOTE:
          heard( payload );
          break;
        case BYE:
          return;
        default:
          throw Malformed();
      }
    }
  }
};

}

int FileCopy::run( const Options& options, int in_fd, int out_fd )
{
  signal( SIGPIPE, SIG_IGN );
  End* end = NULL;
  int status = 1;
  try {
    if ( options.sender ) {
      end = new Sender( options, in_fd, out_fd );
    } else {
      end = new Receiver( options, in_fd, out_fd );
    }
    try {
      end->run();
    } catch ( const std::exception& e ) {
      end->failed( e.what() );
    }
    status = end->status();
  } catch ( const std::exception& e ) {
    if ( options.local ) {
      fprintf( stderr, "mocp: %s\n", e.what() );
    }
  }
  delete end;
  return status;
}
