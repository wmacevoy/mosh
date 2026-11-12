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

/* Tests the file copying of mocp: a sender and a receiver, joined by a socket pair. */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <csignal>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/network/filecopy.h"

static int failures = 0;

#define CHECK( x )                                                                                                 \
  do {                                                                                                             \
    if ( !( x ) ) {                                                                                                \
      fprintf( stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #x );                                      \
      failures++;                                                                                                  \
    }                                                                                                              \
  } while ( 0 )

static std::string root;

static std::string varied( size_t n, unsigned int seed )
{
  std::string s( n, '\0' );
  unsigned int x = seed * 2654435761u + 1;
  for ( size_t i = 0; i < n; i++ ) {
    x = x * 1664525u + 1013904223u;
    s[i] = static_cast<char>( x >> 24 );
  }
  return s;
}

static void put( const std::string& path, const std::string& content )
{
  std::ofstream out( ( root + "/" + path ).c_str(), std::ios::binary | std::ios::trunc );
  out << content;
}

static std::string get( const std::string& path )
{
  std::ifstream in( ( root + "/" + path ).c_str(), std::ios::binary );
  if ( !in ) {
    return "(missing)";
  }
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

static bool exists( const std::string& path )
{
  struct stat st;
  return stat( ( root + "/" + path ).c_str(), &st ) == 0;
}

static void dir( const std::string& path )
{
  mkdir( ( root + "/" + path ).c_str(), 0777 );
}

static std::vector<std::string> words( const std::string& line )
{
  std::vector<std::string> ret;
  std::istringstream in( line );
  std::string w;
  while ( in >> w ) {
    if ( w[0] != '-' && w != "send" && w != "receive" ) {
      w = root + "/" + w;
    }
    ret.push_back( w );
  }
  return ret;
}

struct Running
{
  pid_t sender, receiver;
};

/* Starts the two ends, each a process.  The receiver is the "local" one, and quiet. */
static Running start( const std::string& send, const std::string& receive )
{
  int pair[2];
  if ( socketpair( AF_UNIX, SOCK_STREAM, 0, pair ) < 0 ) {
    perror( "socketpair" );
    exit( 1 );
  }
  Running r;
  for ( int i = 0; i < 2; i++ ) {
    const pid_t pid = fork();
    if ( pid == 0 ) {
      close( pair[1 - i] );
      FileCopy::Options options;
      if ( !FileCopy::parse( words( i == 0 ? send : receive ), options ) ) {
        _exit( 9 );
      }
      options.local = i == 1;
      options.quiet = true;
      _exit( FileCopy::run( options, pair[i], pair[i] ) );
    }
    ( i == 0 ? r.sender : r.receiver ) = pid;
  }
  close( pair[0] );
  close( pair[1] );
  return r;
}

static int finish( const Running& r )
{
  int status = 0, other = 0;
  waitpid( r.receiver, &status, 0 );
  waitpid( r.sender, &other, 0 );
  return WIFEXITED( status ) ? WEXITSTATUS( status ) : 100;
}

static int copy( const std::string& send, const std::string& receive )
{
  return finish( start( send, receive ) );
}

static bool eventually( bool ( *what )( void ) )
{
  for ( int i = 0; i < 100; i++ ) {
    if ( what() ) {
      return true;
    }
    usleep( 50000 );
  }
  return false;
}

static const std::string big = varied( 300000, 1 );

static bool auto_first( void )
{
  return get( "mirror/a.txt" ) == "one" && get( "mirror/sub/b.bin" ) == big;
}
static bool auto_changed( void )
{
  return get( "mirror/a.txt" ) == "two!" && get( "mirror/new.txt" ) == "new";
}
static bool auto_removed( void )
{
  return !exists( "mirror/sub/b.bin" ) && !exists( "mirror/gone" ) && get( "mirror/a.txt" ) == "two!";
}

int main( void )
{
  signal( SIGALRM, SIG_DFL );
  alarm( 120 );

  char scratch[] = "/tmp/mosh-file-copy-XXXXXX";
  if ( !mkdtemp( scratch ) ) {
    perror( "mkdtemp" );
    return 1;
  }
  root = scratch;

  CHECK( FileCopy::safe_relative_path( "a/b" ) && FileCopy::safe_relative_path( "./a" ) );
  CHECK( !FileCopy::safe_relative_path( "/a" ) && !FileCopy::safe_relative_path( "a/../b" ) );
  CHECK( !FileCopy::safe_relative_path( ".." ) && !FileCopy::safe_relative_path( "a//b" )
         && !FileCopy::safe_relative_path( "" ) );
  {
    FileCopy::Hash whole, parts;
    whole.add( big.data(), big.size() );
    parts.add( big.data(), 1000 );
    parts.add( big.data() + 1000, big.size() - 1000 );
    CHECK( whole == parts );
    FileCopy::Hash other;
    other.add( big.data(), big.size() - 1 );
    CHECK( !( whole == other ) );
  }

  /* one file, to a new name; then into a directory; then nothing to do */
  dir( "src" );
  dir( "out" );
  put( "src/a.txt", "one" );
  put( "src/empty", "" );
  CHECK( copy( "send -- src/a.txt", "receive -- out/renamed.txt" ) == 0 );
  CHECK( get( "out/renamed.txt" ) == "one" );
  CHECK( copy( "send -- src/a.txt src/empty", "receive -- out" ) == 0 );
  CHECK( get( "out/a.txt" ) == "one" && get( "out/empty" ) == "" );
  CHECK( copy( "send -- src/a.txt", "receive -- out/newdir/" ) == 0 );
  CHECK( get( "out/newdir/a.txt" ) == "one" );

  /* something that is not there is an error, and the rest is still copied */
  CHECK( copy( "send -- src/nothing src/a.txt", "receive -- out/newdir2/" ) == 1 );
  CHECK( get( "out/newdir2/a.txt" ) == "one" );
  /* a directory without -r */
  CHECK( copy( "send -- src", "receive -- out/not" ) == 1 );
  CHECK( !exists( "out/not" ) );

  /* a tree: under a new name, and into a directory that is there */
  dir( "src/sub" );
  dir( "src/sub/deep" );
  dir( "src/hollow" );
  put( "src/sub/b.bin", big );
  put( "src/sub/deep/c", "sea" );
  chmod( ( root + "/src/sub/deep/c" ).c_str(), 0755 );
  CHECK( copy( "send -r -- src", "receive -- tree" ) == 0 );
  CHECK( get( "tree/a.txt" ) == "one" && get( "tree/sub/b.bin" ) == big && get( "tree/sub/deep/c" ) == "sea" );
  CHECK( exists( "tree/hollow" ) );
  {
    struct stat st, was;
    CHECK( stat( ( root + "/tree/sub/deep/c" ).c_str(), &st ) == 0 && ( st.st_mode & 0100 ) );
    CHECK( stat( ( root + "/src/sub/b.bin" ).c_str(), &was ) == 0
           && stat( ( root + "/tree/sub/b.bin" ).c_str(), &st ) == 0 && st.st_mtime == was.st_mtime );
  }
  CHECK( copy( "send -r -- src", "receive -- out" ) == 0 );
  CHECK( get( "out/src/sub/deep/c" ) == "sea" );
  /* "what is in this directory" */
  CHECK( copy( "send -r -- src/sub/.", "receive -- contents" ) == 0 );
  CHECK( get( "contents/b.bin" ) == big && get( "contents/deep/c" ) == "sea" );
  /* patterns */
  CHECK( copy( "send --glob -- src/sub/*.bin src/*.txt", "receive -- globbed" ) == 0 );
  CHECK( get( "globbed/b.bin" ) == big && get( "globbed/a.txt" ) == "one" && !exists( "globbed/empty" ) );

  /* (again into a directory that is there: so, its contents)
     a copy that was cut off is carried on from where it got to... */
  put( "tree/sub/.b.bin.mocp-part", big.substr( 0, 123456 ) );
  unlink( ( root + "/tree/sub/b.bin" ).c_str() );
  CHECK( copy( "send -r -- src/.", "receive -- tree" ) == 0 );
  CHECK( get( "tree/sub/b.bin" ) == big && !exists( "tree/sub/.b.bin.mocp-part" ) );
  /* ...unless what is there is not the start of this file */
  put( "tree/sub/.b.bin.mocp-part", varied( 5000, 7 ) );
  unlink( ( root + "/tree/sub/b.bin" ).c_str() );
  CHECK( copy( "send -r -- src/.", "receive -- tree" ) == 0 );
  CHECK( get( "tree/sub/b.bin" ) == big );

  /* a file here that differs is replaced; what is not at the source stays, unless asked */
  put( "tree/a.txt", "something else entirely" );
  put( "tree/sub/extra", "extra" );
  CHECK( copy( "send -r -- src/.", "receive -- tree" ) == 0 );
  CHECK( get( "tree/a.txt" ) == "one" && get( "tree/sub/extra" ) == "extra" );
  CHECK( copy( "send -r --delete -- src/.", "receive --delete -- tree" ) == 0 );
  CHECK( !exists( "tree/sub/extra" ) && get( "tree/sub/deep/c" ) == "sea" && get( "tree/a.txt" ) == "one" );

  /* a file where a directory should be, and the other way about */
  dir( "clash" );
  dir( "clash/a.txt" );
  CHECK( copy( "send -- src/a.txt", "receive -- clash" ) == 1 );

  /* kept up to date */
  {
    dir( "src/gone" );
    put( "src/gone/x", "x" );
    const Running r = start( "send -r --auto --delete --interval=100 -- src/.",
                             "receive --auto --delete -- mirror" );
    CHECK( eventually( auto_first ) );
    CHECK( get( "mirror/gone/x" ) == "x" );
    put( "src/a.txt", "two!" );
    put( "src/new.txt", "new" );
    CHECK( eventually( auto_changed ) );
    unlink( ( root + "/src/sub/b.bin" ).c_str() );
    unlink( ( root + "/src/gone/x" ).c_str() );
    rmdir( ( root + "/src/gone" ).c_str() );
    CHECK( eventually( auto_removed ) );
    CHECK( get( "mirror/sub/deep/c" ) == "sea" );
    kill( r.sender, SIGTERM );
    CHECK( finish( r ) == 1 ); /* the receiver is told the connection closed */
  }

  const std::string cleanup = "rm -rf '" + root + "'";
  if ( system( cleanup.c_str() ) != 0 ) {
    failures++;
  }
  if ( failures ) {
    fprintf( stderr, "file-copy: %d check(s) FAILED\n", failures );
    return 1;
  }
  printf( "file-copy: all checks passed\n" );
  return 0;
}
