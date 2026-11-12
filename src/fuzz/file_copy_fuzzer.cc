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

/*
 * Fuzzes the receiving end of a file copy (mocp): the input is what the
 * sending end might say.  It is the end that writes files where it is
 * told to, by another machine, so it is the end that must not be led
 * astray.  Everything it does should stay inside its destination.
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/network/filecopy.h"

static std::string scratch;

static void empty( const std::string& path, bool and_remove )
{
  struct stat st;
  if ( lstat( path.c_str(), &st ) < 0 ) {
    return;
  }
  if ( S_ISDIR( st.st_mode ) ) {
    if ( DIR* dir = opendir( path.c_str() ) ) {
      while ( struct dirent* d = readdir( dir ) ) {
        const std::string name = d->d_name;
        if ( name != "." && name != ".." ) {
          empty( path + "/" + name, true );
        }
      }
      closedir( dir );
    }
    if ( and_remove ) {
      rmdir( path.c_str() );
    }
  } else {
    unlink( path.c_str() );
  }
}

static void cleanup( void )
{
  empty( scratch, true );
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  if ( scratch.empty() ) {
    char name[] = "/tmp/mosh-copy-fuzz-XXXXXX";
    if ( !mkdtemp( name ) ) {
      abort();
    }
    scratch = name;
    mkdir( ( scratch + "/dest" ).c_str(), 0700 );
    atexit( cleanup );
  }
  if ( size < 1 ) {
    return 0;
  }

  /* what the other end said, as something to read from */
  const std::string said = scratch + "/said";
  int fd = open( said.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600 );
  if ( fd < 0 || write( fd, data + 1, size - 1 ) != static_cast<ssize_t>( size - 1 ) ) {
    abort();
  }
  close( fd );

  FileCopy::Options options;
  options.sender = false;
  options.local = false;
  options.remove = data[0] & 1;
  options.paths.push_back( ( data[0] & 2 ) ? scratch + "/dest/" : scratch + "/dest/as" );

  const int in = open( said.c_str(), O_RDONLY );
  const int out = open( "/dev/null", O_WRONLY );
  if ( in < 0 || out < 0 ) {
    abort();
  }
  FileCopy::run( options, in, out );
  close( in );
  close( out );

  /* whatever it was told, what it was given to read is still there: it did not climb out of dest */
  struct stat st;
  if ( stat( said.c_str(), &st ) < 0 || st.st_size != static_cast<off_t>( size - 1 ) ) {
    abort();
  }
  empty( scratch + "/dest", false );
  return 0;
}
