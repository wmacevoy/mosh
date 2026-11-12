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

#ifndef FILECOPY_HPP
#define FILECOPY_HPP

#include <cstdint>
#include <string>
#include <vector>

/*
 * Copying files between the two ends of a session, for mocp.
 *
 * Each end runs one of these, a sender and a receiver, joined by a
 * reliable stream (which the session carries, and keeps through any loss
 * of contact).  The sender says what it has; the receiver says which of
 * it it lacks, and how much of each it already holds from an earlier
 * attempt; the sender sends the rest.
 *
 *   sender                               receiver
 *     LIST (files, sizes, times) ---->
 *     LIST_END                   ---->
 *                                <----   WANT (file, from where) ...
 *                                <----   PLAN_END
 *     FILE_BEGIN, DATA..., FILE_END -->
 *                                <----   RESULT
 *     ROUND_END                  ---->
 *                                <----   ROUND_DONE
 *
 * A file arrives under another name and takes its own only when it is
 * whole and its checksum agrees, so a copy that is cut off leaves no
 * broken file, only a part to carry on from.  With "automatic" the
 * sender does not finish: it looks again every so often and sends what
 * has changed.
 *
 * Every message is a type (one byte), a length (four, most significant
 * first) and that many bytes.
 */

namespace FileCopy {

struct Options
{
  bool sender;    /* or the receiver */
  bool local;     /* at the user's end: says what happens, on standard error */
  bool recursive; /* directories and what is in them */
  bool automatic; /* keep going, sending what changes */
  bool remove;    /* what is gone from the source goes from the destination */
  bool glob;      /* sender: the paths are patterns, as a shell would take them */
  bool quiet;
  int interval;                   /* ms between looks, when automatic */
  std::vector<std::string> paths; /* the sources, or the one destination */

  Options()
    : sender( false ), local( false ), recursive( false ), automatic( false ), remove( false ), glob( false ),
      quiet( false ), interval( 2000 ), paths()
  {}
};

/*
 * From words: "send" or "receive", then any of -r --auto --delete --glob
 * -q --interval=MS, then "--" and the paths.  False if they make no sense.
 */
bool parse( const std::vector<std::string>& words, Options& options );

/* Runs one end until the copy is done or the stream ends.  Returns an exit status. */
int run( const Options& options, int in_fd, int out_fd );

/* The checksum used: 128 bits, not cryptographic (the session already is). */
struct Hash
{
  uint64_t a, b;
  Hash() : a( 0xcbf29ce484222325ULL ), b( 0x9e3779b97f4a7c15ULL ) {}
  void add( const char* data, size_t len );
  bool operator==( const Hash& x ) const { return a == x.a && b == x.b; }
};

/* For the receiver: a path from the other end that stays inside the destination. */
bool safe_relative_path( const std::string& path );

}

#endif
