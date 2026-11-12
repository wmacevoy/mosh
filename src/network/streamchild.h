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

#ifndef STREAMCHILD_HPP
#define STREAMCHILD_HPP

#include <string>
#include <vector>

#include <sys/types.h>

/*
 * The process at each end of a session's stream (see TYPE_STREAM): what
 * the stream is a stream between.  It is described by words, kept
 * together in one string with the character 0x1F between them:
 *
 *   @copy WORDS...   one end of a file copy (filecopy.h)
 *   @stdio           this program's own standard input and output
 *   @sh COMMAND      a command, run by the user's shell as ssh would run it
 */

namespace Network {

std::vector<std::string> stream_words( const std::string& joined );

/* Whether the words describe something that can be started. */
bool stream_words_valid( const std::vector<std::string>& words );

/*
 * Starts the process and returns a socket joined to it, or -1.  "local"
 * says it is at the user's end, where it may say things on standard
 * error.  With pid, the caller will wait for it; without, nobody need.
 */
int stream_child( const std::vector<std::string>& words, bool local, pid_t* pid );

}

#endif
