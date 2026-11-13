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

#ifndef MOSHWRAPPER_HPP
#define MOSHWRAPPER_HPP

#include <string>
#include <vector>

/*
 * What the "mosh" command does, as part of mosh-client itself: log in
 * to the server with ssh, start mosh-server there, read where it is and
 * its key, and become the client of that session.  It was a Perl
 * script (scripts/mosh.pl, which is still there), and that made Perl
 * something to install wherever mosh was wanted, which on Windows is
 * not nothing.  The options are the script's.
 *
 * mosh-client does this when it is run under the name "mosh" or "mocp"
 * (mocp being mosh --copy), or as "mosh-client mosh ..." and
 * "mosh-client mocp ...".
 */

namespace MoshWrapper {

/*
 * args: what followed the command name.  name: what to call ourselves
 * in messages.  self: argv[0] of this process.  print_colors: prints
 * the terminal's number of colors on standard output.
 *
 * Returns true to go on as the client: client_args are then its
 * arguments (the first being its name), and the environment has been
 * set up for it.  Returns false to exit, with status.
 */
bool run( const std::vector<std::string>& args,
          bool copy,
          const std::string& name,
          const std::string& self,
          void ( *print_colors )( void ),
          std::vector<std::string>& client_args,
          int& status );

/* ssh's way to the server when we are its ProxyCommand: says which address it reached, then carries bytes. */
int fake_proxy( const std::string& family, const std::string& host, const std::string& port );

/* Pieces, for testing. */
std::vector<std::string> shell_words( const std::string& line );
std::string shell_quote( const std::vector<std::string>& words );
/* "host:path" as a remote place: true, with host and path, if it is one. */
bool remote_place( const std::string& word, std::string& host, std::string& path );

}

#endif
