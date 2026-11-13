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
 * Fuzzes what the hole-punching socket has to make sense of from anyone
 * at all on the Internet: answers from a STUN server (or from whoever
 * says they are one), and addresses given as text.
 */

#include <cstdint>
#include <cstdlib>
#include <string>

#include "src/network/punch.h"

using namespace Network;

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  /* an exact copy, so that reading past the end is seen */
  char* copy = static_cast<char*>( malloc( size ? size : 1 ) );
  if ( !copy ) {
    return 0;
  }
  for ( size_t i = 0; i < size; i++ ) {
    copy[i] = static_cast<char>( data[i] );
  }

  Addr mapped;
  if ( stun_parse( copy, size, mapped ) ) {
    /* whatever it said, it is an address that can be written down and read back */
    Addr again;
    const std::string text = format_ip_port( mapped );
    if ( text.empty() ) {
      abort();
    }
    if ( mapped.sin.sin_port != 0 && ( !parse_ip_port( text, again ) || format_ip_port( again ) != text ) ) {
      abort();
    }
  }

  Addr addr;
  const std::string text( copy, size );
  if ( parse_ip_port( text, addr ) && format_ip_port( addr ).empty() ) {
    abort();
  }
  free( copy );
  return 0;
}
