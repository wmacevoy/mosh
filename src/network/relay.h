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

#ifndef RELAY_HPP
#define RELAY_HPP

#include <string>
#include <vector>

#include <sys/types.h>

#include "src/network/network.h"

/*
 * A way through for when UDP cannot get there.
 *
 * mosh talks UDP, and some networks will not carry it.  They do carry
 * ssh, or mosh could not have been started at all.  So when datagrams
 * are not getting through, they are carried over an ssh connection
 * instead, between two relays:
 *
 *   mosh-client --UDP--> local relay ==ssh==> remote relay --UDP--> mosh-server
 *    (this machine, loopback)                    (the server, to itself)
 *
 * Nothing changes for mosh-server: it sees a client at one of its own
 * addresses, and when the ssh connection is replaced, a client that has
 * moved, which is what it expects of clients.  Nor does the mosh
 * session depend on the ssh connection, which can come and go.
 *
 * The local relay does not give up on UDP.  Everything from the client
 * is still sent straight to the server as well, and while answers are
 * coming straight back the ssh connection is left alone (and after a
 * while, closed).  It is opened when nothing has come back directly for
 * a few seconds.  Sending both ways costs duplicates, which mosh is
 * indifferent to, and means there is never a decision to get wrong.
 *
 * Over ssh, datagrams lose what made them datagrams: they arrive late
 * rather than never.  It is for a pinch.
 *
 * On the stream each datagram is preceded by its length, as two bytes,
 * most significant first.
 */

namespace Network {

/* A datagram as it goes on the stream. */
std::string relay_frame( const std::string& datagram );

/* Takes the stream apart again. */
class RelayFrameParser
{
private:
  std::string pending;

public:
  RelayFrameParser() : pending() {}

  void append( const char* data, size_t len ) { pending.append( data, len ); }

  /* The next whole datagram, if one has arrived. */
  bool next( std::string& datagram );
};

/*
 * The remote relay ("mosh-server relay ADDRESS PORT"): datagrams
 * arriving on standard input go to ADDRESS:PORT, and what comes back
 * goes to standard output, until standard input ends.  Returns an exit
 * status.
 */
int relay_remote( const char* address, const char* port );

struct RelayOptions
{
  Addr server; /* where mosh-server is, for the direct route */
  socklen_t server_len;
  std::vector<std::string> command; /* starts the remote relay, typically through ssh */
  bool stream_only;                 /* don't try UDP at all */

  RelayOptions() : server(), server_len( 0 ), command(), stream_only( false ) {}
};

/*
 * Starts the local relay as a process of its own, and returns the UDP
 * port on 127.0.0.1 that it listens on for the client, or 0 if it could
 * not be started.  It runs until keep_alive_fd is closed, which happens
 * of itself when the caller exits.
 */
int relay_start_local( const RelayOptions& options, int& keep_alive_fd, pid_t& pid );

}

#endif
