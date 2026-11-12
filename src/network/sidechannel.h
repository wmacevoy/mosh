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

#ifndef SIDECHANNEL_HPP
#define SIDECHANNEL_HPP

#include <cstddef>
#include <cstdint>
#include <string>

/*
 * The side channel carries datagrams between the two ends of a mosh
 * session *underneath* the state-synchronization transport.  Payloads
 * are encrypted and authenticated by the session like any other mosh
 * datagram, but they are not acknowledged, retransmitted, ordered or
 * paced: a side-channel datagram that is lost stays lost.
 *
 * On the wire, a side-channel payload is distinguished from a transport
 * Fragment by its first byte.  A Fragment begins with a big-endian
 * 64-bit instruction id that counts up from zero, so its first byte
 * cannot be 0xFF within the lifetime of any session.
 *
 * A side-channel datagram is only ever sent to a peer that has
 * advertised CAPABILITY_SIDECHANNEL in a transport Instruction, because
 * older peers would try to parse it as a Fragment.
 */

namespace Network {

const uint8_t SIDECHANNEL_MAGIC = 0xFF;

/* Bits for Instruction.capabilities */
const uint32_t CAPABILITY_SIDECHANNEL = 1;

/* Receives side-channel payloads (including the leading magic byte). */
class SideChannelSink
{
public:
  virtual void sidechannel_recv( const std::string& payload ) = 0;
  virtual ~SideChannelSink() {}
};

/* Sends side-channel payloads.  Implemented by Transport. */
class SideChannelLink
{
public:
  /* True once the peer has advertised support and we may send. */
  virtual bool sidechannel_ready( void ) const = 0;

  /* Largest payload (including the magic byte) that fits in one datagram. */
  virtual size_t sidechannel_max_payload( void ) const = 0;

  /* Payload must begin with SIDECHANNEL_MAGIC. */
  virtual void sidechannel_send( const std::string& payload ) = 0;

  virtual ~SideChannelLink() {}
};

}

#endif
