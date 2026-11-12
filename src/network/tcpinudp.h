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

#ifndef TCPINUDP_HPP
#define TCPINUDP_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "src/network/network.h"

/*
 * TCP-in-UDP: a TCP segment relabelled as a UDP datagram, with no added
 * bytes, after draft-cheshire-tcp-over-udp and the eBPF implementation
 * at https://github.com/multipath-tcp/tcp-in-udp.
 *
 * The 20-byte TCP header is rearranged so that it starts with a valid
 * UDP header.  The urgent pointer gives up its place to the UDP length
 * (so URG cannot be carried), and the rest moves down:
 *
 *            TCP                              TCP-in-UDP
 *    0  source port | dest port        0  source port | dest port    \ UDP
 *    4  sequence number                4  length      | checksum     / header
 *    8  acknowledgment number          8  offset+flags| window       \
 *   12  offset+flags| window          12  sequence number             } UDP
 *   16  checksum    | urgent pointer  16  acknowledgment number       } payload
 *   20  options, then data            20  options, then data         /
 *
 * This is the structural layer for carrying TCP over mosh's UDP
 * forwarding (udpforward.h).  What a UDP socket sends or receives -- and
 * so what "mosh -LU" forwards -- is the right-hand column from offset 8
 * on: the "datagram" form below.  The ports travel in the UDP header,
 * i.e. in socket addresses, and are rewritten by the forwarder exactly
 * as a NAT would rewrite them.
 *
 * mosh's own TCP endpoints (tcpadapter.h) read and write the datagram
 * form directly.  The other two forms, and the checksums, are for
 * exchanging segments with a real TCP stack: for instance the kernel
 * translator named above run at one end, which nothing in mosh does.
 *
 * Because forwarded datagrams are never retransmitted by mosh, the TCP
 * endpoints see an ordinary lossy path and there is only one layer of
 * retransmission.  Since segments are not fragmented, the endpoints
 * must be held to a small enough MSS (see max_segment_size()).
 */

namespace Network {

class TCPInUDP
{
public:
  static constexpr size_t UDP_HEADER_LEN = 8;
  static constexpr size_t TCP_HEADER_LEN = 20; /* without options */
  static constexpr size_t DATAGRAM_HEADER_LEN = TCP_HEADER_LEN - UDP_HEADER_LEN; /* likewise */
  static constexpr size_t MAX_OPTIONS_LEN = 40;

  enum Flag
  {
    FIN = 0x001,
    SYN = 0x002,
    RST = 0x004,
    PSH = 0x008,
    ACK = 0x010,
    URG = 0x020, /* never set: there is nowhere to put the urgent pointer */
    ECE = 0x040,
    CWR = 0x080
  };

  uint16_t source_port;
  uint16_t dest_port;
  uint32_t seq;
  uint32_t ack;
  uint16_t flags; /* the 12 bits after the data offset: 4 reserved, then CWR..FIN */
  uint16_t window;
  std::string options; /* a multiple of 4 bytes, at most MAX_OPTIONS_LEN */
  std::string payload;

  TCPInUDP()
    : source_port( 0 ), dest_port( 0 ), seq( 0 ), ack( 0 ), flags( 0 ), window( 0 ), options(), payload()
  {}

  bool has( Flag f ) const { return flags & f; }

  /* Header length in 32-bit words, as it appears in the data offset field. */
  unsigned int data_offset( void ) const { return ( TCP_HEADER_LEN + options.size() ) / 4; }

  /*
   * Datagram form: the payload of the UDP datagram.  The ports are not
   * part of it; they are the datagram's own.
   * Parsing returns false (leaving "out" unspecified) on malformed input.
   */
  static bool from_datagram( uint16_t source_port,
                             uint16_t dest_port,
                             const std::string& datagram,
                             TCPInUDP& out );
  std::string to_datagram( void ) const;

  /*
   * TCP form: a native TCP segment, header first, without an IP header.
   * Parsing ignores the checksum, and refuses segments with URG set
   * because they cannot be represented.  Serializing computes the
   * checksum for the given addresses, which must be of the same family.
   */
  static bool from_tcp( const std::string& segment, TCPInUDP& out );
  std::string to_tcp( const Addr& source, const Addr& dest ) const;

  /* UDP form: the whole UDP datagram, header and checksum included. */
  std::string to_udp( const Addr& source, const Addr& dest ) const;

  /*
   * Internet checksum of a transport segment (whose own checksum field
   * must be zero) with the IPv4 or IPv6 pseudo-header for "protocol".
   * Throws NetworkException if the addresses can't be used together.
   */
  static uint16_t checksum( uint8_t protocol, const Addr& source, const Addr& dest, const std::string& segment );

  /*
   * The largest MSS the TCP endpoints may use if each datagram-form
   * segment must fit in max_datagram bytes (for forwarding, the side
   * channel's limit less UDPForwarder::HEADER_LEN), leaving room for a
   * full set of options.
   */
  static size_t max_segment_size( size_t max_datagram );

private:
  bool valid( void ) const;
};

}

#endif
