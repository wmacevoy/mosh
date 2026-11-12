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

#ifndef TUNTCP_HPP
#define TUNTCP_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "src/network/tcpforward.h"

/*
 * The TUN device: a SegmentPort that lets the kernel be the TCP endpoint.
 *
 * We create a point-to-nowhere network interface with a small private
 * subnet.  The kernel routes that subnet to the interface, where its
 * packets come to us; packets we write appear to arrive from it.
 *
 * Client (subnet 10.111.0.0/24, interface address .1):
 *   An application connects to 10.111.0.2:PORT, where PORT is the port
 *   of a forwarding specification.  Its segments are sent to the server
 *   and the replies are written back as if from 10.111.0.2:PORT.
 *
 * Server (subnet 10.112.0.0/24, interface address .1):
 *   Segments from the client are written as if from 10.112.0.(2+N),
 *   where N is the forward's index, to the forward's target, which must
 *   be an IPv4 address of the server itself.  The target's replies are
 *   routed back to the interface.
 *
 * The interface's MTU is set so that the kernel never produces a
 * segment too large to forward.
 *
 * Creating the interface needs CAP_NET_ADMIN, and Linux; otherwise the
 * constructor throws, and TCPForwarder falls back to AdapterPort.
 * Only one mosh on a machine can use each subnet at a time.
 */

namespace Network {

class TunPort : public SegmentPort
{
public:
  static constexpr uint32_t CLIENT_SUBNET = 0x0A6F0000; /* 10.111.0.0 */
  static constexpr uint32_t SERVER_SUBNET = 0x0A700000; /* 10.112.0.0 */
  static constexpr uint32_t NETMASK = 0xFFFFFF00;
  static constexpr uint32_t INTERFACE_HOST = 1;
  static constexpr uint32_t FIRST_PEER_HOST = 2;

  static constexpr size_t IP_HEADER_LEN = 20;
  static constexpr int MAX_READS_PER_WAKEUP = 16;

  /* An IPv4 packet around a TCP segment (whose checksum must already be right). */
  static std::string ip_packet( uint32_t source, uint32_t dest, uint16_t id, const std::string& tcp_segment );

  /* Takes one apart.  False unless it is an unfragmented IPv4 packet carrying TCP. */
  static bool parse_ip_packet( const std::string& packet,
                               uint32_t& source,
                               uint32_t& dest,
                               std::string& tcp_segment );

private:
  struct Forward
  {
    uint8_t index;
    uint16_t port;   /* client: the port applications connect to.  server: the target's port. */
    uint32_t target; /* server: the target's address */
  };

  SegmentSink* sink;
  bool client;
  int fd;
  std::string ifname;
  uint32_t subnet;
  uint16_t next_id;
  std::vector<Forward> forwards;

  void configure( size_t mtu );
  void write_segment( uint32_t source, uint32_t dest, const TCPInUDP& segment );
  void handle_packet( const std::string& packet );

  /* unused */
  TunPort( const TunPort& );
  TunPort& operator=( const TunPort& );

public:
  /* Throws NetworkException if a TUN device can't be created and configured. */
  TunPort( SegmentSink* s_sink, bool s_client );
  ~TunPort();

  const std::string& name( void ) const { return ifname; }

  /* Client: forward connections to this specification's port.  Returns the address to connect to. */
  std::string add_listener( uint8_t forward, const ForwardSpec& spec );

  /* Server: deliver this forward's connections to a local IPv4 address.  Returns it, as text. */
  std::string add_target( uint8_t forward, const Addr& target );

  std::vector<int> fds( void ) const;
  void read_fd( int fd );
  void tick( uint64_t ) {}
  int wait_time( uint64_t ) const { return INT_MAX; }
  void from_network( uint8_t forward, const TCPInUDP& segment );
};

}

#endif
