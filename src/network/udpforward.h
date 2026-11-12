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

#ifndef UDPFORWARD_HPP
#define UDPFORWARD_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "src/network/network.h"
#include "src/network/sidechannel.h"

/*
 * UDP port forwarding over the mosh side channel ("-L", in the manner
 * of ssh's TCP forwarding).
 *
 * The client listens on a local UDP port.  Each datagram it receives is
 * sent to the server over the side channel, and the server re-sends it
 * to a fixed target from a socket of its own.  Whatever the target
 * replies travels back the same way and is delivered to the original
 * local sender.
 *
 * Delivery is exactly as unreliable as UDP itself: nothing is
 * retransmitted or reordered.  A datagram that does not fit in a single
 * mosh datagram is dropped (there is no fragmentation).  A datagram is
 * never delivered more than once, even if an attacker replays it.
 *
 * Both ends are given the same list of forwarding specifications, so
 * nothing but data needs to cross the network: a forwarded datagram
 * names its specification by index and its conversation by a flow id
 * that the client chooses.
 */

namespace Network {

/* [bind_address:]port:host:hostport -- IPv6 addresses go in [brackets]. */
class ForwardSpec
{
public:
  std::string bind_host; /* empty or "*" means all interfaces; default is loopback */
  std::string bind_port;
  std::string target_host;
  std::string target_port;

  ForwardSpec( const std::string& spec ); /* throws NetworkException */
};

/* Sliding-window duplicate suppression, as in IPsec. */
class ReplayWindow
{
public:
  static constexpr uint64_t WINDOW = 1024;

private:
  std::vector<bool> seen; /* seen[ seq % WINDOW ] for highest - WINDOW < seq <= highest */
  uint64_t highest;
  bool any;

public:
  ReplayWindow() : seen( WINDOW, false ), highest( 0 ), any( false ) {}

  /* True the first time a sequence number is offered, unless it is too old to tell. */
  bool accept( uint64_t seq );
};

class UDPForwarder : public SideChannelSink
{
public:
  enum Role
  {
    LISTEN, /* mosh-client: accept datagrams on local ports */
    CONNECT /* mosh-server: relay them to the targets */
  };

  /* magic, type, forward index, flow id (2), sequence number (8) */
  static constexpr size_t HEADER_LEN = 13;
  static constexpr uint8_t TYPE_UDP_DATA = 0;
  static constexpr uint8_t TYPE_TCP_SEGMENT = 1; /* see tcpforward.h */

  static constexpr size_t MAX_FORWARDS = 16;
  static constexpr size_t MAX_FLOWS = 64;
  static constexpr uint64_t FLOW_IDLE_TIMEOUT = 120000; /* ms */
  static constexpr int MAX_READS_PER_WAKEUP = 16;

  /* The same framing serves every kind of forwarded payload. */
  static std::string encode_frame( uint8_t type,
                                   uint8_t forward,
                                   uint16_t flow_id,
                                   uint64_t seq,
                                   const std::string& data );
  static bool decode_frame( const std::string& payload,
                            uint8_t& type,
                            uint8_t& forward,
                            uint16_t& flow_id,
                            uint64_t& seq,
                            std::string& data );

  static std::string encode( uint8_t forward, uint16_t flow_id, uint64_t seq, const std::string& datagram );
  static bool decode( const std::string& payload,
                      uint8_t& forward,
                      uint16_t& flow_id,
                      uint64_t& seq,
                      std::string& datagram );

private:
  struct Forward
  {
    int listen_fd; /* LISTEN only */
    Addr target;   /* CONNECT only */
    socklen_t target_len;
    std::string description;

    Forward() : listen_fd( -1 ), target(), target_len( 0 ), description() {}
  };

  struct Flow
  {
    uint8_t forward;
    uint16_t id;
    int fd;    /* CONNECT: our socket, connected to the target */
    Addr peer; /* LISTEN: the local application that started this flow */
    socklen_t peer_len;
    uint64_t last_used;

    Flow() : forward( 0 ), id( 0 ), fd( -1 ), peer(), peer_len( 0 ), last_used( 0 ) {}
  };

  SideChannelLink* link;
  Role role;
  unsigned int verbose;

  std::vector<Forward> forwards;
  std::vector<Flow> flows;
  uint16_t next_flow_id;

  uint64_t next_seq;
  ReplayWindow replay;

  uint64_t dropped_oversize;

  void expire_flows( uint64_t now );
  void remove_flow( size_t index );
  Flow* new_flow( uint8_t forward, uint16_t id, uint64_t now );
  void to_network( Flow& flow, const char* data, size_t len );

  /* unused */
  UDPForwarder( const UDPForwarder& );
  UDPForwarder& operator=( const UDPForwarder& );

public:
  /* Throws NetworkException if a specification can't be parsed, resolved or bound. */
  UDPForwarder( SideChannelLink* s_link, Role s_role, const std::vector<std::string>& specs );
  ~UDPForwarder();

  void set_verbose( unsigned int s_verbose ) { verbose = s_verbose; }

  /* Sockets to poll for reading; pass each readable one to read_fd(). */
  std::vector<int> fds( void ) const;
  void read_fd( int fd );

  /* A forwarded datagram has arrived from the other end of the session. */
  void sidechannel_recv( const std::string& payload );

  size_t flow_count( void ) const { return flows.size(); }
  uint64_t get_dropped_oversize( void ) const { return dropped_oversize; }
};

}

#endif
