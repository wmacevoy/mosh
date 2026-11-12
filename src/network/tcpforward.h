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

#ifndef TCPFORWARD_HPP
#define TCPFORWARD_HPP

#include <climits>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "src/network/network.h"
#include "src/network/sidechannel.h"
#include "src/network/tcpinudp.h"
#include "src/network/udpforward.h"

/*
 * TCP port forwarding over the mosh side channel.
 *
 * A forwarded TCP connection is carried as TCP *segments*, each one a
 * side-channel datagram in TCP-in-UDP form (tcpinudp.h).  mosh does not
 * retransmit or reorder them: the two TCP endpoints do, so there is one
 * layer of reliability, not two stacked.
 *
 * Each end turns connections into segments and back with a
 * SegmentPort, of which there are two kinds:
 *
 *  - TunPort (tuntcp.h) hands segments to the kernel's TCP through a
 *    TUN device.  It needs CAP_NET_ADMIN and is only used on request.
 *
 *  - AdapterPort (tcpadapter.h) is a small TCP of our own that bridges
 *    to ordinary sockets.  It needs no privileges and is what is used
 *    whenever a TUN device is not asked for or cannot be had.
 *
 * The two ends choose independently, and any pairing works.
 *
 * One end of a forward listens for applications to connect, and the
 * other connects to the forward's target.  For a local forward (-L) the
 * client listens; for a remote forward (-R) the server does.  The two
 * directions are separate TCPForwarders with the roles exchanged, told
 * apart on the wire by their frame type.
 *
 * As with UDP forwarding, both ends are given the same list of
 * specifications.  A segment names its specification by index and its
 * connection by the TCP port at the listening end, which travels in the
 * frame header in place of the UDP forwarder's flow id; the port at the
 * connecting end is implied.  So of a TCPInUDP's two port fields, only
 * the listening end's (source_port going to the connecting end,
 * dest_port coming from it) means anything between a SegmentPort and
 * its SegmentSink.
 */

namespace Network {

/* Where a SegmentPort sends segments bound for the other end. */
class SegmentSink
{
public:
  /* False if nothing can be sent now (so new connections should be refused). */
  virtual bool segment_ready( void ) const = 0;

  /* The largest segment, in TCP-in-UDP datagram form, that can be sent. */
  virtual size_t max_datagram( void ) const = 0;

  virtual void to_network( uint8_t forward, const TCPInUDP& segment ) = 0;

  virtual ~SegmentSink() {}
};

/* One end's source and destination of TCP segments. */
class SegmentPort
{
public:
  virtual std::vector<int> fds( void ) const = 0;
  virtual void read_fd( int fd ) = 0;

  /* Timers.  wait_time() is in milliseconds, INT_MAX if nothing is pending. */
  virtual void tick( uint64_t now ) = 0;
  virtual int wait_time( uint64_t now ) const = 0;

  virtual void from_network( uint8_t forward, const TCPInUDP& segment ) = 0;

  virtual ~SegmentPort() {}
};

class AdapterPort;
class TunPort;

class TCPForwarder : public SideChannelSink, public SegmentSink
{
public:
  enum Role
  {
    LISTEN, /* applications on this machine connect to us */
    CONNECT /* we connect to the targets */
  };

  enum Device
  {
    ADAPTER, /* ordinary sockets */
    TUN      /* a TUN device where possible, otherwise ordinary sockets */
  };

  static constexpr size_t MAX_FORWARDS = 16;

private:
  SideChannelLink* link;
  Role role;
  uint8_t frame_type;
  unsigned int verbose;

  std::unique_ptr<AdapterPort> adapter;
  std::unique_ptr<TunPort> tun;
  std::vector<SegmentPort*> port_of; /* by forward index; points at one of the above */
  std::vector<std::string> notes;

  uint64_t next_seq;
  ReplayWindow replay;

  uint64_t dropped_oversize;

  /* unused */
  TCPForwarder( const TCPForwarder& );
  TCPForwarder& operator=( const TCPForwarder& );

public:
  /*
   * Throws NetworkException if a specification can't be parsed, resolved or bound.
   * The two ends of a set of forwards must be given the same frame type.
   */
  TCPForwarder( SideChannelLink* s_link,
                Role s_role,
                const std::vector<std::string>& specs,
                Device device,
                uint8_t s_frame_type = UDPForwarder::TYPE_TCP_SEGMENT );
  ~TCPForwarder();

  void set_verbose( unsigned int s_verbose ) { verbose = s_verbose; }

  /* How each forward ended up being provided, one line each, for the user. */
  const std::vector<std::string>& get_notes( void ) const { return notes; }

  std::vector<int> fds( void ) const;
  void read_fd( int fd );
  void tick( void );
  int wait_time( void ) const;

  /* SideChannelSink */
  void sidechannel_recv( const std::string& payload );

  /* SegmentSink */
  bool segment_ready( void ) const { return link->sidechannel_ready(); }
  size_t max_datagram( void ) const;
  void to_network( uint8_t forward, const TCPInUDP& segment );

  uint64_t get_dropped_oversize( void ) const { return dropped_oversize; }
};

}

#endif
