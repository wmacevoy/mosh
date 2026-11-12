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
#include <functional>
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
 * Each end turns connections into segments and back with an
 * AdapterPort (tcpadapter.h): a small TCP of our own, bridged to
 * ordinary sockets, since the kernel will not give an unprivileged
 * program TCP segments, only byte streams.
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

  /*
   * False while the session has lost contact with the other end.  It
   * may be back in a moment or tomorrow; connections are kept, not
   * timed out, in the meantime.
   */
  virtual bool link_up( void ) const = 0;

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

class TCPForwarder : public SideChannelSink, public SegmentSink
{
public:
  enum Role
  {
    LISTEN, /* applications on this machine connect to us */
    CONNECT /* we connect to the targets */
  };

  static constexpr size_t MAX_FORWARDS = 16;

private:
  SideChannelLink* link;
  Role role;
  uint8_t frame_type;
  unsigned int verbose;

  std::unique_ptr<AdapterPort> adapter;
  size_t forwards; /* how many there are */

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
                uint8_t s_frame_type = UDPForwarder::TYPE_TCP_SEGMENT );
  ~TCPForwarder();

  void set_verbose( unsigned int s_verbose ) { verbose = s_verbose; }

  /*
   * A forward with no listening port and no address to connect to: a
   * stream between a socket the LISTEN end already has and one the
   * CONNECT end makes when asked.  It is forward number 0, and a
   * forwarder that has one was given no specifications.
   */
  void stream_spawner( const std::function<int()>& spawn ); /* CONNECT end */
  bool stream_open( int fd );                               /* LISTEN end; false if it can't be, now */
  void stream_allow( void ) { forwards = 1; }
  size_t connection_count( void ) const;

  std::vector<int> fds( void ) const;
  void read_fd( int fd );
  void tick( void );
  int wait_time( void ) const;

  /* SideChannelSink */
  void sidechannel_recv( const std::string& payload );

  /* SegmentSink */
  bool segment_ready( void ) const { return link->sidechannel_ready(); }
  bool link_up( void ) const { return link->sidechannel_connected(); }
  size_t max_datagram( void ) const;
  void to_network( uint8_t forward, const TCPInUDP& segment );

  uint64_t get_dropped_oversize( void ) const { return dropped_oversize; }
};

}

#endif
