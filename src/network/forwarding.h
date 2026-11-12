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

#ifndef FORWARDING_HPP
#define FORWARDING_HPP

#include <algorithm>
#include <climits>
#include <memory>
#include <string>
#include <vector>

#include "src/network/tcpforward.h"
#include "src/network/udpforward.h"

/* Everything a frontend forwards over the side channel, behind one event-loop interface. */

namespace Network {

class Forwarding
{
private:
  SideChannelMux mux;
  std::unique_ptr<UDPForwarder> udp;
  std::unique_ptr<TCPForwarder> tcp;

public:
  /* Throws NetworkException if a specification can't be parsed, resolved or bound. */
  Forwarding( SideChannelLink* link,
              bool client,
              const std::vector<std::string>& udp_specs,
              const std::vector<std::string>& tcp_specs,
              bool tcp_tun )
    : mux(), udp(), tcp()
  {
    if ( !udp_specs.empty() ) {
      udp.reset( new UDPForwarder( link, client ? UDPForwarder::LISTEN : UDPForwarder::CONNECT, udp_specs ) );
      mux.set_sink( UDPForwarder::TYPE_UDP_DATA, udp.get() );
    }
    if ( !tcp_specs.empty() ) {
      tcp.reset( new TCPForwarder( link,
                                   client ? TCPForwarder::CLIENT : TCPForwarder::SERVER,
                                   tcp_specs,
                                   tcp_tun ? TCPForwarder::TUN : TCPForwarder::ADAPTER ) );
      mux.set_sink( UDPForwarder::TYPE_TCP_SEGMENT, tcp.get() );
    }
  }

  /* Give this to Transport::set_sidechannel_sink(). */
  SideChannelSink* sink( void ) { return &mux; }

  void set_verbose( unsigned int verbose )
  {
    if ( udp ) {
      udp->set_verbose( verbose );
    }
    if ( tcp ) {
      tcp->set_verbose( verbose );
    }
  }

  /* What the user should know about how TCP forwards are provided. */
  std::vector<std::string> notes( void ) const { return tcp ? tcp->get_notes() : std::vector<std::string>(); }

  std::vector<int> fds( void ) const
  {
    std::vector<int> ret;
    if ( udp ) {
      ret = udp->fds();
    }
    if ( tcp ) {
      const std::vector<int> more = tcp->fds();
      ret.insert( ret.end(), more.begin(), more.end() );
    }
    return ret;
  }

  void read_fd( int fd )
  {
    /* each forwarder ignores descriptors that aren't its own */
    if ( udp ) {
      udp->read_fd( fd );
    }
    if ( tcp ) {
      tcp->read_fd( fd );
    }
  }

  /* Call once per trip around the event loop. */
  void tick( void )
  {
    if ( tcp ) {
      tcp->tick();
    }
  }

  /* Milliseconds until tick() next has something to do; INT_MAX if nothing is pending. */
  int wait_time( void ) const { return tcp ? tcp->wait_time() : INT_MAX; }
};

}

#endif
