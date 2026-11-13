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

#ifndef PUNCH_HPP
#define PUNCH_HPP

#include <memory>
#include <string>
#include <vector>

#include "src/crypto/crypto.h"
#include "src/network/network.h"

/*
 * A way straight through, for two machines that are each behind an
 * address translator (a NAT) and so cannot simply be sent to.
 *
 * A NAT lets a datagram in from outside only where one has lately gone
 * out the other way.  So if both ends send to each other at once, each
 * one's NAT takes the other's datagrams for answers to its own, and
 * lets them in: "hole punching" (RFC 5128).  For that each end has to
 * know where the other appears to be, from outside.  It finds out its
 * own outside address by asking a server that will say where a datagram
 * came from (STUN, RFC 8489); it adds its addresses on its own network,
 * in case the other end is on that too; and the two tell each other over some
 * way they already have of talking: here, the ssh connection that
 * carries the relay (relay.h), whose two ends hold one of these each.
 *
 * It does not always work.  Some NATs give a different outside address
 * for each destination, and then what the server saw is no use to
 * anyone else.  Nothing is lost by trying: the relay goes on carrying
 * the session over ssh until a way through is found, and again if it
 * closes.
 *
 * On the socket there are three kinds of datagram, told apart by how
 * they begin:
 *   probes   an 8-byte mark, then a sealed message: "are you there",
 *            "I am", "goodbye".  Sealed with a key the two ends share
 *            (sent over ssh), and numbered, so that only the other end
 *            can say where the other end is.
 *   STUN     answers from the server asked.
 *   the rest the session's own datagrams, taken only from where the
 *            other end was last heard to be.  (They are mosh's, and
 *            sealed already.)
 *
 * IPv4 only: that is where the NATs are.
 */

namespace Network {

/* The mark that begins a probe, and a control message between relays (relay.h). */
extern const char PUNCH_MARK[8];

/* A STUN request for our outside address: txid is 12 bytes of anything. */
std::string stun_request( const char* txid );
/* If this is an answer to one that says where we were seen: true, and where. */
bool stun_parse( const char* data, size_t len, Addr& mapped );

/* "1.2.3.4:567" both ways.  IPv4 only. */
bool parse_ip_port( const std::string& text, Addr& addr );
std::string format_ip_port( const Addr& addr );

class Punch
{
public:
  static const uint64_t FAST_FOR = 8000;    /* ms of probing every... */
  static const uint64_t FAST_EVERY = 250;   /* ...this often, then every... */
  static const uint64_t SLOW_EVERY = 2000;  /* ...this often, while there is no way through */
  static const uint64_t OPEN_EVERY = 1000;  /* and this often once there is, to know that there still is */
  static const uint64_t OPEN_FOR = 3500;    /* how long without hearing before it is thought closed */
  static const size_t MAX_CANDIDATES = 16;

  enum Got
  {
    NOTHING, /* nothing there to read */
    OTHER,   /* something of ours, or of nobody's: dealt with */
    DATA,    /* a datagram of the session's */
    GOODBYE  /* the other end has finished */
  };

private:
  int sock;
  bool initiator;
  std::unique_ptr<Crypto::Session> session;
  uint64_t send_seq, heard_seq;
  std::vector<Addr> candidates;       /* where the other end might be */
  std::vector<std::string> local_new; /* where we appear to be, not yet told to the other end */
  std::vector<std::string> local_all;
  Addr peer; /* where it was last heard to be */
  bool locked;
  uint64_t heard, started, last_probe;

  void probe( char type, const Addr& to );

  /* unused */
  Punch( const Punch& );
  Punch& operator=( const Punch& );

public:
  /*
   * key: as Crypto::Base64Key prints it.  The end that made it up is the
   * initiator.  stun_servers: "host:port", asked (from another process,
   * so as not to wait on name lookups) where we appear to be.
   * Throws NetworkException if there is no socket to be had.
   */
  Punch( bool s_initiator, const std::string& key, const std::vector<std::string>& stun_servers, uint64_t now );
  ~Punch();

  int fd( void ) const { return sock; }
  uint16_t local_port( void ) const;

  void add_candidate( const std::string& ip_port );
  /* Where we may be reached, as far as has been learnt since this was last asked. */
  std::vector<std::string> take_local_candidates( void );

  void tick( uint64_t now );
  /* Reads one datagram, if there is one. */
  Got receive( uint64_t now, std::string& datagram );

  /* Whether there is, as far as we know, a way through just now. */
  bool open( uint64_t now ) const { return locked && now - heard < OPEN_FOR; }
  uint64_t last_heard( void ) const { return locked ? heard : 0; }
  std::string where( void ) const { return locked ? format_ip_port( peer ) : std::string(); }

  void send( const std::string& datagram );
  void goodbye( void );
};

}

#endif
