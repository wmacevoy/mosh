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

#include "src/include/config.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstring>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "src/network/tcpadapter.h"
#include "src/util/timestamp.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

using namespace Network;

/* sequence numbers wrap */
static bool seq_lt( uint32_t a, uint32_t b )
{
  return static_cast<int32_t>( a - b ) < 0;
}

static void prepare_socket( int fd )
{
  int flags = fcntl( fd, F_GETFL );
  if ( flags >= 0 ) {
    fcntl( fd, F_SETFL, flags | O_NONBLOCK );
  }
  flags = fcntl( fd, F_GETFD );
  if ( flags >= 0 ) {
    fcntl( fd, F_SETFD, flags | FD_CLOEXEC );
  }
#ifdef SO_NOSIGPIPE
  int on = 1;
  setsockopt( fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof( on ) );
#endif
}

static void no_delay( int fd )
{
  int on = 1;
  setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof( on ) );
}

/* Close so that the application sees a reset rather than an orderly end. */
static void close_with_reset( int fd )
{
  struct linger l;
  l.l_onoff = 1;
  l.l_linger = 0;
  setsockopt( fd, SOL_SOCKET, SO_LINGER, &l, sizeof( l ) );
  close( fd );
}

static uint32_t mss_option( const std::string& options )
{
  for ( size_t i = 0; i < options.size(); ) {
    const uint8_t kind = options[i];
    if ( kind == 0 ) {
      break;
    }
    if ( kind == 1 ) {
      i++;
      continue;
    }
    if ( i + 1 >= options.size() ) {
      break;
    }
    const uint8_t len = options[i + 1];
    if ( len < 2 || i + len > options.size() ) {
      break;
    }
    if ( kind == 2 && len == 4 ) {
      return ( static_cast<uint8_t>( options[i + 2] ) << 8 ) | static_cast<uint8_t>( options[i + 3] );
    }
    i += len;
  }
  return AdapterPort::DEFAULT_MSS;
}

AdapterPort::AdapterPort( SegmentSink* s_sink, bool s_client )
  : sink( s_sink ), client( s_client ), listeners(), targets(), conns(), next_port( 32768 ), prng()
{}

AdapterPort::~AdapterPort()
{
  for ( std::vector<Listener>::iterator i = listeners.begin(); i != listeners.end(); i++ ) {
    close( i->fd );
  }
  for ( std::list<Conn>::iterator i = conns.begin(); i != conns.end(); i++ ) {
    if ( i->fd >= 0 ) {
      close( i->fd );
    }
  }
}

std::string AdapterPort::add_listener( uint8_t forward, const ForwardSpec& spec )
{
  const bool wildcard = spec.bind_host.empty() || spec.bind_host == "*";
  const std::string where = spec.bind_host + ":" + spec.bind_port;

  struct addrinfo hints, *res = NULL;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  int errcode = getaddrinfo( wildcard ? NULL : spec.bind_host.c_str(), spec.bind_port.c_str(), &hints, &res );
  if ( errcode != 0 ) {
    throw NetworkException( "TCP forwarding: " + where + ": " + gai_strerror( errcode ), 0 );
  }

  int fd = socket( res->ai_family, SOCK_STREAM, 0 );
  int saved_errno = errno;
  const char* failed = "socket";
  if ( fd >= 0 ) {
    int on = 1;
    setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof( on ) );
    prepare_socket( fd );
    if ( bind( fd, res->ai_addr, res->ai_addrlen ) < 0 ) {
      failed = "bind";
    } else if ( listen( fd, 16 ) < 0 ) {
      failed = "listen";
    } else {
      failed = NULL;
    }
    saved_errno = errno;
  }
  freeaddrinfo( res );

  if ( failed ) {
    if ( fd >= 0 ) {
      close( fd );
    }
    throw NetworkException( std::string( "TCP forwarding: " ) + failed + " " + where, saved_errno );
  }

  Listener listener;
  listener.forward = forward;
  listener.fd = fd;
  listeners.push_back( listener );
  return where;
}

void AdapterPort::add_target( uint8_t forward, const Addr& addr, socklen_t len )
{
  if ( targets.size() <= forward ) {
    targets.resize( forward + 1 );
  }
  targets[forward].addr = addr;
  targets[forward].len = len;
  targets[forward].present = true;
}

AdapterPort::Conn* AdapterPort::find( uint8_t forward, uint16_t port )
{
  for ( std::list<Conn>::iterator i = conns.begin(); i != conns.end(); i++ ) {
    if ( !i->dead && i->forward == forward && i->port == port ) {
      return &*i;
    }
  }
  return NULL;
}

AdapterPort::Conn* AdapterPort::new_conn( uint8_t forward, uint16_t port, int fd )
{
  conns.push_back( Conn() );
  Conn& c = conns.back();
  c.forward = forward;
  c.port = port;
  c.fd = fd;
  c.iss = prng.uint32();
  c.snd_una = c.snd_nxt = c.snd_max = c.iss;
  return &c;
}

void AdapterPort::sweep( void )
{
  for ( std::list<Conn>::iterator i = conns.begin(); i != conns.end(); ) {
    if ( i->dead ) {
      i = conns.erase( i );
    } else {
      i++;
    }
  }
}

uint32_t AdapterPort::local_mss( void ) const
{
  /* We send no options after the handshake, so a segment is our 12 bytes of header and its data. */
  const size_t limit = sink->max_datagram();
  if ( limit < TCPInUDP::DATAGRAM_HEADER_LEN + MIN_MSS ) {
    return MIN_MSS;
  }
  return std::min<size_t>( limit - TCPInUDP::DATAGRAM_HEADER_LEN, 0xFFFF );
}

/*
 * How much to send at a time: what the other end asked for, if it fits.
 * An absurdly small request is not honoured: a peer that asked for
 * segments of no bytes at all would otherwise have us send for ever.
 */
uint32_t AdapterPort::agreed_mss( const std::string& their_options ) const
{
  return std::max( MIN_MSS, std::min( mss_option( their_options ), local_mss() ) );
}

uint16_t AdapterPort::window( const Conn& c ) const
{
  const size_t space = c.recv_buf.size() < RECV_BUFFER ? RECV_BUFFER - c.recv_buf.size() : 0;
  return std::min<size_t>( space, 0xFFFF );
}

void AdapterPort::emit( Conn& c, uint16_t flags, uint32_t seq, const std::string& payload, bool with_mss )
{
  TCPInUDP s;
  ( client ? s.source_port : s.dest_port ) = c.port;
  s.flags = flags;
  s.seq = seq;
  s.ack = ( flags & TCPInUDP::ACK ) ? c.rcv_nxt : 0;
  s.window = c.last_window = window( c );
  if ( with_mss ) {
    const uint32_t m = local_mss();
    const char option[4] = { 2, 4, static_cast<char>( m >> 8 ), static_cast<char>( m & 0xFF ) };
    s.options.assign( option, sizeof( option ) );
  }
  s.payload = payload;
  sink->to_network( c.forward, s );
}

/* Answer a segment that belongs to no connection, as RFC 9293 3.10.7.1 says to. */
void AdapterPort::reply_reset( uint8_t forward, uint16_t port, const TCPInUDP& to )
{
  if ( to.has( TCPInUDP::RST ) ) {
    return;
  }

  TCPInUDP s;
  ( client ? s.source_port : s.dest_port ) = port;
  if ( to.has( TCPInUDP::ACK ) ) {
    s.flags = TCPInUDP::RST;
    s.seq = to.ack;
  } else {
    s.flags = TCPInUDP::RST | TCPInUDP::ACK;
    s.ack = to.seq + to.payload.size() + ( to.has( TCPInUDP::SYN ) ? 1 : 0 ) + ( to.has( TCPInUDP::FIN ) ? 1 : 0 );
  }
  sink->to_network( forward, s );
}

void AdapterPort::abort( Conn& c, bool tell_peer )
{
  if ( c.dead ) {
    return;
  }
  if ( tell_peer && c.state != CONNECTING ) {
    emit( c, TCPInUDP::RST | TCPInUDP::ACK, c.snd_nxt, "" );
  }
  if ( c.fd >= 0 ) {
    close_with_reset( c.fd );
    c.fd = -1;
  }
  c.dead = true;
}

void AdapterPort::maybe_finish( Conn& c )
{
  /* both directions closed and everything delivered */
  if ( !c.dead && c.fin_acked && c.fin_received && c.recv_buf.empty() ) {
    close( c.fd );
    c.fd = -1;
    c.dead = true;
  }
}

/* Client: an application has connected.  Open a connection for it through the tunnel. */
void AdapterPort::accept_from( const Listener& listener, uint64_t now )
{
  int fd = accept( listener.fd, NULL, NULL );
  if ( fd < 0 ) {
    return;
  }

  if ( !sink->segment_ready() || conns.size() >= MAX_CONNECTIONS ) {
    /* no forwarding at the other end (yet), or too busy: connection refused */
    close_with_reset( fd );
    return;
  }
  prepare_socket( fd );
  no_delay( fd );

  while ( find( listener.forward, next_port ) ) {
    next_port = next_port == 0xFFFF ? 32768 : next_port + 1;
  }
  Conn* c = new_conn( listener.forward, next_port, fd );
  next_port = next_port == 0xFFFF ? 32768 : next_port + 1;

  c->state = SYN_SENT;
  emit( *c, TCPInUDP::SYN, c->iss, "", true );
  c->snd_nxt = c->snd_max = c->iss + 1;
  c->rto_deadline = now + c->rto;
}

/* Server: the other end wants a connection.  See whether the target will have it. */
void AdapterPort::passive_open( uint8_t forward, uint16_t port, const TCPInUDP& syn, uint64_t now )
{
  if ( forward >= targets.size() || !targets[forward].present || conns.size() >= MAX_CONNECTIONS ) {
    reply_reset( forward, port, syn );
    return;
  }
  const Target& target = targets[forward];

  int fd = socket( target.addr.sa.sa_family, SOCK_STREAM, 0 );
  if ( fd < 0 ) {
    reply_reset( forward, port, syn );
    return;
  }
  prepare_socket( fd );
  no_delay( fd );

  if ( connect( fd, &target.addr.sa, target.len ) < 0 && errno != EINPROGRESS ) {
    close( fd );
    reply_reset( forward, port, syn );
    return;
  }

  Conn* c = new_conn( forward, port, fd );
  c->state = CONNECTING;
  c->connect_deadline = now + CONNECT_TIMEOUT;
  c->rcv_nxt = syn.seq + 1;
  c->snd_wnd = syn.window;
  c->mss = agreed_mss( syn.options );
}

/* Server: our socket has reached the target, so accept the connection from the tunnel. */
void AdapterPort::connected( Conn& c, uint64_t now )
{
  c.state = SYN_RCVD;
  emit( c, TCPInUDP::SYN | TCPInUDP::ACK, c.iss, "", true );
  c.snd_nxt = c.snd_max = c.iss + 1;
  c.rto_deadline = now + c.rto;
}

void AdapterPort::from_network( uint8_t forward, const TCPInUDP& segment )
{
  const uint64_t now = timestamp();
  const uint16_t port = client ? segment.dest_port : segment.source_port;

  Conn* c = find( forward, port );
  if ( !c ) {
    if ( !client && segment.has( TCPInUDP::SYN ) && !segment.has( TCPInUDP::ACK )
         && !segment.has( TCPInUDP::RST ) ) {
      passive_open( forward, port, segment, now );
    } else {
      reply_reset( forward, port, segment );
    }
    return;
  }

  switch ( c->state ) {
    case CONNECTING:
      if ( segment.has( TCPInUDP::RST ) ) {
        abort( *c, false );
      }
      /* otherwise it's the SYN again: they will hear from us when we know */
      break;

    case SYN_SENT:
      if ( segment.has( TCPInUDP::ACK ) && segment.ack != c->iss + 1 ) {
        reply_reset( forward, port, segment );
      } else if ( segment.has( TCPInUDP::RST ) ) {
        if ( segment.has( TCPInUDP::ACK ) ) {
          abort( *c, false ); /* connection refused */
        }
      } else if ( segment.has( TCPInUDP::SYN ) && segment.has( TCPInUDP::ACK ) ) {
        c->state = ESTABLISHED;
        c->snd_una = c->iss + 1;
        c->rcv_nxt = segment.seq + 1;
        c->snd_wnd = segment.window;
        c->mss = agreed_mss( segment.options );
        c->cwnd = INITIAL_WINDOW_SEGMENTS * c->mss;
        c->rto_deadline = 0;
        c->retries = 0;
        emit( *c, TCPInUDP::ACK, c->snd_nxt, "" );
      }
      break;

    case SYN_RCVD:
      if ( segment.has( TCPInUDP::RST ) ) {
        abort( *c, false );
      } else if ( segment.has( TCPInUDP::SYN ) ) {
        emit( *c, TCPInUDP::SYN | TCPInUDP::ACK, c->iss, "", true ); /* ours was lost */
      } else if ( segment.has( TCPInUDP::ACK ) && segment.ack == c->iss + 1 ) {
        c->state = ESTABLISHED;
        c->snd_una = c->iss + 1;
        c->snd_wnd = segment.window;
        c->cwnd = INITIAL_WINDOW_SEGMENTS * c->mss;
        c->rto_deadline = 0;
        c->retries = 0;
        established_input( *c, segment, now ); /* it may carry data already */
      }
      break;

    case ESTABLISHED:
      established_input( *c, segment, now );
      break;
  }

  sweep();
}

void AdapterPort::established_input( Conn& c, const TCPInUDP& segment, uint64_t now )
{
  if ( segment.has( TCPInUDP::RST ) ) {
    /* believe it only if it is where we expect the other end to be */
    if ( segment.seq - c.rcv_nxt <= 0xFFFF ) {
      abort( c, false );
    }
    return;
  }
  if ( segment.has( TCPInUDP::SYN ) ) {
    emit( c, TCPInUDP::ACK, c.snd_nxt, "" ); /* our handshake ACK was lost */
    return;
  }

  if ( segment.has( TCPInUDP::ACK ) ) {
    process_ack( c, segment, now );
  }

  if ( !segment.payload.empty() || segment.has( TCPInUDP::FIN ) ) {
    accept_data( c, segment.seq, segment.payload, segment.has( TCPInUDP::FIN ) );

    flush( c );
    if ( c.dead ) {
      return;
    }
    emit( c, TCPInUDP::ACK, c.snd_nxt, "" );
  }

  output( c, now );
  maybe_finish( c );
}

/* Take what continues the stream, and keep what will continue it later. */
void AdapterPort::accept_data( Conn& c, uint32_t seq, const std::string& payload, bool fin )
{
  if ( c.fin_received ) {
    return;
  }

  const uint32_t skip = c.rcv_nxt - seq; /* how much of this we already have */
  if ( skip > payload.size() ) {
    /* Not next.  If it is ahead of us (and not absurdly far), hold on to it. */
    const uint32_t ahead = seq - c.rcv_nxt;
    if ( !payload.empty() && ahead <= RECV_BUFFER && c.early_bytes + payload.size() <= RECV_BUFFER
         && c.early.insert( std::make_pair( seq, payload ) ).second ) {
      c.early_bytes += payload.size();
    }
    return; /* (an early FIN is not remembered; it will be sent again) */
  }

  const size_t space = c.recv_buf.size() < RECV_BUFFER ? RECV_BUFFER - c.recv_buf.size() : 0;
  const size_t take = std::min( payload.size() - skip, space );
  c.recv_buf.append( payload, skip, take );
  c.rcv_nxt += take;
  if ( take < payload.size() - skip ) {
    return; /* no room for the rest */
  }
  if ( fin ) {
    c.fin_received = true;
    c.rcv_nxt++;
    c.early.clear();
    c.early_bytes = 0;
    return;
  }

  /* Does something we were holding come next now? */
  for ( std::map<uint32_t, std::string>::iterator i = c.early.begin(); i != c.early.end(); ) {
    const uint32_t behind = c.rcv_nxt - i->first;
    if ( behind > RECV_BUFFER ) {
      i++; /* still ahead */
      continue;
    }
    const std::string held = i->second;
    const uint32_t held_seq = i->first;
    c.early_bytes -= held.size();
    c.early.erase( i );
    if ( behind <= held.size() ) {
      accept_data( c, held_seq, held, false );
      return; /* which has looked through the rest */
    }
    i = c.early.begin(); /* that one was stale; start over */
  }
}

void AdapterPort::process_ack( Conn& c, const TCPInUDP& segment, uint64_t now )
{
  const uint32_t ack = segment.ack;

  if ( seq_lt( c.snd_max, ack ) || seq_lt( ack, c.snd_una ) ) {
    return; /* for something we never sent, or old news */
  }

  const uint32_t flight = c.snd_max - c.snd_una;

  if ( ack == c.snd_una ) {
    /* Nothing new.  Three of these in a row, otherwise empty, mean a segment went missing. */
    if ( flight && segment.payload.empty() && !segment.has( TCPInUDP::FIN ) && segment.window == c.snd_wnd ) {
      if ( ++c.dupacks == 3 && !c.recovering ) {
        c.ssthresh = std::max( flight / 2, 2 * c.mss );
        c.cwnd = c.ssthresh;
        c.rtt_timing = false;
        c.recovering = true;
        c.recover = c.snd_max;
        retransmit_one( c );
      }
    }
    c.snd_wnd = segment.window;
    return;
  }

  /* new data acknowledged */
  uint32_t acked = ack - c.snd_una;
  if ( c.fin_was_sent && ack == c.fin_seq + 1 ) {
    c.fin_sent = c.fin_acked = true;
    acked--;
  }
  c.send_buf.erase( 0, std::min<size_t>( acked, c.send_buf.size() ) );
  c.snd_una = ack;
  if ( seq_lt( c.snd_nxt, ack ) ) {
    c.snd_nxt = ack;
  }
  c.snd_wnd = segment.window;
  c.dupacks = 0;
  c.retries = 0;

  /* round-trip time, from a segment that was sent only once */
  if ( c.rtt_timing && !seq_lt( ack, c.rtt_seq ) ) {
    const double r = now - c.rtt_start;
    if ( !c.rtt_valid ) {
      c.srtt = r;
      c.rttvar = r / 2;
      c.rtt_valid = true;
    } else {
      c.rttvar = 0.75 * c.rttvar + 0.25 * fabs( c.srtt - r );
      c.srtt = 0.875 * c.srtt + 0.125 * r;
    }
    c.rtt_timing = false;
  }
  if ( c.rtt_valid ) {
    const double rto = c.srtt + std::max( 4 * c.rttvar, 10.0 );
    c.rto = std::min<double>( std::max<double>( rto, RTO_MIN ), RTO_MAX );
  }

  if ( c.recovering ) {
    if ( seq_lt( ack, c.recover ) ) {
      /* That filled one hole and revealed another.  Fill it too, without waiting to be asked three times. */
      retransmit_one( c );
      c.rto_deadline = now + c.rto;
      return;
    }
    c.recovering = false;
  }

  /* slow start, then congestion avoidance */
  if ( c.cwnd < c.ssthresh ) {
    c.cwnd += std::min( acked, c.mss );
  } else {
    c.cwnd += std::max<uint32_t>( 1, static_cast<uint64_t>( c.mss ) * c.mss / c.cwnd );
  }
  c.cwnd = std::min<uint32_t>( c.cwnd, SEND_BUFFER );

  c.rto_deadline = ( c.snd_nxt != c.snd_una ) ? now + c.rto : 0;
}

/* Send whatever the windows allow. */
void AdapterPort::output( Conn& c, uint64_t now )
{
  if ( c.dead || c.state != ESTABLISHED ) {
    return;
  }

  /* What fits in a datagram can shrink while a connection is open, if mosh has to lower its own MTU. */
  const uint32_t mss = std::min( c.mss, local_mss() );

  while ( true ) {
    const uint32_t flight = c.snd_nxt - c.snd_una;
    const uint32_t data_sent = flight - ( c.fin_sent && !c.fin_acked ? 1 : 0 );
    const size_t unsent = c.send_buf.size() - data_sent;

    uint32_t allowed = std::min( c.snd_wnd, c.cwnd );
    if ( allowed == 0 && flight == 0 ) {
      allowed = 1; /* probe a closed window, or we could wait forever for it to open */
    }

    const bool fresh = !seq_lt( c.snd_nxt, c.snd_max );

    if ( unsent ) {
      if ( flight >= allowed ) {
        break;
      }
      const size_t n = std::min<size_t>( std::min<size_t>( unsent, mss ), allowed - flight );
      if ( n == 0 ) {
        break; /* (can't happen, but looping here for ever would be the worst way to find out) */
      }
      emit( c,
            TCPInUDP::ACK | ( n == unsent ? TCPInUDP::PSH : 0 ),
            c.snd_nxt,
            c.send_buf.substr( data_sent, n ) );
      c.snd_nxt += n;
    } else if ( c.local_eof && !c.fin_sent ) {
      emit( c, TCPInUDP::FIN | TCPInUDP::ACK, c.snd_nxt, "" );
      c.fin_sent = c.fin_was_sent = true;
      c.fin_seq = c.snd_nxt;
      c.snd_nxt++;
    } else {
      break;
    }

    if ( fresh && !c.rtt_timing ) {
      c.rtt_timing = true;
      c.rtt_seq = c.snd_nxt;
      c.rtt_start = now;
    }
    if ( seq_lt( c.snd_max, c.snd_nxt ) ) {
      c.snd_max = c.snd_nxt;
    }
    if ( !c.rto_deadline ) {
      c.rto_deadline = now + c.rto;
    }
  }
}

void AdapterPort::retransmit_one( Conn& c )
{
  if ( !c.send_buf.empty() ) {
    emit( c, TCPInUDP::ACK, c.snd_una, c.send_buf.substr( 0, std::min( c.mss, local_mss() ) ) );
  } else if ( c.fin_was_sent && !c.fin_acked ) {
    emit( c, TCPInUDP::FIN | TCPInUDP::ACK, c.fin_seq, "" );
  }
}

/* The retransmission timer has gone off. */
void AdapterPort::timeout( Conn& c, uint64_t now )
{
  c.rto = std::min<uint32_t>( c.rto * 2, RTO_MAX );
  c.rto_deadline = now + c.rto;

  if ( c.state == SYN_SENT || c.state == SYN_RCVD ) {
    if ( ++c.retries > MAX_SYN_RETRIES ) {
      abort( c, c.state == SYN_RCVD );
    } else if ( c.state == SYN_SENT ) {
      emit( c, TCPInUDP::SYN, c.iss, "", true );
    } else {
      emit( c, TCPInUDP::SYN | TCPInUDP::ACK, c.iss, "", true );
    }
    return;
  }

  /* A closed window is the other end's choice, not a sign that it has gone. */
  if ( c.snd_wnd != 0 && ++c.retries > MAX_RETRIES ) {
    abort( c, true );
    return;
  }

  /* Assume everything outstanding was lost, and start again gently from there. */
  c.ssthresh = std::max<uint32_t>( ( c.snd_max - c.snd_una ) / 2, 2 * c.mss );
  c.cwnd = c.mss;
  c.snd_nxt = c.snd_una;
  c.fin_sent = c.fin_acked;
  c.dupacks = 0;
  c.recovering = false;
  c.rtt_timing = false;
  c.rto_deadline = 0;
  output( c, now );
  if ( !c.rto_deadline ) {
    c.rto_deadline = now + c.rto;
  }
}

/* Pass what has arrived on to the socket. */
void AdapterPort::flush( Conn& c )
{
  if ( c.dead || c.fd < 0 ) {
    return;
  }

  while ( !c.recv_buf.empty() ) {
    ssize_t n = send( c.fd, c.recv_buf.data(), c.recv_buf.size(), MSG_DONTWAIT | MSG_NOSIGNAL );
    if ( n > 0 ) {
      c.recv_buf.erase( 0, n );
    } else if ( n < 0 && ( errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ) ) {
      break; /* the application is slow; tick() will try again */
    } else {
      abort( c, true ); /* the application has gone */
      return;
    }
  }

  if ( c.recv_buf.empty() && c.fin_received && !c.shut_wr ) {
    shutdown( c.fd, SHUT_WR );
    c.shut_wr = true;
  }

  /* If we had told the other end to stop, tell it that it can go on. */
  if ( c.state == ESTABLISHED && c.last_window < c.mss && window( c ) >= 2 * c.mss ) {
    emit( c, TCPInUDP::ACK, c.snd_nxt, "" );
  }
}

void AdapterPort::read_socket( Conn& c, uint64_t now )
{
  char buf[65536];
  const size_t space = c.send_buf.size() < SEND_BUFFER ? SEND_BUFFER - c.send_buf.size() : 0;
  if ( c.dead || c.state != ESTABLISHED || c.local_eof || !space ) {
    return;
  }

  ssize_t n = recv( c.fd, buf, std::min( space, sizeof( buf ) ), MSG_DONTWAIT );
  if ( n > 0 ) {
    c.send_buf.append( buf, n );
  } else if ( n == 0 ) {
    c.local_eof = true; /* a FIN will follow the data */
  } else if ( errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ) {
    return;
  } else {
    abort( c, true );
    return;
  }
  output( c, now );
}

std::vector<int> AdapterPort::fds( void ) const
{
  std::vector<int> ret;
  for ( std::vector<Listener>::const_iterator i = listeners.begin(); i != listeners.end(); i++ ) {
    ret.push_back( i->fd );
  }
  for ( std::list<Conn>::const_iterator i = conns.begin(); i != conns.end(); i++ ) {
    /* only when we have room for what we would read */
    if ( !i->dead && i->state == ESTABLISHED && !i->local_eof && i->send_buf.size() < SEND_BUFFER ) {
      ret.push_back( i->fd );
    }
  }
  return ret;
}

void AdapterPort::read_fd( int fd )
{
  const uint64_t now = timestamp();

  for ( std::vector<Listener>::const_iterator i = listeners.begin(); i != listeners.end(); i++ ) {
    if ( i->fd == fd ) {
      accept_from( *i, now );
      return;
    }
  }
  for ( std::list<Conn>::iterator i = conns.begin(); i != conns.end(); i++ ) {
    if ( i->fd == fd && !i->dead ) {
      read_socket( *i, now );
      maybe_finish( *i );
      break;
    }
  }
  sweep();
}

void AdapterPort::tick( uint64_t now )
{
  for ( std::list<Conn>::iterator i = conns.begin(); i != conns.end(); i++ ) {
    Conn& c = *i;
    if ( c.dead ) {
      continue;
    }

    if ( c.state == CONNECTING ) {
      struct pollfd p;
      p.fd = c.fd;
      p.events = POLLOUT;
      p.revents = 0;
      if ( poll( &p, 1, 0 ) > 0 ) {
        int error = 0;
        socklen_t len = sizeof( error );
        if ( getsockopt( c.fd, SOL_SOCKET, SO_ERROR, &error, &len ) == 0 && error == 0 ) {
          connected( c, now );
        } else {
          /* the target refused; so do we */
          c.state = SYN_RCVD;
          abort( c, true );
        }
      } else if ( now >= c.connect_deadline ) {
        c.state = SYN_RCVD;
        abort( c, true );
      }
      continue;
    }

    if ( !c.recv_buf.empty() ) {
      flush( c );
      maybe_finish( c );
    }
    if ( !c.dead && c.rto_deadline && now >= c.rto_deadline ) {
      timeout( c, now );
    }
  }
  sweep();
}

int AdapterPort::wait_time( uint64_t now ) const
{
  int ret = INT_MAX;
  for ( std::list<Conn>::const_iterator i = conns.begin(); i != conns.end(); i++ ) {
    if ( i->dead ) {
      continue;
    }
    if ( i->state == CONNECTING || !i->recv_buf.empty() ) {
      ret = std::min( ret, POLL_INTERVAL );
    }
    if ( i->rto_deadline ) {
      ret = std::min<int64_t>( ret, i->rto_deadline > now ? i->rto_deadline - now : 0 );
    }
  }
  return ret;
}
