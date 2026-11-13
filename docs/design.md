---
title: How it works
---

[Overview](index.md) · [Using it](usage.md) · [How it works](design.md) · [Status and limits](status.md)

# How it works

## The problem with mosh's transport

Mosh's network layer has two parts. The lower one sends encrypted,
authenticated UDP datagrams and follows the client as its address changes.
The upper one, the State Synchronization Protocol, keeps a copy of an object
(the screen, the keystrokes) in step at both ends by sending differences, and
deliberately skips intermediate states and paces what it sends. That is what
makes the terminal feel good, and it is the wrong shape for forwarded
traffic, where every datagram matters and delay hurts.

So forwarding does not go through state synchronization. It uses the lower
layer directly.

## The side channel

A forwarded payload is sent as a mosh datagram of its own, **underneath** the
state synchronization transport. It is encrypted and authenticated exactly
like every other mosh datagram and roams with the session, but it is not
acknowledged, retransmitted, ordered or paced. If it is lost, it stays lost.

Two details make this safe to add to an existing protocol:

- **Telling the two kinds of datagram apart.** A transport datagram begins
  with a 64-bit instruction number that counts up from zero. A side-channel
  datagram begins with the byte `0xFF`, which that number cannot reach in the
  life of a session.
- **Not confusing older peers.** Each end advertises that it understands the
  side channel in a new optional field of the transport's acknowledgment
  message, which older versions ignore. Nothing is sent on the side channel
  until the peer has advertised it, and it is only advertised when a forward
  is configured. A session without forwards is unchanged on the wire, and a
  session with an older peer just forwards nothing.

Every side-channel datagram carries a 13-byte header:

| Bytes | Field |
|---|---|
| 1 | `0xFF` |
| 1 | type: UDP datagram, UDP fragment or TCP segment, each for a local or a remote forward |
| 1 | which forward (index into the list both ends were given) |
| 2 | which conversation within that forward |
| 8 | sequence number |

Both ends are given the same list of forwards on their command lines, so
nothing but data ever needs to cross: there are no "open" or "close" control
messages to lose.

### Replay protection

Mosh's transport tolerates replayed datagrams because applying the same state
twice is harmless. Forwarded data is not like that, so each forwarder checks
the sequence number against a sliding window (1024 wide, as IPsec does) and
discards anything it has seen before or that is too old to judge.

## UDP forwarding

For a local forward, the client listens on the local port. Each distinct sender is given a
conversation number, and its datagrams are sent to the server, which opens
one socket per conversation and re-sends them to the target. Replies come
back the same way and are delivered to the original sender from the listening
port. Conversations are forgotten after two minutes of silence.

### Fragmentation

A mosh datagram has room for about 1200 bytes of forwarded payload (1206 on
IPv4). A larger datagram is cut into the fewest pieces that fit, as nearly
equal as possible, and each piece is sent with a 4-byte header giving its
index, the number of pieces, and the datagram's total length. The receiver
keeps up to 64 partial datagrams for up to one second each. If a piece never
arrives, the datagram is dropped, as with IP fragmentation.

Pieces are sent with consecutive sequence numbers, so the first one's number
identifies the datagram and the replay window covers fragments too.

### Parity

With parity, the pieces are taken in groups of up to eight and each group is
followed by one more fragment: the exclusive-or of its pieces. Any one piece
of a group can be rebuilt from the others and the parity. Making the pieces
equal in size keeps the parity fragment as small as it can be.

Whether that is worth the extra traffic depends on how lossy the path is and
how many pieces a datagram needs. A datagram of `k` pieces on a path losing a
fraction `p` of datagrams arrives with probability `(1-p)^k`. In `auto` mode
the sender adds parity when the chance of losing the datagram without it,
`1 - (1-p)^k`, is at least 2%:

| Loss rate | Parity is added for |
|---|---|
| none | nothing |
| 0.1% | 21 or more fragments |
| 1% | 3 or more fragments |
| 5% | everything fragmented |

### Measuring loss

Mosh did not previously measure loss; its transport never needed to. But
every datagram already carries the next number in a sequence, so the ones
missing from those received were lost. Each end now works that out about once
a second, over at least 20 datagrams, and averages it into an estimate. That
covers all of the session's traffic, the terminal's included, so an estimate
exists before anything is forwarded.

Each end reports its estimate to the other in another optional field of the
acknowledgment message, which the transport sends at least every three
seconds anyway. So no new messages are needed, and it is sent only when
forwarding is in use.

## TCP forwarding

A forwarded TCP connection is carried as TCP **segments**, one per
side-channel datagram. Mosh does not retransmit them. The two TCP endpoints
do, as they would over any lossy network, so there is one layer of
reliability rather than two stacked.

### TCP-in-UDP

Segments travel in the form described by
[TCP-in-UDP](https://blog.mptcp.dev/2025/07/14/TCP-in-UDP.html)
(draft-cheshire-tcp-over-udp): the 20-byte TCP header rearranged so that it
starts with a UDP header, with no bytes added.

```
           TCP                              TCP-in-UDP
   0  source port | dest port        0  source port | dest port    \ UDP
   4  sequence number                4  length      | checksum     / header
   8  acknowledgment number          8  offset+flags| window       \
  12  offset+flags| window          12  sequence number             } UDP
  16  checksum    | urgent pointer  16  acknowledgment number       } payload
  20  options, then data            20  options, then data         /
```

The side channel carries the right-hand column from offset 8 on. The port at
the listening end travels in the frame header as the conversation number, and
the port at the connecting end is implied by the forward. The urgent pointer
has no place in this form, so urgent data is not carried.

### The socket adapter

Without special privileges the kernel will not hand a program TCP segments,
only byte streams. So mosh contains a small TCP implementation of its own,
joined back to back with an ordinary socket:

```
application <-- kernel TCP --> socket | adapter <== segments ==> other end
```

At the listening end it accepts a connection and opens one through the tunnel.
At the connecting end it answers by connecting to the target, and completes
the handshake only if that works, so a refused connection is refused all the
way back to the application.

A mosh session survives losing contact with the other end, so a forwarded
connection must too. While the session has not heard from its peer for ten
seconds, unanswered retransmissions are not counted against a connection, and
when the peer is heard from again everything outstanding is sent at once
rather than when a backed-off timer expires.

It implements the handshake in both roles, cumulative acknowledgment,
reassembly of out-of-order segments, retransmission with an adaptive timeout
(RFC 6298), fast retransmit and recovery (NewReno, RFC 6582), slow start and
congestion avoidance, flow control with zero-window probes, independent
half-close of each direction, resets, and window scaling (RFC 7323). It
leaves out selective acknowledgment and timestamps, which costs speed but not
correctness.

Window scaling lets up to a megabyte be on its way at once, where the plain
TCP header allows 64 KB, which on a long path is the difference between using
the path and idling on it. It is negotiated, so either end may be an older
build without it. With that much in flight a burst can overrun the path and
lose hundreds of segments at once, which NewReno repairs one per round trip.
So when one repair uncovers a third hole, the adapter stops repairing: it
goes back to the first hole and sends on from there, starting slowly, as it
would after a timeout but without waiting for one. The other end says what it
already has, and that is skipped. For a round trip afterwards, duplicate
acknowledgments are not taken as loss, being echoes of the resending.

### Remote forwards

`-R` is `-L` with the ends exchanged: the server listens and the client
connects. It is implemented as a second pair of forwarders with the roles the
other way round, using a different frame type so the two directions share the
side channel without confusion. `-RU` is `-LU` reversed in exactly the same
way.

## Streams, and copying files

A forward joins a socket at one end to a socket at the other. The same
machinery can join two processes: instead of a listening port, the client has
a socket already in hand (one end of a socket pair, the other end being a
process it has started), and instead of an address to connect to, the server
has a way of making a socket when asked (the same again). That is all a
*stream* is: forward number 0 of its own frame type, with the built-in TCP in
the middle, and so reliable, ordered, and kept through any loss of contact.
The client opens it once the session is up. The session is told at each end
what its process is (`-X`), and ends when the client's process does; the
client exits with that process's status.

`mosh --stdio` puts a small pump at the client end (its own standard input
and output) and a command at the server end. `mocp` puts one end of a file
copy at each.

The copy is a conversation between a sender and a receiver, whichever way
round they are:

```
sender                                receiver
  LIST (names, sizes, times)  ---->
                              <----   WANT (which, and from what offset)
  FILE_BEGIN, DATA..., FILE_END ---->
                              <----   RESULT
```

The receiver wants a file unless it has one of that name, size and time. If
it holds part of the file from an earlier attempt it says how much, with a
checksum of that much; the sender checks that against the start of its own
file and, if they agree, sends only the rest. The whole file's checksum goes
at the end, and only if it agrees is the part renamed into place. The
checksum is 128 bits and not cryptographic: the session already authenticates
every datagram, so it is there against a file changing between attempts, not
against an adversary.

With `--auto` the sender does not finish. It remembers what it has offered,
looks again at intervals, and offers what differs (by size, time to the
nanosecond where the file system has it, and mode). A file that changes while
it is being read is abandoned and offered again next time.

The receiver takes names from another machine and writes files, so it checks
every one: relative, with no `..`, under the destination. It never creates
links. A fuzzer feeds it arbitrary senders.

## The relay: when UDP is blocked

Everything above rides on mosh's UDP datagrams, and some networks do not
carry UDP. They do carry ssh, or the session could not have been started. So
the datagrams can go by ssh:

```
mosh-client --UDP--> local relay ==ssh==> mosh-server relay --UDP--> mosh-server
       (your machine, loopback)                 (the server, to itself)
```

The local relay is a process `mosh-client` forks; the client then simply
sends to it on loopback instead of to the server. The remote one is
`mosh-server relay ADDRESS PORT`, run by ssh, which copies between its
standard input and output and a UDP socket. On the stream each datagram is
preceded by its length in two bytes. The remote relay is told the address
the client uses for the server, but tries the server's own addresses for
itself as well (the one ssh arrived at, and loopback) and keeps whichever
answers: behind address translation, the outside address is often not one a
machine can send to itself. The datagrams are mosh's own, encrypted
and authenticated end to end as always: the relays see nothing they can read
or alter, and need no trust.

What makes this small is that mosh already roams. `mosh-server` is not
changed at all: it sees a client at one of its own addresses, and when the
ssh connection is replaced, a client whose address has changed, which it has
always allowed for. Nor does the session depend on the ssh connection. The
local relay starts another when one ends, backing off from one second to
thirty (or to five minutes if none has ever worked, which usually means ssh
cannot log in unattended, and there is no sense in knocking).

**No decision to get wrong.** The local relay sends everything straight to
the server by UDP as well, always. Only when nothing has come straight back
for 2.5 seconds does it also use the stream, and when the stream has been
unneeded for a minute it is closed. Duplicates cost nothing, since mosh
discards them by sequence number, so the two routes need no arbitration and
there is no state in which a working route is left unused.

The client decides only whether to have a relay at all: with `--relay=auto`,
when it has heard nothing for three seconds at the start of a session or ten
later on. Once started, the relay stays for the rest of the session. A
session that never loses UDP never starts one.

**What is lost.** A stream delivers late what UDP would have dropped, so
mosh's round-trip estimates and its frame-rate control are working from
worse information, and forwarded TCP is TCP over TCP. That is why it is a
fallback and not a mode to prefer.

## The `mosh` command

Mosh has always been three programs: `mosh-server`, `mosh-client`, and a Perl
script, `mosh`, that logs in with ssh, starts the server, reads the port and
key it prints, and runs the client. The script made Perl a requirement
wherever mosh was to be used, which matters little on Linux and macOS and a
good deal on Windows.

From 1.4.0-pf.5 the client does that itself. Run under the name `mosh` or
`mocp` (which is how they are installed: links to `mosh-client`, or copies of
it on Windows), or as `mosh-client mosh ...`, it does what the script did and
then carries on, in the same process, as the client of the session it has
made. The options are the script's and so is what it tells ssh, including the
way it learns which address ssh reached: it has ssh run it again as its
`ProxyCommand`, where it connects to the server itself, says which address
that was, and carries ssh's bytes.

The script is kept (`scripts/mosh.pl`, installed as `mosh.pl`) and the two are
tested side by side on the same tasks.

## Through NATs

The relay gets a session through when UDP cannot reach the server, at the
price of carrying it in a stream. When the reason is a NAT in front of the
server, there is usually a way for UDP after all, and the relay is where to
look for it, because the relay is a conversation the two ends are already
having.

A NAT lets a datagram in only where one has lately gone out the other way.
If both ends send to each other at once, each NAT takes the other's datagrams
for answers and lets them in: hole punching (RFC 5128). Each end needs to
know where the other appears to be from outside. So:

```
local relay                                       remote relay
   |  <------------- HELLO (over ssh) -------------  |   "I know how"
   |  ---- KEY, STUN servers, my port ------------>  |
   |== asks a STUN server where it appears to be ==  |== and so does this ==
   |  <------------ where each may be reached ---->  |
   |  ............ probes, both ways, by UDP .......  |
   |  ============ the session, by UDP ============  |
```

Each relay opens a UDP socket for this, asks a STUN server (RFC 8489) where
datagrams from it appear to come from, and adds its own addresses on its own
network. The two exchange those over the stream, as frames that begin with a
mark no mosh datagram begins with, and send probes to every one of them, four
times a second at first. A probe is sealed with a key the local relay makes
up and sends over ssh, and is numbered, so only the other relay can answer
one or say where the other relay is; whichever address a newer genuine probe
comes from is where that end now is, as with mosh itself. Once probes are
being answered, the session's datagrams go that way.

Nothing is decided once and for all. The local relay goes on as before: it
sends by every route by UDP it has, and by the stream as well whenever
nothing has come back by UDP for 2.5 seconds. So the stream falls idle when
the direct path works, and is closed after a minute; and is started again,
with a new attempt, when the path stops working. The remote relay, which used
to end with its ssh connection, now stays on (as a process of its own) while
it is one end of a path that is in use, and for a minute after it last was.
The local relay tells it when the client is finished.

`mosh-server` and `mosh-client` are not changed by any of this: each still
talks to a relay on its own machine.

What it cannot do: a NAT that gives a different outside address for each
destination has told the STUN server something that is true of no one else,
and there is nothing to send to. Tailscale and WebRTC, which do the same
thing with more machinery, fall back to relays in that case too.

So does this, if it is given one: `mosh-server stun` with a key (what TURN is
to STUN). Each end can always send UDP out to a machine with a public
address, so each sends its datagrams there with a short header (a mark, proof
of the key, and sixteen bytes naming the pair of ends, which both can work
out from the key they share and no one else can) and the server sends them on
to whichever other address has lately named that pair. To the code that
looks for a path, "by way of the server" is one more place the other end can
be found, tried along with the rest and taken only while there is no path
straight there; while it is in use, the direct candidates are still tried
every two seconds. The proof of the key is twelve bytes that look like any
STUN transaction id, four random and eight that only the key gives for those
four, so the same request serves a public server and a private one.

## Why not something else?

**UDP over a reliable stream.** One lost packet would stall everything behind
it, and stale datagrams would arrive late instead of never. That is the wrong
trade for the real-time traffic people use UDP for.

**TCP as a byte stream over QUIC.** The socket adapter already has this
shape: it terminates TCP at each end and carries the bytes reliably between.
QUIC would be a much stronger transport in the middle than the built-in TCP.
But QUIC brings its own mandatory TLS handshake and connection migration,
both of which mosh already has; it needs a large library; and its minimum
datagram size (1200 bytes) does not fit inside mosh's own datagrams on every
path. It would have to run beside mosh rather than inside it.

**Doing everything through state synchronization.** That would deliver
forwarded data reliably and in order, with up to 250 ms of batching: TCP
semantics for UDP, and TCP-over-TCP for TCP.

## Where the code is

| File (under `src/network/`) | What it holds |
|---|---|
| `sidechannel.h` | The side channel's interfaces and the type multiplexer |
| `udpforward.{h,cc}` | Frame format, replay window, UDP forwarder, fragmentation and parity |
| `tcpinudp.{h,cc}` | The TCP-in-UDP header transformation and checksums |
| `tcpforward.{h,cc}` | TCP forwarder: framing and replay protection |
| `tcpadapter.{h,cc}` | The socket adapter (built-in TCP) |
| `relay.{h,cc}` | The two relays and the framing between them |
| `punch.{h,cc}` | Finding a direct path between the relays through NATs |
| `streamchild.{h,cc}` | The process at each end of a stream |
| `filecopy.{h,cc}` | `mocp`'s sender and receiver |
| `../frontend/moshwrapper.{h,cc}` | The `mosh` and `mocp` commands, in `mosh-client` |
| `forwarding.h` | Everything above behind one event-loop interface for the two programs |
| `network.{h,cc}` | Loss measurement (added to the existing connection) |
| `networktransport*.h`, `transportsender*.h` | Side-channel hooks and the two new optional message fields |
