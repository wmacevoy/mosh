---
title: Status and limits
---

[Overview](index.md) · [Using it](usage.md) · [How it works](design.md) · [Status and limits](status.md)

# Status and limits

This is a prototype on a personal fork. It has not been reviewed or accepted
by the mosh project. The mosh maintainers have historically kept mosh's scope
narrow, and forwarding widens it considerably.

## What has been tested

Everything below was run on Linux over the loopback interface, with the real
`mosh-client` and `mosh-server` unless noted.

**Mosh's own test suite** passes with these changes (31 pass, 2 expected
failures and 2 skips, as before, plus the new unit tests).

**New unit tests** (`make check` runs them):

| Test | Covers |
|---|---|
| `udp-forward` | Specification parsing, the frame format, the replay window, fragmentation and parity (every single-fragment loss across a range of sizes), reassembly timeout, the automatic parity decision, loss measurement, and a relay through two forwarders |
| `tcp-in-udp` | The header transformation in both directions, with checksums checked against independently computed values for IPv4 and IPv6 |
| `tcp-forward` | Real TCP connections through a pair of socket adapters, clean and with 5% of datagrams lost, with a small MTU, a refusing target, a peer that does not support forwarding, and local and remote forwards sharing one session |

**End to end:**

| Scenario | Result |
|---|---|
| TCP `-L` | Echo, 2 MB each way with a half-close, 8 simultaneous connections, and a refused target all correct |
| The same with 2% and 10% of datagrams dropped | Correct; roughly 10-30 Mbit/s at 2% and about 1 Mbit/s at 10% |
| TCP `-R` | The same checks pass, clean and at 2% loss |
| UDP `-LU` and `-RU` | Datagrams from 1 byte to 65,507 bytes echoed correctly |
| UDP, 3000-byte datagrams, 5% loss | Request/reply pairs complete 76% of the time without parity, 97.5% with it, 95.5% in `auto` |
| UDP, 5000-byte datagrams, 1% loss | 89.6% without parity, 99.0% in `auto` |
| New client with an old server, and old client with a new server | Terminal works normally; nothing is forwarded |

## What has not been tested

- A real network. Every test ran over loopback, with loss injected by a
  relay. Latency, reordering, real roaming and real MTU limits are untested.
- IPv6 forwarding targets and IPv6 mosh sessions.
- The `mosh` wrapper over a real ssh connection (only that it passes the
  options to both ends).
- Any platform other than Linux. The code is meant to be portable but has
  not been built elsewhere.

## Known limits

**TCP throughput on long paths.** The built-in TCP has no window scaling, so
at most about 64 KB is in flight per round trip: roughly 5 Mbit/s at 100 ms.
It also has no selective acknowledgment, so recovery from heavy loss is slow.

**No rate limiting.** Forwarded traffic competes with the terminal for the
same path. A large transfer can make the terminal less responsive.

**Bursts of UDP.** A burst of several hundred datagrams sent at once can
overflow socket buffers somewhere along the path and lose some. This is
ordinary UDP behaviour, but forwarding adds two more sockets where it can
happen.

**Automatic parity reacts in seconds, not instantly.** Loss is measured over
a second and reported at most every three, so the first few seconds of a bad
patch are unprotected.

**Counts.** Up to 16 forwards of each kind, and 64 simultaneous TCP
connections and 64 UDP conversations in each direction.

**Forwards end with the session.** There is no way to keep a forward without
a terminal, and no way to add or remove one while the session runs.

**Security.** A local forward lets anything that can reach the listening
address use it, so the default is loopback only. The server will connect or
send to whatever target the authenticated client was started with; as with
ssh, that is the user's own authority on the server. The added code has had
no security review.

## Not implemented

- `-D`, a SOCKS proxy. It needs asynchronous DNS resolution in `mosh-server`,
  which mosh does not have, and would lean hard on the built-in TCP.
- Forwarding of Unix-domain sockets, X11, or the ssh agent.
- Carrying forwarded TCP with the operating system's own TCP through a TUN
  device. An earlier version of this branch had it (`--tcp-tun`) and it
  worked, but it needed root and Linux, changed the address applications
  connect to, and on the server only reached the server's own addresses, so
  it was removed.
