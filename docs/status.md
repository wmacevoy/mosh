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

**Mosh's own test suite** passes with these changes (34 pass, 2 expected
failures and 2 skips, as before, plus the new unit tests).

**New tests** (`make check` runs them):

| Test | Covers |
|---|---|
| `udp-forward` | Specification parsing, the frame format, the replay window, fragmentation and parity (every single-fragment loss across a range of sizes), reassembly timeout, the automatic parity decision, loss measurement, and a relay through two forwarders |
| `tcp-in-udp` | The header transformation in both directions, with checksums checked against independently computed values for IPv4 and IPv6 |
| `file-copy` | `mocp`'s sender and receiver joined directly: single files and trees, the destination as a name and as a directory, patterns, a copy carried on from a part file (and not from one that is the wrong file), unchanged files skipped, `--delete`, name clashes, and `--auto` following changes, additions and removals |
| `mocp.test` | The `mocp` and `mosh --stdio` commands with a real `mosh-server` and `mosh-client` (the server being this machine, without ssh): copies in both directions, by pattern, repeated, a missing source reported from the other end, and `--auto --delete` keeping a directory in step. Needs `perl` |
| `relay.test` | Sessions carried by the relay: from the start; found by the client when UDP gets no answer; with the relay told an address that is not the server's own; over IPv6; with the relay killed part way, after which the session carries on through a new one; and that no relay outlives its client. The remote relay is run directly, where ssh would run it. Needs `python3` |
| `forward-e2e.test` | A real `mosh-server` and `mosh-client` with one forward of each kind (`-L`, `-R`, `-LU`, `-RU`): TCP both ways with an orderly close, and UDP datagrams sent whole and in fragments. Needs `python3`; skipped without it |
| `tcp-forward` | Six simulated hours out of contact without losing a connection; and real TCP connections through a pair of socket adapters, clean and with 5% of datagrams lost, with a small MTU, a refusing target, a peer that does not support forwarding, and local and remote forwards sharing one session |

**End to end:**

| Scenario | Result |
|---|---|
| TCP `-L` | Echo, 2 MB each way with a half-close, 8 simultaneous connections, and a refused target all correct |
| The same with 2% and 10% of datagrams dropped | Correct; roughly 10-30 Mbit/s at 2% and about 1 Mbit/s at 10% |
| TCP `-R` | The same checks pass, clean and at 2% loss |
| UDP `-LU` and `-RU` | Datagrams from 1 byte to 65,507 bytes echoed correctly |
| UDP, 3000-byte datagrams, 5% loss | Request/reply pairs complete 76% of the time without parity, 97.5% with it, 95.5% in `auto` |
| UDP, 5000-byte datagrams, 1% loss | 89.6% without parity, 99.0% in `auto` |
| UDP cut off in the middle of a session (`--relay=auto`) | Carries on through the relay about 12 seconds later; goes back to UDP when it returns, and closes the relay a minute after |
| `mocp` of 12 MB with the path cut for 25 seconds part way | Nothing arrives while it is cut; the copy finishes 7 seconds after, identical |
| `mocp` killed part way, then run again | The 3.7 MB that had arrived is kept, and the second run sends the rest; identical |
| `mocp` to a server with an older build | Says at once that the server's mosh is too old |
| 20 MB through a forward, round trip 100 ms and 300 ms | 8.5-10.6 and 3.9 Mbit/s, where 1.4.0-pf.3 managed 5.2 and 1.7 |
| New client with an old server, and old client with a new server | Terminal works normally; nothing is forwarded |

## Checked on every change

GitHub Actions runs these on each push:

| Job | What it does |
|---|---|
| `build` | Builds with warnings as errors and runs the test suite on Ubuntu 22.04, Ubuntu 24.04 and macOS, and on Ubuntu with a second cryptography library |
| `msys2` | Builds on Windows in MSYS2, runs the unit tests there, and checks that the packaged client and server run a forwarding session outside MSYS2 |
| `sanitizers` | Runs the whole suite under AddressSanitizer and UndefinedBehaviorSanitizer, with leak checking for the forwarding tests |
| `fuzz` | Runs each fuzzer for a minute with libFuzzer, starting from a saved set of inputs |
| CodeQL | Static analysis of the C++, also run weekly |

## Fuzzing

Four fuzzers cover the code that handles input from the other end of a
session, which is where a malicious or compromised peer would attack:

| Fuzzer | Covers |
|---|---|
| `forward_frame_fuzzer` | The frame header, fragment reassembly, parity and the replay window, checking that whatever is split can be rebuilt and nothing is accepted twice |
| `tcpinudp_fuzzer` | The TCP-in-UDP codec, checking that whatever parses can be written and read back unchanged |
| `udp_forward_fuzzer` | The UDP forwarder, with real loopback sockets |
| `tcp_adapter_fuzzer` | The built-in TCP in both roles, with real loopback sockets |

They found two bugs when first run, both fixed:

- A peer that advertised a TCP maximum segment size of zero made the built-in
  TCP send empty segments for ever, freezing the program.
- A UDP datagram needing 227 to 255 fragments was sent but could never be
  reassembled.

The one-minute runs in CI are a check against regressions. They are not a
fuzzing campaign, and none of this is a security audit: the code has had no
independent review.

## What has not been tested

- A real network. Every test ran over loopback, with loss injected by a
  relay. Latency, reordering, real roaming and real MTU limits are untested.
- IPv6 forwarding targets and IPv6 mosh sessions.
- The `mosh` wrapper over a real ssh connection (only that it passes the
  options to both ends).
- `mocp` over a real ssh login, between two machines, or on Windows beyond
  one file each way between programs on the same machine.
- The relay over a real ssh connection, and on a real network that blocks
  UDP. In the tests the remote relay is started directly and UDP is "blocked"
  by pointing the client at a port nothing answers on.
- Any platform other than Linux. The code is meant to be portable but has
  not been built elsewhere.

## Known limits

**TCP throughput.** The built-in TCP, which carries forwards and `mocp`, has
window scaling from 1.4.0-pf.4 but no selective acknowledgment, so each time
it finds the limit of the path it loses a burst and starts again from the
loss. Measured on one machine through a path with added delay, it carried
about 9 Mbit/s at 100 ms round trip and 4 at 300 ms, and 20 to 30 with little
delay, where the limit was mosh itself handling a datagram at a time. An
operating system's TCP (so, `scp`) does better on a clean fast path. `mocp`
is for copies that must survive the network, not for the fastest copy.

**`mocp` sends changed files whole**, does not compress, and with `--auto`
looks for changes at intervals rather than being told of them. It keeps
times and permission bits, not ownership, links or special files. Its
`--auto` goes one way.

**`--stdio` brings back neither the command's standard error nor its exit
status.**

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

**The relay needs ssh to log in unattended.** It is run with `BatchMode`, so
with password-only login there is no fallback. Mosh cannot tell that from a
network that is merely away, so while it hears nothing from the server it
tries ssh again: a few times in the first minutes, then every five. Those
show in the server's log as failed logins; `--relay=never` stops them.

**The local relay listens on a loopback UDP port.** Another user of your
machine can send to it. They cannot read or forge the session, which is
encrypted and authenticated from end to end, but they can misdirect the
server's replies until your client next sends, which is a brief stall. And it is a fallback: over
ssh, mosh's datagrams queue behind one another like any TCP traffic.

**Forwards end with the session.** There is no way to add or remove one
while the session runs.

**Security.** A local forward lets anything that can reach the listening
address use it, so the default is loopback only. The server will connect or
send to whatever target the authenticated client was started with; as with
ssh, that is the user's own authority on the server. Mosh authenticates every
datagram before the forwarding code sees it, so the code can only be reached
by the other end of the session. It is fuzzed and run under sanitizers (see
above) but has had no independent security review.

## Not implemented

- `-D`, a SOCKS proxy. It needs asynchronous DNS resolution in `mosh-server`,
  which mosh does not have, and would lean hard on the built-in TCP.
- Forwarding of Unix-domain sockets, X11, or the ssh agent.
- Carrying forwarded TCP with the operating system's own TCP through a TUN
  device. An earlier version of this fork had it (`--tcp-tun`) and it
  worked, but it needed root and Linux, changed the address applications
  connect to, and on the server only reached the server's own addresses, so
  it was removed.
