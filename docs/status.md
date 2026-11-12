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

**New tests** (`make check` runs them):

| Test | Covers |
|---|---|
| `udp-forward` | Specification parsing, the frame format, the replay window, fragmentation and parity (every single-fragment loss across a range of sizes), reassembly timeout, the automatic parity decision, loss measurement, and a relay through two forwarders |
| `tcp-in-udp` | The header transformation in both directions, with checksums checked against independently computed values for IPv4 and IPv6 |
| `forward-e2e.test` | A real `mosh-server` and `mosh-client` with one forward of each kind (`-L`, `-R`, `-LU`, `-RU`): TCP both ways with an orderly close, and UDP datagrams sent whole and in fragments. Needs `python3`; skipped without it |
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

## Checked on every change

GitHub Actions runs these on each push:

| Job | What it does |
|---|---|
| `build` | Builds with warnings as errors and runs the test suite on Ubuntu 22.04, Ubuntu 24.04 and macOS, and on Ubuntu with a second cryptography library |
| `msys2` | Builds on Windows in MSYS2, runs the unit tests there, and checks that the packaged client starts outside MSYS2 |
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
