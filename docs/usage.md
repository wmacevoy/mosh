---
title: Using it
---

[Overview](index.md) · [Using it](usage.md) · [How it works](design.md) · [Status and limits](status.md)

# Using port forwarding

## Building

Build as you would build mosh, on both the client machine and the server:

```
git clone -b udp-forward https://github.com/wmacevoy/mosh.git
cd mosh
./autogen.sh
./configure
make
sudo make install        # or run from the build tree, see below
```

To try it without installing, point the wrapper at the binaries you built.
`--server` is a path on the server; `--client` is a path on your machine:

```
perl scripts/mosh --client=$PWD/src/frontend/mosh-client \
     --server=/path/on/server/mosh/src/frontend/mosh-server \
     -L 8080:localhost:80 user@server
```

Both ends must be this build. Against an older `mosh-server` the terminal
session works normally and the forwards do nothing.

## The forwarding specification

All three forwarding options take the same argument as ssh:

```
[bind_address:]port:host:hostport
```

- `port` is where the forward **listens**.
- `host:hostport` is where the other end **connects**, resolved there.
- `bind_address` is which address to listen on. It defaults to `127.0.0.1`,
  so only programs on the listening machine can use the forward. Use `*` for
  all interfaces.
- IPv6 addresses go in square brackets: `[::1]:8080:[2001:db8::1]:80`.

Each option can be given several times (up to 16 of each kind).

## `-L`: local TCP forward

```
mosh -L 8080:localhost:80 user@server
```

Connections to `localhost:8080` on your machine come out on the server and
connect to `localhost:80` there. Long form: `--tcp-forward=`.

Examples:

```
# a web app that only listens on the server's loopback
mosh -L 8080:localhost:3000 user@server
# then browse http://localhost:8080

# a database on another host the server can reach
mosh -L 5432:db.internal:5432 user@bastion
psql -h localhost -p 5432

# ssh to a machine behind the server, over the roaming session
mosh -L 2222:inner-host:22 user@bastion
ssh -p 2222 localhost
```

## `-R`: remote TCP forward

```
mosh -R 9000:localhost:3000 user@server
```

Connections to `localhost:9000` **on the server** come back through the
session and connect to `localhost:3000` on your machine. Long form:
`--tcp-remote-forward=`.

- The server listens on `127.0.0.1` unless you give a bind address, so by
  default only programs on the server can use it.
- Connections are refused until your client has connected to the session.

## `-U`: UDP forward

```
mosh -U 5353:10.0.0.53:53 user@server
dig @127.0.0.1 -p 5353 example.com
```

Datagrams sent to `localhost:5353` on your machine are re-sent by the server
to `10.0.0.53:53`, and replies come back to whoever sent them. Long form:
`--udp-forward=`.

- Each local sender gets its own conversation, which is forgotten after two
  minutes of silence.
- Datagrams of any size up to UDP's limit are forwarded. Ones larger than
  about 1200 bytes are split into fragments and reassembled at the other end.
- Delivery is as unreliable as UDP: nothing is retransmitted. A datagram is
  never delivered twice.
- There is no remote (server-listens) UDP forward.

### `--fragment-parity`

A fragmented datagram is lost if any one of its fragments is. Parity adds one
extra fragment per group of up to eight, from which any single lost fragment
in the group can be rebuilt.

| Mode | Behaviour |
|---|---|
| `auto` (default) | Add parity only when the session's measured loss makes it worthwhile: when the datagram would otherwise be lost at least 2% of the time. On a clean network no parity is sent. |
| `always` | Add parity to every fragmented datagram. |
| `never` | Never add parity. `--no-fragment-parity` means the same. |

You should not normally need to set this. In `auto` it can take a few seconds
after the network gets worse for parity to switch on.

## `--tcp-tun`: let the kernel carry TCP

By default mosh carries a forwarded TCP connection with a small TCP
implementation of its own (see [How it works](design.md)). With `--tcp-tun`,
each end tries to create a TUN network device instead, so that the operating
system's TCP is the endpoint.

- Needs Linux and the `CAP_NET_ADMIN` capability (for example, running as
  root). An end that cannot create the device quietly uses the default
  instead; the two ends decide independently.
- **On your machine, the address changes.** With a TUN device, applications
  connect to `10.111.0.2:port` instead of `127.0.0.1:port`. The client shows
  which applies in a message at the top of the screen for a few seconds after
  connecting.
- On the server, a TUN device is only used for forwards whose `host` is an
  IPv4 address of the server itself.
- Applies to `-L` only; `-R` never uses a TUN device.
- Only one mosh session per machine can use TUN devices at a time (they use
  fixed networks, `10.111.0.0/24` and `10.112.0.0/24`).

Most people should not use this option.

## Running the helper programs directly

The `mosh` wrapper passes the forwarding options to both ends. If you start
`mosh-server` and `mosh-client` yourself, give both the same specifications
in the same order:

| `mosh` | `mosh-client` and `mosh-server` |
|---|---|
| `-L spec`, `--tcp-forward=spec` | `-L spec` |
| `-R spec`, `--tcp-remote-forward=spec` | `-R spec` |
| `-U spec`, `--udp-forward=spec` | `-U spec` |
| `--tcp-tun` | `-w` |
| `--fragment-parity=mode` | `-F mode` |

`mosh-server -v` prints how each TCP forward is being provided.

## Troubleshooting

**"Connection refused" on a forwarded port.**
The usual causes, in order:
the server is not this build (forwards need both ends);
the session has not finished connecting yet;
the target itself refused, in which case the refusal is passed back;
or `--tcp-tun` is in use and the forward is at `10.111.0.2`, not `127.0.0.1`.

**A forward stops when I close the terminal session.**
Forwards live exactly as long as the mosh session. There is no equivalent of
`ssh -N` or `ssh -f`.

**The listening port is already in use.**
`mosh-client` (for `-L`, `-U`) or `mosh-server` (for `-R`) exits with a
"bind" error instead of starting the session. Choose another port.

**Large UDP datagrams go missing on a bad network.**
That is expected of UDP; `--fragment-parity=always` will recover more of
them at the cost of extra traffic.

**Forwarded TCP is slow on a long, fast path.**
The built-in TCP is limited to about 64 KB in flight per round trip (roughly
5 Mbit/s at 100 ms). See [Status and limits](status.md).
