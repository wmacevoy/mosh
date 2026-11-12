---
title: Port forwarding for mosh
---

[Overview](index.md) · [Using it](usage.md) · [How it works](design.md) · [Status and limits](status.md)

# Port forwarding for mosh

This fork of [mosh](https://mosh.org) adds **experimental port forwarding**:
TCP and UDP, each in both directions, carried inside the mosh session.

```
mosh -L 8080:localhost:80 user@server      # TCP, like ssh -L
mosh -R 9000:localhost:3000 user@server    # TCP the other way, like ssh -R
mosh -LU 5353:10.0.0.53:53 user@server     # UDP
mosh -RU 6000:localhost:6000 user@server   # UDP the other way
```

It is a prototype. It works and is tested, but it has not been reviewed by the
mosh maintainers and is not part of any mosh release. See
[Status and limits](status.md) before relying on it.

## What was added

| Option | What it forwards | ssh equivalent |
|---|---|---|
| `-L [bind:]port:host:hostport` | TCP connections made to a port on **your machine**, to `host:hostport` as seen from the server | `ssh -L` |
| `-R [bind:]port:host:hostport` | TCP connections made to a port on **the server**, to `host:hostport` as seen from your machine | `ssh -R` |
| `-LU [bind:]port:host:hostport` | UDP datagrams sent to a port on **your machine**, to `host:hostport` as seen from the server | none |
| `-RU [bind:]port:host:hostport` | UDP datagrams sent to a port on **the server**, to `host:hostport` as seen from your machine | none |
| `-N` | No terminal: just hold the session and its forwards open | `ssh -N` |
| `--fragment-parity=MODE` | Whether large UDP datagrams get parity so they survive a lost fragment: `auto` (the default), `always` or `never` | none |

## Why

Stock mosh says of itself that it "does not support X forwarding or the
non-interactive uses of SSH, including port forwarding." People who rely on
mosh for its roaming and its tolerance of bad networks have had to keep a
separate ssh connection open for forwards, and that connection has neither
property: it dies when the laptop sleeps or changes network.

A forward carried inside the mosh session inherits what mosh is good at:

- **It roams.** Change network, close the lid, come back: the forward is
  still there, like the terminal.
- **It is encrypted and authenticated** by the session's existing key. There
  is no second handshake and no extra port to open.
- **It does not stack retransmission.** Forwarded traffic bypasses mosh's
  terminal synchronization and is never retransmitted by mosh. A forwarded
  TCP connection is retransmitted only by its own two endpoints, so there is
  no TCP-over-TCP stall; forwarded UDP stays as unreliable as UDP is meant to
  be.

It also makes UDP forwarding possible at all, which ssh does not offer.

## What you need

- This build of mosh on **both** ends. If the server is an older mosh,
  the terminal works as usual and forwards simply do nothing (connections are
  refused).
- Nothing else: no extra privileges, ports or configuration. On Linux there
  is a [one-line installer](usage.md#installing) that needs no root.

## Where to go next

- [Using it](usage.md): options, examples, building, troubleshooting.
- [How it works](design.md): the side channel, the wire format, and the
  design choices.
- [Status and limits](status.md): what has been tested, what has not, and
  what is missing.
