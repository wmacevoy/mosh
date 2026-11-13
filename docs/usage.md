---
title: Using it
---

[Overview](index.md) · [Using it](usage.md) · [How it works](design.md) · [Status and limits](status.md)

# Using port forwarding

## Installing

Port forwarding needs this build on **both** your machine and the server.

**Linux** (x86-64 or ARM64, glibc 2.34 or newer: Debian 12, Ubuntu 22.04,
RHEL 9 and later) and **macOS** (11 or later, Apple Silicon or Intel). Run
this on each machine. It installs into `~/.local/bin` and needs no root:

```
curl -fsSL https://raw.githubusercontent.com/wmacevoy/mosh/master/scripts/install.sh | sh
```

It downloads the newest [release](https://github.com/wmacevoy/mosh/releases),
checks it against the published checksums, and installs `mosh`, `mocp`,
`mosh-client` and `mosh-server`. The programs need nothing that does not
come with the operating system (on macOS, no Homebrew).

- On your own machine, put `~/.local/bin` on your `PATH` if it isn't (the
  installer says so). `mosh` needs `ssh`, which is how a session is started,
  and nothing else. (Before 1.4.0-pf.5 it was a Perl script and needed Perl;
  it is now `mosh-client` itself under another name. The script is still
  installed, as `mosh.pl`.)
- On a server, nothing more: this `mosh` looks for `mosh-server` in
  `~/.local/bin` on the server before anywhere else, so it finds the one you
  installed even if the system has an older mosh.
- Set `PREFIX` to install somewhere else, or `MOSH_VERSION` for a particular
  release.

**Windows.** Download the `msys2` zip from the release page and unpack it. It
holds `mosh.exe`, `mocp.exe`, `mosh-client.exe`, `mosh-server.exe` and the
MSYS2 libraries they need. `mosh` and `mocp` need `ssh`, which Windows 10 and
later have (`ssh.exe`), and from 1.4.0-pf.5 nothing else: no Perl, and no
MSYS2 installation. That has been checked only as far as the programs
starting on Windows; see [Status and limits](status.md).

A Windows machine can be the server too (from release 1.4.0-pf.2): start
`mosh-server.exe` there, for instance over Windows's own OpenSSH server.
Windows blocks incoming UDP unless told otherwise, so allow it for
`mosh-server.exe` in the firewall first. (Before 1.4.0-pf.3 it also had to
be given an address to listen on with `-i`.) The Windows server has only been
tested with forwards and no terminal (`-N`), talking to a client on the same
machine.

**Everything else.** Build from source, below.

The macOS programs are not signed with an Apple Developer ID. Installed with
the script above that makes no difference. If you download the package with
a browser instead, macOS will quarantine it; clear that with
`xattr -dr com.apple.quarantine` on the unpacked directory.

Releases are marked as pre-releases: this is experimental and has not been
audited. Each download is listed in the release's `SHA256SUMS`, and was built
by the repository's release workflow from the tagged commit, which
`gh attestation verify FILE --repo wmacevoy/mosh` will confirm.

## Building

Build as you would build mosh, on both the client machine and the server:

```
git clone https://github.com/wmacevoy/mosh.git
cd mosh
./autogen.sh
./configure
make
sudo make install        # or run from the build tree, see below
```

To try it without installing, run the client you built as `mosh` (it is
`mosh` when its first word says so) and tell it where the server you built
is. `--server` is a path on the server:

```
src/frontend/mosh-client mosh \
     --server=/path/on/server/mosh/src/frontend/mosh-server \
     -L 8080:localhost:80 user@server
```

Both ends must be this build. Against an older `mosh-server` the terminal
session works normally and the forwards do nothing.

## The forwarding specification

All four forwarding options take the same argument as ssh's `-L`:

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

## `-LU` and `-RU`: UDP forwards

The UDP options are the TCP ones with a `U` added.

```
mosh -LU 5353:10.0.0.53:53 user@server
dig @127.0.0.1 -p 5353 example.com
```

Datagrams sent to `localhost:5353` on your machine are re-sent by the server
to `10.0.0.53:53`, and replies come back to whoever sent them. Long form:
`--udp-forward=`.

```
mosh -RU 6000:localhost:6000 user@server
```

Datagrams sent to `localhost:6000` **on the server** are re-sent by your
machine to `localhost:6000` there, and replies go back to the sender on the
server. Long form: `--udp-remote-forward=`. As with `-R`, the server listens
on `127.0.0.1` unless you give a bind address.

Write the specification as a separate word, as shown: `-LU spec`, not
`-LUspec`.

- Each local sender gets its own conversation, which is forgotten after two
  minutes of silence.
- Datagrams of any size up to UDP's limit are forwarded. Ones larger than
  about 1200 bytes are split into fragments and reassembled at the other end.
- Delivery is as unreliable as UDP: nothing is retransmitted. A datagram is
  never delivered twice.

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

## `-N`: forwards without a terminal

```
mosh -N -L 8080:localhost:80 user@server
```

With `-N`, mosh does not use the terminal at all. It keeps the session and
its forwards open until you interrupt it (Ctrl-C) or kill it, like `ssh -N`.

- It needs no terminal and reads no input, so it can run in the background
  (`mosh -N ... &`), from a script, or under another program.
- It prints `mosh: connected; forwarding.` on standard error once the
  forwards can be used. A program starting it can wait for that line.
- On the server it runs a command that just waits. Give a command to run
  something else for the life of the session: `mosh -N -L ... server -- some-daemon`.
  The session ends when that command does.

## `mocp`: copying files

```
mocp report.pdf server:docs/          # to the server
mocp -r server:build/out .            # from it, with everything inside
mocp 'server:logs/*.txt' logs/        # by pattern (expanded on the server)
```

`mocp` is `scp` through a mosh session. It needs this build (1.4.0-pf.4 or
later) at both ends and nothing else. What it adds is what mosh adds:

- **The copy survives the network.** Lose the connection, change networks,
  close the laptop: the copy waits, and carries on when the server can be
  reached again. Nothing has to be restarted.
- **A copy that was stopped carries on where it left off.** If `mocp` itself
  is killed, or the machine is switched off, run the same command again. What
  had arrived of a file is checked against the source and the rest is sent.
- **Nothing is half there.** A file arrives under a temporary name
  (`.name.mocp-part`) and replaces the real one only when it is whole and its
  checksum agrees.
- **What is already there is not sent.** A file with the same size and
  modification time at the destination is skipped, so repeating a copy of a
  directory sends only what changed.

Exactly one end is remote, written `[user@]host:path`; a relative path there
is relative to your home directory. As with `scp`: several sources, or a
destination that is a directory or ends in `/`, means "put them in there";
otherwise the one source takes the destination's name. `dir/.` as a source
means the contents of `dir` rather than `dir` itself.

| Option | |
|---|---|
| `-r` | Directories, and everything in them. |
| `--auto` | Having copied, stay, and copy again whatever changes at the source. |
| `--delete` | Remove from the destination what is no longer at the source (within the directories copied). |
| `--interval=SECONDS` | How often `--auto` looks. Default 2. |
| `-q` | Say only what goes wrong. |

mosh's own connection options (`--ssh`, `--server`, `-p`, `--relay`) work too.
It exits 0 if everything was copied and 1 if anything was not, and says what
and why, whichever end the trouble was at.

### `--auto`: keeping a directory up to date

```
mocp --auto -r --delete server:project/build/. ./build
```

copies the server's `project/build` into `./build`, and then keeps doing so:
every two seconds it looks for files that are new, changed or gone, and
brings `./build` into line. It runs until you interrupt it, through any
number of network changes in between. It is for the case of building on a
server and wanting the results on your own machine (or the other way about:
editing here, running there).

It goes one way only. Changes made at the destination are not sent back, and
with `--delete` files that exist only at the destination are removed. A
changed file is sent whole, not as differences, so it suits build output and
documents better than one enormous file that changes a little; for that,
`rsync -e 'mosh --stdio'` sends differences.

## `--stdio`: a command's input and output

```
echo hello | mosh --stdio server -- tr a-z A-Z
rsync -e 'mosh --stdio' -a project/ server:project/
```

`mosh --stdio host -- command` runs the command on the server with its
standard input and output connected to mosh's own, as `ssh host command`
does, but carried by the mosh session, so the stream outlasts network
changes. It is what `mocp` is built on. Unlike ssh, the command's standard
error and its exit status are not brought back.

## Losing the network

A mosh session survives losing contact with the server, for as long as it
takes, and so do the connections forwarded through it. While the session is
out of contact a forwarded TCP connection simply waits; nothing times out at
mosh's end. When contact returns, whatever was waiting is sent at once.

What can still end a connection during an outage is the programs using it:
an application or server with its own inactivity or keepalive timeout will
still apply it.

## When UDP is blocked

Mosh talks UDP, and some networks carry only TCP: a campus or hotel network,
a firewall nobody will open, a host behind a jump box. Mosh used to start
there and then sit at "Connecting...", since ssh had got through and its own
datagrams could not.

Now it gets through the way ssh did. If the server has not answered by UDP
within three seconds of starting (ten, later in a session), mosh opens an ssh
connection to the server, runs `mosh-server relay` there, and sends its
datagrams through that. You need do nothing; `--relay` is for saying otherwise:

| `--relay=` | |
|---|---|
| `auto` | The default. UDP, with ssh brought in when UDP gets no answer. |
| `always` | ssh from the start, and no UDP. For a network you know blocks it: saves the three seconds. |
| `never` | UDP only, as mosh has always behaved. |

What to know about it:

- **It is still a mosh session.** It does not depend on the ssh connection:
  if that drops, or you change networks, another is opened, and the session
  carries on. The terminal and the forwards survive as they do over UDP.
- **UDP is not given up on.** In `auto` mosh keeps trying it, uses it again
  as soon as it works, and closes the ssh connection after a minute unused.
  So a laptop carried from a network that blocks UDP to one that does not
  goes back to UDP by itself.
- **ssh has to get in again without asking.** The extra connection is made
  with `BatchMode`, so it needs keys, an agent or a shared connection
  (`ControlMaster`). With password-only login the fallback cannot happen and
  mosh behaves as before.
- **It is slower to react.** Over ssh a delayed datagram holds up everything
  behind it, which is the thing mosh was built to avoid. Typing is still
  echoed locally. Forwarded UDP (`-LU`, `-RU`) arrives late instead of not at
  all, which suits real-time traffic badly.
- **Both ends need this build.** An older `mosh-server` has no `relay`, and
  the fallback then does nothing.

With `-N`, mosh says on standard error which way it went:
`mosh: no answer by UDP; trying through ssh as well.` or, with
`--relay=always`, `mosh: connecting through ssh.`

## Running the helper programs directly

The `mosh` wrapper passes the forwarding options to both ends. If you start
`mosh-server` and `mosh-client` yourself, give both the same specifications
in the same order:

| `mosh` | `mosh-client` and `mosh-server` |
|---|---|
| `-L spec`, `--tcp-forward=spec` | `-L spec` |
| `-R spec`, `--tcp-remote-forward=spec` | `-R spec` |
| `-LU spec`, `--udp-forward=spec` | `-LU spec` |
| `-RU spec`, `--udp-remote-forward=spec` | `-RU spec` |
| `--fragment-parity=mode` | `-F mode` |
| `-N` | `-N` (client only; the server is given a command that waits) |
| `--relay=when` | `MOSH_RELAY=when` and `MOSH_RELAY_COMMAND` in `mosh-client`'s environment (below) |
| `--stdio`, `--copy` | `-X words` at each end, saying what the process at that end of the stream is (see `mosh-server(1)`) |

`MOSH_RELAY_COMMAND` is the command that reaches a relay on the server, as
its arguments separated by the unit-separator character (code 31); it is run
directly, without a shell. The wrapper's is, in effect,

```
ssh -T -o BatchMode=yes user@server -- mosh-server relay ADDRESS PORT
```

where `ADDRESS` and `PORT` are the server's own, as `mosh-server` reported
them. Anything that gives a byte stream to `mosh-server relay` on the server
will do in its place.

## Troubleshooting

**It sits at "Connecting..." for a few seconds and then works, every time.**
UDP is blocked between you and the server, and mosh is finding its way
through ssh. `--relay=always` skips the wait. See
[When UDP is blocked](#when-udp-is-blocked).

**"Connection refused" on a forwarded port.**
The usual causes, in order:
the server is not this build (forwards need both ends);
the session has not finished connecting yet;
or the target itself refused, in which case the refusal is passed back.

**A forward stops when I close the terminal session.**
Forwards live exactly as long as the mosh session. Use `-N` for a session
that is nothing but forwards, and run it in the background if you like.

**The listening port is already in use.**
`mosh-client` (for `-L`, `-LU`) or `mosh-server` (for `-R`, `-RU`) exits with a
"bind" error instead of starting the session. Choose another port.

**Large UDP datagrams go missing on a bad network.**
That is expected of UDP; `--fragment-parity=always` will recover more of
them at the cost of extra traffic.

**Forwarded TCP, or a copy, is slower than the network could manage.**
The built-in TCP recovers from loss less cleverly than an operating system's
does. See [Status and limits](status.md) for what was measured.

**`mocp` says the mosh on the server is too old.**
Copying needs 1.4.0-pf.4 or later at both ends. Install it on the server too.

**There are `.name.mocp-part` files at the destination.**
They are copies that were cut off. Running the same `mocp` again finishes
them; otherwise they can be deleted.
