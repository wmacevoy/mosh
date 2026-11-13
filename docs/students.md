---
title: Start here (students)
---

[Overview](index.md) · [Start here](students.md) · [Using it](usage.md) · [How it works](design.md) · [Status and limits](status.md)

# A connection that does not drop

*For students who work on a remote machine. Ten minutes from nothing to
working. No administrator needed.*

This is an unofficial, experimental build of [mosh](https://mosh.org). It has
not been reviewed by the mosh project or audited for security. It is used
here because it does things the standard tools do not; see
[Status and limits](status.md) for exactly what has and has not been tested.

## What this is

You do your work on another machine: the course server, a lab machine, a
cloud instance. The usual way in is `ssh`, and ssh is a phone call. Close the
laptop, walk to the next building, lose Wi-Fi for ten seconds, and the call
drops. Whatever was running in that terminal goes with it.

**mosh** is the same thing without the dropped call. It keeps your session
alive on the server and reconnects by itself, from wherever you are, as soon
as there is a network again. You open the laptop and your terminal is exactly
where you left it.

This build adds what you need around that:

| You want to... | You type |
|---|---|
| work in a terminal on the server | `mosh you@server` |
| see a web page that runs on the server, in your own browser | `mosh -L 8080:localhost:8080 you@server` |
| copy files to or from the server | `mocp -r you@server:project/out .` |
| keep a folder on your laptop up to date with one on the server | `mocp --auto -r you@server:project/out .` |

## Why you want it

- **Your connection froze and took your work with it.** With mosh it waits
  and comes back. Nothing to restart.
- **"The site runs on the server. How do I look at it?"** `-L` makes a port
  on the server appear on your laptop. Open `http://localhost:8080`.
- **"How do I get my results onto my laptop?"** `mocp` copies them, and
  `mocp --auto` keeps copying as they change. A copy that is interrupted
  carries on where it stopped.
- **"It doesn't work on campus Wi-Fi."** Some networks block what mosh
  normally uses. This build notices within three seconds and goes through
  ssh instead, then switches back when it can. You do nothing.

## Set it up

You need two things you may already have: a terminal, and an account on the
server that you can reach with `ssh you@server`.

### 1. Make ssh work without a password

mosh starts by logging in with ssh, and some of its features log in again
quietly in the background, where nobody can type a password. So set up a key
once. On **your laptop**:

```
ssh-keygen -t ed25519          # press Enter at each question
ssh-copy-id you@server         # type your password this one last time
ssh you@server                 # should now log you in without asking
```

If `ssh-copy-id` is missing (Windows), ask your instructor, or see the note
for Windows below. Type `exit` to come back to your laptop.

### 2. Install on your laptop

Linux or macOS, in a terminal:

```
curl -fsSL https://raw.githubusercontent.com/wmacevoy/mosh/master/scripts/install.sh | sh
```

It installs into `~/.local/bin` in your own home directory and tells you if
that is not yet on your `PATH` (and what line to add if so). It needs nothing
else: no Homebrew, no Perl, no administrator.

**Windows.** Use WSL (the Linux that comes with Windows: run `wsl --install`
in PowerShell once, then open "Ubuntu"), and follow the Linux steps inside
it. That is the Linux build, which is the well-tested one. There is also a
native Windows zip on the
[releases page](https://github.com/wmacevoy/mosh/releases); it is newer and
much less tested.

### 3. Install on the server

The same line, run on the server. From your laptop:

```
ssh you@server 'curl -fsSL https://raw.githubusercontent.com/wmacevoy/mosh/master/scripts/install.sh | sh'
```

Both ends need this build. If the server only has the standard mosh, the
terminal still works but the extras do not.

### 4. Connect

```
mosh you@server
```

You are in a terminal on the server. Now try the point of it: close the
laptop lid, wait a minute, open it. The terminal is still there. Turn Wi-Fi
off and on. Still there.

To leave, type `exit`. If it ever gets stuck, press `Ctrl-^` and then `.`
(a full stop).

### 5. Recommended: tmux

mosh keeps your *connection*. `tmux` keeps your *work*, even if you close
the terminal window by accident or your laptop runs out of battery:

```
mosh you@server -- tmux new -A -s main
```

That joins a session called `main`, or makes it. Three keys are enough to
start: `Ctrl-b c` new window, `Ctrl-b n` next window, `Ctrl-b d` detach
(leave everything running and go). Run the same command later, from
anywhere, and you are back in it.

## The three things you will actually use

### See a web page that runs on the server

Your program on the server listens on port 8080. Start mosh with a forward:

```
mosh -L 8080:localhost:8080 you@server
```

and open `http://localhost:8080` in the browser on your laptop. The forward
lasts as long as the mosh session, and survives everything the session
survives. Use another number on the left if 8080 is busy on your laptop:
`-L 9000:localhost:8080`, then `http://localhost:9000`.

### Copy files

```
mocp notes.pdf you@server:docs/          # to the server
mocp -r you@server:project/out .         # a whole folder, from the server
mocp 'you@server:logs/*.txt' logs/       # by pattern (keep the quotes)
```

It is `scp` with mosh's patience. If the network goes away in the middle,
the copy waits and then continues. If you kill it, running the same command
again picks up where it stopped. A file never appears half-written.

### Keep a folder up to date

```
mocp --auto -r you@server:project/out ./out
```

Leave this running in its own terminal. Every two seconds it looks at
`project/out` on the server and brings `./out` on your laptop into line: new
files, changed files. It goes one way (server to laptop, here). Press
`Ctrl-C` to stop it. Add `--delete` if files removed on the server should be
removed on your laptop too.

Point it at the folder of results, not at a whole project with thousands of
dependency files in it: it copies everything it is pointed at.

## When it does not work

**`ssh you@server` asks for a password.** Go back to step 1. Until this
works without asking, the automatic fallback and `mocp` will not.

**`mosh: Did not find mosh server startup message`** or
**`mosh-server: command not found`.** This build is not installed on the
server. Do step 3.

**`mocp` says the mosh on the server is too old.** Same: step 3, to get the
current release there.

**It sits at "Connecting..." for a few seconds, then works, every time.**
Your network blocks UDP, and mosh is finding its way through ssh. It is
working as intended. `mosh --relay=always you@server` skips the wait.

**"Connection refused" when you open `localhost:8080`.** Either nothing is
listening on that port on the server yet (start your program), or the
session has not finished connecting (wait a second and reload).

**There are files called `.something.mocp-part`.** A copy was interrupted.
Run the same `mocp` command again and it finishes them; or delete them.

## Your own relay, on a free cloud machine

*Optional. You need this only if the machine you want to reach has no public
address: a desktop at home, a lab machine behind a firewall.*

mosh can already reach a server that has a public address. A machine behind
a home router is different: nothing outside can start a conversation with
it. The fix is a tiny machine in the cloud that both ends *can* reach, which
introduces them to each other. After the introduction they usually talk
directly, and the cloud machine carries nothing. When they cannot (some
networks do not allow it), it passes their traffic along instead.

The smallest instance any cloud offers is enough. These steps are for AWS.
**They have not been run by the author on AWS**; they are the standard
steps, and the mosh parts are tested in a lab with real NAT routers. Check
what AWS's free tier currently includes for your account before you start:
it has changed over the years, and a public IP address is not always free.

### 1. Launch the machine

In the AWS console, go to **EC2**, then **Launch instance**:

- **Name:** `mosh-relay`
- **Image:** Ubuntu Server 24.04 LTS
- **Instance type:** whichever is marked *Free tier eligible* (a `micro`)
- **Key pair:** create one, download the `.pem` file, and keep it safe
- **Network settings**, **Edit**, and allow:

  | Type | Protocol | Port | Source | For |
  |---|---|---|---|---|
  | SSH | TCP | 22 | Anywhere | logging in |
  | Custom UDP | UDP | 60000 | Anywhere | the relay |

Launch it, and note its **Public IPv4 address**. Below it is written
`RELAY`.

On your laptop, let ssh use the key file:

```
chmod 600 ~/Downloads/mosh-relay.pem
ssh -i ~/Downloads/mosh-relay.pem ubuntu@RELAY
```

### 2. Install and start the relay

On the relay (you are logged in as `ubuntu`):

```
curl -fsSL https://raw.githubusercontent.com/wmacevoy/mosh/master/scripts/install.sh | sh

mkdir -p ~/.config/mosh
echo "MOSH_STUN_KEY=$(~/.local/bin/mosh-server stun-key)" > ~/.config/mosh/stun.env
chmod 600 ~/.config/mosh/stun.env
cat ~/.config/mosh/stun.env        # this is your key: copy what follows the =
```

The key is what makes the relay yours. Without it nobody gets an answer.

Have it start by itself, now and after every reboot:

```
sudo tee /etc/systemd/system/mosh-relay.service >/dev/null <<'EOF'
[Unit]
Description=Private STUN server and UDP relay for mosh
After=network-online.target
Wants=network-online.target

[Service]
User=ubuntu
EnvironmentFile=/home/ubuntu/.config/mosh/stun.env
ExecStart=/home/ubuntu/.local/bin/mosh-server stun 60000
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now mosh-relay
systemctl status mosh-relay --no-pager     # should say: active (running)
```

### 3. Tell your laptop about it

Add two lines to the end of `~/.bashrc` (or `~/.zshrc` on a Mac), with your
relay's address and your key, then open a new terminal:

```
export MOSH_STUN=RELAY:60000
export MOSH_STUN_KEY=paste-your-key-here
```

From now on, whenever mosh cannot reach a server directly, it asks your
relay for help instead of a public service.

### 4. Reach a machine at home through it

The machine at home has to hold a door open, because nothing can knock from
outside. On the **home machine** (install this build there first, step 3
above, and put your laptop's ssh key on it):

```
ssh -i mosh-relay.pem -N -R 2222:localhost:22 ubuntu@RELAY
```

Leave that running (in `tmux`, or as a service). It makes port 2222 on the
relay lead to the home machine's ssh.

On your **laptop**, add to `~/.ssh/config`:

```
Host relay
    HostName RELAY
    User ubuntu
    IdentityFile ~/Downloads/mosh-relay.pem

Host home
    HostName localhost
    Port 2222
    User your-name-on-the-home-machine
    ProxyJump relay
```

Check that `ssh home` logs you in. Then:

```
mosh --experimental-remote-ip=remote home
```

For the first few seconds the session travels through the relay by ssh.
Then the two ends find each other and it moves to a direct connection, or
to UDP passed along by your relay if a direct one is not possible. `mocp`
and `-L` work the same way: `mocp --experimental-remote-ip=remote ...`.

When you are finished with the relay for good, **terminate the instance** in
the EC2 console so that it cannot cost you anything.

## How it works

**ssh is a phone call; mosh is a pair of notebooks.** ssh sends every
keystroke and every character of output in order over one connection (TCP).
If the connection breaks, the conversation is over. mosh keeps a copy of
the screen at each end and sends small sealed notes (UDP datagrams) that
say "here is what changed". Notes can be lost, arrive late, or come from a
new address, and it does not matter: the next note brings the other end up
to date. That is why it survives sleep and changing networks.

**Forwarding and copying ride in the same notes.** A web page or a file
needs every byte, in order, so this build runs a small reliable channel
inside the session for them. When the network disappears, that channel
waits. Nothing times out at mosh's end.

**Four ways to get through, best first.** mosh tries them without being
asked, and keeps trying the better ones:

1. **Straight there by UDP.** The normal case, when the server has a public
   address.
2. **Straight there through the routers ("hole punching").** A home router
   lets traffic in only as an answer to something sent out. If both ends
   send to each other at the same moment, each router believes it is seeing
   an answer, and lets the other in. To aim, each end first asks a server
   outside "what address do I appear to have?" (that question is called
   STUN).
3. **By UDP, passed along by your relay.** Some routers cannot be fooled
   that way. Then both ends send to your relay, which hands each one's
   traffic to the other. It cannot read it: mosh seals everything between
   its two ends.
4. **Inside an ssh connection.** When UDP is blocked completely. It works,
   but it is the phone call again, so mosh leaves it as soon as it can.

**Who can read what.** Everything mosh sends is encrypted and authenticated
between your laptop and the server with a key that was exchanged over ssh.
A relay, a STUN server and the networks in between see that two addresses
are talking, and nothing of what they say.

## Batteries included: the editor

If you would rather have an editor than a terminal, there is an extension
for [VSCodium](https://vscodium.com) that does all of this for you:
[remote-mosh](https://github.com/wmacevoy/remote-mosh). You give it
`you@server`; it installs mosh at both ends, opens the server's files in
the editor on your laptop, survives the network the same way, and can keep
folders you tick copied to your laptop. It is earlier in its life than mosh
itself. Ask your instructor whether it is ready for your course.

## More

- [Using it](usage.md): every option.
- [How it works](design.md): the full story, for the curious.
- [Status and limits](status.md): what is tested, and what is not.
