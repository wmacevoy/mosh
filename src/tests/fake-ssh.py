#!/usr/bin/env python3

"""Stands in for ssh in wrapper.test: "logs in" to this machine.

It takes the arguments the mosh command gives ssh, and does with them
what ssh would as far as mosh can tell:

  * if it is given a ProxyCommand, it runs it (that is how mosh learns
    the server's address) and checks that bytes pass through it both
    ways to the port it was told to reach;
  * it runs the command with a shell, with SSH_CONNECTION set as sshd
    would set it, and its own output as the command's.

FAKE_SSH_LOG, if set, names a file to which each use is added: the
arguments, one use to a line.
"""

import os
import socket
import subprocess
import sys

args = sys.argv[1:]
options, proxy, host, command = [], None, None, None
i = 0
while i < len(args):
    a = args[i]
    if a in ("-o", "-S", "-p", "-l", "-i", "-F"):
        if a == "-o" and args[i + 1].startswith("ProxyCommand="):
            proxy = args[i + 1][len("ProxyCommand="):]
        options.append(a + " " + args[i + 1])
        i += 2
    elif a.startswith("-") and host is None:
        options.append(a)
        i += 1
    elif host is None:
        host = a
        i += 1
    else:
        rest = args[i + 1:] if a == "--" else args[i:]
        command = " ".join(rest)
        break

log = os.environ.get("FAKE_SSH_LOG")
if log:
    with open(log, "a") as f:
        f.write(repr(args) + "\n")

if host is None or command is None:
    sys.stderr.write("fake-ssh: expected a host and a command\n")
    sys.exit(255)

if proxy is not None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(20)
    line = proxy.replace("%h", "localhost").replace("%p", str(listener.getsockname()[1]))
    # (ssh runs it with the user's shell; its standard error is ssh's own)
    through = subprocess.Popen([os.environ.get("SHELL", "/bin/sh"), "-c", line], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        conn, _ = listener.accept()
        conn.settimeout(20)
        through.stdin.write(b"SSH-2.0-there\r\n")
        through.stdin.flush()
        there = conn.recv(100)
        conn.sendall(b"SSH-2.0-back\r\n")
        back = through.stdout.read(14)
        if there != b"SSH-2.0-there\r\n" or back != b"SSH-2.0-back\r\n":
            raise OSError("%r %r" % (there, back))
        through.stdin.close()  # our end is finished with...
        if conn.recv(100) != b"":
            raise OSError("no end of stream")
        conn.close()  # ...and so is the other
        if through.wait(20) != 0:
            raise OSError("exit status %d" % through.returncode)
    except (OSError, subprocess.TimeoutExpired) as e:
        through.kill()
        sys.stderr.write("fake-ssh: the proxy command did not carry bytes to the port: %s\n" % e)
        sys.exit(255)

env = dict(os.environ, SSH_CONNECTION="127.0.0.1 54321 127.0.0.1 22")
# (-n: nothing for the command to read.  Otherwise it reads what we are given, as the relay does.)
sys.exit(subprocess.call(["/bin/sh", "-c", command], env=env, stdin=subprocess.DEVNULL if "-n" in options else None))
