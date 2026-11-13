#!/usr/bin/env python3

"""A forwarding session with no terminal at either end, on any system.

Starts mosh-server and "mosh-client -N" on this machine and sends a TCP
connection through a forward.  Unlike forward-e2e.py it needs no
pseudo-terminal of its own, so it also runs under native Windows Python,
which is the point: it is how the Windows build of mosh-server is tested.

usage: headless-smoke.py MOSH_SERVER MOSH_CLIENT [ADDRESS [RELAY]]

ADDRESS is where the session itself runs: 127.0.0.1 by default, or ::1
to have mosh talk to itself over IPv6.

RELAY tests carrying the session over a stream when UDP cannot get
there (src/network/relay.h), with the remote relay run directly instead
of through ssh:
  always    by the relay from the start, and nothing by UDP
  blocked   the client is given a UDP port where nobody is, as if UDP
            were being dropped, and has to find its own way to the relay
  punched   as blocked; and then the two relays are to find a way straight
            to each other by UDP (src/network/punch.h), having asked a
            STUN server (one of our own, here) where they appear to be,
            and to let the stream go and carry on without it
  translated  as always, but the relay is told an address for the server
            that is not this machine's, as when addresses are translated
            on the way, and has to find the server for itself
  returned  as blocked; and then UDP works again, and the session is to go
            back to it by itself and let the stream go; and then UDP stops
            again, and the stream is to be brought back
"""

import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

server_path, client_path = sys.argv[1], sys.argv[2]
address = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
relay = sys.argv[4] if len(sys.argv) > 4 else None
windows = os.name == "nt"

# the service being forwarded to: it sends back whatever it gets
target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
target.bind(("127.0.0.1", 0))
target.listen(4)


def echo(conn):
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def accept_loop():
    while True:
        try:
            conn, _ = target.accept()
        except OSError:
            return
        threading.Thread(target=echo, args=(conn,), daemon=True).start()


threading.Thread(target=accept_loop, daemon=True).start()

probe = socket.socket()
probe.bind(("127.0.0.1", 0))
port = probe.getsockname()[1]
probe.close()
spec = "%d:127.0.0.1:%d" % (port, target.getsockname()[1])

# The session lasts as long as its command, so give it one that waits.
wait = ["cmd.exe", "/c", "pause"] if windows else ["/bin/sh", "-c", "while :; do sleep 1000; done"]

env = dict(os.environ, LC_ALL="C.UTF-8")
failures = []


def check(name, ok, detail=""):
    print("%-52s %s %s" % (name, "ok" if ok else "FAIL", detail), flush=True)
    if not ok:
        failures.append(name)


started = subprocess.run([server_path, "new", "-i", address, "-L", spec, "--"] + wait,
                         env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
match = re.search(r"MOSH CONNECT (\d+) (\S+)", started.stdout)
check("mosh-server starts and detaches", bool(match), "" if match else repr((started.stdout + started.stderr)[-400:]))
if not match:
    sys.exit(1)

client_env = dict(env, MOSH_KEY=match.group(2))
# (the relays ask servers on the Internet where they appear to be, unless told not to: not from a test)
client_env["MOSH_STUN"] = "none"
relay_log = None
client_port = match.group(1)
if relay:
    told = address
    if relay == "translated":
        told = "192.0.2.1"  # (an address set aside for examples: nobody's)
        client_env["SSH_CONNECTION"] = "192.0.2.2 50000 %s 22" % address  # as ssh would describe its arrival
    client_env["MOSH_RELAY_COMMAND"] = "\x1f".join([server_path, "relay", told, match.group(1)])
    client_env["MOSH_RELAY"] = "auto" if relay in ("blocked", "punched", "returned") else "always"
    if relay in ("punched", "returned"):
        handle, relay_log = tempfile.mkstemp(prefix="mosh-relay-log-")
        os.close(handle)
        client_env["MOSH_RELAY_LOG"] = relay_log
        # (the stream is let go after a minute unused: three seconds, for this test)
        client_env["MOSH_RELAY_STREAM_IDLE_MS"] = "3000"
    if relay == "punched":
        # A STUN server of our own: it answers a request with where the request came from.
        stun = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stun.bind(("127.0.0.1", 0))

        def answer():
            while True:
                try:
                    request, where = stun.recvfrom(2048)
                except OSError:
                    return
                if len(request) >= 20 and request[:2] == b"\x00\x01":
                    port = struct.pack("!H", where[1] ^ 0x2112)
                    ip = bytes(a ^ b for a, b in zip(socket.inet_aton(where[0]), b"\x21\x12\xa4\x42"))
                    stun.sendto(b"\x01\x01\x00\x0c" + request[4:20] + b"\x00\x20\x00\x08\x00\x01" + port + ip, where)

        threading.Thread(target=answer, daemon=True).start()
        client_env["MOSH_STUN"] = "127.0.0.1:%d" % stun.getsockname()[1]
    if relay == "returned":
        # Between the client and the server, a gate that this test shuts and opens:
        # UDP that does not get there, and then does.  It begins shut.
        gate_open = [False]
        relay_at = [None]
        gate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        gate.bind(("127.0.0.1", 0))
        onward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        onward.bind(("127.0.0.1", 0))
        server_at = ("127.0.0.1", int(match.group(1)))

        def inward():
            while True:
                try:
                    datagram, relay_at[0] = gate.recvfrom(65536)
                    if gate_open[0]:
                        onward.sendto(datagram, server_at)
                except OSError:
                    pass

        def outward():
            while True:
                try:
                    datagram, _ = onward.recvfrom(65536)
                    if gate_open[0] and relay_at[0]:
                        gate.sendto(datagram, relay_at[0])
                except OSError:
                    pass

        threading.Thread(target=inward, daemon=True).start()
        threading.Thread(target=outward, daemon=True).start()
        client_port = str(gate.getsockname()[1])
        # (on one machine the relays would find a way straight to each other, and the stream
        # would be let go for that reason and not for this one)
        client_env["MOSH_PUNCH"] = "never"
    if relay in ("blocked", "punched"):
        nobody = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM)
        nobody.bind((address, 0))
        client_port = str(nobody.getsockname()[1])  # bound and never read: datagrams sent here vanish

client = subprocess.Popen([client_path, "-N", "-L", spec, address, client_port],
                          env=client_env,
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
said = []
threading.Thread(target=lambda: said.extend(l.decode("latin-1") for l in client.stderr), daemon=True).start()
deadline = time.time() + 40
while time.time() < deadline and not any("connected; forwarding" in l for l in said) and client.poll() is None:
    time.sleep(0.1)
check("the session comes up", any("connected; forwarding" in l for l in said), "".join(said)[-300:].strip())

try:
    conn = socket.create_connection(("127.0.0.1", port), timeout=10)
    conn.settimeout(10)
    conn.sendall(b"through the forward")
    got = conn.recv(100)
    blob = bytes(range(256)) * 400
    threading.Thread(target=lambda: conn.sendall(blob), daemon=True).start()
    back = b""
    while len(back) < len(blob):
        chunk = conn.recv(65536)
        if not chunk:
            break
        back += chunk
    conn.close()
except OSError as error:
    got, back, blob = repr(error).encode(), b"", b"x"
check("a TCP connection is forwarded", got == b"through the forward", "" if got == b"through the forward" else got.decode("latin-1"))
check("%d bytes there and back" % len(blob), back == blob)

if relay:
    check("it came by the relay", any("through ssh" in l for l in said), "".join(said)[-200:].strip())

def logged():
    with open(relay_log) as f:
        return f.read()


def through_the_forward(data):
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=10)
        c.settimeout(10)
        c.sendall(data)
        back = c.recv(100)
        c.close()
        return back == data
    except OSError:
        return False


if relay == "punched":
    deadline = time.time() + 15
    while time.time() < deadline and logged().count("a way through is open") < 2:
        time.sleep(0.2)
    log = logged()
    check("each relay asks where it appears to be, and is told",
          "local: we may be reached at 127.0.0.1:" in log and "remote: we may be reached at 127.0.0.1:" in log)
    check("the two find a way through to each other", log.count("a way through is open") == 2, log if log.count("a way through is open") != 2 else "")
    # Now the stream is not needed, and after a while (three seconds, for this test) is let go.
    deadline = time.time() + 20
    while time.time() < deadline and "staying for the way through" not in logged():
        through_the_forward(b"keeping busy")
        time.sleep(0.3)
    check("the stream is let go, and the far relay stays", "staying for the way through" in logged())
    ok = all(through_the_forward(b"without the stream %d" % i) for i in range(5))
    time.sleep(4)
    ok = ok and through_the_forward(b"and still")
    log = logged()
    check("the session carries on by the way through alone", ok and log.count("starting the stream") == 1,
          "" if ok and log.count("starting the stream") == 1 else log)

if relay == "returned":
    check("it is the stream that carries it", logged().count("starting the stream") == 1)
    gate_open[0] = True
    closing = "the stream has not been needed for a while: closing it"
    deadline = time.time() + 20
    while time.time() < deadline and closing not in logged():
        through_the_forward(b"keeping busy")
        time.sleep(0.3)
    check("UDP works again, and the stream is let go", closing in logged(), "" if closing in logged() else logged())
    ok = all(through_the_forward(b"without the stream %d" % i) for i in range(5))
    time.sleep(4)
    ok = ok and through_the_forward(b"and still")
    log = logged()
    check("the session carries on by UDP alone", ok and log.count("starting the stream") == 1,
          "" if ok and log.count("starting the stream") == 1 else log)
    gate_open[0] = False
    deadline = time.time() + 30
    ok = False
    while time.time() < deadline and not (ok and logged().count("starting the stream") == 2):
        ok = through_the_forward(b"by the stream again")
    log = logged()
    check("UDP stops again, and the stream is brought back", ok and log.count("starting the stream") == 2,
          "" if ok and log.count("starting the stream") == 2 else log)

if relay and relay not in ("punched", "returned") and not windows:
    # The connection the relay rides on is lost (here, the remote relay is killed).
    # The session does not depend on it: another is made, and it carries on.
    relays = subprocess.run(["pgrep", "-f", "%s relay %s %s" % (server_path, told, match.group(1))],
                            capture_output=True, text=True).stdout.split()
    for pid in relays:
        os.kill(int(pid), 9)
    try:
        conn = socket.create_connection(("127.0.0.1", port), timeout=30)
        conn.settimeout(30)
        conn.sendall(b"after the relay was replaced")
        again = conn.recv(100)
        conn.close()
    except OSError as error:
        again = repr(error).encode()
    check("the relay is killed, and the session carries on", len(relays) == 1 and again == b"after the relay was replaced",
          "(%d relay(s) found) %s" % (len(relays), "" if again == b"after the relay was replaced" else again.decode("latin-1")))

client.terminate()
client.wait(20)

if relay and not windows:
    # nothing of the relay should outlive the client
    deadline = time.time() + 10
    pattern = "%s relay %s %s" % (server_path, address, match.group(1))
    left = ["?"]
    while time.time() < deadline and left:
        left = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True).stdout.split()
        time.sleep(0.2)
    check("the relay goes when the client does", not left, "(%d left)" % len(left))


def copy(to_server):
    """A file copied through a session of its own, as mocp does it (see src/network/filecopy.h)."""
    work = tempfile.mkdtemp(prefix="mosh-copy-")
    there = work.replace("\\", "/")  # (the programs take either on Windows; the copy speaks of paths with /)
    data = os.urandom(700000)
    with open(os.path.join(work, "sent.bin"), "wb") as f:
        f.write(data)
    send = ["@copy", "send", "-q", "--", there + "/sent.bin"]
    receive = ["@copy", "receive", "-q", "--", there + "/arrived.bin"]
    begun = subprocess.run([server_path, "new", "-i", address, "-X", "\x1f".join(receive if to_server else send), "--"] + wait,
                           env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    found = re.search(r"MOSH CONNECT (\d+) (\S+)", begun.stdout)
    if not found:
        return False, repr((begun.stdout + begun.stderr)[-300:])
    done = subprocess.run([client_path, "-X", "\x1f".join(send if to_server else receive), address, found.group(1)],
                          env=dict(env, MOSH_KEY=found.group(2)), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90)
    try:
        with open(os.path.join(work, "arrived.bin"), "rb") as f:
            same = f.read() == data
    except OSError:
        same = False
    shutil.rmtree(work, ignore_errors=True)
    return done.returncode == 0 and same, "" if done.returncode == 0 and same else "(exit %d) %s" % (done.returncode, done.stderr[-300:])


if relay == "punched":
    # the far relay is told when the client goes, and goes too, without waiting to wonder
    deadline = time.time() + 10
    while time.time() < deadline and "the other end has finished" not in logged():
        time.sleep(0.2)
    check("the far relay is told the client has gone", "the other end has finished" in logged())
if relay_log:
    os.remove(relay_log)

if not relay:
    check("a file is copied to the server", *copy(True))
    check("a file is copied from the server", *copy(False))

if windows:
    subprocess.run(["taskkill", "/F", "/IM", "mosh-server.exe"], capture_output=True)
else:
    pid = re.search(r"pid = (\d+)", started.stderr)
    if pid:
        try:
            os.kill(int(pid.group(1)), 15)
        except OSError:
            pass
sys.exit(1 if failures else 0)
