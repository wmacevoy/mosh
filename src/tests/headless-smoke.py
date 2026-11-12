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
  translated  as always, but the relay is told an address for the server
            that is not this machine's, as when addresses are translated
            on the way, and has to find the server for itself
"""

import os
import re
import socket
import subprocess
import sys
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
client_port = match.group(1)
if relay:
    told = address
    if relay == "translated":
        told = "192.0.2.1"  # (an address set aside for examples: nobody's)
        client_env["SSH_CONNECTION"] = "192.0.2.2 50000 %s 22" % address  # as ssh would describe its arrival
    client_env["MOSH_RELAY_COMMAND"] = "\x1f".join([server_path, "relay", told, match.group(1)])
    client_env["MOSH_RELAY"] = "auto" if relay == "blocked" else "always"
    if relay == "blocked":
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

if relay and not windows:
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
