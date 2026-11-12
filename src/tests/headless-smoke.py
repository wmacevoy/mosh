#!/usr/bin/env python3

"""A forwarding session with no terminal at either end, on any system.

Starts mosh-server and "mosh-client -N" on this machine and sends a TCP
connection through a forward.  Unlike forward-e2e.py it needs no
pseudo-terminal of its own, so it also runs under native Windows Python,
which is the point: it is how the Windows build of mosh-server is tested.

usage: headless-smoke.py MOSH_SERVER MOSH_CLIENT [ADDRESS]

ADDRESS is where the session itself runs: 127.0.0.1 by default, or ::1
to have mosh talk to itself over IPv6.
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

client = subprocess.Popen([client_path, "-N", "-L", spec, address, match.group(1)],
                          env=dict(env, MOSH_KEY=match.group(2)),
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

client.terminate()
client.wait(20)
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
