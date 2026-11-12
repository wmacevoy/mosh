#!/usr/bin/env python3

"""End-to-end test of port forwarding, run by forward-e2e.test.

Starts a real mosh-server and mosh-client on this machine with one
forward of each kind, and sends traffic through each of them:

    -L   TCP, the client listens       -LU  UDP, the client listens
    -R   TCP, the server listens       -RU  UDP, the server listens

usage: forward-e2e.py MOSH_SERVER MOSH_CLIENT
"""

import fcntl
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time

SKIP = 77
server_path, client_path = sys.argv[1], sys.argv[2]

# Nothing here should take long.  Don't hang the test suite if something does.
signal.alarm(180)


def free_port(kind):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def blob(n, seed):
    return bytes((i * 7 + seed + (i >> 8)) & 0xFF for i in range(n))


# ---- the services being forwarded to: each sends back whatever it gets

tcp_target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_target.bind(("127.0.0.1", 0))
tcp_target.listen(16)

udp_target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_target.bind(("127.0.0.1", 0))


def tcp_echo(conn):
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


def tcp_accept_loop():
    while True:
        try:
            conn, _ = tcp_target.accept()
        except OSError:
            return
        threading.Thread(target=tcp_echo, args=(conn,), daemon=True).start()


def udp_echo_loop():
    while True:
        try:
            data, addr = udp_target.recvfrom(65536)
            udp_target.sendto(data, addr)
        except OSError:
            return


threading.Thread(target=tcp_accept_loop, daemon=True).start()
threading.Thread(target=udp_echo_loop, daemon=True).start()

tcp_to = "127.0.0.1:%d" % tcp_target.getsockname()[1]
udp_to = "127.0.0.1:%d" % udp_target.getsockname()[1]
ports = {
    "-L": free_port(socket.SOCK_STREAM),
    "-R": free_port(socket.SOCK_STREAM),
    "-LU": free_port(socket.SOCK_DGRAM),
    "-RU": free_port(socket.SOCK_DGRAM),
}
forwards = []
for option, port in ports.items():
    forwards += [option, "%d:%s" % (port, udp_to if option.endswith("U") else tcp_to)]

# ---- start the session

env = dict(os.environ, TERM="xterm")
started = subprocess.run(
    [server_path, "new", "-i", "127.0.0.1"] + forwards + ["--", "/bin/sh", "-c", "echo SHELL-READY; cat"],
    env=env,
    stdin=subprocess.DEVNULL,
    capture_output=True,
    text=True,
    timeout=30,
)
match = re.search(r"MOSH CONNECT (\d+) (\S+)", started.stdout)
if not match:
    sys.stderr.write("mosh-server did not start:\n" + started.stdout + started.stderr)
    sys.exit(1)
mosh_port, key = match.group(1), match.group(2)
pid_match = re.search(r"pid = (\d+)", started.stderr)
server_pid = int(pid_match.group(1)) if pid_match else None

client_pid, terminal = pty.fork()
if client_pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    os.execve(client_path, [client_path] + forwards + ["127.0.0.1", mosh_port], dict(env, MOSH_KEY=key))

screen = bytearray()


def read_terminal():
    while True:
        try:
            ready, _, _ = select.select([terminal], [], [], 0.1)
            if ready:
                screen.extend(os.read(terminal, 65536))
        except OSError:
            return


threading.Thread(target=read_terminal, daemon=True).start()


def on_screen(text, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline and text not in screen:
        time.sleep(0.05)
    return text in screen


failures = []


def check(name, ok):
    print("%-58s %s" % (name, "ok" if ok else "FAIL"), flush=True)
    if not ok:
        failures.append(name)


def finish():
    try:
        os.write(terminal, b"\x1e.")  # mosh's quit sequence
        time.sleep(0.5)
    except OSError:
        pass
    for pid in (client_pid, server_pid):
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    sys.exit(1 if failures else 0)


check("terminal session starts", on_screen(b"SHELL-READY", 30))
if failures:
    sys.stderr.write(bytes(screen).decode("latin-1")[-2000:] + "\n")
    finish()

# ---- TCP


def tcp_round_trip(port, data):
    """Send data and close our side; return everything that comes back."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=30)
    conn.settimeout(60)
    received = bytearray()

    def reader():
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
        except OSError:
            pass

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    conn.sendall(data)
    conn.shutdown(socket.SHUT_WR)
    thread.join(60)
    conn.close()
    return bytes(received)


def tcp_works(port):
    # The two ends agree to forward in their first exchange; until then, connections are refused.
    for attempt in range(100):
        try:
            if tcp_round_trip(port, b"hello") == b"hello":
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


for option in ("-L", "-R"):
    check("%-3s  TCP connection is forwarded" % option, tcp_works(ports[option]))
    data = blob(300000, len(option))
    try:
        check("%-3s  300000 bytes there and back, then end of stream" % option, tcp_round_trip(ports[option], data) == data)
    except OSError as e:
        check("%-3s  300000 bytes there and back (%s)" % (option, e), False)

# ---- UDP


def udp_round_trip(port, data, tries):
    """UDP may lose a datagram, so allow a few attempts."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    try:
        for attempt in range(tries):
            try:
                s.sendto(data, ("127.0.0.1", port))
                while True:
                    if s.recvfrom(65536)[0] == data:
                        return True
            except OSError:
                pass
        return False
    finally:
        s.close()


for option in ("-LU", "-RU"):
    check("%-3s  UDP datagram is forwarded, and the reply returned" % option, udp_round_trip(ports[option], b"ping", 40))
    for size in (1200, 5000, 9000):  # (some systems won't send a much larger datagram at all)
        check("%-3s  %5d-byte datagram (%s)" % (option, size, "whole" if size <= 1200 else "in fragments"),
              udp_round_trip(ports[option], blob(size, size), 10))

# ---- and the terminal has not suffered

os.write(terminal, b"still-here\r")
check("terminal still works afterwards", on_screen(b"still-here", 15))

finish()
