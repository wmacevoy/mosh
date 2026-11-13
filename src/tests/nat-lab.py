#!/usr/bin/env python3
"""Hole punching through real NATs (Linux's own), in network namespaces.

Not part of "make check": it needs to be root in a network namespace of
its own, and the nft program.  As root:

    unshare -m -n python3 nat-lab.py DIRECTORY-OF-THE-PROGRAMS $(command -v nft) easy

or without being root, where the system allows it: unshare -Urnm ...
CI runs it each way (the "nat" job).

   client 192.168.1.2 -- natA 203.0.113.11 --+
                                             +-- "the Internet" 203.0.113.1 (a meetup)
   server 192.168.2.2 -- natB 203.0.113.12 --+

usage: nat-lab.py BINDIR NFT [easy|hard|passed|moved|room]
  easy   both NATs keep the port number (as most home routers do)
  hard   the server's NAT picks a new port for every destination: no way through; the stream has to do
  passed hard, but with the meetup's key, so that it passes the session on by UDP
  moved  easy, and then the client's NAT changes its outside address
  room   the server is behind the client's own NAT (192.168.3.2): two machines in one room

Everything it starts is stopped by process id, or by being a program from BINDIR:
never by name (there may be other mosh sessions on this machine, and they are not ours).
"""
import os, re, signal, socket, struct, subprocess, sys, tempfile, threading, time
bindir, nft, kind = os.path.realpath(sys.argv[1]), sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "easy")

def sh(cmd, **kw):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)
    if r.returncode:
        sys.exit("failed: %s\n%s%s" % (cmd, r.stdout, r.stderr))
    return r.stdout

def stop_ours():
    """Stops the programs from BINDIR that are still running (by where they are, not what they are called)."""
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                if os.path.realpath(os.readlink("/proc/%s/exe" % pid)).startswith(bindir + "/"):
                    os.kill(int(pid), signal.SIGTERM)
            except OSError:
                pass

sh("mount -t tmpfs none /run && mkdir -p /run/netns")
sh("ip link set lo up && ip link add br0 type bridge && ip addr add 203.0.113.1/24 dev br0 && ip link set br0 up")
for name, outside, lan in (("A", "203.0.113.11", "192.168.1"), ("B", "203.0.113.12", "192.168.2")):
    nat, host = "nat" + name, ("client" if name == "A" else "server")
    sh("ip netns add %s && ip netns add %s" % (nat, host))
    sh("ip link add up%s type veth peer name eth0 netns %s && ip link set up%s master br0 up" % (name, nat, name))
    sh("ip link add lan%s netns %s type veth peer name eth0 netns %s" % (name, nat, host))
    sh("ip -n %s addr add %s/24 dev eth0 && ip -n %s link set eth0 up && ip -n %s link set lo up" % (nat, outside, nat, nat))
    sh("ip -n %s addr add %s.1/24 dev lan%s && ip -n %s link set lan%s up" % (nat, lan, name, nat, name))
    sh("ip -n %s addr add %s.2/24 dev eth0 && ip -n %s link set eth0 up && ip -n %s link set lo up" % (host, lan, host, host))
    sh("ip -n %s route add default via %s.1" % (host, lan))
    sh("ip netns exec %s sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'" % nat)
    how = "masquerade random,fully-random" if (kind in ("hard", "passed") and name == "B") else "masquerade"
    sh("ip netns exec %s %s add table ip nat" % (nat, nft))
    sh("ip netns exec %s %s 'add chain ip nat post { type nat hook postrouting priority 100 ; }'" % (nat, nft))
    sh("ip netns exec %s %s add rule ip nat post oifname eth0 %s" % (nat, nft, how))
    # and nothing comes in that was not asked for
    sh("ip netns exec %s %s add table ip filter" % (nat, nft))
    sh("ip netns exec %s %s 'add chain ip filter through { type filter hook forward priority 0 ; policy drop ; }'" % (nat, nft))
    sh("ip netns exec %s %s add rule ip filter through ct state established,related accept" % (nat, nft))
    sh("ip netns exec %s %s add rule ip filter through iifname lan%s accept" % (nat, nft, name))
    # ...nor to the router itself, as any router's firewall has it
    sh("ip netns exec %s %s 'add chain ip filter inward { type filter hook input priority 0 ; policy drop ; }'" % (nat, nft))
    sh("ip netns exec %s %s add rule ip filter inward ct state established,related accept" % (nat, nft))
    sh("ip netns exec %s %s add rule ip filter inward iifname != eth0 accept" % (nat, nft))
    sh("ip netns exec %s %s add rule ip filter inward icmp type echo-request accept" % (nat, nft))

where, server_ip = "server", "192.168.2.2"
if kind == "room":
    # another machine on the client's side of its NAT; the NAT's outside address is no way to it
    sh("ip netns add roommate && ip link add lanC netns natA type veth peer name eth0 netns roommate")
    sh("ip -n natA addr add 192.168.3.1/24 dev lanC && ip -n natA link set lanC up")
    sh("ip -n roommate addr add 192.168.3.2/24 dev eth0 && ip -n roommate link set eth0 up && ip -n roommate link set lo up")
    sh("ip -n roommate route add default via 192.168.3.1")
    sh("ip netns exec natA %s add rule ip filter through iifname lanC accept" % nft)
    where, server_ip = "roommate", "192.168.3.2"

ok = subprocess.run("ip netns exec client ping -c1 -W2 203.0.113.1 >/dev/null && ! ip netns exec client ping -c1 -W1 192.168.2.2 >/dev/null 2>&1", shell=True).returncode == 0
print("the lab: each side reaches the Internet and not the other".ljust(66), "ok" if ok else "FAIL", flush=True)
if not ok:
    sys.exit(1)

# the Internet's meetup: "mosh-server meetup", which says where an asker appears to be; with a key it
# answers only those who have it, and for them will also pass datagrams on
meetup_key = subprocess.run([bindir + "/mosh-server", "meetup-key"], capture_output=True, text=True).stdout.strip()
keyed = kind in ("passed", "room")
meetup = subprocess.Popen([bindir + "/mosh-server", "meetup", "3478"], env=dict(os.environ, **({"MOSH_MEETUP_KEY": meetup_key} if keyed else {})))
time.sleep(0.3)

work = tempfile.mkdtemp(prefix="natlab-")
log = work + "/relay.log"; open(log, "w").close()
env = dict(os.environ, LC_ALL="C.UTF-8", MOSH_RELAY_LOG=log, HOME=work)
echo = "import socket,threading\ns=socket.socket();s.setsockopt(1,2,1);s.bind(('127.0.0.1',7777));s.listen(5)\ndef e(c):\n while True:\n  d=c.recv(65536)\n  if not d: break\n  c.sendall(d)\nwhile True:\n c,_=s.accept();threading.Thread(target=e,args=(c,),daemon=True).start()\n"
target = subprocess.Popen(["ip", "netns", "exec", where, "python3", "-c", echo])
time.sleep(0.5)
out = subprocess.run(["ip", "netns", "exec", where, bindir + "/mosh-server", "new", "-i", server_ip, "-L", "8888:127.0.0.1:7777", "--",
                      "sh", "-c", "while :; do sleep 1000; done"], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True).stdout
port, key = re.search(r"MOSH CONNECT (\d+) (\S+)", out).groups()

# The client is told an address it cannot reach (as when ssh came by a jump host), so it turns to the relay:
# which here is started in the server's namespace directly, where ssh would start it.
cenv = dict(env, MOSH_KEY=key, MOSH_RELAY="auto", MOSH_MEETUP="203.0.113.1:3478", MOSH_RELAY_STREAM_IDLE_MS="4000",
            **({"MOSH_MEETUP_KEY": meetup_key} if keyed else {}),
            MOSH_RELAY_COMMAND="\x1f".join(["ip", "netns", "exec", where, bindir + "/mosh-server", "relay", server_ip, port]))
client = subprocess.Popen(["ip", "netns", "exec", "client", bindir + "/mosh-client", "-N", "-L", "8888:127.0.0.1:7777", "198.51.100.9", port],
                          env=cenv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
said = []
threading.Thread(target=lambda: said.extend(l.decode() for l in client.stderr), daemon=True).start()

probe = "import socket,sys\ntry:\n c=socket.create_connection(('127.0.0.1',8888),timeout=6);c.settimeout(6);c.sendall(b'x'*int(sys.argv[1]));n=0\n while n<int(sys.argv[1]):\n  d=c.recv(65536)\n  if not d: break\n  n+=len(d)\n sys.exit(0 if n==int(sys.argv[1]) else 1)\nexcept OSError: sys.exit(1)\n"
def works(size=1000):
    return subprocess.run(["ip", "netns", "exec", "client", "python3", "-c", probe, str(size)]).returncode == 0
def logged(): return open(log).read()
failures = []
def check(name, good, detail=""):
    print(name.ljust(66), "ok" if good else "FAIL", detail if not good else "", flush=True)
    if not good:
        failures.append(name)
def wait(what, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline and not what(): time.sleep(0.25)
    return what()

try:
    check("the session comes up (through the stream, there being no other way)", wait(lambda: any("connected" in l for l in said), 20) and works())
    there = "203.0.113.11" if kind == "room" else "203.0.113.12"
    told = wait(lambda: "local: we may be reached at 203.0.113.11:" in logged() and ("remote: we may be reached at %s:" % there) in logged(), 10)
    check("each end learns its outside address from the meetup", told, logged())

    if kind == "passed":
        check("a way is found by UDP, through the meetup, having its key", wait(lambda: logged().count("a way through is open, to the meetup at 203.0.113.1:3478") >= 2, 15), logged())
        wait(lambda: (works(), "staying for the way through" in logged())[1], 25)
        check("the stream is let go; the far relay stays", "staying for the way through" in logged(), logged())
        starts = logged().count("starting the stream")
        good = all(works() for i in range(5)) and works(300000)
        time.sleep(5)
        check("the session works by UDP alone, passed on by the meetup", good and works() and logged().count("starting the stream") == starts, logged())
        # and nobody without the key is answered at all
        asker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); asker.settimeout(1.5)
        asker.sendto(b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12), ("203.0.113.1", 3478))
        try:
            asker.recvfrom(100); silent = False
        except socket.timeout:
            silent = True
        check("the meetup says nothing to someone without the key", silent)
    elif kind == "hard":
        time.sleep(12)
        check("no way through is found (the server's NAT gives it away to nobody)", "a way through is open" not in logged(), logged())
        check("and the session goes on working, by the stream", all(works() for i in range(3)) and works(200000))
    else:
        check("a way through is found", wait(lambda: logged().count("a way through is open") >= 2, 15), logged())
        if kind == "room":
            check("and it is the way across the room, not out and back", "local: a way through is open, to 192.168.3.2:" in logged(), logged())
        wait(lambda: (works(), "staying for the way through" in logged())[1], 25)
        check("the stream is let go; the far relay stays", "staying for the way through" in logged(), logged())
        starts = logged().count("starting the stream")
        good = all(works() for i in range(5)) and works(300000)
        time.sleep(5)
        check("the session works by UDP alone, straight through the NATs", good and works() and logged().count("starting the stream") == starts, logged())
        if kind == "moved":
            # the client's NAT gets a new outside address, and forgets what it knew
            sh("ip -n natA addr del 203.0.113.11/24 dev eth0 && ip -n natA addr add 203.0.113.21/24 dev eth0")
            sh("ip netns exec natA %s flush table ip nat; ip netns exec natA %s add rule ip nat post oifname eth0 masquerade" % (nft, nft))
            began = time.time()
            back = wait(works, 40)
            check("after the client's address changes, the session comes back (%.0f s)" % (time.time() - began), back, logged())
            again = wait(lambda: "to 203.0.113.21:" in logged(), 30)
            check("and a way through is found again, from the new address", again, logged())
            wait(lambda: (works(), logged().count("staying for the way through") >= 2)[1], 25)
            check("and the stream is let go again", logged().count("staying for the way through") >= 2 and works(), logged())

    client.send_signal(signal.SIGINT)
    try:
        client.wait(10)
    except subprocess.TimeoutExpired:
        client.kill()
    check("the far relay is told when the client goes", kind == "hard" or wait(lambda: "the other end has finished" in logged(), 8), logged())
finally:
    target.kill()
    meetup.kill()
    if client.poll() is None:
        client.kill()
    stop_ours()
if failures:
    print("--- the relays' account of it")
    print(logged())
sys.exit(1 if failures else 0)
