#!/usr/bin/env python3
"""poll-state.py - poll the pad's UIC state (svc 4/0x05) and log every change.

Waits for the pad to be awake, then asks for its state every 2 s and prints a
timeline, reading the replies off the wire (the streamer owns 50023). Use it while
performing a physical action on the pad - e.g. tapping a profile tile - so the effect
of that action on the pad's state is measured rather than guessed.
"""
import importlib.util, os, socket, subprocess, sys, time

ROOT = "/home/kali/Wiiu"; IFACE = "WiiUAP"; PAD = "192.168.1.11"; PAD_CMD = 50123
spec = importlib.util.spec_from_file_location("ps", os.path.join(ROOT, "run/pad-state.py"))
ps = importlib.util.module_from_spec(spec); spec.loader.exec_module(ps)
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 120
NAMES = {0: "Active", 3: "Sleep", 4: "Standby", 5: "Pairing", 6: "FWUpdate",
         11: "WOWLSetting", 12: "DKSetting/menu"}

def awake():
    a = int(open("/sys/class/net/%s/statistics/rx_packets" % IFACE).read())
    time.sleep(2)
    b = int(open("/sys/class/net/%s/statistics/rx_packets" % IFACE).read())
    return (b - a) / 2.0 >= 20

print("waiting for the pad to be awake...", flush=True)
while not awake():
    time.sleep(2)
print("pad awake - polling state every 2 s", flush=True)

pcap = "/tmp/.poll-state.pcap"
if os.path.exists(pcap): os.unlink(pcap)
cap = subprocess.Popen(["timeout", str(SECS + 8), "tcpdump", "-i", IFACE, "-n", "-w",
                        pcap, "udp and dst port 50023"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.168.1.10", 0))
sent = {}
t0 = time.time(); seq = 0xE00
while time.time() - t0 < SECS:
    s.sendto(ps.build_generic(4, 0x05, b"", seq=seq), (PAD, PAD_CMD))
    sent[seq] = round(time.time() - t0, 1)
    seq += 1
    time.sleep(2)
cap.wait(timeout=SECS + 20)
out = subprocess.run(["tshark", "-r", pcap, "-n", "-T", "fields", "-e", "udp.payload"],
                     capture_output=True, text=True).stdout
last = None
for line in out.splitlines():
    p = bytes.fromhex(line.replace(":", "")) if line else b""
    if len(p) < 18 or p[0] != 0x02: continue
    sq = int.from_bytes(p[6:8], "little")
    if sq not in sent: continue
    body = p[20:]
    if not body: continue
    st = body[0]
    if st != last:
        print("  t=%6.1fs  state -> %2d (%s)" % (sent[sq], st, NAMES.get(st, "?")), flush=True)
        last = st
os.unlink(pcap)
