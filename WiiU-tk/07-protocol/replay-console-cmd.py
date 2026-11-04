#!/usr/bin/env python3
"""Replay the real console's UIC state command (service 0, method 0x11) to the pad.

Decrypted from capture/console-truth.pcap (see SETUP.md round 11n): the console
sends this 1048-byte command ~5x/second and our stack has never sent it. This
replays the captured bytes so we can see whether the pad's display gate depends
on it.

Sends from an ephemeral source port to $PAD:50123, because our streamer already
owns 192.168.1.10:50023. If the pad validates the source port this will be
ignored - in that case the next step is to stop the streamer's command socket.
"""
import socket, struct, sys, time, os

PAD = "192.168.1.11"
PORT = 50123
INTERVAL = float(os.environ.get("REPLAY_INTERVAL", "0.2"))
files = [f for f in sys.argv[1:] if os.path.exists(f)] or ["capture/console-cmd-0.bin"]
payloads = [open(f, "rb").read() for f in files]
print(f"loaded {len(payloads)} payload(s): {[len(p) for p in payloads]} bytes")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("192.168.1.10", 0))
print(f"sending from {s.getsockname()} -> {PAD}:{PORT} every {INTERVAL*1000:.0f} ms")

# Wait until the pad is actually on our network (it prefers the real console when
# that is powered on), so the replay starts the moment it joins us.
import subprocess
while True:
    r = subprocess.run(["ping","-c1","-W1",PAD], capture_output=True)
    if r.returncode == 0:
        print("pad is reachable - starting replay", flush=True)
        break
    time.sleep(2)

sent = 0
try:
    while True:
        for p in payloads:
            s.sendto(p, (PAD, PORT))
            sent += 1
        if sent % 25 == 0:
            print(f"sent={sent}", flush=True)
        time.sleep(INTERVAL)
except KeyboardInterrupt:
    print(f"stopped after {sent}")
