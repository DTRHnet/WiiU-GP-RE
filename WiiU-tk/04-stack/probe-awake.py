#!/usr/bin/env python3
"""probe-awake.py - interrogate the pad the moment it is awake.

The pad sleeps within ~15-40 s of the last input, so manual probes miss it, and
several conclusions in this project were drawn from measurements taken while it was
asleep. This waits for the pad's own input stream (the only reliable "awake"
signal - it answers ARP but never ICMP), then immediately asks the two questions
that matter:

  svc 4 / 0x05   the pad's UIC state index (12 = the menu-ish state it sits in at
                 session start, 0 = active, ...). This is the oracle for "is the pad
                 in a console session or its own UI".
  svc 5 / 0x15   the arming oracle: 9004 = pad managers not armed, 0 = armed.

Queries are sent from an ephemeral port and the replies are read off the wire,
because the streamer owns 192.168.1.10:50023 and the pad always answers there.

Usage: sudo ./run/probe-awake.py [--timeout 300]
"""
import argparse
import importlib.util
import os
import socket
import struct
import subprocess
import sys
import time

ROOT = "/home/kali/Wiiu"
PAD = "192.168.1.11"
PAD_CMD = 50123
CONSOLE_CMD = 50023
IFACE = "WiiUAP"

_spec = importlib.util.spec_from_file_location("pad_state", os.path.join(ROOT, "run/pad-state.py"))
pad_state = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pad_state)


def pad_awake(min_rate=20):
    a = int(open("/sys/class/net/%s/statistics/rx_packets" % IFACE).read())
    time.sleep(2)
    b = int(open("/sys/class/net/%s/statistics/rx_packets" % IFACE).read())
    return (b - a) / 2.0 >= min_rate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=300)
    args = ap.parse_args()

    print("waiting for the pad to send input (power it on / touch it)...", flush=True)
    t0 = time.time()
    while time.time() - t0 < args.timeout:
        if pad_awake():
            break
        time.sleep(1)
    else:
        print("FAIL: pad never woke within %.0fs" % args.timeout)
        return 1
    print("pad is awake - probing now", flush=True)

    pcap = "/tmp/.probe-awake.pcap"
    if os.path.exists(pcap):
        os.unlink(pcap)
    cap = subprocess.Popen(["timeout", "8", "tcpdump", "-i", IFACE, "-n", "-w", pcap,
                            "udp and dst port %d" % CONSOLE_CMD],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("192.168.1.10", 0))
    sock.settimeout(2.0)
    sent = {}
    for seq, (svc, meth, label) in enumerate([(4, 0x05, "state"), (5, 0x15, "gate")]):
        pkt = pad_state.build_generic(svc, meth, b"", seq=seq)
        sock.sendto(pkt, (PAD, PAD_CMD))
        sent[seq] = label
    cap.wait(timeout=15)

    out = subprocess.run(["tshark", "-r", pcap, "-n", "-Y", "udp", "-T", "fields",
                          "-e", "udp.payload"], capture_output=True, text=True).stdout
    results = []
    for line in out.splitlines():
        raw = bytes.fromhex(line.replace(":", "")) if line else b""
        r = pad_state.parse_reply(raw)
        if r:
            results.append(r)
    os.unlink(pcap)

    if not results:
        print("no replies captured (pad slept again, or the streamer consumed them)")
        return 1
    for r in results:
        label = sent.get(r.get("seq"), "?")
        body = r.get("body") or b""
        print("  %-6s seq=%d error=%d body=%s" %
              (label, r.get("seq", -1), r.get("error", -1), body.hex()))
        if label == "state" and body:
            names = {0: "Active", 3: "Sleep", 4: "Standby", 5: "Pairing",
                     6: "FWUpdate", 11: "WOWLSetting", 12: "DKSetting/menu"}
            print("         -> UIC state %d (%s)"
                  % (body[0], names.get(body[0], "unknown")))
        if label == "gate":
            print("         -> managers armed" if r.get("error") == 0
                  else "         -> NOT armed (9004 = not in session)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
