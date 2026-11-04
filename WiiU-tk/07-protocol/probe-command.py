#!/usr/bin/env python3
"""
Inject one console-style command at a time into a running (quiet) session and
measure what the GamePad does about it.

Established 2026-11-04: with our streamer sending media only the pad requests
0.0 keyframes/s; with its command plane on it asks ~50/s. Every single-knob run
still asked, so no single *message* was implicated by that design - but those
runs still sent the other four commands. This tool settles causality: it leaves
the media untouched and sends exactly one command kind, from the console's own
source port 50023, then reports the pad's resync rate before/after.

Payloads come from the decrypted real console session where possible
(out/evidence/truth/console-messages/), so what is injected is what a console
would send.

Usage (needs root for the capture):
  run/probe-command.py --pad 192.168.1.11 --kind uvc --seconds 30
  run/probe-command.py --pad 192.168.1.11 --kind time --period 1 --seconds 30
  run/probe-command.py --pad 192.168.1.11 --kind uicblob --seconds 30
  run/probe-command.py --pad 192.168.1.11 --kind raw --file some.bin --dport 50123
  run/probe-command.py --pad 192.168.1.11 --kind panel --seconds 30
"""
import argparse
import collections
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MSG = os.path.join(ROOT, "out/evidence/truth/console-messages")

# name -> (payload source, destination port, source port)
KINDS = {
    # console's own 56-byte UVC/UAC query (type 0, query 1, len 48)
    "uvc":       ("cmd_t0_q1_len48.bin", 50123, 50023),
    # console's own 16-byte clock command (type 0, query 2, len 8)
    "time":      ("cmd_t0_q2_len8.bin", 50123, 50023),
    # console's 1048-byte UIC state blob (type 0, query 0, len 1040)
    "uicblob":   ("cmd_t0_q0_len1040.bin", 50123, 50023),
    # console's 20-byte generic UIC command (7e 01 ...)
    "generic":   ("cmd_t0_q0_len12.bin", 50123, 50023),
    # console's 332-byte one-off
    "blob332":   ("cmd_t0_q0_len324.bin", 50123, 50023),
    # the 96-byte panel table the console sends on 50025 -> 50125
    "panel":     ("cmd_50025_table.bin", 50125, 50025),
}


def load_payload(kind, path):
    if kind == "raw":
        if not path:
            raise SystemExit("--kind raw needs --file")
        return open(path, "rb").read()
    name = KINDS[kind][0]
    return open(os.path.join(MSG, name), "rb").read()


def resync_rate(pcap, t_from=0.0):
    out = subprocess.run(["tshark", "-r", pcap, "-n", "-Y", "udp.dstport==50010",
                          "-T", "fields", "-e", "frame.time_relative"],
                         capture_output=True, text=True)
    ts = [float(x) for x in out.stdout.split() if x]
    ts = [t for t in ts if t >= t_from]
    if not ts:
        return 0.0, 0
    span = max(ts) - min(ts) if len(ts) > 1 else 1.0
    return len(ts) / max(span, 1e-9), len(ts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pad", default="192.168.1.11")
    ap.add_argument("--kind", required=True, choices=sorted(KINDS) + ["raw"])
    ap.add_argument("--file", help="payload for --kind raw")
    ap.add_argument("--dport", type=int, help="override destination port")
    ap.add_argument("--sport", type=int, help="override source port")
    ap.add_argument("--period", type=float, default=1.0, help="seconds between sends")
    ap.add_argument("--seconds", type=float, default=30.0)
    ap.add_argument("--baseline", type=float, default=8.0,
                    help="seconds captured before the first send")
    ap.add_argument("--iface", default="WiiUAP")
    args = ap.parse_args()

    payload = load_payload(args.kind, args.file)
    _, dport_def, sport_def = KINDS.get(args.kind, ("", 50123, 50023))
    dport = args.dport or dport_def
    sport = args.sport or sport_def

    pcap = os.path.join(tempfile.gettempdir(), "probe-%s.pcap" % args.kind)
    if os.path.exists(pcap):
        os.remove(pcap)
    cap = subprocess.Popen(["tcpdump", "-i", args.iface, "-n", "-w", pcap, "udp"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", sport))

    print("[*] kind=%s payload=%dB %s -> %s:%d every %.2fs for %.0fs"
          % (args.kind, len(payload), sport, args.pad, dport, args.period,
             args.seconds))
    time.sleep(max(args.baseline - 1, 0))     # baseline window
    base_rate, _ = resync_rate(pcap, 0.0)
    print("[*] baseline resync rate during media-only window: %.1f/s" % base_rate)

    t0 = time.time()
    sent = 0
    while time.time() - t0 < args.seconds:
        try:
            sock.sendto(payload, (args.pad, dport))
            sent += 1
        except OSError as exc:
            print("   send error: %s" % exc)
        time.sleep(max(args.period, 0.01))
    time.sleep(1)
    cap.send_signal(2)
    cap.wait(timeout=10)

    after, n = resync_rate(pcap, args.baseline)
    print("[*] injected %d datagrams; resync during injection: %.1f/s (%d total)"
          % (sent, after, n))
    verdict = "CAUSES THE FLOOD" if after > 5 * max(base_rate, 1.0) and after > 5 \
        else ("no effect" if after < 5 else "partial")
    print("[=] verdict: %s  (baseline %.1f/s -> %.1f/s)" % (verdict, base_rate, after))


if __name__ == "__main__":
    main()
