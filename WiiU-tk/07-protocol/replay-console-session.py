#!/usr/bin/env python3
"""
Replay a COMPLETE real console session to the GamePad: commands, video, audio,
format messages and the 50025 table, all with the console's own bytes and its
recorded timing.

Why this exists. Decrypting a real console session (2026-11-04) showed the
console does not just start streaming: it performs a fixed session-start
handshake on the command channel. Replayed from the decrypted capture, in order:

    t=0.00  type 0 / query 2 / len 8     the "time" command
    t=0.02  type 0 / query 0 / len 12    x13 generic UIC commands
                                         (service 0/0, 4/4, 5/6, 4/5, 5/0x0c, 0/0x10 ...)
    t=0.22  type 0 / query 0 / len 1040  x778 state blobs (service 0, method 0x11)
    t=69.3  type 0 / query 1 / len 48    UVC/UAC keepalive, 1/s from then on

Our streamer sends the 5/6 query once, a clock command and a backlight command
each second, and none of the rest. On real hardware the pad shows its own UI and
then "could not connect" after trying to bring the session up, which is what the
operator has been seeing all along - so the missing element may be this
handshake, not the media.

Media-only replay holds the pad quiet (0 resync/s); this replays the whole
session so the pad can complete whatever it is waiting for.

Usage:
  ./run/replay-console-session.py --pad 192.168.1.11 --seconds 150 --ts-shift
  ./run/replay-console-session.py --pad 192.168.1.11 --no-commands     # control
"""
import argparse
import os
import socket
import struct
import sys
import time

TRUTH = "out/evidence/truth"

# destination port -> (source port we must bind)
STREAMS = {
    50120: (50020, "port50120.bin", "video"),
    50121: (50021, "port50121.bin", "audio+format"),
    50123: (50023, "port50123.bin", "console->pad commands"),
    50125: (50025, "port50125.bin", "panel table"),
    50023: (None, "port50023.bin", "pad->console replies (absorb only)"),
}


def load(path):
    data = open(path, "rb").read()
    recs, off = [], 0
    while off + 20 <= len(data):
        ts, _s, _d, ln = struct.unpack(">d4s4sI", data[off:off + 20])
        off += 20
        recs.append((ts, data[off:off + ln]))
        off += ln
    return recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pad", default="192.168.1.11")
    ap.add_argument("--truth", default=TRUTH)
    ap.add_argument("--seconds", type=float, default=150)
    ap.add_argument("--ts-shift", action="store_true",
                    help="rewrite media timestamps into the pad's epoch")
    ap.add_argument("--no-commands", action="store_true",
                    help="media only (control run)")
    ap.add_argument("--no-media", action="store_true",
                    help="commands only (control run)")
    ap.add_argument("--media-lead", type=float, default=8.0,
                    help="start media this many seconds after the command "
                         "sequence begins (the capture's own gap between the "
                         "handshake and the first video datagram was ~60s, which "
                         "is how long the pad took to wake, not a protocol "
                         "requirement); use -1 to keep the recorded gap")
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--dry-run", action="store_true",
                    help="count what would be sent and exit (no sockets)")
    ap.add_argument("--iface", default="192.168.1.10",
                    help="local address to bind")
    args = ap.parse_args()

    events = []          # (t_rel, dport, payload)
    t_first = None
    for dport, (sport, fname, label) in STREAMS.items():
        path = os.path.join(args.truth, fname)
        if not os.path.exists(path) or sport is None:
            continue
        if args.no_commands and dport == 50123:
            continue
        if args.no_media and dport in (50120, 50121, 50125):
            continue
        recs = load(path)
        if not recs:
            continue
        base = recs[0][0]
        if dport == 50120 and (t_first is None or base < t_first):
            t_first = base
        print("[*] %-22s %6d datagrams from %s" % (label, len(recs), fname))
        events.append((dport, sport, base, recs))
    if not events:
        raise SystemExit("nothing to replay")

    # The command stream starts the session, so it defines t=0. Anchoring on the
    # first video datagram instead (the earlier version) silently discarded the
    # whole startup handshake, because in the capture the console began talking
    # ~60 s before it sent any video.
    t0_abs = min(base for _d, _s, base, _r in events)
    rel = []
    for dport, sport, base, recs in events:
        # Optionally compress the gap between the handshake and the media: in the
        # capture that gap is how long the pad took to wake up, not a protocol
        # requirement, and it makes every run 60 s longer than it needs to be.
        shift = 0.0
        if dport != 50123 and args.media_lead >= 0:
            shift = max(0.0, (base - t0_abs) - args.media_lead)
        for ts, payload in recs:
            t = (ts - t0_abs) - shift
            if t < 0:
                continue
            if t > args.seconds:
                break
            rel.append((t, dport, sport, payload))
    rel.sort(key=lambda e: e[0])
    print("[*] %d datagrams over %.1fs" % (len(rel), rel[-1][0] if rel else 0))

    if args.dry_run:
        by = {}
        for t, dport, sport, payload in rel:
            by.setdefault(dport, []).append(t)
        for dport in sorted(by):
            ts = by[dport]
            print("   dport %d: %6d datagrams, %.1fs..%.1fs"
                  % (dport, len(ts), ts[0], ts[-1]))
        return 0

    socks = {}
    for dport, (sport, fname, label) in STREAMS.items():
        if sport is None:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 5)
        try:
            s.bind((args.iface, sport))
        except OSError as exc:
            print("[-] bind %s:%d failed: %s" % (args.iface, sport, exc))
            return 2
        socks[sport] = s
    # absorb (and count) the pad's resync requests / replies so its stack does
    # not see ICMP port-unreachable for traffic a real console would accept
    absorb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    absorb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        absorb.bind((args.iface, 50010))
    except OSError:
        pass

    # media timestamps get their own origin, same as the media-only replayer
    vid_first_ts = None
    vid_start = None
    for dport, sport, base, recs in events:
        if dport == 50120 and recs:
            vid_first_ts = struct.unpack(">I", recs[0][1][4:8])[0]
            vid_start = base
            break
    media_shift = 0.0
    if vid_start is not None and args.media_lead >= 0:
        media_shift = max(0.0, (vid_start - t0_abs) - args.media_lead)

    def restamp(ts_rel, payload):
        if not args.ts_shift or vid_first_ts is None:
            return payload
        q = bytearray(payload)
        # ts_rel is already replay-relative; the media clock should advance 1:1
        # from the first frame's own timestamp, so subtract the compression.
        newts = (vid_first_ts + int((ts_rel + media_shift) * 1e6)) & 0xFFFFFFFF
        if len(q) >= 16 and q[2] & 0x08:
            q[4:8] = struct.pack(">I", newts)
        elif len(q) == 32 and q[0] == 0x04:
            q[8:12] = struct.pack("<I", newts)
        return bytes(q)

    t0 = time.perf_counter()
    sent = fails = 0
    for t, dport, sport, payload in rel:
        due = t / args.rate
        wait = due - (time.perf_counter() - t0)
        if wait > 0.002:
            time.sleep(wait - 0.001)
        while time.perf_counter() - t0 < due:
            pass
        s = socks.get(sport)
        if s is None:
            continue
        pkt = payload if dport == 50123 or dport == 50125 else restamp(t, payload)
        try:
            s.sendto(pkt, (args.pad, dport))
            sent += 1
        except OSError:
            fails += 1
    print("[+] replayed %d datagrams (%d failed) in %.1fs"
          % (sent, fails, time.perf_counter() - t0))


if __name__ == "__main__":
    sys.exit(main())
