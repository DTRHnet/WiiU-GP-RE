#!/usr/bin/env python3
"""
Replay a REAL console's media stream to the GamePad, byte for byte.

Everything it sends was captured from a real Wii U console talking to a real
GamePad and decrypted (out/evidence/truth/port50120.bin and port50121.bin; see
research/GROUND-TRUTH-SESSION.md). The datagrams are replayed verbatim, on the
console's own source ports (50020 video, 50021 audio+format), with the console's
recorded inter-packet timing.

Why this exists: by 2026-11-04 every property we control has been made
console-identical and measured on the wire (envelope, options, chunking,
payload cap, 5.0 chunk-ends/frame, 16683 us cadence, format bytes and phase,
1 Hz 50125 table, init semantics) and the pad still asks for a resync ~61 times
a second. This experiment isolates the one variable left: the encoded bytes.
If the pad decodes these, our encoder is the gate. If it does not, the gate is
outside the media plane (clock/control), because these bytes are the console's.

Usage:
  ./run/replay-console-media.py --pad 192.168.1.11                # 1x real time
  ./run/replay-console-media.py --pad 192.168.1.11 --loops 2
  ./run/replay-console-media.py --pad 192.168.1.11 --ts-shift    # restamp clock

Notes:
  * Run it INSTEAD of the streamer: stop drcvncclient first, or two media
    sources will fight over the pad.
  * --ts-shift rewrites the 32-bit media timestamp inside every VSTRM packet and
    the video-format message to (original + offset), where the offset makes the
    first frame's timestamp equal the elapsed seconds since start. Without it the
    console's original clock (about 92 s at that point in its uptime) is replayed
    unchanged.
  * Needs to bind 50020/50021 as source ports; the console does the same.
"""
import argparse
import socket
import struct
import sys
import time

TRUTH = "out/evidence/truth"


def load_port(path):
    """Records are: double ts, 4B src, 4B dst, u32 len, payload."""
    data = open(path, "rb").read()
    recs, off = [], 0
    while off + 20 <= len(data):
        ts, _src, _dst, ln = struct.unpack(">d4s4sI", data[off:off + 20])
        off += 20
        recs.append((ts, data[off:off + ln]))
        off += ln
    return recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pad", default="192.168.1.11")
    ap.add_argument("--truth", default=TRUTH)
    ap.add_argument("--loops", type=int, default=1)
    ap.add_argument("--rate", type=float, default=1.0, help="1.0 = real time")
    ap.add_argument("--ts-base", type=float, default=None,
                    help="media clock start in SECONDS (default: epoch-derived "
                         "value that the pad accepts when unarmed)")
    ap.add_argument("--ts-shift", action="store_true",
                    help="restamp media timestamps to start at 0")
    ap.add_argument("--skip-audio", action="store_true")
    ap.add_argument("--seconds", type=float, default=0,
                    help="stop after N seconds of replayed media (0 = all)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    vid = load_port("%s/port50120.bin" % args.truth)
    aud = load_port("%s/port50121.bin" % args.truth)
    if not vid:
        raise SystemExit("no video records in %s" % args.truth)

    # Rebase both streams onto one timeline that starts with the first video
    # datagram: audio and format messages before that belong to the console's
    # earlier boot phase, not to this stream.
    t_vid0 = vid[0][0]
    vid = [(t - t_vid0, p) for t, p in vid]
    if args.skip_audio:
        aud = []
    else:
        aud = [(t - t_vid0, p) for t, p in aud if t >= t_vid0]
    events = [(t, 0, p) for t, p in vid] + [(t, 1, p) for t, p in aud]
    events.sort(key=lambda e: (e[0], e[1]))
    span = events[-1][0]

    print("[*] replay: %d video + %d audio/format datagrams, %.2fs of console media"
          % (len(vid), len(aud), span))
    print("[*] destination %s:50120 (src 50020) and :50121 (src 50021)" % args.pad)

    if args.dry_run:
        vsock = asock = None
    else:
        vsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        vsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        vsock.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 5)
        vsock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0xa0)
        vsock.bind(("0.0.0.0", 50020))
        asock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        asock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        asock.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 5)
        asock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0xa0)
        asock.bind(("0.0.0.0", 50021))

    # The first video datagram's own timestamp is the origin used by --ts-shift.
    first_ts = struct.unpack(">I", vid[0][1][4:8])[0]

    def restamp(payload, elapsed_us, shift):
        q = bytearray(payload)
        ts = (first_ts + int(elapsed_us) + shift) & 0xFFFFFFFF
        if len(q) >= 16 and q[2] & 0x08:      # vstrm: timestamp present
            q[4:8] = struct.pack(">I", ts)
        elif len(q) == 32 and q[0] == 0x04:   # video-format message: LE ts at 8
            q[8:12] = struct.pack("<I", ts)
        return bytes(q)

    sent = fails = 0
    for loop in range(args.loops):
        shift = 0
        if args.ts_shift:
            if args.ts_base is not None:
                # explicit starting value for the media clock, in microseconds
                shift = int(args.ts_base * 1e6) - first_ts
            else:
                # make the replayed clock look like "now" for the pad
                shift = (int(time.time() * 1000) & 0xFFFFFFFF) - first_ts
        t_start = time.perf_counter()
        for t, kind, payload in events:
            if args.seconds and t > args.seconds:
                break
            due = t / args.rate
            now = time.perf_counter() - t_start
            wait = due - now
            if wait > 0.002:
                time.sleep(wait - 0.001)
            while time.perf_counter() - t_start < due:
                pass
            pkt = restamp(payload, t * 1_000_000, shift) if args.ts_shift else payload
            sock = vsock if kind == 0 else asock
            port = 50120 if kind == 0 else 50121
            if args.dry_run:
                sent += 1
                continue
            try:
                sock.sendto(pkt, (args.pad, port))
                sent += 1
            except OSError:
                fails += 1
        print("[*] loop %d/%d done: %d sent, %d failed, %.2fs"
              % (loop + 1, args.loops, sent, fails, time.perf_counter() - t_start))
    print("[+] replayed %d datagrams" % sent)


if __name__ == "__main__":
    main()
