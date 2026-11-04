#!/usr/bin/env python3
"""Score the UVC/UAC (query type 1) exchange and the resync rate from a live
WiiUAP capture.

Why this exists
---------------
libdrc's reverse-engineering notes (`web/docs/re/sc-cmd.rst`) state:

    "This command is issued every second. Recent versions of the GamePad
     firmware will only show the video stream after receiving one such
     command."

That makes the UVC/UAC transaction -- not the media plane -- a candidate for the
display gate. The cmd protocol is a 4-state machine (query -> ack -> reply ->
ack) and both sides retry until acked, so the diagnostic is a *ratio*: in the
decrypted real-console session the console sent 228 UVC/UAC queries and the pad
sent back 228 replies (1:1, `out/evidence/truth/flows.json`, port50123.bin). If
our stack sends 1/s but the pad never replies, the pad is not accepting the
command at all, and the documented precondition for showing video is unmet.

Everything is measured from plaintext UDP on the AP interface, so no decryption
is needed when the host is the AP.

Usage:
  sudo ./tests/uvc-exchange.py capture/uvc-120000.pcap

  # add --watch to follow a live file while the run is in progress
"""
import argparse
import collections
import subprocess
import sys

PAD_CMD = 50123
CONSOLE_CMD = 50023
PAD_RESYNC = 50010
PAD_INPUT = 50022
UVC_WIRE_LEN = 56          # 8 B UDP header + 48 B UvcUacCommand payload (measured)
CONSOLE_TRUTH = {"uvc_queries": 228, "uvc_replies": 228, "resync_in_300s": 3}


def rows(pcap):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-n", "-Y", "udp",
         "-T", "fields", "-e", "frame.time_relative",
         "-e", "ip.src", "-e", "udp.srcport", "-e", "udp.dstport",
         "-e", "udp.length", "-e", "udp.payload"],
        capture_output=True, text=True).stdout
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 6:
            continue
        try:
            pay = bytes.fromhex(f[5].replace(":", "")) if f[5] else b""
            yield (float(f[0]), f[1], int(f[2]), int(f[3]), int(f[4]), pay)
        except ValueError:
            continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--watch", action="store_true",
                    help="keep re-reading until Ctrl-C (live file)")
    args = ap.parse_args()

    qu, rp, resync, inp = 0, 0, 0, 0
    lens_q = collections.Counter()
    lens_r = collections.Counter()
    lens_c = collections.Counter()
    inp_buckets = collections.Counter()
    last_t = 0.0
    try:
        for t, _ip, sp, dp, ul, pay in rows(args.pcap):
            last_t = max(last_t, t)
            # Classify by payload signature, NOT by length: the pad's UVC/UAC
            # reply is a 24 B datagram (16 B payload) while the query is 56 B,
            # so a length test silently scores every reply as "missing".
            head = pay[:4]
            if head == b"\x00\x00\x01\x00":       # query type 1, query
                lens_q[ul] += 1
                qu += 1
            elif head == b"\x02\x00\x01\x00":     # query type 1, reply
                lens_r[ul] += 1
                rp += 1
            if sp == CONSOLE_CMD or dp == CONSOLE_CMD:
                lens_c[ul] += 1
            if dp == PAD_RESYNC or sp == PAD_RESYNC:
                resync += 1
            if dp == PAD_INPUT or sp == PAD_INPUT:
                inp += 1
                inp_buckets[int(t // 10)] += 1
    except KeyboardInterrupt:
        pass

    span = last_t if last_t else 1.0
    print("capture span           : %.1f s" % span)
    print("UVC/UAC queries (->pad): %d  (%.2f/s)" % (qu, qu / span))
    print("UVC/UAC replies (<-pad) : %d  (%.2f/s)" % (rp, rp / span))
    if qu:
        print("reply ratio            : %.0f %%  %s"
              % (100.0 * rp / qu,
                 "OK - exchange completes"
                 if rp >= qu * 0.8 else
                 "*** PAD IS NOT ANSWERING: documented video-show gate unmet ***"))
    else:
        print("reply ratio            : n/a - we sent no UVC/UAC query at all")
    print("resync                   : %d datagrams  (%.2f/s; console truth %d/300 s)"
          % (resync, resync / span, CONSOLE_TRUTH["resync_in_300s"]))
    # A falling input rate means the pad is going to sleep -- any "quiet" video
    # score in that window is meaningless (see research/DISPLAY-GATE-FRONTIER.md).
    print("pad input                : %d datagrams  (%.2f/s)" % (inp, inp / span))
    if inp_buckets:
        per10 = " ".join("%d:%d" % (k, v) for k, v in sorted(inp_buckets.items()))
        counts = [v for _k, v in sorted(inp_buckets.items())]
        trend = "FALLING - pad is going to sleep"
        if len(counts) > 1 and counts[-1] >= counts[0] * 0.6:
            trend = "stable"
        print("input per 10 s bucket    : %s   (%s)" % (per10, trend))
    print()
    print("UVC query  sizes : %s" % dict(sorted(lens_q.items())))
    print("UVC reply  sizes : %s" % dict(sorted(lens_r.items())))
    print("cmd-port wire lengths (either direction): %s"
          % dict(sorted(lens_c.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
