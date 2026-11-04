#!/usr/bin/env python3
"""
Turn a live WiiUAP capture of OUR stream into a replayable media file.

The purpose is a controlled payload A/B with nothing else different: replay the
console's captured datagrams (out/evidence/truth/) and our own captured datagrams
(this tool's output) with the same replayer, the same clock path, the same
pacing and no command traffic at all. If the pad goes quiet for the console's
payload and keeps asking for ours, the encoded bytes are the gate and everything
else is exonerated.

Output is the same format run/replay-console-media.py loads:
    repeated { double ts, 4B src, 4B dst, u32 payload_len, payload }

Usage:
  ./tests/pcap-to-replay.py capture/phase4-clock-083704.pcap \\
      --outdir out/evidence/replay-ours
  sudo ./run/phase3-replay-console.sh 90 --ts-shift --truth out/evidence/replay-ours
"""
import argparse
import collections
import os
import subprocess
import struct
import sys

VIDEO_DST = 50120
ASTREAM_DST = 50121


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()

    out = subprocess.run(
        ["tshark", "-r", args.pcap, "-n", "-Y", "udp",
         "-T", "fields", "-e", "frame.time_relative",
         "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload"],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(out.stderr.strip() or "tshark failed")

    vid, aud = [], []
    for line in out.stdout.splitlines():
        f = line.split("\t")
        if len(f) < 4 or not f[0]:
            continue
        try:
            ts = float(f[0])
            sport, dport = int(f[1] or 0), int(f[2] or 0)
        except ValueError:
            continue
        payload = bytes.fromhex(f[3].replace(":", "")) if f[3] else b""
        if not payload:
            continue
        rec = (ts, struct.pack(">4s4s" if False else ">II",
                               0, 0), payload)
        if dport == VIDEO_DST:
            vid.append(rec[0:1] + (payload,))
        elif dport == ASTREAM_DST:
            aud.append(rec[0:1] + (payload,))

    os.makedirs(args.outdir, exist_ok=True)

    def write(path, recs):
        with open(path, "wb") as fh:
            for item in recs:
                ts, payload = item[0], item[1]
                fh.write(struct.pack(">d4s4sI", ts, b"\x00" * 4, b"\x00" * 4,
                                     len(payload)))
                fh.write(payload)
        return len(recs)

    nv = write(os.path.join(args.outdir, "port50120.bin"), vid)
    na = write(os.path.join(args.outdir, "port50121.bin"), aud)
    print("[+] %s: %d video datagrams, %d audio/format datagrams"
          % (args.outdir, nv, na))
    if nv:
        span = vid[-1][0] - vid[0][0]
        print("    video spans %.1fs => %.1f frames/s worth of data"
              % (span, nv / max(span, 1e-9) / 5.2))
    # a quick sanity summary so a bad capture is obvious here, not mid-experiment
    sizes = collections.Counter(len(p) for _, p in vid)
    if sizes:
        print("    video payload sizes: max %d, %d distinct"
              % (max(sizes), len(sizes)))


if __name__ == "__main__":
    sys.exit(main())
