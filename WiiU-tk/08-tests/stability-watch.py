#!/usr/bin/env python3
"""Sample a live DRC session every 30 s and record whether it stays healthy.

Answers the stability questions that a single scored run cannot:
  * does the video plane hold ~57 fps for minutes?
  * does the media clock stay in the AP-TSF domain (and follow a TSF reset if
    the AP's vif restarts)?
  * when the pad sleeps and re-joins, does video resume without help (the
    streamer re-arms on rejoin), and does the clock stay sane?
  * is the pad associated, and does its input resume after the sleep?

Each window is a short plaintext capture on the AP interface, so no decryption
is needed. Numbers are printed per window and summarised at the end.

Usage: sudo ./tests/stability-watch.py --minutes 8 [--window 5] [--period 30]
"""
import argparse
import os
import statistics
import subprocess
import sys
import time

IFACE = "WiiUAP"
PAD = "192.168.1.11"
ROOT = "/home/kali/Wiiu"


def sample_better(seconds, path):
    subprocess.run(["timeout", str(seconds), "tcpdump", "-i", IFACE, "-n", "-w", path,
                    "udp and host %s" % PAD], capture_output=True)
    return path


def stats(path):
    out = subprocess.run(
        ["tshark", "-r", path, "-n", "-T", "fields",
         "-e", "frame.time_relative", "-e", "udp.srcport", "-e", "udp.dstport",
         "-e", "udp.length", "-e", "udp.payload"],
        capture_output=True, text=True).stdout
    vid = inp = rs = uvc_q = 0
    ts = []
    span = 0.0
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 5:
            continue
        try:
            t = float(f[0]); sp = int(f[1]); ul = int(f[3])
        except ValueError:
            continue
        span = max(span, t)
        if sp == 50020:
            vid += 1
            pay = bytes.fromhex(f[4].replace(":", "")) if len(f) > 4 and f[4] else b""
            if len(pay) >= 8 and (pay[0] & 0xF0) == 0xF0 and (pay[2] & 0x10):
                ts.append(__import__("struct").unpack_from(">I", pay, 4)[0])
        elif sp == 50122:
            inp += 1
        elif sp == 50110:
            rs += 1
        pay = bytes.fromhex(f[4].replace(":", "")) if len(f) > 4 and f[4] else b""
        if pay[:4] == b"\x00\x00\x01\x00":
            uvc_q += 1
    span = span or 1.0
    d = [ts[i + 1] - ts[i] for i in range(len(ts) - 1) if ts[i + 1] > ts[i]]
    return {
        "span": span, "vid_s": vid / span, "inp_s": inp / span, "rs_s": rs / span,
        "frames": len(ts), "fps": len(ts) / span,
        "delta": statistics.median(d) if d else 0,
        "ts_first": ts[0] if ts else 0, "ts_last": ts[-1] if ts else 0,
    }


def associated():
    try:
        out = subprocess.run(["iw", "dev", IFACE, "station", "dump"],
                             capture_output=True, text=True).stdout
        return out.count("Station")
    except Exception:
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=8)
    ap.add_argument("--window", type=float, default=5)
    ap.add_argument("--period", type=float, default=30)
    args = ap.parse_args()

    stamp = time.strftime("%H%M%S")
    logpath = os.path.join(ROOT, "out/logs/stability-%s.log" % stamp)
    log = open(logpath, "w")
    print("logging to %s" % logpath)
    hdr = ("t     assoc  video/s  fps   delta   ts_first   ts_last    input/s  resync/s")
    print(hdr); log.write(hdr + "\n")

    t0 = time.time()
    rows = []
    i = 0
    while time.time() - t0 < args.minutes * 60:
        i += 1
        path = "/tmp/stab-%s-%02d.pcap" % (stamp, i)
        sample_better(args.window, path)
        s = stats(path)
        assoc = associated()
        rel = time.time() - t0
        line = ("%5.0fs %5d  %6.1f %5.1f %6.0f %10.1f %10.1f  %7.1f  %7.1f"
                % (rel, assoc, s["vid_s"], s["fps"], s["delta"],
                   s["ts_first"] / 1e6, s["ts_last"] / 1e6, s["inp_s"], s["rs_s"]))
        print(line); log.write(line + "\n"); log.flush()
        rows.append((rel, assoc, s))
        os.unlink(path)
        time.sleep(max(0.0, args.period - args.window))

    print("\n--- summary ---")
    fps = [r[2]["fps"] for r in rows if r[2]["fps"] > 0]
    deltas = [r[2]["delta"] for r in rows if r[2]["delta"] > 0]
    ctl = [r[2]["ts_first"] for r in rows if r[2]["ts_first"] > 0]
    print("windows              : %d over %.0f min" % (len(rows), args.minutes))
    if fps:
        print("fps   min/med/max    : %.1f / %.1f / %.1f"
              % (min(fps), statistics.median(fps), max(fps)))
    if deltas:
        print("ts delta min/med/max : %.0f / %.0f / %.0f us  (console 16683)"
              % (min(deltas), statistics.median(deltas), max(deltas)))
    if ctl:
        print("clock domain         : %.1f s .. %.1f s"
              % (min(ctl) / 1e6, max(r[2]["ts_last"] for r in rows) / 1e6))
    dead = [r for r in rows if r[2]["fps"] < 5]
    print("windows with no video: %d %s" % (len(dead), [round(r[0]) for r in dead]))
    asleep = [r for r in rows if r[2]["inp_s"] < 20]
    print("windows with pad idle: %d %s" % (len(asleep), [round(r[0]) for r in asleep]))
    log.close()
    print("log: %s" % logpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
