#!/usr/bin/env python3
"""Keep /var/run/drc/tsf-offset-us correct with minimal monitor-vif load.

Why this replaces the continuous monitor capture
------------------------------------------------
The media clock must be the AP's real TSF (see research/DISPLAY-WORKS.md). The
first implementation kept a *continuous* `tshark -i mon0` capture alive for the
whole session to track it. On this hardware that is expensive: the AX210
firmware crashed repeatedly (`iwlwifi: Device error - SW reset`), and each crash
resets the phy TSF, which silently corrupted our frame timestamps and dropped the
pad to "could not connect".

So instead: take ONE short TSF sample every few seconds, and between samples
leave the clock alone (the offset only needs correcting when it actually
changes). A large change means the phy reset under us, and that is not something
we can paper over by retuning the offset - the pad's own clock stepped too, so
the video stream has to be restarted. This tool detects that and leaves a marker
in /var/run/drc/tsf-reset; drcvncclient consumes it and re-arms + re-inits.

Usage:
  sudo ./run/tsf-keeper.py                 # follow streamer.pid forever
  sudo ./run/tsf-keeper.py --pid 1234 --period 5
"""
import argparse
import os
import subprocess
import sys
import time

RUNDIR = "/var/run/drc"
OFFSET_FILE = os.path.join(RUNDIR, "tsf-offset-us")
RESET_MARKER = os.path.join(RUNDIR, "tsf-reset")
RESET_THRESHOLD_US = 5_000_000      # 5 s: far beyond jitter, means a phy reset
WRITE_THRESHOLD_US = 300_000        # 0.3 s: ignore ordinary drift


def sample_once(iface="mon0", timeout=6):
    """One TSF reading (microseconds) from a single radiotap frame."""
    # Do NOT use -c 1: it stops on the first frame, and if that frame carries no
    # radiotap TSFT the field is empty and the sample silently yields nothing
    # (measured: this made the clock guard fail intermittently, so the offset was
    # never corrected after a phy reset). Take a short window and use the first
    # frame that actually had a TSF.
    try:
        out = subprocess.run(
            ["tshark", "-i", iface, "-n", "-a", "duration:3", "-T", "fields",
             "-e", "wlan_radio.timestamp"],
            capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    return None


def proc_elapsed_us(pid):
    with open("/proc/%d/stat" % pid) as fh:
        fields = fh.read().rsplit(")", 1)[1].split()
    starttime = int(fields[19])
    with open("/proc/uptime") as fh:
        uptime = float(fh.read().split()[0])
    return int((uptime - starttime / os.sysconf("SC_CLK_TCK")) * 1_000_000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="mon0")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--period", type=float, default=5.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    if args.once:
        v = sample_once(args.iface)
        print(v if v is not None else "", end="")
        return 0 if v is not None else 1

    pid = args.pid
    if pid is None:
        try:
            pid = int(open(os.path.join(RUNDIR, "streamer.pid")).read().strip())
        except Exception:
            pid = None

    prev = None
    print("[tsf-keeper] period %.1fs, resets write %s" % (args.period, RESET_MARKER),
          flush=True)
    while True:
        tsft = sample_once(args.iface)
        if tsft is None:
            print("[tsf-keeper] no TSF sample (monitor idle or phy down)", flush=True)
            time.sleep(args.period)
            continue
        if pid is None:
            try:
                pid = int(open(os.path.join(RUNDIR, "streamer.pid")).read().strip())
            except Exception:
                pid = None
        if pid is None:
            time.sleep(args.period)
            continue
        try:
            elapsed = proc_elapsed_us(pid)
        except Exception:
            pid = None
            time.sleep(args.period)
            continue
        offset = tsft - elapsed
        if prev is None or abs(offset - prev) > WRITE_THRESHOLD_US:
            try:
                with open(OFFSET_FILE, "w") as fh:
                    fh.write("%d\n" % offset)
            except OSError as exc:
                print("[tsf-keeper] cannot write %s: %s" % (OFFSET_FILE, exc),
                      flush=True)
                return 2
            print("[tsf-keeper] TSF %.1fs elapsed %.1fs -> offset %d"
                  % (tsft / 1e6, elapsed / 1e6, offset), flush=True)
        if prev is not None and abs(offset - prev) > RESET_THRESHOLD_US:
            print("[tsf-keeper] PHY TSF STEPPED %.1f s - the radio reset under us."
                  % ((offset - prev) / 1e6), flush=True)
            try:
                with open(RESET_MARKER, "w") as fh:
                    fh.write("%d\n" % offset)
            except OSError:
                pass
        prev = offset
        time.sleep(args.period)
    return 0


if __name__ == "__main__":
    sys.exit(main())
