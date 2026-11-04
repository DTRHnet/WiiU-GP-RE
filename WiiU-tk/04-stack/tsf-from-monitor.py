#!/usr/bin/env python3
"""
Serve the AP's REAL 802.11 TSF as the media clock, from a monitor interface.

Why this exists (and why it is the highest-impact item in the Barista diff):
the GamePad schedules video against the AP's TSF, which it syncs from our
beacons. Every working implementation hands the pad timestamps in that domain:
wozt/bottom_screen via wozt/rtw88_TSF, Barista via a monitor-derived radiotap
TSF (runtime_transport.cpp:1212-1322). Our stack has no `.get_tsf` (iwlwifi), so
GetTsf() falls back to a synthetic monotonic clock plus a manual offset, and the
offsets used so far were guesses:
  * 0                              -> ~0 s   (far behind the pad)
  * (epoch_ms mod 2^32)            -> ~2797 s (a wall-clock accident)
  * hostapd process age            -> ~4574 s (WRONG: the phy TSF restarts when
                                              the radio/vif comes up; measured
                                              radiotap TSFT was 731 s at that
                                              moment)

A monitor vif's radiotap TSFT is a LOCAL phy timestamp, so any frame received on
that vif - including the pad's own 180/s input stream - reports our AP's TSF. That
is measured working here: pad frames show `radiotap.present.tsft=True,
wlan_radio.timestamp=731107349`.

What it does: reads TSFT from mon0, and keeps /var/run/drc/tsf-offset-us equal to
(TSFT_now - streamer_elapsed), which is exactly the constant the streamer adds to
its own monotonic clock (tsf-linux.cpp: synthetic elapsed + offset). Updating it
every second keeps the two locked even if the streamer restarts.

Usage:
  sudo ./run/tsf-from-monitor.py                     # follow every second
  sudo ./run/tsf-from-monitor.py --pid $(cat /var/run/drc/streamer.pid)
  ./run/tsf-from-monitor.py --dry-run                # print TSFT only
"""
import argparse
import os
import socket
import struct
import sys
import time

RUNDIR = "/var/run/drc"
OFFSET_FILE = os.path.join(RUNDIR, "tsf-offset-us")


def tshark_tsft_stream(iface):
    """Yield (tsft_us) from a live tshark on the monitor interface.

    tshark is used rather than a hand-rolled or scapy radiotap parse: the header
    has a variable present-word chain and per-field alignment, and both naive
    alternatives produced garbage here (hand parse: 8.9e6 s; scapy: TSFT marked
    present but value None). tshark reports the correct 731 s.
    """
    import subprocess
    # radiotap.present.tsft is a multi-value field ("True,False,False"), so the
    # timestamp field is read on its own: every frame we capture on the monitor
    # vif carries the phy's TSF in wlan_radio.timestamp.
    proc = subprocess.Popen(
        ["tshark", "-i", iface, "-n", "-l", "-T", "fields",
         "-e", "wlan_radio.timestamp"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            value = line.strip()
            if not value:
                continue
            try:
                yield int(value)
            except ValueError:
                continue
    finally:
        proc.terminate()


def proc_elapsed_us(pid):
    """Microseconds since `pid` started, from /proc/<pid>/stat (Linux clock ticks)."""
    with open("/proc/%d/stat" % pid) as fh:
        fields = fh.read().rsplit(")", 1)[1].split()
    starttime = int(fields[19])              # field 22 of stat, 0-based here
    with open("/proc/uptime") as fh:
        uptime = float(fh.read().split()[0])
    hz = os.sysconf("SC_CLK_TCK")
    return int((uptime - starttime / hz) * 1_000_000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="mon0")
    ap.add_argument("--pid", type=int, help="streamer pid; default: streamer.pid")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--seconds", type=float, default=0, help="0 = forever")
    ap.add_argument("--once", action="store_true",
                    help="print the first TSFT sample (microseconds) and exit; "
                         "use this to seed the offset file before the streamer "
                         "starts, when no streamer pid exists yet")
    args = ap.parse_args()

    if args.once:
        for tsft in tshark_tsft_stream(args.iface):
            print(tsft)
            return 0
        return 1

    pid = args.pid
    if pid is None:
        try:
            pid = int(open(os.path.join(RUNDIR, "streamer.pid")).read().strip())
        except Exception:
            pid = None

    last = None
    wrote = 0
    prev_offset = None
    t0 = time.time()
    for tsft in tshark_tsft_stream(args.iface):
        if args.seconds and time.time() - t0 > args.seconds:
            break
        if args.dry_run:
            if last is None or tsft - last > 500_000:
                print("  TSFT %d us (%.3f s)" % (tsft, tsft / 1e6), flush=True)
                last = tsft
            continue
        if pid is None:
            continue
        try:
            elapsed = proc_elapsed_us(pid)
        except Exception:
            continue
        offset = tsft - elapsed
        # A phy/vif reset makes the TSF jump backwards (measured 2026-11-04: it
        # went 1003 s -> 173 s mid-session). The offset is still "correct" after
        # that (timestamp = elapsed + offset = current TSF), but the frame clock
        # jumps BACKWARDS by minutes and the pad discards the stream - the screen
        # drops to "could not connect". Report it loudly instead of silently
        # retuning, because the fix is to restart the session.
        if prev_offset is not None and abs(offset - prev_offset) > 5_000_000:
            print("[!] AP TSF JUMPED %.1f s (phy/vif reset): frame timestamps are "
                  "no longer continuous - restart the session (run/uvc-stop.sh && "
                  "run/uvc-live.sh)" % ((offset - prev_offset) / 1e6), flush=True)
        prev_offset = offset
        try:
            with open(OFFSET_FILE, "w") as fh:
                fh.write("%d\n" % offset)
        except OSError as exc:
            print("[-] cannot write %s: %s" % (OFFSET_FILE, exc), flush=True)
            return 2
        wrote += 1
        if wrote % 50 == 1:
            print("  TSFT %.3fs  elapsed %.3fs  offset=%d"
                  % (tsft / 1e6, elapsed / 1e6, offset), flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
