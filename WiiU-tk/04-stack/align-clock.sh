#!/bin/bash
# align-clock.sh - put our media timestamps into the radio's real TSF domain.
#
# The GamePad schedules playback against the TSF it syncs from our beacons. Our
# AX210 has no .get_tsf, so libdrc falls back to a synthetic clock whose epoch is
# the *streamer's start* - a domain the pad cannot resolve. The phy TSF is still
# readable: a monitor vif alongside the AP reports it as the radiotap TSFT field.
#
# So: read the phy TSF, subtract the streamer's own elapsed synthetic value, and
# write the difference where libdrc re-reads it every second
# (/var/run/drc/tsf-offset-us, added for exactly this purpose).
#
# Re-run this after every streamer restart (the synthetic epoch resets then).
# Requires: mon0 monitor vif on the AP's channel (drc-up.sh creates it).
# Usage: sudo ./run/align-clock.sh
set -uo pipefail
PID=$(pgrep -x drcvncclient | head -1)
[ -n "${PID:-}" ] || { echo "streamer not running"; exit 1; }
CHAN=${CHAN:-149}
iw dev mon0 info >/dev/null 2>&1 || { echo "mon0 missing - create it: iw dev wlan0 interface add mon0 type monitor"; exit 1; }
ip link set mon0 up 2>/dev/null
iw dev mon0 set channel "$CHAN" 2>/dev/null
TSF=$(timeout 4 tcpdump -i mon0 -c 2 -n 2>/dev/null | grep -o '[0-9]*us tsft' | head -1 | grep -o '[0-9]*')
[ -n "${TSF:-}" ] || { echo "could not read TSFT (is anything on $CHAN?)"; exit 1; }
OFF=$(python3 - "$PID" "$TSF" <<'PY'
import sys
pid, tsf = int(sys.argv[1]), int(sys.argv[2])
start_ticks = int(open("/proc/%d/stat" % pid).read().split()[21])
up = float(open("/proc/uptime").read().split()[0])
print(int(tsf - (up - start_ticks / 100.0) * 1e6))
PY
)
mkdir -p /var/run/drc
echo "$OFF" > /var/run/drc/tsf-offset-us
echo "phy TSF=${TSF}us  offset=${OFF}us  -> media clock now in the pad's TSF domain"
