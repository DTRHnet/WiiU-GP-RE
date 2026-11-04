#!/bin/bash
# tsf-guard.sh - keep the media clock aligned to the AP's real TSF, cheaply.
#
# The pad schedules playback against the TSF it syncs from our beacons, so the
# VSTRM timestamp must be in that domain (A/B tested: epoch 0 -> no video,
# epoch = AP TSF -> video).
#
# The offset is seeded when the streamer starts, but the AX210 firmware resets the
# phy TSF whenever it crashes, and after that our timestamps are minutes off and
# the pad shows nothing. A permanent monitor capture fixes that but loads the
# radio hard enough to make the crashes more frequent, so this samples ONE frame
# every --period seconds instead (a couple of seconds of monitor use per minute)
# and, on a step, both rewrites the offset and drops a marker that makes
# drcvncclient re-arm + re-init the video stream.
#
# Usage: sudo ./run/tsf-guard.sh [--period 60]
set -uo pipefail
ROOT=/home/kali/Wiiu
RUNDIR=/var/run/drc
OFFSET_FILE=$RUNDIR/tsf-offset-us
RESET_MARKER=$RUNDIR/tsf-reset
PERIOD=60
[ "${1:-}" = "--period" ] && PERIOD="${2:-60}"

say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

ensure_mon() {
  # A monitor vif is the ONLY TSF source on this radio (iwlwifi has no get_tsf,
  # so the patched mac80211 sysfs node is static and useless here). It must also
  # be tuned to the AP's channel or it receives nothing - which is why an
  # earlier version of this guard silently corrected nothing for hours.
  if ! iw dev mon0 info >/dev/null 2>&1; then
    iw dev wlan0 interface add mon0 type monitor 2>/dev/null || true
    sleep 1
  fi
  ip link set mon0 up 2>/dev/null
  iw dev mon0 set channel "${MON_CHANNEL:-149}" HT20 2>/dev/null
}

prev=$(cat "$OFFSET_FILE" 2>/dev/null || echo "")
pending=""
say "tsf-guard up (period ${PERIOD}s, offset ${prev:-unset})"

while :; do
  sleep "$PERIOD"
  spid=$(cat "$RUNDIR/streamer.pid" 2>/dev/null || true)
  [ -n "$spid" ] || continue
  kill -0 "$spid" 2>/dev/null || continue
  ensure_mon
  tsft=$(python3 "$ROOT/run/tsf-keeper.py" --once 2>/dev/null | tail -1)
  [ -n "$tsft" ] || { say "no TSF sample (monitor busy or radio down)"; continue; }
  elapsed=$(python3 - "$spid" <<'PY' 2>/dev/null
import os, sys
pid = int(sys.argv[1])
f = open('/proc/%d/stat' % pid).read().rsplit(')', 1)[1].split()
start = int(f[19])
up = float(open('/proc/uptime').read().split()[0])
print(int((up - start / os.sysconf('SC_CLK_TCK')) * 1e6))
PY
)
  [ -n "${elapsed:-}" ] || continue
  offset=$(( tsft - elapsed ))
  # VALIDATION BEFORE ANY WRITE. A monitor sample can be garbage (wrong vif state,
  # a frame with no TSFT, a phy mid-reset). Writing a bad offset destroys the
  # timestamp domain mid-stream and the pad shows nothing - measured failure:
  # "clock stepped 1870695 ms -> new offset -23191915", i.e. a negative domain.
  # Rule: only accept a step that TWO consecutive samples agree on, and never ship
  # an offset that would make the frame clock go backwards.
  if [ -z "$pending" ]; then
    pending=$offset
    continue
  fi
  pdiff=$(( pending - offset )); [ "$pdiff" -lt 0 ] && pdiff=$(( -pdiff ))
  if [ "$pdiff" -gt 500000 ]; then
    say "discarding an unconfirmed sample (two samples disagreed by $(( pdiff / 1000 )) ms)"
    pending=$offset
    continue
  fi
  offset=$pending
  pending=""
  if [ -z "$prev" ]; then
    echo "$offset" > "$OFFSET_FILE"; prev=$offset
    say "offset seeded from TSF: $offset"
    continue
  fi
  diff=$(( offset - prev )); [ "$diff" -lt 0 ] && diff=$(( -diff ))
  if [ "$diff" -gt 2000000 ]; then
    echo "$offset" > "$OFFSET_FILE"
    say "clock stepped $(( diff / 1000 )) ms (confirmed twice) -> new offset $offset; asking the streamer to re-init"
    echo "$offset" > "$RESET_MARKER"
    prev=$offset
  fi
done
