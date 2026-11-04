#!/bin/bash
# reset-watcher.sh - re-seed the media clock whenever the radio firmware resets.
#
# Why: the media clock can only be seeded from a monitor-vif TSF sample, and on this
# radio a monitor vif CANNOT be re-tuned while the AP is running (measured:
# `iw dev mon0 set channel 149 HT20` exits 0 but leaves the vif with no channel, so
# it captures nothing). Therefore no live refiner can keep the offset correct.
#
# What does work is a fresh seed at streamer start. So the trigger has to be an
# event, not a poll: every iwlwifi firmware reset also resets the phy TSF (measured
# offsets 1003 -> 173 -> 87.5 -> 71 -> 61 -> 6 -> 19 s across resets), and the kernel
# prints it. Watch dmesg, and on a new reset restart the supervised session, which
# reseeds from a freshly created monitor vif.
#
# Usage: sudo ./run/reset-watcher.sh &
set -uo pipefail
ROOT=/home/kali/Wiiu
POLL=${POLL:-5}
say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

exec 7>/var/run/drc/reset-watcher.lock
flock -n 7 || { echo "reset-watcher already running"; exit 0; }

marker() { dmesg 2>/dev/null | grep -c "restart completed"; }
last=$(marker)
say "reset-watcher up (poll ${POLL}s, ${last} resets so far)"

while :; do
  sleep "$POLL"
  now=$(marker)
  if [ "$now" -gt "$last" ]; then
    say "firmware reset detected (+$((now-last))) - the phy TSF moved, so the frame clock is stale; restarting the session to reseed"
    "$ROOT/run/uvc-kill-live.sh" >/dev/null 2>&1
    sleep 3
    "$ROOT/run/uvc-start.sh" 8>&- 2>&1 | tail -2
    last=$now
  fi
done
