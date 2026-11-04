#!/bin/bash
# drc-watchdog.sh - keep the DRC AP + streamer alive unattended.
#
# The stack has been observed to die in two ways while nobody was watching:
#   1. NetworkManager reclaims wlan0 -> the AP vif disappears (now permanently
#      unmanaged, but a phy reset can still take the vif with it);
#   2. hostapd exits gracefully, leaving no beacon and no DHCP.
# Both look identical from the pad's side: it drops and waits. This watchdog
# re-runs drc-up.sh when any essential piece is missing, so a sleeping operator
# wakes up to a working link.
#
# Usage: setsid nohup ./run/drc-watchdog.sh > out/logs/watchdog.log 2>&1 &
set -uo pipefail
ROOT=/home/kali/Wiiu
RUNDIR=/var/run/drc
INTERVAL=${INTERVAL:-30}
log(){ echo "[$(date '+%F %T')] $*"; }

log "watchdog starting (interval ${INTERVAL}s)"
while :; do
  broken=""
  [ -e /sys/class/net/WiiUAP ] || broken="WiiUAP missing"
  if [ -z "$broken" ] && [ -f "$RUNDIR/hostapd.pid" ]; then
    kill -0 "$(cat "$RUNDIR/hostapd.pid" 2>/dev/null)" 2>/dev/null || broken="hostapd dead"
  fi
  # The pid file can be stale (the streamer is restarted by hand during
  # experiments), so fall back to a name check before declaring it dead.
  if [ -z "$broken" ]; then
    spid=$(cat "$RUNDIR/streamer.pid" 2>/dev/null || true)
    if [ -n "$spid" ] && ! kill -0 "$spid" 2>/dev/null; then
      pgrep -x drcvncclient >/dev/null || broken="streamer dead"
    elif ! pgrep -x drcvncclient >/dev/null; then
      broken="streamer dead"
    fi
  fi
  if [ -z "$broken" ] && ! ss -lun 2>/dev/null | grep -q '192.168.1.10:50022'; then
    broken="streamer sockets missing"
  fi
  if [ -z "$broken" ] && ! ss -lun 2>/dev/null | grep -q '0.0.0.0:50021'; then
    broken="media sockets missing"
  fi

  # Beacon-level check: after an iwlwifi firmware SW reset the AP stops
  # TRANSMITTING while hostapd stays alive and every pid/socket check above still
  # passes. Measured 2026-11-04: tx_packets grows by 0 and no beacon ever goes out
  # again, so the pad cannot associate and sits on "could not connect". Nothing
  # but a driver reload fixes that, so escalate to ap-recover.sh instead of
  # drc-up.sh.
  if [ -z "$broken" ] && ! "$ROOT/run/ap-health.sh" --quiet; then
    broken="AP not transmitting (firmware reset)"
    radio_dead=1
  fi

  if [ -n "$broken" ]; then
    if [ "${radio_dead:-0}" = "1" ]; then
      log "REPAIR: $broken -> running ap-recover.sh (driver reload)"
      "$ROOT/run/ap-recover.sh" 8>&- >> "$ROOT/out/logs/watchdog-repair.log" 2>&1 \
        && log "radio recovery finished" || log "radio recovery failed (see watchdog-repair.log)"
      radio_dead=0
      sleep "$INTERVAL"
      continue
    fi
    log "REPAIR: $broken -> running drc-up.sh"
    "$ROOT/run/drc-down.sh" >/dev/null 2>&1
    sleep 2
    if "$ROOT/run/drc-up.sh" >> "$ROOT/out/logs/watchdog-repair.log" 2>&1; then
      log "repair finished"
      # drc-up.sh starts its own bare streamer (joystick mode, no media clock).
      # Replace it with the supervised one, which seeds the AP-TSF clock - without
      # that the pad shows nothing even though video is on the wire.
      "$ROOT/run/uvc-kill-live.sh" >/dev/null 2>&1
      "$ROOT/run/uvc-start.sh" 8>&- >> "$ROOT/out/logs/watchdog-repair.log" 2>&1 \
        && log "supervised streamer started" || log "could not start supervised streamer"
    else
      log "repair reported a failure (see watchdog-repair.log)"
    fi
  fi
  sleep "$INTERVAL"
done
