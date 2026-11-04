#!/bin/bash
# uvc-live.sh - stream the Kali desktop to the GamePad and KEEP DOING IT.
#
# This is the working configuration, confirmed on hardware 2026-11-04 (video on
# the pad + pad input driving the Kali cursor/touch):
#
#   * the media clock MUST be the AP's real TSF, because the pad schedules
#     playback against the TSF it syncs from our beacons. GetTsf() has no
#     /sys/class/net/<if>/tsf on iwlwifi, so the stack runs on the synthetic
#     monotonic clock plus /var/run/drc/tsf-offset-us, and that offset must be
#     seeded from mon0's radiotap TSFT *and kept refined while the streamer
#     runs*. A stale offset (2 s while the AP TSF was 1637 s) makes every frame
#     look ~27 minutes stale: the pad shows nothing. A/B tested.
#   * no fixed duration: runs until Ctrl-C or `run/uvc-stop.sh`.
#
# Usage: sudo ./run/uvc-live.sh            (Ctrl-C to stop)
set -uo pipefail

ROOT=/home/kali/Wiiu
IF=WiiUAP
PAD=192.168.1.11
STAMP=$(date +%H%M%S)
LOG=$ROOT/out/logs/live-$STAMP.log
say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
mkdir -p "$ROOT/out/logs"

exec 9>/var/run/drc/hw.lock
flock -n 9 || { echo "another DRC session already owns the hardware"; exit 1; }

[ -x "$ROOT/out/bin/bin/drcvncclient" ] || { echo "no drcvncclient build"; exit 1; }
export LD_LIBRARY_PATH="$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib:${LD_LIBRARY_PATH:-}"
export DRC_SYNTHETIC_TSF=1

SPID=""; TSFPID=""
cleanup() {
  say "stopping"
  [ -n "$SPID" ] && kill -INT "$SPID" 2>/dev/null
  pkill -f tsf-from-monitor.py 2>/dev/null
  pkill -f tsf-keeper.py 2>/dev/null
  exit 0
}
trap cleanup INT TERM

say "freeing console ports"
for pat in drcvncclient replay-console-media command-plane.py; do pkill -f "$pat" 2>/dev/null; done
sleep 3
if ss -lun | grep -qE ':(5002[0-9])\b'; then
  ss -lun | grep -E ':(5002[0-9])\b'; echo "FAIL: ports busy"; exit 1
fi

# shellcheck source=/dev/null
. "$ROOT/run/_wait-for-pad.sh"
say "waiting for the pad (power it on / tap the screen)"
wait_for_pad 600 || { echo "FAIL: pad never associated"; exit 1; }

if ! pgrep -x x11vnc >/dev/null; then
  say "starting x11vnc"
  x11vnc -display "${DISPLAY_TO_SERVE:-:0}" -localhost -rfbport 5900 \
         -nopw -forever -shared -scale "${SCALE:-0.46875}" -bg -quiet -noxdamage \
    || { echo "FAIL: x11vnc"; exit 1; }
  sleep 2
fi

say "seeding the media clock from the AP's real TSF (mon0)"
rm -f /var/run/drc/tsf-reset
pkill -f tsf-from-monitor.py 2>/dev/null
  pkill -f tsf-keeper.py 2>/dev/null
# One-shot monitor vif: a permanent monitor capture alongside the AP adds radio
# load, and this AX210 firmware crashes under it (`iwlwifi: Device error - SW
# reset`, which resets the phy TSF and drops the pad). Create it, take a single
# TSF sample, remove it again.
if ! iw dev mon0 info >/dev/null 2>&1; then
  iw dev wlan0 interface add mon0 type monitor 2>/dev/null
  sleep 1
  MON_CREATED=1
fi
# TUNE IT. A monitor vif that has never been given a channel receives NOTHING on
# this driver, which makes the sample below return empty and the whole run abort
# (or, worse, ship a stale offset). This was the actual reason the clock kept
# being wrong after every rebuild.
ip link set mon0 up 2>/dev/null
iw dev mon0 set channel "${CHANNEL:-149}" HT20 2>/dev/null
sleep 2
# Require TWO consecutive agreeing samples before trusting the seed. A single
# sample can be garbage (monitor vif mid-reset), and seeding from it puts the whole
# session in the wrong timestamp domain - which looks exactly like "video stopped
# working" with nothing else wrong.
seed_tsf() {
  local a b d
  for _ in 1 2 3 4 5 6; do
    a=$(python3 "$ROOT/run/tsf-keeper.py" --once 2>/dev/null | tail -1)
    [ -n "$a" ] || { sleep 1; continue; }
    sleep 1
    b=$(python3 "$ROOT/run/tsf-keeper.py" --once 2>/dev/null | tail -1)
    [ -n "$b" ] || continue
    d=$(( b - a )); [ "$d" -lt 0 ] && d=$(( -d ))
    # Each sample costs ~3 s (tshark window), so two samples legitimately differ
    # by 3-5 s. Accept a monotonic pair within 12 s; reject jumps and backwards
    # samples (the failure mode that put the offset in a negative domain).
    if [ "$b" -gt "$a" ] && [ "$d" -lt 12000000 ]; then
      echo "$b"
      return 0
    fi
  done
  return 1
}
TSF_REF=$(seed_tsf)
# Keep mon0 alive and tuned: tsf-guard needs it every 25 s to keep the offset
# correct. Deleting it here made the guard sample nothing and silently stop
# correcting the clock after the first firmware reset - exactly the "video worked
# once then never again" behaviour.
if [ -z "${TSF_REF:-}" ]; then
  echo "FAIL: cannot read the AP TSF from mon0 - refusing to run with a wrong clock"
  echo "      (is mon0 tuned to ch149? try: iw dev mon0 set channel 149 HT20)"
  echo "      (video will silently not appear if this is skipped)"
  exit 1
fi
echo "$TSF_REF" >/var/run/drc/tsf-offset-us
say "AP TSF = $TSF_REF us ($(awk "BEGIN{printf \"%.1f\", $TSF_REF/1e6}") s) - seeded"

say "starting the streamer (log: $LOG)"
# Mouse mode by default: buttons then map to keys/clicks over VNC
# (A=Enter B=Backspace X=Space Y=Tab, d-pad=arrows, ZL/ZR=click, L/R=right
# click, +/-=Copy/Paste, Home=Escape). -joystick sends every button to the
# uinput feeder instead, where nothing on the desktop reads it - that is why
# the buttons did nothing. Set JOYSTICK=1 to get the old behaviour.
"$ROOT/out/bin/bin/drcvncclient" ${JOYSTICK:+-joystick} 127.0.0.1:5900 >"$LOG" 2>&1 9>&- &
SPID=$!
echo "$SPID" >/var/run/drc/streamer.pid

# Light clock guard: one TSF sample per minute, and on a phy step it rewrites the
# offset and asks the streamer to re-init. A permanent monitor capture made the
# AX210 firmware crash more often, so this keeps monitor use negligible.
# Do NOT re-seed the clock while streaming. The frame clock only has to run at the
# TSF's RATE with a constant offset, and our monotonic clock does exactly that, so
# one validated seed is valid for the whole session. Re-writing the offset mid-
# stream moves the timestamp domain (measured damage: a guard write of
# "-23191915" put the session into a negative domain and the pad showed nothing).
# The guard is therefore started in DETECT-ONLY mode: it logs a phy step so the
# cause is visible, but never touches the running stream. A phy reset means a new
# session anyway (restart via run/uvc-stop.sh && run/uvc-start.sh).
if [ "${DRC_TSF_GUARD_WRITE:-0}" = "1" ]; then
  nohup /bin/bash "$ROOT/run/tsf-guard.sh" --period 25 \
        >>"$ROOT/out/logs/tsf-guard.log" 2>&1 9>&- &
  TSFPID=$!
  say "clock guard in WRITE mode (diagnostic only - not recommended while streaming)"
else
  say "clock seeded once; no mid-stream re-seeding (set DRC_TSF_GUARD_WRITE=1 to override)"
fi
sleep 1
OFF=$(cat /var/run/drc/tsf-offset-us 2>/dev/null)
say "offset now $OFF (refined every second)"
# Guard: the frame clock must start near the AP's current TSF. A negative or tiny
# offset means the phy TSF reset under us (measured 2026-11-04: 1003 s -> 0), and
# shipping that makes the pad drop to "could not connect".
TSF_NOW=$(python3 "$ROOT/run/tsf-keeper.py" --once 2>/dev/null | tail -1)
if [ -n "${TSF_NOW:-}" ] && [ -n "${OFF:-}" ]; then
  DIFF=$(( (TSF_NOW - OFF) / 1000000 )); DIFF=${DIFF#-}
  say "clock check: AP TSF $((TSF_NOW/1000000))s, offset $((OFF/1000000))s, diff ${DIFF}s"
  if [ "$DIFF" -gt 60 ]; then
    say "WARNING: offset and AP TSF disagree by ${DIFF}s - the phy TSF probably reset."
    say "         video timestamps will not match the pad's clock; expect no picture."
  fi
fi

say "RUNNING - the pad should show this desktop; Ctrl-C or run/uvc-stop.sh to stop"
while kill -0 "$SPID" 2>/dev/null; do
  sleep 10
  ASSOC=$(iw dev "$IF" station dump 2>/dev/null | grep -c '^Station')
  OFFS=$(cat /var/run/drc/tsf-offset-us 2>/dev/null)
  FPS=$(grep -c 'error' "$LOG" 2>/dev/null)
  say "pad=$([ "$ASSOC" -gt 0 ] && echo associated || echo absent) tsf_offset=$OFFS streamer_errors=$FPS"
done

say "streamer exited unexpectedly; last 10 log lines:"
tail -10 "$LOG"
pkill -f tsf-from-monitor.py 2>/dev/null
  pkill -f tsf-keeper.py 2>/dev/null
exit 1
