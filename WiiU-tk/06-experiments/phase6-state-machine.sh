#!/bin/bash
# phase6-state-machine.sh - does the pad change STATE when the console's command
# plane is present?
#
# Setup: our own captured media is replayed (proven to keep the pad quiet, so it
# removes the data plane as a variable), and one command mode is exercised at a
# time. run/command-plane.py owns 192.168.1.10:50023, ACKs every pad reply, and
# polls svc 4/0x05 - the documented state oracle - so the outcome is a state
# timeline, not an opinion.
#
#   state   : queries only (baseline; expect index 0 = pad painting its own UI)
#   blobs   : + the console's 4-fragment svc 0/method 0x11 state push, M M M S,
#             at the console's own cadence (~29 fragments/s)
#   uvcuac  : + the console's 56-byte UVC/UAC query at 1/s, payload byte[0]
#             flipping to 1 after the first validated reply (never done before)
#   full    : all of the above together, as a console starts a session
#
# Usage: sudo ./run/phase6-state-machine.sh [seconds_per_mode]
set -uo pipefail
ROOT=/home/kali/Wiiu
PAD=192.168.1.11
SECS=${1:-45}
TRUTH=${TRUTH:-$ROOT/out/evidence/replay-ours}
say() { printf '\n######## %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
. "$ROOT/run/_wait-for-pad.sh"

say "freeing the console ports"
pkill -x drcvncclient 2>/dev/null && echo "   stopped streamer"
for _ in $(seq 1 20); do ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' || break; sleep 0.5; done
ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' && { echo "   FAIL: ports busy"; exit 1; }
echo "   ports free"

wait_for_pad "${WAIT_S:-300}" || exit 1

say "starting the media replayer (our own media, quiet baseline)"
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" --truth "$TRUTH" \
        --ts-shift --loops 40 > "$ROOT/out/logs/phase6-media.log" 2>&1 &
RPID=$!
sleep 5

for mode in state blobs uvcuac full; do
  say "command mode: $mode (${SECS}s)"
  python3 "$ROOT/run/command-plane.py" --mode "$mode" --seconds "$SECS" \
          --state-period 2 2>&1 | grep -E "STATE|state |UVC/UAC|done:" | sed 's/^/   /'
  sleep 2
done

kill -INT $RPID 2>/dev/null; wait $RPID 2>/dev/null

say "restoring our streamer"
BASE_US=$(( ( $(date +%s%3N) ) & 0xFFFFFFFF ))
echo "$BASE_US" > /var/run/drc/tsf-offset-us
export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib
setsid nohup env DRC_SYNTHETIC_TSF=1 DRC_TSF_OFFSET_US="$BASE_US" \
  "$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient" -joystick 127.0.0.1:5900 \
  > "$ROOT/out/logs/drcvnc-restored.log" 2>&1 < /dev/null &
echo $! > /var/run/drc/streamer.pid

cat <<'EOF'

######## how to read it
   "STATE ? -> N" is the pad reporting its own state via svc 4/0x05.
   Baseline on the notice screen is index 0. Any change away from 0 while a
   command mode runs means that mode moved the pad, and the mode that does it is
   the missing session step. No change anywhere => the pad is not waiting for
   anything on the command plane, and the gate is elsewhere.
EOF
