#!/bin/bash
# phase8: the console's pre-video "arm" burst, with our media already flowing.
set -uo pipefail
ROOT=/home/kali/Wiiu; PAD=192.168.1.11; MODE=${1:-arm}; SECS=${2:-45}
[ "$(id -u)" = 0 ] || exit 1
. "$ROOT/run/_wait-for-pad.sh"
pkill -x drcvncclient 2>/dev/null
for _ in $(seq 1 20); do ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' || break; sleep 0.5; done
wait_for_pad 300 || exit 1
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" --truth "$ROOT/out/evidence/replay-ours" \
        --ts-shift --loops 40 > "$ROOT/out/logs/phase8-media.log" 2>&1 &
RPID=$!
sleep 5
python3 "$ROOT/run/command-plane.py" --mode "$MODE" --seconds "$SECS" --state-period 2
# resync rate during the window
kill -INT $RPID 2>/dev/null; wait $RPID 2>/dev/null
