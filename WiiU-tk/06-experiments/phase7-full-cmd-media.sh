#!/bin/bash
# phase7: the combination never actually run before - media + the console's whole
# command plane, with our ACKs of the pad's replies (earlier full-session replays
# replayed the console's *recorded* ACKs, whose sequence numbers do not match the
# pad's current replies).
set -uo pipefail
ROOT=/home/kali/Wiiu; PAD=192.168.1.11; SECS=${1:-75}
[ "$(id -u)" = 0 ] || exit 1
. "$ROOT/run/_wait-for-pad.sh"
pkill -x drcvncclient 2>/dev/null
for _ in $(seq 1 20); do ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' || break; sleep 0.5; done
wait_for_pad 300 || exit 1
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" --truth "$ROOT/out/evidence/replay-ours" \
        --ts-shift --loops 40 > "$ROOT/out/logs/phase7-media.log" 2>&1 &
RPID=$!
sleep 4
python3 "$ROOT/run/command-plane.py" --mode full --seconds "$SECS" --state-period 3
kill -INT $RPID 2>/dev/null; wait $RPID 2>/dev/null
