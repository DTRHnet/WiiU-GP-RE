#!/bin/bash
# phase12-armed-stream.sh - arm the pad's session with the console's own command
# burst, THEN stream our media, and watch whether the pad accepts video while the
# command service is open.
#
# Why: a parallel line of work measured that the console's arm burst (svc 5/0x02
# plus the surrounding pre-video commands) makes the pad's cmd service leave its
# 9004 "not in session" error mode - i.e. the pad HAS an armed state that our
# streamer never enters. The display gate is very likely the same state: while
# unarmed the pad ignores the video plane (and floods resync requests when it is
# trying to paint); while armed it may accept it.
#
# Order here is deliberate: arm first (immediately), then media 2 s later, so the
# video arrives inside the armed window rather than before it.
#
# Usage: sudo ./run/phase12-armed-stream.sh [seconds]
#   TRUTH=out/evidence/truth sudo ./run/phase12-armed-stream.sh 60
#     replays the CONSOLE's media instead of ours, with the same arming. If the
#     pad paints the console's bytes while armed but not ours, the gate is the
#     payload under arming; if it paints neither, the video path never arms.
set -uo pipefail
ROOT=/home/kali/Wiiu
IF=WiiUAP
PAD=192.168.1.11
SECS=${1:-60}
STAMP=$(date +%H%M%S)
PCAP=$ROOT/capture/phase12-armed-$STAMP.pcap
say() { printf '\n== %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
. "$ROOT/run/_wait-for-pad.sh"

say "freeing the console ports"
pkill -x drcvncclient 2>/dev/null
pkill -f replay-console-media 2>/dev/null
pkill -f command-plane.py 2>/dev/null
sleep 3
for _ in $(seq 1 20); do ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' || break; sleep 0.5; done
ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' && { echo "   FAIL: ports busy"; exit 1; }
echo "   ports free"

wait_for_pad 240 || exit 1

say "capturing $PCAP"
tcpdump -i "$IF" -n -w "$PCAP" udp >/dev/null 2>&1 &
CPID=$!

say "arming the session (console burst + state push + UVC/UAC), then media"
python3 "$ROOT/run/command-plane.py" --mode full --seconds "$SECS" --state-period 2 &
CMDPID=$!
sleep 2
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" \
        --truth "${TRUTH:-$ROOT/out/evidence/replay-ours}" --ts-shift ${TS_BASE:+--ts-base $TS_BASE} --loops 30 &
RPID=$!
wait $CMDPID 2>/dev/null
kill -INT $RPID 2>/dev/null
sleep 1
kill -INT $CPID 2>/dev/null
sleep 1

say "pad-side outcome"
L=$(ls -t "$ROOT"/out/logs/command-plane-*.log 2>/dev/null | head -1)
[ -n "$L" ] && { echo "   command plane log: $L"; grep -E "STATE|reply svc|error" "$L" | tail -12; }
echo
echo "   pad replies received: $(grep -cE 'reply svc' "$L" 2>/dev/null)"
echo "   state transitions:    $(grep -c 'STATE' "$L" 2>/dev/null)"

say "wire outcome"
python3 "$ROOT/tests/score-live-session.py" "$PCAP" 2>/dev/null \
  | grep -E "datagrams over|50120|50010|resync|frames |fps |pad -> 50010" | head -8
