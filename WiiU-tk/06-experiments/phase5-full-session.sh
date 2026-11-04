#!/bin/bash
# phase5-full-session.sh - replay a COMPLETE real console session to the GamePad.
#
# This tests the operator's read: the pad boots into its own UI, tries to bring
# the console session up, and lands on "could not connect". Decrypting a real
# session showed the console performs a fixed handshake first (a clock command,
# 13 generic UIC commands, 778 state blobs on service 0/method 0x11) and only
# then streams. Our stack sends two of those messages and none of the handshake.
#
# So this replays everything the console sent - commands, video, audio, format
# messages and the 50025 table - with the console's bytes and timing, and the
# media clock placed in the pad's epoch (proven necessary: with the console's own
# ~92 s clock the pad refuses the same bytes).
#
#   pad leaves "could not connect" -> the session handshake is the gate, and the
#                                     next step is to shrink this replay down to
#                                     the minimum subset that still works
#   pad unchanged                  -> the handshake is not it; fall back to the
#                                     command-plane bisect results
#
# Usage: sudo ./run/phase5-full-session.sh [seconds] [extra replayer args]
set -uo pipefail
ROOT=/home/kali/Wiiu
IF=WiiUAP
PAD=192.168.1.11
SECS=${1:-150}
EXTRA=${2:-}
STAMP=$(date +%H%M%S)
PCAP=$ROOT/capture/phase5-session-$STAMP.pcap
TVNC=$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient
export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib

say() { printf '\n== %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
. "$ROOT/run/_wait-for-pad.sh"

say "parking the watchdog"
ps -eo pid,args | awk '/drc[-]watchdog\.sh/ {print $1}' | xargs -r kill 2>/dev/null

say "freeing every console port our streamer owns"
pkill -x drcvncclient && echo "   stopped drcvncclient"
for _ in $(seq 1 20); do ss -lun | grep -q '0.0.0.0:5002' || break; sleep 0.5; done
ss -lun | grep -qE '0.0.0.0:5002[0-9]' && { echo "   FAIL: console ports still held"; exit 1; }
echo "   ports free"

say "waiting for the pad to attach"
wait_for_pad "${WAIT_S:-300}" || exit 1

say "capturing $PCAP"
tcpdump -i "$IF" -n -w "$PCAP" udp >/dev/null 2>&1 &
TCPID=$!
sleep 1

say "replaying the complete console session for up to ${SECS}s"
python3 "$ROOT/run/replay-console-session.py" --pad "$PAD" --seconds "$SECS" \
        --iface 192.168.1.10 --ts-shift $EXTRA
sleep 1
kill -INT $TCPID 2>/dev/null; wait $TCPID 2>/dev/null

say "scoring what went out and what the pad did"
python3 "$ROOT/tests/score-live-session.py" "$PCAP"
echo
echo "   pad -> 50010 resync rate above is the pass/fail line: a real console"
echo "   session asks 3 times in 300 s. Also watch the pad's screen during the run."

say "restoring our streamer"
BASE_US=$(( ( $(date +%s%3N) ) & 0xFFFFFFFF ))
echo "$BASE_US" > /var/run/drc/tsf-offset-us
setsid nohup env DRC_SYNTHETIC_TSF=1 DRC_TSF_OFFSET_US="$BASE_US" \
  "$TVNC" -joystick 127.0.0.1:5900 \
  > "$ROOT/out/logs/drcvnc-restored.log" 2>&1 < /dev/null &
echo $! > /var/run/drc/streamer.pid
sleep 2
ss -lun | grep -q '192.168.1.10:50022' && echo "   streamer back up (pid $(cat /var/run/drc/streamer.pid))"
