#!/bin/bash
# phase4-clock-domain.sh - run OUR OWN streamer with its media clock placed in
# the domain the pad accepts, and measure whether it starts decoding.
#
# Why this exists (2026-11-04): replaying a real console's media to the pad with
# its original clock (~92 s) left the pad asking for a resync 59.7 times/s for
# 51 s. Replaying the SAME bytes with the clock rebased to (epoch_ms mod 2^32)
# microseconds - ~2797 s - made the pad go completely quiet: resync 0.0/s for
# 70 s while it kept sending input at 179/s (awake, not asleep). No other
# variable changed. Our streamer instead starts its synthetic clock at 0, i.e.
# far behind the pad's own time, which is the one property every working
# implementation has and we lacked.
#
# This runs our streamer (all console-parity fixes in) with DRC_TSF_OFFSET_US
# set so its timestamps land in that same domain, and scores the wire.
#
# Usage:  sudo ./run/phase4-clock-domain.sh [seconds] [base_us]
#   DRC_EXTRA_ENV passes knobs to the streamer, which is how the command plane
#   gets bisected after 2026-11-04 showed that replaying our own media through a
#   bare socket (no commands) silences the pad while the streamer does not:
#     sudo DRC_EXTRA_ENV="DRC_QUIET_CMDS=1" ./run/phase4-clock-domain.sh 70
#     sudo DRC_EXTRA_ENV="DRC_SEND_TIME=0"    ./run/phase4-clock-domain.sh 70
#     sudo DRC_EXTRA_ENV="DRC_SEND_UVCUAC=0"  ./run/phase4-clock-domain.sh 70
#         base_us defaults to $(date +%s%3N) & 0xFFFFFFFF  (the value that worked)
set -uo pipefail

ROOT=/home/kali/Wiiu
IF=WiiUAP
PAD=192.168.1.11
SECS=${1:-70}
TVNC=$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient
export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib

say() { printf '\n== %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
. "$ROOT/run/_wait-for-pad.sh"

# (epoch milliseconds) mod 2^32 == what the working replay used. Expressed in
# microseconds by the stack's clock, it lands ~2800 s after process start and
# advances 1:1 with wall time, so it stays in the pad's domain as time passes.
AUTO_BASE=$(( ( $(date +%s%3N) ) & 0xFFFFFFFF ))
BASE=${2:-$AUTO_BASE}
mkdir -p /var/run/drc
echo "$BASE" > /var/run/drc/tsf-offset-us   # the file wins over the env var
STAMP=$(date +%H%M%S)
PCAP=$ROOT/capture/phase4-clock-$STAMP.pcap

say "parking the watchdog (it would rewrite the clock offset)"
ps -eo pid,args | awk '/drc[-]watchdog\.sh/ {print $1}' | xargs -r kill 2>/dev/null
echo "   done"

say "freeing the media ports before the pad attaches (nothing should be streaming yet)"
pkill -x drcvncclient && echo "   stopped drcvncclient"
for _ in $(seq 1 20); do ss -lun | grep -q '192.168.1.10:50022' || break; sleep 0.5; done
ss -lun | grep -q '192.168.1.10:50022' && { echo "   FAIL: 50022 still held"; exit 1; }
echo "   media ports free"

say "waiting for the pad to attach (the whole stream is captured from its first frame)"
wait_for_pad "${WAIT_S:-300}" || exit 1
echo "   media clock base: $BASE us (= $((BASE/1000000)) s, +$((SECS)) s of runtime)"

say "now capturing $PCAP - before the first frame we send"
tcpdump -i "$IF" -n -w "$PCAP" udp >/dev/null 2>&1 &
TCPID=$!
sleep 1

say "starting OUR streamer with the clock in the accepted domain"
setsid nohup env DRC_SYNTHETIC_TSF=1 DRC_TSF_OFFSET_US="$BASE" ${DRC_EXTRA_ENV:-} \
  "$TVNC" -joystick 127.0.0.1:5900 \
  > "$ROOT/out/logs/drcvnc-phase4.log" 2>&1 < /dev/null &
echo $! > /var/run/drc/streamer.pid
sleep 3
ss -lun | grep -q '192.168.1.10:50022' || { echo "   FAIL: streamer did not start"; tail -5 "$ROOT/out/logs/drcvnc-phase4.log"; kill -INT $TCPID; exit 1; }
echo "   streamer up (pid $(cat /var/run/drc/streamer.pid))"

say "watching for ${SECS}s - the pad needs ~15-20s before it judges the stream"
sleep "$SECS"
kill -INT $TCPID 2>/dev/null; wait $TCPID 2>/dev/null

say "scoring $PCAP"
python3 "$ROOT/tests/score-live-session.py" "$PCAP"

cat <<EOF

== the one number that matters
   "pad -> 50010 (resync requests)": the goal is ~0/s. Our stack has been stuck
   at 57-61/s for every previous configuration; the console's own session is
   0.01/s. If this run reports a low rate (or the pad's screen comes alive), the
   media clock domain was the gate all along and the fix is to keep this base.

   If it is still ~60/s, the difference between this and the working replay is
   the payload, and the next step is the byte-level chunk diff against
   out/evidence/truth/console-messages/video_first_frame.bin.
EOF
