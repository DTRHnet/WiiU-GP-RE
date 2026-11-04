#!/bin/bash
# phase3-replay-console.sh - replay the real console's captured media to the pad.
#
# This is the isolating experiment the whole project has been missing. Everything
# we control is now console-identical on the wire (verified: envelope, options,
# 5 chunk-ends/frame, 16683 us cadence, format bytes 00 00 00 00, 5 ms format
# lead, 1 Hz 50125 table, init on the first frame only) and the pad still asks
# for a resync ~61 times a second. So this sends the CONSOLE'S OWN bytes - 73,500
# verbatim video datagrams plus 41,355 audio/format datagrams decrypted from
# capture/console-truth.pcap - over our AP, on the console's source ports and
# with its recorded timing.
#
#   pad displays  -> the payload/encoder is the gate (our x264 DRH output), and
#                    the next work is a byte-level diff against
#                    out/evidence/truth/console-messages/video_first_frame.bin
#   pad still asks for resyncs -> the gate is outside the media plane
#                    (clock/control), because these bytes came off a real console
#
# Usage: sudo ./run/phase3-replay-console.sh [seconds] [--ts-shift]
#   Starts by waiting (WAIT_S=300 by default) for the pad to attach, then
#   captures before the first replayed datagram, so the run covers everything.
set -uo pipefail

ROOT=/home/kali/Wiiu
IF=WiiUAP
PAD=192.168.1.11
SECS=${1:-90}
SHIFT=${2:-}
# optional: --truth <dir> replays a different capture set. Use it to replay OUR
# own stream (tests/pcap-to-replay.py) through the identical path, which makes
# the payload the only variable left.
TRUTH=""
if [ "${3:-}" = "--truth" ] && [ -n "${4:-}" ]; then TRUTH="--truth $4"; fi
STAMP=$(date +%H%M%S)
PCAP=$ROOT/capture/phase3-replay-$STAMP.pcap
TVNC=$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient
export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib

say() { printf '\n== %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
. "$ROOT/run/_wait-for-pad.sh"

say "parking the watchdog"
ps -eo pid,args | awk '/drc[-]watchdog\.sh/ {print $1}' | xargs -r kill 2>/dev/null

say "freeing the media ports before the pad attaches"
pkill -x drcvncclient && echo "   stopped drcvncclient"
for _ in $(seq 1 20); do ss -lun | grep -q '0.0.0.0:50020' || break; sleep 0.5; done
ss -lun | grep -q '0.0.0.0:50020' && { echo "   FAIL: 50020 still held"; exit 1; }
echo "   media ports free"

say "waiting for the pad to attach (the whole replay is captured)"
wait_for_pad "${WAIT_S:-300}" || exit 1

say "capturing $PCAP while the console's own media is replayed"
tcpdump -i "$IF" -n -w "$PCAP" udp >/dev/null 2>&1 &
TCPID=$!
sleep 2

say "replaying the real console stream for ${SECS}s"
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" --seconds "$SECS" $SHIFT $TRUTH
RCPID=$?

sleep 1
kill -INT $TCPID 2>/dev/null; wait $TCPID 2>/dev/null

say "scoring what actually went out"
python3 "$ROOT/tests/score-live-session.py" "$PCAP"

say "restoring our own streamer (so the stack is as it was)"
setsid nohup env DRC_SYNTHETIC_TSF=1 "$TVNC" -joystick 127.0.0.1:5900 \
  > "$ROOT/out/logs/drcvnc-restored.log" 2>&1 < /dev/null &
echo $! > /var/run/drc/streamer.pid
sleep 2
ss -lun | grep -q '192.168.1.10:50022' && echo "   streamer back up (pid $(cat /var/run/drc/streamer.pid))"

cat <<EOF

== read it like this
   * "the console's own" applies when --truth is out/evidence/truth (default).
     Pass --truth out/evidence/replay-ours to send OUR captured datagrams through
     the same path instead: same clock, same pacing, no command traffic, so any
     difference in the pad's behaviour is the payload.
   * The replayed stream is the console's own: 73,500 video datagrams, 5.0
     chunk-ends/frame, 16683 us cadence, options 8200838506000000 /
     8082008385060000, format bytes 00 00 00 00, plus real PCM audio.
   * If the resync rate under "pad -> 50010" is still tens per second, the pad
     is refusing a real console's bitstream, which rules the encoder out and
     points at the clock/control plane.
   * If it collapses toward zero (or the screen comes alive), the encoder is the
     gate.
   Watch the GamePad during the replay.
EOF
