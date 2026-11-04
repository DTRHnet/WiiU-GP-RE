#!/bin/bash
# phase2-console-parity.sh - restart ONLY the media streamer while the pad stays
# associated, capture the wire from *before* the restart, then score it.
#
# Why this ordering matters: the streamer's first frame is the only one that
# carries the VSTRM `init` flag (console behaviour, measured). If the AP and the
# streamer restart together, that frame is emitted ~10 s before the pad
# re-associates and is never received - which is exactly what happened in the
# previous round, making the test unable to see the flag it was testing.
#
# This round tests the three remaining console-measured deltas at once:
#   1. 50025 -> 50125 96-byte table at 1 Hz        (was: never sent)
#   2. video-format bytes 4..7 = 00 00 00 00       (was: 11 11 81 08)
#   3. format -> first-video-datagram lead ~5.15ms (was: same instant)
# Attached to the same run, the `init` frame now lands on a ready pad.
#
# Success signal: the pad's resync rate (pad:50110 -> us:50010). Console
# reference: 3 datagrams in 300 s. Our broken state: 38-63/s.
#
# Usage:  sudo ./run/phase2-console-parity.sh [seconds]
set -uo pipefail

ROOT=/home/kali/Wiiu
IF=WiiUAP
PAD=192.168.1.11
SECS=${1:-35}
STAMP=$(date +%H%M)
PCAP=$ROOT/capture/phase2-parity-$STAMP.pcap
TVNC=$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient
export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib

say() { printf '\n== %s\n' "$*"; }

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

say "preconditions"
ip -brief addr show "$IF" | sed 's/^/   /'
if ! ping -c2 -W1 "$PAD" >/dev/null 2>&1; then
  echo "   FAIL: pad $PAD does not answer - wake the GamePad and retry"
  exit 1
fi
echo "   pad answers"
if ! ss -lun | grep -q '192.168.1.10:50022'; then
  echo "   WARN: no streamer currently listening (continuing - a restart is the point)"
fi

say "starting capture BEFORE the restart (so the init frame is on the wire)"
tcpdump -i "$IF" -n -w "$PCAP" udp >/dev/null 2>&1 &
TCPID=$!
sleep 2

say "stopping the existing streamer (exact-name match only)"
pkill -x drcvncclient && echo "   killed drcvncclient"
for _ in $(seq 1 20); do
  ss -lun | grep -q '192.168.1.10:50022' || break
  sleep 0.5
done
ss -lun | grep -q '192.168.1.10:50022' && { echo "   FAIL: port 50022 still held"; kill $TCPID; exit 1; }
echo "   media sockets released"

say "starting the console-parity streamer (pad stays associated)"
setsid nohup env DRC_SYNTHETIC_TSF=1 \
  "$TVNC" -joystick 127.0.0.1:5900 \
  > "$ROOT/out/logs/drcvnc-phase2.log" 2>&1 < /dev/null &
echo $! > /var/run/drc/streamer.pid
sleep 3
if ! ss -lun | grep -q '192.168.1.10:50022'; then
  echo "   FAIL: streamer did not come up"; tail -5 "$ROOT/out/logs/drcvnc-phase2.log"
  kill -INT $TCPID; exit 1
fi
echo "   streamer up: pid $(cat /var/run/drc/streamer.pid), libdrc mapped:"
grep -c libdrc "/proc/$(cat /var/run/drc/streamer.pid)/maps" | sed 's/^/      /'
ss -lun | grep -E '50025|50022' | sed 's/^/      /'

say "recording ${SECS}s - watch the GamePad screen now"
sleep "$SECS"
kill -INT $TCPID 2>/dev/null
wait $TCPID 2>/dev/null
sleep 1

say "scoring $PCAP"
python3 "$ROOT/tests/score-live-session.py" "$PCAP"

say "the pad's own view, for the record"
echo "   resync requests (should be ~0): $(ss -lun >/dev/null; echo see score above)"
cat <<EOF

== what to look at
   * resync rate: console reference is 0.01/s. Still tens per second => the
     media plane is still not decodable and these three deltas are ruled out.
   * "50125 (console sends a 96-byte table ~1/s)": should now be ~1/s, not 0.
   * "format bytes 4..7": should read 00 00 00 00.
   * "init-marked datagrams": should be >0 (one frame) and confined to the
     first frame.
   * 50125 + format bytes + lead all match AND resyncs still high => the gate is
     the payload/encoder side, and the next step is a byte-level diff of our IDR
     chunk stream against out/evidence/truth/console-messages/video_first_frame.bin.

   Stack left running. Stop with: sudo ./run/drc-down.sh
EOF
