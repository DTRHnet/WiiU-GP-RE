#!/bin/bash
# bisect-inject.sh - find which command-plane message makes the GamePad request
# keyframes, by injecting one console payload at a time into a quiet session.
#
# Method (2026-11-04): our own captured media, replayed through a bare socket,
# holds the pad at 0.0 resync/s. The replayer binds only 50020/50021, so UDP
# 50023 is free - which is exactly the console's command source port. That lets
# us inject the console's own captured payloads from the console's own port,
# with the media completely untouched, and see which one the pad reacts to.
#
# Usage: sudo ./run/bisect-inject.sh [seconds_per_probe]
set -uo pipefail
ROOT=/home/kali/Wiiu
PAD=192.168.1.11
SECS=${1:-25}
TRUTH=${TRUTH:-$ROOT/out/evidence/replay-ours}
say() { printf '\n### %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

say "stopping our streamer so 50023 is free for console-parity injection"
pkill -x drcvncclient && echo "   stopped"
for _ in $(seq 1 20); do ss -lun | grep -q '0.0.0.0:50020' || break; sleep 0.5; done
ss -lun | grep -q '0.0.0.0:50020' && { echo "   FAIL: 50020 held"; exit 1; }

ping -c1 -W1 "$PAD" >/dev/null 2>&1 || { echo "   FAIL: pad asleep - wake it"; exit 1; }

say "replaying our own media (this alone keeps the pad quiet)"
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" --truth "$TRUTH" \
        --ts-shift --loops 12 > "$ROOT/out/logs/replay-bisect.log" 2>&1 &
RPID=$!
sleep 8

# baseline: media only
tcpdump -i WiiUAP -n -w /tmp/base.pcap udp >/dev/null 2>&1 &
CPID=$!
sleep 8
kill -INT $CPID 2>/dev/null; wait $CPID 2>/dev/null
BASE=$(tshark -r /tmp/base.pcap -n -Y 'udp.dstport==50010' -T fields -e frame.time_relative 2>/dev/null | wc -l)
BASE_RATE=$(( BASE / 8 ))
say "baseline with media only: ${BASE} resync datagrams in 8s (~${BASE_RATE}/s)"

printf '\n%-10s %10s  %s\n' kind resync/s verdict
for kind in uvc time uicblob generic blob332 panel; do
  out=$(python3 "$ROOT/run/probe-command.py" --pad "$PAD" --kind "$kind" \
             --seconds "$SECS" --baseline 6 2>&1)
  rate=$(printf '%s\n' "$out" | sed -n 's/.*resync during injection: \([0-9.]*\)\/s.*/\1/p' | tail -1)
  verdict=$(printf '%s\n' "$out" | sed -n 's/.*verdict: \(.*\)  (baseline.*/\1/p' | tail -1)
  printf '%-10s %10s  %s\n' "$kind" "${rate:-?}" "${verdict:-?}"
  printf '%s\n' "$out" | grep -E "error|FAIL" | sed 's/^/    /'
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
sleep 2
ss -lun | grep -q '192.168.1.10:50022' && echo "   streamer back up"

cat <<'EOF'

### reading it
   resync/s ~0 for a kind  => that console payload is harmless.
   resync/s tens          => that payload is what puts the pad into keyframe-
                              request mode; the fix belongs in how we send it.
EOF
