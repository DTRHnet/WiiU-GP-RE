#!/bin/bash
# await-and-probe.sh - wait for the GamePad to be awake, then immediately run the
# IR/TV-remote probes.
#
# Why: on 2026-11-04 the pad oscillated between "streaming input at ~180/s" and
# "asleep / re-DHCPing", and a parallel operator session was also driving it.
# Binding 50023 is contested, so the probe sniffs instead (ir-sniff-probe.py),
# and this wrapper simply waits for the window where the pad answers at all.
#
# The liveness signal is the pad's own input stream (50122 -> 50022), which is
# present exactly when its LVC services are up (BOOT-AND-MODES.md §10).
set -uo pipefail
ROOT=/home/kali/Wiiu
IF=WiiUAP
THRESH=${THRESH:-30}          # input packets per 1 s that count as "awake"
TRIES=${TRIES:-150}           # 150 x 4 s = 10 minutes
LOG=$ROOT/out/logs/await-probe-$(date +%H%M%S).log

mkdir -p "$ROOT/out/logs" "$ROOT/out/evidence"
{
  echo "== waiting for the pad (threshold ${THRESH} pkt/s on 50122), log $LOG"
  for i in $(seq 1 "$TRIES"); do
    n=$(timeout 1 tcpdump -i "$IF" -nn -q 'src 192.168.1.11 and port 50122' 2>/dev/null | wc -l)
    printf '%s awake-check %3d pkt/s\n' "$(date +%H:%M:%S)" "$n"
    if [ "$n" -gt "$THRESH" ]; then
      echo "== pad is awake at $(date +%H:%M:%S) - probing now"
      OUT=$ROOT/out/evidence/rce-ir-live-$(date +%H%M%S)
      python3 "$ROOT/research/rce-hunt/ir-sniff-probe.py" \
          --filter B,TV1,H1,H2 --out "$OUT"
      echo "== probe done -> $OUT"
      exit 0
    fi
    sleep 3
  done
  echo "== pad never woke within the window"
  exit 1
} 2>&1 | tee -a "$LOG"
