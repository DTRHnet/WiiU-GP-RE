#!/bin/bash
# phase9: media + command plane running, state polled, while the OPERATOR taps an
# app tile on the Quick Start Menu. Those taps travel to us in the 128-byte input
# stream; a real console would answer them by starting a session, and we never do.
set -uo pipefail
ROOT=/home/kali/Wiiu; PAD=192.168.1.11; SECS=${1:-150}
[ "$(id -u)" = 0 ] || exit 1
. "$ROOT/run/_wait-for-pad.sh"
pkill -x drcvncclient 2>/dev/null
for _ in $(seq 1 20); do ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' || break; sleep 0.5; done
wait_for_pad 300 || exit 1
tcpdump -i WiiUAP -n -w "$ROOT/capture/phase9-padinit.pcap" udp >/dev/null 2>&1 &
CPID=$!
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" --truth "$ROOT/out/evidence/replay-ours" \
        --ts-shift --loops 60 > "$ROOT/out/logs/phase9-media.log" 2>&1 &
RPID=$!
sleep 4
python3 "$ROOT/run/command-plane.py" --mode arma --seconds "$SECS" --state-period 2
kill -INT $RPID 2>/dev/null; wait $RPID 2>/dev/null
sleep 1; kill -INT $CPID 2>/dev/null; wait $CPID 2>/dev/null
python3 "$ROOT/tests/score-live-session.py" "$ROOT/capture/phase9-padinit.pcap" | tail -12
