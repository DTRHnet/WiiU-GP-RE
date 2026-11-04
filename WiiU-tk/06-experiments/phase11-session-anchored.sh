#!/bin/bash
# phase11-session-anchored.sh - start the console's command stream 0.3 s after the
# pad's DHCP ACK, which is when the real console does it (measured: +285 ms),
# instead of whenever we happen to launch a tool.
#
# Why this and not another replay: the decrypted capture shows the console's
# session establishment runs entirely on the command channel (50023->50123) and
# begins 285 ms after the pad's lease. Nothing is sent on 50010 into the pad, so
# there is no separate "console is here" announcement to find. Every replay we ran
# so far started seconds late, so if the pad arms a session against a deadline
# measured from DHCP, none of them could have matched.
#
# Usage: sudo ./run/phase11-session-anchored.sh [seconds]
set -uo pipefail
ROOT=/home/kali/Wiiu
IF=WiiUAP
PAD=192.168.1.11
SECS=${1:-45}
LEAD=${MEDIA_LEAD:-8}
STAMP=$(date +%H%M%S)
PCAP=$ROOT/capture/phase11-anchored-$STAMP.pcap
say() { printf '\n== %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

say "freeing the console ports"
pkill -x drcvncclient 2>/dev/null
pkill -f replay-console-media 2>/dev/null
pkill -f command-plane.py 2>/dev/null
sleep 3
for _ in $(seq 1 20); do ss -lun | grep -qE '0.0.0.0:5002[0-9]|192.168.1.10:50023' || break; sleep 0.5; done

say "forcing a fresh association so the anchor is deterministic"
HAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd_cli
if [ -e /var/run/hostapd/WiiUAP ]; then
  "$HAPD" -p /var/run/hostapd -i WiiUAP deauthenticate 40:d2:8a:17:e2:09 2>/dev/null
  echo "   deauthenticated the pad; a fresh DHCP should follow within seconds"
  rm -f /tmp/phase11-dhcp.log
fi

say "waiting for the pad's DHCP request (this is the anchor)"
# tcpdump -l prints each packet immediately; the pad's DHCP request appears as it
# associates. We watch for either the discover or the request from the pad's MAC.
( tcpdump -i "$IF" -n -l -e 'udp dst port 67' 2>/dev/null | while read -r line; do
    echo "$line"
  done ) > /tmp/phase11-dhcp.log &
DHCPW=$!
T0=$SECONDS
HIT=0
while [ $((SECONDS - T0)) -lt 240 ]; do
  if [ -s /tmp/phase11-dhcp.log ]; then HIT=1; break; fi
  sleep 0.2
done
kill -INT $DHCPW 2>/dev/null
if [ "$HIT" = "1" ]; then
  echo "   DHCP request seen after $((SECONDS - T0))s - starting the console sequence now"
else
  echo "   no DHCP request within 240s (pad asleep or already leased)"
  echo "   continuing anyway; power-cycle the pad's screen to force a re-lease"
fi

say "capturing $PCAP"
tcpdump -i "$IF" -n -w "$PCAP" udp >/dev/null 2>&1 &
CPID=$!

say "console command stream from t=0 (acks ours), media begins ${LEAD}s in"
python3 "$ROOT/run/command-plane.py" --mode console --seconds "$SECS" --state-period 4 &
CMDPID=$!
sleep "$LEAD"
python3 "$ROOT/run/replay-console-media.py" --pad "$PAD" \
        --truth "$ROOT/out/evidence/replay-ours" --ts-shift --loops 20 &
RPID=$!
wait $CMDPID 2>/dev/null
kill -INT $RPID 2>/dev/null
sleep 1
kill -INT $CPID 2>/dev/null
sleep 1

say "score"
python3 "$ROOT/tests/score-live-session.py" "$PCAP" 2>/dev/null | grep -E "datagrams over|50120|50010|resync|frames |fps " | head -8
echo
echo "state timeline:"; grep -E "STATE" /tmp/command-plane-*.log 2>/dev/null | tail -8
