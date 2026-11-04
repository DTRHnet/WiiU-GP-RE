#!/bin/bash
# ap-health.sh - is our AP actually beaconing? Exit 0 = healthy, 1 = dead.
#
# Why a beacon check and not "is the pad associated": a sleeping pad has no
# station entry either, so station presence cannot distinguish "pad asleep" from
# "AP stopped beaconing". With no stations, the only thing an AP transmits is
# beacons (10/s at the default interval), so tx_packets must keep growing. If it
# does not and hostapd is alive, the radio has stopped working - which on this
# AX210 happens after every `iwlwifi: Device error - SW reset` (measured
# 2026-11-04: the AP never recovers on its own, the pad drops to "could not
# connect" and stays there).
#
# Usage: sudo ./run/ap-health.sh [--quiet]
IF=WiiUAP
TX=/sys/class/net/$IF/statistics/tx_packets
q=0
[ "${1:-}" = "--quiet" ] && q=1

fail() { [ "$q" = "1" ] || echo "$*"; exit 1; }

[ -r "$TX" ] || fail "AP interface $IF missing"
pgrep -x hostapd >/dev/null || fail "hostapd is not running"
iw dev "$IF" info >/dev/null 2>&1 || fail "$IF is not present"

before=$(cat "$TX")
sleep 5
after=$(cat "$TX")
delta=$(( after - before ))

# No stations: only beacons are transmitted, ~50 frames in 5 s.
# With stations there is real traffic; either way delta should be large.
if [ "$delta" -lt 5 ]; then
  fail "AP is not transmitting: tx_packets grew by $delta in 5 s (beacons stopped)"
fi
[ "$q" = "1" ] || echo "AP healthy: tx_packets +$delta in 5 s, hostapd up"
exit 0
