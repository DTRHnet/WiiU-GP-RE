#!/bin/bash
# drc-down.sh - stop the DRC stack using only recorded PIDs.
#
# Deliberately avoids `pkill -f <pattern>`: those match the invoking shell's own
# command line and have killed this session's terminal several times.
set -uo pipefail

ROOT=/home/kali/Wiiu
RUNDIR=/var/run/drc
APIF=WiiUAP
RADIO=${RADIO:-wlan0}

say(){ printf '\n== %s\n' "$*"; }

for name in streamer netboot hostapd idle-supplicant; do
  f="$RUNDIR/$name.pid"
  [ -f "$f" ] || continue
  pid=$(cat "$f" 2>/dev/null)
  if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null && echo "stopped $name (pid $pid)"
  else
    echo "$name not running"
  fi
  rm -f "$f"
done

say "removing AP interface"
iw dev "$APIF" del 2>/dev/null && echo "  $APIF removed" || echo "  $APIF absent"

say "restoring the radio MAC"
if [ -f "$RUNDIR/$RADIO.orig-mac" ]; then
  ip link set "$RADIO" down 2>/dev/null
  ip link set "$RADIO" address "$(cat "$RUNDIR/$RADIO.orig-mac")" 2>/dev/null \
    && echo "  $RADIO MAC restored" || echo "  $RADIO MAC unchanged"
  ip link set "$RADIO" up 2>/dev/null
fi

say "restoring NetworkManager control (uplink untouched)"
for i in "$RADIO" wlan1; do
  [ -e /sys/class/net/$i ] || continue
  nmcli dev set "$i" managed yes 2>/dev/null && echo "  $i -> NM"
done

say "state"
ip route show default
ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo "  internet OK" || echo "  internet DOWN"
