#!/bin/bash
# ap-recover.sh - rebuild the DRC radio stack after an iwlwifi firmware reset.
#
# Measured failure (2026-11-04, AX210): the firmware hits
#   iwlwifi: Unhandled alg: 0x71b / 0x3000707   (repeating)
#   iwlwifi: Device error - SW reset
#   iwlwifi: restart completed
# and afterwards the AP interface stops beaconing for good. hostapd is still
# "running" but nothing is transmitted, so the pad cannot associate and sits on
# "could not connect". Only a driver reload brings the radio back, and after the
# reload iwlwifi's LAR marks every 5 GHz channel no-IR until an idle
# wpa_supplicant's country hint plus a scan clears it.
#
# This script does that whole sequence, then re-runs drc-up.sh. It is safe to
# call from a watchdog: it refuses to touch the interface carrying the uplink
# (drc-up.sh enforces that too).
#
# Usage: sudo ./run/ap-recover.sh
set -uo pipefail
ROOT=/home/kali/Wiiu
RADIO=wlan0
WPAS=$ROOT/build/hostap-2.12/wpa_supplicant/wpa_supplicant
GOOD=$ROOT/out/logs/ap-recover-ok

say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

say "stopping DRC processes"
"$ROOT/run/uvc-kill-live.sh" >/dev/null 2>&1
pkill -x hostapd 2>/dev/null
pkill -x netboot 2>/dev/null
pkill -x wpa_supplicant 2>/dev/null
sleep 2
iw dev WiiUAP del 2>/dev/null
sleep 1

say "reloading iwlwifi"
modprobe -r iwlmvm iwlwifi 2>/dev/null
sleep 2
modprobe iwlwifi || { say "FAIL: cannot reload iwlwifi"; exit 1; }
sleep 3

say "clearing stale supplicant state and unlocking 5 GHz"
rm -rf /var/run/wpa-idle /var/run/wpa-wlan0 /var/run/wpa-wlan0.pid /var/run/wpa-idle.pid 2>/dev/null
printf 'ctrl_interface=/var/run/wpa-idle\ncountry=CA\n' > /var/run/wpa-idle.conf
ip link set "$RADIO" up
setsid nohup "$WPAS" -i "$RADIO" -c /var/run/wpa-idle.conf -D nl80211 \
  >"$ROOT/out/logs/wpa-idle.log" 2>&1 < /dev/null &
sleep 6
iw dev "$RADIO" scan >/dev/null 2>&1
PHY=$(basename "$(readlink -f "/sys/class/net/$RADIO/phy80211")")
if iw phy "$PHY" info 2>/dev/null | grep -A1 "\[149\]" | grep -q "no IR"; then
  say "ch149 still no-IR, retrying scan"
  sleep 3
  iw dev "$RADIO" scan >/dev/null 2>&1
fi

say "bringing the AP back up"
"$ROOT/run/drc-up.sh" 2>&1 | tail -6
if ! iw dev WiiUAP info >/dev/null 2>&1; then
  say "FAIL: WiiUAP did not come up"
  exit 1
fi
say "restarting the streamer supervisor"
"$ROOT/run/uvc-start.sh" 2>&1 | tail -2
touch "$GOOD"
say "recovery complete"
