#!/bin/bash
# restore-stock-mac80211.sh - undo run/01-load-tsf.sh and go back to the distro build.
#
# Why: the confirmed-working session (12:27-12:43) ran on the STOCK mac80211; a
# locally built patched mac80211 (which only adds an inert /sys/class/net/<if>/tsf
# node that returns UINT64_MAX on iwlwifi) has been loaded since ~15:10. A different
# build changes the AP/driver behaviour it implements, so the audit
# (research/FAILURE-CAUSES-AUDIT.md) lists reverting it as the first thing to test.
#
# Cost: unloading mac80211 unloads every wireless driver on the box, so the uplink
# drops for ~15-30 s. Everything is reloaded before exit, and the script verifies
# that the wireless interfaces came back.
#
# Usage: sudo ./run/restore-stock-mac80211.sh
set -uo pipefail
ROOT=/home/kali/Wiiu
say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

say "stopping the DRC stack"
"$ROOT/run/uvc-kill-live.sh" >/dev/null 2>&1 || true
pkill -x hostapd 2>/dev/null; pkill -x netboot 2>/dev/null; pkill -x wpa_supplicant 2>/dev/null
sleep 2

HOLDERS=$(ls /sys/module/mac80211/holders/ 2>/dev/null)
say "drivers to restore: ${HOLDERS:-none}"

say "unloading wireless drivers (uplink will drop)"
for h in $HOLDERS; do modprobe -r "$h" 2>/dev/null || rmmod "$h" 2>/dev/null || true; done
for h in $HOLDERS; do modprobe -r "$h" 2>/dev/null || true; done
modprobe -r mac80211 2>/dev/null || rmmod mac80211 2>/dev/null || true
if lsmod | grep -q '^mac80211'; then
  say "FAIL: could not unload mac80211 (still in use) - nothing changed"
  exit 1
fi

say "loading the STOCK mac80211"
if ! modprobe mac80211; then
  say "FAIL: stock mac80211 did not load - reloading drivers anyway"
fi

say "reloading drivers"
modprobe -a $HOLDERS 2>/dev/null || true
sleep 4

say "verifying"
ok=1
for i in wlan0 wlan1; do
  if [ -e "/sys/class/net/$i" ]; then echo "   $i present"; else echo "   $i MISSING"; ok=0; fi
done
for i in wlan0 wlan1 WiiUAP; do
  [ -e "/sys/class/net/$i/tsf" ] && echo "   WARNING: $i still has a tsf node (patched still loaded?)"
done
lsmod | grep -q '^mac80211' && echo "   mac80211 loaded: $(modinfo -n mac80211 2>/dev/null)" || { echo "   mac80211 NOT loaded"; ok=0; }

say "waiting for the uplink to come back"
for _ in $(seq 1 30); do
  if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then say "uplink is back"; break; fi
  sleep 2
done
ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 || say "WARNING: uplink has not answered yet (check wlan1 / NetworkManager)"

say "bringing the DRC AP back up"
"$ROOT/run/drc-up.sh" 2>&1 | tail -6

exit "$((1-ok))"
