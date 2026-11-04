#!/bin/bash
# load-patched-mac80211.sh - load the locally built mac80211 (TSF sysfs node).
#
# This is the forced variant of run/01-load-tsf.sh. That script refuses to keep the
# patched module unless /sys/class/net/<if>/tsf produces a *changing* value, which
# iwlwifi can never do (it has no get_tsf()), so it always rolls back on this
# hardware. The operator wants the patched build loaded anyway for an A/B, so this
# script skips the liveness gate and only verifies that the module loaded and the
# node exists.
#
# Cost: unloading mac80211 unloads every wireless driver, so the uplink drops for
# ~15-30 s. Drivers are restored before exit.
#
# Usage: sudo ./run/load-patched-mac80211.sh
set -uo pipefail
ROOT=/home/kali/Wiiu
KO=$ROOT/kernel/linux-source-7.1/net/mac80211/mac80211.ko
say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$KO" ] || { echo "missing $KO"; exit 1; }

say "stopping the DRC stack"
"$ROOT/run/uvc-kill-live.sh" >/dev/null 2>&1 || true
pkill -x hostapd 2>/dev/null; pkill -x netboot 2>/dev/null; pkill -x wpa_supplicant 2>/dev/null
sleep 2

HOLDERS=$(ls /sys/module/mac80211/holders/ 2>/dev/null)
say "drivers to restore: ${HOLDERS:-none}"
say "unloading wireless drivers (uplink drops)"
for h in $HOLDERS; do modprobe -r "$h" 2>/dev/null || rmmod "$h" 2>/dev/null || true; done
for h in $HOLDERS; do modprobe -r "$h" 2>/dev/null || true; done
modprobe -r mac80211 2>/dev/null || rmmod mac80211 2>/dev/null || true
if lsmod | grep -q '^mac80211'; then say "FAIL: mac80211 still loaded"; exit 1; fi

say "insmod the patched mac80211"
if ! insmod "$KO"; then
  say "FAIL: insmod rejected the module - restoring stock"
  modprobe mac80211 2>/dev/null
  modprobe -a $HOLDERS 2>/dev/null
  exit 1
fi

say "reloading drivers"
modprobe -a $HOLDERS 2>/dev/null || true
sleep 4

say "verifying"
for i in wlan0 wlan1; do [ -e "/sys/class/net/$i" ] && echo "   $i present" || echo "   $i MISSING"; done
found=0
for i in wlan0 wlan1; do [ -e "/sys/class/net/$i/tsf" ] && { echo "   $i has a tsf node -> patched module active"; found=1; }; done
[ "$found" = "1" ] || echo "   WARNING: no tsf node found - patched module may not be active"

say "waiting for the uplink"
for _ in $(seq 1 30); do ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && { say "uplink is back"; break; }; sleep 2; done
ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 || say "WARNING: uplink not answering yet"

say "bringing the DRC AP up"
"$ROOT/run/drc-up.sh" 2>&1 | tail -6
