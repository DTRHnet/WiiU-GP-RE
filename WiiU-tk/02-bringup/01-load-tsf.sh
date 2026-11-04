#!/bin/bash
# 01 - Load the patched mac80211 that exports /sys/class/net/<iface>/tsf.
#
# libdrc needs the AP's hardware TSF clock to stamp GamePad video frames; stock
# Linux never exports it. This module adds the sysfs node (kernel/tsf-kali-7.1.5.patch).
#
# SAFETY: the module is insmod'ed from this source tree and is never installed into
# /lib/modules, so a reboot always restores the stock module. If the patched module
# fails to load, this script rolls the whole Wi-Fi stack back to stock automatically.
#
# Reloading mac80211 necessarily unloads the Wi-Fi drivers (wlan0 drops) because
# mac80211 is a single shared module. Everything is restored before exit.
#
# No patched module? Run the stack with DRC_SYNTHETIC_TSF=1 instead - see SETUP.md.
set -uo pipefail

KO=/home/kali/Wiiu/kernel/linux-source-7.1/net/mac80211/mac80211.ko
IFACE="${1:-}"

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }
[ -f "$KO" ] || { echo "missing $KO - build it first"; exit 1; }

if [ -z "$IFACE" ]; then
  echo "usage: $0 <drc-wifi-iface>   e.g. $0 wlan1"
  echo "current wireless interfaces:"
  for i in /sys/class/net/*; do
    d=$(readlink -f "$i/device/driver" 2>/dev/null | xargs -r basename)
    [ -n "$d" ] && echo "   $(basename "$i") -> $d"
  done
  exit 1
fi

# Recursively unload everything that depends on $1, depth first.
unload_deps() {
  local m="$1" h
  for h in $(ls "/sys/module/$m/holders" 2>/dev/null); do
    unload_deps "$h"
  done
  modprobe -r "$m" 2>/dev/null || rmmod "$m" 2>/dev/null || true
}

restore_stock() {
  echo "[!] rolling back to the stock mac80211"
  rmmod mac80211 2>/dev/null || true
  modprobe mac80211 2>/dev/null || true
  # shellcheck disable=SC2086
  [ -n "${PRE_MODS:-}" ] && modprobe -a $PRE_MODS 2>/dev/null
  test -n "$(ls /sys/class/net | grep -E '^(wlan|wlx)' || true)" \
    && echo "    Wi-Fi interfaces back: $(ls /sys/class/net | grep -E '^(wlan|wlx)' | tr '\n' ' ')" \
    || echo "    WARNING: no wireless interface came back - reboot to be safe"
}

# Record what is currently loaded so it can all be brought back.
PRE_MODS=$(lsmod | awk 'NR>1 {print $1}' | grep -E 'iwl|rt2|ath|rtw|mt76' | tr '\n' ' ')
echo "[1] stock mac80211: $(modinfo -n mac80211 2>/dev/null)"
echo "    wifi driver modules to restore: ${PRE_MODS:-none}"

echo "[2] unloading the Wi-Fi stack (wlan0 drops for a few seconds)"
unload_deps mac80211
if lsmod | grep -q '^mac80211'; then
  echo "    FAIL: could not unload mac80211"; exit 1
fi

echo "[3] insmod patched mac80211"
if ! insmod "$KO"; then
  echo "    FAIL: insmod rejected the module"
  dmesg | tail -5 | sed 's/^/      /'
  restore_stock
  exit 1
fi

echo "[4] reloading the drivers on top of the patched mac80211"
[ -n "$PRE_MODS" ] && modprobe -a $PRE_MODS 2>/dev/null
modprobe rt2800usb 2>/dev/null || true   # the usual DRC dongle driver
modprobe ath9k_htc 2>/dev/null || true
sleep 2

echo "[5] verification gate"
if [ ! -d "/sys/class/net/$IFACE" ]; then
  echo "    FAIL: interface $IFACE did not come back"
  restore_stock
  exit 1
fi

if [ -f "/sys/class/net/$IFACE/tsf" ]; then
  a=$(od -An -tu8 "/sys/class/net/$IFACE/tsf" 2>/dev/null | tr -d ' ')
  sleep 1
  b=$(od -An -tu8 "/sys/class/net/$IFACE/tsf" 2>/dev/null | tr -d ' ')
  echo "    tsf node PRESENT, value $a -> $b"
  if [ "$a" != "$b" ]; then
    echo "    PASS: TSF is advancing (patched module live)"
    echo
    echo "Next: run/02-pair.sh $IFACE"
    exit 0
  fi
  echo "    FAIL: TSF node exists but is static - driver lacks get_tsf()."
else
  echo "    FAIL: no /sys/class/net/$IFACE/tsf on this driver."
fi

echo "         iwlwifi has no get_tsf(); rt2800usb/RT5572 and ath9k do."
echo "         Options:"
echo "           - use an RT5572/ath9k dongle for the DRC AP, or"
echo "           - skip the patch entirely:  export DRC_SYNTHETIC_TSF=1"
echo "             (libdrc falls back to the monotonic clock)"
echo "    Restoring stock so your Wi-Fi keeps working."
restore_stock
exit 1
