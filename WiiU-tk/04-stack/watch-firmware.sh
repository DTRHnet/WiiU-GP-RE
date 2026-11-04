#!/bin/bash
# watch-firmware.sh - sample radio health + firmware resets while streaming.
#
# The AX210 firmware resets under load (`iwlwifi: Device error - SW reset`), and
# after each reset the AP stops transmitting. This prints one line per interval
# so a load change (e.g. DRC_FPS=30) can be judged by reset rate rather than by
# feel.
#
# Usage: sudo ./run/watch-firmware.sh [minutes] [interval_s]
set -uo pipefail
ROOT=/home/kali/Wiiu
MIN=${1:-8}
SECS=${2:-30}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

base=$(dmesg | grep -c "Device error - SW reset")
start=$(date +%s)
end=$(( start + MIN * 60 ))
printf '%-6s %-10s %-8s %-7s %-9s %s\n' t resets health pad resync note
last=$base
while [ "$(date +%s)" -lt "$end" ]; do
  sleep "$SECS"
  now_r=$(dmesg | grep -c "Device error - SW reset")
  if "$ROOT/run/ap-health.sh" --quiet; then health=ok; else health=DEAD; fi
  pad=$(iw dev WiiUAP station dump 2>/dev/null | grep -c '^Station')
  # resync rate over 3 s, plaintext on the AP interface (no monitor vif)
  resync=$(timeout 4 tcpdump -i WiiUAP -n -c 200 "udp and src port 50110" 2>/dev/null | wc -l)
  note=""
  [ "$now_r" -gt "$last" ] && note="RESET +$((now_r - last))"
  last=$now_r
  printf '%-6s %-10s %-8s %-7s %-9s %s\n' \
    "$(( $(date +%s) - start ))s" "$((now_r - base))" "$health" "$pad" "$resync" "$note"
done
echo "total new resets in ${MIN} min: $(( $(dmesg | grep -c 'Device error - SW reset') - base ))"
