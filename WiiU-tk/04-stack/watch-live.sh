#!/bin/bash
# watch-live.sh - one line per sample: is the pad awake, and is the media plane
# healthy, RIGHT NOW?
#
# Why this exists: several "still no picture" reports coincided with a pad that had
# gone to sleep (0 input, 0 resync, 0 command replies) while the stream carried on
# transmitting one-way. Without a shared live indicator, the operator and the
# tooling end up looking at different moments.
#
# Columns: whether the pad is on the air, its input rate, video transmit rate, its
# resync rate, the media-clock error against the AP TSF, and whether the pad is
# engaging with the session (command replies or resyncs > 0).
#
# Usage: sudo ./run/watch-live.sh [seconds] [period]
set -uo pipefail
ROOT=/home/kali/Wiiu
SECS=${1:-120}
PERIOD=${2:-2}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

elapsed_us() {
  python3 - "$1" <<'PY' 2>/dev/null
import os, sys
pid = int(sys.argv[1])
f = open('/proc/%d/stat' % pid).read().rsplit(')', 1)[1].split()
start = int(f[19])
up = float(open('/proc/uptime').read().split()[0])
print(int((up - start / os.sysconf('SC_CLK_TCK')) * 1e6))
PY
}

printf '%-9s %-7s %-8s %-9s %-8s %-7s %s\n' time pad input/s video/s resync/s clkerr engaged
end=$(( $(date +%s) + SECS ))
while [ "$(date +%s)" -lt "$end" ]; do
  pcap=/tmp/.wl-live.pcap
  rm -f "$pcap"
  timeout "$PERIOD" tcpdump -i WiiUAP -n -w "$pcap" udp 2>/dev/null || true
  read -r inp vid rs cmd < <(tshark -r "$pcap" -n -T fields -e udp.srcport 2>/dev/null |
    awk -v p="$PERIOD" '
      $1==50122{i++} $1==50020{v++} $1==50110{r++} $1==50123{c++}
      END{printf "%d %d %d %d\n", i/p, v/p, r/p, c/p}')
  off=$(cat /var/run/drc/tsf-offset-us 2>/dev/null || echo 0)
  pid=$(cat /var/run/drc/streamer.pid 2>/dev/null || echo 0)
  el=$(elapsed_us "$pid"); el=${el:-}
  tsf=$(timeout 8 python3 "$ROOT/run/tsf-keeper.py" --once 2>/dev/null | tail -1)
  clk="-"
  [ -n "$el" ] && [ -n "$tsf" ] && clk="$(( (el + off - tsf) / 1000000 ))s"
  pad="ASLEEP"; [ "${inp:-0}" -gt 20 ] && pad="AWAKE"
  eng="no"; { [ "${cmd:-0}" -gt 0 ] || [ "${rs:-0}" -gt 0 ]; } && eng="YES"
  printf '%-9s %-7s %-8s %-9s %-8s %-7s %s\n' \
    "$(date +%H:%M:%S)" "$pad" "${inp:-0}" "${vid:-0}" "${rs:-0}" "$clk" "$eng"
done
rm -f /tmp/.wl-live.pcap
