#!/bin/bash
# find-console-channel.sh -- sequentially sweep 5GHz and report which channel carries
# the real console (BSSID cc:fb:65:b6:81:69) and the GamePad (40:d2:8a:17:e2:09).
#
# Why sequential: a background hop loop launched from a script with
# `exec > >(tee ...)` did not actually change the channel (every frame came back on
# one channel), while the same `iw dev wlan0 set channel` works when run inline. Doing
# it in the main shell removes that variable and gives a per-channel verdict.
#
# wlan0 (AX210) becomes the monitor; wlan1 (USB dongle) keeps the uplink, so nothing
# drops.
set -uo pipefail
ROOT=/home/kali/Wiiu
CAP=$ROOT/capture
mkdir -p "$CAP"
LOG=$CAP/channelsweep.log
CONSOLE=cc:fb:65:b6:81:69
PAD=40:d2:8a:17:e2:09
DWELL=${DWELL:-9}
CHANNELS=(36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 165)

exec > >(tee "$LOG") 2>&1
say(){ echo "[$(date '+%H:%M:%S')] $*"; }

restore(){
  say "--- restoring wlan0"
  sudo ip link set wlan0 down 2>/dev/null
  sudo iw dev wlan0 set type managed 2>/dev/null
  sudo ip link set wlan0 up 2>/dev/null
  sudo nmcli dev set wlan0 managed yes 2>/dev/null
  sleep 4
  say "wlan1 uplink: $(iw dev wlan1 link 2>/dev/null | head -1)"
}
trap restore EXIT

say "=== preflight: wlan1 must carry the uplink ==="
ping -c1 -W2 -I wlan1 1.1.1.1 >/dev/null 2>&1 || { say "!! wlan1 has no internet - aborting"; exit 1; }
say "wlan1 ok"

sudo nmcli dev set wlan0 managed no 2>/dev/null
sudo nmcli dev disconnect wlan0 2>/dev/null
sleep 3
sudo ip link set wlan0 down 2>/dev/null
sudo iw dev wlan0 set type monitor 2>/dev/null
sudo ip link set wlan0 up 2>/dev/null
sleep 2
say "wlan0 monitor up: $(iw dev wlan0 info 2>/dev/null | awk '/type/{print $2}')"

say "=== sweeping ${#CHANNELS[@]} channels, ${DWELL}s each ==="
BEST_CH=""; BEST_N=0
for ch in "${CHANNELS[@]}"; do
  sudo iw dev wlan0 set channel "$ch" 2>/dev/null
  actual=$(iw dev wlan0 info 2>/dev/null | awk '/channel/{print $2}')
  f=$CAP/ch$ch.pcap
  rm -f "$f"
  sudo timeout "$DWELL" tcpdump -i wlan0 -n -s 0 -w "$f" 2>/dev/null
  c=$(sudo tshark -r "$f" -Y "wlan.addr==$CONSOLE" -T fields -e frame.number 2>/dev/null | wc -l)
  p=$(sudo tshark -r "$f" -Y "wlan.addr==$PAD" -T fields -e frame.number 2>/dev/null | wc -l)
  tot=$(sudo tshark -r "$f" -T fields -e frame.number 2>/dev/null | wc -l)
  flag=""
  [ "$c" -gt 0 ] && flag=" <== CONSOLE ($c frames)"
  say "  ch$ch (tuned=$actual) total=$tot console=$c pad=$p$flag"
  if [ "$c" -gt "$BEST_N" ]; then BEST_N=$c; BEST_CH=$ch; fi
done

say "=== verdict ==="
if [ -n "$BEST_CH" ] && [ "$BEST_N" -gt 0 ]; then
  say "console found on channel $BEST_CH ($BEST_N frames)"
  echo "$BEST_CH" > "$CAP/console-channel.txt"
else
  say "console NOT seen on any channel - is it powered on and on the air?"
fi
