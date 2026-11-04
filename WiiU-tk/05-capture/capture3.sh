#!/bin/bash
# capture3.sh -- capture a real console<->GamePad session, robust to a hopping AP.
#
# Lessons from the previous two attempts:
#   1. iwlwifi is single-channel: while wlan0 is associated the monitor is stuck on the
#      uplink's channel, so the uplink must be dropped for the capture.
#   2. The console changes channel between sessions (observed 36 -> 40), so locking the
#      monitor to one channel misses it. This hops instead.
#   3. The handshake only exists when the pad *associates*, so the pad must be
#      power-cycled during the window.
#   4. The console must actually be on: this waits for it to be visible for 20s
#      continuously, so toggling it on/off doesn't burn the capture window.
set -uo pipefail
ROOT=/home/kali/Wiiu
CAP=$ROOT/capture
mkdir -p "$CAP"
PCAP=$CAP/console-session4.pcap
LOG=$CAP/capture4.log
DUR=${DUR:-240}
WAIT=${WAIT:-600}
CONSOLE_MAC=cc:fb:65:b6:81:69

exec > >(tee "$LOG") 2>&1
say(){ echo "[$(date '+%H:%M:%S')] $*"; }

restore(){
  say "--- restore networking"
  sudo pkill -x tcpdump 2>/dev/null
  sleep 1
  sudo ip link set wlan0 down 2>/dev/null
  sudo iw dev wlan0 set type managed 2>/dev/null
  sudo ip link set wlan0 up 2>/dev/null
  sudo systemctl start wpa_supplicant 2>/dev/null
  sudo nmcli dev set wlan0 managed yes 2>/dev/null
  sudo systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 30); do ping -c1 -W1 192.168.86.1 >/dev/null 2>&1 && { say "uplink back ~$((i*2))s"; break; }; sleep 2; done
}
trap restore EXIT

if [ "${SKIP_GATE:-0}" = "1" ]; then
  say "=== skipping the visibility gate (console presumed on; scan misses DFS channels) ==="
else
say "=== waiting for the console to be STABLY on (${WAIT}s budget, needs 20s continuous) ==="
stable=0
for i in $(seq 1 $((WAIT/5))); do
  if sudo iw dev wlan0 scan 2>/dev/null | grep -qi "$CONSOLE_MAC"; then
    stable=$((stable+1))
    say "  visible (${stable}/4)"
    [ "$stable" -ge 4 ] && break
  else
    [ "$stable" -gt 0 ] && say "  lost it, resetting stability counter"
    stable=0
  fi
  sleep 5
done
[ "$stable" -lt 4 ] && { say "!!! console never stayed up - power it on and LEAVE it on"; exit 1; }
say "console stable."
fi

say "=== dropping uplink, switching radio to monitor ==="
sudo nmcli dev set wlan0 managed no 2>/dev/null
sudo nmcli dev disconnect wlan0 2>/dev/null
sudo systemctl stop wpa_supplicant 2>/dev/null
sudo pkill -x wpa_supplicant 2>/dev/null
sleep 3
sudo ip link set wlan0 down 2>/dev/null
sudo iw dev wlan0 set type monitor 2>/dev/null
sudo ip link set wlan0 up 2>/dev/null
sleep 2
say "  wlan0 type=$(iw dev wlan0 info 2>/dev/null | awk '/type/{print $2}')"

rm -f "$PCAP"
sudo timeout "$DUR" tcpdump -i wlan0 -n -s 0 -w "$PCAP" 2>/dev/null &
TCPID=$!

say "=== hopping 5GHz channels every 300ms for ${DUR}s ==="
say "############ POWER-CYCLE THE GAMEPAD NOW (hold power, then press) ############"
( end=$SECONDS
  CH=(36 40 44 48 52 56 60 64 100 104 108 112 149 153 157 161)
  i=0
  while [ $SECONDS -lt $((end + DUR)) ]; do
    sudo iw dev wlan0 set channel "${CH[$i]}" 2>/dev/null
    i=$(( (i+1) % ${#CH[@]} ))
    sleep 0.3
  done ) &
wait "$TCPID" 2>/dev/null
sleep 1

say "=== results ==="
say "frames: $(sudo tcpdump -r "$PCAP" -n 2>/dev/null | wc -l)  size: $(stat -c%s "$PCAP" 2>/dev/null)"
say "channels seen: $(sudo tshark -r "$PCAP" -T fields -e radiotap.channel.freq 2>/dev/null | sort -n | uniq -c | tr '\n' ' ')"
say "EAPOL: $(sudo tshark -r "$PCAP" -Y eapol -T fields -e frame.number 2>/dev/null | wc -l)"
say "console frames: $(sudo tshark -r "$PCAP" -Y "wlan.addr==$CONSOLE_MAC" -T fields -e frame.number 2>/dev/null | wc -l)"
say "pad frames: $(sudo tshark -r "$PCAP" -Y 'wlan.addr==40:d2:8a:17:e2:09' -T fields -e frame.number 2>/dev/null | wc -l)"
