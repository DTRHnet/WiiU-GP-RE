#!/bin/bash
# capture5.sh -- monitor on wlan0 (AX210) while wlan1 (USB dongle) carries the uplink.
#
# This is the version that does NOT disrupt connectivity:
#   wlan1 (RTL8188FU, 2.4GHz)  -> uplink, managed by NetworkManager, untouched
#   wlan0 (AX210, 5GHz)        -> monitor, free to hop channels
#
# Only wlan0 is touched. NetworkManager is NOT restarted, so wlan1 never bounces.
set -uo pipefail
ROOT=/home/kali/Wiiu
CAP=$ROOT/capture
mkdir -p "$CAP"
PCAP=$CAP/console-session5.pcap
LOG=$CAP/capture5.log
DUR=${DUR:-240}

exec > >(tee "$LOG") 2>&1
say(){ echo "[$(date '+%H:%M:%S')] $*"; }

restore(){
  say "--- restoring wlan0 to a managed station (wlan1 keeps the uplink)"
  sudo pkill -x tcpdump 2>/dev/null
  sleep 1
  sudo ip link set wlan0 down 2>/dev/null
  sudo iw dev wlan0 set type managed 2>/dev/null
  sudo ip link set wlan0 up 2>/dev/null
  sudo nmcli dev set wlan0 managed yes 2>/dev/null
  sleep 5
  say "wlan0: $(iw dev wlan0 info 2>/dev/null | awk '/type/{print $2}')  wlan1 uplink: $(iw dev wlan1 link 2>/dev/null | head -1)"
  ping -c1 -W2 -I wlan1 1.1.1.1 >/dev/null 2>&1 && say "internet still up via wlan1" || say "!! internet down"
}
trap restore EXIT

say "=== preflight ==="
say "wlan1 (uplink): $(ip -br addr show wlan1 | tr -s ' ')"
ping -c1 -W2 -I wlan1 1.1.1.1 >/dev/null 2>&1 || { say "!! wlan1 has no internet - aborting so we don't lose contact"; exit 1; }
say "wlan1 confirmed as uplink"

say "=== moving wlan0 to monitor (NM not restarted) ==="
sudo nmcli dev set wlan0 managed no 2>/dev/null
sudo nmcli dev disconnect wlan0 2>/dev/null
sleep 3
sudo ip link set wlan0 down 2>/dev/null
sudo iw dev wlan0 set type monitor 2>/dev/null
sudo ip link set wlan0 up 2>/dev/null
sleep 2
say "  wlan0 type=$(iw dev wlan0 info 2>/dev/null | awk '/type/{print $2}')"
ping -c1 -W2 -I wlan1 1.1.1.1 >/dev/null 2>&1 && say "  uplink intact after the switch" || say "  !! uplink lost"

rm -f "$PCAP"
sudo timeout "$DUR" tcpdump -i wlan0 -n -s 0 -w "$PCAP" 2>/dev/null &
TCPID=$!
say "=== hopping 5GHz for ${DUR}s ==="
say "############ POWER-CYCLE THE GAMEPAD NOW ############"
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
say "channels: $(sudo tshark -r "$PCAP" -T fields -e radiotap.channel.freq 2>/dev/null | sort -n | uniq -c | tr '\n' ' ')"
say "EAPOL (handshake): $(sudo tshark -r "$PCAP" -Y eapol -T fields -e frame.number 2>/dev/null | wc -l)"
say "console cc:fb:.. frames: $(sudo tshark -r "$PCAP" -Y 'wlan.addr==cc:fb:65:b6:81:69' -T fields -e frame.number 2>/dev/null | wc -l)"
say "pad 40:d2:.. frames:    $(sudo tshark -r "$PCAP" -Y 'wlan.addr==40:d2:8a:17:e2:09' -T fields -e frame.number 2>/dev/null | wc -l)"
