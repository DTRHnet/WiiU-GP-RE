#!/bin/bash
# capture2.sh -- capture a real console<->GamePad session on the CONSOLE's channel.
#
# Fixes two bugs from the first attempt:
#   1. iwlwifi allows only one channel at a time, so while wlan0 is associated to the
#      home AP the monitor is pinned to that AP's channel (149) and never sees the
#      console (channel 36). The uplink must be dropped for the capture.
#   2. No EAPOL was captured because the pad was already associated. The pad needs to
#      re-associate DURING the window, so power-cycle it when the capture goes live.
#
# wlan0 is put in monitor mode on the console's channel, captured, then restored.
set -uo pipefail
ROOT=/home/kali/Wiiu
CAP=$ROOT/capture
mkdir -p "$CAP"
PCAP=$CAP/console-session2.pcap
LOG=$CAP/capture2.log
DUR=${DUR:-180}
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
  sudo nmcli dev set wlan0 managed yes 2>/dev/null
  sudo systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 30); do ping -c1 -W1 192.168.86.1 >/dev/null 2>&1 && { say "uplink back after ~$((i*2))s"; break; }; sleep 2; done
}
trap restore EXIT

say "=== 1. find the console's channel ==="
FREQ=""
for i in $(seq 1 20); do
  FREQ=$(sudo iw dev wlan0 scan 2>/dev/null | awk '/^BSS /{b=$2} /freq:/{f=$2} /signal:/{if (b ~ /cc:fb:65:b6:81:69/) print f}')
  [ -n "$FREQ" ] && break
  sleep 5
done
[ -z "$FREQ" ] && { say "!!! console not visible - power it on"; exit 1; }
CHAN=$(python3 -c "f=${FREQ%.*}; print(int((f-5000)//5) if f<5925 else 0)")
say "console on ${FREQ} MHz -> channel ${CHAN}"

say "=== 2. drop the uplink and switch the radio to channel ${CHAN} ==="
sudo nmcli dev set wlan0 managed no 2>/dev/null
sudo nmcli dev disconnect wlan0 2>/dev/null
sudo systemctl stop wpa_supplicant 2>/dev/null
sudo pkill -x wpa_supplicant 2>/dev/null
sleep 3
sudo ip link set wlan0 down 2>/dev/null
sudo iw dev wlan0 set type monitor 2>/dev/null
sudo ip link set wlan0 up 2>/dev/null
sleep 2
sudo iw dev wlan0 set channel "$CHAN" 2>/dev/null
sleep 1
say "  wlan0 type=$(iw dev wlan0 info 2>/dev/null | awk '/type/{print $2}') channel=$(iw dev wlan0 info 2>/dev/null | awk '/channel/{print $2}')"

say "=== 3. capturing ${DUR}s -- POWER-CYCLE THE GAMEPAD NOW ==="
rm -f "$PCAP"
sudo timeout "$DUR" tcpdump -i wlan0 -n -s 0 -w "$PCAP" 2>/dev/null
sleep 1

say "=== 4. what did we get? ==="
frames=$(sudo tcpdump -r "$PCAP" -n 2>/dev/null | wc -l)
say "frames: $frames  size: $(stat -c%s "$PCAP" 2>/dev/null) bytes"
say "channel(s) captured: $(sudo tshark -r "$PCAP" -T fields -e radiotap.channel.freq 2>/dev/null | sort -u | tr '\n' ' ')"
say "EAPOL frames: $(sudo tshark -r "$PCAP" -Y eapol -T fields -e frame.number 2>/dev/null | wc -l)"
say "frame types: $(sudo tshark -r "$PCAP" -T fields -e wlan.fc.type_subtype 2>/dev/null | sort | uniq -c | tr '\n' ' ')"
