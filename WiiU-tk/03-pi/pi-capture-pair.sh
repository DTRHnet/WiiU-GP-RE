#!/bin/bash
# pi-capture-pair.sh -- run as root, detached. Captures the GamePad<->console pairing.
#
# Constraints learned the hard way:
#   * a monitor vif CANNOT coexist with wlan0 being an associated station
#     (`Operation not supported -95`), and
#   * a plain down/up of wlan0 breaks brcmfmac for good.
# So this detaches wlan0 from NetworkManager for the duration of the capture (the
# remote session dies - that is expected), sniffs, then ALWAYS restores networking
# and POSTs its summary to Kali.
#
# What you get:
#   * the console's real BSSID + its pairing-AP name (WiiU..._STA1)
#   * the WPS EAP exchange (M1..M8; Nintendo rotates the KDK 3 bytes left)
#   * the WPA2 4-way handshake (EAPOL key frames) -> PSK is recoverable from it,
#     because only 4 PIN digits are unknown (4^4 = 256) and the suffix is fixed "5678".
# The pcap stays on the Pi for later analysis.
#
# DUR=seconds (default 240).
ROOT=/home/kali/wiiu-work
PCAP=$ROOT/pair.pcap
LOG=$ROOT/capture.log
REPORT=http://192.168.86.23:8899/report
MON=mon0
DUR=${DUR:-240}
GW=192.168.86.1

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

cleanup(){
  say "--- cleanup: restoring networking"
  pkill -x tcpdump 2>/dev/null
  sleep 1
  iw dev "$MON" del 2>/dev/null
  sleep 1
  ip link set wlan0 down 2>/dev/null
  iw dev wlan0 set type managed 2>/dev/null
  ip link set wlan0 up 2>/dev/null
  sleep 1
  systemctl start wpa_supplicant 2>/dev/null
  nmcli dev set wlan0 managed yes 2>/dev/null
  ip link set wlan0 up 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 45); do
    ping -c1 -W1 "$GW" >/dev/null 2>&1 && { say "network back after ~$((i*2))s"; break; }
    sleep 2
  done
  say "wlan0: $(ip -br addr show wlan0 2>/dev/null | tr -s ' ')"
  say "pcap: $(ls -l "$PCAP" 2>/dev/null | awk '{print $5" bytes"}')"
  curl -s --max-time 25 --data-binary "@$LOG" "$REPORT"
  say "=== DONE ==="
}
( sleep $((DUR + 240)); systemctl restart NetworkManager ) >/dev/null 2>&1 &
trap cleanup EXIT

say "=== pairing capture start (${DUR}s) ==="
say "before: $(ip -br addr show wlan0 2>/dev/null | tr -s ' ')"

say "--- detaching wlan0 from NetworkManager (remote session will drop)"
nmcli dev set wlan0 managed no 2>/dev/null
nmcli dev disconnect wlan0 2>/dev/null
for i in $(seq 1 15); do
  iw dev wlan0 link 2>/dev/null | grep -q "Not connected" && break
  sleep 1
done
say "wlan0 link: $(iw dev wlan0 link 2>/dev/null | head -1)"

say "--- releasing wpa_supplicant's hold on wlan0"
systemctl stop wpa_supplicant 2>/dev/null
pkill -x wpa_supplicant 2>/dev/null
sleep 2
say "    supplicants left: $(pgrep -c -x wpa_supplicant)"

say "--- enabling monitor mode"
# A monitor *vif* is refused (-95) on this driver, so flip wlan0 itself instead.
MONDEV=wlan0
ip link set wlan0 down 2>/dev/null; sleep 1
if ! iw dev wlan0 set type monitor 2>&1 | head -2; then
  say "    set type monitor failed, trying iw phy"
  PHY=$(iw dev wlan0 info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
  iw phy "$PHY" interface add "$MON" type monitor 2>&1 | head -2
  [ -d "/sys/class/net/$MON" ] && MONDEV=$MON
fi
ip link set "$MONDEV" up 2>/dev/null
sleep 2
TYPE=$(iw dev "$MONDEV" info 2>/dev/null | awk '/type/{print $2}')
say "    $MONDEV type=$TYPE"
if [ "$TYPE" != "monitor" ]; then
  say "!!! could not enter monitor mode - aborting"; exit 1
fi

say "--- channel hopping 36/40/44/48/149/153/157/161 every 2s"
( end=$SECONDS
  CH=(36 40 44 48 36 40 44 48 149 153 157 161 149 153 157 161)
  i=0
  while [ $SECONDS -lt $((end + DUR)) ]; do
    iw dev "$MONDEV" set channel "${CH[$i]}" 2>/dev/null
    i=$(( (i+1) % ${#CH[@]} ))
    sleep 2
  done ) &

rm -f "$PCAP"
tcpdump -i "$MONDEV" -n -s 0 -w "$PCAP" 2>/tmp/tcpdump.err &
TCPID=$!
say "*** CAPTURING - PAIR THE GAMEPAD WITH THE CONSOLE NOW (SYNC twice) ***"
sleep "$DUR"
kill "$TCPID" 2>/dev/null
sleep 2
pkill -x tcpdump 2>/dev/null
sleep 2

say "--- CAPTURE SUMMARY"
say "size: $(stat -c%s "$PCAP" 2>/dev/null) bytes"
say "packets: $(tcpdump -r "$PCAP" -n 2>/dev/null | wc -l)"
say "EAPOL frames: $(tcpdump -r "$PCAP" -n -v 2>/dev/null | grep -c EAPOL)"
say "BSSIDs seen (top 8):"
tcpdump -r "$PCAP" -n 2>/dev/null | grep -oE "BSSID:[0-9a-f:]{17}" | sort | uniq -c | sort -rn | head -8 | sed 's/^/    /'
say "WiiU SSIDs seen:"
tcpdump -r "$PCAP" -n -e 2>/dev/null | grep -oE "\(WiiU[^)]*\)" | sort -u | head -10 | sed 's/^/    /'
say "GamePad 40:d2:8a:17:e2:09 frames: $(tcpdump -r "$PCAP" -n 2>/dev/null | grep -c '40:d2:8a:17:e2:09')"
say "console cc:fb:65:b6:81:69 frames: $(tcpdump -r "$PCAP" -n 2>/dev/null | grep -c 'cc:fb:65:b6:81:69')"
say "--- EAPOL sample ---"
tcpdump -r "$PCAP" -n -v 2>/dev/null | grep -B1 -A2 EAPOL | head -24 | sed 's/^/    /'
