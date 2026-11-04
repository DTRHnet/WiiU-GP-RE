#!/bin/bash
# Pi 5 DRC-radio test: bring up a 5 GHz AP on brcmfmac alongside the STA uplink.
#
# Two things this proves:
#   1. the patched hostapd (CONFIG_TENDONIN) can run as an AP on this radio, and
#   2. brcmfmac APSTA works on channel 149 (same channel as the uplink) when the AP
#      interface has its OWN MAC. With wlan0's MAC duplicated, beacons failed with
#      "-100 Network is down".
# A watchdog plus an explicit teardown mean a failure cannot strand the board.
ROOT=/home/kali/wiiu-work
LOG=$ROOT/pi-ap-test.log
HAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
CONF=/tmp/drc-ap-test.conf
APMAC=b8:27:eb:74:f2:6e      # distinct from wlan0 = b8:27:eb:74:f2:6c
HOLD=${HOLD:-60}

cleanup() {
  sudo pkill -f "hostapd .*$CONF" 2>/dev/null
  sleep 1
  sudo iw dev wlanAP del 2>/dev/null
  echo "--- cleanup done; wlan0: $(iw dev wlan0 link 2>/dev/null | head -1)" >> "$LOG"
}
trap cleanup EXIT
( sleep $((HOLD + 45)); sudo pkill -f "hostapd .*$CONF"; sudo ip link del wlanAP ) >/dev/null 2>&1 &

: > "$LOG"
echo "=== $(date '+%H:%M:%S') create AP iface (MAC $APMAC) ===" >> "$LOG"
sudo iw dev wlan0 interface add wlanAP type __ap >> "$LOG" 2>&1
sudo ip link set wlanAP down >> "$LOG" 2>&1
sudo ip link set wlanAP address "$APMAC" >> "$LOG" 2>&1
sudo ip link set wlanAP up >> "$LOG" 2>&1
echo "iface addr: $(cat /sys/class/net/wlanAP/address 2>/dev/null)" >> "$LOG"

cat > "$CONF" <<'CFG'
interface=wlanAP
driver=nl80211
logger_stdout=-1
logger_stdout_level=2
ctrl_interface=/var/run/hostapd
ctrl_interface_group=sudo
hw_mode=a
channel=149
beacon_int=100
dtim_period=3
auth_algs=3
wmm_enabled=1
ieee80211n=1
ht_capab=[HT20]
ssid=DRC-RF-TEST
ignore_broadcast_ssid=0
wpa=2
wpa_psk=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
CFG

echo "=== $(date '+%H:%M:%S') start hostapd ===" >> "$LOG"
sudo "$HAPD" -dd "$CONF" >> "$LOG" 2>&1 &
sleep 10
{
  echo "=== STATUS $(date '+%H:%M:%S') ==="
  echo "AP-ENABLED:      $(grep -c 'AP-ENABLED' "$LOG")"
  echo "beacon failures: $(grep -c 'Beacon set failed' "$LOG")"
  iw dev wlanAP info 2>&1 | grep -E "type|channel"
  echo "STA: $(iw dev wlan0 link 2>/dev/null | head -1)"
  echo "wlanAP carrier: $(cat /sys/class/net/wlanAP/carrier 2>/dev/null)"
} >> "$LOG" 2>&1

echo "=== holding AP for ${HOLD}s ($(date '+%H:%M:%S') -> ) ===" >> "$LOG"
sleep "$HOLD"
echo "=== HOLD END $(date '+%H:%M:%S') ===" >> "$LOG"
