#!/bin/bash
# pi-fix.sh -- run as root, detached. Makes wlan1 (USB dongle) the uplink so the
# 5 GHz wlan0 is free, then serves the exact SSID the GamePad is probing for.
#
# Why this shape: every live NetworkManager experiment so far has knocked the Pi off
# the network, costing a power cycle. So this runs detached, logs everything, and an
# EXIT trap ALWAYS restores NetworkManager and wlan0, then POSTs the log to Kali.
#
# Facts established from the probe capture:
#   GamePad MAC      : 40:d2:8a:17:e2:09
#   probes for SSID  : WiiUccfb65b68169   (console Wi-Fi MAC cc:fb:65:b6:81:69)
#   wlan0 as uplink  : AP mode beacons fail
#   wlan0 free       : AP mode works (verified on air)
#   mode-change EBUSY: wpa_supplicant/NM holding wlan0 -> use an AP *vif* instead
ROOT=/home/kali/wiiu-work
LOG=$ROOT/fix.log
REPORT=http://192.168.86.23:8899/report
PAD=40:d2:8a:17:e2:09
CONSOLE_SSID=WiiUccfb65b68169
APVIF=wlanAP
APMAC=b8:27:eb:74:f2:6e
GW=192.168.86.1
SSID_HOME="Sir Connects A Lot"

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

have_ip(){ ip -4 addr show "$1" 2>/dev/null | grep -q "inet "; }

restore(){
  say "--- RESTORE"
  pkill -x hostapd 2>/dev/null
  pkill -x tcpdump 2>/dev/null
  sleep 1
  iw dev "$APVIF" del 2>/dev/null
  nmcli dev set wlan0 managed yes 2>/dev/null
  ip link set wlan0 up 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 45); do
    ping -c1 -W1 "$GW" >/dev/null 2>&1 && { say "network back after ~$((i*2))s"; break; }
    sleep 2
  done
  say "wlan0: $(ip -br addr show wlan0 2>/dev/null | tr -s ' ')   wlan1: $(ip -br addr show wlan1 2>/dev/null | tr -s ' ')"
}

finish(){ kill "${TIMER:-}" 2>/dev/null; restore; say "--- POSTING REPORT"; curl -s --max-time 25 --data-binary "@$LOG" "$REPORT"; say "=== DONE ==="; }
( sleep 420; systemctl restart NetworkManager ) >/dev/null 2>&1 & TIMER=$!
trap finish EXIT

say "=== pi-fix start (kernel $(uname -r)) ==="
say "usb: $(lsusb | grep -iE 'realtek|802.11' | head -2)"
for i in wlan0 wlan1; do say "$i: $(ip -br link show $i 2>/dev/null | tr -s ' ')"; done

# ---------- 1. does the dongle work at all? ----------
say "--- 1. dongle scan test"
ip link set wlan1 up 2>/dev/null
sleep 2
n=$(timeout 20 iw dev wlan1 scan 2>/dev/null | grep -c "^BSS")
say "wlan1 sees $n BSS entries"
timeout 20 iw dev wlan1 scan 2>/dev/null | grep -E "SSID" | sort -u | head -6 | sed 's/^/    /'

# ---------- 2. make wlan1 the uplink (own profile, leave wlan0's alone) ----------
say "--- 2. build a dedicated uplink profile on wlan1"
PSK=$(nmcli -s -g 802-11-wireless-security.psk connection show "$SSID_HOME" 2>/dev/null)
say "recovered home PSK: $([ -n "${PSK:-}" ] && echo yes || echo NO)"
if [ -n "${PSK:-}" ]; then
  nmcli connection delete drc-uplink 2>/dev/null
  nmcli connection add type wifi ifname wlan1 con-name drc-uplink ssid "$SSID_HOME" >/dev/null 2>&1
  nmcli connection modify drc-uplink wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PSK" \
     connection.autoconnect yes 802-11-wireless.band bg >/dev/null 2>&1
  nmcli connection up drc-uplink ifname wlan1 2>&1 | head -2
  for i in $(seq 1 25); do have_ip wlan1 && break; sleep 2; done
fi
say "wlan1: $(ip -br addr show wlan1 2>/dev/null | tr -s ' ')"

if ! have_ip wlan1; then
  say "!!! wlan1 has no IP - cannot free wlan0, stopping before any damage"
  exit 1
fi

# ---------- 3. free wlan0 and serve the console SSID on a vif ----------
say "--- 3. wlan1 is up; detaching wlan0 (do NOT change its mode: EBUSY)"
nmcli dev set wlan0 managed no 2>/dev/null
sleep 2
say "wlan0: $(ip -br link show wlan0 | tr -s ' ')  type=$(iw dev wlan0 info 2>/dev/null | awk '/type/{print $2}')"

iw dev wlan0 interface add "$APVIF" type __ap 2>/dev/null
ip link set "$APVIF" down 2>/dev/null
ip link set "$APVIF" address "$APMAC" 2>/dev/null
ip link set "$APVIF" up 2>/dev/null
sleep 2
say "AP vif: $(cat /sys/class/net/$APVIF/address 2>/dev/null) type=$(iw dev $APVIF info 2>/dev/null | awk '/type/{print $2}')"

cat > /tmp/fix-ap.conf <<CFG
interface=$APVIF
driver=nl80211
logger_stdout=-1
logger_stdout_level=1
ctrl_interface=/var/run/hostapd
ctrl_interface_group=sudo
hw_mode=a
channel=36
beacon_int=100
dtim_period=3
auth_algs=3
wmm_enabled=1
ieee80211n=1
ht_capab=[HT20]
ssid=$CONSOLE_SSID
ignore_broadcast_ssid=0
wpa=0
CFG
hostapd -dd /tmp/fix-ap.conf > /tmp/fix-ap.out 2>&1 &
HAPID=$!
sleep 8
say "AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/fix-ap.out)  errors=$(grep -ciE 'Failed to set beacon|Could not connect to kernel' /tmp/fix-ap.out)"
grep -m1 "Using interface" /tmp/fix-ap.out | sed 's/^/    /'

# ---------- 4. wait for the pad ----------
say "--- 4. waiting up to 60s for $PAD to associate"
for i in $(seq 1 30); do
  if grep -qi "AP-STA-CONNECTED" /tmp/fix-ap.out; then
    say "*** ASSOCIATED: $(grep -i 'AP-STA-CONNECTED' /tmp/fix-ap.out | tail -1)"
    break
  fi
  sleep 2
done
grep -iE "AP-STA|authentication|associated|deauth|WPA" /tmp/fix-ap.out | tail -8 | sed 's/^/    /'

say "--- 5. what the pad is doing now (any frames from it?)"
timeout 10 tcpdump -i "$APVIF" -n -c 5 2>/dev/null | head -5 | sed 's/^/    /'
kill "$HAPID" 2>/dev/null
say "=== summary: AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/fix-ap.out) associated=$(grep -c 'AP-STA-CONNECTED' /tmp/fix-ap.out) ==="
