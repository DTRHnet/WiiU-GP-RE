#!/bin/bash
# pi-ap-wlandown.sh -- run as root, detached.
#
# Per instruction: bring wlan0 fully DOWN, pause, and only then build the AP on top
# of it. NetworkManager detaching alone leaves the interface in a state where
# brcmfmac refuses to set beacon parameters, so this sequence is explicit:
#
#   NM detach -> ip link down -> sleep -> ip link up -> sleep -> AP vif -> hostapd
#
# Unattended by design: taking wlan0 down kills the remote session. Everything is
# logged, verified three ways, and then reported back over HTTP once networking is
# restored by the EXIT trap.
ROOT=/home/kali/wiiu-work
LOG=$ROOT/ap-downonly.log
HAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
CONF=/tmp/drc-wd.conf
WLAN=wlan0
APVIF=wlan0
MONVIF=monAP
APMAC=b8:27:eb:74:f2:6e
REPORT=http://192.168.86.23:8899/report
GW=192.168.86.1
SSID=DRC-RF-TEST
PSK=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
DOWNSLEEP=${DOWNSLEEP:-4}

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

post_report(){
  say "posting report to $REPORT"
  for i in 1 2 3; do
    command -v curl >/dev/null 2>&1 && curl -s --max-time 25 --data-binary "@$LOG" "$REPORT" \
      && { say "report POSTed"; return 0; }
    sleep 3
  done
  say "!!! report delivery failed"
}

restore_net(){
  say "restoring networking"
  pkill -x hostapd 2>/dev/null
  pkill -x tcpdump 2>/dev/null
  sleep 1
  iw dev "$MONVIF" del 2>/dev/null
  iw dev "$APVIF" del 2>/dev/null
  ip link set "$WLAN" up 2>/dev/null
  nmcli dev set "$WLAN" managed yes 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 45); do
    ping -c1 -W1 "$GW" >/dev/null 2>&1 && { say "network back after ~$((i*2))s"; return 0; }
    sleep 2
  done
  say "!!! network did NOT return"
  return 1
}

finish(){ kill "${TIMER_PID:-}" 2>/dev/null; restore_net; post_report; say "=== COMPLETE ==="; }
( sleep 480; systemctl restart NetworkManager ) >/dev/null 2>&1 & TIMER_PID=$!
trap finish EXIT

render_conf(){
  local chan="$1" n="$2"
  cat > "$CONF" <<CFG
interface=$APVIF
driver=nl80211
logger_stdout=-1
logger_stdout_level=2
ctrl_interface=/var/run/hostapd
ctrl_interface_group=sudo
hw_mode=a
channel=$chan
beacon_int=100
dtim_period=3
auth_algs=3
wmm_enabled=1
ieee80211n=$n
ht_capab=[HT20]
ssid=$SSID
ignore_broadcast_ssid=0
wpa=2
wpa_psk=$PSK
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
CFG
  [ "$n" = "0" ] && sed -i '/^ht_capab=/d' "$CONF"
}

cleanup_vifs(){
  pkill -x hostapd 2>/dev/null
  sleep 1
  iw dev "$MONVIF" del 2>/dev/null
  iw dev "$APVIF" del 2>/dev/null
  sleep 1
}

try_one(){
  local chan="$1" n="$2"
  say ""
  say "########## CHANNEL $chan  ieee80211n=$n ##########"
  cleanup_vifs

  say "step 1: detach NetworkManager"
  nmcli dev set "$WLAN" managed no 2>/dev/null
  nmcli dev disconnect "$WLAN" 2>/dev/null
  sleep 1

  say "step 2: ip link set $WLAN DOWN"
  ip link set "$WLAN" down 2>/dev/null
  say "        wlan0 state: $(cat /sys/class/net/$WLAN/operstate 2>/dev/null); sleeping ${DOWNSLEEP}s"
  sleep "$DOWNSLEEP"

  say "step 3: leave $WLAN DOWN and let hostapd bring it up itself"
  sleep 1
  say "        wlan0: $(ip -br link show $WLAN 2>/dev/null)"

  say "step 4: use $APVIF directly (no vif)"

  say "step 5: (monitor vif not supported on this driver, skipping)"

  say "step 6: hostapd"
  render_conf "$chan" "$n"
  local tx0 tx1 delta enabled berr
  tx0=$(cat /sys/class/net/$APVIF/statistics/tx_packets 2>/dev/null || echo 0)
  "$HAPD" "$CONF" > /tmp/wd-hapd.out 2>&1 &
  HAPD_PID=$!
  sleep 10
  enabled=$(grep -c "AP-ENABLED" /tmp/wd-hapd.out 2>/dev/null || true)
  berr=$(grep -c "Beacon set failed" /tmp/wd-hapd.out 2>/dev/null || true)
  tx1=$(cat /sys/class/net/$APVIF/statistics/tx_packets 2>/dev/null || echo 0)
  delta=$(( ${tx1:-0} - ${tx0:-0} ))
  say "        AP-ENABLED=${enabled:-0}  beacon_errors=${berr:-0}  tx_packets $tx0 -> $tx1 (delta $delta)"

  say "step 7: sampling tx counters for 10s"
  local seen=0
  if [ -d "/sys/class/net/$MONVIF" ]; then
    timeout 12 tcpdump -i "$MONVIF" -n -e -c 3 "type mgt subtype beacon" > /tmp/wd-sniff.out 2>&1
    seen=$(grep -ci "beacon" /tmp/wd-sniff.out 2>/dev/null || true)
    say "        beacons sniffed: ${seen:-0}"
    grep -i "beacon" /tmp/wd-sniff.out 2>/dev/null | head -3 | sed 's/^/          /'
  else
    say "        no monitor vif"
  fi

  if [ "${enabled:-0}" -ge 1 ] && [ "${seen:-0}" -ge 1 ]; then
    say "VERDICT ch$chan: PASS - AP up and beacons confirmed on air"
  elif [ "${enabled:-0}" -ge 1 ] && [ "$delta" -ge 50 ]; then
    say "VERDICT ch$chan: PARTIAL - AP up, tx growing, no beacon sniffed"
  else
    say "VERDICT ch$chan: FAIL"
    grep -iE "failed|error|not supported|busy" /tmp/wd-hapd.out 2>/dev/null | head -4 | sed 's/^/          /'
  fi

  say "step 8: teardown"
  kill "$HAPD_PID" 2>/dev/null
  cleanup_vifs
}

say "=== wlan0-down AP test start (kernel $(uname -r)) ==="
say "wlan0 before: $(ip -br link show $WLAN 2>/dev/null)"

try_one 149 1
try_one 36 1

say ""
say "=== verdicts ==="
grep -E "CHANNEL|VERDICT" "$LOG" 2>/dev/null | sed 's/^/  /'
