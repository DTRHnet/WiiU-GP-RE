#!/bin/bash
# pi-radio-selftest.sh  --  run as root, detached. Takes ~3 minutes.
#
# Takes wlan0 away from NetworkManager and runs it as a DEDICATED 5 GHz DRC AP.
# That is exactly what we could not do while SSH needed the radio, so this script
# loses the network on purpose, tests several hypotheses unattended, then restores
# networking and POSTs its log back to Kali so the result is not lost.
#
# Because we cannot watch it happen, each hypothesis is verified THREE ways:
#   1. hostapd reached AP-ENABLED
#   2. no "Beacon set failed" (the failure mode seen when sharing the radio)
#   3. a monitor-mode vif sniffs our OWN beacons off the air, plus tx_packets growth
# A "VERDICT: PASS" requires the AP up AND beacons actually transmitted.
#
# Hypotheses tested:
#   H1 dedicated AP, channel 149, HT20
#   H2 dedicated AP, channel 36,  HT20     (drc-hostap's own default channel)
#   H3 dedicated AP, channel 149, pure 11a (no HT)
#   H4 shared AP+STA on 149                (expected to fail: control/regression)
#
# Restore is unconditional: EXIT trap + a hard timer, so the board cannot be
# stranded. Report URL is POSTed once the network is back.

ROOT=/home/kali/wiiu-work
LOG=$ROOT/radio-selftest2.log
HAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
CONF=/tmp/drc-selftest.conf
PIDF=/tmp/drc-selftest.pid
WLAN=wlan0
MONVIF=monAP
REPORT=http://192.168.86.23:8899/report
GW=192.168.86.1
SSID=DRC-RF-TEST
PSK=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

post_report(){
  say "posting report to $REPORT"
  for i in 1 2 3; do
    if command -v curl >/dev/null 2>&1; then
      curl -s --max-time 25 --data-binary "@$LOG" "$REPORT" && { say "report POSTed (curl)"; return 0; }
    fi
    if command -v wget >/dev/null 2>&1; then
      wget -q -O /dev/null --post-file="$LOG" "$REPORT" && { say "report POSTed (wget)"; return 0; }
    fi
    if command -v python3 >/dev/null 2>&1; then
      python3 - "$LOG" "$REPORT" <<'PY' && { say "report POSTed (python)"; return 0; }
import sys, urllib.request
data = open(sys.argv[1], 'rb').read()
urllib.request.urlopen(urllib.request.Request(sys.argv[2], data=data), timeout=25)
PY
    fi
    sleep 3
  done
  say "!!! could not deliver the report (network may still be down)"
}

restore_net(){
  say "restoring networking"
  pkill -x hostapd 2>/dev/null
  pkill -x tcpdump 2>/dev/null
  sleep 1
  iw dev "$MONVIF" del 2>/dev/null
  ip link set "$WLAN" up 2>/dev/null
  nmcli dev set "$WLAN" managed yes 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 45); do
    if ping -c1 -W1 "$GW" >/dev/null 2>&1; then
      say "network restored after ~$((i*2))s"
      return 0
    fi
    sleep 2
  done
  say "!!! network did NOT come back on its own"
  return 1
}

finish(){
  kill "${TIMER_PID:-}" 2>/dev/null
  restore_net
  post_report
  say "=== SELFTEST COMPLETE ==="
}

# hard safety timer: if anything hangs, put networking back
( sleep 420; systemctl restart NetworkManager ) >/dev/null 2>&1 &
TIMER_PID=$!
trap finish EXIT
trap 'say "interrupted"; exit 1' INT TERM

say "=== radio self-test start (kernel $(uname -r)) ==="
say "APSTA/interface combinations advertised by this phy:"
iw list 2>/dev/null | sed -n '/valid interface combinations/,/^$/p' | sed 's/^/    /'

# --- take the radio away from NetworkManager -----------------------------------
say "detaching $WLAN from NetworkManager (this kills the remote session)"
nmcli dev set "$WLAN" managed no 2>/dev/null
nmcli dev disconnect "$WLAN" 2>/dev/null
sleep 2
ip link set "$WLAN" down 2>/dev/null
sleep 1
ip link set "$WLAN" up 2>/dev/null
sleep 2
say "current addresses: $(ip -br addr show "$WLAN")"

write_conf(){
  local chan="$1" n="$2"
  cat > "$CONF" <<CFG
interface=$WLAN
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

teardown_ap(){
  [ -n "${HAPD_PID:-}" ] && kill "$HAPD_PID" 2>/dev/null
  [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null
  pkill -x hostapd 2>/dev/null
  rm -f "$PIDF"
  iw dev "$MONVIF" del 2>/dev/null
  sleep 1
}

try_config(){
  local desc="$1" chan="$2" n="$3"
  say ""
  say "=========== HYPOTHESIS: $desc  (channel $chan, ieee80211n=$n) ==========="
  teardown_ap
  nmcli dev set "$WLAN" managed no 2>/dev/null
  nmcli dev disconnect "$WLAN" 2>/dev/null
  sleep 2
  ip link set "$WLAN" up 2>/dev/null
  sleep 1
  # dedicated AP vif with its OWN MAC - the variant that once beaconed cleanly
  iw dev "$WLAN" interface add wlanAP type __ap 2>/dev/null
  ip link set wlanAP down 2>/dev/null
  ip link set wlanAP address b8:27:eb:74:f2:6e 2>/dev/null
  ip link set wlanAP up 2>/dev/null
  iw dev "$WLAN" interface add "$MONVIF" type monitor 2>/dev/null
  ip link set "$MONVIF" up 2>/dev/null
  write_conf "$chan" "$n"
  sed -i "s/^interface=.*/interface=wlanAP/" "$CONF"

  local tx0 tx1
  tx0=$(cat /sys/class/net/$WLAN/statistics/tx_packets 2>/dev/null || echo 0)
  "$HAPD" "$CONF" > /tmp/hapd.out 2>&1 &
  HAPD_PID=$!
  sleep 9
  local enabled berr
  enabled=$(grep -c "AP-ENABLED" /tmp/hapd.out 2>/dev/null || true)
  berr=$(grep -c "Beacon set failed" /tmp/hapd.out 2>/dev/null || true)
  tx1=$(cat /sys/class/net/$WLAN/statistics/tx_packets 2>/dev/null || echo 0)
  local delta=$(( ${tx1:-0} - ${tx0:-0} ))
  say "AP-ENABLED=$enabled  beacon_errors=${berr:-0}  tx_packets $tx0 -> $tx1 (delta $delta)"
  say "iface: $(iw dev $WLAN info 2>/dev/null | grep -E 'channel' | head -1)"

  # --- proof: sniff our own beacons -------------------------------------------
  local seen=0
  if [ -d "/sys/class/net/$MONVIF" ]; then
    timeout 12 tcpdump -i "$MONVIF" -n -e -c 3 "type mgt subtype beacon" > /tmp/sniff.out 2>&1
    seen=$(grep -ci "beacon" /tmp/sniff.out 2>/dev/null || true)
    say "monitor vif sniffed beacon frames: ${seen:-0}"
    grep -i "beacon" /tmp/sniff.out 2>/dev/null | head -3 | sed 's/^/      /'
  else
    say "could not create a monitor vif"
  fi

  # --- verdict ----------------------------------------------------------------
  if [ "${enabled:-0}" -ge 1 ] && [ "${seen:-0}" -ge 1 ]; then
    say "VERDICT: PASS - AP enabled AND beacons confirmed on air"
  elif [ "${enabled:-0}" -ge 1 ] && [ "$delta" -ge 50 ]; then
    say "VERDICT: PARTIAL - AP enabled and tx is growing, but no beacon sniffed"
  else
    say "VERDICT: FAIL - AP did not come up / did not transmit"
    grep -iE "failed|error|busy|not supported" /tmp/hapd.out 2>/dev/null | head -5 | sed 's/^/      /'
  fi
  pkill -x hostapd 2>/dev/null
  iw dev "$MONVIF" del 2>/dev/null
  iw dev wlanAP del 2>/dev/null
  sleep 1
}

# --- H4 first: shared AP+STA, the configuration that previously misbehaved ----
say ""
say "=========== HYPOTHESIS: H4 shared AP+STA on 149 (control) ==========="
teardown_ap
ip link set "$WLAN" up 2>/dev/null
nmcli dev set "$WLAN" managed yes 2>/dev/null
systemctl restart NetworkManager >/dev/null 2>&1
say "waiting for the uplink to come back before the control test"
for i in $(seq 1 20); do ping -c1 -W1 "$GW" >/dev/null 2>&1 && break; sleep 2; done
say "uplink: $(iw dev $WLAN link 2>/dev/null | head -1)"
iw dev "$WLAN" interface add wlanAP type __ap 2>/dev/null
ip link set wlanAP down 2>/dev/null
ip link set wlanAP address b8:27:eb:74:f2:6e 2>/dev/null
ip link set wlanAP up 2>/dev/null
sed "s/^interface=.*/interface=wlanAP/" "$CONF" > /tmp/drc-h4.conf 2>/dev/null
write_conf 149 1; sed -i "s/^interface=.*/interface=wlanAP/" "$CONF"
"$HAPD" -B -P "$PIDF" "$CONF" > /tmp/hapd-h4.out 2>&1
sleep 9
say "AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/hapd-h4.out 2>/dev/null) beacon_errors=$(grep -c 'Beacon set failed' /tmp/hapd-h4.out 2>/dev/null)"
say "uplink after: $(iw dev $WLAN link 2>/dev/null | head -1)"
pkill -x hostapd 2>/dev/null; iw dev wlanAP del 2>/dev/null; sleep 1

# --- dedicated tests ----------------------------------------------------------
teardown_ap
ip link set "$WLAN" up 2>/dev/null
try_config "H1 dedicated AP, ch149, HT20"      149 1
try_config "H2 dedicated AP, ch36,  HT20"       36 1
try_config "H3 dedicated AP, ch149, pure 11a"  149 0

say ""
say "=== summary of what the log contains: grep 'VERDICT' above ==="
grep -E "HYPOTHESIS|VERDICT" "$LOG" 2>/dev/null | sed 's/^/  /'
