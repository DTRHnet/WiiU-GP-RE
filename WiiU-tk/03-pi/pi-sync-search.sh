#!/bin/bash
# pi-sync-search.sh -- run as root, detached.
#
# The GamePad is in Settings->SYNC (pairing mode) and searching for a console.
# We raise a fake pairing console (open AP named WiiU..._STA1 with Nintendo-style WPS)
# for it to find, and log every authentication/association attempt.
#
# Constraints already established:
#   * wlan0 as uplink -> AP beaconing fails, so the uplink must be sacrificed
#   * wpa_supplicant holds wlan0 -> must be stopped or hostapd gets -16 EBUSY
#   * monitor mode is refused on this driver, so we cannot see its probe targets;
#     hostapd's own log is our only window on what it does
# Cleanup always restores networking, then POSTs the log.
ROOT=/home/kali/wiiu-work
LOG=$ROOT/sync-search.log
REPORT=http://192.168.86.23:8899/report
HAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
CONF=/tmp/sync-pair.conf
GW=192.168.86.1
HOLD=${HOLD:-140}
SSID=WiiUb827eb74f26cb827eb74f26_STA1
PIN=01235678

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

cleanup(){
  say "--- restore"
  pkill -x hostapd 2>/dev/null
  sleep 1
  ip link set wlan0 down 2>/dev/null
  iw dev wlan0 set type managed 2>/dev/null
  ip link set wlan0 up 2>/dev/null
  systemctl start wpa_supplicant 2>/dev/null
  nmcli dev set wlan0 managed yes 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 45); do ping -c1 -W1 "$GW" >/dev/null 2>&1 && { say "network back ~$((i*2))s"; break; }; sleep 2; done
  say "wlan0: $(ip -br addr show wlan0 2>/dev/null | tr -s ' ')"
  say "--- association attempts seen:"
  grep -iE "AP-STA|authentication|associated|deauth|WPS" /tmp/sync-hapd.out 2>/dev/null | grep -viE "^WPS:  \*" | tail -15 | sed 's/^/    /'
  say "--- result: AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/sync-hapd.out 2>/dev/null) ASSOCIATED=$(grep -c 'AP-STA-CONNECTED' /tmp/sync-hapd.out 2>/dev/null)"
  curl -s --max-time 25 --data-binary "@$LOG" "$REPORT"
  say "=== DONE ==="
}
( sleep $((HOLD + 240)); systemctl restart NetworkManager ) >/dev/null 2>&1 &
trap cleanup EXIT

say "=== fake console up for a searching GamePad (${HOLD}s) ==="

say "--- free wlan0 (stop NM + supplicant; this drops the remote session)"
nmcli dev set wlan0 managed no 2>/dev/null
nmcli dev disconnect wlan0 2>/dev/null
systemctl stop wpa_supplicant 2>/dev/null
pkill -x wpa_supplicant 2>/dev/null
sleep 2
ip link set wlan0 down 2>/dev/null
iw dev wlan0 set type managed 2>/dev/null
ip link set wlan0 up 2>/dev/null
sleep 2
say "wlan0: $(ip -br link show wlan0 | tr -s ' ')"

cat > "$CONF" <<CFG
interface=wlan0
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
ssid=$SSID
ignore_broadcast_ssid=0
ieee8021x=1
eapol_version=1
eap_server=1
wps_pin_requests=/tmp/sync-pinreq
wps_state=2
ap_pin=$PIN
uuid=22210203-0405-0607-0809-0a0b0c0d0e0f
manufacturer=Broadcom
model_name=SoftAP
model_number=0
serial_number=0
device_type=6-a4c0e1f4-1
device_name=WiiUb827eb74f26c
os_version=80000000
config_methods=label push_button
wps_rf_bands=a
CFG
touch /tmp/sync-pinreq

say "--- starting hostapd as fake console (PIN $PIN)"
"$HAPD" -dd "$CONF" > /tmp/sync-hapd.out 2>&1 &
sleep 8
say "AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/sync-hapd.out)  beaconErr=$(grep -c 'Beacon set failed' /tmp/sync-hapd.out)"
grep -m1 "Using interface" /tmp/sync-hapd.out | sed 's/^/    /'

say "=== WATCHING ${HOLD}s for the pad to find us ==="
for i in $(seq 1 $((HOLD/5))); do
  if grep -qi "AP-STA-CONNECTED" /tmp/sync-hapd.out; then
    say "*** ASSOCIATED at ${i}x5s: $(grep -i 'AP-STA-CONNECTED' /tmp/sync-hapd.out | tail -1)"
  fi
  sleep 5
done
say "--- final attempts ---"
grep -iE "AP-STA|authentication|associated|WPS M|EAPOL" /tmp/sync-hapd.out | tail -12 | sed 's/^/    /'
