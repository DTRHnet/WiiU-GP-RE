#!/bin/bash
# pi-pair-wps.sh -- run as root, detached:  sudo PIN=0123 ./pi-pair-wps.sh
#
# Route A, the documented one (libdrc web/docs/network.rst): act as a WPS *client* of
# the console's pairing AP and let it hand us the real SSID and PSK.
#
#   console in pairing mode -> open AP "WiiU<mac>_STA1" -> modified WPS where
#   AuthKey = KDF(KDK rotated 3 bytes left), PIN = 4 symbol digits + "5678".
#   Stock wpa_supplicant fails at M2 for exactly that reason; ours is built with
#   CONFIG_TENDONIN and gets past it.
#
# We do NOT derive the PSK ourselves: the console generates it randomly and ships it
# encrypted in the WPS credential. Only a real WPS exchange reveals it, which is why
# this beats trying to sniff it (monitor mode is refused by brcmfmac/nexmon here).
#
# The uplink dies for the duration; cleanup always restores it and POSTs the result.
ROOT=/home/kali/wiiu-work
LOG=$ROOT/pair-wps.log
REPORT=http://192.168.86.23:8899/report
WPA=$ROOT/pc2drc/drc-hostap/wpa_supplicant/wpa_supplicant
CLI=$ROOT/pc2drc/drc-hostap/wpa_supplicant/wpa_cli
CONF=/tmp/pair-get_psk.conf
CTRL=/var/run/wpa_supplicant_drc
GW=192.168.86.1
PIN="${PIN:?run as: sudo PIN=0123 ./pi-pair-wps.sh}"
FULLPIN="${PIN}5678"

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

cleanup(){
  say "--- restore networking"
  pkill -x wpa_supplicant 2>/dev/null
  sleep 1
  ip link set wlan0 down 2>/dev/null
  iw dev wlan0 set type managed 2>/dev/null
  ip link set wlan0 up 2>/dev/null
  systemctl start wpa_supplicant 2>/dev/null
  nmcli dev set wlan0 managed yes 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 45); do ping -c1 -W1 "$GW" >/dev/null 2>&1 && { say "network back after ~$((i*2))s"; break; }; sleep 2; done
  say "wlan0: $(ip -br addr show wlan0 2>/dev/null | tr -s ' ')"
  curl -s --max-time 25 --data-binary "@$LOG" "$REPORT"
  say "=== DONE ==="
}
( sleep 420; systemctl restart NetworkManager ) >/dev/null 2>&1 &
trap cleanup EXIT

say "=== WPS client pairing, PIN=${FULLPIN} ==="
[ -x "$WPA" ] || { say "!!! $WPA missing"; exit 1; }

say "--- free wlan0 from NM + supplicant"
nmcli dev set wlan0 managed no 2>/dev/null
nmcli dev disconnect wlan0 2>/dev/null
systemctl stop wpa_supplicant 2>/dev/null
pkill -x wpa_supplicant 2>/dev/null
sleep 2
ip link set wlan0 down 2>/dev/null
iw dev wlan0 set type managed 2>/dev/null
ip link set wlan0 up 2>/dev/null
sleep 2
say "wlan0: $(ip -br link show wlan0 | tr -s ' ')  type=$(iw dev wlan0 info 2>/dev/null | awk '/type/{print $2}')"

cat > "$CONF" <<CFG
ctrl_interface=$CTRL
update_config=1
CFG
mkdir -p "$CTRL"
chmod 777 "$CTRL" 2>/dev/null

say "--- start patched wpa_supplicant"
"$WPA" -Dnl80211 -i wlan0 -c "$CONF" > /tmp/wpa-run.log 2>&1 &
sleep 4
say "supplicant: $(pgrep -c -x wpa_supplicant) procs; $(tail -2 /tmp/wpa-run.log | tr '\n' ' ')"

say "--- locate the console's pairing AP"
BSSID="${BSSID_OVERRIDE:-}"   # the console hides its SSID; we know its BSSID
if [ -n "$BSSID" ]; then say "    using supplied BSSID $BSSID"; fi
for i in $(seq 1 10); do
  [ -n "$BSSID" ] && break
  SSIDLINE=$(iw dev wlan0 scan 2>/dev/null | grep -B12 -oE "WiiU[0-9a-z]{10,30}_STA1" | head -1)
  if [ -z "$SSIDLINE" ]; then
     SSIDLINE=$(iw dev wlan0 scan 2>/dev/null | grep -oE "WiiU[0-9a-z]{10,30}_STA1" | head -1)
     BSSID=$(iw dev wlan0 scan 2>/dev/null | grep -B20 -E "WiiU[0-9a-z]{10,30}_STA1" | grep -oE "([0-9a-f]{2}:){5}[0-9a-f]{2}" | head -1)
  fi
  [ -n "$BSSID" ] && break
  say "    scan $i: nothing yet"
  sleep 4
done
if [ -z "$BSSID" ]; then
  say "!!! console pairing AP not found. Is the console in pairing mode (SYNC twice)?"
  say "    SSIDs visible:"; iw dev wlan0 scan 2>/dev/null | grep "SSID:" | sort -u | head -10 | sed 's/^/      /'
  exit 1
fi
say "    found AP: $SSIDLINE  BSSID=$BSSID"

say "--- wps_pin $BSSID $FULLPIN"
"$CLI" -p "$CTRL" wps_pin "$BSSID" "$FULLPIN" 2>&1 | head -4
for i in $(seq 1 20); do
  if grep -qE "WPS-SUCCESS|CTRL-EVENT-CONNECTED" /tmp/wpa-run.log; then say "    WPS reported success"; break; fi
  sleep 3
done
say "--- supplicant status"
"$CLI" -p "$CTRL" status 2>&1 | head -8 | sed 's/^/    /'

say "--- reading PSK"
if grep -qE "psk=[0-9a-f]{64}" "$CONF" 2>/dev/null; then
  PSK=$(grep -oE "psk=[0-9a-f]{64}" "$CONF" | head -1 | cut -d= -f2)
  say "*** PSK = $PSK"
  say "*** console SSID = $(grep -oE 'ssid="[^"]*"' "$CONF" | head -1)"
  printf 'CONSOLE_SSID=%s\nPSK=%s\nCONSOLE_BSSID=%s\n' \
    "$(grep -oE 'ssid="[^"]*"' "$CONF" | head -1 | cut -d'"' -f2)" "$PSK" "$BSSID" \
    > "$ROOT/pairing.env"
  chmod 600 "$ROOT/pairing.env"
  say "*** saved to $ROOT/pairing.env"
else
  say "!!! no PSK in config. wpa_supplicant log:"
  tail -20 /tmp/wpa-run.log | sed 's/^/    /'
fi
