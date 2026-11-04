#!/bin/bash
# pi-be-the-console.sh -- run as root, detached.
#
# We now hold the console's real credentials (from the WPS pairing):
#   SSID = WiiUccfb65b68169
#   PSK  = from pairing.env
#   BSSID the pad learned = cc:fb:65:b6:81:69
# So: raise an AP that *is* the console - same SSID, same key, same BSSID, and the
# Nintendo cipher selectors + PTK rotation that CONFIG_TENDONIN provides - then serve
# the pad 192.168.1.11 over DHCP and watch for it to join.
#
# The uplink is sacrificed while this runs; cleanup restores it and POSTs the log.
ROOT=/home/kali/wiiu-work
LOG=$ROOT/be-console.log
REPORT=http://192.168.86.23:8899/report
HAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
NETBOOT=$ROOT/pc2drc/drc-hostap/netboot/netboot
CONF=/tmp/be-console.conf
GW=192.168.86.1
PAD=40:d2:8a:17:e2:09
BSSID=cc:fb:65:b6:81:69
HOLD=${HOLD:-150}

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

# shellcheck disable=SC1091
. "$ROOT/pairing.env" 2>/dev/null || { say "!!! pairing.env missing"; exit 1; }
[ -n "${PSK:-}" ] || { say "!!! no PSK"; exit 1; }
say "using SSID=$CONSOLE_SSID  PSK=${PSK:0:12}...  BSSID=$BSSID"

cleanup(){
  say "--- restore"
  pkill -x hostapd 2>/dev/null; pkill -x netboot 2>/dev/null
  sleep 1
  ip addr flush dev wlan0 2>/dev/null
  ip link set wlan0 down 2>/dev/null
  iw dev wlan0 set type managed 2>/dev/null
  ip link set wlan0 up 2>/dev/null
  systemctl start NetworkManager 2>/dev/null
  systemctl start wpa_supplicant 2>/dev/null
  nmcli dev set wlan0 managed yes 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  for i in $(seq 1 45); do ping -c1 -W1 "$GW" >/dev/null 2>&1 && { say "network back ~$((i*2))s"; break; }; sleep 2; done
  say "--- RESULT: associated=$(grep -c 'AP-STA-CONNECTED' /tmp/be-console.out 2>/dev/null) ping=$(ping -c1 -W2 192.168.1.11 >/dev/null 2>&1 && echo yes || echo no)"
  say "--- station events:"
  grep -iE "AP-STA|authentication|associated|deauth|WPA|4-way" /tmp/be-console.out 2>/dev/null | tail -12 | sed 's/^/    /'
  curl -s --max-time 25 --data-binary "@$LOG" "$REPORT"
  say "=== DONE ==="
}
( sleep $((HOLD + 240)); systemctl restart NetworkManager ) >/dev/null 2>&1 &
trap cleanup EXIT

say "--- free wlan0 (uplink drops now)"
# NM itself must go: leaving the service up keeps wlan0 busy and hostapd's mode
# change fails with -16 EBUSY. Nothing needs the network until cleanup, and the
# script reports over HTTP afterwards.
systemctl stop NetworkManager 2>/dev/null
systemctl stop wpa_supplicant 2>/dev/null
nmcli dev set wlan0 managed no 2>/dev/null
pkill -x wpa_supplicant 2>/dev/null
pkill -x NetworkManager 2>/dev/null
sleep 3
say "    NM=$(systemctl is-active NetworkManager) supplicants=$(pgrep -c -x wpa_supplicant) link=$(iw dev wlan0 link 2>/dev/null | head -1)"
ip link set wlan0 down 2>/dev/null
iw dev wlan0 set type managed 2>/dev/null
say "--- bring wlan0 up WITHOUT changing its MAC"
# Setting the MAC to the console's (cc:fb:...) is what made hostapd's mode change
# fail with -16 EBUSY on every previous attempt. The pad matches on SSID + key, and
# the console's own normal AP hides its SSID, so the BSSID is not required.
ip link set wlan0 up 2>/dev/null
sleep 1
say "wlan0 MAC now: $(cat /sys/class/net/wlan0/address)"

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
macaddr_acl=0
auth_algs=3
wmm_enabled=1
uapsd_advertisement_enabled=1
wmm_ac_be_acm=0
wmm_ac_be_aifs=2
wmm_ac_be_cwmin=4
wmm_ac_be_cwmax=5
wmm_ac_be_txop_limit=47
wmm_ac_bk_acm=0
wmm_ac_bk_aifs=7
wmm_ac_bk_cwmin=4
wmm_ac_bk_cwmax=10
wmm_ac_bk_txop_limit=0
wmm_ac_vi_acm=0
wmm_ac_vi_aifs=3
wmm_ac_vi_cwmin=4
wmm_ac_vi_cwmax=5
wmm_ac_vi_txop_limit=94
wmm_ac_vo_acm=0
wmm_ac_vo_aifs=3
wmm_ac_vo_cwmin=4
wmm_ac_vo_cwmax=5
wmm_ac_vo_txop_limit=47
ieee80211n=1
ht_capab=[HT20]
ssid=$CONSOLE_SSID
ignore_broadcast_ssid=0
wpa=2
wpa_psk=$PSK
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
CFG

say "--- start hostapd as the console"
"$HAPD" -dd "$CONF" > /tmp/be-console.out 2>&1 &
sleep 8
say "AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/be-console.out)  beaconErr=$(grep -c 'Beacon set failed' /tmp/be-console.out)"
grep -m1 "Using interface" /tmp/be-console.out | sed 's/^/    /'

say "--- address the DRC network: us 192.168.1.10, pad 192.168.1.11"
ip addr add 192.168.1.10/24 dev wlan0 2>/dev/null
ip link set mtu 1800 dev wlan0 2>/dev/null
"$NETBOOT" 192.168.1.255 192.168.1.10 192.168.1.11 "$PAD" > /tmp/be-netboot.out 2>&1 &
sleep 2

say "=== waiting ${HOLD}s for the GamePad to join ==="
for i in $(seq 1 $((HOLD/5))); do
  if grep -qi "AP-STA-CONNECTED" /tmp/be-console.out; then
    say "*** ASSOCIATED: $(grep -i 'AP-STA-CONNECTED' /tmp/be-console.out | tail -1)"
  fi
  if ping -c1 -W1 192.168.1.11 >/dev/null 2>&1; then
    say "*** PING OK: 192.168.1.11 is alive at $((i*5))s"
  fi
  sleep 5
done
say "--- final station events"
grep -iE "AP-STA|authentication|associated|deauth|4-way|WPA:" /tmp/be-console.out | tail -14 | sed 's/^/    /'
say "--- ping test"
ping -c2 -W2 192.168.1.11 2>&1 | tail -3 | sed 's/^/    /'
