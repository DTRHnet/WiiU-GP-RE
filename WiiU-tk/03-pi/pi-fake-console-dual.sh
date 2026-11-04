#!/bin/bash
# pi-fake-console-dual.sh -- run as root, detached.
#
# Correct topology: wlan1 (USB dongle, 2.4 GHz) is the uplink and stays under
# NetworkManager; only wlan0 (5 GHz, brcmfmac) is detached so it can be the AP.
# Do NOT stop NetworkManager here - that would take wlan1 down with it, which is
# exactly what broke the previous attempts.
#
# Also: do NOT change wlan0's MAC. Every attempt that set it to the console's MAC made
# hostapd's AP mode change fail with -16 EBUSY. The pad matches on SSID + key.
#
# Credentials came from a real WPS pairing with the console, so this AP *is* the
# console as far as the pad is concerned.
ROOT=/home/kali/wiiu-work
LOG=$ROOT/fake-console.log
REPORT=http://192.168.86.23:8899/report
HAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
NETBOOT=$ROOT/pc2drc/drc-hostap/netboot/netboot
CONF=/tmp/fake-console.conf
PAD=40:d2:8a:17:e2:09
HOLD=${HOLD:-180}
GW=192.168.86.1

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

. "$ROOT/pairing.env" 2>/dev/null || { say "!!! pairing.env missing"; exit 1; }
[ -n "${PSK:-}" ] || { say "!!! no PSK"; exit 1; }
say "SSID=$CONSOLE_SSID  PSK=${PSK:0:12}...  (pad will be handed 192.168.1.11)"

cleanup(){
  say "--- teardown"
  pkill -x hostapd 2>/dev/null; pkill -x netboot 2>/dev/null
  sleep 1
  ip addr flush dev wlan0 2>/dev/null
  nmcli dev set wlan0 managed yes 2>/dev/null
  sleep 2
  say "--- RESULT associated=$(grep -c 'AP-STA-CONNECTED' /tmp/fc-hapd.out 2>/dev/null) ping11=$(ping -c1 -W2 192.168.1.11 >/dev/null 2>&1 && echo yes || echo no)"
  say "--- station events:"
  grep -iE "AP-STA|authentication|associated|deauth|4-way|WPA:" /tmp/fc-hapd.out 2>/dev/null | tail -14 | sed 's/^/    /'
  curl -s --max-time 25 --data-binary "@$LOG" "$REPORT" 2>/dev/null
  say "=== DONE ==="
}
( sleep $((HOLD + 240)); pkill -x hostapd ) >/dev/null 2>&1 &
trap cleanup EXIT

say "--- detach ONLY wlan0 (wlan1/dongle keeps the uplink)"
nmcli dev set wlan0 managed no 2>/dev/null
nmcli dev disconnect wlan0 2>/dev/null
sleep 3
say "wlan1 uplink: $(ip -br addr show wlan1 2>/dev/null | tr -s ' ')"
say "wlan0:        $(ip -br link show wlan0 2>/dev/null | tr -s ' ') link=$(iw dev wlan0 link 2>/dev/null | head -1)"
ip link set wlan0 up 2>/dev/null
sleep 2

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

say "--- hostapd as the console (patched: Nintendo OUI + PTK rot3)"
"$HAPD" -dd "$CONF" > /tmp/fc-hapd.out 2>&1 &
sleep 8
say "AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/fc-hapd.out)  beaconErr=$(grep -c 'Beacon set failed' /tmp/fc-hapd.out)  busyErr=$(grep -c 'busy' /tmp/fc-hapd.out)"
grep -m1 "Using interface" /tmp/fc-hapd.out | sed 's/^/    /'

say "--- DRC network: us 192.168.1.10, pad 192.168.1.11, MTU 1800"
ip addr add 192.168.1.10/24 dev wlan0 2>/dev/null
ip link set mtu 1800 dev wlan0 2>/dev/null
"$NETBOOT" 192.168.1.255 192.168.1.10 192.168.1.11 "$PAD" > /tmp/fc-netboot.out 2>&1 &
sleep 1

say "=== waiting ${HOLD}s ==="
for i in $(seq 1 $((HOLD/5))); do
  grep -qi "AP-STA-CONNECTED" /tmp/fc-hapd.out && say "*** ASSOCIATED at $((i*5))s: $(grep -i 'AP-STA-CONNECTED' /tmp/fc-hapd.out | tail -1)"
  ping -c1 -W1 192.168.1.11 >/dev/null 2>&1 && say "*** PING 192.168.1.11 OK at $((i*5))s"
  sleep 5
done
say "--- final"
grep -iE "AP-STA|associated|deauth" /tmp/fc-hapd.out | tail -8 | sed 's/^/    /'
