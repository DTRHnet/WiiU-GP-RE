#!/bin/bash
# pi-standard-ap.sh -- run as root, ON THE PI, with wlan1 (dongle) as the uplink.
#
# THE HYPOTHESIS THIS TESTS:
# The libdrc note that the Wii U "refuses your connection with error 0x000c" unless you
# advertise a4:c0:e1 applies to a *supplicant joining the console's AP*. The GamePad
# joining *our* AP may simply follow whatever RSN IE we advertise. If so, a plain
# standard-WPA2 AP carrying the console's real SSID+PSK is enough, and we skip the
# kernel patch that Nintendo's cipher selectors would otherwise require
# (the kernel rejects them with -22 EINVAL).
#
# So: STOCK hostapd (/usr/sbin/hostapd), standard CCMP, real credentials.
ROOT=/home/kali/wiiu-work
LOG=$ROOT/standard-ap.log
REPORT=http://192.168.86.23:8899/report
NETBOOT=$ROOT/pc2drc/drc-hostap/netboot/netboot
CONF=/tmp/std-ap.conf
PAD=40:d2:8a:17:e2:09
HOLD=${HOLD:-180}

exec > "$LOG" 2>&1
ts(){ date '+%H:%M:%S'; }
say(){ echo "[$(ts)] $*"; }

. "$ROOT/pairing.env" 2>/dev/null || { say "!!! pairing.env missing"; exit 1; }
say "SSID=$CONSOLE_SSID  PSK=${PSK:0:12}...  (standard WPA2, stock hostapd)"

cleanup(){
  say "--- teardown"
  pkill -x hostapd 2>/dev/null; pkill -x netboot 2>/dev/null
  sleep 1
  ip addr flush dev wlan0 2>/dev/null
  nmcli dev set wlan0 managed yes 2>/dev/null
  systemctl restart NetworkManager 2>/dev/null
  sleep 3
  say "--- RESULT associated=$(grep -c 'AP-STA-CONNECTED' /tmp/std-hapd.out 2>/dev/null) ping11=$(ping -c1 -W2 192.168.1.11 >/dev/null 2>&1 && echo yes || echo no)"
  say "--- station events:"
  grep -iE "AP-STA|authentication|associated|deauth|WPA|4-way" /tmp/std-hapd.out 2>/dev/null | tail -16 | sed 's/^/    /'
  curl -s --max-time 25 --data-binary "@$LOG" "$REPORT" 2>/dev/null
  say "=== DONE ==="
}
trap cleanup EXIT

say "--- wlan0 must exist; reload brcmfmac if the chip was left unresponsive"
if [ ! -d /sys/class/net/wlan0 ]; then
  say "    wlan0 missing -> modprobe -r/+ brcmfmac"
  modprobe -r brcmfmac 2>/dev/null; sleep 2; modprobe brcmfmac 2>/dev/null; sleep 8
fi
if [ ! -d /sys/class/net/wlan0 ]; then
  say "!!! wlan0 still missing (chip needs a power cycle: 'dongle is not responding')"
  exit 1
fi
say "    wlan0 present: $(cat /sys/class/net/wlan0/address)"

say "--- detach wlan0 from NetworkManager (uplink stays on wlan1/dongle)"
nmcli dev set wlan0 managed no 2>/dev/null
nmcli dev disconnect wlan0 2>/dev/null
sleep 3
ip link set wlan0 up 2>/dev/null
sleep 1
say "    wlan0: $(ip -br link show wlan0 | tr -s ' ')  link=$(iw dev wlan0 link 2>/dev/null | head -1)"
say "    wlan1: $(ip -br addr show wlan1 2>/dev/null | tr -s ' ')"

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
uapsd_advertisement_enabled=1
ieee80211n=1
ht_capab=[HT20]
ssid=$CONSOLE_SSID
ignore_broadcast_ssid=0
wpa=2
wpa_psk=$PSK
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
CFG

say "--- starting STOCK hostapd (standard CCMP, /usr/sbin/hostapd)"
/usr/sbin/hostapd -dd "$CONF" > /tmp/std-hapd.out 2>&1 &
sleep 8
say "AP-ENABLED=$(grep -c 'AP-ENABLED' /tmp/std-hapd.out)  beaconErr=$(grep -c 'Beacon set failed' /tmp/std-hapd.out)  einval=$(grep -c 'Invalid argument' /tmp/std-hapd.out)"
grep -m1 "Using interface" /tmp/std-hapd.out | sed 's/^/    /'
a=$(cat /sys/class/net/wlan0/statistics/tx_packets 2>/dev/null); sleep 5; b=$(cat /sys/class/net/wlan0/statistics/tx_packets 2>/dev/null)
say "tx_packets delta over 5s: $(( ${b:-0} - ${a:-0} )) (beacons alone ~50 => AP is really on air)"

say "--- DRC network: us 192.168.1.10, pad 192.168.1.11, MTU 1800"
ip addr add 192.168.1.10/24 dev wlan0 2>/dev/null
ip link set mtu 1800 dev wlan0 2>/dev/null
"$NETBOOT" 192.168.1.255 192.168.1.10 192.168.1.11 "$PAD" > /tmp/std-netboot.out 2>&1 &

say "=== waiting ${HOLD}s for the GamePad ==="
for i in $(seq 1 $((HOLD/5))); do
  grep -qi "AP-STA-CONNECTED" /tmp/std-hapd.out && say "*** ASSOCIATED at $((i*5))s: $(grep -i 'AP-STA-CONNECTED' /tmp/std-hapd.out | tail -1)"
  ping -c1 -W1 192.168.1.11 >/dev/null 2>&1 && say "*** PING 192.168.1.11 OK at $((i*5))s"
  sleep 5
done
say "--- final events"
grep -iE "AP-STA|associated|deauth|authentication" /tmp/std-hapd.out | tail -10 | sed 's/^/    /'
