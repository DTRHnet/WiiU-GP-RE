#!/bin/bash
# 02 - Pair the GamePad and capture the PSK.
#
# Route A (documented, needs a Wii U console):
#   The console in pairing mode raises an open AP called WiiU<mac>_STA1 and runs
#   Nintendo's WPS variant: AuthKey = KDF(KDK rotated 3 bytes left). A stock WPS
#   client fails at message M2, so the patched wpa_supplicant below is required.
#
#   PIN = 4 digits shown on the TV as symbols (spade=0 heart=1 diamond=2 club=3)
#         + the hardcoded suffix "5678".   e.g. spade spade diamond club -> 00235678
#
# Route B (no console): host run/wiiu_ap_pairing.conf with drc-hostap and enter a
#   code of your choosing on the GamePad - see RESEARCH.md.
set -uo pipefail

IFACE="${1:-}"
WPA=/home/kali/Wiiu/pc2drc/drc-hostap/wpa_supplicant/wpa_supplicant
CLI=/home/kali/Wiiu/pc2drc/drc-hostap/wpa_supplicant/wpa_cli
CONF=/home/kali/Wiiu/run/get_psk.conf
CTRL=/var/run/wpa_supplicant_drc

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }
[ -z "$IFACE" ] && { echo "usage: $0 <drc-wifi-iface>"; exit 1; }
[ -x "$WPA" ] || { echo "missing $WPA - run build/inner-build3.sh first"; exit 1; }

# Nothing else may own the interface.
echo "[1] stopping NetworkManager's grip on $IFACE (if any)"
nmcli dev set "$IFACE" managed no 2>/dev/null || true
ip link set "$IFACE" down 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true

echo "[2] starting patched wpa_supplicant on $IFACE"
mkdir -p "$CTRL"
"$WPA" -Dnl80211 -i"$IFACE" -c"$CONF" > /var/log/drc-pair.log 2>&1 &
sleep 3

echo "[3] NOW: press SYNC twice on the Wii U console (pairing mode)."
read -r -p "     press <enter> when the console is showing the 4 symbols... " _

echo "[4] scanning for the pairing AP (WiiU<mac>_STA1)"
for i in 1 2 3 4 5 6; do
  iw dev "$IFACE" scan 2>/dev/null | grep -Eo 'WiiU[0-9a-z]{20,23}_STA1' | sort -u && break
  sleep 4
done
BSSID=$(iw dev "$IFACE" scan 2>/dev/null | grep -B8 -Eo 'WiiU[0-9a-z]{20,23}_STA1' | grep -Eo '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
[ -z "$BSSID" ] && { echo "no pairing AP seen"; exit 1; }
echo "     BSSID: $BSSID"

echo "[5] decode the 4 symbols shown on the TV:  spade=0 heart=1 diamond=2 club=3"
read -r -p "     enter the 4 digits: " FOUR
PIN="${FOUR}5678"
echo "     PIN = $PIN"

echo "[6] WPS enrolment"
"$CLI" -p "$CTRL" wps_pin "$BSSID" "$PIN"
sleep 12
"$CLI" -p "$CTRL" status 2>/dev/null | head -5

echo "[7] reading the negotiated PSK"
if grep -q "^[[:space:]]*psk=" "$CONF"; then
  PSK=$(grep -oE 'psk=[0-9a-f]{64}' "$CONF" | head -1 | cut -d= -f2)
  echo "     PSK: $PSK"
  SSIDHEX=$(echo "$BSSID" | cut -d: -f1-6 | tr -d ':' | tr 'A-F' 'a-f')
  echo "     AP SSID to use: WiiU$SSIDHEX"
  printf 'IFACE=%s\nSSID=WiiU%s\nPSK=%s\nCONSOLE_MAC=%s\n' \
         "$IFACE" "$SSIDHEX" "$PSK" "$BSSID" > /home/kali/Wiiu/run/pairing.env
  chmod 600 /home/kali/Wiiu/run/pairing.env
  echo "     saved -> run/pairing.env"
else
  echo "     no PSK yet; check /var/log/drc-pair.log and retry"
fi

kill %1 2>/dev/null
echo "done"
