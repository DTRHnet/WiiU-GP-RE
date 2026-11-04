#!/bin/bash
# 03 - Raise the DRC access point so the GamePad joins us as if we were the console.
#
# Needs run/pairing.env (written by 02-pair.sh): IFACE, SSID, PSK.
# Channel: the console hops channels, but the GamePad follows whatever channel the
# AP advertises. 36 is the safe default; try 165 / the channel your console used
# if the GamePad refuses to associate.
set -uo pipefail

ROOT=/home/kali/Wiiu
AP=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
NETBOOT=$ROOT/pc2drc/drc-hostap/netboot/netboot
ENVF=$ROOT/run/pairing.env
CONF=/var/run/drc-ap.conf
CHANNEL="${CHANNEL:-36}"
GAMEPAD_MAC="${GAMEPAD_MAC:-}"

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }
[ -f "$ENVF" ] || { echo "missing $ENVF - run 02-pair.sh first"; exit 1; }
# shellcheck disable=SC1090
. "$ENVF"
[ -n "${PSK:-}" ] || { echo "no PSK in $ENVF"; exit 1; }

echo "[1] detaching $IFACE from NetworkManager"
# Do NOT bounce the link. On brcmfmac (Pi 5) a plain `ip link set down` followed by
# `up` leaves the interface DOWN/NO-CARRIER for good - only a NetworkManager restart
# recovers it - and any hostapd run afterwards fails with "Could not connect to
# kernel driver" / "Failed to set beacon parameters". Just detach and leave it up.
nmcli dev set "$IFACE" managed no 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true
sleep 1

# The GamePad learns an SSID *and* a BSSID during WPS pairing, and may refuse an AP
# that does not present the console's MAC. Pinning it is the most likely single fix
# if the pad associates but never streams. PIN_MAC=0 disables this.
AP_MAC="${AP_MAC:-${CONSOLE_MAC:-}}"
APIF="$IFACE"
if [ -n "$AP_MAC" ] && [ "${PIN_MAC:-1}" != "0" ]; then
  echo "    pinning AP MAC to $AP_MAC via a virtual __ap interface"
  iw dev "$IFACE" interface add WiiUAP type __ap 2>/dev/null || true
  ip link set WiiUAP down 2>/dev/null || true
  if ip link set WiiUAP address "$AP_MAC" 2>/dev/null; then
    echo "    WiiUAP MAC now $(cat /sys/class/net/WiiUAP/address 2>/dev/null)"
  else
    echo "    WARN: could not set the MAC; continuing with the default"
  fi
  ip link set WiiUAP up 2>/dev/null || true
  APIF=WiiUAP
fi

echo "[2] rendering AP config for $APIF (ssid=$SSID channel=$CHANNEL)"
sed -e "s/__IFACE__/$APIF/" -e "s/__SSID__/$SSID/" \
    -e "s/__PSK__/$PSK/" -e "s/__CHANNEL__/$CHANNEL/" \
    "$ROOT/run/wiiu_ap_normal.conf.template" > "$CONF"
chmod 600 "$CONF"

ip addr add 192.168.1.10/24 dev "$APIF"
ip link set mtu 1800 dev "$APIF"
echo "    $(ip -br addr show "$APIF")"

echo "[3] starting hostapd (patched: Nintendo OUI a4:c0:e1 + PTK rot3)"
"$AP" -dd "$CONF" > /var/log/drc-ap.log 2>&1 &
sleep 5
if ! grep -qi "AP-ENABLED\|Setup of interface done" /var/log/drc-ap.log; then
  echo "    hostapd did not come up - tail of /var/log/drc-ap.log:"
  tail -15 /var/log/drc-ap.log
  exit 1
fi
echo "    AP is up. Power on the GamePad now."

echo "[4] waiting for the GamePad to associate (up to 60s)"
for i in $(seq 1 30); do
  MAC=$(grep -Eo "AP-STA-CONNECTED ([0-9a-f:]{17})" /var/log/drc-ap.log | tail -1 | awk '{print $2}')
  [ -n "$MAC" ] && { echo "    GamePad associated: $MAC"; break; }
  sleep 2
done
if [ -z "${MAC:-}" ]; then
  echo "    no association yet. Checks:"
  echo "      - GamePad powered on and in range (5GHz)"
  echo "      - SSID/PSK really came from pairing"
  echo "      - try CHANNEL=165 $0"
  tail -20 /var/log/drc-ap.log
  exit 1
fi

echo "[5] DHCP: handing the GamePad 192.168.1.11"
if [ -z "$GAMEPAD_MAC" ]; then
  echo "    discovering the requesting MAC (run netboot once with no args):"
  timeout 20 "$NETBOOT" 2>&1 | head -5 || true
  GAMEPAD_MAC="$MAC"
fi
"$NETBOOT" 192.168.1.255 192.168.1.10 192.168.1.11 "$GAMEPAD_MAC" > /var/log/drc-dhcp.log 2>&1 &
sleep 3

echo "[6] verification"
ping -c 2 -W 2 192.168.1.11 && echo "    PASS: GamePad answers at 192.168.1.11" \
  || echo "    FAIL: no ping response yet (DHCP may still be settling)"
echo
echo "AP running. Next: run/04-stream.sh $IFACE"
