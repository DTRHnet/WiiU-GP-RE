#!/bin/bash
# 05 - Diagnose: is the GamePad actually speaking DRC to us, or merely associated?
#
# Ping alone proves nothing. The GamePad only counts as "talking" once it exchanges
# DRC service traffic. Ports come from libdrc's own constants
# (include/drc/streamer.h) and match libdrc.org/docs/re/services.html:
#
#   console (us) 192.168.1.10            pad 192.168.1.11
#   video    send ->                        50120
#   audio    send ->                        50121
#   input    bind 50022  <-                 50122
#   command  bind 50023  <->                50123
#   message  bind 50010
#
# Usage: sudo ./05-diagnose.sh [iface]        (DUR=30 to watch longer)
set -uo pipefail
IFACE="${1:-${IFACE:-}}"
DUR="${DUR:-20}"
PAD=192.168.1.11
US=192.168.1.10
PCAP=/tmp/drc-diag.pcap

[ "$(id -u)" -eq 0 ] || { echo "must run as root (needs tcpdump)"; exit 1; }

echo "=== 1. layer 2: is the GamePad on our AP? ==="
if command -v iw >/dev/null && [ -n "$IFACE" ]; then
  iw dev "$IFACE" station dump 2>/dev/null | grep -E "Station|signal:|rx bytes|tx bytes" | head -12 \
    || echo "  no stations on $IFACE"
else
  echo "  (pass the interface as \$1 to list associated stations)"
fi

echo
echo "=== 2. layer 3: does it have 192.168.1.11? ==="
ip neigh show $PAD 2>/dev/null | sed 's/^/  /' || true
ping -c 2 -W 2 $PAD >/dev/null 2>&1 && echo "  ICMP: replies" || echo "  ICMP: no reply (DHCP may not be serving yet)"

echo
echo "=== 3. layer 4: DRC service traffic for ${DUR}s ==="
echo "  If the GamePad is speaking DRC you should see:"
echo "    50122 -> 50022   input stream (the GamePad sending its buttons/touch)"
echo "    50123 -> 50023   command protocol"
echo "    ...    -> 50120   our video stream to the pad"
echo
timeout "$DUR" tcpdump -i "${IFACE:-any}" -n -w "$PCAP" \
        "udp and host $PAD" >/dev/null 2>&1
[ -s "$PCAP" ] || { echo "  no UDP traffic with $PAD captured"; exit 1; }

echo "  observed flows:"
tcpdump -n -r "$PCAP" 2>/dev/null \
  | awk '{for(i=1;i<=NF;i++) if($i ~ /^192\.168\.1\.(10|11)\.[0-9]+$/ || $i ~ /^192\.168\.1\.(10|11)$/) printf "%s ", $i; print ""}' \
  | tr -s ' ' | sort | uniq -c | sort -rn | head -20 | sed 's/^/    /'

echo
seen=$(tcpdump -n -r "$PCAP" 2>/dev/null | grep -cE "192\.168\.1\.11\.50122 > 192\.168\.1\.10\.50022")
if [ "${seen:-0}" -gt 0 ]; then
  echo "  PASS: GamePad is streaming input to us ($seen packets on 50122->50022)"
  echo "        the DRC link is up - run 04-stream.sh"
else
  echo "  no input stream yet. Checks, in order:"
  echo "    - GamePad powered on and showing the 'cannot connect' screen?"
  echo "    - SSID/PSK really came from pairing (run/pairing.env)"
  echo "    - try pinning the AP MAC to the console MAC (see SETUP.md)"
  echo "    - try CHANNEL=165 with 03-ap.sh"
fi
echo
echo "raw capture kept at $PCAP"
