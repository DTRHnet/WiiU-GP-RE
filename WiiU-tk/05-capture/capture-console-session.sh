#!/bin/bash
# capture-console-session.sh
#
# Records a real console<->GamePad session and decrypts it with the PSK we already
# recovered from the WPS exchange.
#
# Why the handshake matters: WPA2 is not forward-secret, but the PSK alone cannot
# decrypt. The per-session key needs the nonces that only exist inside the 4-way
# handshake:
#     PTK = PRF-512(PMK, "Pairwise key expansion",
#                   min/max(AP,STA MAC) || min/max(ANonce,SNonce))
# So the capture must contain the EAPOL exchange *and* the encrypted video. tshark
# does the derivation for us given the PSK.
#
# Output: capture/console-session.pcap (raw) and capture/console-session-d.pcap
# (decrypted), plus an SPS/PPS dump.
set -uo pipefail

ROOT=/home/kali/Wiiu
CAP=$ROOT/capture
mkdir -p "$CAP"
PSK=$(grep '^PSK=' "$ROOT/pairing.env" | cut -d= -f2)
SSID=$(grep '^CONSOLE_SSID=' "$ROOT/pairing.env" | cut -d= -f2)
CONSOLE_MAC=cc:fb:65:b6:81:69
PCAP=$CAP/console-session.pcap
DPCAP=$CAP/console-session-d.pcap
LOG=$CAP/capture.log
WAIT=${WAIT:-300}
DUR=${DUR:-150}

exec > >(tee "$LOG") 2>&1
say(){ echo "[$(date '+%H:%M:%S')] $*"; }

say "=== waiting up to ${WAIT}s for the console AP ($CONSOLE_MAC) ==="
FREQ=""
for i in $(seq 1 $((WAIT/5))); do
  FREQ=$(sudo iw dev wlan0 scan 2>/dev/null | awk '/^BSS /{b=$2} /freq:/{f=$2} /signal:/{g=$2; if (b ~ /cc:fb:65:b6:81:69/) print f}')
  [ -n "$FREQ" ] && { say "console visible on ${FREQ} MHz"; break; }
  sleep 5
done
if [ -z "$FREQ" ]; then
  say "!!! console never appeared - is it powered on with a TV?"
  exit 1
fi

CHAN=$(python3 -c "f=${FREQ%.*}; print(int((f-5000)//5) if f<5925 else 0)")
say "channel: $CHAN"

say "=== monitor + capture ${DUR}s on channel $CHAN ==="
sudo iw dev mon1 del 2>/dev/null; sleep 1
sudo iw dev wlan0 interface add mon1 type monitor || { say "monitor vif failed"; exit 1; }
sudo ip link set mon1 up
sudo iw dev mon1 set channel "$CHAN" || say "  (channel set may be refused; continuing)"
sleep 1

rm -f "$PCAP"
sudo timeout "$DUR" tcpdump -i mon1 -n -s 0 -w "$PCAP" 2>/dev/null
sleep 1
say "raw capture: $(stat -c%s "$PCAP" 2>/dev/null) bytes, $(sudo tcpdump -r "$PCAP" -n 2>/dev/null | wc -l) frames"
sudo iw dev mon1 del 2>/dev/null

say "=== handshake check ==="
EAPOL=$(sudo tshark -r "$PCAP" -Y "eapol" -T fields -e frame.number 2>/dev/null | wc -l)
say "EAPOL frames captured: $EAPOL  ($([ "$EAPOL" -ge 4 ] && echo 'handshake present' || echo 'NO handshake - pad did not associate during capture'))"

say "=== decrypt with the recovered PSK ==="
sudo tshark -r "$PCAP" -o "wpa-pwd:${PSK}:${SSID}" -w "$DPCAP" -F pcap 2>&1 | tail -3
DEC=$(sudo tshark -r "$DPCAP" -Y "udp.port==50120" -T fields -e frame.number 2>/dev/null | wc -l)
say "decrypted video packets on :50120 -> $DEC"
say "next: inspect SPS/PPS and packet structure (see analyse below)"
