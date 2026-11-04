#!/bin/bash
# decrypt-capture.sh - take a captured console<->pad session and report whether
# it can be decrypted, then decrypt it and extract the H.264 payload.
#
# A capture can only be decrypted if it contains the 4-way handshake that is
# actually in force for the session (the PTK is derived from it). Earlier
# captures failed for exactly this reason: the pad had associated on a channel
# we were not monitoring, so the key in force predated the capture. Capture
# from BEFORE association (run/12-capture-truth.sh does that).
#
# Usage: ./tests/decrypt-capture.sh capture/console-truth.pcap
set -uo pipefail
ROOT=/home/kali/Wiiu
PCAP=${1:?usage: decrypt-capture.sh <pcap>}
[ -f "$PCAP" ] || { echo "no such file: $PCAP"; exit 1; }

# The PSK obtained in round 4 via WPS pairing (see run/pairing.env).
. "$ROOT/run/pairing.env"
echo "== capture: $PCAP ($(du -h "$PCAP" | cut -f1))"
echo "== SSID=$SSID  PSK=${PSK:0:8}..."

echo
echo "== EAPOL (4-way handshake) frames in the capture:"
count=$(tshark -r "$PCAP" -Y 'eapol' -T fields -e frame.number 2>/dev/null | wc -l)
echo "   $count"
if [ "$count" -lt 4 ]; then
  cat <<'MSG'
   NOT ENOUGH: a complete 4-way handshake (4 EAPOL frames per association) is
   required. Re-capture with the monitor tuned to the console's channel and
   start recording BEFORE the pad associates (sleep->wake the pad mid-capture).
MSG
  exit 2
fi

echo
echo "== trying decryption + payload extraction (out/evidence/decrypt_h264.py)"
python3 "$ROOT/out/evidence/decrypt_h264.py" "$PCAP" 2>&1 | tail -25
