#!/bin/bash
# 12-capture-truth.sh - capture a REAL console<->GamePad session so it can be
# decrypted and diffed against our stack.
#
# Why this exists: as of 2026-11-04 our stack matches the console on every
# property that can be measured from our side alone (vstrm options, 5x6-MB-row
# chunks, 59.94 fps, payload <=1694, byte-exact video-format message, PCM audio
# and format messages from source ports 50020/50021, UVC/UAC little-endian, and
# a UIC config exchange that is byte-identical to Barista's known-good command).
# The pad still shows "could not connect" and sends NO media return traffic to
# 50020/50021, so the difference must be inside the console's own media/session
# sequencing or DRH payload, which is only observable in a real capture.
#
# HOW TO USE (operator steps):
#   1. Have the console ON and the GamePad connected to the CONSOLE as usual
#      (not to us). Do NOT power the pad off - the capture needs the session.
#   2. Plug the USB dongle in as the Internet uplink (wlan1). wlan0 = AX210 is
#      used as the 5 GHz monitor. The uplink must stay up: this script refuses
#      to run without it.
#   3. Run:  sudo ./run/12-capture-truth.sh [CHANNEL] [SECONDS]
#      Then make the pad RECONNECT to the console while it records - the whole
#      point is to catch the 4-way handshake that is actually in force. The
#      reliable way: briefly press the pad's power button to let it sleep, then
#      wake it; or dock/undock it. Recording starts BEFORE that.
#   4. Afterwards run:  ./tests/decrypt-capture.sh <pcap>
#
# Evidence needed for a decisive diff: the handshake + at least ~5 s of video.
set -uo pipefail
ROOT=/home/kali/Wiiu
OUT=$ROOT/capture
CAP=${CAP:-$OUT/console-truth.pcap}
LOG=$OUT/capture-truth.log
CHAN=${1:-149}
DUR=${2:-180}
IF=wlan0
mkdir -p "$OUT"
exec > >(tee "$LOG") 2>&1
say(){ echo "[$(date '+%H:%M:%S')] $*"; }

say "=== preflight: uplink must be on something other than $IF ==="
UP=$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
say "uplink is ${UP:-none}"
[ "${UP:-}" != "$IF" ] || { say "!! $IF carries the default route; plug the dongle in so the uplink moves"; exit 1; }
ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 || { say "!! no internet; refusing to free $IF"; exit 1; }

cleanup(){
  say "--- restoring $IF"
  sudo pkill -x tcpdump 2>/dev/null
  sleep 1
  sudo ip link set $IF down 2>/dev/null
  sudo iw dev $IF set type managed 2>/dev/null
  sudo ip link set $IF up 2>/dev/null
  sudo nmcli dev set $IF managed yes 2>/dev/null
  say "link state: $(iw dev $IF link 2>/dev/null | head -1)"
}
trap cleanup EXIT

say "=== stopping our DRC AP so the pad goes back to the console ==="
sudo "$ROOT/run/drc-down.sh" || true
sleep 2

say "=== $IF -> monitor on channel $CHAN for ${DUR}s ==="
sudo nmcli dev set $IF managed no 2>/dev/null
sudo iw dev $IF set type monitor 2>/dev/null || { say "!! cannot set monitor mode"; exit 1; }
sudo ip link set $IF up
sudo iw dev $IF set channel "$CHAN" 2>/dev/null && say "tuned to $CHAN" || say "!! tune failed"
say "RECORDING - now make the GamePad reconnect to the console (sleep->wake)"
sudo timeout "$DUR" tcpdump -i $IF -n -w "$CAP" 'udp or (wlan type mgmt)' 2>/dev/null
say "capture written: $CAP ($(du -h "$CAP" | cut -f1))"
say "next: ./tests/decrypt-capture.sh $CAP"
