#!/bin/bash
# pi-deploy-videofix.sh - push the GamePad parameter-set fix to the Pi and drive
# the on-pad verification.
#
# Context (see out/evidence/VIDEO-PARAMSET-FINDING.md):
#   The GamePad decodes against a HARDCODED SPS with
#   log2_max_frame_num_minus4 = 4 (8-bit frame_num). Stock x264 emits 5 bits for
#   our keyint, which desynchronises every slice header. drc-x264's
#   encoder/set.c is patched to force 8 bits.
#
# Usage:
#   ./run/pi-deploy-videofix.sh patch    # patch + rebuild x264, verify emitted SPS
#   ./run/pi-deploy-videofix.sh ap       # raise the DRC AP (needs eth0 for uplink)
#   ./run/pi-deploy-videofix.sh stream   # bridge Kali's desktop to the pad
#   ./run/pi-deploy-videofix.sh all      # patch, then ap, then stream
#
# Requirements on the Pi: reachable over eth0, NOPASSWD sudo, sources in
# ~/wiiu-work, and wlan0 FREE (the brcmfmac radio cannot be uplink + AP).
set -uo pipefail

PI_HOST="${PI_HOST:-192.168.86.28}"
PI_USER="${PI_USER:-kali}"
ROOT_LOCAL=/home/kali/Wiiu
PI_ROOT="${PI_ROOT:-/home/kali/wiiu-work}"
KALI_IP_FOR_VNC="${KALI_IP_FOR_VNC:-192.168.86.30}"

SSH="ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no ${PI_USER}@${PI_HOST}"
say() { printf '\n== %s\n' "$*"; }

check_pi() {
  say "checking ${PI_USER}@${PI_HOST}"
  if ! $SSH true 2>/dev/null; then
    echo "Pi unreachable over SSH."
    echo "Needs: (1) powered on, (2) Ethernet in eth0 - the brcmfmac radio cannot"
    echo "be uplink + AP at once, so wlan0 must be free for the DRC AP."
    exit 1
  fi
  $SSH 'uname -m; ls /sys/class/net; ip -br addr show eth0 2>/dev/null | head -1'
  say "TSF patch (libdrc needs /sys/class/net/<if>/tsf)"
  $SSH 'ls /sys/class/net/*/tsf 2>/dev/null || echo "  MISSING - load the patched module first (run/pi-fix.sh)"'
}

do_patch() {
  say "patching drc-x264 on the Pi (force 8-bit frame_num)"
  $SSH "cd ${PI_ROOT}/pc2drc/drc-x264 && cp -n encoder/set.c encoder/set.c.bak-videofix && \
    python3 - <<'PY'
import re
p='encoder/set.c'
s=open(p).read()
if 'Wii U GamePad compatibility' in s:
    print('  already patched')
else:
    old='''    sps->i_log2_max_frame_num = 4;
    while( (1 << sps->i_log2_max_frame_num) <= max_frame_num )
        sps->i_log2_max_frame_num++;'''
    new=old+'''
    /* Wii U GamePad compatibility: the pad decodes against a hardcoded SPS
     * with log2_max_frame_num_minus4 = 4 (8-bit frame_num). Any other width
     * desynchronises every slice header and the pad rejects the stream. */
    sps->i_log2_max_frame_num = 8;'''
    assert old in s, 'anchor not found - set.c already differs'
    open(p,'w').write(s.replace(old,new))
    print('  patched')
PY"

  say "rebuilding libx264 on the Pi"
  $SSH "cd ${PI_ROOT}/pc2drc/drc-x264 && make -j\$(nproc) 2>&1 | tail -3"

  say "deploying it where libdrc loads it from"
  $SSH "cd ${PI_ROOT}/pc2drc/drc-x264 && \
    for d in ${PI_ROOT}/out/x264/lib ${PI_ROOT}/../out/x264/lib; do \
      [ -d \"\$d\" ] && cp -f libx264.so.140 \"\$d/\" && echo \"  updated \$d\"; \
    done; true"

  say "verifying the SPS the Pi's encoder now emits"
  scp -q "${ROOT_LOCAL}/pc2drc/sps_probe.c" "${PI_USER}@${PI_HOST}:/tmp/sps_probe.c"
  $SSH "cd ${PI_ROOT}/pc2drc && gcc -O2 -I./drc-x264 /tmp/sps_probe.c ./drc-x264/libx264.a -lm -lpthread -o /tmp/sps_probe 2>&1 | head -3; \
        /tmp/sps_probe ultrafast 0 0" | head -4
  echo
  echo "Expect an SPS whose log2_max_frame_num_minus4 is 4. The 8-bit value shows"
  echo "up as the SPS differing from the pre-fix 674d401ea680d83de6e1..."
}

do_ap() {
  say "raising the DRC AP on the Pi"
  $SSH "cd ${ROOT_LOCAL}/run 2>/dev/null || cd ${PI_ROOT}/run; sudo -E ./pi-standard-ap.sh" 2>&1 | tail -30
}

do_stream() {
  say "starting x11vnc on Kali so the pad sees THIS desktop"
  if ! pgrep -x x11vnc >/dev/null; then
    x11vnc -display :0 -rfbport 5900 -nopw -forever -shared \
           -scale 0.46875 -noxdamage -allow 192.168.86.0/24 -bg -quiet
    sleep 2
  fi
  say "starting drcvncclient on the Pi (bridge to ${KALI_IP_FOR_VNC})"
  $SSH "cd ${PI_ROOT} && VNC_HOST=${KALI_IP_FOR_VNC} sudo -E ./run/04-stream.sh" 2>&1 | tail -40
}

check_pi
case "${1:-all}" in
  patch)  do_patch ;;
  ap)     do_ap ;;
  stream) do_stream ;;
  all)    do_patch; do_ap; do_stream ;;
  *) echo "usage: $0 {patch|ap|stream|all}"; exit 1 ;;
esac
