#!/bin/bash
# pi-push-tree.sh - send the pc2drc sources + run scripts to the Pi.
#
# x86-64 build artifacts (*.o, *.a, *.so*, and the compiled tools) are excluded:
# they are useless on aarch64 and only make the transfer bigger. The Pi rebuilds
# everything natively (see SETUP.md "Raspberry Pi 5" for the three build quirks:
# serial OpenSSL 1.0.1u, static OpenSSL in LIBS via -Wl,--start-group, and the
# <cstddef>/<cstdio> includes libdrc needs under gcc-12).
#
# Usage: ./run/pi-push-tree.sh [dest-dir-on-pi]
set -uo pipefail

PI_HOST="${PI_HOST:-192.168.86.28}"
PI_USER="${PI_USER:-kali}"
SRC=/home/kali/Wiiu
DEST="${1:-/home/kali/wiiu-work}"
BUNDLE=/tmp/pc2drc-src.tgz

say() { printf '\n== %s\n' "$*"; }

say "checking ${PI_USER}@${PI_HOST}"
ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no \
    "${PI_USER}@${PI_HOST}" 'uname -m; free -m | head -2' || {
  echo "Pi unreachable - power it on first (and put it on Ethernet)."; exit 1; }

say "building source bundle (excluding x86 artifacts)"
tar czf "$BUNDLE" -C "$SRC" \
  --exclude='*.o' --exclude='*.a' --exclude='*.so' --exclude='*.so.*' \
  --exclude='pc2drc/sps_probe' --exclude='pc2drc/encode_dump' \
  --exclude='drc-hostap/hostapd/hostapd' \
  --exclude='drc-hostap/wpa_supplicant/wpa_supplicant' \
  --exclude='drc-hostap/netboot/netboot' \
  --exclude='.git' --exclude='capture' --exclude='out' \
  pc2drc run pairing.env 2>/dev/null
ls -lh "$BUNDLE"

say "copying to ${PI_HOST}:${DEST}"
ssh "${PI_USER}@${PI_HOST}" "mkdir -p ${DEST}"
scp -q "$BUNDLE" "${PI_USER}@${PI_HOST}:/tmp/"

say "extracting"
ssh "${PI_USER}@${PI_HOST}" "tar xzf /tmp/pc2drc-src.tgz -C ${DEST} && \
  echo '  contents:' && ls ${DEST} && echo && \
  echo '  verify the frame_num fix is in the sources:' && \
  grep -n 'Wii U GamePad compatibility' ${DEST}/pc2drc/drc-x264/encoder/set.c || \
  echo '  (patch NOT present in set.c - apply it with pi-deploy-videofix.sh patch)'"

cat <<EOF

== next, on the Pi
  cd ${DEST}
  # 1. build the stack (OpenSSL 1.0.1u serially first - see SETUP.md)
  # 2. ./run/pi-deploy-videofix.sh patch     # confirms/rebuilds the x264 fix
  # 3. ./run/pi-deploy-videofix.sh ap
  # 4. ./run/pi-deploy-videofix.sh stream
EOF
