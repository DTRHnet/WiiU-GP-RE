#!/bin/bash
# Build patched cfg80211 (+ mac80211 with the TSF export) against the running Kali
# kernel, install them out-of-tree, and reload the Wi-Fi stack so the Nintendo cipher
# selector is accepted. Run as root:  sudo ./build-patched-wireless.sh
#
# Only cfg80211 needs the Nintendo patch; mac80211 is rebuilt too so we keep the
# /sys/class/net/<if>/tsf export available for libdrc (not needed on iwlwifi, which has
# no get_tsf, but harmless and it keeps the option open).
set -uo pipefail

KSRC=/home/kali/Wiiu/kernel/linux-source-7.1
KBUILD=/lib/modules/$(uname -r)/build
LOG=/home/kali/Wiiu/kernel/build-patched-wireless.log
exec > >(tee "$LOG") 2>&1

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

echo "=== kernel: $(uname -r) ==="
echo "=== patch cfg80211 ==="
python3 /home/kali/Wiiu/kernel/patch-cfg80211-nintendo-oui.py || exit 1

echo "=== build net/wireless (cfg80211.ko) ==="
make -C "$KBUILD" M="$KSRC/net/wireless" CONFIG_CFG80211=m modules -j"$(nproc)" || {
  echo "cfg80211 build FAILED"; exit 1; }

echo "=== build net/mac80211 (mac80211.ko, TSF export) ==="
make -C "$KBUILD" M="$KSRC/net/mac80211" CONFIG_MAC80211=m modules -j"$(nproc)" || {
  echo "mac80211 build FAILED"; exit 1; }

echo "=== artefacts ==="
ls -l "$KSRC/net/wireless/cfg80211.ko" "$KSRC/net/mac80211/mac80211.ko" 2>/dev/null

echo
echo "=== to activate (destroys Wi-Fi briefly) ==="
cat <<EOF
  modprobe -r iwlmvm iwlwifi
  modprobe -r mac80211 cfg80211
  insmod $KSRC/net/wireless/cfg80211.ko
  insmod $KSRC/net/mac80211/mac80211.ko
  modprobe iwlmvm
  # verify
  lsmod | grep -E 'cfg80211|mac80211'
EOF
