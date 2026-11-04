#!/bin/bash
# sd-repair.sh - repair the unclean-shutdown state on the rpi5-kali boot card.
#
# Background: the card was pulled / the Pi lost power, leaving
#   FAT-fs (sda1): Volume was not properly unmounted
#   EXT4-fs (sda2): recovery complete
# On top of that the card itself threw ~182k suppressed buffer I/O errors and
# dropped off the USB bus mid-check, so this script also reports whether the
# device is electrically healthy - a metadata repair is pointless on dying NAND.
#
# Usage: sudo ./run/sd-repair.sh [device]     (default /dev/sda)
set -uo pipefail

DEV="${1:-/dev/sda}"
[ -b "$DEV" ] || { echo "no such block device: $DEV"; echo "Plug the card reader in first."; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

say() { printf '\n== %s\n' "$*"; }

say "device"
lsblk -o NAME,SIZE,TYPE,TRAN,FSTYPE,LABEL,MOUNTPOINT "$DEV"

# Partition names differ between sd (sda1) and mmc (mmcblk0p1)
if [ -b "${DEV}1" ]; then P1="${DEV}1"; else P1="${DEV}p1"; fi
if [ -b "${DEV}2" ]; then P2="${DEV}2"; else P2="${DEV}p2"; fi
[ -b "$P1" ] && [ -b "$P2" ] || { echo "expected two partitions on $DEV"; exit 1; }

say "unmounting"
for p in "$P1" "$P2"; do
  for mp in $(findmnt -nlo TARGET -S "$p" 2>/dev/null); do
    umount "$mp" && echo "  unmounted $mp"
  done
done

say "read-integrity smoke test before trusting a repair"
# Read 64 MiB from the start and the end-ish of the card. If this errors out,
# the card is failing and fsck cannot make it trustworthy.
ERRORS=0
for off in 0 100000; do
  if ! dd if="$DEV" of=/dev/null bs=1M count=64 skip="$off" 2>/dev/null; then
    echo "  READ FAILURE around ${off} MiB"
    ERRORS=$((ERRORS+1))
  else
    echo "  ${off} MiB..$((off+64)) MiB readable"
  fi
done
KER=$(dmesg 2>/dev/null | grep -ciE "Buffer I/O error|I/O error.*sd[a-z]|tag#.*FAILED|Sense Key")
echo "  kernel I/O-error lines so far: ${KER}"

say "boot partition (vfat) - fixes the 'not properly unmounted' dirty bit"
fsck.vfat -a "$P1" 2>&1 | tail -6

say "root partition (ext4) - this one takes a while on a large card"
# -p = preen (safe, automatic); fall back to -fy if preen says it needs work.
fsck -p "$P2" 2>&1 | tail -20
RC=$?
if [ $RC -ne 0 ]; then
  echo "  preen returned $RC - running a full repair"
  fsck -fy "$P2" 2>&1 | tail -25
fi

say "verdict"
KER2=$(dmesg 2>/dev/null | grep -ciE "Buffer I/O error|tag#.*FAILED|Sense Key")
echo "  kernel I/O-error lines now: ${KER2} (was ${KER})"
if [ "$KER2" -gt "$KER" ] || [ "$ERRORS" -gt 0 ]; then
  cat <<'EOF'
  *** The filesystem may be consistent now, but this card logged new I/O errors.
  *** Metadata repair does not fix failing NAND: expect data loss to recur.
  *** Do not boot the DRC/AP workload from it - use the USB SSD.
EOF
else
  cat <<'EOF'
  No new I/O errors and the filesystems are clean. The "not properly unmounted"
  state was the only defect, and it is now repaired.
  Remount and check the config survived:
      sudo mount <P1> /mnt && grep -E "usb_max_current_enable|hdmi_blanking|piscreen" /mnt/config.txt
EOF
fi
