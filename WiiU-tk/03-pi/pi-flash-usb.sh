#!/bin/bash
# pi-flash-usb.sh - flash a Kali ARM image to a USB SSD / NVMe enclosure and
# pre-apply the headless low-power config so the very first boot is already
# in the right state (no need to fight a dead SD card again).
#
# Usage:
#   sudo ./run/pi-flash-usb.sh <image.img|image.img.xz> <device> [--patch-config]
#
#   <device> is the WHOLE disk, e.g. /dev/sda - not a partition.
#
# Safety: refuses to touch a device that holds /, /boot, or swap.
set -uo pipefail

YES=0; PATCH=""; IMG=""; DEV=""
for a in "$@"; do
  case "$a" in
    --yes)          YES=1 ;;
    --patch-config) PATCH="--patch-config" ;;
    -*)             echo "unknown option: $a"; exit 1 ;;
    *)              if [ -z "$IMG" ]; then IMG="$a"; elif [ -z "$DEV" ]; then DEV="$a"; fi ;;
  esac
done
[ -n "$IMG" ] && [ -n "$DEV" ] || { sed -n '2,16p' "$0"; exit 1; }
[ -b "$DEV" ] || { echo "not a block device: $DEV"; exit 1; }
[ -f "$IMG" ] || { echo "no such image: $IMG"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

# ------------------------------------------------------------ safety checks
echo "== target $DEV"
lsblk -o NAME,SIZE,TYPE,TRAN,FSTYPE,MOUNTPOINT "$DEV"
ROOT_SRC=$(findmnt -no SOURCE /); BOOT_SRC=$(findmnt -no SOURCE /boot/efi 2>/dev/null || true)
for holder in "$ROOT_SRC" "$BOOT_SRC"; do
  [ -n "$holder" ] || continue
  case "$holder" in
    "$DEV"|"$DEV"p*|"$DEV"[0-9]*)
      echo "REFUSING: $DEV backs $holder (the running system)."
      echo "Pick the external enclosure's disk instead."
      exit 1 ;;
  esac
done
if grep -qs "^$DEV" /proc/swaps; then echo "REFUSING: $DEV is in use as swap"; exit 1; fi
REMOVABLE=$(lsblk -dno RM "$DEV")
echo "== removable flag: $REMOVABLE (1 = USB enclosure)"
echo
if [ "$YES" -eq 1 ]; then
  echo "== --yes given: writing to $DEV without a typed confirmation"
else
  read -r -p "DESTROYS ALL DATA on $DEV. Type the device name again to confirm: " CONFIRM
  [ "$CONFIRM" = "$DEV" ] || { echo "aborted"; exit 1; }
fi

# ------------------------------------------------------------ write
echo "== unmounting anything on $DEV"
for p in $(lsblk -lno NAME "$DEV" | tail -n +2); do umount "/dev/$p" 2>/dev/null || true; done

echo "== writing $IMG -> $DEV"
case "$IMG" in
  *.xz)        xz -dc "$IMG" | dd of="$DEV" bs=4M conv=fsync status=progress ;;
  *.zip)       ( command -v unzip >/dev/null || { echo "need unzip"; exit 1; }
                 TMPI=$(mktemp -d); unzip -o "$IMG" -d "$TMPI" >/dev/null
                 RAW=$(ls "$TMPI"/*.img | head -1); echo "   inner image: $RAW"
                 dd if="$RAW" of="$DEV" bs=4M conv=fsync status=progress
                 rm -rf "$TMPI" ) ;;
  *)           dd if="$IMG" of="$DEV" bs=4M conv=fsync status=progress ;;
esac
sync; partprobe "$DEV" 2>/dev/null || true; sleep 2
echo "== after flash"
lsblk -o NAME,SIZE,TYPE,FSTYPE "$DEV"

# ------------------------------------------------------------ pre-config
if [ "$PATCH" = "--patch-config" ]; then
  echo
  echo "== pre-applying headless / USB-current config on the boot partition"
  BOOTP=$(lsblk -lno NAME,FSTYPE "$DEV" | awk '$2=="vfat"{print $1; exit}')
  if [ -z "${BOOTP:-}" ]; then
    echo "   no vfat boot partition found - skip (do it on the Pi instead)"
  else
    MNT=$(mktemp -d)
    if mount "/dev/$BOOTP" "$MNT"; then
      CFG="$MNT/config.txt"; [ -f "$CFG" ] || CFG="$MNT/firmware/config.txt"
      if [ -f "$CFG" ]; then
        cp -n "$CFG" "${CFG}.bak-flash"
        grep -qE "^usb_max_current_enable=" "$CFG" \
          && sed -i 's/^usb_max_current_enable=.*/usb_max_current_enable=1/' "$CFG" \
          || echo "usb_max_current_enable=1" >> "$CFG"
        grep -qE "^hdmi_blanking=" "$CFG" \
          && sed -i 's/^hdmi_blanking=.*/hdmi_blanking=2/' "$CFG" \
          || echo "hdmi_blanking=2" >> "$CFG"
        grep -qE "^dtoverlay=disable-bt" "$CFG" || echo "dtoverlay=disable-bt" >> "$CFG"
        echo "   patched $CFG:"
        grep -E "^(usb_max_current_enable|hdmi_blanking|dtoverlay=disable-bt)" "$CFG" | sed 's/^/     /'
      else
        echo "   config.txt not found on the boot partition"
      fi
      umount "$MNT"
    else
      echo "   could not mount /dev/$BOOTP"
    fi
    rmdir "$MNT" 2>/dev/null || true
  fi
fi

cat <<EOF

== next
1. Remove the SD card, plug the SSD/enclosure into the Pi 5, power on.
   Pi 5 tries SD first, then USB - with no SD present it boots the SSD.
   If it does not, set the boot order on the Pi (digits are tried RIGHT TO LEFT):
       sudo rpi-eeprom-config --edit
       BOOT_ORDER=0xf14      # 4 = USB-MSD first, then 1 = SD, then f = restart
                             # use 0xf16 for NVMe-first (needs the M.2 HAT + pciex1)
       sudo vcgencmd bootloader_config | grep BOOT_ORDER     # verify
2. First boot, on the Pi:
       sudo ./run/pi-bootstrap-headless.sh     # verifies headless/low-power state
       ./run/pi-deploy-videofix.sh patch       # applies the 8-bit frame_num fix
3. Then the on-pad test: ./run/pi-deploy-videofix.sh ap && ./run/pi-deploy-videofix.sh stream
EOF
