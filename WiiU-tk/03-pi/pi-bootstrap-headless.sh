#!/bin/bash
# pi-bootstrap-headless.sh - run ON the Pi after a fresh Kali ARM image.
#
# Two jobs:
#   1. make the box headless and low-power, freeing CPU/RAM and (crucially)
#      USB current budget for a 5 GHz adapter. The screen is not the main
#      consumer: `usb_max_current_enable=1` is, because Pi 5 otherwise caps
#      total USB current hard and a 5 GHz dongle browns out.
#   2. leave the DRC stack ready to build.
#
# Run:  sudo ./pi-bootstrap-headless.sh
set -uo pipefail

say() { printf '\n== %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

# ---------------------------------------------------------------- config.txt
say "config.txt: USB current + HDMI off"
CFG=/boot/firmware/config.txt
[ -f "$CFG" ] || CFG=/boot/config.txt
[ -f "$CFG" ] || { echo "no config.txt found"; exit 1; }
cp -n "$CFG" "${CFG}.bak-bootstrap"
add_opt() {
  local key="$1" val="$2"
  if grep -qE "^${key}=" "$CFG"; then
    sed -i "s/^${key}=.*/${key}=${val}/" "$CFG"
    echo "  ${key}=${val} (updated)"
  else
    echo "${key}=${val}" >> "$CFG"
    echo "  ${key}=${val} (added)"
  fi
}
grep -q "^# DRC/headless" "$CFG" || echo "# DRC/headless low-power block" >> "$CFG"
add_opt usb_max_current_enable 1
add_opt hdmi_blanking 2
grep -qE "^dtoverlay=disable-bt" "$CFG" || { echo "dtoverlay=disable-bt" >> "$CFG"; echo "  dtoverlay=disable-bt (added)"; }
echo "  NOTE: dtoverlay=disable-wifi is NOT applied - wlan0 is needed for the DRC AP."

# ------------------------------------------------- 3.5" SPI screen HAT
# The rpi5-kali image enables an ILI9486+XPT2046 SPI panel. It holds the SPI/I2C
# buses and draws panel + backlight current - exactly the budget the 5 GHz
# adapter needs. Commented out rather than deleted, so it is one '#' removal
# away. NB: piscreen does NOT accept penirq=; an unknown overlay parameter is
# fatal to boot.
say "disabling the 3.5\" SPI screen HAT"
if grep -qE "^dtoverlay=piscreen" "$CFG"; then
  sed -i -e 's|^dtparam=spi=on|#dtparam=spi=on|' \
         -e 's|^dtparam=i2c_arm=on|#dtparam=i2c_arm=on|' \
         -e 's|^dtoverlay=piscreen.*|#&|' "$CFG"
  echo "  commented out: dtparam=spi, dtparam=i2c_arm, dtoverlay=piscreen"
else
  echo "  no active piscreen overlay (nothing to do)"
fi

# ---------------------------------------------------------------- headless
say "headless: boot to console, no desktop"
systemctl set-default multi-user.target
for dm in lightdm gdm3 sddm; do
  if systemctl list-unit-files "${dm}.service" >/dev/null 2>&1; then
    systemctl disable --now "${dm}.service" 2>/dev/null && echo "  disabled ${dm}"
  fi
done
systemctl mask bluetooth.service 2>/dev/null && echo "  bluetooth masked"

say "resulting state"
systemctl get-default
for dm in lightdm gdm3 sddm; do systemctl is-enabled "${dm}.service" 2>/dev/null | sed "s/^/  ${dm}: /"; done
grep -E "^(usb_max_current_enable|hdmi_blanking|dtoverlay=disable-bt)" "$CFG" | sed 's/^/  /'

# ---------------------------------------------------------------- DRC stack
say "DRC stack"
if [ -d "$HOME/wiiu-work/pc2drc/drc-x264" ]; then
  echo "  sources already present at ~/wiiu-work"
  echo "  apply the video fix with:  ./run/pi-deploy-videofix.sh patch"
else
  echo "  ~/wiiu-work missing - copy the tree over, then run:"
  echo "    ./run/pi-deploy-videofix.sh patch   # patches set.c and rebuilds libx264"
fi

say "reboot to apply config.txt (usb_max_current_enable + hdmi_blanking)"
echo "  sudo reboot"
