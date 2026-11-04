#!/bin/bash
# Round 3: compile the stack inside the persistent drcbuild image (deps + OpenSSL
# 1.0.1u are baked in at /opt/drc).
OUT=/work/out
LOG=$OUT/logs
mkdir -p "$LOG" "$OUT/x264" "$OUT/libdrc" "$OUT/bin"
step() { echo; echo "=============== $* ==============="; }

step "x264 (patched for GamePad H.264, with -fPIC)"
( cd /work/pc2drc/drc-x264 && make clean > /dev/null 2>&1
  ./configure --prefix="$OUT/x264" --enable-static --disable-cli --enable-pic > "$LOG/x264-conf3.log" 2>&1 &&
  make -j"$(nproc)" > "$LOG/x264-make3.log" 2>&1 &&
  make install > "$LOG/x264-install3.log" 2>&1 )
echo "x264 exit=$?"; [ -f "$OUT/x264/lib/libx264.a" ] && echo "  OK libx264.a"

step "libdrc (encode/stream to GamePad, receive input)"
( cd /work/pc2drc/libdrc-vnc/libdrc-thefloppydriver && make clean > /dev/null 2>&1
  PKG_CONFIG_PATH="$OUT/x264/lib/pkgconfig" ./configure --prefix="$OUT/libdrc" --disable-demos > "$LOG/libdrc-conf3.log" 2>&1 &&
  make -j"$(nproc)" > "$LOG/libdrc-make3.log" 2>&1 &&
  make install > "$LOG/libdrc-install3.log" 2>&1 )
echo "libdrc exit=$?"; [ -f "$OUT/libdrc/lib/libdrc.so" ] && echo "  OK libdrc.so"

step "drcvncclient (VNC -> GamePad renderer)"
( cd /work/pc2drc/libdrc-vnc/drcvncclient && make clean > /dev/null 2>&1
  PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
  make -j"$(nproc)" > "$LOG/vncclient-make3.log" 2>&1 )
if [ $? -ne 0 ]; then
  echo "  retrying via autogen + configure"
  ( cd /work/pc2drc/libdrc-vnc/drcvncclient && ./autogen.sh > "$LOG/vncclient-autogen3.log" 2>&1
    PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
    ./configure --prefix="$OUT/bin" > "$LOG/vncclient-conf3.log" 2>&1
    PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
    make -j"$(nproc)" > "$LOG/vncclient-make3.log" 2>&1 )
fi
echo "drcvncclient exit=$?"
grep -E "error:|undefined reference" "$LOG/vncclient-make3.log" 2>/dev/null | head -6

step "netboot (DHCP: hands the GamePad 192.168.1.11)"
( cd /work/pc2drc/drc-hostap/netboot && gcc -o netboot netboot.c > "$LOG/netboot3.log" 2>&1 )
echo "netboot exit=$?"

step "hostapd (patched defconfig: CONFIG_TENDONIN=y, Nintendo OUI, PTK rot3)"
( cd /work/pc2drc/drc-hostap/hostapd
  cp -f ./defconfig ./.config
  sed -i "s?/_123sedreplaceme?/opt/drc?g" ./.config
  make clean > /dev/null 2>&1
  make -j"$(nproc)" > "$LOG/hostapd-make3.log" 2>&1 )
echo "hostapd exit=$?"
grep -E "error:" "$LOG/hostapd-make3.log" 2>/dev/null | head -6

step "wpa_supplicant + wpa_cli (pairing: wps_pin)"
( cd /work/pc2drc/drc-hostap/wpa_supplicant
  cp -f ./defconfig ./.config
  sed -i "s?/_123sedreplaceme?/opt/drc?g" ./.config
  make clean > /dev/null 2>&1
  make -j"$(nproc)" > "$LOG/wpasupp-make3.log" 2>&1 )
echo "wpa_supplicant exit=$?"
grep -E "error:" "$LOG/wpasupp-make3.log" 2>/dev/null | head -6

step "artefacts"
ok=0; bad=0
for b in /work/pc2drc/drc-hostap/hostapd/hostapd \
         /work/pc2drc/drc-hostap/wpa_supplicant/wpa_supplicant \
         /work/pc2drc/drc-hostap/wpa_supplicant/wpa_cli \
         /work/pc2drc/drc-hostap/netboot/netboot \
         "$OUT/bin/bin/drcvncclient" \
         "$OUT/libdrc/lib/libdrc.so" \
         "$OUT/x264/lib/libx264.a"; do
  if [ -f "$b" ]; then echo "  BUILT  $b"; ok=$((ok+1)); else echo "  MISSING $b"; bad=$((bad+1)); fi
done
echo "  -> $ok built, $bad missing"
chown -R 1000:1000 /work/out 2>/dev/null
echo; echo "ROUND 3 COMPLETE"
