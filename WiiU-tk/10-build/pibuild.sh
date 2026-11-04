#!/bin/bash
# Native arm64 build of the full DRC stack on the Raspberry Pi 5 (Kali aarch64).
# Mirrors the x86 drcbuild:20.04 recipe: 2016-era hostapd needs OpenSSL 1.0.1 and a
# compiler that tolerates old C, so we build OpenSSL 1.0.1u and prefer gcc-12.
set -uo pipefail
ROOT=/home/kali/wiiu-work
OUT=$ROOT/out
LOG=$OUT/logs
EXT=$ROOT/external_pkg_install_dir
mkdir -p "$LOG" "$OUT/x264" "$OUT/libdrc" "$OUT/bin" "$EXT"
step(){ echo; echo "=============== $* ==============="; }

if command -v gcc-12 >/dev/null 2>&1; then
  export CC=gcc-12 CXX=g++-12
else
  export CC=gcc CXX=g++
fi
echo "toolchain: $($CC --version | head -1)"

step "1. OpenSSL 1.0.1u (needed: 2016 hostapd dereferences structs that 1.1+ hides)"
if [ ! -f "$EXT/lib/libcrypto.a" ]; then
  ( cd /tmp && rm -rf openssl-1.0.1u \
    && tar xf "$ROOT/build/openssl-1.0.1u.tar.gz" \
    && cd openssl-1.0.1u \
    && ./config --prefix="$EXT/" --openssldir=openssl threads zlib no-shared > "$LOG/openssl-conf.log" 2>&1 \
    && make -j4 > "$LOG/openssl-make.log" 2>&1 \
    && make install > "$LOG/openssl-install.log" 2>&1 )
  echo "openssl exit=$?"
else
  echo "openssl already built"
fi
[ -f "$EXT/lib/libcrypto.a" ] && echo "  OK libcrypto.a" || echo "  MISSING libcrypto.a"

step "2. drc-x264 (patched: b_drh_mode, 6-row slicing)"
( cd "$ROOT/pc2drc/drc-x264" && make clean >/dev/null 2>&1
  ./configure --prefix="$OUT/x264" --enable-shared --enable-static --disable-cli --enable-pic \
      > "$LOG/x264-conf.log" 2>&1 \
  && make -j4 > "$LOG/x264-make.log" 2>&1 \
  && make install > "$LOG/x264-install.log" 2>&1 )
echo "x264 exit=$?"; ls "$OUT/x264/lib"/libx264.so* 2>/dev/null | head -2

step "3. libdrc"
( cd "$ROOT/pc2drc/libdrc-vnc/libdrc-thefloppydriver" && make clean >/dev/null 2>&1
  PKG_CONFIG_PATH="$OUT/x264/lib/pkgconfig" ./configure --prefix="$OUT/libdrc" \
      --disable-demos --cxx="$CXX" > "$LOG/libdrc-conf.log" 2>&1 \
  && make -j4 > "$LOG/libdrc-make.log" 2>&1 \
  && make install > "$LOG/libdrc-install.log" 2>&1 )
echo "libdrc exit=$?"
readelf -d "$OUT/libdrc/lib/libdrc.so" 2>/dev/null | grep NEEDED | head -5

step "4. drcvncclient"
cd "$ROOT/pc2drc/libdrc-vnc/drcvncclient" || exit 1
[ -f Makefile ] || ./autogen.sh > "$LOG/vnc-autogen.log" 2>&1
PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
  ./configure --prefix="$OUT/bin" CC="$CC" CXX="$CXX" > "$LOG/vnc-conf.log" 2>&1
PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
  make -j4 > "$LOG/vnc-make.log" 2>&1
echo "drcvncclient exit=$?"
grep -E "error:|undefined reference" "$LOG/vnc-make.log" 2>/dev/null | head -6

step "5. netboot (DHCP -> 192.168.1.11)"
( cd "$ROOT/pc2drc/drc-hostap/netboot" && gcc -o netboot netboot.c > "$LOG/netboot.log" 2>&1 )
echo "netboot exit=$?"

step "6. hostapd (CONFIG_TENDONIN: Nintendo OUI + PTK rot3)"
( cd "$ROOT/pc2drc/drc-hostap/hostapd" \
  && cp -f ./defconfig ./.config \
  && sed -i "s?/_123sedreplaceme?$ROOT?g" ./.config \
  && make clean >/dev/null 2>&1 \
  && make -j4 CC="$CC" > "$LOG/hostapd.log" 2>&1 )
echo "hostapd exit=$?"
grep -E "error:" "$LOG/hostapd.log" 2>/dev/null | head -6

step "7. wpa_supplicant + wpa_cli"
( cd "$ROOT/pc2drc/drc-hostap/wpa_supplicant" \
  && cp -f ./defconfig ./.config \
  && sed -i "s?/_123sedreplaceme?$ROOT?g" ./.config \
  && make clean >/dev/null 2>&1 \
  && make -j4 CC="$CC" > "$LOG/wpasupp.log" 2>&1 )
echo "wpa_supplicant exit=$?"
grep -E "error:" "$LOG/wpasupp.log" 2>/dev/null | head -6

step "8. artefacts"
ok=0; bad=0
for b in "$ROOT/pc2drc/drc-hostap/hostapd/hostapd" \
         "$ROOT/pc2drc/drc-hostap/wpa_supplicant/wpa_supplicant" \
         "$ROOT/pc2drc/drc-hostap/wpa_supplicant/wpa_cli" \
         "$ROOT/pc2drc/drc-hostap/netboot/netboot" \
         "$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient" \
         "$OUT/libdrc/lib/libdrc.so" "$OUT/x264/lib/libx264.so.140"; do
  if [ -f "$b" ]; then echo "  BUILT   $b"; ok=$((ok+1)); else echo "  MISSING $b"; bad=$((bad+1)); fi
done
echo "  -> $ok built, $bad missing"
