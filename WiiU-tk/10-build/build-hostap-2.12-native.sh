#!/bin/bash
# Build hostapd + wpa_supplicant 2.12 with the DRC (CONFIG_TENDONIN) patches
# NATIVELY on Kali -- no Ubuntu 20.04 container, no gcc 9, no OpenSSL 1.0.1u.
#
# Verified 2026-11-03 on Kali rolling / gcc 16.2 / OpenSSL 3.6.3:
#   hostapd v2.12, wpa_supplicant v2.12, wpa_cli -- all built, Nintendo
#   selectors 0xa4c0e104 / 0xa4c0e102 present in the binaries.
#
# Why this works where our 2013-era drc-hostap needed a container:
#   vanilla-wiiu/drc-hostap rebased the CONFIG_TENDONIN patches onto hostap
#   2.12 (upstream, 2026), which builds against OpenSSL 1.1/3 and modern gcc.
#
# No root required: the -dev headers come from apt downloads extracted into a
# local prefix (the system has the runtime libs but not the headers).
set -euo pipefail

ROOT=/home/kali/Wiiu/build
SRC=$ROOT/hostap-2.12
DEPS=$ROOT/deps
PREFIX=$DEPS/root

# 1. sources
if [ ! -d "$SRC/hostapd" ]; then
  git clone --depth 1 https://github.com/vanilla-wiiu/drc-hostap.git "$SRC"
  rm -rf "$SRC/.git"
fi

# 2. -dev headers, extracted locally (no root)
mkdir -p "$DEPS/debs" "$PREFIX"
( cd "$DEPS/debs" && apt-get download libnl-3-dev libnl-genl-3-dev libssl-dev )
for d in "$DEPS"/debs/*.deb; do dpkg-deb -x "$d" "$PREFIX"; done

# libssl-dev ships static libs only; link against the system shared OpenSSL
LIBDIR=$PREFIX/usr/lib/x86_64-linux-gnu
rm -f "$LIBDIR/libcrypto.a" "$LIBDIR/libssl.a"
ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.3 "$LIBDIR/libcrypto.so"
ln -sf /usr/lib/x86_64-linux-gnu/libssl.so.3   "$LIBDIR/libssl.so"

# 3. build with the DRC configs
export PKG_CONFIG_PATH=$LIBDIR/pkgconfig
export CFLAGS="-I$PREFIX/usr/include -I$PREFIX/usr/include/x86_64-linux-gnu -I$PREFIX/usr/include/libnl3"
export LDFLAGS="-L$LIBDIR"

cp "$SRC/conf/hostapd.config"        "$SRC/hostapd/.config"
cp "$SRC/conf/wpa_supplicant.config" "$SRC/wpa_supplicant/.config"

make -C "$SRC/hostapd"        -j"$(nproc)"
make -C "$SRC/wpa_supplicant" -j"$(nproc)"

# 4. verify
"$SRC/hostapd/hostapd" -v | head -1
"$SRC/wpa_supplicant/wpa_supplicant" -v | head -1
for b in hostapd/hostapd wpa_supplicant/wpa_supplicant; do
  n=$(xxd -p "$SRC/$b" | tr -d '\n' | grep -o '04e1c0a4' | wc -l)
  echo "$b: Nintendo CCMP selector 0xa4c0e104 x$n (want >0)"
done
