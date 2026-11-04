#!/bin/bash
# Round 2: fix the three failures from the first pass.
#  - hostapd/wpa_supplicant: 2016 code needs OpenSSL 1.0.1 (opaque structs in 1.1+),
#    and must build from the patched `defconfig`, not conf/hostapd.config.
#  - drcvncclient: static libx264 was built without -fPIC, breaking the PIE link.
OUT=/work/out
LOG=$OUT/logs
EXT=/work/pc2drc/external_pkg_install_dir
mkdir -p "$LOG" "$EXT" "$OUT/x264" "$OUT/libdrc" "$OUT/bin"
export DEBIAN_FRONTEND=noninteractive
step() { echo; echo "=============== $* ==============="; }

step "A. OpenSSL 1.0.1u -> $EXT (userland TLS for 2016 hostapd)"
if [ ! -f "$EXT/lib/libcrypto.a" ]; then
  ( cd /tmp && rm -rf openssl-1.0.1u openssl-1.0.1u.tar.gz && \
    wget -q --no-check-certificate https://ftp.openssl.org/source/old/1.0.1/openssl-1.0.1u.tar.gz && \
    tar xf openssl-1.0.1u.tar.gz && cd openssl-1.0.1u && \
    ./config --prefix="$EXT/" --openssldir=openssl threads zlib no-shared > "$LOG/openssl-conf.log" 2>&1 && \
    make -j"$(nproc)" > "$LOG/openssl-make.log" 2>&1 && \
    make install > "$LOG/openssl-install.log" 2>&1 )
  echo "openssl exit=$?"
else
  echo "openssl already built"
fi
ls -1 "$EXT/lib" 2>/dev/null | head -5
[ -f "$EXT/include/openssl/ssl.h" ] && echo "  OK   openssl headers" || echo "  MISS openssl headers"

step "B. netboot DHCP server"
( cd /work/pc2drc/drc-hostap/netboot && gcc -o netboot netboot.c > "$LOG/netboot.log" 2>&1 )
echo "netboot exit=$?"; [ -x /work/pc2drc/drc-hostap/netboot/netboot ] && echo "  OK   netboot built"

step "C. hostapd (patched defconfig, CONFIG_TENDONIN=y)"
( cd /work/pc2drc/drc-hostap/hostapd && \
  cp -f ./defconfig ./.config && \
  sed -i "s?/_123sedreplaceme?/work/pc2drc?g" ./.config && \
  make clean > /dev/null 2>&1; make -j"$(nproc)" > "$LOG/hostapd-make2.log" 2>&1 )
echo "hostapd exit=$?"
grep -cE "error:" "$LOG/hostapd-make2.log" 2>/dev/null | sed 's/^/  compile errors: /'
[ -x /work/pc2drc/drc-hostap/hostapd/hostapd ] && echo "  OK   hostapd binary" || echo "  --   hostapd NOT built"

step "D. wpa_supplicant (patched defconfig, WPS PIN client)"
( cd /work/pc2drc/drc-hostap/wpa_supplicant && \
  cp -f ./defconfig ./.config && \
  sed -i "s?/_123sedreplaceme?/work/pc2drc?g" ./.config && \
  make clean > /dev/null 2>&1; make -j"$(nproc)" > "$LOG/wpasupp-make2.log" 2>&1 )
echo "wpa_supplicant exit=$?"
grep -cE "error:" "$LOG/wpasupp-make2.log" 2>/dev/null | sed 's/^/  compile errors: /'
for b in wpa_supplicant wpa_cli; do
  [ -x "/work/pc2drc/drc-hostap/wpa_supplicant/$b" ] && echo "  OK   $b" || echo "  --   $b NOT built"
done

step "E. drc-x264 rebuilt WITH -fPIC, then libdrc + drcvncclient"
( cd /work/pc2drc/drc-x264 && make clean > /dev/null 2>&1; \
  ./configure --prefix="$OUT/x264" --enable-static --disable-cli --enable-pic > "$LOG/x264-conf2.log" 2>&1 && \
  make -j"$(nproc)" > "$LOG/x264-make2.log" 2>&1 && \
  make install > "$LOG/x264-install2.log" 2>&1 )
echo "x264(pic) exit=$?"

( cd /work/pc2drc/libdrc-vnc/libdrc-thefloppydriver && make clean > /dev/null 2>&1; \
  PKG_CONFIG_PATH="$OUT/x264/lib/pkgconfig" ./configure --prefix="$OUT/libdrc" --disable-demos > "$LOG/libdrc-conf2.log" 2>&1 && \
  make -j"$(nproc)" > "$LOG/libdrc-make2.log" 2>&1 && \
  make install > "$LOG/libdrc-install2.log" 2>&1 )
echo "libdrc exit=$?"

echo "libvncclient available: $(ls /usr/lib/x86_64-linux-gnu/libvncclient* 2>/dev/null | head -2)"
( cd /work/pc2drc/libdrc-vnc/drcvncclient && make clean > /dev/null 2>&1; \
  PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
  make -j"$(nproc)" > "$LOG/vncclient-make2.log" 2>&1 )
echo "drcvncclient exit=$?"
grep -E "error:|undefined reference" "$LOG/vncclient-make2.log" 2>/dev/null | head -5

step "F. final artefacts"
for b in /work/pc2drc/drc-hostap/hostapd/hostapd \
         /work/pc2drc/drc-hostap/wpa_supplicant/wpa_supplicant \
         /work/pc2drc/drc-hostap/wpa_supplicant/wpa_cli \
         /work/pc2drc/drc-hostap/netboot/netboot \
         "$OUT/bin/bin/drcvncclient" "$OUT/libdrc/lib/libdrc.so"; do
  [ -f "$b" ] && echo "  BUILT  $b" || echo "  --     $b"
done
chown -R 1000:1000 /work/out /work/pc2drc/external_pkg_install_dir 2>/dev/null
echo; echo "ROUND 2 COMPLETE"
