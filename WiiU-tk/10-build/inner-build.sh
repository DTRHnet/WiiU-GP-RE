#!/bin/bash
# Build the Wii U DRC stack inside an Ubuntu 20.04 container (pc2drc's supported env).
# Mounted at /work (host: /home/kali/Wiiu). All artefacts land in /work/out.
OUT=/work/out
LOG=$OUT/logs
mkdir -p "$LOG" "$OUT/x264" "$OUT/libdrc" "$OUT/hostapd"
export DEBIAN_FRONTEND=noninteractive

step() { echo; echo "=============== $* ==============="; }

step "1. toolchain + libraries"
apt-get update -qq
apt-get install -y --no-install-recommends \
  build-essential pkg-config git ca-certificates nasm yasm \
  autoconf automake libtool m4 \
  libnl-3-dev libnl-genl-3-dev libssl-dev \
  libswscale-dev libavutil-dev libavcodec-dev \
  libsdl2-dev libglew-dev freeglut3-dev libgl1-mesa-dev \
  libvncserver-dev libjpeg-dev libpng-dev zlib1g-dev libbz2-dev liblzo2-dev libgcrypt20-dev \
  > "$LOG/apt.log" 2>&1
echo "apt exit=$?  (see apt.log)"
for h in /usr/include/rfb/rfbclient.h /usr/include/nl80211.h /usr/include/SDL2/SDL.h \
         /usr/include/libavutil/avutil.h /usr/include/libswscale/swscale.h /usr/include/openssl/ssl.h; do
  [ -f "$h" ] && echo "  OK   $h" || echo "  MISS $h"
done
echo "gcc: $(gcc -dumpversion)"

step "2. drc-x264 (patched x264 - GamePad H.264 is non-standard)"
( cd /work/pc2drc/drc-x264 && \
  ./configure --prefix="$OUT/x264" --enable-static --disable-cli > "$LOG/x264-conf.log" 2>&1 && \
  make -j"$(nproc)"             > "$LOG/x264-make.log" 2>&1 && \
  make install                  > "$LOG/x264-install.log" 2>&1 )
echo "x264 exit=$?"; tail -4 "$LOG/x264-make.log" 2>/dev/null

step "3. libdrc (video/audio encode -> GamePad, input <- GamePad)"
( cd /work/pc2drc/libdrc-vnc/libdrc-thefloppydriver && \
  PKG_CONFIG_PATH="$OUT/x264/lib/pkgconfig:$PKG_CONFIG_PATH" \
  ./configure --prefix="$OUT/libdrc" --disable-demos > "$LOG/libdrc-conf.log" 2>&1 && \
  make -j"$(nproc)" > "$LOG/libdrc-make.log" 2>&1 && \
  make install      > "$LOG/libdrc-install.log" 2>&1 )
echo "libdrc exit=$?"; tail -6 "$LOG/libdrc-make.log" 2>/dev/null; tail -5 "$LOG/libdrc-conf.log" 2>/dev/null

step "4. drcvncclient (renders a VNC desktop onto the GamePad)"
( cd /work/pc2drc/libdrc-vnc/drcvncclient && \
  ./autogen.sh > "$LOG/vncclient-autogen.log" 2>&1 && \
  PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig:$PKG_CONFIG_PATH" \
  ./configure --prefix="$OUT/bin" > "$LOG/vncclient-conf.log" 2>&1 && \
  make -j"$(nproc)" > "$LOG/vncclient-make.log" 2>&1 )
echo "drcvncclient exit=$?"; tail -8 "$LOG/vncclient-make.log" 2>/dev/null; tail -5 "$LOG/vncclient-conf.log" 2>/dev/null

step "5. drc-hostap: hostapd (CONFIG_TENDONIN=y - Nintendo PTK rot3 / WPS KDK rot3)"
( cd /work/pc2drc/drc-hostap && cp conf/hostapd.config hostapd/.config && \
  cd hostapd && make -j"$(nproc)" > "$LOG/hostapd-make.log" 2>&1 )
echo "hostapd exit=$?"; tail -6 "$LOG/hostapd-make.log" 2>/dev/null

step "6. drc-hostap: wpa_supplicant (pairing client + WPS PIN)"
( cd /work/pc2drc/drc-hostap && cp conf/wpa_supplicant.config wpa_supplicant/.config && \
  cd wpa_supplicant && make -j"$(nproc)" > "$LOG/wpasupp-make.log" 2>&1 )
echo "wpa_supplicant exit=$?"; tail -6 "$LOG/wpasupp-make.log" 2>/dev/null

step "7. artefacts"
for b in /work/pc2drc/drc-hostap/hostapd/hostapd \
         /work/pc2drc/drc-hostap/wpa_supplicant/wpa_supplicant \
         /work/pc2drc/drc-hostap/wpa_supplicant/wpa_cli \
         "$OUT/bin/bin/drcvncclient" \
         "$OUT/libdrc/lib/libdrc.so" ; do
  if [ -f "$b" ]; then printf "  BUILT  %s\n" "$b"; else printf "  --     %s\n" "$b"; fi
done
ls "$OUT/libdrc/lib" 2>/dev/null
find "$OUT/bin" -maxdepth 2 -type f -perm -u+x 2>/dev/null
chown -R 1000:1000 /work/out 2>/dev/null
echo; echo "BUILD PASS COMPLETE"
