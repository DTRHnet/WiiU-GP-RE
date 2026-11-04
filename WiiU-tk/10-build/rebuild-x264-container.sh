#!/bin/bash
# Rebuild drc-x264 (with the pad frame_num=8 fix) inside drcbuild:20.04 so the
# container-built libdrc/drcvncclient can link against it again.
set -euo pipefail
ROOT=/home/kali/Wiiu
docker run --rm -v "$ROOT":/work -w /work/pc2drc/drc-x264 drcbuild:20.04 bash -lc '
  make clean >/dev/null 2>&1 || true
  ./configure --prefix=/work/out/x264 --enable-shared --enable-static \
              --disable-cli --enable-pic > /work/out/logs/x264-conf6.log 2>&1
  make -j"$(nproc)" > /work/out/logs/x264-make6.log 2>&1
  make install > /work/out/logs/x264-install6.log 2>&1
'
echo "x264 rebuilt:"; ls -l "$ROOT/out/x264/lib/libx264.so.140"
grep -n "i_log2_max_frame_num = 8" "$ROOT/pc2drc/drc-x264/encoder/set.c" | head -2
