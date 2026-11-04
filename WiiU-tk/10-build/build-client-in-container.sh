#!/bin/bash
# Rebuild drcvncclient in the drcbuild:20.04 container against our libdrc/x264.
set -euo pipefail
ROOT=/home/kali/Wiiu
docker run --rm -v "$ROOT":/work -w /work/pc2drc/libdrc-vnc/drcvncclient drcbuild:20.04 bash -lc '
  export PKG_CONFIG_PATH=/work/out/libdrc/lib/pkgconfig:/work/out/x264/lib/pkgconfig
  make clean >/dev/null 2>&1 || true
  make -j"$(nproc)" LDFLAGS="-L/work/out/x264/lib -L/work/out/libdrc/lib -Wl,-rpath-link,/work/out/x264/lib" 2>&1 | tail -5
'
install -m 0755 "$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient" "$ROOT/out/bin/bin/drcvncclient"
echo "installed: $ROOT/out/bin/bin/drcvncclient"
