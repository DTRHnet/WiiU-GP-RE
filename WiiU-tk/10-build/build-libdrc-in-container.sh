#!/bin/bash
# Build libdrc (the pc2drc/thefloppydriver fork, which is what drcvncclient and
# our tests link) inside the drcbuild:20.04 container and install it to
# out/libdrc/lib.
#
# Why a container: the tree needs the vendored patched x264 (drc-x264) headers
# and the focal-era toolchain. A host build also works if Makefile.config points
# at host paths - this script just pins the container paths so `make` stops
# failing on stale .d files that reference host compiler includes.
#
# Usage: ./build/build-libdrc-in-container.sh
set -euo pipefail

ROOT=/home/kali/Wiiu
SRC=$ROOT/pc2drc/libdrc-vnc/libdrc-thefloppydriver

docker run --rm -v "$ROOT":/work -w /work/pc2drc/libdrc-vnc/libdrc-thefloppydriver \
  drcbuild:20.04 bash -lc '
    cat > Makefile.config <<EOF
PREFIX:=/work/out/libdrc
DEMOS:=n
CXX:=g++
CXXFLAGS:=-O2 -fPIC -I include -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -std=gnu++11 -I/usr/include/x86_64-linux-gnu -I/work/out/x264/include
LDFLAGS:= -lswscale -L/work/out/x264/lib -lx264 -lpthread -lm -ldl
LDFLAGS_DEMOS:=-lpthread
EOF
    make clean >/dev/null 2>&1 || true
    make -j"$(nproc)"
'

install -m 0755 "$SRC/libdrc.so" "$ROOT/out/libdrc/lib/libdrc.so"
install -m 0644 "$SRC/libdrc.a"  "$ROOT/out/libdrc/lib/libdrc.a"
echo "installed: $ROOT/out/libdrc/lib/libdrc.so"
