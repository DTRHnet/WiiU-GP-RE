#!/bin/bash
# Builds and runs the streamer smoke test: exercises the patched VideoStreamer's
# producer/sender threads with no GamePad and no radio.
#
# Requires libdrc.so built from pc2drc/libdrc-vnc/libdrc-thefloppydriver
# (build it in drcbuild:20.04, see research/CODEC-SPEC.md and SETUP.md).
#
# Usage: ./tests/run-streamer-smoke.sh
set -uo pipefail
ROOT=/home/kali/Wiiu
LIB=$ROOT/pc2drc/libdrc-vnc/libdrc-thefloppydriver

export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib:${LD_LIBRARY_PATH:-}

echo "=== build ==="
g++ -O2 -std=c++17 "$ROOT/tests/streamer_smoke.cpp" \
    -o "$ROOT/out/bin/streamer_smoke" \
    -I"$LIB/include" -I"$ROOT/out/x264/include" \
    -L"$ROOT/out/libdrc/lib" -ldrc \
    -L"$ROOT/out/libs" -l:libswscale.so.5.5.100 -l:libavutil.so.56.31.100 \
    -L"$ROOT/out/x264/lib" -lx264 -lpthread -lm -ldl || exit 1

echo "=== run (synthetic TSF; sends go to an unreachable GamePad address) ==="
DRC_SYNTHETIC_TSF=1 timeout 60 "$ROOT/out/bin/streamer_smoke"
