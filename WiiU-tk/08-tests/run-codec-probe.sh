#!/bin/bash
# codec_probe — measure the DRC H.264 path with no GamePad and no radio.
#
# Builds tests/codec_probe.cpp against the patched drc-x264 that libdrc links,
# then measures three things:
#   * bytes/frame and per-chunk sizes at each x264 preset, against the vstrm
#     payload ceiling (so you can see whether a chunk fits one UDP packet);
#   * the same on realistic moving content and on a real X11 desktop;
#   * whether asking the encoder for an IDR mid-stream actually produces one.
#
# Usage: ./run-codec-probe.sh [-n frames]
set -uo pipefail

ROOT=/home/kali/Wiiu
X264=$ROOT/pc2drc/drc-x264
PROBE=$ROOT/out/bin/codec_probe
FRAMES=${FRAMES:-30}

while [ $# -gt 0 ]; do
  case "$1" in
    -n) FRAMES=$2; shift 2 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

echo "=== build ==="
g++ -O2 -std=c++17 "$ROOT/tests/codec_probe.cpp" -o "$PROBE" \
    -I"$X264" -I"$ROOT/research/libdrc/include" \
    -L"$X264" -lx264 -lpthread -lm || exit 1
echo "ok: $PROBE"

echo
echo "=== 1. synthetic gradient (easy content) ==="
"$PROBE" presets "$FRAMES"

echo
echo "=== 2. testsrc2 864x480 (moving content, ffmpeg-generated) ==="
if ffmpeg -hide_banner -loglevel error -f lavfi \
     -i "testsrc2=s=864x480:r=60" -frames:v "$FRAMES" \
     -pix_fmt yuv420p -f rawvideo /tmp/testsrc2-864x480.yuv -y 2>/dev/null; then
  "$PROBE" yuv /tmp/testsrc2-864x480.yuv "$FRAMES"
else
  echo "ffmpeg unavailable - skipped"
fi

echo
echo "=== 3. real X11 desktop (idle) ==="
if [ -n "${DISPLAY:-}" ] && ffmpeg -hide_banner -loglevel error -f x11grab \
     -video_size 864x480 -framerate 60 -i "$DISPLAY" -frames:v "$FRAMES" \
     -pix_fmt yuv420p -f rawvideo /tmp/desktop-864x480.yuv -y 2>/dev/null; then
  DRC_PROBE_VERBOSE=1 "$PROBE" yuv /tmp/desktop-864x480.yuv "$FRAMES"
else
  echo "no X display - skipped"
fi

echo
echo "=== 4. does idr=true produce a real IDR? ==="
for p in slow medium ultrafast; do
  DRC_PROBE_PRESET=$p "$PROBE" idr | grep -E "preset=|IDR emitted|VERDICT"
done
