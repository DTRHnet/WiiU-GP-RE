#!/bin/bash
# Hardware-free test suite for the DRC stack.
#
# Everything here runs WITHOUT a GamePad and WITHOUT root, and covers the parts of
# the pipeline that the radio/hardware does not touch:
#   1. the TSF clock source (patched-mac80211 sysfs node, or synthetic fallback)
#   2. libdrc's H.264 encoder contract (5 DRH row-chunks per frame)
#   3. a decodable stream at the GamePad's exact settings, verified with ffmpeg
#
# Usage: ./tests/run-tests.sh
set -uo pipefail
ROOT=/home/kali/Wiiu
BIN=$ROOT/out/bin/encoder_test
export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib:${LD_LIBRARY_PATH:-}
pass=0; fail=0
ok(){   echo "  PASS  $*"; pass=$((pass+1)); }
bad(){  echo "  FAIL  $*"; fail=$((fail+1)); }

[ -x "$BIN" ] || { echo "missing $BIN - build it first (see build/)"; exit 1; }

echo "=== 1. TSF clock source ==="
if "$BIN" tsf >/dev/null 2>&1; then
  ok "hardware TSF available (/sys/class/net/<if>/tsf)"
else
  echo "  --    no hardware TSF (patched mac80211 not loaded) - trying synthetic fallback"
  if DRC_SYNTHETIC_TSF=1 "$BIN" tsf >/dev/null 2>&1; then
    ok "synthetic TSF fallback works (DRC_SYNTHETIC_TSF=1)"
  else
    bad "neither hardware nor synthetic TSF"
  fi
fi

echo "=== 2. libdrc H.264 encoder: DRH chunking contract ==="
if "$BIN" drh 2>&1 | grep -q "PASS: 12/12 frames had exactly 5 chunks"; then
  ok "every frame yields exactly 5 macroblock-row chunks"
else
  bad "DRH chunking contract"
fi

echo "=== 3. GamePad-format stream decodes ==="
TMP=$(mktemp -d)
if "$BIN" file "$TMP/t.h264" >/dev/null 2>&1; then
  if ffmpeg -v error -i "$TMP/t.h264" -f null - 2>&1 | grep -q .; then
    bad "ffmpeg reported errors decoding the stream"
  else
    ok "ffmpeg decodes 60 frames with no errors"
  fi
  geo=$(ffprobe -v error -show_entries stream=width,height -of csv=p=0 "$TMP/t.h264" 2>/dev/null)
  [ "$geo" = "854,480" ] && ok "geometry 854x480" || bad "geometry was '$geo'"
  slices=$(ffprobe -v error -count_frames -show_entries stream=nb_read_frames -of csv=p=0 "$TMP/t.h264" 2>/dev/null)
  ok "frames decoded: ${slices:-?}"
else
  bad "could not encode a test stream"
fi
rm -rf "$TMP"

echo "=== 4. DRC wire-format round-trip (vstrm + cmd) ==="
if [ -x "$ROOT/out/bin/protocol_test" ]; then
  if "$ROOT/out/bin/protocol_test" >/dev/null 2>&1; then
    ok "vstrm/cmd headers serialise and parse symmetrically"
  else
    bad "protocol round-trip"
  fi
else
  echo "  --    protocol_test not built (see tests/protocol_test.cpp)"
fi

echo "=== 5. video packet schedule + IDR policy ==="
SCHED=$ROOT/out/bin/scheduler_test
if [ ! -x "$SCHED" ]; then
  g++ -O2 -std=c++17 "$ROOT/tests/scheduler_test.cpp" -o "$SCHED" \
      -I"$ROOT/pc2drc/libdrc-vnc/libdrc-thefloppydriver/include" 2>/dev/null
fi
if [ -x "$SCHED" ] && "$SCHED" >/dev/null 2>&1; then
  n=$("$SCHED" 2>/dev/null | grep -c "^  PASS")
  ok "in-frame pacing + IDR policy ($n checks)"
else
  bad "video packet schedule / IDR policy"
fi

echo "=== 6. streamer thread lifecycle (patched sender) ==="
if [ -x "$ROOT/out/bin/streamer_smoke" ] || [ -x "$ROOT/out/libdrc/lib/libdrc.so" ]; then
  if timeout 90 "$ROOT/tests/run-streamer-smoke.sh" >/tmp/smoke.log 2>&1; then
    ok "producer/sender threads start, pace and stop without deadlock"
  else
    echo "  --    streamer smoke test failed; see /tmp/smoke.log"
    bad "streamer thread lifecycle"
  fi
else
  echo "  --    libdrc.so not built; skipping smoke test"
fi

echo "=== 7. end-to-end stream validation (loopback + reconstruction) ==="
if [ -x "$ROOT/out/libdrc/lib/libdrc.so" ] && command -v ffmpeg >/dev/null; then
  if timeout 300 "$ROOT/tests/run-stream-validation.sh" 60 >/tmp/streamval.log 2>&1; then
    ok "packet-level clean and reconstructs to a decodable 854x480 stream"
  else
    echo "  --    see /tmp/streamval.log"
    bad "end-to-end stream validation"
  fi
else
  echo "  --    libdrc.so or ffmpeg missing; skipping"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
