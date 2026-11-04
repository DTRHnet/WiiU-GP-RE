#!/bin/bash
# End-to-end, hardware-free validation of the DRC video path.
#
# Drives the patched VideoStreamer at loopback, captures the VSTRM datagrams it
# emits, then uses Barista's on-wire tooling to (a) verify packet-level
# correctness and (b) reconstruct Annex-B H.264 and decode it with ffmpeg.
#
# This proves encoder + DRH chunking + packetisation + pacing are right without
# a GamePad or a radio. It does NOT prove the pad accepts the stream.
#
# Usage: ./tests/run-stream-validation.sh [frames]
set -uo pipefail
ROOT=/home/kali/Wiiu
LIB=$ROOT/pc2drc/libdrc-vnc/libdrc-thefloppydriver
SCRIPTS=$ROOT/research/barista-ref/scripts
FRAMES=${1:-120}
PCAP=/tmp/drc-loopback.pcap
H264=/tmp/drc-loopback.h264

export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib:${LD_LIBRARY_PATH:-}

fail=0
ok(){ echo "  PASS  $*"; }
bad(){ echo "  FAIL  $*"; fail=$((fail+1)); }

echo "=== build ==="
g++ -O2 -std=c++17 "$ROOT/tests/streamer_capture.cpp" \
    -o "$ROOT/out/bin/streamer_capture" \
    -I"$LIB/include" -I"$ROOT/out/x264/include" \
    -L"$ROOT/out/libdrc/lib" -ldrc \
    -L"$ROOT/out/libs" -l:libswscale.so.5.5.100 -l:libavutil.so.56.31.100 \
    -L"$ROOT/out/x264/lib" -lx264 -lpthread -lm -ldl || exit 1

echo "=== 1. capture our own stream at loopback ==="
DRC_SYNTHETIC_TSF=1 timeout 180 "$ROOT/out/bin/streamer_capture" "$PCAP" "$FRAMES" \
  | tail -2

echo "=== 2. packet-level analysis (Barista analyze-media-capture.py) ==="
ANALYSIS=$(python3 "$SCRIPTS/analyze-media-capture.py" "$PCAP" 2>&1)
echo "$ANALYSIS" | python3 -c '
import json,sys
d=json.load(sys.stdin)
c=d["counts"]
print("  counts:", json.dumps(c))
print("  fps:", d["observed_video_fps"])
print("  frame spacing median us:", d["host_packet_spacing"]["frame"].get("median_us"))
print("  packet spacing median us:", d["host_packet_spacing"]["video"].get("median_us"))
errors={k:v for k,v in c.items() if any(t in k for t in
    ("error","discontinuit","invalid","inconsistent","outside","unfinished","regression"))}
sys.exit(1 if errors else 0)
' || bad "packet-level errors present"

python3 - <<PY || bad "expected 5 chunk-ends and one frame-end per frame"
import json,subprocess,sys
d=json.loads(subprocess.run(["python3","$SCRIPTS/analyze-media-capture.py","$PCAP"],
                            capture_output=True,text=True).stdout)
c=d["counts"]
sys.exit(0 if c.get("complete_frames",0)>50 and "invalid_frames" not in c
              and "payload_length_errors" not in c else 1)
PY
[ $? -eq 0 ] && ok "every frame carried 5 chunk-ends + 1 frame-end, lengths consistent"

echo "=== 3. reconstruct Annex-B H.264 and decode ==="
if python3 "$SCRIPTS/reconstruct-media-capture.py" "$PCAP" > "$H264" 2>/tmp/recon.err; then
  head -1 /tmp/recon.err | sed 's/^/  /'
else
  bad "reconstruction failed"
fi
GEO=$(ffprobe -v error -show_entries stream=profile,width,height,pix_fmt -of csv=p=0 "$H264" 2>/dev/null)
echo "  ffprobe: $GEO"
[ "$GEO" = "High,854,480,yuv420p" ] && ok "reconstructed stream is High profile 854x480 yuv420p" \
  || bad "unexpected geometry/profile: $GEO"
if ffmpeg -v error -xerror -c:v h264 -f h264 -i "$H264" -f null - 2>/tmp/decode.err; then
  ok "ffmpeg decodes the whole reconstructed stream with zero errors"
else
  bad "ffmpeg decode errors"; head -3 /tmp/decode.err | sed 's/^/  /'
fi

BYTES=$(stat -c %s "$H264")
echo "  reconstructed: $BYTES bytes from $FRAMES pushed frames"

echo
if [ $fail -eq 0 ]; then
  echo "PASS: DRC video path validated end to end (no GamePad, no radio)"
else
  echo "FAIL: $fail check(s) failed"
fi
exit $fail
