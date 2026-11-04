#!/bin/bash
# drc-sweep.sh - sweep libdrc encoder parameters live and let the GamePad judge.
#
# Metric: the pad sends a 4-byte message "\1\0\0\0" to console:50010 for every
# frame it fails to decode (libdrc's Streamer treats exactly that as a resync
# request). So "resync per second" is a direct, objective decode-failure rate:
#
#   resync/s ~= frames/s  -> pad rejects every frame (current state)
#   resync/s -> 0         -> pad accepted the stream (SUCCESS)
#
# Each candidate is applied via environment variables (no rebuild), the streamer
# is restarted, and both directions are counted on the AP interface.
#
# Usage: sudo ./run/drc-sweep.sh [candidate-name ...]
set -uo pipefail

IF=WiiUAP
VNC=127.0.0.1:5900
BIN=/home/kali/Wiiu/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient
export LD_LIBRARY_PATH=/home/kali/Wiiu/out/libs:/home/kali/Wiiu/out/libdrc/lib:/home/kali/Wiiu/out/x264/lib
SETTLE=5      # seconds to let the stream start before measuring
WINDOW=10     # measurement seconds

restart_streamer() {
  pkill -x drcvncclient 2>/dev/null
  sleep 1
  env DRC_SYNTHETIC_TSF=1 "$@" "$BIN" -joystick "$VNC" > /tmp/drcvnc-sweep.log 2>&1 &
  sleep "$SETTLE"
}

# counts: "<resync> <video>" over $WINDOW seconds
measure() {
  local out
  out=$(timeout $((WINDOW+2)) tcpdump -i "$IF" -n -c 4000 \
        'udp and (dst port 50010 or dst port 50120)' 2>/dev/null)
  local r v
  r=$(printf '%s\n' "$out" | grep -c '\.50010')
  v=$(printf '%s\n' "$out" | grep -c '\.50120')
  printf '%s %s\n' "$r" "$v"
}

run_candidate() {
  local label="$1"; shift
  if ! pgrep -x drcvncclient >/dev/null; then
    restart_streamer "$@"
  else
    restart_streamer "$@"
  fi
  local res
  res=$(measure)
  local r=${res% *} v=${res#* }
  local rs rv
  rs=$(awk -v r="$r" -v w="$WINDOW" 'BEGIN{printf "%.1f", r/w}')
  rv=$(awk -v v="$v" -v w="$WINDOW" 'BEGIN{printf "%.1f", v/w}')
  printf '%-26s resync/s=%-7s video/s=%-7s  %s\n' "$label" "$rs" "$rv" \
    "$(awk -v r="$rs" 'BEGIN{ if (r+0 < 2) print "<<< PAD ACCEPTED"; else if (r+0 < 20) print "improved"; else print "" }')"
}

echo "=== candidate               metric"
echo "=== baseline (no overrides)"
run_candidate baseline

for c in "$@"; do
  case "$c" in
    keyint1)   run_candidate "keyint=1 (all IDR)"   DRC_KEYINT=1 ;;
    drh0)      run_candidate "drh_mode=0 (raw NALs)" DRC_DRH=0 ;;
    fps30)     run_candidate "fps=30"                DRC_FPS=30 ;;
    fps60)     run_candidate "fps=60"                DRC_FPS=60 ;;
    qp26)      run_candidate "qp=26"                 DRC_QP=26 ;;
    qp40)      run_candidate "qp=40"                 DRC_QP=40 ;;
    deblock)   run_candidate "deblock=on"            DRC_DEBLOCK=1 ;;
    refs2)     run_candidate "refs=2"                DRC_REFS=2 ;;
    slices5)   run_candidate "slices=5"              DRC_SLICES=5 ;;
    t8x8)      run_candidate "transform8x8=on"       DRC_8X8=1 ;;
    threads2)  run_candidate "threads=2"             DRC_THREADS=2 ;;
    nointra)   run_candidate "intra_refresh=0+K30"   DRC_INTRA_REFRESH=0 DRC_KEYINT=30 ;;
    main)      run_candidate "profile=main"          DRC_PROFILE=main ;;
    t8x8drh0)  run_candidate "t8x8+drh0"             DRC_8X8=1 DRC_DRH=0 ;;
    t8x8k1)    run_candidate "t8x8+keyint1"          DRC_8X8=1 DRC_KEYINT=1 ;;
    t8x8q26)   run_candidate "t8x8+qp26"             DRC_8X8=1 DRC_QP=26 ;;
    t8x8deblk) run_candidate "t8x8+deblock"          DRC_8X8=1 DRC_DEBLOCK=1 ;;
    t8x8fps60) run_candidate "t8x8+fps60"            DRC_8X8=1 DRC_FPS=60 ;;
    t8x8all)   run_candidate "t8x8+drh0+k1+deblk"    DRC_8X8=1 DRC_DRH=0 DRC_KEYINT=1 DRC_DEBLOCK=1 ;;
    *) echo "unknown candidate: $c" ;;
  esac
done
pkill -x drcvncclient 2>/dev/null
echo "=== done (streamer stopped; restart it to keep streaming)"
