#!/bin/bash
# uvc-stop.sh - stop a run started by run/uvc-live.sh and leave the pad alone.
#
# Usage: sudo ./run/uvc-stop.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
echo "stopping the DRC streamer and clock helper"
pkill -INT -x drcvncclient 2>/dev/null
sleep 1
pkill -x drcvncclient 2>/dev/null
pkill -f tsf-from-monitor.py 2>/dev/null
sleep 1
if pgrep -x drcvncclient >/dev/null; then
  echo "still running: $(pgrep -x drcvncclient | tr '\n' ' ')"
  exit 1
fi
echo "stopped"
