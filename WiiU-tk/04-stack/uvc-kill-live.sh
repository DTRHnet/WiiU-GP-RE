#!/bin/bash
# uvc-kill-live.sh - stop the uvc-live.sh supervisor and its children.
#
# This exists because `pkill -f run/uvc-live.sh` run from an interactive command
# line matches the *caller's* own command line and kills the calling shell
# (drc-up.sh documents the same hazard). Running the pattern from inside this
# file cannot match: this file's command line is "run/uvc-kill-live.sh", which
# does not contain the pattern.
#
# Usage: sudo ./run/uvc-kill-live.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
pkill -x drcvncclient 2>/dev/null
pkill -f run/uvc-live.sh 2>/dev/null
pkill -f tsf-keeper.py 2>/dev/null
pkill -f tsf-guard.sh 2>/dev/null
pkill -f tsf-from-monitor.py 2>/dev/null
sleep 3
pkill -KILL -x drcvncclient 2>/dev/null
pkill -KILL -f run/uvc-live.sh 2>/dev/null
sleep 1
if pgrep -x drcvncclient >/dev/null; then
  echo "FAIL: streamer still running: $(pgrep -x drcvncclient | tr '\n' ' ')"
  exit 1
fi
echo "all DRC processes stopped"
