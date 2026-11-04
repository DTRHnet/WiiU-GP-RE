#!/bin/bash
# uvc-start.sh - start run/uvc-live.sh fully detached and return immediately.
#
# The live session must outlive whatever shell asked for it. Starting it inline
# from an interactive command means a timeout or Ctrl-C on that command can take
# the session down with it, which cost several restarts during bring-up.
#
# Usage: sudo ./run/uvc-start.sh [extra env assignments...]
#   sudo DRC_INPUT_LOG=1 ./run/uvc-start.sh
set -uo pipefail
ROOT=/home/kali/Wiiu
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
LOGDIR=$ROOT/out/logs
mkdir -p "$LOGDIR"
STAMP=$(date +%H%M%S)
OUT=$LOGDIR/live-supervisor-$STAMP.log
setsid nohup /bin/bash "$ROOT/run/uvc-live.sh" >"$OUT" 2>&1 < /dev/null &
echo $! > /var/run/drc/live-supervisor.pid
sleep 2
echo "supervisor pid $(cat /var/run/drc/live-supervisor.pid)"
echo "output: $OUT"
