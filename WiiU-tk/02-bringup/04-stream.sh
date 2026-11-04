#!/bin/bash
# 04 - Push a desktop to the GamePad over the DRC video stream.
#
# Chain: X desktop --x11vnc--> drcvncclient --H.264--> GamePad
# GamePad touch/buttons come back as VNC input events, so they drive the machine
# RUNNING THE VNC SERVER - no /dev/uinput plumbing needed.
#
# Two supported layouts:
#   all-in-one : x11vnc and drcvncclient on the same host (VNC_HOST unset)
#   bridge     : DRC stack on the Pi, desktop on Kali  (VNC_HOST=<kali-ip>)
#
# drcvncclient upstream assumed an 854x480 VNC source and segfaulted otherwise;
# this tree patches it to follow the server's real size.
set -uo pipefail

ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
VNCVIEW="${VNCVIEW:-}"
for cand in "$ROOT/out/bin/bin/drcvncclient" \
            "$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient"; do
  [ -x "$cand" ] && { VNCVIEW="$cand"; break; }
done
export LD_LIBRARY_PATH="$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib:${LD_LIBRARY_PATH:-}"

DISPLAY_TO_SERVE="${DISPLAY_TO_SERVE:-:0}"
X11VNC="$(command -v x11vnc || echo /usr/bin/x11vnc)"
RFB_PORT="${RFB_PORT:-5900}"
JOYSTICK="${JOYSTICK:--joystick}"
VNC_HOST="${VNC_HOST:-127.0.0.1}"
# Fit the real desktop into 480 lines, preserving aspect: 1024 -> 480 => 0.46875
SCALE="${SCALE:-0.46875}"

[ -n "$VNCVIEW" ] || { echo "no drcvncclient found under $ROOT - build first"; exit 1; }

if [ "$VNC_HOST" = "127.0.0.1" ] || [ "$VNC_HOST" = "localhost" ]; then
  if pgrep -x "$(basename "$X11VNC")" >/dev/null; then
    echo "[1] x11vnc already running"
  else
    echo "[1] starting x11vnc on $DISPLAY_TO_SERVE (port $RFB_PORT, scale $SCALE)"
    "$X11VNC" -display "$DISPLAY_TO_SERVE" -localhost -rfbport "$RFB_PORT" \
              -nopw -forever -shared -scale "$SCALE" -bg -quiet -noxdamage
    sleep 2
  fi
else
  echo "[1] bridge mode: expecting a VNC server on $VNC_HOST:$RFB_PORT"
  echo "    on that host run:"
  echo "      x11vnc -display :0 -rfbport $RFB_PORT -nopw -forever -shared \\"
  echo "             -scale $SCALE -noxdamage -allow 192.168.86.0/24"
fi

echo "[2] reachability"
(exec 3<>"/dev/tcp/$VNC_HOST/$RFB_PORT") 2>/dev/null \
  && { echo "    TCP $VNC_HOST:$RFB_PORT is open"; exec 3>&-; } \
  || { echo "    FAIL: cannot reach $VNC_HOST:$RFB_PORT"; exit 1; }

echo "[3] starting drcvncclient -> GamePad"
echo "    (touch = pointer, buttons/sticks mapped by libdrc; Ctrl-C to stop)"
"$VNCVIEW" $JOYSTICK "${VNC_HOST}:${RFB_PORT}"
