#!/bin/bash
# bisect-commands.sh - find which command-plane message keeps the GamePad asking
# for keyframes.
#
# Established 2026-11-04: with our streamer sending media only (DRC_QUIET_CMDS=1)
# the pad requests 0.0 keyframes/s for 74 s; with the command plane on it asks
# ~59/s. Each run below re-enables everything except one command.
#
# Result columns: resync/s (goal 0.0), IDR frames/s, fps, pad input/s.
#
# Usage: sudo ./run/bisect-commands.sh [seconds_per_run]
set -uo pipefail
ROOT=/home/kali/Wiiu
SECS=${1:-50}
say() { printf '\n### %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

CONFIGS=(
  "DRC_SEND_TIME=0"
  "DRC_SEND_BACKLIGHT=0"
  "DRC_SEND_UVCUAC=0"
  "DRC_SEND_UIC=0"
  "DRC_SEND_50125=0"
)

printf '\n%-24s %10s %8s %7s %8s\n' config resync/s idr/s fps input/s
for cfg in "${CONFIGS[@]}"; do
  say "run: $cfg"
  out=$(DRC_EXTRA_ENV="$cfg" "$ROOT/run/phase4-clock-domain.sh" "$SECS" 2>&1)
  res=$(printf '%s\n' "$out" | awk '/pad -> 50010 \(resync/ {for(i=1;i<=NF;i++) if($i=="=>"){print $(i+1); exit}}')
  idr=$(printf '%s\n' "$out" | awk '/IDR-marked datagrams/ {for(i=1;i<=NF;i++) if($i=="=>"){print $(i+1); exit}}')
  fps=$(printf '%s\n' "$out" | awk '/frames [0-9]+ \| frame-ends/ {for(i=1;i<=NF;i++) if($i=="fps"){print $(i+1); exit}}')
  inp=$(printf '%s\n' "$out" | awk '/50122 -> 50022/ {for(i=1;i<=NF;i++) if($i ~ /^\(/) {gsub(/[()\/s]/,"",$i); print $i; exit}}')
  pitch=$(printf '%s\n' "$out" | awk '/pad -> 50010 \(resync/ {print; exit}')
  printf '%-24s %10s %8s %7s %8s\n' "$cfg" "${res:-?}" "${idr:-?}" "${fps:-?}" "${inp:-?}"
  printf '   raw: %s\n' "${pitch:-no resync line}"
done

cat <<'EOF'

### how to read it
   resync/s near 0 with one knob off  => that message is the one upsetting the pad.
   resync/s ~59 with one knob off     => that message is innocent; keep looking.
EOF
