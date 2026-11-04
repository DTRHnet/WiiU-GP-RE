#!/bin/bash
# drc-up.sh - bring the whole DRC stack up in one shot, or fail cleanly.
#
# Verified working 2026-11-04 02:44: WiiUAP on ch149, pad associates, 4-way
# handshake completes, DHCP 192.168.1.11, video 143 pkt/s to 50120, input
# 69 pkt/s from 50122, ZERO resync requests. Evidence: out/evidence/live-0245/.
#
# Design rules (learned the hard way):
#   * NEVER touch the interface carrying the default route. The AP radio must be
#     a free radio; the uplink stays on its own card.
#   * No `pkill -f <pattern>`: those match the calling shell and have killed this
#     session's own terminal repeatedly. Only recorded PIDs are killed.
#   * Background children must be started with setsid: a plain `nohup ... &` from
#     a `sudo sh -c` wrapper dies with the wrapper (that silently killed the
#     streamer once, leaving the pad talking to a closed port).
#   * Idempotent: safe to run twice.
#
# Why an idle wpa_supplicant is started on the AP radio (the non-obvious part):
#   iwlwifi's self-managed regulatory (LAR) marks every 5 GHz channel `no IR`
#   when the radio is idle, and `iw reg set` is ignored by a self-managed phy.
#   hostapd then dies with:
#       Configured channel (149) not found from the channel list ... (-3)
#   A wpa_supplicant with `country=CA` on that phy sends a COUNTRY hint that
#   makes UNII-3 IR-capable. It needs NO network configured - it only has to be
#   running. Stopping it drops the AP's channel permission again.
#   (A hostapd `country_code=`/`ieee80211d=` line does NOT help: hostapd applies
#   the country after channel selection, so it fails before it gets there.)
#
# Requires: a free wireless radio (default wlan0) and wlan1/dongle carrying the
# uplink. Refuses to run if that is not the case.
set -uo pipefail

ROOT=/home/kali/Wiiu
APIF=WiiUAP
RADIO=${RADIO:-wlan0}
CONF=/var/run/drc-ap.conf
RUNDIR=/var/run/drc
PSK_FILE=$ROOT/run/pairing.env
WPA_IDLE=/var/run/wpa-idle.conf
PAD=40:d2:8a:17:e2:09
BSSID=cc:fb:65:b6:81:69
SSID=WiiUccfb65b68169
CHANNEL=${CHANNEL:-149}
VNC=127.0.0.1:5900
HOSTAPD=$ROOT/pc2drc/drc-hostap/hostapd/hostapd
WPAS=$ROOT/build/hostap-2.12/wpa_supplicant/wpa_supplicant
TVNC=$ROOT/pc2drc/libdrc-vnc/drcvncclient/src/drcvncclient
export LD_LIBRARY_PATH=$ROOT/out/libs:$ROOT/out/libdrc/lib:$ROOT/out/x264/lib

say() { printf '\n== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*"; exit 1; }
mkdir -p "$RUNDIR" "$ROOT/out/logs"

# ---------------------------------------------------------------- safety
UP_IF=$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
say "uplink is $UP_IF"
[ -e "/sys/class/net/$RADIO" ] || die "$RADIO does not exist"
if [ "${UP_IF:-}" = "$RADIO" ]; then
  cat <<EOF
REFUSING TO RUN: $RADIO currently carries your default route, so using it as
the AP would drop your internet.

Fix (any one):
  * plug the RTL8188FU dongle back in -> it becomes wlan1 as the uplink, or
  * run with RADIO=<other free radio> ./run/drc-up.sh
EOF
  exit 1
fi

# ---------------------------------------------------------------- regulatory
# Remember the radio MAC so drc-down.sh can put it back.
ORIG_MAC=$(cat "/sys/class/net/$RADIO/address")
echo "$ORIG_MAC" > "$RUNDIR/$RADIO.orig-mac"

say "unmanaging $RADIO and $APIF in NetworkManager"
mkdir -p /etc/NetworkManager/conf.d
if [ ! -f /etc/NetworkManager/conf.d/99-wiiuap-unmanaged.conf ]; then
  cat > /etc/NetworkManager/conf.d/99-wiiuap-unmanaged.conf <<EOF
# Wii U DRC AP vif is managed entirely by drc-hostap; NM must never touch it.
[keyfile]
unmanaged-devices=interface-name:WiiUAP
EOF
  nmcli general reload >/dev/null 2>&1 || true
  sleep 3
fi
nmcli dev set "$RADIO" managed no 2>/dev/null || true
nmcli dev set "$APIF" managed no 2>/dev/null || true

say "holding the 5 GHz regulatory domain open with an idle supplicant"
cat > "$WPA_IDLE" <<EOF
ctrl_interface=/var/run/wpa-idle
ctrl_interface_group=0
country=CA
EOF
chmod 600 "$WPA_IDLE"
# stop a previous one (recorded pid only)
if [ -f "$RUNDIR/idle-supplicant.pid" ]; then
  kill "$(cat "$RUNDIR/idle-supplicant.pid")" 2>/dev/null && sleep 2
fi
# A stale control socket / pid file makes wpa_supplicant exit immediately, and
# the radio then stays 5 GHz no-IR, so hostapd cannot select the channel.
rm -rf /var/run/wpa-idle /var/run/wpa-wlan0 /var/run/wpa-wlan0.pid /var/run/wpa-idle.pid 2>/dev/null
ip link set "$RADIO" up 2>/dev/null
cd "$ROOT"
setsid nohup "$WPAS" -i "$RADIO" -c "$WPA_IDLE" -D nl80211 \
  > "$ROOT/out/logs/wpa-idle.log" 2>&1 < /dev/null &
echo $! > "$RUNDIR/idle-supplicant.pid"
PHYNAME=$(basename "$(readlink -f "/sys/class/net/$RADIO/phy80211")")
FREQ=""
for _ in $(seq 1 12); do
  FREQ=$(iw phy "$PHYNAME" info 2>/dev/null \
         | awk -v ch="$CHANNEL" '$0 ~ "\\* " && $0 ~ "\\["ch"\\]" {print; exit}')
  case "$FREQ" in
    *"no IR"*|"") sleep 1 ;;
    *) break ;;
  esac
done
echo "   $FREQ"
case "$FREQ" in
  *"no IR"*) die "ch$CHANNEL is still no-IR; the supplicant did not unlock 5 GHz" ;;
esac

# ---------------------------------------------------------------- egress
# A leftover OUTPUT DROP rule for UDP 50121 has silently starved the pad
# before: that port carries the video-format/timing message AND the PCM audio,
# and without the format message the pad stays on its "cannot connect" screen
# and never asks for video at all. Drop such a rule if it is still there.
if iptables -S OUTPUT 2>/dev/null | grep -q -- "--dport 50121 -j DROP"; then
  say "removing stale OUTPUT DROP rule for udp/50121"
  iptables -D OUTPUT -p udp -m udp --dport 50121 -j DROP 2>/dev/null || true
fi
if ! python3 - <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x" * 4, ("127.0.0.1", 50121))
except OSError:
    sys.exit(1)
PY
then
  say "WARNING: udp/50121 egress looks blocked; the pad will not start decoding"
fi

# ---------------------------------------------------------------- AP
say "preparing $APIF on $RADIO"
iw dev "$APIF" del 2>/dev/null || true
sleep 1
# Create it AS an AP vif and never call `iw dev X set type` on it afterwards:
# on iwlwifi the down+set-type dance returns -EBUSY and silently flips the vif
# back to managed, after which hostapd cannot see any 5 GHz channel.
iw dev "$RADIO" interface add "$APIF" type __ap || die "cannot create $APIF"
nmcli dev set "$APIF" managed no 2>/dev/null || true
ip link set "$APIF" down
# The AP must advertise the console's own MAC or the pad ignores it.
ip link set "$APIF" address "$BSSID"
ip link set "$APIF" up
ip addr replace 192.168.1.10/24 dev "$APIF"
ip link set mtu 1800 dev "$APIF"

say "rendering hostapd config"
PSK=$(grep '^PSK=' "$PSK_FILE" | cut -d= -f2)
sed -e "s/__IFACE__/$APIF/" -e "s/__SSID__/$SSID/" \
    -e "s/__PSK__/$PSK/" -e "s/__CHANNEL__/$CHANNEL/" \
    "$ROOT/run/wiiu_ap_normal.conf.template" > "$CONF"
# Keep the pad from being dropped as "inactive", and pin the BSSID.
sed -i "s/^hw_mode=a\$/ap_max_inactivity=86400\ndisassoc_low_ack=0\nbssid=$BSSID\nhw_mode=a/" "$CONF"
chmod 600 "$CONF"

say "starting hostapd"
setsid nohup "$HOSTAPD" -dd "$CONF" > /var/log/drc-ap.log 2>&1 < /dev/null &
echo $! > "$RUNDIR/hostapd.pid"
sleep 7
if ! grep -q "AP-ENABLED" /var/log/drc-ap.log; then
  echo "hostapd failed; last lines:"; tail -6 /var/log/drc-ap.log
  exit 1
fi
CH=$(iw dev "$APIF" info 2>/dev/null | awk '/channel/{print $2}')
echo "   channel=$CH  RF-seen packet count in 3s below"

# ---------------------------------------------------------------- DHCP
say "starting DHCP for the pad"
setsid nohup "$ROOT/pc2drc/drc-hostap/netboot/netboot" \
  192.168.1.255 192.168.1.10 192.168.1.11 "$PAD" \
  > /var/log/drc-dhcp.log 2>&1 < /dev/null &
echo $! > "$RUNDIR/netboot.pid"
sleep 2
grep -qi "can not bind" /var/log/drc-dhcp.log && { echo "   DHCP bind failed"; tail -3 /var/log/drc-dhcp.log; }

# ---------------------------------------------------------------- media clock
# The pad schedules video against a media timestamp in its own clock domain.
# Measured 2026-11-04 (research/GROUND-TRUTH-SESSION.md sec.4): replaying a real
# console's own media bytes with the console's original ~92 s clock left the pad
# requesting keyframes 59.7 times/s; the SAME bytes with the clock rebased to
# (epoch_ms mod 2^32) microseconds - ~2800 s, in the pad's own epoch - made it go
# silent (0.0 requests/s for 70 s). A clock starting at 0 (what this script used
# to produce) is far behind the pad and is rejected outright. DRC_TSF_BASE_US
# pins an explicit base; align-clock.sh is no longer needed (and would clobber
# this with the AP's much smaller TSF).
say "placing the media clock in the pad's epoch"
TSF_BASE=${DRC_TSF_BASE_US:-$(( ( $(date +%s%3N) ) & 0xFFFFFFFF ))}
mkdir -p "$RUNDIR"
echo "$TSF_BASE" > "$RUNDIR/tsf-offset-us"
echo "   clock base $TSF_BASE us ($((TSF_BASE/1000000)) s)"

# ---------------------------------------------------------------- stream
say "starting VNC + streamer"
pgrep -x x11vnc >/dev/null || x11vnc -display :0 -localhost -rfbport 5900 -nopw \
  -forever -shared -scale 0.46875 -bg -quiet -noxdamage

# Wait for the pad BEFORE starting media. The streamer's first frame is the only
# one that carries the VSTRM `init` flag (console behaviour), so starting it
# while the pad is still joining throws that frame away and the pad never learns
# a stream began. Barista gates media on the same condition (input seen on 50022
# plus a validated UVC/UAC reply). DRC_WAIT_PAD=0 skips the wait; the timeout is
# DRC_WAIT_SECS (default 120 s) and a timeout only warns - the stack still comes
# up, so this can never make drc-up.sh unusable.
if [ "${DRC_WAIT_PAD:-1}" != "0" ]; then
  WAIT_MAX=${DRC_WAIT_SECS:-120}
  say "waiting up to ${WAIT_MAX}s for the GamePad before starting media"
  WAIT_T0=$SECONDS
  PAD_READY=0
  while [ $((SECONDS - WAIT_T0)) -lt "$WAIT_MAX" ]; do
    if ping -c1 -W1 192.168.1.11 >/dev/null 2>&1; then
      A=$(cat "/sys/class/net/$APIF/statistics/rx_packets" 2>/dev/null || echo 0)
      sleep 2
      B=$(cat "/sys/class/net/$APIF/statistics/rx_packets" 2>/dev/null || echo 0)
      if [ $(( (B - A) / 2 )) -ge 40 ]; then
        echo "   pad ready after $((SECONDS - WAIT_T0))s - starting media on a live pad"
        PAD_READY=1
        break
      fi
    fi
    sleep 2
  done
  [ "$PAD_READY" = "1" ] || echo "   pad not ready after ${WAIT_MAX}s - starting media anyway" \
                           " (re-run drc-up.sh, or DRC_WAIT_PAD=0 to silence this)"
fi

setsid nohup env DRC_SYNTHETIC_TSF=1 DRC_TSF_OFFSET_US="$TSF_BASE" ${DRC_EXTRA_ENV:-} \
  "$TVNC" -joystick "$VNC" \
  > "$ROOT/out/logs/drcvnc.log" 2>&1 < /dev/null &
echo $! > "$RUNDIR/streamer.pid"
sleep 8
if ! ss -lunp 2>/dev/null | grep -q '192.168.1.10:50022'; then
  echo "   WARNING: streamer is not listening on 192.168.1.10:50022"
  tail -4 "$ROOT/out/logs/drcvnc.log"
fi

cat <<EOF

== up
   AP        $APIF on channel $CH (BSSID $BSSID, SSID $SSID)
   DHCP      pad -> 192.168.1.11
   streamer  pid $(cat $RUNDIR/streamer.pid), listening 50010/50022/50023
   PIDs      $RUNDIR/*.pid

   Verify:  run/05-diagnose.sh
   Stop:    sudo $ROOT/run/drc-down.sh
EOF
