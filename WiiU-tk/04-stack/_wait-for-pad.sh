#!/bin/bash
# _wait-for-pad.sh - sourced by the live experiment scripts.
#
# Why: every experiment so far started the capture and the media BEFORE the pad
# was attached (or assumed it already was), so the one frame that carries the
# VSTRM `init` flag went out while the pad was still joining, and the capture
# began somewhere in the middle of the stream. The console's own ordering is the
# opposite - the pad is associated and its services are alive long before video
# starts - which is also what Barista does (it gates media on "input seen +
# UVC/UAC reply seen"). So: wait for the pad, THEN start capturing, THEN start
# the media, and the capture contains the entire stream from its first frame.
#
# Detection is deliberately two-stage: an ICMP answer only proves the pad has an
# IP; the rx_packets counter on the AP interface proves it is actually sending
# input frames to us right now (the pad must be awake, not just associated).

# wait_for_pad <timeout_s> [min_pkts_per_s]
wait_for_pad() {
  # callers may not export these; the helper must never be the reason a run dies
  local iface=${IF:-WiiUAP}
  local pad=${PAD:-192.168.1.11}
  local timeout=${1:-300}
  local want=${2:-40}
  local t0=$SECONDS
  local a b delta
  printf '   waiting up to %ss for the GamePad to send input (press power on the pad)\n' "$timeout"
  while [ $((SECONDS - t0)) -lt "$timeout" ]; do
    # Do NOT gate on ICMP. The pad answers ARP but not ping (measured: 100% packet
    # loss while it is sending input at ~280 pkt/s), so a ping test blocks every
    # start even when the pad is perfectly awake - it silently wasted a full
    # 10-minute wait more than once.
    a=$(cat "/sys/class/net/$iface/statistics/rx_packets")
    sleep 2
    b=$(cat "/sys/class/net/$iface/statistics/rx_packets")
    delta=$(( (b - a) / 2 ))
    if [ "$delta" -ge "$want" ]; then
      printf '   pad is up and sending input (%s pkt/s) after %ss\n' \
             "$delta" "$((SECONDS - t0))"
      return 0
    fi
    sleep 2
  done
  printf '   FAIL: pad did not attach within %ss\n' "$timeout"
  return 1
}
