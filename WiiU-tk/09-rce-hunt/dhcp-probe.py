#!/usr/bin/env python3
"""Minimal DHCP responder used to diagnose a GamePad stuck in DISCOVER.

Why: our DHCP server (`pc2drc/drc-hostap/netboot`) answers the pad's DISCOVER with
an OFFER that carries option 53 and 54 but **no option 1 (subnet mask) and no
option 3 (router)**, and advertises `PXEClient` in option 60. On 2026-11-04 the
pad answered that OFFER never (it re-DISCOVERed at 2 Hz for minutes while still
answering ICMP on 192.168.1.11). This responder sends the same lease with a
complete option set, so the difference between "pad accepts" and "pad ignores" is
one variable.

It is diagnostic only: no flash, no pad state change beyond a normal DHCP lease,
and the operator's `netboot` must be stopped first (it owns udp/67).

Usage (root, netboot stopped):
  sudo python3 research/rce-hunt/dhcp-probe.py --lease 192.168.1.11 --secs 60
"""
from __future__ import annotations

import argparse
import socket
import struct
import time

PAD_MAC = bytes.fromhex("40d28a17e209")
MAGIC = b"\x63\x82\x53\x63"


def parse_req(data: bytes) -> dict | None:
    if len(data) < 240 or data[236:240] != MAGIC:
        return None
    out = {
        "op": data[0], "xid": data[4:8], "flags": struct.unpack("!H", data[10:12])[0],
        "chaddr": data[28:34], "ciaddr": data[12:16],
        "opts": {},
    }
    i = 240
    while i < len(data):
        code = data[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        out["opts"][code] = data[i + 2:i + 2 + ln]
        i += 2 + ln
    out["msgtype"] = out["opts"].get(53, b"\x00")[0]
    return out


def build_reply(req: dict, msgtype: int, server: str, lease: str,
                netmask: str, router: str, dns: str) -> bytes:
    pkt = bytearray(240)
    pkt[0] = 2                      # BOOTREPLY
    pkt[1] = 1                      # ethernet
    pkt[2] = 6                      # hlen
    pkt[3] = 0
    pkt[4:8] = req["xid"]
    struct.pack_into("!H", pkt, 8, 0)                 # secs
    struct.pack_into("!H", pkt, 10, req["flags"])     # echo broadcast flag
    pkt[12:16] = b"\x00" * 4                          # ciaddr
    pkt[16:20] = socket.inet_aton(lease)              # yiaddr
    pkt[20:24] = socket.inet_aton(server)             # siaddr
    pkt[24:28] = b"\x00" * 4                          # giaddr
    pkt[28:34] = req["chaddr"]
    pkt[236:240] = MAGIC
    opts = bytearray()
    opts += bytes([53, 1, msgtype])
    opts += bytes([54, 4]) + socket.inet_aton(server)
    opts += bytes([51, 4]) + struct.pack("!I", 0xFFFFFFFF)
    opts += bytes([1, 4]) + socket.inet_aton(netmask)
    opts += bytes([3, 4]) + socket.inet_aton(router)
    opts += bytes([6, 4]) + socket.inet_aton(dns)
    opts += bytes([58, 4]) + struct.pack("!I", 600)
    opts += bytes([59, 4]) + struct.pack("!I", 900)
    opts += bytes([28, 4]) + socket.inet_aton("192.168.1.255")
    opts += b"\xff"
    return bytes(pkt + opts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="192.168.1.10")
    ap.add_argument("--lease", default="192.168.1.11")
    ap.add_argument("--netmask", default="255.255.255.0")
    ap.add_argument("--router", default="192.168.1.10")
    ap.add_argument("--dns", default="192.168.1.10")
    ap.add_argument("--secs", type=float, default=60)
    ap.add_argument("--only-mac", action="store_true",
                    help="ignore requests from any MAC but the GamePad (default: on)")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # must bind the wildcard: a socket bound to a specific unicast address
    # never receives the pad's 255.255.255.255:67 DISCOVER (that is why
    # netboot binds both 192.168.1.10:67 and 255.255.255.255:67).
    s.bind(("", 67))
    s.settimeout(1.0)
    print(f"# DHCP responder on {args.server}:67 -> lease {args.lease} "
          f"mask {args.netmask} router {args.router} for {args.secs:.0f}s")
    print("# wait for the pad's DISCOVER/REQUEST ...")
    seen = {"DISCOVER": 0, "REQUEST": 0, "other": 0}
    t_end = time.time() + args.secs
    while time.time() < t_end:
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            continue
        req = parse_req(data)
        if not req:
            continue
        if args.only_mac and req["chaddr"] != PAD_MAC:
            print(f"  (ignored {req['chaddr'].hex(':')} type {req['msgtype']})")
            continue
        kind = {1: "DISCOVER", 3: "REQUEST"}.get(req["msgtype"], f"type{req['msgtype']}")
        seen[kind if kind in seen else "other"] = seen.get(kind if kind in seen else "other", 0) + 1
        reply_type = 2 if req["msgtype"] == 1 else 5      # OFFER / ACK
        pkt = build_reply(req, reply_type, args.server, args.lease,
                          args.netmask, args.router, args.dns)
        s.sendto(pkt, ("255.255.255.255", 68))
        # ALSO unicast: a power-saving station can miss a broadcast the AP
        # buffers for DTIM; the pad already holds 192.168.1.11 so this is
        # deliverable directly. New xid per attempt on the pad side suggests
        # it never sees the broadcast.
        try:
            s.sendto(pkt, (args.lease, 68))
        except OSError as exc:
            print(f"  (unicast failed: {exc})")
        opts = req["opts"]
        print(f"{time.strftime('%H:%M:%S')} {kind:8s} from {req['chaddr'].hex(':')} "
              f"xid={req['xid'].hex()} flags=0x{req['flags']:04x} "
              f"opts={sorted(opts)} -> sent {('OFFER' if reply_type == 2 else 'ACK')} "
              f"({len(pkt)}B)")
    print(f"# summary {seen}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
