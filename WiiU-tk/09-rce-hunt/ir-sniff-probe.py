#!/usr/bin/env python3
"""IR/TV-remote probes that do not need to own udp/50023.

Several tools in this repo bind 192.168.1.10:50023 with SO_REUSEADDR, and on
2026-11-04 a parallel operator session was holding it. The pad, however, always
answers to `192.168.1.10:50023` regardless of the source port of the query
(research/BOOT-AND-MODES.md §5.1), so a probe can:

  1. send from an ephemeral source port, and
  2. read the pad's type-1 ACKs and type-2 replies off the AP interface with an
     AF_PACKET sniffer, filtered on udp/50123.

That makes the probe contention-tolerant: it never fights for the port, and
whatever else is running still gets its own copy of the replies.

Cases are the same IR/TV-remote hypotheses as ir-probe.py (IRCOM over-claim,
opcode confusion, svc 5/0x16 selector, svc 5/0x17 remocon-ID lookup). Nothing
persistent is attempted: no svc 5/0x18, no svc 5/0x0c, no svc 5/0x02, no svc 0
0x02-0x05/0x0b-0x0f.

Usage:
  sudo research/rce-hunt/ir-sniff-probe.py --dry-run
  sudo research/rce-hunt/ir-sniff-probe.py --out out/evidence/rce-ir-sniff
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time

PAD_IP = "192.168.1.11"
CMD_PORT = 50123
CONSOLE_CMD_PORT = 50023
IFACE = "WiiUAP"

IRCOM = (5, 0x11)
IRCOM_MISC = (5, 0x16)
TVCMD = (5, 0x17)


def build(svc: int, method: int, payload: bytes, seq: int,
          declared: int | None = None, flags: int = 0x40,
          tid: int = 0, fid: int = 0) -> bytes:
    outer = struct.pack("<HHHH", 0, 0, 12 + len(payload), seq & 0xFFFF)
    gen = bytearray(12)
    gen[0] = 0x7E
    gen[1] = 0x01
    gen[2] = (tid >> 8) & 0xFF
    gen[3] = ((tid << 4) & 0xF0) | (0x08 if True else 0) | ((fid >> 8) & 0x07)
    gen[4] = fid & 0xFF
    gen[5] = flags
    gen[6] = svc
    gen[7] = method
    gen[8:10] = struct.pack(">H", 0)
    gen[10:12] = struct.pack(">H", len(payload) if declared is None else declared)
    return outer + bytes(gen) + payload


def cases() -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []

    def add(name, svc, method, payload, declared=None):
        out.append((name, build(svc, method, payload, 0, declared)))

    add("B0.ircom_connect", *IRCOM, b"\x00")
    add("B1.ircom_send_8B", *IRCOM, b"\x01" + bytes.fromhex("1a2b3c4d5e6f7a8b"))
    add("B2.ircom_receive", *IRCOM, b"\x02")
    add("B3.ircom_disconnect", *IRCOM, b"\x03")
    for declared in (64, 255, 520, 1028, 0xFFFF):
        add(f"H1.ircom_20B_declare{declared}", *IRCOM, b"\x01" + bytes(19), declared)
    add("H1b.ircom_64B_declare8", *IRCOM, b"\x01" + bytes(63), 8)
    add("H1c.ircom_0B_declare520", *IRCOM, b"", 520)
    for op in (0x04, 0x05, 0x7F, 0x80, 0xFF):
        add(f"H2.ircom_opcode{op:02x}", *IRCOM, bytes([op]) + bytes(8))
    add("H2b.recv_before_connect", *IRCOM, b"\x02" + bytes(8))
    add("H2c.double_connect", *IRCOM, b"\x00\x00" + bytes(8))
    add("H2d.send_after_disconnect", *IRCOM, b"\x03\x01" + bytes(8))
    add("H2e.ircom_520B", *IRCOM, b"\x01" + bytes(519))
    for val in (0x00, 0x01, 0xFF, 0x02, 0x7F, 0x80):
        add(f"H3.misc_{val:02x}", *IRCOM_MISC, bytes([val]))
    add("H4.tvcmd_zeros", *TVCMD, bytes(7))
    add("H4.tvcmd_ff", *TVCMD, b"\xff" * 7)
    add("H4.tvcmd_seq", *TVCMD, bytes.fromhex("01020304050607"))
    add("H4.tvcmd_short3", *TVCMD, b"\x01\x02\x03")
    add("H4.tvcmd_long16", *TVCMD, bytes(16))
    # our own UIC EEPROM dump says remocon ID1 is "T0156" (09-tv-remote-ir.md §3),
    # so this is the one ID value likely to resolve; it may emit real IR.
    add("H4.tvcmd_T0156", *TVCMD, b"T0156" + b"\x00\x00")
    # TV1: repeat the bare "receive" so a stale-buffer echo would differ run to run
    add("TV1.recv_1", *IRCOM, b"\x02")
    add("TV1.recv_2", *IRCOM, b"\x02")
    add("TV1.recv_3", *IRCOM, b"\x02")
    add("TV1.recv_520decl", *IRCOM, b"\x02", 520)
    add("TV1.connect_then_recv", *IRCOM, b"\x00", None)
    return out


def parse_cmd(pkt: bytes) -> dict | None:
    if len(pkt) < 20:
        return None
    ptype, qtype, plen, seq = struct.unpack_from("<HHHH", pkt, 0)
    if pkt[8] != 0x7E:
        return None
    return {"packet_type": ptype, "query_type": qtype, "seq": seq,
            "service": pkt[14], "method": pkt[15],
            "error": struct.unpack_from(">H", pkt, 16)[0],
            "body_len": struct.unpack_from(">H", pkt, 18)[0],
            "body": pkt[20:20 + struct.unpack_from(">H", pkt, 18)[0]]}


def sniff_drain(sniff: socket.socket, replies: dict[int, list[dict]],
                acks: dict[int, int]) -> int:
    """Pull datagrams from the AF_PACKET socket; index by cmd sequence id."""
    n = 0
    while True:
        try:
            frame = sniff.recv(65535)
        except BlockingIOError:
            return n
        if len(frame) < 28:
            continue
        ihl = (frame[0] & 0x0F) * 4
        if frame[9] != 17:                      # UDP only
            continue
        udp = frame[ihl:]
        if len(udp) < 8:
            continue
        sport, dport, ulen = struct.unpack_from(">HHH", udp, 0)
        if dport != CONSOLE_CMD_PORT or sport != CMD_PORT:
            continue                            # we want pad -> console:50023
        payload = udp[8:ulen]
        p = parse_cmd(payload)
        if not p:
            continue
        n += 1
        if p["packet_type"] == 1:
            acks[p["seq"]] = acks.get(p["seq"], 0) + 1
        elif p["packet_type"] == 2:
            replies.setdefault(p["seq"], []).append(
                {"error": p["error"], "len": len(p["body"]),
                 "body": p["body"].hex(), "declared": p["body_len"],
                 "service": p["service"], "method": p["method"]})
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--iface", default=IFACE)
    ap.add_argument("--wait", type=float, default=1.0,
                    help="seconds to listen for late replies after each case")
    ap.add_argument("--gap", type=float, default=0.25)
    ap.add_argument("--filter", default=None,
                    help="comma-separated case-name prefixes, e.g. 'B,H1,H2'")
    args = ap.parse_args()

    todo = cases()
    if args.filter:
        pats = [p.strip() for p in args.filter.split(",") if p.strip()]
        todo = [c for c in todo if any(c[0].startswith(p) for p in pats)]
    print(f"# {len(todo)} cases, pad={PAD_IP}, iface={args.iface}, "
          f"{'dry-run' if args.dry_run else 'SEND+sniff'}")
    if args.dry_run:
        for name, pkt in todo:
            print(f"  {name:32s} {len(pkt):3d}B  {pkt.hex()[:70]}")
        return 0

    sniff = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                          socket.htons(0x0800))
    sniff.bind((args.iface, 0))
    sniff.setblocking(False)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.bind(("0.0.0.0", 0))               # ephemeral: we never claim 50023

    replies: dict[int, list] = {}
    acks: dict[int, int] = {}
    seq = 0x900
    rows = []
    for name, pkt in todo:
        seq = (seq + 1) & 0xFFFF
        pkt = bytearray(pkt)
        pkt[6:8] = struct.pack("<H", seq)
        sniff_drain(sniff, replies, acks)
        tx.sendto(bytes(pkt), (PAD_IP, CMD_PORT))
        t_end = time.time() + args.wait
        while time.time() < t_end:
            sniff_drain(sniff, replies, acks)
            time.sleep(0.02)
        r = replies.get(seq, [])
        rec = {"case": name, "seq": seq, "sent": bytes(pkt).hex(),
               "acks": acks.get(seq, 0), "replies": r}
        rows.append(rec)
        if r:
            detail = " | ".join(f"err={x['error']} {x['len']}B {x['body'][:36]}"
                                for x in r)
        else:
            detail = "NO REPLY"
        print(f"{name:32s} acks={rec['acks']} {detail}")
        time.sleep(args.gap)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "ir-sniff.json"), "w") as fh:
            json.dump({"when": time.ctime(), "iface": args.iface, "rows": rows},
                      fh, indent=1)
        print(f"# evidence in {args.out}")
    total = sum(len(v) for v in replies.values())
    print(f"# {total} pad replies captured, {len(rows)} cases, "
          f"{sum(1 for r in rows if r['replies'])} answered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
