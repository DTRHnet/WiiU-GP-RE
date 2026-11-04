#!/usr/bin/env python3
"""TV-remote / IR surface probes (non-destructive) — the `ir` manager path.

Hypotheses under test (research/rce-hunt/02-attack-surface.md §4.2, and the IRCOM
row that says payload AND reply are both capped at 520 B):

  H1  over-claim: an IRCOM request declares a larger generic payload_size than it
      delivers. If the handler trusts the declared size it reads past the
      datagram, and because `svc 5/0x11` can *reply with up to 520 B*, those
      bytes may come back to us = a memory-disclosure channel.
  H2  opcode confusion: payload byte 0 selects connect/send/receive/disconnect
      (0..3). Values outside that range, and out-of-order sequences (receive
      before connect, double connect, send after disconnect), are untested.
  H3  `svc 5/0x16`: documented as "should be either 0 or -1" — every other value
      is undefined and untested.
  H4  `svc 5/0x17`: 7-byte payload whose first 5 bytes are a remocon ID. An
      attacker-chosen ID is a 5-byte key into whatever store the `ir` manager
      searches; 0x00 and 0xFF fills are the cheap extremes.

Deliberately NOT touched (persistent or brick-gated under this engagement's ROE):
  `svc 5/0x18` (set remocon IDs), `svc 5/0x0c` (UIC EEPROM write),
  `svc 5/0x02` (102 B into the UIC), `svc 0` 0x02-0x05 / 0x0b-0x0f.

Observables: reply presence/length/content (the leak signal), type-1 ACK, pad
input rate, and whether `svc 4/0x05` still answers afterwards.

Usage:
  research/rce-hunt/ir-probe.py                     # dry run
  sudo research/rce-hunt/ir-probe.py --send --out out/evidence/rce-ir-$(date +%H%M)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
import importlib.util as _ilu  # noqa: E402

_spec = _ilu.spec_from_file_location("probe_readonly",
                                     os.path.join(_HERE, "probe-readonly.py"))
_pr = _ilu.module_from_spec(_spec)
sys.modules["probe_readonly"] = _pr
_spec.loader.exec_module(_pr)  # type: ignore[union-attr]

CONSOLE_IP = _pr.CONSOLE_IP
PAD_IP = _pr.PAD_IP
CONSOLE_CMD_PORT = _pr.CONSOLE_CMD_PORT
PAD_CMD_PORT = _pr.PAD_CMD_PORT
build_generic = _pr.build_generic
parse_cmd = _pr.parse_cmd
open_liveness_sockets = _pr.open_liveness_sockets
drain = _pr.drain
port_owner_warning = _pr.port_owner_warning

IRCOM = (5, 0x11)
IRCOM_MISC = (5, 0x16)
TVCMD = (5, 0x17)


def dgram(svc: int, method: int, payload: bytes, seq: int,
          declared: int | None = None, flags: int = 0x40) -> bytes:
    pkt = bytearray(build_generic(svc, method, payload, seq=seq, flags=flags))
    if declared is not None:
        pkt[18:20] = struct.pack(">H", declared)
    return bytes(pkt)


def build_cases() -> list[tuple[str, bytes]]:
    cases: list[tuple[str, bytes]] = []

    def add(name: str, svc: int, method: int, payload: bytes,
            declared: int | None = None) -> None:
        cases.append((name, dgram(svc, method, payload, seq=0, declared=declared)))

    # --- H2/H1 baseline: the documented IRCOM four-state protocol ------------
    add("B0.ircom_connect", *IRCOM, b"\x00")
    add("B1.ircom_send_8B", *IRCOM, b"\x01" + bytes.fromhex("1a2b3c4d5e6f7a8b"))
    add("B2.ircom_receive", *IRCOM, b"\x02")
    add("B3.ircom_disconnect", *IRCOM, b"\x03")

    # --- H1: over-claim. 20 real bytes, larger declaration -------------------
    short = b"\x01" + bytes(19)
    for declared in (64, 255, 520, 1028, 0xFFFF):
        add(f"H1.ircom_send20_declare{declared}", *IRCOM, short, declared=declared)
    # ...and the opposite: declare less than delivered
    add("H1b.ircom_send64_declare8", *IRCOM, b"\x01" + bytes(63), declared=8)
    # empty payload with a large declaration
    add("H1c.ircom_empty_declare520", *IRCOM, b"", declared=520)

    # --- H2: opcode confusion ------------------------------------------------
    for op in (0x04, 0x05, 0x7F, 0x80, 0xFF):
        add(f"H2.ircom_opcode{op:02x}", *IRCOM, bytes([op]) + bytes(8))
    add("H2b.ircom_receive_before_connect", *IRCOM, b"\x02" + bytes(8))
    add("H2c.ircom_double_connect", *IRCOM, b"\x00\x00" + bytes(8))
    add("H2d.ircom_send_after_disconnect", *IRCOM, b"\x03\x01" + bytes(8))
    add("H2e.ircom_520B_send", *IRCOM, b"\x01" + bytes(519))

    # --- H3: svc 5/0x16 undocumented selector --------------------------------
    for val in (0x00, 0x01, 0xFF, 0x02, 0x7F, 0x80):
        add(f"H3.ircom_misc_{val:02x}", *IRCOM_MISC, bytes([val]))

    # --- H4: svc 5/0x17 remocon-ID lookup ------------------------------------
    add("H4.tvcmd_zeros", *TVCMD, bytes(7))
    add("H4.tvcmd_ff", *TVCMD, b"\xff" * 7)
    add("H4.tvcmd_seq", *TVCMD, bytes.fromhex("01020304050607"))
    add("H4.tvcmd_short3", *TVCMD, b"\x01\x02\x03")
    add("H4.tvcmd_long16", *TVCMD, bytes(16))
    return cases


def ask(sock: socket.socket, name: str, pkt: bytes, seq: int,
        timeout: float) -> dict:
    sock.sendto(pkt, (PAD_IP, PAD_CMD_PORT))
    rec = {"case": name, "sent": pkt.hex(), "result": "NOREPLY", "acks": 0,
           "replies": [], "t": time.time()}
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        p = parse_cmd(data)
        if not p or p.get("seq") != (seq & 0xFFFF):
            continue
        if p["packet_type"] == 1:
            rec["acks"] += 1
        elif p["packet_type"] == 2:
            body = p.get("body", b"")
            rec["replies"].append({"error": p.get("error"), "len": len(body),
                                   "body": body.hex(),
                                   "declared": p.get("body_len")})
            rec["result"] = "OK"
            sock.sendto(struct.pack("<HHHH", 3, p["query_type"], 8, seq & 0xFFFF),
                        (PAD_IP, PAD_CMD_PORT))
    if not rec["replies"]:
        rec["result"] = "NOACK" if rec["acks"] else "NOREPLY"
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--timeout", type=float, default=1.2)
    ap.add_argument("--gap", type=float, default=0.35)
    ap.add_argument("--deadman", type=int, default=6)
    args = ap.parse_args()

    cases = build_cases()
    print(f"# {len(cases)} IR/TV-remote cases, pad={PAD_IP}, "
          f"{'SEND' if args.send else 'dry-run'}")
    if not args.send:
        for name, pkt in cases:
            print(f"  {name:34s} {len(pkt):3d}B  {pkt.hex()[:72]}")
        return 0
    if not port_owner_warning():
        return 2

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((CONSOLE_IP, CONSOLE_CMD_PORT))
    sock.settimeout(0.05)
    live_socks, live = open_liveness_sockets()
    outdir = args.out
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        jl = open(os.path.join(outdir, "ir.jsonl"), "w")

    seq = 0x700
    fails = 0
    baseline_state = None
    for name, pkt in cases:
        seq = (seq + 1) & 0xFFFF
        pkt = bytearray(pkt)
        pkt[6:8] = struct.pack("<H", seq)      # outer seq
        pre = live.take()
        rec = ask(sock, name, bytes(pkt), seq, args.timeout)
        t_end = time.time() + 0.35
        while time.time() < t_end:
            drain(live_socks, live)
            time.sleep(0.02)
        post = live.take()
        rec["input"] = pre["input_pkts"] + post["input_pkts"]
        rec["resync"] = pre["resync_pkts"] + post["resync_pkts"]

        # liveness check on the *state* query, in the same socket/seq space
        seq = (seq + 1) & 0xFFFF
        st = ask(sock, "state", dgram(4, 0x05, b"", seq), seq, args.timeout)
        rec["state"] = (st["replies"][0]["body"] if st["replies"] else st["result"])
        if baseline_state is None and st["replies"]:
            baseline_state = rec["state"]

        r = rec["replies"][0] if rec["replies"] else None
        detail = (f"error={r['error']} body={r['len']}B {r['body'][:40]}"
                  if r else rec["result"])
        print(f"{name:34s} {rec['result']:7s} acks={rec['acks']} {detail} "
              f"in={rec['input']:3d} rs={rec['resync']} state={rec['state']}")
        if outdir:
            jl.write(json.dumps(rec) + "\n")
            jl.flush()
        fails = 0 if rec["result"] == "OK" else fails + 1
        if fails >= args.deadman:
            print(f"# deadman: {fails} consecutive failures, stopping")
            break
        time.sleep(args.gap)

    if outdir:
        jl.close()
        print(f"# evidence in {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
