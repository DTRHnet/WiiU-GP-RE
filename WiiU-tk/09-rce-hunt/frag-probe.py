#!/usr/bin/env python3
"""E5 — command-plane multi-fragment reassembly probes (non-destructive).

The real console pushes a 194-message state stream as strict `M M M S` groups of
four 1048-byte datagrams (svc 0 / method 0x11), each declaring an inner
payload_size of 0x0404 = 1028 (VERIFIED, research/GROUND-TRUTH-SESSION.md §7b and
out/evidence/truth/port50123.bin). This tool keeps the outer envelope identical
and lies about the length inside it, which is the cheapest way to test whether
the pad's reassembly trusts the declared size over the received datagram size.

The hypothesis (02-attack-surface.md ranking #3, M3/M4): the pad copies
`payload_size` bytes out of a datagram that contains fewer, i.e. an out-of-bounds
read of its own network buffers whose contents then land in the reassembly target
(a UIC staging buffer) or in a reply we can read.

Nothing here writes flash, reboots the pad or changes persistent settings:
svc 0/0x11 is the console's own *state push* handler. Series D of the report
(tid confusion with svc 0/0x03, the firmware-data method) is deliberately
EXCLUDED because it could start an update.

Observables (02-attack-surface.md §6): type-1 ACK presence (O4), reply
presence/content (O14), pad input rate (O1), a reset of the input sequence or of
the fw-version byte (O2/O3), and whether svc 4/0x05 still answers afterwards.

Usage:
  research/rce-hunt/frag-probe.py                      # dry run, list cases
  sudo research/rce-hunt/frag-probe.py --send --out out/evidence/rce-frag-$(date +%H%M)
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

TID = 0x10B            # the console's own transaction id for the state push
DECLARED = 0x0404      # 1028: what every real fragment declares
FINAL_BIT = 0x08       # generic header byte 3 bit 3 = "final fragment"
FLAG_CONT = 0x42       # measured on 778 console fragments
FLAG_FINAL = 0x40      # measured on the last fragment of each group


def frag(tid: int, fid: int, payload: bytes, declared: int,
         final: bool, flags: int, seq: int) -> bytes:
    """One datagram, with the inner generic payload_size overridden."""
    pkt = bytearray(build_generic(0x00, 0x11, payload, seq=seq, tid=tid, fid=fid,
                                  final=final, flags=flags))
    pkt[18:20] = struct.pack(">H", declared)      # generic payload_size (BE, wire 18..19)
    return bytes(pkt)


def build_cases() -> list[tuple[str, list[bytes]]]:
    """name -> list of datagrams to send back to back (one logical message)."""
    cases = []
    body = lambda i: struct.pack("<I", i) + bytes(1024)   # 1028 real bytes

    # A0: control, byte-identical shape to the console (4 x 1028 real bytes)
    cases.append(("A0.control_4x1028", [
        frag(TID, 0, body(1), DECLARED, False, FLAG_CONT, 0x300),
        frag(TID, 1, body(2), DECLARED, False, FLAG_CONT, 0x301),
        frag(TID, 2, body(3), DECLARED, False, FLAG_CONT, 0x302),
        frag(TID, 3, body(4), DECLARED, True, FLAG_FINAL, 0x303),
    ]))

    # A1..A3: declare 1028, deliver less and less
    for name, sent in (("A1.declare1028_send20", 20),
                       ("A2.declare1028_send0", 0),
                       ("A3.declare1028_send1", 1)):
        short = struct.pack("<I", 1) + bytes(max(0, sent - 4))[:max(0, sent - 4)]
        short = short[:sent]
        cases.append((name, [
            frag(TID, 0, short, DECLARED, False, FLAG_CONT, 0x310),
            frag(TID, 1, short, DECLARED, False, FLAG_CONT, 0x311),
            frag(TID, 2, short, DECLARED, False, FLAG_CONT, 0x312),
            frag(TID, 3, short, DECLARED, True, FLAG_FINAL, 0x313),
        ]))

    # A4: absurd declaration
    cases.append(("A4.declare0xffff_send20", [
        frag(TID, 0, bytes(20), 0xFFFF, False, FLAG_CONT, 0x320),
        frag(TID, 1, bytes(20), 0xFFFF, True, FLAG_FINAL, 0x321),
    ]))

    # A5: declaration disagrees with outer length (outer says 12+20)
    cases.append(("A5.declare_gt_outer", [
        frag(TID, 0, bytes(20), 0x0404, True, FLAG_FINAL, 0x330),
    ]))

    # B: many fragments, final bit only on the last
    many = [frag(TID + 1, i, bytes(20), DECLARED, i == 15,
                 FLAG_FINAL if i == 15 else FLAG_CONT, 0x340 + i)
            for i in range(16)]
    cases.append(("B0.fid0to15_fin_at_end", many))

    # B1: no final fragment at all (the console itself stops mid-message)
    cases.append(("B1.no_final", [
        frag(TID + 2, i, bytes(20), DECLARED, False, FLAG_CONT, 0x360 + i)
        for i in range(3)]))

    # C: order / repeat abuse
    cases.append(("C0.order_3_0_1_2", [
        frag(TID + 3, 3, bytes(20), DECLARED, False, FLAG_CONT, 0x370),
        frag(TID + 3, 0, bytes(20), DECLARED, False, FLAG_CONT, 0x371),
        frag(TID + 3, 1, bytes(20), DECLARED, False, FLAG_CONT, 0x372),
        frag(TID + 3, 2, bytes(20), DECLARED, True, FLAG_FINAL, 0x373),
    ]))
    cases.append(("C1.same_fid_x4", [
        frag(TID + 4, 0, bytes(20), DECLARED, i == 3,
             FLAG_FINAL if i == 3 else FLAG_CONT, 0x380 + i) for i in range(4)]))
    cases.append(("C2.final_then_more", [
        frag(TID + 5, 0, bytes(20), DECLARED, True, FLAG_FINAL, 0x390),
        frag(TID + 5, 1, bytes(20), DECLARED, False, FLAG_CONT, 0x391),
        frag(TID + 5, 2, bytes(20), DECLARED, True, FLAG_FINAL, 0x392),
    ]))

    # D: flags confusion (0x43 = cont+low bit, per doc "flags&3 => multi-fragment")
    cases.append(("D0.flags_0x43", [
        frag(TID + 6, 0, bytes(20), DECLARED, False, 0x43, 0x3A0),
        frag(TID + 6, 1, bytes(20), DECLARED, True, 0x41, 0x3A1),
    ]))
    return cases


def probe_state(sock: socket.socket, seq: int, timeout: float) -> str:
    """svc 4/0x05 liveness probe: returns '<error>/<len>B' or NOREPLY."""
    sock.sendto(build_generic(4, 0x05, b"", seq=seq), (PAD_IP, PAD_CMD_PORT))
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        p = parse_cmd(data)
        if not p or p.get("seq") != (seq & 0xFFFF):
            continue
        if p["packet_type"] == 2:
            sock.sendto(struct.pack("<HHHH", 3, p["query_type"], 8, seq & 0xFFFF),
                        (PAD_IP, PAD_CMD_PORT))
            return f"err={p.get('error')} {len(p.get('body', b''))}B"
    return "NOREPLY"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--gap", type=float, default=0.5)
    args = ap.parse_args()

    cases = build_cases()
    total = sum(len(v) for _, v in cases)
    print(f"# {len(cases)} cases / {total} datagrams, pad={PAD_IP}, "
          f"{'SEND' if args.send else 'dry-run'}")
    if not args.send:
        for name, dgrams in cases:
            print(f"  {name:26s} {len(dgrams):2d} datagrams "
                  f"(first {len(dgrams[0])} B: {dgrams[0].hex()})")
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
        jl = open(os.path.join(outdir, "frag.jsonl"), "w")
    seq = 0x400

    before = probe_state(sock, seq, args.timeout)
    seq += 1
    print(f"# baseline svc4/0x05 -> {before}")

    for name, dgrams in cases:
        pre = live.take()
        acks = replies = 0
        reply_info = ""
        for d in dgrams:
            sock.sendto(d, (PAD_IP, PAD_CMD_PORT))
            end = time.time() + 0.25
            while time.time() < end:
                try:
                    data, _ = sock.recvfrom(4096)
                except socket.timeout:
                    break
                p = parse_cmd(data)
                if not p:
                    continue
                if p["packet_type"] == 1:
                    acks += 1
                elif p["packet_type"] == 2:
                    replies += 1
                    ack = struct.pack("<HHHH", 3, p["query_type"], 8, p["seq"])
                    sock.sendto(ack, (PAD_IP, PAD_CMD_PORT))
                    reply_info = (f"svc={p.get('service')} m=0x{(p.get('method') or 0):02x} "
                                  f"err={p.get('error')} body={p.get('body', b'')[:32].hex()}")
        t_end = time.time() + 0.4
        while time.time() < t_end:
            drain(live_socks, live)
            time.sleep(0.02)
        post = live.take()
        after = probe_state(sock, seq, args.timeout)
        seq += 1
        rec = {"case": name, "acks": acks, "replies": replies, "reply": reply_info,
               "input": pre["input_pkts"] + post["input_pkts"],
               "resync": pre["resync_pkts"] + post["resync_pkts"],
               "state_before": before, "state_after": after, "t": time.time()}
        print(f"{name:26s} acks={acks:2d} replies={replies} in={rec['input']:3d} "
              f"rs={rec['resync']} state:{after:16s} {reply_info}")
        if outdir:
            jl.write(json.dumps(rec) + "\n")
            jl.flush()
        time.sleep(args.gap)

    if outdir:
        jl.close()
        print(f"# evidence in {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
