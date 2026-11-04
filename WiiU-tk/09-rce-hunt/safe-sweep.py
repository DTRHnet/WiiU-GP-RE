#!/usr/bin/env python3
"""Safe (non-destructive) command-plane sweep: E1 + E2 from 02-attack-surface.md.

Hypothesis under test: the pad's cmd handlers treat a 1-byte selector/index as
trusted and index a table with it, so values outside the documented range either
(a) return memory the sender should not see (an OOB read leaked in the reply), or
(b) wedge the handler (no reply / reboot), which is the observable failure mode.

Both outcomes are informative and neither touches flash:
  svc 0/0x0a  "Gets version from EEPROM"  documented payload 0..4
  svc 0/0x09  "Returns hardcoded values"  documented payload 1 byte
  svc 3/0x03..0x05  wl stats, 1-byte selector
  svc 4/0x09,0x0b,0x19 / svc 5/0x00,0x0b   no-arg readers

Observability (no eyes on the panel), per 02-attack-surface.md §6:
  O1 pad input rate on 50022 (normal ~163/s; 0 = dead/off-session)
  O6 resync rate, pad 50110 -> our 50010
  O14 reply body/length changes -- the actual leak signal
  deadman: stop the run on N consecutive anonymous failures

Usage:
  research/rce-hunt/safe-sweep.py                       # dry run: list cases
  sudo research/rce-hunt/safe-sweep.py --send --out out/evidence/rce-sweep-$(date +%H%M)
  research/rce-hunt/safe-sweep.py --send --max-index 64 # short run
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

_spec = _ilu.spec_from_file_location(
    "probe_readonly", os.path.join(_HERE, "probe-readonly.py"))
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


def build_cases(max_index: int) -> list[tuple[str, int, int, bytes]]:
    cases: list[tuple[str, int, int, bytes]] = []
    # E1: the documented 0..4 index, then the rest of the byte space
    for idx in range(0, max_index + 1):
        cases.append((f"eeprom_ver.idx{idx:02x}", 0, 0x0A, bytes([idx])))
    # E2: other 1-byte selectors
    for sel in range(0, min(max_index, 15) + 1):
        cases.append((f"svc0_m09.sel{sel:02x}", 0, 0x09, bytes([sel])))
        cases.append((f"wl_phy.sel{sel:02x}", 3, 0x03, bytes([sel])))
        cases.append((f"wl_pkt.sel{sel:02x}", 3, 0x04, bytes([sel])))
        cases.append((f"wl_wmm.sel{sel:02x}", 3, 0x05, bytes([sel])))
    # E2b: no-arg readers (repeat them, so a state change over the run is visible)
    for name, svc, meth in [("svc4_m09", 4, 0x09), ("svc4_m0b", 4, 0x0B),
                            ("svc4_m19", 4, 0x19), ("svc5_m00", 5, 0x00),
                            ("svc5_m0b", 5, 0x0B), ("state", 4, 0x05),
                            ("bright", 5, 0x15)]:
        cases.append((name, svc, meth, b""))
    return cases


def one(sock: socket.socket, name: str, svc: int, meth: int, payload: bytes,
        seq: int, timeout: float) -> dict:
    pkt = build_generic(svc, meth, payload, seq=seq)
    t0 = time.time()
    sock.sendto(pkt, (PAD_IP, PAD_CMD_PORT))
    acks, reply = 0, None
    deadline = t0 + timeout
    while time.time() < deadline:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        p = parse_cmd(data)
        if not p or p.get("seq") != (seq & 0xFFFF):
            continue
        if p["packet_type"] == 1:
            acks += 1
        elif p["packet_type"] == 2:
            reply = p
            break
    rec = {"case": name, "svc": svc, "method": meth, "payload": payload.hex(),
           "sent": pkt.hex(), "acks": acks,
           "result": "OK" if reply else ("NOACK" if acks else "NOREPLY"),
           "dt_ms": round((time.time() - t0) * 1000, 2)}
    if reply:
        body = reply.get("body", b"")
        rec.update({"error": reply.get("error"), "body_len": len(body),
                    "body": body.hex(), "rsp_svc": reply.get("service"),
                    "rsp_method": reply.get("method")})
        ack = struct.pack("<HHHH", 3, reply["query_type"], 8, seq & 0xFFFF)
        sock.sendto(ack, (PAD_IP, PAD_CMD_PORT))
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-index", type=int, default=255)
    ap.add_argument("--timeout", type=float, default=1.2)
    ap.add_argument("--deadman", type=int, default=10,
                    help="abort after N consecutive failed cases")
    ap.add_argument("--gap", type=float, default=0.06)
    args = ap.parse_args()

    cases = build_cases(args.max_index)
    print(f"# {len(cases)} cases, pad={PAD_IP}, "
          f"{'SEND' if args.send else 'dry-run'}")
    if not args.send:
        for n, s, m, p in cases[:12]:
            print(f"  {n:22s} svc={s} meth=0x{m:02x} payload={p.hex() or '-'}")
        print(f"  ... ({len(cases)} total)")
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
        jl = open(os.path.join(outdir, "sweep.jsonl"), "w")

    baseline: dict[tuple[int, int], list] = {}
    anomalies = []
    fails_in_row = 0
    seq = 0x2000
    t_start = time.time()
    stopped = None

    for name, svc, meth, payload in cases:
        pre = live.take()
        t_after = time.time() + 0.12
        while time.time() < t_after:
            drain(live_socks, live)
            time.sleep(0.02)
        mid = live.take()

        seq = (seq + 1) & 0xFFFF
        rec = one(sock, name, svc, meth, payload, seq, args.timeout)

        post = live.take()
        rec["input_rate"] = mid["input_pkts"] + post["input_pkts"]
        rec["resync"] = mid["resync_pkts"] + post["resync_pkts"]
        rec["t"] = round(time.time() - t_start, 2)

        ok = rec["result"] == "OK"
        fails_in_row = 0 if ok else fails_in_row + 1

        # anomaly detection: length or content change against the first sighting
        key = (svc, meth)
        if ok:
            sig = (rec["body_len"], rec["body"][:64])
            if key not in baseline:
                baseline[key] = [sig, rec["payload"]]
            elif sig != baseline[key][0]:
                anomalies.append({
                    "case": name, "kind": "BODY_CHANGE",
                    "first": baseline[key][0], "now": sig})
                rec["anomaly"] = "BODY_CHANGE"
        if rec.get("rsp_svc") is not None and (rec["rsp_svc"], rec["rsp_method"]) != key:
            anomalies.append({"case": name, "kind": "MISMATCHED_REPLY",
                              "got": (rec["rsp_svc"], rec["rsp_method"]), "sent": key})
            rec["anomaly"] = "MISMATCHED_REPLY"

        err = rec.get("error")
        if ok and err not in (0, 9004):
            anomalies.append({"case": name, "kind": "NEW_ERROR", "error": err})
            rec["anomaly"] = "NEW_ERROR"

        flag = ("  <-- " + rec["anomaly"]) if rec.get("anomaly") else ""
        print(f"{rec['t']:7.2f}s {name:22s} {rec['result']:7s} "
              f"acks={rec['acks']} err={err if err is not None else '-':>4} "
              f"body={rec.get('body_len', 0):>3}B in={rec['input_rate']:>3} "
              f"rs={rec['resync']}{flag}  {rec.get('body','')[:48]}")
        if outdir:
            jl.write(json.dumps(rec) + "\n")
            jl.flush()

        if fails_in_row >= args.deadman:
            stopped = f"deadman: {fails_in_row} consecutive failures at {name}"
            break
        time.sleep(args.gap)

    print()
    if stopped:
        print(f"# STOPPED: {stopped}")
    print(f"# {len(anomalies)} anomalies")
    for a in anomalies[:40]:
        print(f"  {a}")
    if outdir:
        with open(os.path.join(outdir, "anomalies.json"), "w") as fh:
            json.dump({"when": time.ctime(), "stopped": stopped,
                       "anomalies": anomalies}, fh, indent=1)
        jl.close()
        print(f"# evidence in {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
