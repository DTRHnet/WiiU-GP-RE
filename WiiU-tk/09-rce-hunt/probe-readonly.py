#!/usr/bin/env python3
"""Read-only command-plane enumerator for the gamepad RCE hunt.

Sends only the *documented read* methods of libdrc's cmd protocol
(`research/libdrc/web/docs/re/sc-cmd.rst`) to the GamePad and records exactly what
comes back. No flash writes, no mode reboots, no malformed packets: this is the
recon instrument, not the fuzzer.

Why it matters for the hunt:
  * it maps which service/method handlers exist in the pad firmware and reply,
  * svc 5/0x06 alone returns 772 bytes = UIC firmware version + 768 bytes of UIC
    EEPROM -- an attacker-controlled-peer information leak we get for free,
  * the reply bodies give us the exact reply sizes a mutator should target,
  * the per-query liveness columns give us the crash oracle baseline.

Wire format (little-endian outside the generic header, which is mixed):
  CmdHeader      le16 packet_type | le16 query_type | le16 payload_size | le16 seq
  GenericCmdHdr  7e | 01 | tid_hi | tid_lo<<4|final<<3|fid_hi | fid_lo |
                 flags | service | method | be16 error | be16 payload_size

State machine: we send type 0, pad ACKs (type 1), pad replies (type 2), we ACK
(type 3). Retransmit on timeout; the pad retransmits too, so duplicates are normal.

Usage:
  research/rce-hunt/probe-readonly.py                  # dry run: hexdump the packets
  sudo research/rce-hunt/probe-readonly.py --send      # ask the live pad
  sudo research/rce-hunt/probe-readonly.py --send --out out/evidence/rce-ro-$(date +%H%M)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass, field

CONSOLE_IP = "192.168.1.10"
PAD_IP = "192.168.1.11"
CONSOLE_CMD_PORT = 50023
PAD_CMD_PORT = 50123
PAD_INPUT_PORT = 50022          # we listen: pad input (liveness)
CONSOLE_MSG_PORT = 50010        # we listen: pad broadcast msg / resync requests
PAD_MAC = "40:d2:8a:17:e2:09"

# name, service, method, payload, documented reply size (None = unknown)
QUERIES = [
    ("lvc.version",            0, 0x00, b"",     8),
    ("lvc.hardcoded",          0, 0x09, b"\x00", None),
    ("lvc.eeprom_ver.langbank",0, 0x0A, b"\x00", 4),
    ("lvc.eeprom_ver.remocon", 0, 0x0A, b"\x01", 4),
    ("lvc.eeprom_ver.service", 0, 0x0A, b"\x02", 4),
    ("lvc.eeprom_ver.screen1", 0, 0x0A, b"\x03", 4),
    ("lvc.eeprom_ver.screen2", 0, 0x0A, b"\x04", 4),
    ("wifi.config",            1, 0x05, b"",   113),
    ("wifi.wowl_key",          1, 0x08, b"",    16),
    ("dev.noop",               2, 0x00, b"",     0),
    ("dev.id_and_cert",        2, 0x0C, b"",   272),
    ("wl.phy_stats",           3, 0x03, b"\x00", 13),
    ("wl.pkt_stats",           3, 0x04, b"\x00",152),
    ("wl.wmm_stats",           3, 0x05, b"\x00",448),
    ("wl.rssi",                3, 0x06, b"",     2),
    ("sys.version_info",       4, 0x04, b"",    28),
    ("sys.state_index",        4, 0x05, b"",     1),
    ("sys.unknown_09",         4, 0x09, b"",     4),
    ("sys.unknown_0b",         4, 0x0B, b"",     1),
    ("sys.unknown_19",         4, 0x19, b"",    12),
    ("uic.table_f8d0",         5, 0x00, b"",     6),
    ("uic.fw_and_eeprom",      5, 0x06, b"",   772),
    ("uic.unknown_0b",         5, 0x0B, b"",     1),
    ("lcd.brightness",         5, 0x15, b"",     1),
    ("lcd.params",             5, 0x1A, b"",    13),
]

RETVALS = [0, 10, 4, 5, 6, 1, 2, 3, 9, 7, 8, 11]


def build_generic(service: int, method: int, payload: bytes = b"", seq: int = 0,
                  query_type: int = 0, tid: int = 0, fid: int = 0,
                  final: bool = True, flags: int = 0x40) -> bytes:
    """Outer CmdHeader + 12-byte generic header + payload (console -> pad query)."""
    outer = struct.pack("<HHHH", 0, query_type, 12 + len(payload), seq & 0xFFFF)
    gen = bytearray(12)
    gen[0] = 0x7E
    gen[1] = 0x01
    gen[2] = (tid >> 8) & 0xFF
    gen[3] = ((tid << 4) & 0xF0) | (0x08 if final else 0x00) | ((fid >> 8) & 0x07)
    gen[4] = fid & 0xFF
    gen[5] = flags
    gen[6] = service
    gen[7] = method
    gen[8:10] = struct.pack(">H", 0)              # error code, big-endian
    gen[10:12] = struct.pack(">H", len(payload))  # payload size, big-endian
    return outer + bytes(gen) + payload


def parse_cmd(pkt: bytes) -> dict | None:
    if len(pkt) < 8:
        return None
    ptype, qtype, plen, seq = struct.unpack_from("<HHHH", pkt, 0)
    out = {"packet_type": ptype, "query_type": qtype, "declared_payload": plen,
           "seq": seq, "len": len(pkt)}
    if len(pkt) >= 20 and pkt[8] == 0x7E:
        tid = (pkt[10] << 8) | (pkt[11] >> 4)
        fid = ((pkt[11] & 0x07) << 8) | pkt[12]
        out.update({
            "magic": pkt[8], "version": pkt[9], "tid": tid, "fid": fid,
            "flags": pkt[13], "service": pkt[14], "method": pkt[15],
            "error": struct.unpack_from(">H", pkt, 16)[0],
            "body_len": struct.unpack_from(">H", pkt, 18)[0],
            "body": pkt[20:20 + struct.unpack_from(">H", pkt, 18)[0]],
        })
    return out


def explain(name: str, body: bytes) -> str:
    try:
        if name == "sys.state_index" and body:
            idx = body[0]
            where = RETVALS.index(idx) if idx in RETVALS else -1
            return f"state index {idx} (retvals[{where}])"
        if name == "wifi.config" and len(body) >= 113:
            auth, enc = body[13], body[14]
            sl = body[47]
            ssid = body[15:15 + sl]
            pl = body[112]
            psk = body[48:48 + pl]
            return f"ssid={ssid!r} auth={auth} enc={enc} psk_len={pl} psk={psk[:16].hex()}..."
        if name == "sys.version_info":
            return "raw=" + body.hex()
        if name.startswith("lvc.version") and len(body) >= 8:
            run, inst = struct.unpack_from("<II", body, 0)
            return f"running={run} installed={inst}"
        if name.startswith("lvc.eeprom_ver") and len(body) >= 4:
            return "u32=" + str(struct.unpack_from("<I", body, 0)[0])
        if name == "uic.fw_and_eeprom" and len(body) >= 772:
            fw = struct.unpack_from("<I", body, 0)[0]
            eeprom = body[4:772]
            nz = sum(1 for b in eeprom if b)
            return (f"UIC fw version=0x{fw:08x} ({fw}); EEPROM dump 768B, "
                    f"{nz} non-zero bytes; first 32: {eeprom[:32].hex()}")
        if name == "dev.id_and_cert" and len(body) >= 272:
            return f"device_id={body[0:16].hex()} cert[0:32]={body[16:48].hex()}"
        if name == "lcd.brightness" and body:
            return f"brightness={body[0]}"
        if name == "wl.rssi" and len(body) >= 2:
            return f"rssi antennas={body[0]},{body[1]}"
    except Exception as exc:                                    # noqa: BLE001
        return f"(decode error: {exc}) raw={body[:32].hex()}"
    return f"{len(body)}B {body[:48].hex()}"


@dataclass
class Liveness:
    """Passive counters sampled from the pad's own uplink."""
    input_pkts: int = 0
    resync_pkts: int = 0
    other: dict[str, int] = field(default_factory=dict)

    def take(self) -> dict:
        snap = {"input_pkts": self.input_pkts, "resync_pkts": self.resync_pkts}
        self.input_pkts = 0
        self.resync_pkts = 0
        return snap


def open_liveness_sockets() -> tuple[list[socket.socket], Liveness]:
    live = Liveness()
    socks = []
    for port in (PAD_INPUT_PORT, CONSOLE_MSG_PORT):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((CONSOLE_IP, port))
        except OSError as exc:
            print(f"  ! liveness listener on {port} failed: {exc}", file=sys.stderr)
            s.close()
            continue
        s.setblocking(False)
        socks.append(s)
    return socks, live


def drain(socks: list[socket.socket], live: Liveness) -> None:
    for s in socks:
        while True:
            try:
                data, _addr = s.recvfrom(4096)
            except BlockingIOError:
                break
            except OSError:
                break
            port = s.getsockname()[1]
            if port == PAD_INPUT_PORT:
                live.input_pkts += 1
            else:
                # the pad's resync request is a 4-byte 01 00 00 00 from src 50110
                if data[:4] == b"\x01\x00\x00\x00":
                    live.resync_pkts += 1
                live.other["msg"] = live.other.get("msg", 0) + 1


def port_owner_warning() -> bool:
    """Detect a competing binder on 50023 the way BOOT-AND-MODES.md 5.1 describes."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((CONSOLE_IP, CONSOLE_CMD_PORT))
        probe.close()
        return True
    except OSError as exc:
        print(f"ERROR: cannot bind {CONSOLE_IP}:{CONSOLE_CMD_PORT}: {exc}\n"
              f"       Another process owns the cmd port (drc-down.sh first).",
              file=sys.stderr)
        return False


def send_query(sock: socket.socket, name: str, svc: int, meth: int, payload: bytes,
               seq: int, timeout: float, retries: int = 3) -> dict:
    pkt = build_generic(svc, meth, payload, seq=seq)
    record = {"query": name, "service": svc, "method": meth,
              "sent_hex": pkt.hex(), "t0": time.time(),
              "acks": 0, "replies": [], "result": "NOREPLY"}
    sock.sendto(pkt, (PAD_IP, PAD_CMD_PORT))
    got_reply = False
    deadline = time.time() + timeout
    last_send = time.time()
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            if not got_reply and time.time() - last_send > timeout / 2 and retries > 0:
                sock.sendto(pkt, (PAD_IP, PAD_CMD_PORT))
                retries -= 1
                last_send = time.time()
            continue
        parsed = parse_cmd(data)
        if not parsed:
            continue
        if parsed.get("seq") != seq & 0xFFFF and parsed["packet_type"] != 1:
            continue
        if parsed["packet_type"] == 1:
            record["acks"] += 1
        elif parsed["packet_type"] == 2:
            got_reply = True
            record["replies"].append({
                "rx_hex": data.hex(),
                "error": parsed.get("error"),
                "body_len": parsed.get("body_len"),
                "service": parsed.get("service"),
                "method": parsed.get("method"),
                "body_hex": parsed.get("body", b"").hex(),
                "explain": explain(name, parsed.get("body", b"")),
                "dt_ms": round((time.time() - record["t0"]) * 1000, 2),
            })
            # ACK the reply (type 3) so the pad stops retransmitting
            ack = struct.pack("<HHHH", 3, parsed["query_type"], 8, seq & 0xFFFF)
            sock.sendto(ack, (PAD_IP, PAD_CMD_PORT))
            record["result"] = "OK"
            break
    return record


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--send", action="store_true", help="actually transmit (default: dry run)")
    ap.add_argument("--out", default=None, help="evidence directory (default: none)")
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--only", default=None, help="comma/prefix filter, e.g. 'uic.,lcd.'")
    args = ap.parse_args()

    queries = QUERIES
    if args.only:
        pats = [p.strip() for p in args.only.split(",") if p.strip()]
        queries = [q for q in QUERIES if any(q[0].startswith(p) for p in pats)]
    print(f"# {len(queries)} read-only queries; pad={PAD_IP} mode="
          f"{'SEND' if args.send else 'dry-run'}")

    if not args.send:
        for name, svc, meth, payload, _ in queries:
            pkt = build_generic(svc, meth, payload, seq=1)
            print(f"{name:26s} svc={svc} meth=0x{meth:02x} len={len(pkt):3d}  {pkt.hex()}")
        return 0

    if not port_owner_warning():
        return 2

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((CONSOLE_IP, CONSOLE_CMD_PORT))
    sock.settimeout(0.05)
    live_socks, live = open_liveness_sockets()

    # baseline liveness over 1 s before we touch anything
    t_end = time.time() + 1.0
    while time.time() < t_end:
        drain(live_socks, live)
        time.sleep(0.02)
    baseline = live.take()
    print(f"# baseline: input={baseline['input_pkts']}/s resync={baseline['resync_pkts']}/s")

    outdir = args.out
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    results = []
    seq = 0x100
    for name, svc, meth, payload, expect in queries:
        seq = (seq + 1) & 0xFFFF
        pre = live.take()
        rec = send_query(sock, name, svc, meth, payload, seq, args.timeout)
        t_after = time.time() + 0.3
        while time.time() < t_after:
            drain(live_socks, live)
            time.sleep(0.02)
        post = live.take()
        rec["expect_reply_bytes"] = expect
        rec["input_rate_before/after"] = [pre["input_pkts"], post["input_pkts"]]
        rec["resync_before/after"] = [pre["resync_pkts"], post["resync_pkts"]]
        results.append(rec)

        body = rec["replies"][0] if rec["replies"] else None
        got = len(bytes.fromhex(body["body_hex"])) if body else 0
        err = f"error={body['error']}" if body else "no reply"
        size_note = ""
        if expect is not None and body:
            size_note = "  size-match" if got == expect else f"  !expected {expect}"
        print(f"{name:26s} {rec['result']:8s} acks={rec['acks']} "
              f"{err} body={got}B{size_note} "
              f"input {pre['input_pkts']}->{post['input_pkts']} "
              f"resync {pre['resync_pkts']}->{post['resync_pkts']}")
        if body:
            print(f"    {body['explain']}")
        if outdir:
            with open(os.path.join(outdir, f"{name}.bin"), "wb") as fh:
                fh.write(bytes.fromhex(rec["sent_hex"]))
            if body:
                with open(os.path.join(outdir, f"{name}.reply.bin"), "wb") as fh:
                    fh.write(bytes.fromhex(body["rx_hex"]))
        time.sleep(0.05)

    if outdir:
        with open(os.path.join(outdir, "results.json"), "w") as fh:
            json.dump({"pad": PAD_IP, "when": time.ctime(),
                       "baseline": baseline, "results": results}, fh, indent=1)
        print(f"# evidence in {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
