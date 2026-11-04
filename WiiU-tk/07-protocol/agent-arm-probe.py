#!/usr/bin/env python3
"""Causal probe for the pad's command channel: send candidate arm triggers from the
console's own source port 192.168.1.10:50023, ACK every pad reply, and record the pad's
state index (svc 4/0x05, retvals[current_state]) plus each reply's error code after every
step — so "which command arms the video path?" is measured, not eyeballed.

Reuses run/pad-state.py's packet builders + reply parser, so the wire format matches the
project's other tools byte for byte. Payloads are the exact bytes the decrypted console
session (out/evidence/truth/port50123.bin) carries; see research/agents/command-causal-map.md
for the derivation.

Plans (each is an ordered list of (service, method, payload) steps):
  arm      svc 0/0x00, 4/0x04, 5/0x02(102 zero bytes), 5/0x06   [MEASURED 12->0]
  enable   svc 5/0x08 payload 01                                [docs: 00 disables video]
  trio     svc 0/0x12(count=779), 4/0x21(32 zeros), 4/0x1a flags 0x42 [state-push end]
  full     trio, then arm                                       [console order]

SAFE BY DEFAULT: with no --run the tool only prints each step's exact wire bytes and
exits — no socket is created, nothing is transmitted. --run is the only thing that
transmits, it is strictly unicast to the pad, and it rate-limits every step.

Usage:
  run/agent-arm-probe.py                  # dry run: show the arm plan's exact bytes
  run/agent-arm-probe.py --plan trio      # dry run of the state-push-end trio
  sudo run/agent-arm-probe.py --run --plan full --interval 0.4   # live, console order
  sudo run/agent-arm-probe.py --run --steps 5/0x08/01 5/0x02/z102
"""
import argparse
import importlib.util
import os
import socket
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- reuse the packet builders + reply parser from the state oracle -------------
_spec = importlib.util.spec_from_file_location(
    "pad_state", os.path.join(ROOT, "run/pad-state.py"))
pad_state = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pad_state)
build_generic = pad_state.build_generic
parse_reply = pad_state.parse_reply
RETVALS = pad_state.RETVALS

CONSOLE_IP, PAD_IP = "192.168.1.10", "192.168.1.11"
CONSOLE_CMD, PAD_CMD = 50023, 50123

# Canonical payloads lifted byte-for-byte from out/evidence/truth/port50123.bin
SV502 = b"\x00" * 102                          # svc 5/0x02: UIC cmd 0x0c config push (all zero)
SV012 = b"\x00\x00\x03\x0b" + b"\x00" * 28     # svc 0/0x12: BE u32 0x30b = 779 (= #blobs) + 28 zero
SV421 = b"\x00" * 32                           # svc 4/0x21: undocumented, 32 zero bytes

# plan -> ordered [(label, service, method, payload, flags)]
PLANS = {
    "arm": [
        ("lvc-ver",  0, 0x00, b"",        0x40),
        ("version",  4, 0x04, b"",        0x40),
        ("uic-cfg",  5, 0x02, SV502,      0x40),
        ("uic-eep",  5, 0x06, b"",        0x40),
    ],
    "enable": [
        ("vid-en",   5, 0x08, b"\x01",    0x40),
    ],
    "trio": [
        ("blob-end", 0, 0x12, SV012,      0x40),
        ("unk-421",  4, 0x21, SV421,      0x40),
        ("shutdown", 4, 0x1a, b"",        0x42),   # console sends flags 0x42 here
    ],
    "full": None,   # built below = trio + arm (console order)
}
PLANS["full"] = PLANS["trio"] + PLANS["arm"]


def parse_step(tok):
    """Parse 'svc/method/hex' or 'svc/method/z<N>' into (service, method, payload, flags)."""
    parts = tok.split("/")
    if len(parts) not in (2, 3):
        raise SystemExit("bad step %r: want svc/method[/hex or /z<N>]" % tok)
    try:
        svc = int(parts[0], 0)
        meth = int(parts[1], 0)
    except ValueError:
        raise SystemExit("bad step %r: svc/method must be ints" % tok)
    payload, flags = b"", 0x40
    if len(parts) == 3 and parts[2] != "":
        if parts[2].startswith("z"):
            try:
                payload = b"\x00" * int(parts[2][1:])
            except ValueError:
                raise SystemExit("bad zero-pad in %r: want z<N>" % tok)
        else:
            try:
                payload = bytes.fromhex(parts[2])
            except ValueError:
                raise SystemExit("bad hex payload in %r" % tok)
    return ("step %s/%#04x" % (svc, meth), svc, meth, payload, flags)


def build_steps(args):
    if args.steps:
        return [parse_step(t) for t in args.steps]
    return list(PLANS[args.plan])


def hexdump(b, cap=64):
    h = b.hex()
    return h[:cap] + ("..." if len(h) > cap else "")


def describe_state(body):
    if len(body) >= 1:
        idx = body[0]
        raw = RETVALS.index(idx) if idx in RETVALS else None
        return "state index %d%s" % (idx, "" if raw is None else " (=retvals[%d]=%d)" % (raw, idx))
    return "no body"


def send_collect(sock, pad, service, method, payload, flags, seq, timeout):
    """Send one generic command; return (acked, reply_dict_or_None). ACKs the type-2 reply."""
    pkt = build_generic(service, method, payload, seq=seq, flags=flags)
    try:
        sock.sendto(pkt, (pad, PAD_CMD))
    except OSError as exc:
        return False, {"error": -1, "note": "send: %s" % exc, "body": b""}
    deadline = time.time() + timeout
    acked = False
    while time.time() < deadline:
        sock.settimeout(max(0.02, deadline - time.time()))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            break
        r = parse_reply(data)
        if not r or r["seq"] != seq:
            continue
        if r["packet_type"] == 1:
            acked = True
            continue
        if r["packet_type"] == 2:
            sock.sendto(struct.pack("<HHHH", 3, 0, 0, seq), (pad, PAD_CMD))
            r["acked_query"] = acked
            return True, r
    return acked, None


def poll_state(sock, pad, seq, timeout):
    _, r = send_collect(sock, pad, 4, 0x05, b"", 0x40, seq, timeout)
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="store_true",
                    help="actually transmit (default is dry-run: print bytes, exit)")
    ap.add_argument("--pad", default=PAD_IP)
    ap.add_argument("--plan", default="arm", choices=sorted(PLANS))
    ap.add_argument("--steps", nargs="*", metavar="svc/meth/hex",
                    help="override the plan: e.g. '5/0x08/01' or '5/0x02/z102'")
    ap.add_argument("--interval", type=float, default=0.4,
                    help="rate limit: seconds between steps (>=0.05)")
    ap.add_argument("--timeout", type=float, default=1.2,
                    help="per-command reply timeout")
    ap.add_argument("--repeat", type=int, default=1,
                    help="repeat the whole sequence N times (idempotent)")
    ap.add_argument("--no-state", action="store_true",
                    help="skip the svc 4/0x05 state poll after each step")
    args = ap.parse_args()

    steps = build_steps(args)
    interval = max(args.interval, 0.05)

    if not args.run:
        print("DRY RUN (add --run to transmit to %s:%d)\nplan: %s, %d step(s)\n"
              % (args.pad, PAD_CMD, args.plan, len(steps)))
        print("  %-3s %-9s %-9s %-6s %-5s %s" % ("#", "service", "method", "flags", "bytes", "payload"))
        for i, (label, svc, meth, payload, flags) in enumerate(steps):
            pkt = build_generic(svc, meth, payload, seq=0x0100 + i, flags=flags)
            print("  %-3d %-9s %-9s 0x%02x %-5d %s" %
                  (i + 1, "svc %d" % svc, "0x%02x" % meth, flags, len(payload),
                   hexdump(payload) if payload else "(none)"))
            print("       wire: %s" % pkt.hex())
        return 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((CONSOLE_IP, CONSOLE_CMD))
        where = "%s:%d" % (CONSOLE_IP, CONSOLE_CMD)
    except OSError as e:
        sock.bind((CONSOLE_IP, 0))
        where = "%s:%d (ephemeral — port %d busy; pad replies may be split between sockets)"
        where = where % (CONSOLE_IP, sock.getsockname()[1], CONSOLE_CMD)
        print("[!] %s" % e)
    print("from %s -> %s:%d  plan=%s  interval=%.2fs\n"
          % (where, args.pad, PAD_CMD, args.plan, interval))

    seq = 0x0100
    state = None
    print("  %-3s %-12s %-8s %-6s %-8s %-10s %s" %
          ("#", "command", "flags", "ack", "replyErr", "replyB", "state after"))
    for rep in range(args.repeat):
        for i, (label, svc, meth, payload, flags) in enumerate(steps):
            seq = (seq + 1) & 0xFFFF
            acked, r = send_collect(sock, args.pad, svc, meth, payload, flags, seq,
                                    args.timeout)
            name = "%d/0x%02x" % (svc, meth)
            if not r:
                print("  %-3d %-12s 0x%02x %-6s %-8s %-10s (no reply)"
                      % (rep * len(steps) + i + 1, name, flags,
                         "Y" if acked else "n", "-", "-"))
            else:
                body = r.get("body") or b""
                print("  %-3d %-12s 0x%02x %-6s %-8d %-10d %s"
                      % (rep * len(steps) + i + 1, name, flags,
                         "Y" if r.get("acked_query") else "n",
                         r["error"], len(body),
                         describe_state(body) if svc == 4 and meth == 0x05 else ""))
            if not args.no_state and not (svc == 4 and meth == 0x05):
                seq = (seq + 1) & 0xFFFF
                sr = poll_state(sock, args.pad, seq, args.timeout)
                if sr and sr.get("body"):
                    state = sr["body"][0]
                print("       -> state: %s" % (describe_state(b"%c" % state)
                                               if state is not None else "?"))
            time.sleep(interval)
    print("\ndone. final state index: %s" % (state if state is not None else "?"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
