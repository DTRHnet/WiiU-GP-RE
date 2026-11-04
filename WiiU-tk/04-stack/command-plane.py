#!/usr/bin/env python3
"""
Drive the pad's command plane the way a console does, and watch the pad's state
index while you do it.

Why: BOOT-AND-MODES.md §7 isolates two command-plane leads that no previous test
actually executed - (a) the UVC/UAC display gate, sequenced during an open
session with byte[0] flipping to 1 after the first validated reply, and (b) the
console's dominant traffic, a 4-fragment state message to svc 0 / method 0x11
(svc 0, tid 0x10b, u32 index running 1..778 with no gaps, strict M M M S
grouping, ~29 fragments/s for the first 28 s of a session). Round 11o replayed
three fragments with no final fragment, from an ephemeral port, so it never
delivered a complete message.

This tool owns 192.168.1.10:50023 for the whole run, so the pad's replies and its
keyframe requests land in one socket, and it ACKs every reply (type 3) as the
console does. Its success signal is not the resync rate: it polls svc 4 / 0x05
(the documented state oracle, retvals[current_state]) and prints a state
timeline, so "did the pad change state?" is measured, not eyeballed.

Usage (with the media replayer running separately):
  sudo run/command-plane.py --mode state  --seconds 60
  sudo run/command-plane.py --mode blobs  --seconds 60
  sudo run/command-plane.py --mode uvcuac --seconds 60
  sudo run/command-plane.py --mode full   --seconds 120     # time+generics+blobs+uvcuac
"""
import argparse
import collections
import importlib.util
import os
import socket
import struct
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRUTH = os.path.join(ROOT, "out/evidence/truth")
CONSOLE_IP, PAD_IP = "192.168.1.10", "192.168.1.11"
CONSOLE_CMD, PAD_CMD = 50023, 50123

# reuse the packet builders from the state oracle so both tools agree on format
_spec = importlib.util.spec_from_file_location(
    "pad_state", os.path.join(ROOT, "run/pad-state.py"))
pad_state = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pad_state)
build_generic = pad_state.build_generic
parse_reply = pad_state.parse_reply
RETVALS = pad_state.RETVALS


def load_truth(name):
    path = os.path.join(TRUTH, name)
    if not os.path.exists(path):
        return []
    data = open(path, "rb").read()
    recs, off = [], 0
    while off + 20 <= len(data):
        ts, _s, _d, ln = struct.unpack(">d4s4sI", data[off:off + 20])
        off += 20
        recs.append((ts, data[off:off + ln]))
        off += ln
    return recs


class Plane:
    def __init__(self, log):
        self.log = log
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((CONSOLE_IP, CONSOLE_CMD))
        self.sock.settimeout(0.2)
        self.seq = 200
        self.state = None
        self.gate = "init"
        self.state_changes = []
        self.replies = collections.Counter()
        self.uvcuac_gate_seen = False
        self.uvcuac_byte0 = 0
        self.stop = False

    def say(self, msg):
        line = "[%8.3f] %s" % (time.time() % 10000, msg)
        print(line, flush=True)
        self.log.write(line + "\n")
        self.log.flush()

    def next_seq(self):
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def send(self, pkt):
        try:
            self.sock.sendto(pkt, (PAD_IP, PAD_CMD))
            return True
        except OSError as exc:
            self.say("send error: %s" % exc)
            return False

    def query(self, service, method, payload=b"", timeout=1.0, label=""):
        seq = self.next_seq()
        pkt = build_generic(service, method, payload, seq=seq)
        if not self.send(pkt):
            return None
        deadline = time.time() + timeout
        while time.time() < deadline and not self.stop:
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            r = parse_reply(data)
            if not r:
                continue
            self.note_reply(r, label)
            if r["seq"] == seq and r["packet_type"] == 2:
                ack = struct.pack("<HHHH", 3, 0, 0, seq)
                self.send(ack)
                return r
        return None

    def note_reply(self, r, label):
        if r["packet_type"] == 2 and r["error"] != 0:
            self.say("reply svc %d/0x%02x error %d" %
                     (r["service"], r["method"], r["error"]))
        self.replies[(r["packet_type"], r["service"], r["method"])] += 1
        if r["packet_type"] == 2 and label == "uvcuac":
            body = r.get("body") or b""
            if len(body) >= 16 and not self.uvcuac_gate_seen:
                self.uvcuac_gate_seen = True
                self.say("UVC/UAC reply validated (%dB) -> request byte[0] becomes 1 "
                         "(console behaviour)" % len(body))
            ack = struct.pack("<HHHH", 3, 0, 0, r["seq"])
            self.send(ack)

    # ---------------------------------------------------------------- probes
    def read_gate(self):
        """svc 5/0x15 (brightness read) is the sharpest 'is the video/AV manager
        armed' oracle: it returns error 9004 until the pad's managers are up, and
        err=0 once they are (measured in research/rce-hunt/10-tv-remote-live.md
        sec.6/sec.8). Logged on change so we can time the arming exactly."""
        r = self.query(5, 0x15, timeout=0.8)
        err = None
        if r is not None:
            err = r["error"]
        elif not self.replies:
            err = "noreply"
        if err != self.gate:
            self.say("GATE 5/0x15 -> %s%s" % (err,
                     "" if r is None or not r.get("body")
                     else " body=%s" % r["body"].hex()))
            self.gate = err
        return r

    def read_state(self):
        r = self.query(4, 0x05, timeout=1.0)
        if not r or not r["body"]:
            return None
        idx = r["body"][0]
        if idx != self.state:
            self.state_changes.append((time.time(), self.state, idx))
            self.say("STATE %s -> %d  (retvals[%d]=%d)"
                     % ("?" if self.state is None else self.state, idx,
                        RETVALS.index(idx) if idx in RETVALS else -1, idx))
            self.state = idx
        return idx

    def pump(self, seconds):
        """Receive + ACK everything for `seconds`, without sending queries."""
        end = time.time() + seconds
        n = 0
        while time.time() < end and not self.stop:
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            r = parse_reply(data)
            if not r:
                continue
            n += 1
            self.replies[(r["packet_type"], r["service"], r["method"])] += 1
            if r["packet_type"] == 2:
                self.send(struct.pack("<HHHH", 3, 0, 0, r["seq"]))
        return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="state",
                    choices=["state", "blobs", "uvcuac", "full", "arm", "arma",
                             "console"])
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--state-period", type=float, default=2.0)
    ap.add_argument("--quiet-replies", action="store_true")
    # Hypothesis: the pad's armed state expires, and the console keeps it alive with
    # continuous arm traffic (our client arms only once per rejoin, ~80 s).
    ap.add_argument("--arm-period", type=float, default=0)
    args = ap.parse_args()

    os.makedirs(os.path.join(ROOT, "out/logs"), exist_ok=True)
    logpath = os.path.join(ROOT, "out/logs/command-plane-%s.log"
                           % time.strftime("%H%M%S"))
    log = open(logpath, "w")
    p = Plane(log)
    p.say("command plane up on %s:%d -> %s:%d, mode=%s"
          % (CONSOLE_IP, CONSOLE_CMD, PAD_IP, PAD_CMD, args.mode))

    # everything the console sent early, in order, with its cadence
    console = load_truth("port50123.bin")
    cons = [(ts, pkt) for ts, pkt in console]
    t0 = cons[0][0] if cons else 0
    blobs = [(ts - t0, pkt) for ts, pkt in cons
             if len(pkt) >= 8 and struct.unpack_from("<HH", pkt, 4)[0] == 1040]
    generics = [(ts - t0, pkt) for ts, pkt in cons
                if len(pkt) >= 8 and struct.unpack_from("<HH", pkt, 4)[0] in (8, 12, 17, 44)]
    p.say("console capture has %d blob fragments, %d early generic/clock commands"
          % (len(blobs), len(generics)))

    # ---- the console's non-bulk command bursts -----------------------------
    # Extracted from the decrypted session. "arm" is the burst the console sends
    # 2.5 s BEFORE video starts - including svc 5/method 0x02, the only service-5
    # command in the whole session and the only command that appears right before
    # the video stream - and "arma" additionally includes the post-state-push
    # transition at t=28 (svc 0/0x12, svc 4/0x21, svc 4/0x1a flags 0x42).
    def sel(svc_meth, t_lo, t_hi):
        out = []
        for ts, pkt in cons:
            if len(pkt) < 20 or pkt[8] != 0x7E:
                continue
            rel = ts - t0
            if (pkt[14], pkt[15]) != svc_meth or not (t_lo <= rel <= t_hi):
                continue
            # skip ack-only generic packets (type 3 outer) and the blob stream
            if struct.unpack_from("<H", pkt, 0)[0] == 3:
                continue
            out.append(pkt)
        return out

    arm_burst = (sel((0, 0x00), 58.0, 59.5) + sel((4, 0x04), 58.0, 59.5) +
                 sel((5, 0x02), 58.0, 59.5) + sel((5, 0x06), 58.0, 59.5))
    # svc 5/0x02 is "102 bytes to UIC command 0x0c" - a UIC WRITE. Ours carries 102
    # zero bytes, and the pad moves 0 -> 12 (menu) right after a burst that includes
    # it. DRC_ARM_NO_502=1 drops it to test whether it is what disarms the pad.
    if os.environ.get("DRC_ARM_NO_502") == "1":
        arm_burst = [pkt for pkt in arm_burst if (pkt[14], pkt[15]) != (5, 0x02)]
        p.say("DRC_ARM_NO_502=1: arm burst without svc 5/0x02")
    post_push = (sel((0, 0x12), 27.0, 29.5) + sel((4, 0x21), 27.0, 29.5) +
                 sel((4, 0x1a), 27.0, 29.5))
    p.say("arm burst: %d packets (incl. svc 5/0x02: %d); post-push: %d packets"
          % (len(arm_burst), len(sel((5, 0x02), 58.0, 59.5)), len(post_push)))
    if args.mode in ("arm", "arma", "full"):
        sequence = (post_push if args.mode == "arma" else []) + arm_burst
        for i, pkt in enumerate(sequence):
            p.send(pkt)
            time.sleep(0.25)
            p.pump(0.05)
        p.say("sent %d command(s) in the arm sequence; watching state"
              % len(sequence))

    # ---- mode "console": the console's whole non-ack command stream, in its own
    # order and at its own cadence, from t=0. Used by phase11, which starts it
    # ~0.3 s after the pad's DHCP ACK - the real console's timing (measured:
    # first command 285 ms after the lease).
    console_seq = []
    if args.mode == "console":
        for ts, pkt in cons:
            if len(pkt) < 8:
                continue
            ptype = struct.unpack_from("<H", pkt, 0)[0]
            if ptype == 3:            # pad-reply acks: we generate our own
                continue
            console_seq.append((ts - cons[0][0], pkt))
        p.say("mode console: %d datagrams in recorded order (0.0..%.1fs)"
              % (len(console_seq), console_seq[-1][0] if console_seq else 0))

    t_console = None
    console_idx = 0
    next_arm = 0.0
    stop_at = time.time() + args.seconds
    next_state = 0.0
    blob_idx = 0
    gen_idx = 0
    t_replay = None
    next_uvc = 0.0

    while time.time() < stop_at:
        now = time.time()
        if args.arm_period and arm_burst and now >= next_arm:
            for pkt in arm_burst:
                p.send(pkt)
            p.read_gate()
            p.say("re-sent arm burst (%d packets)" % len(arm_burst))
            next_arm = now + args.arm_period

        if now >= next_state:
            p.read_state()
            p.read_gate()
            next_state = now + args.state_period

        if args.mode in ("blobs", "full") and blobs:
            if t_replay is None:
                t_replay = now
            while blob_idx < len(blobs) and now - t_replay >= blobs[blob_idx][0]:
                p.send(blobs[blob_idx][1])
                blob_idx += 1

        if args.mode == "full" and generics:
            if t_replay is None:
                t_replay = now
            while gen_idx < len(generics) and now - t_replay >= generics[gen_idx][0]:
                p.send(generics[gen_idx][1])
                gen_idx += 1

        if args.mode in ("uvcuac", "full") and now >= next_uvc:
            # Console parity for the documented display gate: send the console's
            # own 56-byte UVC/UAC query (query type 1) once a second, and flip
            # the first payload byte to 1 only after a reply has been validated
            # (Barista does exactly this; we never did).
            src = [pkt for _t, pkt in console
                   if len(pkt) == 56 and struct.unpack_from("<HH", pkt, 2)[0] == 1]
            if src:
                seq = p.next_seq()
                pkt = bytearray(src[0])
                struct.pack_into("<H", pkt, 6, seq)
                pkt[8] = 1 if p.uvcuac_gate_seen else 0   # payload byte[0]
                p.send(bytes(pkt))
            next_uvc = now + 1.0

        if args.mode == "console" and console_seq:
            if t_console is None:
                t_console = now
            while (console_idx < len(console_seq) and
                   now - t_console >= console_seq[console_idx][0]):
                p.send(console_seq[console_idx][1])
                console_idx += 1

        got = p.pump(0.02)

    p.say("done: %d reply packets received; state changes: %d"
          % (sum(p.replies.values()), len(p.state_changes)))
    for t, a, b in p.state_changes:
        p.say("  state %s -> %d" % (a, b))
    log.close()
    print("\nlog: %s" % logpath)


if __name__ == "__main__":
    main()
