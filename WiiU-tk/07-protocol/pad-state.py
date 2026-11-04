#!/usr/bin/env python3
"""Ask the GamePad which *state* it is in — the objective answer to "which screen
is it on, and is it still mine?".

Three documented read-only cmd-service queries (libdrc `web/docs/re/sc-cmd.rst`):

  svc 4 / 0x05  -> 1 byte  : pad's current state index (retvals[] = {0,10,4,5,6,
                             1,2,3,9,7,8,11}, index read from the UIC)
  svc 4 / 0x04  -> 28 bytes : version information
  svc 1 / 0x05  -> 113 bytes: WL config + auth/enc + SSID + PSK *as stored in the
                             pad* — the direct test for "is this pad still paired
                             to us or did the console take it back?"
  svc 0 / 0x00  -> 8 bytes  : LVC firmware version (running, installed)
  svc 5 / 0x15  -> 1 byte   : current LCD brightness (1-5)

Wire format (all little-endian outside the generic header, which is mixed):

  CmdHeader      : le16 packet_type | le16 query_type | le16 payload_size | le16 seq
  GenericCmdHdr  : 7e | 01 | tid_hi | tid_lo<<4|final<<3|fid_hi | fid_lo |
                   flags | service | method | be16 error | be16 payload_size

A query is type 0, the pad ACKs with type 1, replies with type 2, and we ACK the
reply with type 3 (libdrc's cmd protocol state machine).

Safe by default: prints the packet and exits. Add --send to transmit. Stop the
streamer first (`run/drc-down.sh`) if you want to own port 50023 as the console;
otherwise an ephemeral source port is used and the pad may or may not answer.

Usage:
  run/pad-state.py                     # dry run: show the bytes for every query
  sudo run/pad-state.py --send         # ask the connected pad
  sudo run/pad-state.py --send --query wifi
"""
import argparse
import socket
import struct
import sys
import time

DEFAULT_PAD = "192.168.1.11"
CONSOLE_IP = "192.168.1.10"
PAD_CMD_PORT = 50123
CONSOLE_CMD_PORT = 50023

# name -> (service, method, known reply size or None)
QUERIES = {
    "state":   (4, 0x05, 1),
    "version": (4, 0x04, 28),
    "wifi":    (1, 0x05, 113),
    "lvc":     (0, 0x00, 8),
    "bright":  (5, 0x15, 1),
}

# retvals[] from sc-cmd.rst: the pad returns retvals[current_state].
RETVALS = [0, 10, 4, 5, 6, 1, 2, 3, 9, 7, 8, 11]


def build_generic(service, method, payload=b"", seq=0, query_type=0,
                  tid=0, fid=0, final=True, flags=0x40):
    """Outer CmdHeader + 12-byte generic header + payload."""
    if len(payload) > 1016:
        raise ValueError("generic payload exceeds kMaxGenericCmdPayloadSize")
    outer = struct.pack("<HHHH", 0, query_type, 12 + len(payload), seq & 0xFFFF)
    gen = bytearray(12)
    gen[0] = 0x7E
    gen[1] = 0x01
    gen[2] = (tid >> 8) & 0xFF
    gen[3] = ((tid << 4) & 0xF0) | (0x08 if final else 0) | ((fid >> 8) & 0x07)
    gen[4] = fid & 0xFF
    gen[5] = flags
    gen[6] = service
    gen[7] = method
    gen[8:10] = struct.pack(">H", 0)                 # error, big-endian
    gen[10:12] = struct.pack(">H", len(payload))     # payload size, big-endian
    return outer + bytes(gen) + payload


def parse_reply(pkt):
    """Return dict for a pad->console cmd packet, or None if not a type-2 reply."""
    if len(pkt) < 20:
        return None
    ptype, qtype, plen, seq = struct.unpack_from("<HHHH", pkt, 0)
    if pkt[8] != 0x7E:
        return None
    svc, meth = pkt[14], pkt[15]
    error = struct.unpack_from(">H", pkt, 16)[0]
    body_len = struct.unpack_from(">H", pkt, 18)[0]
    return {
        "packet_type": ptype, "query_type": qtype, "seq": seq,
        "service": svc, "method": meth, "error": error,
        "body_len": body_len, "body": pkt[20:20 + body_len],
    }


def describe(name, body):
    if name == "state" and len(body) >= 1:
        idx = body[0]
        guess = RETVALS.index(idx) if idx in RETVALS else None
        return ("state index %d%s" %
                (idx, "" if guess is None else " (= retvals[%d], i.e. raw UIC state %d; "
                 "meaning undocumented — record it next to what you SEE)" % (guess, guess)))
    if name == "wifi" and len(body) >= 113:
        auth, enc = body[13], body[14]
        ssid = body[15:47].split(b"\x00")[0]
        ssid_len = body[47]
        psk = body[48:112].split(b"\x00")[0]
        psk_len = body[112]
        return ("ssid=%r (%d) auth=%d enc=%d psk=%r (%d bytes)"
                % (ssid[:ssid_len], ssid_len, auth, enc, psk[:psk_len], psk_len))
    if name == "version" and len(body) >= 8:
        return "version bytes: " + body[:28].hex()
    if name == "lvc" and len(body) >= 8:
        running, installed = struct.unpack_from("<II", body, 0)
        return "LVC running=%d installed=%d" % (running, installed)
    if name == "bright" and len(body) >= 1:
        return "LCD brightness level %d (1-5)" % body[0]
    return "payload: " + body[:64].hex()


def one_roundtrip(sock, pad, service, method, seq, timeout=1.5):
    pkt = build_generic(service, method, b"", seq=seq)
    sock.sendto(pkt, (pad, PAD_CMD_PORT))
    deadline = time.time() + timeout
    acked = False
    while time.time() < deadline:
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            break
        r = parse_reply(data)
        if not r or r["seq"] != seq:
            continue
        if r["packet_type"] == 1:
            acked = True
            continue
        if r["packet_type"] == 2:
            # ACK the reply (type 3), as the console does.
            # console acks replies with a bare 8-byte type-3 header (see
            # GROUND-TRUTH-SESSION.md: 445 x 8 B on 50023)
            ack = struct.pack("<HHHH", 3, 0, 0, seq)
            sock.sendto(ack, (pad, PAD_CMD_PORT))
            r["acked_query"] = acked
            return r
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pad", default=DEFAULT_PAD)
    ap.add_argument("--send", action="store_true", help="actually transmit")
    ap.add_argument("--query", default="all", choices=sorted(QUERIES) + ["all"])
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--interval", type=float, default=0.2,
                    help="delay between queries (console cadence is ~1/s per kind)")
    args = ap.parse_args()

    pad = args.pad
    names = sorted(QUERIES) if args.query == "all" else [args.query]

    if not args.send:
        print("dry run (add --send to transmit to %s:%d)\n" % (pad, PAD_CMD_PORT))
        seq = 15  # matches the console's first observed command sequence
        for name in names:
            svc, meth, known = QUERIES[name]
            pkt = build_generic(svc, meth, b"", seq=seq)
            print("  %-8s svc %d method 0x%02x  seq %-3d  %2d B  %s"
                  % (name, svc, meth, seq, len(pkt), pkt.hex()))
            seq += 1
        print("\n  known-good comparison (libdrc's own on-wire backlight command):")
        print("  bright   " + build_generic(5, 0x14, b"\x04", seq=0).hex())
        print("  -> generic header must read 7e 01 00 08 00 40 05 14 00 00 00 01")
        return 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((CONSOLE_IP, CONSOLE_CMD_PORT))
        where = "%s:%d" % (CONSOLE_IP, CONSOLE_CMD_PORT)
    except OSError as e:
        sock.bind((CONSOLE_IP, 0))
        where = "%s:%d (ephemeral: port %d busy — is the streamer running?)" % (
            CONSOLE_IP, sock.getsockname()[1], CONSOLE_CMD_PORT)
        print("[!] %s" % e)
    print("from %s -> %s:%d" % (where, pad, PAD_CMD_PORT))

    seq = 100
    rc = 0
    for name in names:
        svc, meth, known = QUERIES[name]
        r = None
        for attempt in range(args.retries):
            r = one_roundtrip(sock, pad, svc, meth, seq)
            if r:
                break
            seq += 1
        if not r:
            print("  %-8s NO REPLY (pad asleep, not associated, or port 50023 owned "
                  "by another socket)" % name)
            rc = 1
        else:
            print("  %-8s svc %d/0x%02x error=%d %dB  %s"
                  % (name, r["service"], r["method"], r["error"],
                     len(r["body"]), describe(name, r["body"])))
            if known and len(r["body"]) != known:
                print("           (expected %d bytes; got %d)" % (known, len(r["body"])))
        seq += 1
        time.sleep(args.interval)
    return rc


if __name__ == "__main__":
    sys.exit(main())
