#!/usr/bin/env python3
"""P0/P1/P2 packet set for the GamePad firmware-update path (research/rce-hunt).

Companion to research/rce-hunt/01-pad-firmware-update.md §6. It builds the exact
bytes and, only with --send, transmits them. Dry run is the default.

Safety design:
  * P0 (read-only queries) is the only thing --send will transmit by default.
  * P1 (svc 0/0x05 abort, svc 0/0x04 end) needs --send --state-probes.
  * P2 (svc 4/0x01 payload 2 = reboot into firmware-update mode) needs
    --send --enter-update-mode AND an interactive confirmation, because it is the
    commitment point: it can take the pad off the air until it is power-cycled.
  * There is deliberately NO support for svc 0/0x02, 0x03 (data) or 0x0b-0x0f
    (Service/TVCode/Screen/Lang) in this script. Those write flash and are only
    to be driven after the UART harness exists and the block semantics are known
    (01-pad-firmware-update.md §2.3, §6 P3/P4).

Wire format (verified against out/evidence/truth/port50123.bin and libdrc):
  outer  : le16 packet_type | le16 query_type | le16 payload_size | le16 seq
  generic: 7e | 01 | tid(12b, b2<<8|b3>>4) | final(bit3 of b3) | fid(11b)
           | flags | svc | method | be16 error | be16 payload_size
Replies: pad sends a bare 8-byte type-1 ACK, then a type-2 reply on the same seq;
we ACK the reply with a bare 8-byte type-3 packet.

Usage:
  research/rce-hunt/pad-update-probe.py                      # show every P0 packet
  sudo research/rce-hunt/pad-update-probe.py --send           # P0 against the pad
  sudo research/rce-hunt/pad-update-probe.py --send --state-probes
  sudo research/rce-hunt/pad-update-probe.py --send --enter-update-mode
"""
import argparse
import importlib.util
import os
import socket
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_spec = importlib.util.spec_from_file_location(
    "pad_state", os.path.join(ROOT, "run/pad-state.py"))
pad_state = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pad_state)
build_generic = pad_state.build_generic
parse_reply = pad_state.parse_reply

CONSOLE_IP, PAD_IP = "192.168.1.10", "192.168.1.11"
CONSOLE_CMD, PAD_CMD = 50023, 50123

# (name, service, method, payload, note)
P0 = [
    ("lvc-version", 0, 0x00, b"", "running + installed LVC image version (expect 0x190C0117)"),
    ("version-all", 4, 0x04, b"", "28 B version info (word[2] = image version, word[3] = UIC fw)"),
    ("state", 4, 0x05, b"", "1 B state oracle (correlate with what you see on the glass)"),
    ("wifi", 1, 0x05, b"", "113 B: SSID/PSK as stored - proves the pad is ours"),
    ("uic-eeprom", 5, 0x06, b"", "772 B: UIC fw version + first 768 EEPROM bytes"),
    ("brightness", 5, 0x15, b"", "1 B LCD brightness 1-5"),
]

P1 = [
    ("abort-update", 0, 0x05, b"", "docs: no payload, no reply. No update in progress -> expect an error"),
    ("end-update", 0, 0x04, b"", "docs: 4-byte reply. No update in progress -> expect an error code"),
]

P2 = [
    ("enter-fwupdate", 4, 0x01, b"\x02", "reboot to firmware-update mode (COMMITMENT POINT)"),
    ("back-to-normal", 4, 0x01, b"\x00", "reboot to normal mode (the undo, only usable while on the air)"),
]


def show(title, rows, seq):
    print("== %s ==" % title)
    for name, svc, meth, payload, note in rows:
        pkt = build_generic(svc, meth, payload, seq=seq)
        print("  %-16s svc %d m 0x%02x  seq %-4d %3d B  %s"
              % (name, svc, meth, seq, len(pkt), pkt.hex()))
        print("      %s" % note)
        seq += 1
    return seq


def exchange(sock, pad, svc, meth, payload, seq, timeout=1.5):
    pkt = build_generic(svc, meth, payload, seq=seq)
    sock.sendto(pkt, (pad, PAD_CMD))
    deadline = time.time() + timeout
    acked = False
    reply = None
    while time.time() < deadline:
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            data, _addr = sock.recvfrom(8192)
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
            reply = r
            break
    return acked, reply


def describe(name, r):
    b, body = r, r["body"]
    if name == "lvc-version" and len(body) >= 8:
        run, inst = struct.unpack_from(">II", body, 0)
        return "running=0x%08X installed=0x%08X%s" % (
            run, inst, "" if run == inst else "  <-- INSTALLED DIFFERS (mid-update?)")
    if name == "version-all" and len(body) >= 12:
        words = struct.unpack_from(">7I", body, 0)
        return " ".join("%08X" % w for w in words) + "   (word[2]=image version, word[3]=UIC fw)"
    if name == "wifi" and len(body) >= 113:
        ssid = body[15:47].split(b"\x00")[0]
        return "ssid=%r auth=%d enc=%d psk_len=%d" % (ssid, body[13], body[14], body[112])
    if name == "uic-eeprom" and len(body) >= 4:
        return "UIC fw version 0x%s (%d EEPROM bytes)" % (body[:4].hex().upper(), len(body) - 4)
    return "error=%d %dB %s" % (b["error"], len(body), body[:32].hex())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pad", default=PAD_IP)
    ap.add_argument("--send", action="store_true", help="actually transmit (default: dry run)")
    ap.add_argument("--state-probes", action="store_true",
                    help="with --send: also send svc 0/0x05 and svc 0/0x04")
    ap.add_argument("--enter-update-mode", action="store_true",
                    help="with --send: also send svc 4/0x01 payload 2 (asks for confirmation)")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--interval", type=float, default=0.3)
    args = ap.parse_args()

    seq = 100
    if not args.send:
        seq = show("P0 read-only", P0, seq)
        seq = show("P1 state probes (need --send --state-probes)", P1, seq)
        show("P2 mode changes (need --send --enter-update-mode)", P2, seq)
        print("\ndry run: nothing was transmitted. The pad is at %s:%d." % (args.pad, PAD_CMD))
        print("stop the media stack first (run/drc-down.sh) so one socket owns %s:%d."
              % (CONSOLE_IP, CONSOLE_CMD))
        return 0

    rows = list(P0)
    if args.state_probes:
        rows += P1
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((CONSOLE_IP, CONSOLE_CMD))
        where = "%s:%d" % (CONSOLE_IP, CONSOLE_CMD)
    except OSError as e:
        sock.bind((CONSOLE_IP, 0))
        where = "%s:%d (ephemeral; port busy: %s)" % (CONSOLE_IP, sock.getsockname()[1], e)
        print("[!] %s -- the pad may answer the other socket instead" % e)
    print("from %s -> %s:%d" % (where, args.pad, PAD_CMD))

    results = {}
    for name, svc, meth, payload, _note in rows:
        acked = reply = None
        for _ in range(args.retries):
            acked, reply = exchange(sock, args.pad, svc, meth, payload, seq)
            if reply:
                break
            seq += 1
        if not reply:
            print("  %-16s svc %d/0x%02x NO REPLY (acked=%s)" % (name, svc, meth, acked))
        else:
            print("  %-16s svc %d/0x%02x acked=%s  %s"
                  % (name, svc, meth, acked, describe(name, reply)))
            results[name] = reply
        seq += 1
        time.sleep(args.interval)

    if args.enter_update_mode:
        name, svc, meth, payload, _note = P2[0]
        print("\nThis sends svc 4/0x01 payload 2: the pad reboots into firmware-update mode.")
        print("Have the UART harness ready and be ready to power-cycle the pad.")
        if input("type ENTER to commit, anything else to skip: ").strip() != "":
            print("skipped")
            return 0
        acked, reply = exchange(sock, args.pad, svc, meth, payload, seq, timeout=5.0)
        print("  %-16s acked=%s reply=%s" % (name, acked, reply))
        print("now watch for 60 s: hostapd reassoc, DHCP request, and whether svc 0/0x00 answers again.")

    if "lvc-version" in results:
        print("\nbaseline recorded - keep these bytes as the 'before' snapshot.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
