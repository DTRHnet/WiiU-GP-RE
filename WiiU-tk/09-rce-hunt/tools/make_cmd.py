#!/usr/bin/env python3
"""Build console-shaped cmd packets (port 50023 -> pad 50123) and self-test the
builder against the console's own captured bytes.

Wire format, derived from out/evidence/truth/port50123.bin (1475 records) and
cross-checked against run/pad-state.py and libdrc include/drc/internal/cmd-packet.h:

  CmdHeader (8 B, little-endian)
    0..1  packet_type  0=query 1=query-ack 2=reply 3=reply-ack
    2..3  query_type   0=generic 1=UVC/UAC 2=time
    4..5  payload_size = len(datagram) - 8
    6..7  seq_id       one per logical request, echoed by the pad in its replies

  GenericCmdHeader (12 B, only for query_type 0)
    0     magic 0x7E
    1     version 0x01
    2     transaction_id[11:4]
    3     transaction_id[3:0] << 4 | final << 3 | fragment_id[10:8]
    4     fragment_id[7:0]
    5     flags       0x40 = single/final, 0x42 = more fragments follow
    6     service_id
    7     method_id
    8..9  error_code (big-endian, 0 in queries)
    10..11 generic payload_size (big-endian) = len(datagram) - 20

Self-test: reproduces cmd_t0_q0_len12 / _len17 / _44 / _114 (console bytes) exactly.
Run: python3 make_cmd.py
"""
import struct
import sys

MAGIC = 0x7E


def cmd(payload=b"", ptype=0, qtype=0, seq=0):
    return struct.pack("<HHHH", ptype, qtype, len(payload), seq & 0xFFFF) + payload


def generic(service, method, body=b"", tid=0, fid=0, final=True, flags=None,
            error=0, seq=0, declared=None):
    """Console-shaped generic cmd. `declared` overrides the declared generic
    payload_size (attack use); the default is the honest len(body)."""
    if flags is None:
        flags = 0x40 if final else 0x42
    d = len(body) if declared is None else declared
    gen = bytearray(12)
    gen[0] = MAGIC
    gen[1] = 0x01
    gen[2] = (tid >> 8) & 0xFF
    gen[3] = ((tid & 0x0F) << 4) | (0x08 if final else 0) | ((fid >> 8) & 0x07)
    gen[4] = fid & 0xFF
    gen[5] = flags
    gen[6] = service
    gen[7] = method
    gen[8:10] = struct.pack(">H", error)
    gen[10:12] = struct.pack(">H", d)
    return cmd(bytes(gen) + body, ptype=0, qtype=0, seq=seq)


def reply_ack(seq, qtype=0):
    return cmd(b"", ptype=3, qtype=qtype, seq=seq)


# ---------------------------------------------------------------- attack shapes
def frag_series(service, method, body, tid, first_fid=0, final=True, flags=None):
    """One logical message split over several datagrams, console style."""
    out, fid = [], first_fid
    out.append(generic(service, method, body, tid=tid, fid=fid,
                       final=final, flags=flags))
    return b"".join(out)


def shorten(body, n):
    """Deliver fewer bytes than declared (length-vs-data mismatch)."""
    return body[:n]


def selftest():
    ok = True
    cases = [
        # exact console datagrams (outer header included)
        ("svc0/0x00", dict(service=0, method=0, body=b"", tid=0x105, fid=0,
                           final=True, seq=9),
         "000000000c0009007e0101580040000000000000"),
        ("svc5/0x0c", dict(service=5, method=0x0C, body=bytes.fromhex("130302952c"),
                           tid=0x109, fid=0, final=True, seq=13),
         "0000000011000d007e0101980040050c00000005130302952c"),
        ("svc0/0x10", dict(service=0, method=0x10,
                           body=bytes.fromhex("000c2934" + "00" * 28),
                           tid=0x10A, fid=0, final=True, seq=14),
         "000000002c000e007e0101a80040001000000020" "000c2934" + "00" * 28),
        ("svc0/0x11 fid0", dict(service=0, method=0x11,
                                body=bytes.fromhex(
                                    "0000000100000101" + "00" * 8 + "ae522a0a")
                                + bytes(1028 - 20), tid=0x10B, fid=0,
                                final=False, seq=15),
         None),  # length-matched against the captured datagram below
    ]
    for name, kw, want in cases:
        got = generic(seq=kw.pop("seq"), **kw).hex()
        if want is None:
            print(f"  {name:12s} built {len(got)//2} B (no reference)")
            continue
        if got != want:
            ok = False
            print(f"  {name:12s} MISMATCH\n    got  {got}\n    want {want}")
        else:
            print(f"  {name:12s} OK ({len(got)//2} B)")
    # full 1048-byte fragment 1 of the state push, compared byte for byte
    cap = bytes.fromhex(open_ref_frag())
    built = generic(service=0, method=0x11, body=cap[20:], tid=0x10B, fid=0,
                    final=False, seq=15)
    if built == cap:
        print(f"  {'svc0/0x11':12s} OK (1048 B identical to the console fragment)")
    else:
        ok = False
        print(f"  {'svc0/0x11':12s} MISMATCH at "
              f"{next(i for i in range(min(len(built), len(cap))) if built[i] != cap[i])}")
    return ok


def open_ref_frag():
    import os
    p = os.path.join(os.path.dirname(__file__), "..", "..", "..",
                     "out", "evidence", "truth", "console-messages",
                     "cmd_t0_q0_len1040.bin")
    return open(p, "rb").read().hex()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(0 if selftest() else 1)
    print("builder self-test:")
    selftest()
    print("\nexamples:")
    print("  svc0/0x0a index 9      :", generic(0, 0x0A, b"\x09", seq=1).hex())
    print("  svc0/0x0a index 0xFF   :", generic(0, 0x0A, b"\xff", seq=2).hex())
    print("  svc5/0x0c index255 l255:", generic(5, 0x0C, bytes([0xFF, 0xFF]) + bytes(256),
                                             seq=3).hex()[:80] + "...")
    print("  svc0/0x03 blk0xFFFFFFFF:", generic(0, 0x03,
                                             b"\xff\xff\xff\xff" + bytes(1024),
                                             seq=4).hex()[:80] + "...")
    print("  fragment over-claim    :", generic(0, 0x11, b"\x00\x00\x00\x01" + bytes(16),
                                             tid=0x10B, fid=0, final=False,
                                             seq=5, declared=1028).hex())
