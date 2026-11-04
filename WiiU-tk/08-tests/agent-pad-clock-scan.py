#!/usr/bin/env python3
"""Offline scan of the decrypted console<->pad capture for the GamePad's clock.

READ-ONLY. Parses out/evidence/truth/port*.bin (record framing: ">d4s4sI" +
payload, see research/rce-hunt/tools/parse_truth.py) and answers one question:
is there any pad->console field that ticks like a clock or counter?

Prints: (1) every time command the console sent, (2) every pad reply grouped by
the console query that caused it with 4/8-byte words decoded, (3) monotonicity
of the svc 0/0x11 transfer cursor and the input-protocol seq_id, (4) the
svc 5/0x06 UIC-config blob diff.

Usage: python3 tests/agent-pad-clock-scan.py
"""
import collections
import hashlib
import os
import struct

TRUTH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "out", "evidence", "truth")


def records(name):
    """Yield (ts_s, payload) with exact-EOF framing."""
    blob = open(os.path.join(TRUTH, name), "rb").read()
    off = 0
    while off < len(blob):
        ts, si, di, ln = struct.unpack(">d4s4sI", blob[off:off + 20])
        off += 20
        yield ts, blob[off:off + ln]
        off += ln
    assert off == len(blob), name


def gh(body):
    """12-byte GenericCmdHeader (mixed endianness, libdrc packing)."""
    return dict(magic=body[0], ver=body[1], tid=(body[2] << 4) | (body[3] >> 4),
                frag=((body[3] & 0xF) << 8) | body[4], flags=body[5], svc=body[6],
                meth=body[7], err=struct.unpack(">H", body[8:10])[0],
                glen=struct.unpack(">H", body[10:12])[0], payload=body[12:])


def main():
    con = list(records("port50123.bin"))   # console -> pad
    pad = list(records("port50023.bin"))   # pad -> console

    # --- 1. time commands (query type 2) -----------------------------------
    print("=== console -> pad time commands (query type 2, 8-byte LE payload) ===")
    for ts, p in con:
        t, q, sz, sq = struct.unpack("<HHHH", p[:8])
        if t == 0 and q == 2:
            d, pad_, s = struct.unpack("<HHI", p[8:16])
            print("  t=%7.3f seq=%d days=%d(0x%04x) pad=%d seconds=%d(0x%08x)"
                  % (ts, sq, d, d, pad_, s, s))

    # --- 2. every pad reply, grouped by the query that caused it ------------
    qmap = {}
    for ts, p in con:
        t, q, sz, sq = struct.unpack("<HHHH", p[:8])
        if t == 0:
            body = p[8:]
            if q == 0 and len(body) >= 12 and body[0] == 0x7E:
                g = gh(body)
                qmap[sq] = (g["svc"], g["meth"], g["glen"])
            else:
                qmap[sq] = (q, None, len(body))

    print("\n=== pad -> console type-2 replies (grouped) ===")
    groups = collections.defaultdict(list)
    for ts, p in pad:
        t, q, sz, sq = struct.unpack("<HHHH", p[:8])
        if t != 2:
            continue
        groups[(len(p) - 8, q, qmap.get(sq))].append((ts, sq, p[8:]))
    for k in sorted(groups):
        v = groups[k]
        bodies = collections.Counter(x[2].hex() for x in v)
        print("  len=%d q=%d query=%s n=%d distinct=%d"
              % (k[0], k[1], k[2], len(v), len(bodies)))
        for b, n in bodies.items():
            print("      x%-3d %s" % (n, b))

    # --- 3. svc 0/0x11 transfer cursor (the only monotonic cmd reply) -------
    print("\n=== svc 0/0x11 replies (4-byte payload) monotonicity ===")
    cur = []
    for ts, p in pad:
        t, q, sz, sq = struct.unpack("<HHHH", p[:8])
        if t == 2 and q == 0 and len(p) >= 20 and p[8] == 0x7E:
            g = gh(p[8:])
            if g["svc"] == 0 and g["meth"] == 0x11 and len(g["payload"]) >= 4:
                cur.append((ts, struct.unpack(">I", g["payload"][:4])[0]))
    be = [v for _, v in cur]
    print("  n=%d first=%d last=%d deltas=%s monotonic=%s span=%.1f..%.1f s"
          % (len(be), be[0], be[-1],
             sorted(collections.Counter(b - a for a, b in zip(be, be[1:])).items()),
             all(b >= a for a, b in zip(be, be[1:])),
             cur[0][0], cur[-1][0]))

    # --- 4. UIC config blob (svc 5/0x06, 772-byte payload) diff -------------
    print("\n=== svc 5/0x06 UIC config blobs ===")
    blobs = []
    for ts, p in pad:
        t, q, sz, sq = struct.unpack("<HHHH", p[:8])
        if t == 2 and len(p) >= 20 and p[8] == 0x7E:
            g = gh(p[8:])
            if g["svc"] == 5 and g["meth"] == 0x06:
                blobs.append((ts, g["payload"]))
    base = blobs[0][1]
    for i, (ts, b) in enumerate(blobs):
        diffs = [o for o in range(len(base)) if base[o] != b[o]]
        print("  blob[%d] t=%.3f sha=%s differs-from-blob[0] at %s"
              % (i, ts, hashlib.sha256(b).hexdigest()[:12], diffs))
    print("  UIC fw version (payload[0:4]) LE=0x%08x BE=0x%08x"
          % (struct.unpack("<I", base[:4])[0], struct.unpack(">I", base[:4])[0]))

    # --- 5. input protocol seq_id (the only whole-session pad counter) ------
    print("\n=== input protocol (port50022.bin) u16 seq_id ===")
    inp = list(records("port50022.bin"))
    seq = [struct.unpack("<H", p[0:2])[0] for _, p in inp]
    d = collections.Counter(b - a for a, b in zip(seq, seq[1:]))
    print("  records=%d rate=%.2f/s seq deltas=%s wraps=%d (u16)"
          % (len(seq), (len(seq) - 1) / (inp[-1][0] - inp[0][0]),
             sorted(d.items()), sum(1 for a, b in zip(seq, seq[1:]) if b < a)))
    # any other monotonic byte in the 128-byte blob?
    hits = []
    for o in range(128):
        vals = [p[o] for _, p in inp]
        fwd = sum(1 for a, b in zip(vals, vals[1:]) if b >= a)
        if fwd >= 0.98 * (len(vals) - 1) and len(set(vals)) > 1 and o != 0:
            hits.append(o)
    print("  other near-monotonic byte offsets: %s" % (hits[:20] or "none"))


if __name__ == "__main__":
    main()
