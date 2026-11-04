#!/usr/bin/env python3
"""Read-only miner for decrypted console<->pad UDP payload dumps.

Dump format (from capture/truth-decrypt.py): per record
    >d  ts            (8 bytes, origin time)
    4s  src ip
    4s  dst ip
    I   payload length
    p   payload

This tool only READS out/evidence/truth/port*.bin and prints statistics.
It never transmits anything.

Usage: mine_cmd.py <portNNNNN.bin> [--svc S] [--method M] [--types 0,1,2,3]
"""
import struct
import sys
import argparse
import collections


def records(path):
    with open(path, "rb") as f:
        blob = f.read()
    off = 0
    n = len(blob)
    while off + 20 <= n:
        ts, si, di, ln = struct.unpack(">d4s4sI", blob[off:off + 20])
        off += 20
        p = blob[off:off + ln]
        off += ln
        if len(p) != ln:
            break
        yield ts, ".".join(str(b) for b in si), ".".join(str(b) for b in di), p


def parse_generic(p):
    """Return dict for a type-0/query-0 packet carrying a GenericCmdHeader."""
    if len(p) < 8:
        return None
    ptype, qtype, psize, seq = struct.unpack("<HHHH", p[:8])
    if qtype != 0:
        return None
    g = p[8:]
    if len(g) < 12:
        return None
    out = {
        "ptype": ptype, "qtype": qtype, "psize": psize, "seq": seq,
        "magic": g[0], "ver": g[1],
        "tid": (g[2] << 4) | (g[3] >> 4), "frag": ((g[3] & 0xF) << 8) | g[4],
        "flags": g[5], "svc": g[6], "method": g[7],
        "err": struct.unpack(">H", g[8:10])[0],
        "glen": struct.unpack(">H", g[10:12])[0],
        "payload": g[12:],
        "raw": p,
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--svc", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--method", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--dump", type=int, default=0, help="dump first N matching payloads")
    args = ap.parse_args()

    counts = collections.Counter()
    first = {}
    seqs = collections.defaultdict(list)
    matches = []
    total = 0
    for ts, si, di, p in records(args.path):
        total += 1
        g = parse_generic(p)
        if not g:
            if len(p) >= 8:
                counts[("outer", struct.unpack("<HH", p[:4])[0],
                        struct.unpack("<HH", p[:4])[1], len(p))] += 1
            continue
        key = (g["ptype"], g["svc"], g["method"], g["glen"], g["flags"])
        counts[key] += 1
        if key not in first:
            first[key] = (ts, si, di, g)
        seqs[(g["svc"], g["method"])].append(g["seq"])
        if args.svc is not None and g["svc"] != args.svc:
            continue
        if args.method is not None and g["method"] != args.method:
            continue
        matches.append((ts, si, di, g))

    print("== %s: %d records ==" % (args.path, total))
    print("%-48s %s" % ("(ptype, svc, method, glen, flags)", "count"))
    for key, c in counts.most_common(args.top):
        print("%-48s %d" % (str(key), c))

    if matches:
        print("\n== matches: %d ==" % len(matches))
        for ts, si, di, g in matches[:args.dump or 12]:
            print("t=%.3f %s->%s ptype=%d seq=%d tid=0x%x frag=%d flags=0x%02x "
                  "svc=%d m=0x%02x err=0x%04x glen=%d paylen=%d" %
                  (ts, si, di, g["ptype"], g["seq"], g["tid"], g["frag"],
                   g["flags"], g["svc"], g["method"], g["err"], g["glen"],
                   len(g["payload"])))
            print("   raw:", g["raw"][:32].hex(" "))
            if g["payload"]:
                print("   pay:", g["payload"][:48].hex(" "))


if __name__ == "__main__":
    main()
