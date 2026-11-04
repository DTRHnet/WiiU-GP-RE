#!/usr/bin/env python3
"""Read-only: inventory every generic cmd (svc/method) in the decrypted console
capture, with correct tid/fid decoding (matches run/pad-state.py bit layout).

Reads only out/evidence/truth/*.bin; sends nothing.
"""
import collections
import glob
import struct
import sys


def records(path):
    blob = open(path, "rb").read()
    off, n = 0, len(blob)
    while off + 20 <= n:
        ts, si, di, ln = struct.unpack(">d4s4sI", blob[off:off + 20])
        off += 20
        p = blob[off:off + ln]
        off += ln
        if len(p) != ln:
            break
        yield ts, si, di, p


def gen(p):
    if len(p) < 8:
        return None
    ptype, qtype, psize, seq = struct.unpack("<HHHH", p[:8])
    if qtype != 0 or len(p) < 20 or p[8] != 0x7E:
        return None
    tid = (p[10] << 8 | p[11]) >> 4
    final = (p[11] >> 3) & 1
    fid = ((p[11] & 0x07) << 8) | p[12]
    return dict(ptype=ptype, seq=seq, psize=psize, tid=tid, final=final, fid=fid,
                flags=p[13], svc=p[14], method=p[15],
                err=struct.unpack(">H", p[16:18])[0],
                glen=struct.unpack(">H", p[18:20])[0], payload=p[20:])


def main():
    tot = collections.Counter()
    per = collections.defaultdict(collections.Counter)
    examples = {}
    for path in sorted(glob.glob("out/evidence/truth/port*.bin")):
        for ts, si, di, p in records(path):
            g = gen(p)
            if not g:
                continue
            key = (path.split("/")[-1], g["ptype"], g["svc"], g["method"])
            per[key][g["glen"]] += 1
            tot[key] += 1
            examples.setdefault(key, (ts, g))
    print("%-16s %-5s %-4s %-6s %-22s %s" %
          ("file", "type", "svc", "method", "payload sizes:count", "first@t"))
    for key in sorted(tot):
        f, ptype, svc, meth = key
        sizes = ",".join("%d:%d" % (k, v) for k, v in sorted(per[key].items()))
        ts = examples[key][0]
        print("%-16s %-5d %-4d 0x%02x   %-22s t=%.3f" % (f, ptype, svc, meth, sizes, ts))

    print("\n--- presence check for update-related methods ---")
    watch = [(0, 0x02, "svc0 start product update"),
             (0, 0x03, "svc0 update data"),
             (0, 0x04, "svc0 end product update"),
             (0, 0x05, "svc0 abort update"),
             (0, 0x0b, "svc0 TVCode/Service/Screen start update"),
             (0, 0x0c, "svc0 TVCode/Service/Screen end update"),
             (0, 0x0d, "svc0 Lang start update"),
             (0, 0x0e, "svc0 Lang end update"),
             (0, 0x0f, "svc0 Lang update bank/version"),
             (4, 0x01, "svc4 reboot to mode (FWUPDATE=2)"),
             (5, 0x0c, "svc5 EEPROM write"),
             ]
    present = collections.Counter()
    for path in sorted(glob.glob("out/evidence/truth/port*.bin")):
        for ts, si, di, p in records(path):
            g = gen(p)
            if g:
                present[(g["svc"], g["method"], g["ptype"])] += 1
    for svc, meth, desc in watch:
        hits = {pt: c for (s, m, pt), c in present.items() if s == svc and m == meth}
        print("  svc %d 0x%02x  %-38s %s" %
              (svc, meth, desc, hits if hits else "ABSENT"))


if __name__ == "__main__":
    sys.exit(main())
