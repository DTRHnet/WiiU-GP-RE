#!/usr/bin/env python3
"""
Offline byte-level census of the VSTRM video header, console vs our stream.

Inputs (read-only):
  * out/evidence/truth/port50120.bin  -- decrypted real console->pad video
  * capture/phase4-clock-*.pcap / phase12-armed-*.pcap -- our sent video

Record format of port50120.bin (see capture/truth-decrypt.py):
  >d  8 bytes  arrival time (seconds, capture-relative)
  4s  4 bytes  "src"  -- actually VSTRM timestamp bytes b4..b7 (decryptor bug)
  4s  4 bytes  "dst"  -- actually ext-option bytes b8..b11   (decryptor bug)
  >I  4 bytes  payload length
  N bytes      UDP payload = 16-byte VSTRM header + chunk data

The "src"/"dst" fields are NOT IP addresses; truth-decrypt.py slices the UDP
payload (buf[12:16], buf[16:20]) instead of the IP header, so they reproduce
VSTRM header bytes. This tool only reads the correctly-written payload.

VSTRM header (16 bytes):
  b0  = 0xF0 | seq[9:8]        (low 2 bits)
  b1  = seq[7:0]
  b2  = flags(init|fb|ce|fe|ts) << 3 | len[10:8]
  b3  = len[7:0]
  b4..b7 = media timestamp (big-endian u32)
  b8..b15 = ext options, read until 0x00
"""
import collections
import struct
import sys


def parse_console(path):
    """Yield (arrival_s, payload) from a port50120.bin-style dump."""
    recs = []
    with open(path, "rb") as f:
        while True:
            hdr = f.read(20)
            if len(hdr) < 20:
                break
            ts, = struct.unpack(">d", hdr[0:8])
            ln, = struct.unpack(">I", hdr[16:20])
            pay = f.read(ln)
            if len(pay) < ln:
                break
            recs.append((ts, pay))
    return recs


def read_pcap_eth(path):
    """Yield (arrival_s, sport, dport, udp_payload) for Ethernet-linktype pcaps."""
    out = []
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        ts_scale = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            sec, frac, caplen, origlen = struct.unpack(endian + "IIII", hdr)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            if len(data) < 14 or data[12:14] != b"\x08\x00":
                continue
            ip = data[14:]
            if len(ip) < 20 or ip[9] != 17:
                continue
            ihl = (ip[0] & 0xF) * 4
            tot = struct.unpack(">H", ip[2:4])[0]
            udp = ip[ihl:tot]
            if len(udp) < 8:
                continue
            sport, dport, ulen = struct.unpack(">HHH", udp[0:6])
            pay = udp[8:ulen] if ulen >= 8 else udp[8:]
            out.append((sec + frac / ts_scale, sport, dport, pay))
    return out


FLAG_NAMES = ((0x10, "init"), (0x08, "fb"), (0x04, "ce"), (0x02, "fe"), (0x01, "ts"))


def seq_of(p):
    """10-bit sequence: b0[1:0] = seq[9:8], b1[7:0] = seq[7:0]."""
    return ((p[0] & 0x03) << 8) | p[1]


def census(name, recs):
    print("=" * 60)
    print("%s : %d packets" % (name, len(recs)))
    if not recs:
        return
    bad_magic = sum(1 for _, p in recs if (p[0] & 0xF0) != 0xF0)
    b0lo = collections.Counter(p[0] & 0x0F for _, p in recs)
    b1gt3f = sum(1 for _, p in recs if p[1] > 0x3F)
    print("b0 hi-nibble != 0xF: %d   b0[3:2] ever set: %d   b1>0x3F: %d" % (
        bad_magic, sum(1 for _, p in recs if p[0] & 0x0C), b1gt3f))
    print("b0 low-nibble dist: %s" % dict(sorted(b0lo.items())))

    seqs = [seq_of(p) for _, p in recs]
    gaps = sum(1 for i in range(1, len(seqs)) if (seqs[i] - seqs[i - 1]) % 1024 != 1)
    wraps = sum(1 for i in range(1, len(seqs)) if seqs[i - 1] > seqs[i])
    print("seq: max=%d  non-unit deltas=%d  wraps=%d" % (max(seqs), gaps, wraps))

    fc = collections.Counter(p[2] >> 3 for _, p in recs)
    print("flag combos (b2>>3):")
    for fv, c in sorted(fc.items()):
        bits = "".join("1" if fv & m else "0" for m, _ in FLAG_NAMES)
        print("   0x%02x (%s) : %d" % (fv, bits, c))

    mis = 0
    lens = collections.Counter()
    for _, p in recs:
        lf = ((p[2] & 7) << 8) | p[3]
        actual = len(p) - 16
        lens[actual] += 1
        if lf != actual:
            mis += 1
    print("length mismatches: %d   chunk sizes: %d distinct, max=%d (x%d)" % (
        mis, len(lens), max(lens), lens[max(lens)]))

    mts = [struct.unpack(">I", p[4:8])[0] for _, p in recs]
    print("media ts: 0x%08x .. 0x%08x  (big-endian)" % (min(mts), max(mts)))

    ext = collections.Counter(bytes(p[8:16]) for _, p in recs)
    print("ext options (8 bytes):")
    for s, c in ext.most_common():
        print("   %s : %d" % (s.hex(), c))
    codes = collections.Counter()
    for _, p in recs:
        for b in p[8:16]:
            if 0x80 <= b <= 0x8F:
                codes[b] += 1
    print("option bytes 0x80-0x8F seen: %s" % dict(sorted(codes.items())))


def frames(recs):
    fr, cur = [], []
    for i, (_, p) in enumerate(recs):
        if p[2] & 0x40:
            if cur:
                fr.append(cur)
            cur = []
        cur.append(i)
    if cur:
        fr.append(cur)
    return fr


def frame_stats(name, recs):
    fr = frames(recs)
    ft = [struct.unpack(">I", recs[f[0]][1][4:8])[0] for f in fr]
    deltas = collections.Counter((ft[i] - ft[i - 1]) & 0xFFFFFFFF for i in range(1, len(ft)))
    f0 = fr[0]
    return (len(fr), deltas.most_common(4),
            len(f0), sum(1 for i in f0 if recs[i][1][2] & 0x80),
            sum(1 for i in f0 if recs[i][1][8] == 0x80))


def main():
    console = parse_console("out/evidence/truth/port50120.bin")
    census("CONSOLE port50120.bin", console)
    nfr, dl, f0n, f0init, f0idr = frame_stats("console", console)
    print("console frames=%d  deltas=%s  first-frame(pkts=%d init=%d idr=%d)" % (
        nfr, dl, f0n, f0init, f0idr))
    print("console first-frame chunk sizes:", [len(console[i][1]) - 16 for i in frames(console)[0]])

    for cap in ["capture/phase4-clock-083313.pcap", "capture/phase12-armed-104826.pcap"]:
        pkts = read_pcap_eth(cap)
        vid = [(t, p) for t, s, d, p in pkts if d == 50120]
        print()
        census("OURS %s (dport 50120)" % cap, vid)
        nfr, dl, f0n, f0init, f0idr = frame_stats("ours", vid)
        print("ours frames=%d  deltas=%s  first-frame(pkts=%d init=%d idr=%d)" % (
            nfr, dl, f0n, f0init, f0idr))


if __name__ == "__main__":
    sys.exit(main())
