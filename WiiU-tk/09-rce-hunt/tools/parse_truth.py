#!/usr/bin/env python3
"""Reproducible offline parser for the decrypted ground-truth dumps in
out/evidence/truth/ (READ-ONLY; writes only under research/rce-hunt/).

Record format of every port*.bin / udp-payloads.bin dump
-------------------------------------------------------
Written by capture/truth-decrypt.py lines 555-559:

    struct.pack(">d4s4sI", ts, si, di, len(p)) + p        # port*.bin
    struct.pack(">d4s4sHH", ts, si, di, sport, dport) + p # udp-payloads.bin (NO length!)

  off  size field
  0    8    ts   big-endian IEEE-754 double, seconds since capture t0
  8    4    si   (nominal src ip)      <-- see NOTE
  12   4    di   (nominal dst ip)      <-- see NOTE
  16   4    len  big-endian u32 payload length          [port*.bin only]
  20   len  p    decrypted UDP payload

NOTE on si/di: in the files on disk these two 4-byte fields are NOT IP
addresses; they are byte-for-byte equal to payload[4:8] and payload[8:12].
(First record of port67.bin: si=13572bea and di=00008000 while payload[4:12]
= 13572bea 00008000 -- the DHCP xid/secs/flags; the real IPs, 0.0.0.0 and
255.255.255.255, appear nowhere.)  The extractor that produced these dumps
therefore had an offset bug in the si/di capture; the framing (ts + 8 filler
+ u32 length + payload) is nevertheless exact: every one of the 8 dumps parses
to EOF with 0 leftover bytes and the record counts match flows.json exactly.
Direction is recovered from the file name: dump portN contains the datagrams
whose DESTINATION port is N (selection is `dpp == port`, line 553/554), so
    port50123.bin = console -> pad  (dport 50123)
    port50023.bin = pad -> console  (dport 50023)

Usage: python3 research/rce-hunt/tools/parse_truth.py [section ...]
       sections: 1 2 3 4 5 6 7 8 9 10 11 all   (default: all)
"""
import collections
import hashlib
import os
import struct
import sys

TRUTH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "..", "..", "out", "evidence", "truth")
TRUTH = os.path.normpath(TRUTH)
OUTDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "tables"))

BE12 = None  # helper, see gh()


# ------------------------------------------------------------------ framing
def records(name):
    """Yield (index, ts, payload) for a port dump; asserts exact EOF."""
    path = os.path.join(TRUTH, name)
    blob = open(path, "rb").read()
    off, n = 0, 0
    while off < len(blob):
        if off + 20 > len(blob):
            raise SystemExit("%s: truncated header at %d" % (name, off))
        ts, si, di, ln = struct.unpack(">d4s4sI", blob[off:off + 20])
        off += 20
        p = blob[off:off + ln]
        if len(p) != ln:
            raise SystemExit("%s: truncated payload at %d" % (name, off))
        off += ln
        yield n, ts, p, si, di
        n += 1
    if off != len(blob):
        raise SystemExit("%s: %d trailing bytes" % (name, len(blob) - off))


def rl(name):
    return list(records(name))


# ------------------------------------------------------------------ codecs
def cmd_hdr(p):
    """CmdHeader: le16 packet_type, query_type, payload_size, seq_id."""
    t, q, sz, sq = struct.unpack("<HHHH", p[:8])
    return dict(type=t, query=q, declared=sz, seq=sq, body=p[8:])


def gh(g):
    """GenericCmdHeader (12 bytes):
        0 u8 magic 0x7E | 1 u8 version | 2..3 be12 tid | 3..4 be12 frag
        5 flags | 6 service | 7 method | 8..9 be16 error | 10..11 be16 len
    tid  = (g[2] << 4) | (g[3] >> 4)
    frag = ((g[3] & 0x0F) << 8) | g[4]
    """
    return dict(magic=g[0], ver=g[1], tid=(g[2] << 4) | (g[3] >> 4),
                frag=((g[3] & 0x0F) << 8) | g[4], flags=g[5], svc=g[6],
                meth=g[7], err=struct.unpack(">H", g[8:10])[0],
                glen=struct.unpack(">H", g[10:12])[0],
                payload=g[12:])


def hx(b, base=0, per=16, limit=None):
    """xxd-style hexdump with absolute offsets."""
    out = []
    n = len(b) if limit is None else min(len(b), limit)
    for o in range(0, n, per):
        chunk = b[o:o + per]
        h = " ".join("%02x" % c for c in chunk)
        a = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("%08x  %-*s  |%s|" % (base + o, per * 3 - 1, h, a))
    if limit is not None and len(b) > limit:
        out.append("... (%d more bytes)" % (len(b) - limit))
    return "\n".join(out)


def bar(c, n, width=60):
    k = int(round(n * width / float(c))) if c else 0
    return "#" * k


# ================================================================== §1 + §2
def sec1_2(console, pad):
    """cmd outer header distribution over both directions."""
    L = []
    for name, tag in (("port50123.bin", "console->pad"), ("port50023.bin", "pad->console")):
        R = rl(name)
        L.append("### %s (%s): %d records, %d bytes" %
                 (name, tag, len(R), os.path.getsize(os.path.join(TRUTH, name))))
        groups = collections.defaultdict(list)
        mism = []
        for i, ts, p, si, di in R:
            c = cmd_hdr(p)
            groups[(c["type"], c["query"], c["declared"], len(p) - 8)].append((i, c["seq"]))
            if c["declared"] != len(p) - 8:
                mism.append((i, c["declared"], len(p) - 8))
        L.append("")
        L.append("| packet_type | query_type | declared payload_size | actual len-8 | n | "
                 "distinct declared | seq first..last |")
        L.append("|---|---|---|---|---|---|---|")
        for k in sorted(groups):
            v = groups[k]
            L.append("| %d | %d | %d | %d | %d | %d | %d..%d |" %
                     (k[0], k[1], k[2], k[3], len(v), len({x[1] for x in v}),
                      min(x[1] for x in v), max(x[1] for x in v)))
        L.append("")
        L.append("records where declared_len != actual_len-8: **%d**  %s" %
                 (len(mism), mism[:10]))
        # seq behaviour
        seqs = [cmd_hdr(p)["seq"] for i, ts, p, si, di in R]
        L.append("")
        L.append("seq_id: n=%d min=%d max=%d distinct=%d ; repeats=%d ; "
                 "deltas (per record, sorted histogram)=%s" %
                 (len(seqs), min(seqs), max(seqs), len(set(seqs)),
                  len(seqs) - len(set(seqs)),
                  sorted(collections.Counter(
                      (seqs[i + 1] - seqs[i]) for i in range(len(seqs) - 1)).items())))
        # gaps
        s = sorted(set(seqs))
        gaps = [(a, b) for a, b in zip(s, s[1:]) if b - a > 1]
        L.append("integer gaps in the union of seq values: %d %s" %
                 (len(gaps), gaps[:12]))
        # type ordering
        L.append("type transition pairs: %s" % sorted(
            collections.Counter((cmd_hdr(R[i][2])["type"], cmd_hdr(R[i + 1][2])["type"])
                                for i in range(len(R) - 1)).items()))
        L.append("")
    # full tables on disk
    for name in ("port50123.bin", "port50023.bin"):
        path = os.path.join(OUTDIR, name.replace(".bin", "-records.tsv"))
        with open(path, "w") as f:
            f.write("idx\tt_s\tpacket_type\tquery_type\tdeclared_payload_size\t"
                    "actual_len_minus_8\tseq_id\tudp_payload_len\n")
            for i, ts, p, si, di in rl(name):
                c = cmd_hdr(p)
                f.write("%d\t%.6f\t%d\t%d\t%d\t%d\t%d\t%d\n" %
                        (i, ts, c["type"], c["query"], c["declared"], len(p) - 8,
                         c["seq"], len(p)))
        L.append("wrote %s" % path)
    return "\n".join(L)


def sec2(console, pad):
    L = ["## generic header (magic 0x7E) -- console->pad queries"]
    # distribution over ALL console->pad records carrying a generic header
    dist = collections.Counter()
    tids = collections.defaultdict(list)
    for i, ts, p, si, di in console:
        c = cmd_hdr(p)
        if c["query"] != 0 or len(c["body"]) < 12:
            continue
        g = gh(c["body"])
        dist[(c["declared"], g["magic"], g["ver"], g["frag"], g["flags"],
              g["svc"], g["meth"], g["err"], g["glen"])] += 1
        tids[(c["declared"], g["frag"], g["flags"])].append((i, g["tid"]))
    L.append("")
    L.append("magic value(s) seen in console->pad generic headers: %s ; version(s): %s ; "
             "error_code(s): %s" % (sorted({"0x%02x" % k[1] for k in dist}),
                                    sorted({k[2] for k in dist}),
                                    sorted({k[7] for k in dist})))
    L.append("")
    L.append("| cmd.len | magic | ver | frag | flags | svc | meth | err | glen | n | tid values |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for k, n in sorted(dist.items()):
        t = sorted({x[1] for x in tids[(k[0], k[3], k[4])]})
        L.append("| %d | 0x%02x | %d | 0x%03x | 0x%02x | %d | 0x%02x | %d | %d | %d | %s |" %
                 (k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], n,
                  ("%d..%d (%d distinct)" % (min(t), max(t), len(t))) if len(t) > 3
                  else ", ".join(str(x) for x in t)))
    L.append("")
    # ---- the 778 x 1040 UIC state blobs
    blobs = [(i, ts, cmd_hdr(p)) for i, ts, p, si, di in console
             if cmd_hdr(p)["query"] == 0 and cmd_hdr(p)["declared"] == 1040]
    L.append("### 778 x 1048-byte datagrams (cmd type 0/query 0/declared 1040)")
    L.append("")
    gs = [(i, ts, c, gh(c["body"])) for i, ts, c in blobs]
    L.append("magic set = %s ; version set = %s ; svc set = %s ; meth set = %s ; "
             "err set = %s ; glen set = %s" %
             (sorted({g["magic"] for _, _, _, g in gs}),
              sorted({g["ver"] for _, _, _, g in gs}),
              sorted({g["svc"] for _, _, _, g in gs}),
              sorted({"0x%02x" % g["meth"] for _, _, _, g in gs}),
              sorted({g["err"] for _, _, _, g in gs}),
              sorted({g["glen"] for _, _, _, g in gs})))
    L.append("flags histogram = %s" % sorted(collections.Counter(
        "0x%02x" % g["flags"] for _, _, _, g in gs).items()))
    L.append("frag histogram  = %s" % sorted(collections.Counter(
        "0x%03x" % g["frag"] for _, _, _, g in gs).items()))
    L.append("tid range = %d..%d, distinct = %d" % (min(g["tid"] for _, _, _, g in gs),
                                                    max(g["tid"] for _, _, _, g in gs),
                                                    len({g["tid"] for _, _, _, g in gs})))
    # flags sequence of first 40 and last 10
    L.append("")
    L.append("per-record (flags, frag, tid) sequence, first 40:")
    L.append("```")
    L.append("  ".join("%d:%02x/%03x/%d" % (i, g["flags"], g["frag"], g["tid"])
                        for i, _, _, g in gs[:40]))
    L.append("```")
    L.append("last 10:")
    L.append("```")
    L.append("  ".join("%d:%02x/%03x/%d" % (i, g["flags"], g["frag"], g["tid"])
                        for i, _, _, g in gs[-10:]))
    L.append("```")
    # grouping
    runs = []
    for i, ts, c, g in gs:
        key = (g["tid"], g["flags"] & 0x02)
        if runs and runs[-1][0] == key:
            runs[-1][1] += 1
        else:
            runs.append([key, 1, i, g["frag"]])
    L.append("")
    L.append("grouping (tid, flags&2) -> run lengths: %s ; number of runs = %d" %
             (sorted(collections.Counter(r[1] for r in runs).items()), len(runs)))
    L.append("group pattern (first 12 groups): %s" %
             [(r[0], r[1], "0x%03x" % r[3], r[2]) for r in runs[:12]])
    L.append("tid reuse: tid->count histogram = %s" %
             sorted(collections.Counter(
                 collections.Counter(g["tid"] for _, _, _, g in gs).values()).items()))
    # payload structure
    P = [g["payload"] for _, _, _, g in gs]
    idx = [struct.unpack(">I", p[:4])[0] for p in P]
    L.append("")
    L.append("generic payload (1028 B) structure:")
    L.append("* u32 be at payload[0:4] = %d..%d over %d records ; strictly +1 in "
             "datagram order: %s ; distinct: %d ; min=%d max=%d" %
             (min(idx), max(idx), len(idx),
              idx == list(range(idx[0], idx[0] + len(idx))), len(set(idx)),
              min(idx), max(idx)))
    # trailing zeros: where does the last nonzero byte sit
    lastnz = []
    const = collections.Counter()
    zero_const = 0
    off_rng = []
    for o in range(1028):
        vals = {p[o] for p in P}
        if len(vals) == 1:
            const[(o, vals.pop())] += 1
            if const[(o, 0)]:
                pass
        off_rng.append(len(vals))
    for o in range(1028):
        v = {p[o] for p in P}
        if len(v) == 1 and 0 in v:
            zero_const += 1
    for p in P:
        k = len(p) - 1
        while k >= 0 and p[k] == 0:
            k -= 1
        lastnz.append(k)
    L.append("* offsets whose byte value is constant 0x00 across all 778 payloads: "
             "**%d of 1028**" % zero_const)
    L.append("* offsets whose byte value is constant (any value): %d" %
             sum(1 for o in range(1028) if len({p[o] for p in P}) == 1))
    L.append("* index of last non-zero byte per payload: min=%d max=%d ; "
             "histogram(bucket of 64)=%s" %
             (min(lastnz), max(lastnz),
              sorted(collections.Counter(l // 64 * 64 for l in lastnz).items())))
    L.append("* first offset after payload[0:4] that is non-zero in record 0: %d" %
             next((o for o in range(4, 1028) if P[0][o]), None))
    L.append("* per-offset distinct-value-count: mean=%.2f, max=%d at offsets %s" %
             (sum(off_rng) / 1028.0, max(off_rng),
              [o for o in range(1028) if off_rng[o] == max(off_rng)][:12]))
    # byte frequency over the whole 778*1028 byte space
    allb = b"".join(P)
    fr = collections.Counter(allb)
    tot = float(len(allb))
    ent = -sum((c / tot) * __import__("math").log2(c / tot) for c in fr.values())
    L.append("* byte frequency over all %d payload bytes: 0x00 = %d (%.2f%%), "
             "distinct values = %d, Shannon entropy = %.3f bit/byte" %
             (len(allb), fr[0], 100.0 * fr[0] / tot, len(fr), ent))
    L.append("* top 12 byte values: %s" %
             ["0x%02x:%d(%.1f%%)" % (v, c, 100.0 * c / tot)
              for v, c in fr.most_common(12)])
    # is the varying region a table of repeated 4-byte words?
    words = collections.Counter()
    for p in P:
        for o in range(4, 1028 - 3, 4):
            words[p[o:o + 4]] += 1
    L.append("* 4-byte words at aligned offsets [4,1028): distinct=%d ; top 8 = %s" %
             (len(words), ["%s x%d" % (w.hex(), c) for w, c in words.most_common(8)]))
    # dump one payload in full + the distinct-region boundaries
    with open(os.path.join(OUTDIR, "uic-1040-record0.bin"), "wb") as f:
        f.write(blobs[0][2]["body"])          # cmd header + generic + payload
    L.append("")
    L.append("record 0 (seq %d) generic payload, first 96 bytes:" % blobs[0][2]["seq"])
    L.append("```")
    L.append(hx(P[0], 0, 16, 96))
    L.append("```")
    L.append("record 0, byte ranges that are non-zero in ANY record (compressed):")
    nz = [o for o in range(1028) if any(p[o] for p in P)]
    rngs = []
    for o in nz:
        if rngs and o == rngs[-1][1] + 1:
            rngs[-1][1] = o
        else:
            rngs.append([o, o])
    L.append("  " + ", ".join("%d-%d" % (a, b) if a != b else "%d" % a for a, b in rngs))
    return "\n".join(L)


# ================================================================== §3
def sec3(pad):
    L = ["## pad -> console (port50023.bin): replies"]
    R = rl("port50023.bin")
    # ack vs reply grouping: pair each type-1 ack with the console query it acks
    con = rl("port50123.bin")
    q_by_seq = collections.defaultdict(list)
    for i, ts, p, si, di in con:
        c = cmd_hdr(p)
        if c["type"] == 0:
            q_by_seq[c["seq"]].append((i, ts, c))
    rows = []
    nongeneric = collections.Counter()
    flg = collections.Counter()
    err = collections.Counter()
    mism = []
    zero_len_pairs = collections.Counter()
    for i, ts, p, si, di in R:
        c = cmd_hdr(p)
        q = q_by_seq.get(c["seq"])
        qt = q[0][2] if q else None
        if c["type"] == 2 and len(c["body"]) >= 12 and c["body"][0] == 0x7E:
            g = gh(c["body"])
            exp = ((gh(qt["body"])["flags"] >> 3) & 0xFC) | 1 if qt and len(qt["body"]) >= 12 else None
            flg[("0x%02x" % g["flags"], "exp 0x%02x" % exp if exp is not None else "?")] += 1
            err[g["err"]] += 1
            if g["glen"] != len(c["body"]) - 12:
                mism.append((i, g["glen"], len(c["body"]) - 12))
            if qt:
                zero_len_pairs[(qt["type"], qt["query"], qt["declared"],
                                g["svc"], g["meth"], g["glen"], g["flags"])] += 1
        elif c["type"] == 2:
            zero_len_pairs[("no-0x7E", c["query"], c["declared"], -1, -1, -1, -1)] += 1
            nongeneric[(c["query"], c["declared"], c["body"].hex())] += 1
    L.append("")
    L.append("### reply generic-header flags vs documented echo ((q.flags>>3)&0xFC|1)")
    L.append("| pad reply flags | documented prediction | n |")
    L.append("|---|---|---|")
    for k, n in sorted(flg.items()):
        L.append("| %s | %s | %d |" % (k[0], k[1], n))
    L.append("")
    L.append("### error_code histogram over generic replies: %s" %
             sorted(("0x%04x" % k, v) for k, v in err.items()))
    L.append("")
    L.append("### generic payload_size vs actual (glen != len(body)-12): %d  %s" %
             (len(mism), mism[:10]))
    L.append("")
    L.append("### query -> reply mapping (qtype, qquery, qdeclared, svc, meth, reply_glen, reply_flags)")
    L.append("| q.type | q.query | q.declared | reply svc | reply meth | reply glen | reply flags | n |")
    L.append("|---|---|---|---|---|---|---|---|")
    for k, n in sorted(zero_len_pairs.items(), key=lambda x: (str(x[0]))):
        L.append("| %s | %s | %s | %s | %s | %s | %s | %d |" %
                 (k[0], k[1], k[2], k[3], ("0x%02x" % k[4]) if k[4] >= 0 else "-",
                  k[5], ("0x%02x" % k[6]) if k[6] >= 0 else "-", n))
    L.append("")
    L.append("### reply bodies that are NOT a generic command (body[0] != 0x7E)")
    L.append("| q.query | reply cmd.payload_size | body (hex) | n |")
    L.append("|---|---|---|---|")
    for (q, dcl, b), n in sorted(nongeneric.items(), key=lambda x: (-x[1], x[0])):
        L.append("| %d | %d | `%s` | %d |" % (q, dcl, b, n))
    L.append("")
    L.append("### 8-byte replies (no generic header) = pure acks")
    z = collections.Counter()
    for i, ts, p, si, di in R:
        c = cmd_hdr(p)
        if len(c["body"]) == 0:
            z[(c["type"], c["query"])] += 1
    L.append("%s" % sorted(z.items()))
    # the 5 x 792 byte UIC config replies
    L.append("")
    L.append("### the 5 x 792-byte UIC config replies (cmd type 2/query 0/declared 784)")
    blob = []
    for i, ts, p, si, di in R:
        c = cmd_hdr(p)
        if c["declared"] == 784:
            g = gh(c["body"])
            blob.append((i, ts, p, c, g))
    for i, ts, p, c, g in blob:
        L.append("")
        L.append("record %d @ t=%8.3fs seq=%d: %s" % (i, ts, c["seq"], p.hex()[:40] + "..."))
        L.append("  outer: type=%d query=%d payload_size=%d seq=%d ; body=%dB" %
                 (c["type"], c["query"], c["declared"], c["seq"], len(c["body"])))
        L.append("  generic: magic=0x%02x ver=%d tid=%d frag=0x%03x flags=0x%02x "
                 "svc=%d meth=0x%02x err=%d glen=%d (actual %d)" %
                 (g["magic"], g["ver"], g["tid"], g["frag"], g["flags"], g["svc"],
                  g["meth"], g["err"], g["glen"], len(g["payload"])))
        L.append("  first 64 bytes of generic payload:")
        L.append("```")
        L.append(hx(g["payload"], 0, 16, 64))
        L.append("```")
    h = {hashlib.sha256(b[4]["payload"]).hexdigest()[:16] for b in blob}
    L.append("")
    L.append("distinct 772-byte payloads (sha256) = %d -> %s" % (len(h), sorted(h)))
    L.append("differing byte offsets between payload[0] and payload[4]: %s" %
             [o for o in range(len(blob[0][4]["payload"]))
              if blob[0][4]["payload"][o] != blob[-1][4]["payload"][o]])
    with open(os.path.join(OUTDIR, "uic-792-reply0.bin"), "wb") as f:
        f.write(blob[0][2])
    return "\n".join(L)


# ================================================================== §4/§5
def sec4_5(console, pad):
    L = ["## query type 1 (UVC/UAC) and query type 2 (time)"]
    uv = [(i, ts, cmd_hdr(p)) for i, ts, p, si, di in console
          if cmd_hdr(p)["query"] == 1 and cmd_hdr(p)["type"] == 0]
    bodies = collections.OrderedDict()
    seqb0 = []
    for i, ts, c in uv:
        key = c["body"]
        bodies.setdefault(key, []).append((i, ts, c["seq"]))
        seqb0.append((ts, c["seq"], c["body"][0]))
    L.append("### type 0/query 1: %d records, declared=%s, datagram=%s" %
             (len(uv), sorted({c["declared"] for _, _, c in uv}),
              sorted({len(c["body"]) + 8 for _, _, c in uv})))
    L.append("distinct 48-byte bodies = %d" % len(bodies))
    for k, v in bodies.items():
        L.append("")
        L.append("body %s  (n=%d, first t=%.3fs seq=%d, last t=%.3fs seq=%d)" %
                 (hashlib.sha256(k).hexdigest()[:12], len(v), v[0][1], v[0][2],
                  v[-1][1], v[-1][2]))
        L.append("```")
        L.append(hx(k, 0, 16))
        L.append("```")
        L.append("byte[0]=0x%02x byte[1..2]=0x%04x byte[3]=0x%02x byte[4]=0x%02x "
                 "byte[5]=0x%02x byte[6:8]=%d byte[8:10]=%d" %
                 (k[0], struct.unpack(">H", k[1:3])[0], k[3], k[4], k[5],
                  struct.unpack(">h", k[6:8])[0], struct.unpack(">h", k[8:10])[0]))
        L.append("byte[0] distinct values = %s" % sorted({x[2] for x in v}))
    L.append("")
    L.append("byte[0] over time: first 6 and last 4 (t, seq, b0): %s ... %s" %
             ([(round(t, 2), s, b) for t, s, b in seqb0[:6]],
              [(round(t, 2), s, b) for t, s, b in seqb0[-4:]]))
    chg = [(round(t, 2), s, b) for (t, s, b), prev in zip(seqb0[1:], seqb0[:-1]) if b != prev[2]]
    L.append("byte[0] transitions = %s" % chg)
    # the pad's answers to the UVC query
    rep = collections.Counter()
    for i, ts, p, si, di in pad:
        c = cmd_hdr(p)
        if c["query"] == 1:
            rep[(c["type"], c["declared"], c["body"].hex())] += 1
    L.append("")
    L.append("pad answers with query=1: %s" % sorted(rep.items()))
    # ---- time
    L.append("")
    L.append("### type 0/query 2 (TimeCommand): 8-byte payload")
    L.append("| idx | t (s) | seq | raw 8 bytes | u16 days_counter | u16 padding | u32 seconds_counter |")
    L.append("|---|---|---|---|---|---|---|")
    for i, ts, p, si, di in console:
        c = cmd_hdr(p)
        if c["query"] == 2 and c["type"] == 0:
            d, pad_, s = struct.unpack("<HHI", c["body"][:8])
            L.append("| %d | %.3f | %d | %s | %d (0x%04x) | %d | %d (0x%08x) |" %
                     (i, ts, c["seq"], c["body"].hex(), d, d, pad_, s, s))
    return "\n".join(L)


# ================================================================== §6 vstrm
def sec6():
    L = ["## vstrm (port50120.bin)"]
    R = rl("port50120.bin")
    L.append("records = %d" % len(R))
    plen = collections.Counter(len(p) for _, _, p, _, _ in R)
    L.append("UDP payload sizes: min=%d max=%d distinct=%d ; top 6 = %s ; "
             "count at max = %d" %
             (min(plen), max(plen), len(plen),
              ["%dB x%d" % (k, v) for k, v in plen.most_common(6)], plen[max(plen)]))
    bad = []
    seqs = []
    seqs_doc = []
    times = []
    flags = collections.Counter()
    exts = collections.Counter()
    nopts = collections.Counter()
    for i, ts, p, si, di in R:
        b0, b1, b2, b3 = p[0], p[1], p[2], p[3]
        seq = ((b0 & 0x03) << 8) | b1          # measured: 2 bits in b0 + 8 bits in b1
        seq_doc = (b1 << 2) | 3               # what the documented libdrc bitfield yields
        f_init = (b2 >> 7) & 1
        f_fb = (b2 >> 6) & 1
        f_ce = (b2 >> 5) & 1
        f_fe = (b2 >> 4) & 1
        f_ts = (b2 >> 3) & 1
        ln = ((b2 & 0x07) << 8) | b3
        flags[(b0 >> 4, f_init, f_fb, f_ce, f_fe, f_ts)] += 1
        hdr = 8 if not f_ts else 12
        if f_ts:
            hdr = 12
        # 4-byte header when no timestamp / extended header?
        if f_ts:
            t = struct.unpack("<I", p[4:8])[0]
            ext = p[8:16]
            hdr = 16
        else:
            t = None
            ext = p[4:12]
            hdr = 12
        exts[ext] += 1
        n = 0
        while n < 8 and ext[n] != 0:
            n += 2 if ext[n] in (0x81, 0x82, 0x85) else 1
        nopts[(ext[:8].hex(), n)] += 1
        seqs.append(seq)
        seqs_doc.append(seq_doc)
        times.append(t)
        if ln != len(p) - hdr:
            bad.append((i, ln, len(p) - hdr, f_ts))
    L.append("")
    L.append("### header decode check (b0=0xF0|seq[9:6], b1=seq[5:0], "
             "b2=init|fb|ce|fe|ts|len[10:8], b3=len[7:0], ts at 4..7)")
    L.append("distinct (b0>>4) values = %s (every record starts 0xF0..0xF3)" %
             sorted({d[0] for d in flags}))
    L.append("records where declared payload_size != len(p)-16 (ts always 1): **%d** %s" %
             (len(bad), bad[:6]))
    L.append("")
    L.append("### flag-bit combinations")
    L.append("| b0>>4 | init | frame_begin | chunk_end | frame_end | ts_present | n |")
    L.append("|---|---|---|---|---|---|---|")
    for k, n in sorted(flags.items()):
        L.append("| 0x%x | %d | %d | %d | %d | %d | %d |" % (k[0], k[1], k[2], k[3], k[4], k[5], n))
    L.append("")
    L.append("init count = %d ; frame_begin = %d ; chunk_end = %d ; frame_end = %d" %
             (sum(v for k, v in flags.items() if k[1]),
              sum(v for k, v in flags.items() if k[2]),
              sum(v for k, v in flags.items() if k[3]),
              sum(v for k, v in flags.items() if k[4])))
    L.append("")
    L.append("### extended header (8 bytes at offset 8..15 when ts present)")
    L.append("| ext bytes | n | parsed option length |")
    L.append("|---|---|---|")
    for (e, n), c in sorted(nopts.items(), key=lambda x: -x[1]):
        L.append("| `%s` | %d | %d |" % (" ".join(e[i:i + 2] for i in range(0, 16, 2)), c, n))
    L.append("")
    L.append("### sequence number -- CORRECTED layout")
    L.append("b0 = 0xF0 | seq[9:8] ; b1 = seq[7:0] ; seq = ((b0 & 0x03) << 8) | b1")
    L.append("b0 value histogram = %s" % sorted(collections.Counter(
        "0x%02x" % R[i][2][0] for i in range(len(R))).items()))
    L.append("b1 range = %d..%d (%d distinct values, every one used)" %
             (min(R[i][2][1] for i in range(len(R))), max(R[i][2][1] for i in range(len(R))),
              len({R[i][2][1] for i in range(len(R))})))
    d = collections.Counter(b - a for a, b in zip(seqs, seqs[1:]))
    L.append("min=%d max=%d distinct=%d ; full 1023->0 wraps = %d ; "
             "byte-identical repeats = %d ; max forward jump = %d ; max backward jump = %d" %
             (min(seqs), max(seqs), len(set(seqs)),
              sum(1 for a, b in zip(seqs, seqs[1:]) if a == 1023 and b == 0),
              len(seqs) - len(set(seqs)),
              max(b - a for a, b in zip(seqs, seqs[1:])),
              min(b - a for a, b in zip(seqs, seqs[1:]))))
    L.append("delta histogram = %s" % sorted(d.items()))
    anom = [(a, b, b - a) for a, b in zip(seqs, seqs[1:]) if b - a not in (1, -1023)]
    L.append("anomalous transitions (everything except +1 and the clean 1023->0 wrap): "
             "%d -> %s" % (len(anom), anom))
    L.append("b0[1:0] transition on every b1 255->0 step: %s" %
             sorted(collections.Counter(
                 ((a[2][0] & 3), (b[2][0] & 3)) for a, b in zip(R, R[1:])
                 if a[2][1] == 255 and b[2][1] == 0).items()))
    dd = collections.Counter(b - a for a, b in zip(seqs_doc, seqs_doc[1:]))
    L.append("")
    L.append("FALSIFICATION of the 4+6 layout claimed in GROUND-TRUTH sec-4 "
             "(b0=0xF0|seq[9:6], b1=seq[5:0], i.e. seq=((b0&0x0f)<<6)|(b1&0x3f)):")
    gt = [((p[0] & 0x0F) << 6) | (p[1] & 0x3F) for _, _, p, _, _ in R]
    dg = collections.Counter(b - a for a, b in zip(gt, gt[1:]))
    L.append("  under that reading the sequence has %d discontinuities %s and only "
             "%d distinct values (a 10-bit field must hold 1024)" %
             (sum(1 for k in dg if k != 1), sorted(dg.items()),
              len(set(gt))))
    L.append("  b1 reaches 255 (%d times), so it cannot be a 6-bit field" %
             sum(1 for x in seqs if x & 0xFF == 0xFF))
    L.append("  the 2+8 reading yields %d of %d deltas == +1 and %d clean 1023->0 wraps" %
             (d[1], len(seqs) - 1, d[-1023]))
    # frames
    frames = []
    cur = []
    for i, ts, p, si, di in R:
        b2 = p[2]
        ln = ((b2 & 0x07) << 8) | p[3]
        cur.append(i)
        if (b2 >> 4) & 1:
            frames.append(cur)
            cur = []
    if cur:
        frames.append(cur)
    L.append("")
    L.append("### frames (delimited by frame_end)")
    L.append("frames = %d ; packets/frame histogram = %s" %
             (len(frames), sorted(collections.Counter(len(f) for f in frames).items())))
    f1 = frames[0]
    L.append("frame 0 = records %d..%d (%d packets)" % (f1[0], f1[-1], len(f1)))
    L.append("frame-0 packet payload sizes = %s" %
             sorted(collections.Counter(len(R[i][2]) for i in f1).items()))
    L.append("frame-0 chunk data bytes = sum(payload_size) = %d" %
             sum((((R[i][2][2] & 0x07) << 8) | R[i][2][3]) for i in f1))
    L.append("frame-0 chunk_end packets = %d ; init packets = %d" %
             (sum(1 for i in f1 if (R[i][2][2] >> 5) & 1),
              sum(1 for i in f1 if (R[i][2][2] >> 7) & 1)))
    L.append("")
    L.append("frame 0, packet 0 -- full 1710-byte datagram header + first 96 B:")
    p0 = R[f1[0]][2]
    L.append("```")
    L.append(hx(p0, 0, 16, 96))
    L.append("```")
    L.append("frame 0, packet 1 -- first 96 B:")
    p1 = R[f1[1]][2]
    L.append("```")
    L.append(hx(p1, 0, 16, 96))
    L.append("```")
    L.append("frame-0 packet headers (idx, seq, init,fb,ce,fe,ts,len,timestamp,ext):")
    for i in f1[:25]:
        p = R[i][2]
        seq = ((p[0] & 0x03) << 8) | p[1]
        L.append("  rec %3d seq=%3d in=%d fb=%d ce=%d fe=%d ts=%d len=%4d t=%08x ext=%s" %
                 (i, seq, (p[2] >> 7) & 1, (p[2] >> 6) & 1, (p[2] >> 5) & 1,
                  (p[2] >> 4) & 1, (p[2] >> 3) & 1,
                  ((p[2] & 7) << 8) | p[3], struct.unpack("<I", p[4:8])[0],
                  p[8:16].hex()))
    # timestamp progression
    tv = [t for t in times if t is not None]
    L.append("")
    L.append("timestamps present on %d/%d records ; ts deltas histogram = %s" %
             (len(tv), len(times),
              sorted(collections.Counter(b - a for a, b in zip(tv, tv[1:])).items())))
    L.append("ts wrap (u32) events = %d ; first ts = 0x%08x (%.0f us) ; last = 0x%08x" %
             (sum(1 for a, b in zip(tv, tv[1:]) if b < a), tv[0], tv[0], tv[-1]))
    with open(os.path.join(OUTDIR, "frame0-packets.bin"), "wb") as f:
        for i in f1:
            f.write(R[i][2])
    return "\n".join(L)


# ================================================================== §7 astrm
def sec7():
    L = ["## astrm (port50121.bin)"]
    R = rl("port50121.bin")
    L.append("records = %d" % len(R))
    aud, vfmt, other = [], [], []
    for r in R:
        i, ts, p, si, di = r
        if len(p) < 8:
            other.append(r)
            continue
        w = struct.unpack("<H", p[0:2])[0]
        typ = (w >> 5) & 1
        (aud if typ == 0 else vfmt).append(r)
    for tag, S in (("audio (type=0)", aud), ("video-format (type=1)", vfmt),
                   ("short/other", other)):
        L.append("%-22s n=%6d  sizes=%s" % (tag, len(S),
                                            sorted(collections.Counter(len(x[2]) for x in S).items())[:6]))
    L.append("")
    L.append("### audio packets")
    hdr = collections.Counter()
    psz_ok = 0
    psz_bad = []
    tv = []
    fields = collections.Counter()
    for i, ts, p, si, di in aud:
        w = struct.unpack("<H", p[0:2])[0]
        fmt = w & 0x7
        mono = (w >> 3) & 1
        vib = (w >> 4) & 1
        typ = (w >> 5) & 1
        seq = (w >> 6) & 0x3FF
        ps = struct.unpack(">H", p[2:4])[0]
        t = struct.unpack("<I", p[4:8])[0]
        hdr[p[0:8].hex()] += 1
        fields[(fmt, mono, vib, typ)] += 1
        tv.append(t)
        if ps == len(p) - 8:
            psz_ok += 1
        else:
            psz_bad.append((i, ps, len(p) - 8))
    L.append("distinct 8-byte headers = %d ; most common = %s" %
             (len(hdr), hdr.most_common(3)))
    L.append("(format, mono, vibrate, type) histogram = %s" % sorted(fields.items()))
    L.append("payload_size == actual-8 : %d/%d ; mismatches = %d %s" %
             (psz_ok, len(aud), len(psz_bad), psz_bad[:6]))
    L.append("payload_size values = %s" %
             sorted(collections.Counter(struct.unpack(">H", p[2:4])[0] for _, _, p, _, _ in aud).items()))
    L.append("timestamp deltas (us) = %s" %
             sorted(collections.Counter(b - a for a, b in zip(tv, tv[1:])).items())[:12])
    L.append("u32 ts wraps = %d ; first=0x%08x (%.0f us) ; last=0x%08x (%.0f us)" %
             (sum(1 for a, b in zip(tv, tv[1:]) if b < a), tv[0], tv[0], tv[-1], tv[-1]))
    L.append("seq_id (10-bit) range = %d..%d ; distinct = %d ; deltas = %s" %
             (min((struct.unpack("<H", p[0:2])[0] >> 6) & 0x3FF for _, _, p, _, _ in aud),
              max((struct.unpack("<H", p[0:2])[0] >> 6) & 0x3FF for _, _, p, _, _ in aud),
              len({(struct.unpack("<H", p[0:2])[0] >> 6) & 0x3FF for _, _, p, _, _ in aud}),
              sorted(collections.Counter(
                  (((struct.unpack("<H", aud[k + 1][2][0:2])[0] >> 6) & 0x3FF) -
                   ((struct.unpack("<H", aud[k][2][0:2])[0] >> 6) & 0x3FF))
                  for k in range(len(aud) - 1)).items())[:8]))
    L.append("")
    L.append("audio packet 0, first 48 bytes:")
    L.append("```")
    L.append(hx(aud[0][2], 0, 16, 48))
    L.append("```")
    L.append("")
    L.append("### video-format packets (type=1)")
    vf = collections.Counter(x[2] for x in vfmt)
    L.append("n = %d ; distinct 32-byte bodies = %d" % (len(vfmt), len(vf)))
    for b, n in vf.most_common():
        L.append("")
        L.append("body x%d:" % n)
        L.append("```")
        L.append(hx(b, 0, 16))
        L.append("```")
        u = [struct.unpack(">I", b[o:o + 4])[0] for o in range(0, 32, 4)]
        L.append("as be32: %s" % ["0x%08x (%d)" % (x, x) for x in u])
        lu = [struct.unpack("<I", b[o:o + 4])[0] for o in range(0, 32, 4)]
        L.append("as le32: %s" % ["0x%08x (%d)" % (x, x) for x in lu])
        if len(b) >= 8:
            L.append("header first 8 bytes as astrm: w=0x%04x fmt=%d type=%d seq=%d "
                     "psize=%d ts=0x%08x" %
                     (struct.unpack("<H", b[0:2])[0], struct.unpack("<H", b[0:2])[0] & 7,
                      (struct.unpack("<H", b[0:2])[0] >> 5) & 1,
                      (struct.unpack("<H", b[0:2])[0] >> 6) & 0x3FF,
                      struct.unpack(">H", b[2:4])[0], struct.unpack("<I", b[4:8])[0]))
    L.append("")
    L.append("video-format rate: %d over %.3f s = %.2f/s" %
             (len(vfmt), vfmt[-1][1] - vfmt[0][1],
              len(vfmt) / (vfmt[-1][1] - vfmt[0][1])))
    return "\n".join(L)


# ================================================================== §8 50125
def sec8():
    L = ["## UDP 50025 -> 50125 (undocumented 96-byte table)"]
    R = rl("port50125.bin")
    L.append("records = %d ; sizes = %s" % (len(R), sorted(collections.Counter(len(x[2]) for x in R).items())))
    L.append("span t = %.3f .. %.3f s (%d datagrams, %.3f/s)" %
             (R[0][1], R[-1][1], len(R), (len(R) - 1) / (R[-1][1] - R[0][1])))
    L.append("")
    L.append("record 0, full 96 bytes:")
    L.append("```")
    L.append(hx(R[0][2], 0, 16))
    L.append("```")
    L.append("")
    vary = []
    for o in range(96):
        vals = [x[2][o] for x in R]
        if len(set(vals)) > 1:
            vary.append((o, min(vals), max(vals), len(set(vals))))
    const = [o for o in range(96) if o not in {v[0] for v in vary}]
    L.append("offsets that VARY across the %d records: %s" %
             (len(R), ", ".join("%d (0x%02x..0x%02x, %d distinct)" % v for v in vary)))
    L.append("")
    L.append("offsets constant: %d of 96 -> %s" % (len(const), const))
    L.append("")
    L.append("non-zero (in any record) offsets: %s" %
             [o for o in range(96) if any(x[2][o] for x in R)])
    L.append("")
    # u16 fields at the interesting offsets
    L.append("| off | u16 be (first rec) | distinct u16 be | min | max | notes |")
    L.append("|---|---|---|---|---|---|")
    for o in range(0, 96, 2):
        vals = [struct.unpack(">H", x[2][o:o + 2])[0] for x in R]
        L.append("| %d | 0x%04x | %d | 0x%04x | 0x%04x | %s |" %
                 (o, vals[0], len(set(vals)), min(vals), max(vals),
                  "varies" if len(set(vals)) > 1 else "const"))
    L.append("")
    L.append("offset 6..7 (u16 counter) progression, first 12: %s" %
             [struct.unpack(">H", x[2][6:8])[0] for x in R[:12]])
    L.append("offset 6..7 last 6: %s" %
             [struct.unpack(">H", x[2][6:8])[0] for x in R[-6:]])
    c = [struct.unpack(">H", x[2][6:8])[0] for x in R]
    L.append("counter deltas histogram = %s ; monotonic = %s ; wraps = %d" %
             (sorted(collections.Counter(b - a for a, b in zip(c, c[1:])).items()),
              all(b >= a for a, b in zip(c, c[1:])),
              sum(1 for a, b in zip(c, c[1:]) if b < a)))
    L.append("")
    ramp = [struct.unpack(">H", x[2][0x30:0x32])[0] for x in R]
    L.append("u16 ramp at offset 0x30: first 10 = %s ; last 6 = %s ; distinct = %s" %
             ([hex(v) for v in ramp[:10]], [hex(v) for v in ramp[-6:]],
              sorted({hex(v) for v in ramp})[:20]))
    # which 16-bit slots hold the ramp
    for o in range(0, 96, 2):
        vals = [struct.unpack(">H", x[2][o:o + 2])[0] for x in R]
        if len(set(vals)) > 1 and o not in (6,):
            L.append("varying u16 at 0x%02x: %s" % (o, [hex(v) for v in vals[:8]]))
    with open(os.path.join(OUTDIR, "table-50125-record0.bin"), "wb") as f:
        f.write(R[0][2])
    return "\n".join(L)


# ================================================================== §9 DHCP
def sec9():
    L = ["## DHCP (port67.bin, console DHCP server -> pad :68)"]
    R = rl("port67.bin")
    L.append("records = %d" % len(R))
    for i, ts, p, si, di in R:
        L.append("")
        if len(p) < 240:
            L.append("### record %d @ %.3f s -- %d bytes, not a BOOTP message" % (i, ts, len(p)))
            L.append("```")
            L.append(hx(p, 0, 16))
            L.append("```")
            continue
        (op, htype, hlen, hops) = p[0], p[1], p[2], p[3]
        xid = struct.unpack(">I", p[4:8])[0]
        secs, flags = struct.unpack(">HH", p[8:12])
        ciaddr, yiaddr, siaddr, giaddr = p[12:16], p[16:20], p[20:24], p[24:28]
        chaddr = p[28:44]
        sname = p[44:108]
        fname = p[108:236]
        cookie = p[236:240]
        L.append("### record %d @ %.3f s -- %d bytes" % (i, ts, len(p)))
        L.append("op=%d htype=%d hlen=%d hops=%d xid=0x%08x secs=%d flags=0x%04x  "
                 "(flags broadcast bit = %d)" %
                 (op, htype, hlen, hops, xid, secs, flags, flags >> 15))
        L.append("ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s" %
                 (".".join(map(str, ciaddr)), ".".join(map(str, yiaddr)),
                  ".".join(map(str, siaddr)), ".".join(map(str, giaddr))))
        L.append("chaddr[0:hlen]=%s (full 16 = %s)" %
                 (chaddr[:hlen].hex(":"), chaddr.hex()))
        L.append("sname=%r" % sname.rstrip(b"\x00"))
        L.append("file=%r" % fname.rstrip(b"\x00"))
        L.append("magic cookie = %s (%s)" % (cookie.hex(), "OK 63.130.53.99" if cookie == b"\x63\x82\x53\x63" else "??"))
        o = 240
        opts = []
        while o < len(p):
            t = p[o]
            if t == 0:
                opts.append((0, 0, b""))
                o += 1
                continue
            if t == 255:
                opts.append((255, 0, b""))
                o += 1
                break
            if o + 1 >= len(p):
                break
            ln = p[o + 1]
            v = p[o + 2:o + 2 + ln]
            opts.append((t, ln, v))
            o += 2 + ln
        L.append("")
        L.append("| # | opt | len | value (hex) | decoded |")
        L.append("|---|---|---|---|---|")
        for k, (t, ln, v) in enumerate(opts):
            L.append("| %d | %d (%s) | %d | `%s` | %s |" % (k, t, DHCP_NAME.get(t, "?"), ln,
                                                           v.hex(), decode_opt(t, v)))
        L.append("")
        L.append("trailing bytes after option 255: %d  %r" %
                 (len(p) - o, p[o:]) if o < len(p) else "no trailing bytes")
    L.append("")
    L.append("### summary")
    for i, ts, p, si, di in R:
        if len(p) < 240:
            continue
        o = 240
        names = []
        while o < len(p):
            t = p[o]
            if t == 0:
                names.append("PAD")
                o += 1
                continue
            if t == 255:
                names.append("END")
                break
            names.append("%d" % t)
            o += 2 + p[o + 1]
        L.append("rec %d: %s" % (i, " ".join(names)))
    return "\n".join(L)


DHCP_NAME = {0: "PAD", 1: "subnet-mask", 2: "time-offset", 3: "router", 6: "dns",
             12: "hostname", 15: "domain-name", 28: "broadcast", 43: "vendor",
             50: "requested-ip", 51: "lease-time", 52: "opt-overload", 53: "msg-type",
             54: "server-id", 55: "param-request-list", 56: "message", 57: "max-msg-size",
             58: "renewal", 59: "rebinding", 60: "vendor-class-id", 61: "client-id",
             81: "client-fqdn", 255: "END"}


def decode_opt(t, v):
    if t == 53 and len(v) == 1:
        return {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
                6: "NAK", 7: "RELEASE", 8: "INFORM"}.get(v[0], "?") + " (%d)" % v[0]
    if t in (1, 3, 6, 28, 54, 50) and len(v) % 4 == 0:
        return ", ".join(".".join(str(b) for b in v[k:k + 4]) for k in range(0, len(v), 4))
    if t in (51, 58, 59) and len(v) == 4:
        return "%d s" % struct.unpack(">I", v)[0]
    if t == 55:
        return "requested options: " + " ".join(str(b) for b in v)
    if t in (12, 15, 60, 61, 43, 56):
        return repr(v)
    if t == 57 and len(v) == 2:
        return "%d" % struct.unpack(">H", v)[0]
    return ""


# ================================================================== §10
def sec10():
    L = ["## input protocol (port50022.bin, pad->console :50022)"]
    R = rl("port50022.bin")
    L.append("records = %d ; sizes = %s" % (len(R), sorted(collections.Counter(len(x[2]) for x in R).items())))
    L.append("span t = %.3f .. %.3f s" % (R[0][1], R[-1][1]))
    L.append("rate = %.2f packets/s over the full capture" % (len(R) / (R[-1][1] - R[0][1])))
    L.append("")
    L.append("record 0, full 128 bytes:")
    L.append("```")
    L.append(hx(R[0][2], 0, 16))
    L.append("```")
    L.append("")
    seq = [struct.unpack("<H", x[2][0:2])[0] for x in R]
    L.append("u16 le seq_id at offset 0: first 10 = %s ; last 5 = %s" %
             (seq[:10], seq[-5:]))
    L.append("min=%d max=%d ; deltas histogram = %s" %
             (min(seq), max(seq), sorted(collections.Counter(b - a for a, b in zip(seq, seq[1:])).items())[:10]))
    resets = [(i, a, b) for i, (a, b) in enumerate(zip(seq, seq[1:])) if b < a]
    L.append("backward steps (possible resets) = %d -> %s" % (len(resets), resets[:12]))
    L.append("fw_version_neg at offset 127: distinct = %s ; first = %d (0x%02x) -> ~0x%02x" %
             (sorted({x[2][127] for x in R}), R[0][2][127], R[0][2][127],
              (~R[0][2][127]) & 0xFF))
    # other varying offsets
    vary = [o for o in range(128) if len({x[2][o] for x in R}) > 1]
    const = [o for o in range(128) if o not in set(vary)]
    L.append("")
    L.append("offsets that vary = %d ; constant = %d -> %s" % (len(vary), len(const), const))
    L.append("")
    L.append("| off | field | distinct | first values |")
    L.append("|---|---|---|---|")
    names = {0: "seq_id lo", 1: "seq_id hi", 2: "buttons lo", 3: "buttons hi",
             4: "power_status", 5: "battery_charge", 127: "fw_version_neg"}
    for o in vary[:24]:
        vals = [x[2][o] for x in R]
        L.append("| %d | %s | %d | %s |" % (o, names.get(o, ""), len(set(vals)),
                                            [hex(v) for v in vals[:6]]))
    L.append("")
    L.append("timestamp deltas (s) histogram (bucketed to 1 ms) = %s" %
             sorted(collections.Counter(
                 round((b[1] - a[1]) * 1000.0) for a, b in zip(R, R[1:])).items())[:10])
    return "\n".join(L)


# ================================================================== §11
def sec11():
    L = ["## UDP 50110 -> 50010 (resync request), port50010.bin"]
    R = rl("port50010.bin")
    L.append("records = %d" % len(R))
    for i, ts, p, si, di in R:
        L.append("")
        L.append("record %d @ %.4f s, %d bytes: `%s`" % (i, ts, len(p), p.hex()))
        L.append("```")
        L.append(hx(p, 0, 16))
        L.append("```")
    L.append("")
    L.append("inter-datagram gaps = %s" %
             ["%.4f s" % (b[1] - a[1]) for a, b in zip(R, R[1:])])
    return "\n".join(L)


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    want = sys.argv[1:] or ["all"]
    if want == ["all"]:
        want = [str(i) for i in range(1, 12)]
    con = rl("port50123.bin") if ({"1", "2", "3", "4", "5"} & set(want)) else None
    pad = rl("port50023.bin") if ({"1", "3", "4"} & set(want)) else None
    secs = []
    if "1" in want:
        secs.append(sec1_2(con, pad))
    if "2" in want:
        secs.append(sec2(con, pad))
    if "3" in want:
        secs.append(sec3(pad))
    if "4" in want:
        secs.append(sec4_5(con, pad))
    if "6" in want:
        secs.append(sec6())
    if "7" in want:
        secs.append(sec7())
    if "8" in want:
        secs.append(sec8())
    if "9" in want:
        secs.append(sec9())
    if "10" in want:
        secs.append(sec10())
    if "11" in want:
        secs.append(sec11())
    print("\n\n".join(secs))


if __name__ == "__main__":
    main()
