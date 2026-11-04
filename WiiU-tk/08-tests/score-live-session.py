#!/usr/bin/env python3
"""
Score a live WiiUAP capture against the decrypted real-console ground truth
(research/GROUND-TRUTH-SESSION.md).

Everything here is measured from the wire, no assumptions:

  * video (50020 -> 50120): frame rate, datagrams/frame, chunk-end and frame-end
    counts, payload sizes, ext-option bytes, IDR-marked packets, and — the check
    this script exists for — whether the `init` flag appears only on the first
    frame (console behaviour) or on every IDR (our old behaviour, 16 frames/s);
  * audio + video-format (50021 -> 50121): rate, sizes, format body bytes;
  * command (50023 -> 50123): command rate and sequence discipline;
  * pad -> 50010: the resync-request rate, which is the pass/fail signal
    (real console session: 3 datagrams in 300 s; our broken stack: ~63/s);
  * anything on 50125 (the console's 96-byte table) — we send none today.

Usage: ./tests/score-live-session.py capture/after-initfix.pcap
"""
import struct
import subprocess
import sys
import collections

CONSOLE = {
    "video_pkt_max": 1710,          # 16 B VSTRM header + 1694 B chunk
    "datagrams_per_frame": 5.2,
    "fps": 59.19,
    "audio_len": 1672,
    "format_len": 32,
    "format_rate": 59.2,
    "resync_total_in_300s": 3,
}


def udp_payloads(pcap):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-n", "-Y", "udp",
         "-T", "fields", "-e", "frame.time_relative", "-e", "ip.src",
         "-e", "udp.srcport", "-e", "ip.dst", "-e", "udp.dstport",
         "-e", "udp.payload"],
        capture_output=True, text=True)
    rows = []
    for line in out.stdout.splitlines():
        f = line.split("\t")
        if len(f) < 6 or not f[0]:
            continue
        try:
            ts = float(f[0])
        except ValueError:
            continue
        pay = bytes.fromhex(f[5].replace(":", "")) if f[5] else b""
        rows.append((ts, f[1], int(f[2] or 0), f[3], int(f[4] or 0), pay))
    return rows


def vstrm_fields(p):
    """Console layout, and libdrc/Barista layout, both reported."""
    b0, b1, b2, b3 = p[0], p[1], p[2], p[3]
    seq_console = ((b0 & 0x0F) << 6) | (b1 & 0x3F)
    seq_libdrc = ((b0 & 0x03) << 8) | b1
    ln = ((b2 & 0x07) << 8) | b3
    return dict(init=bool(b2 & 0x80), fbegin=bool(b2 & 0x40),
                cend=bool(b2 & 0x20), fend=bool(b2 & 0x10),
                ts_present=bool(b2 & 0x08), seq_c=seq_console,
                seq_l=seq_libdrc, len=ln, ts=struct.unpack(">I", p[4:8])[0],
                opts=p[8:16].hex())


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    rows = udp_payloads(sys.argv[1])
    if not rows:
        raise SystemExit("no UDP in %s" % sys.argv[1])
    t0 = rows[0][0]
    span = rows[-1][0] - t0

    flows = collections.Counter((s, d) for ts, si, s, di, d, p in rows)
    print("== capture %s : %d datagrams over %.1fs" % (sys.argv[1], len(rows), span))
    for (s, d), c in flows.most_common(12):
        print("   %5d -> %-5d %6d  (%.1f/s)" % (s, d, c, c / max(span, 1e-9)))

    # ---- video
    vid = [(ts, p) for ts, si, s, di, d, p in rows if d == 50120 and len(p) >= 16]
    if vid:
        f = [vstrm_fields(p) for ts, p in vid]
        frames, ends = sum(x["fbegin"] for x in f), sum(x["fend"] for x in f)
        init_pkts = [i for i, x in enumerate(f) if x["init"]]
        idr_pkts = [i for i, x in enumerate(f) if p_opts_idr(vid[i][1])]
        sizes = collections.Counter(len(p) for ts, p in vid)
        # init is "confined to the first frame" if every init-flagged datagram
        # sits at or before the last datagram of the first frame that carries one.
        first_init_frame_end = -1
        if init_pkts:
            for i in range(init_pkts[0], len(f)):
                if f[i]["fend"]:
                    first_init_frame_end = i
                    break
        init_all_in_first_frame = bool(init_pkts) and max(init_pkts) <= first_init_frame_end
        deltas = []
        for a, b in zip(f, f[1:]):
            if b["fbegin"]:
                deltas.append((b["ts"] - a["ts"]) & 0xFFFFFFFF)
        med = sorted(deltas)[len(deltas) // 2] if deltas else 0
        print("\n== video 50020 -> 50120")
        print("   datagrams %d (%.1f/s) | frames %d | frame-ends %d | %.2f datagrams/frame"
              % (len(vid), len(vid) / span, frames, ends, len(vid) / max(frames, 1)))
        print("   fps %.2f | median frame-timestamp delta %d us (console 16683)"
              % (frames / span, med))
        print("   payload sizes: max %d (console 1710), distinct %d"
              % (max(sizes), len(sizes)))
        print("   ext options: %s" % collections.Counter(x["opts"] for x in f).most_common(3))
        print("   IDR-marked datagrams %d => ~%.1f IDR frames/s (console ~1 per 26 s)"
              % (len(idr_pkts), len(idr_pkts) / 5.0 / span))
        print("   init-marked datagrams %d" % len(init_pkts))
        if not init_pkts:
            print("   [!] no init flag at all this window")
        elif init_all_in_first_frame:
            print("   [OK] init confined to the first frame — matches the console")
        else:
            later = [i for i in init_pkts if i > first_init_frame_end]
            print("   [FAIL] init on %d datagrams after the first frame — pad is being "
                  "told 'stream restarts here' %.1f times/s"
                  % (len(later), len(later) / 5.0 / span))
        print("   chunk-end/frame %.2f, frame-end/frame %.2f (want 5.00 / 1.00)"
              % (sum(x["cend"] for x in f) / max(frames, 1),
                 ends / max(frames, 1)))
        sq = [x["seq_l"] for x in f]
        breaks = sum(1 for a, b in zip(sq, sq[1:]) if b != (a + 1) & 0x3FF)
        print("   sequence discontinuities: %d of %d" % (breaks, len(sq)))

    # ---- audio + format
    a21 = [(ts, p) for ts, si, s, di, d, p in rows if d == 50121]
    if a21:
        aud = [p for ts, p in a21 if len(p) == CONSOLE["audio_len"]]
        fmt = [p for ts, p in a21 if len(p) == CONSOLE["format_len"]]
        print("\n== audio/format 50021 -> 50121")
        print("   audio %d (%.1f/s, console ~113/s) | format %d (%.1f/s, console %.1f/s)"
              % (len(aud), len(aud) / span, len(fmt), len(fmt) / span,
                 CONSOLE["format_rate"]))
        if aud:
            print("   audio header %s (console 20 00 06 80 …)"
                  % aud[0][:8].hex(" "))
        if fmt:
            b = fmt[0]
            print("   format bytes 4..7 %s (console 00 00 00 00, we used to send 11 11 81 08)"
                  % b[4:8].hex(" "))
            print("   format clocks %d/%d/%d/%d (console 16000/16000/21000/21000)"
                  % tuple(struct.unpack("<I", b[o:o + 4])[0] for o in (12, 16, 20, 24)))

    # ---- commands
    cmd = [p for ts, si, s, di, d, p in rows if d == 50123]
    if cmd:
        seqs = [struct.unpack("<H", p[6:8])[0] for p in cmd if len(p) >= 8]
        print("\n== command 50023 -> 50123: %d packets (%.2f/s, console ~4.9/s)"
              % (len(cmd), len(cmd) / span))
        print("   sizes %s" % collections.Counter(len(p) for p in cmd).most_common(5))
        if seqs:
            print("   sequence %d..%d, distinct %d (console increments per command)"
                  % (seqs[0], seqs[-1], len(set(seqs))))

    # ---- the pass/fail signal
    rs = [(ts, si, s, p) for ts, si, s, di, d, p in rows if d == 50010]
    print("\n== pad -> 50010 (resync requests): %d in %.0fs => %.1f/s"
          % (len(rs), span, len(rs) / span))
    if rs:
        print("   source ports %s | payloads %s"
              % (collections.Counter(s for _, _, s, _ in rs).most_common(3),
                 collections.Counter(p.hex() for _, _, _, p in rs).most_common(3)))
    verdict = "PASS" if len(rs) / span < 0.2 else "FAIL"
    print("   [%s] console reference: %.0f datagrams in 300 s (%.2f/s)"
          % (verdict, CONSOLE["resync_total_in_300s"], CONSOLE["resync_total_in_300s"] / 300.0))
    tbl = [p for ts, si, s, di, d, p in rows if d == 50125]
    print("\n== 50125 (console sends a 96-byte table ~1/s): %d datagrams from us" % len(tbl))


def p_opts_idr(p):
    return len(p) > 8 and p[8] == 0x80


if __name__ == "__main__":
    main()
