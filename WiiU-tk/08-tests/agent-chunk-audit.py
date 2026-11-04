#!/usr/bin/env python3
"""
agent-chunk-audit.py — bit-level audit of the Wii U GamePad ("DRC") H.264 payload.

Compares the real-console VSTRM video stream against ours at the level the pad's
decoder consumes: per-frame / per-chunk raw CABAC byte ranges, no SPS/PPS/slice
header on the wire. For each stream it

  1. splits the 16-byte VSTRM header stream into per-frame / per-chunk byte
     ranges (using frame_begin / chunk_end / frame_end flags, not timestamps);
  2. measures chunk sizes, chunks-per-frame, datagrams-per-chunk and degenerate
     (0/1/2-byte) chunks;
  3. reconstructs Annex-B with the pad's hardcoded SPS/PPS and Barista's synthetic
     slice header and decodes it with ffmpeg (-xerror -err_detect explode),
     checking geometry (854x480 yuv420p) and counting decode warnings/errors;
  4. answers "does each chunk decode as a standalone slice?" by giving every
     chunk its own correctly-built slice header (first_mb_in_slice = i*324) —
     a raw byte cut fails, a terminated slice would decode;
  5. tests the "dense first frame" hypothesis: decode the first IDR alone.

Model note (verified, see research/agents/encoder-conformance.md): the 5 chunks
of one frame are fragments of ONE continuous CABAC slice (1620 MBs, one slice
header per frame). The pad concatenates the chunks; the chunk boundary is only a
transport split, not a slice boundary. This is proven by (3) decoding cleanly
while (4) fails on the real console's own chunks.

Offline only: reads files and runs ffmpeg/tshark; binds no sockets, touches no
network interfaces.

Usage:
  agent-chunk-audit.py --console out/evidence/truth/port50120.bin \
                       --ours capture/phase4-clock-083704.pcap \
                       [--max-frames N] [--outdir /tmp/audit]
"""
import argparse
import collections
import os
import struct
import subprocess
import sys

SPS = bytes.fromhex("67640020ac2b406c1ef368")
PPS = bytes.fromhex("68ee060ce8")
START = b"\x00\x00\x00\x01"
MAX_CHUNK = 1694  # hard VSTRM payload ceiling (16-byte header + <=1694)


# ---------------------------------------------------------------- sources
def vstrm_from_console(path):
    """port50120.bin record = >d ts + 4s + 4s + >I len, then the UDP payload."""
    with open(path, "rb") as f:
        while True:
            hdr = f.read(20)
            if len(hdr) < 20:
                return
            _ts, _a, _b, ln = struct.unpack(">d4s4sI", hdr)
            p = f.read(ln)
            if len(p) < ln:
                return
            yield p


def vstrm_from_pcap(path):
    """Extract plaintext UDP payloads of the 50020->50120 video flow."""
    out = subprocess.run(
        ["tshark", "-r", path, "-T", "fields", "-e", "udp.payload",
         "-Y", "udp.dstport == 50120"],
        capture_output=True, text=True, check=True)
    for line in out.stdout.splitlines():
        h = line.strip().replace(":", "")
        if h:
            yield bytes.fromhex(h)


# ------------------------------------------------------------- frame split
def split_frames(datagrams):
    """Group VSTRM datagrams into {idr, chunks:[bytes], dgrams:[counts]}."""
    frames = []
    cur = None
    chunk = bytearray()
    dgrams = 0
    for p in datagrams:
        if len(p) < 16:
            continue
        fl = p[2]
        fb = bool(fl & 0x40)
        ce = bool(fl & 0x20)
        fe = bool(fl & 0x10)
        length = ((fl & 0x07) << 8) | p[3]
        body = p[16:16 + length]
        if fb:
            if cur is not None:
                cur["incomplete"] = True
            cur = {"chunks": [], "dgrams": [], "idr": p[8] == 0x80,
                   "incomplete": False}
        if cur is None:
            continue
        chunk.extend(body)
        dgrams += 1
        if ce:
            cur["chunks"].append(bytes(chunk))
            cur["dgrams"].append(dgrams)
            chunk = bytearray()
            dgrams = 0
        if fe:
            frames.append(cur)
            cur = None
            dgrams = 0
    return frames


def complete(frames):
    return [f for f in frames if len(f["chunks"]) == 5]


# ------------------------------------------------------------- statistics
def summarize(frames):
    s = collections.Counter()
    s["frames"] = len(frames)
    s["incomplete"] = sum(1 for f in frames if len(f["chunks"]) != 5)
    s["idr_frames"] = sum(1 for f in frames if f["idr"])
    chunks = [c for f in frames for c in f["chunks"]]
    sizes = sorted(len(c) for c in chunks)
    s["chunks"] = len(chunks)
    s["chunk_min"] = sizes[0] if sizes else 0
    s["chunk_med"] = sizes[len(sizes) // 2] if sizes else 0
    s["chunk_mean"] = round(sum(sizes) / len(sizes), 1) if sizes else 0
    s["chunk_max"] = sizes[-1] if sizes else 0
    s["chunk_0B"] = sum(1 for c in sizes if c == 0)
    s["chunk_1B"] = sum(1 for c in sizes if c == 1)
    s["chunk_2B"] = sum(1 for c in sizes if c == 2)
    s["chunk_gt1694"] = sum(1 for c in sizes if c > MAX_CHUNK)
    dgrams = [d for f in frames for d in f["dgrams"]]
    s["dgrams_per_chunk_max"] = max(dgrams) if dgrams else 0
    s["dgrams_per_chunk_mean"] = round(sum(dgrams) / len(dgrams), 2) if dgrams else 0
    s["dgrams_per_frame_mean"] = round(sum(sum(f["dgrams"]) for f in frames) / len(frames), 2) if frames else 0
    fsizes = [sum(len(c) for c in f["chunks"]) for f in frames]
    s["frame_mean"] = round(sum(fsizes) / len(fsizes), 1) if fsizes else 0
    idrs = [f for f in frames if f["idr"]]
    s["idr_frame_mean"] = round(sum(sum(len(c) for c in f["chunks"]) for f in idrs) / len(idrs), 1) if idrs else 0
    s["idr_frame_min"] = min((sum(len(c) for c in f["chunks"]) for f in idrs), default=0)
    return s


# ------------------------------------------------------------ reconstruct
def escape(data):
    out = bytearray()
    zeros = 0
    for v in data:
        if zeros >= 2 and v <= 3:
            out.append(3)
            zeros = 0
        out.append(v)
        zeros = zeros + 1 if v == 0 else 0
    return out


def slice_header(idr, frame_num):
    """Barista's validated synthetic slice header (reconstruct-media-capture.py)."""
    return (0x25b804ff if idr else 0x21e003ff | ((frame_num & 255) << 13)).to_bytes(4, "big")


class BitWriter:
    """Minimal ue(v)/se(v) writer for a first_mb_in_slice-correct slice header."""

    def __init__(self):
        self.b = []

    def ue(self, n):
        v = n + 1
        self.b.extend(bin(v)[2:])

    def se(self, n):
        self.ue(2 * abs(n) - (1 if n <= 0 else 0))

    def bits(self, val, n):
        self.b.extend(format(val, f"0{n}b"))

    def bytes(self):
        b = list(self.b)
        while len(b) % 8:
            b.append("0")
        out = bytearray()
        for i in range(0, len(b), 8):
            out.append(int("".join(b[i:i + 8]), 2))
        return bytes(out)


def slice_header_idr(first_mb):
    """IDR slice header for the pad's hardcoded SPS (log2_max_frame_num_minus4=4,
    pic_order_cnt_type=2, deblocking_filter_control_present=1)."""
    w = BitWriter()
    w.ue(first_mb)   # first_mb_in_slice
    w.ue(2)          # slice_type = I
    w.ue(0)          # pic_parameter_set_id
    w.bits(0, 8)     # frame_num
    w.ue(0)          # idr_pic_id
    w.bits(0, 1)     # no_output_of_prior_pics_flag
    w.bits(0, 1)     # long_term_reference_flag
    w.se(0)          # slice_qp_delta
    w.ue(0)          # disable_deblocking_filter_idc
    w.se(0)          # slice_alpha_c0_offset_div2
    w.se(0)          # slice_beta_offset_div2
    return w.bytes()


def reconstruct(frames, path, start_at_first_idr=False):
    """Barista's model: SPS+PPS, then one slice header PER FRAME, chunks joined."""
    buf = bytearray(START + SPS + START + PPS)
    num = 0
    started = False
    for f in frames:
        if start_at_first_idr and not f["idr"] and not started:
            continue
        started = True
        if f["idr"]:
            num = 0
        hdr = slice_header(f["idr"], num)
        buf.extend(START + escape(hdr + b"".join(f["chunks"])))
        num = (num + 1) % 256
    with open(path, "wb") as fh:
        fh.write(buf)


def decode(path):
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "v:0",
         "-show_entries", "stream=width,height,pix_fmt,profile,level",
         "-of", "default=noprint_wrappers=1", path],
        capture_output=True, text=True)
    dec = subprocess.run(
        ["ffmpeg", "-nostdin", "-v", "warning", "-xerror", "-err_detect", "explode",
         "-c:v", "h264", "-f", "h264", "-i", path, "-f", "null", "-"],
        capture_output=True, text=True)
    warnings = sum(1 for ln in dec.stderr.splitlines() if "warning" in ln.lower())
    errors = sum(1 for ln in dec.stderr.splitlines()
                 if "error" in ln.lower() and "xerror" not in ln.lower())
    return {"geometry": dict(l.split("=", 1) for l in probe.stdout.splitlines() if "=" in l),
            "exit": dec.returncode, "warnings": warnings, "errors": errors}


def standalone_chunks(frame, outdir):
    """Does each chunk decode as an independent slice (correct first_mb)?  Raw
    byte cuts fail; a terminated slice would produce a partial frame."""
    results = []
    for i, c in enumerate(frame["chunks"]):
        hdr = slice_header_idr(i * 324) if frame["idr"] else slice_header(False, 0)
        path = os.path.join(outdir, f"chunk{i}.h264")
        with open(path, "wb") as fh:
            fh.write(START + SPS + START + PPS + START + escape(hdr + c))
        r = subprocess.run(
            ["ffmpeg", "-nostdin", "-v", "error", "-xerror", "-err_detect", "explode",
             "-c:v", "h264", "-f", "h264", "-i", path, "-f", "null", "-"],
            capture_output=True, text=True)
        results.append(r.returncode == 0)
    return results


# ------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--console", required=True)
    ap.add_argument("--ours", required=True)
    ap.add_argument("--max-frames", type=int, default=0)
    ap.add_argument("--outdir", default="/tmp/audit")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    streams = []
    for name, src in (("console", args.console), ("ours", args.ours)):
        gen = vstrm_from_console(src) if name == "console" else vstrm_from_pcap(src)
        datagrams = list(gen)
        frames = split_frames(datagrams)
        if args.max_frames:
            frames = frames[:args.max_frames]
        good = complete(frames)
        s = summarize(frames)
        rec = os.path.join(args.outdir, f"{name}.h264")
        reconstruct(good, rec)
        d = decode(rec)
        # ours may begin with pre-IDR P frames (capture started mid-session)
        rec_idr = os.path.join(args.outdir, f"{name}-from-idr.h264")
        reconstruct(good, rec_idr, start_at_first_idr=True)
        d_idr = decode(rec_idr)
        # dense-first-frame: decode the first IDR alone
        first_idr = next((f for f in good if f["idr"]), None)
        d_first = None
        if first_idr:
            rec1 = os.path.join(args.outdir, f"{name}-first-idr.h264")
            reconstruct([first_idr], rec1)
            d_first = decode(rec1)
        # standalone-chunk probe on the first IDR
        standalone = standalone_chunks(first_idr, args.outdir) if first_idr else []

        streams.append(dict(name=name, s=s, frames=frames, good=good, d=d, d_idr=d_idr,
                            d_first=d_first, standalone=standalone,
                            first_idr_chunks=[len(c) for c in first_idr["chunks"]] if first_idr else [],
                            first_idr_total=sum(len(c) for c in first_idr["chunks"]) if first_idr else 0,
                            n_datagrams=len(datagrams)))

    for st in streams:
        s = st["s"]
        name = st["name"]
        print(f"===== {name} =====")
        print(f"  datagrams={st['n_datagrams']}  frames={s['frames']}  "
              f"complete(5-chunk)={len(st['good'])}  incomplete={s['incomplete']}  "
              f"idr_frames={s['idr_frames']}")
        print(f"  chunk bytes: min={s['chunk_min']} median={s['chunk_med']} "
              f"mean={s['chunk_mean']} max={s['chunk_max']}")
        print(f"  degenerate chunks: 0B={s['chunk_0B']} 1B={s['chunk_1B']} "
              f"2B={s['chunk_2B']}  >1694B(split)={s['chunk_gt1694']}")
        print(f"  datagrams/chunk max={s['dgrams_per_chunk_max']} "
              f"mean={s['dgrams_per_chunk_mean']}  datagrams/frame mean={s['dgrams_per_frame_mean']}")
        print(f"  frame bytes mean={s['frame_mean']}  idr_mean={s['idr_frame_mean']}  "
              f"idr_min={s['idr_frame_min']}")
        g = st["d"]["geometry"]
        print(f"  decode(full): exit={st['d']['exit']} warnings={st['d']['warnings']} "
              f"errors={st['d']['errors']} geom={g.get('width')}x{g.get('height')} {g.get('pix_fmt')} "
              f"{g.get('profile')}/L{g.get('level')}")
        g2 = st["d_idr"]["geometry"]
        print(f"  decode(from first IDR): exit={st['d_idr']['exit']} "
              f"warnings={st['d_idr']['warnings']} errors={st['d_idr']['errors']} "
              f"geom={g2.get('width')}x{g2.get('height')} {g2.get('pix_fmt')}")
        if st["d_first"]:
            print(f"  first IDR alone: exit={st['d_first']['exit']} "
                  f"errors={st['d_first']['errors']} "
                  f"chunks={st['first_idr_chunks']} total={st['first_idr_total']}B")
        print(f"  standalone chunk decode (raw-cut probe): {st['standalone']}")
        print()


if __name__ == "__main__":
    main()
