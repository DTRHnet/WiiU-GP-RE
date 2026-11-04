#!/usr/bin/env python3
"""Reassemble the live DRC VSTRM stream off the wire and check it against the
documented envelope (research/CODEC-SPEC.md section 1.3):

  byte 0..1  0xF in high nibble + 10-bit BE sequence (mod 1024)
  byte 2     bit7 init | bit6 frame-begin | bit5 chunk-end | bit4 frame-end
             | bit3 timestamp-present | low bits = length[10:8]
  byte 3     length[7:0]                       (payload length = udp len - 16)
  byte 4..7  BE u32 media timestamp (us), identical for a whole frame
  byte 8..15 options

Usage: analyze_vstrm.py <pcap> [--dump-frame N <file>]
"""
import struct, subprocess, sys, collections

def packets(pcap):
    out = subprocess.run(["tshark", "-r", pcap, "-T", "fields", "-e", "udp.payload"],
                         capture_output=True, text=True)
    for line in out.stdout.splitlines():
        h = line.strip().replace(":", "")
        if h:
            yield bytes.fromhex(h)

def flags_of(b):
    return {"init": bool(b & 0x80), "frame_begin": bool(b & 0x40),
            "chunk_end": bool(b & 0x20), "frame_end": bool(b & 0x10),
            "ts_present": bool(b & 0x08)}

frames = collections.OrderedDict()
n = truncated = badlen = 0
seqs = []
for p in packets(sys.argv[1]):
    n += 1
    if len(p) < 16:
        truncated += 1
        continue
    seq = ((p[0] & 0x0F) << 8) | p[1]
    f = flags_of(p[2])
    length = ((p[2] & 0x07) << 8) | p[3]
    ts = struct.unpack(">I", p[4:8])[0]
    body = p[16:16 + length]
    if len(body) != length:
        badlen += 1
    seqs.append(seq)
    fr = frames.setdefault(ts, {"chunks": [], "flags": [], "opts": []})
    fr["chunks"].append((seq, body))
    fr["flags"].append(f)
    fr["opts"].append(p[8:16].hex())

print(f"packets={n} frames={len(frames)} truncated={truncated} len_mismatch={badlen}")
seq_gaps = sum(1 for a, b in zip(seqs, seqs[1:]) if (b - a) % 1024 != 1)
print(f"seq_start={seqs[0] if seqs else '-'} seq_wraps/gaps={seq_gaps}")

per_frame = collections.Counter(len(fr["chunks"]) for fr in frames.values())
print("chunks/frame histogram:", dict(sorted(per_frame.items())))

sizes = [len(c[1]) for fr in frames.values() for c in fr["chunks"]]
if sizes:
    oversize = sum(1 for s in sizes if s > 1694)
    print(f"chunk bytes: min={min(sizes)} max={max(sizes)} mean={sum(sizes)/len(sizes):.1f} "
          f"over_1694={oversize}")

begins = sum(1 for fr in frames.values() if fr["flags"][0]["frame_begin"])
ends = sum(1 for fr in frames.values() if fr["flags"][-1]["frame_end"])
print(f"frames with frame_begin on first chunk={begins}/{len(frames)}  "
      f"frame_end on last={ends}/{len(frames)}")

opts = collections.Counter(o for fr in frames.values() for o in fr["opts"][:1])
print("option bytes (first chunk of frame), most common:", opts.most_common(4))

tss = list(frames.keys())
if len(tss) > 1:
    d = [((b - a) & 0xFFFFFFFF) for a, b in zip(tss, tss[1:])]
    d = [x for x in d if x and x < 10_000_000]
    if d:
        d.sort()
        print(f"frame interval us: median={d[len(d)//2]} min={d[0]} max={d[-1]}")

# Optionally dump one reassembled frame (chunk bodies concatenated) for offline work.
if "--dump-frame" in sys.argv:
    idx = int(sys.argv[sys.argv.index("--dump-frame") + 1])
    path = sys.argv[sys.argv.index("--dump-frame") + 2]
    key = list(frames.keys())[idx]
    data = b"".join(c[1] for c in sorted(frames[key]["chunks"]))
    open(path, "wb").write(data)
    print(f"dumped frame {idx} (ts={key}) -> {path} ({len(data)} bytes)")
