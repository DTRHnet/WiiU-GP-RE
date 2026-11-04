# VSTRM video-header census: console vs ours (byte-level)

Scope: all 73,500 decrypted console video datagrams in `out/evidence/truth/port50120.bin`,
plus our plaintext video in `capture/phase4-clock-083313.pcap` (30,014 pkts) and
`capture/phase12-armed-104826.pcap` (18,065 pkts). Reproducer: `tests/agent-vstrm-census.py`.

**Headline: the VSTRM header is byte-for-byte identical between console and our stream.
The one "real deviation" the repo documents — sequence packing — does not exist.**
All remaining differences are encoder/content policy, not header format.

## Header layout (measured, both sides identical)

| byte | field | value |
|---|---|---|
| b0 | `0xF0 \| seq[9:8]` | 0xF0..0xF3; b0[3:2] **never** set (0/73500) |
| b1 | `seq[7:0]` | full 0..255 (55,099 pkts > 0x3F) |
| b2[7:3] | flags init·fb·ce·fe·ts | always ts-present=1 |
| b2[2:0] + b3 | 11-bit chunk length | always == actual payload |
| b4..b7 | media timestamp | big-endian u32 |
| b8..b15 | ext options | `82 00 83 85 06 00 00 00` (P) · `80 82 00 83 85 06 00 00` (IDR) |

## Console census (73,500 pkts, 14,137 frames, 238.86 s)

**Sequence.** 10-bit, +1/datagram, wraps at 1024 (71×). 9 non-unit deltas = capture loss
(8× single-packet drop, one +134 at t=73.31 s = the session-2 re-association). No resets.

**Flags (b2[7:3]):** 0x01 ts-only=2572 · 0x05 chunk-end=42631 · 0x07 ce+frame-end=14136 ·
0x09 frame-begin=231 · 0x0d fb+ce=13905 · init variants 0x11=19, 0x15=4, 0x17=1, 0x19=1.
`init` on **exactly the first frame's 25 datagrams**, never again.

**Length.** 0 mismatches; max chunk 1694 B (2,827 pkts). First frame = 5 chunks × 5 datagrams
(chunk ≈ 7.4 KB → ~37 KB IDR).

**Timestamp.** BE u32 `0x057c5a59..0x13b8fe6b`, frame deltas 16683 µs×8894 + 16684 µs×5101.
Runs at arrival rate (−24 ppm TSF-vs-monitor), +31.02 s offset, **no wrap/reset** at 73 s.

**Ext options.** Exactly two strings: P ×73454, IDR ×46. Option bytes present: 0x80, 0x82,
0x83, 0x85 only. 0x82 val always 0x00; 0x85 val always 0x06; 0x80/0x83 are valueless flags.
**No 0x81/0x84/0x86+ anywhere.** 0x00 terminator in 73500/73500.

## Ours census

| capture | pkts | frames | IDR pkts | first frame |
|---|---|---|---|---|
| phase4-clock | 30,014 | 3,131 | 19,864 (66%) | 5 pkts init+IDR, chunks 10–46 B |
| phase12-armed | 18,065 | 3,454 | 1,035 (5.7%) | 1 pkt, no init (mid-stream) |

Both: identical seq packing (b0[3:2] never set), identical flag semantics (init first-frame
only), 0 length mismatches, identical ext bytes. Ours emit flags 0x01/0x05/0x07/0x09/0x0d +
init 0x15/0x17/0x1d; console additionally emits 0x11/0x19 — a by-product of its larger
25-packet first frame, not a different flag rule.

## Diff

| field | verdict |
|---|---|
| sequence packing | **IDENTICAL** (repo's "6-bit vs 8-bit" claim is **wrong**) |
| ext options (order + values) | identical |
| flag semantics | identical |
| length field | identical (always correct) |
| timestamp format/endianness | identical (BE u32) |
| timestamp *value epoch* | differs (console TSF; ours synthetic + `DRC_TSF_BASE_US`) |
| init policy | identical (first frame only) |
| first-frame size | differs (console ~37 KB; ours ~89 B in phase4) |
| IDR cadence | differs (console 0.06% IDR pkts; ours 5.7%/66%) |

## Specific hunt results

* **Option we never emit:** none — ext strings byte-identical; no undocumented byte.
* **Ordering rule:** constant per frame kind; IDR = P with 0x80 prepended. No other order.
* **Terminator 0x00:** present in every packet, both sides; almost certainly mandatory
  (length-less TLV list — speculation on the pad's hard requirement, untestable offline).
* **Length disagreement:** zero occurrences, either side.
* **Session/stream id in header:** **none.** b0..b15 = seq/flags/len/ts/ext-options only.
  Across the 73 s epoch boundary the sequence jumps (804→938, ~134 lost) and the timestamp
  continues uninterrupted; no field resets or changes. The three epochs are invisible to
  the VSTRM header except as a loss gap.

## Ranked things to change (honest: the header needs nothing)

1. **Fix the docs, not the code.** `GROUND-TRUTH-SESSION.md` §4/§7 and `SETUP.md` round 12
   claim console seq = `b0[3:0]=seq[9:6]`, `b1[5:0]=seq[5:0]`; measured is `b0[1:0]=seq[9:8]`,
   `b1[7:0]=seq[7:0]` — our layout. `vstrm-packet.cpp` `SeqId()`/`SetSeqId()` (L91–122) is
   already correct. No byte change.
2. **Ext options — no change.** `NormalizeExtOptions()` (vstrm-packet.cpp L65–89) already
   emits `80 82 00 83 85 06 00 00` / `82 00 83 85 06 00 00` exactly.
3. **Flags/length/ts-endianness — no change.** `GenerateVstrmPackets`
   (video-streamer.cpp L86–147) matches init-first-frame, fb/ce/fe and the 11-bit length.
4. **(Encoder, not header — speculative decoder impact.)** Console first frame = dense
   ~37 KB IDR (25 datagrams); ours in phase4 = ~89 B total (solid-colour). If the pad needs
   a full-resolution reference frame it may reject a degenerate first IDR. Lives in the
   encoder/idr-policy layer, not `vstrm-packet.cpp`.
5. **(Policy, already capped.)** IDR cadence: console ≈1 IDR/26 s; ours was 66% (phase4),
   5.7% after the round-13 cap. Not a header matter.

## Cosmetic vs potentially material

* **Certainly cosmetic:** the sequence-packing "difference" (not real); the exact flag-combo
  *population* of the first frame (content-driven); timestamp value epoch (timebase question,
  format identical); the `truth-decrypt.py` record quirk (its "src"/"dst" fields are actually
  VSTRM timestamp/ext-option bytes, not IPs — don't read them as addresses).
* **Potentially material (payload, not header):** first-frame IDR density (§4) and IDR
  cadence (§5) — both encoder policy, fully outside the VSTRM header.
* **Not a header difference:** media-clock epoch (already handled via `DRC_TSF_BASE_US` /
  `DRC_SYNTHETIC_TSF`).
