# 05 — The pad-facing wire formats, as the implementations believe them

**Purpose.** A code-grounded reference of what the GamePad's `vstrm` / `astrm` / `hid` / `cmd`
parsers are believed to accept, derived from the four implementations in this tree, then
differenced against the decrypted console session. Every place an implementation *tolerates*
one layout while another *emits* a different one is a hint about which fields the pad's parser
actually reads and which it ignores.

**Method / limits.** Offline audit only: no sockets opened, no files modified, nothing compiled
or executed against hardware. Line numbers are from the files as they exist in this tree at the
time of writing (`2026-11-04`). Statements tagged:

| Tag | Meaning |
|---|---|
| `path:line` | Directly readable in the cited source line(s); most code claims are cited this way. |
| `[C:path:line]` | Same, used inline where a citation would otherwise break a sentence. |
| `[M]` | Measured by me from `out/evidence/truth/*.bin` (decrypted real console session) during this audit; the analysis snippets are reproducible with `research/rce-hunt/mine_cmd.py`-style record framing (`>d 4s 4s I` per record). |
| `[DOC:path:line]` | Stated in prose in the cited doc/comment. |
| **INFERRED** | Consistent with code but not provable from code; flagged explicitly. |

Sources audited:

- `research/libdrc/` — the 2013 original (`Mema Hacking`), plus `web/docs/re/*.rst`.
- `research/wozt-libdrc/` — the fork that works on real hardware; the packet classes are
  byte-identical to libdrc, the streaming policy is not (`diff -r` confirmed: `vstrm-packet.cpp`,
  `astrm-packet.cpp`, `cmd-packet.cpp` identical; only the header comment differs).
- `research/barista-ref/` — BetaZay/Barista, `core/drh/*` + `docs/drc-media-packet-datasheet.md`
  + `docs/gamepad-recovery-experiment.md`.
- `pc2drc/libdrc-vnc/libdrc-thefloppydriver/` — thefloppydriver's 2013 fork **plus our local
  modifications** (the build installed to `out/libdrc/lib`).
- `tests/`, `run/`, `out/evidence/truth/`, `research/GROUND-TRUTH-SESSION.md`.

---

## 0. One correction to the ground-truth document, established first

`research/GROUND-TRUTH-SESSION.md` §4 line 81 records the console VSTRM header as:

```
b0 = 0xF0 | seq[9:6],  b1 = seq[5:0]
```

and §6 item 4 / §7 line 163 / §10 line 217 build on the conclusion that "the console puts the
low **6** bits of the 10-bit sequence in byte 1, while libdrc and Barista both put **8** bits
there".

**That is contradicted by the evidence file itself.** Over all 73,500 video datagrams in
`out/evidence/truth/port50120.bin`:

| Observation | Value |
|---|---|
| Distinct values of byte 0 | **4**: `0xf0, 0xf1, 0xf2, 0xf3` — a 2-bit field, not 4-bit `[M]` |
| Distinct values of byte 1 | **256**, range 0–255 — impossible if byte 1 held 6 bits `[M]` |
| Sequence discontinuities decoding `seq = ((b0 & 0x03) << 8) \| b1` | **9** of 73,499 transitions `[M]` |
| Sequence discontinuities decoding `seq = ((b0 & 0x0f) << 6) \| (b1 & 0x3f)` | **941** `[M]` |

The 9 residual discontinuities are single +2 steps plus one +134 jump at t+9.34 s (a re-key /
epoch boundary), i.e. exactly the shape a correct decode produces on a lossy capture. The
decode that GROUND-TRUTH §4 describes produces 941. **The console therefore uses the same
packing as libdrc and Barista: 2 bits in byte 0, 8 bits in byte 1, modulo 1024** — which also
falsifies the "differs, tolerated by pad" row in §7 and the open question in §10.

`tests/score-live-session.py:60-70` still carries both decodings side by side
(`seq_console`, `seq_libdrc`) and `tests/analyze_vstrm.py:37` carries a third
(`((p[0] & 0x0F) << 8) | p[1]`, a 12-bit field). Only the libdrc/Barista form survives contact
with the bytes.

Two further measured corrections used throughout this document:

- Format-message bytes 4–7 are `00 00 00 00` in **14,142 of 14,142** console format messages
  (`bytes4-7` counter over `port50121.bin`) `[M]`, confirming §4 lines 91-102.
- Format-message outer length bytes 2–3 are `00 00` in **14,142 of 14,142** `[M]`, and PCM
  payload length is `0x0680` (1664) in **27,573 of 27,573** `[M]`.

---

## 1. VSTRM (video, console 50020 → pad 50120)

### 1.1 Header bit packing, per implementation

Canonical layout, agreed by all four implementations and the RE notes
(`web/docs/re/sc-vstrm.rst:23-36`, realigned to the 16-byte fixed header that the code uses):

```
byte 0  bits 7..4  magic 0xF                [sc-vstrm.rst:24]
        bits 3..2  packet type (0 = vstrm)  [sc-vstrm.rst:25]
        bits 1..0  seq[9:8]                 [vstrm-packet.cpp:84-85]
byte 1             seq[7:0]                 [vstrm-packet.cpp:85]
byte 2  bit 7      init                     [vstrm-packet.cpp:129]
        bit 6      frame_begin              [vstrm-packet.cpp:130]
        bit 5      chunk_end                [vstrm-packet.cpp:131]
        bit 4      frame_end                [vstrm-packet.cpp:132]
        bit 3      has_timestamp (always 1) [vstrm-packet.cpp:49]
        bits 2..0  payload_size[10:8]       [vstrm-packet.cpp:116]
byte 3             payload_size[7:0]        [vstrm-packet.cpp:117]
bytes 4..7         timestamp, BE uint32 µs  [vstrm-packet.cpp:59-61, 88-93]
bytes 8..15        ext options, zero-terminated, max 8 bytes, read linearly
```

Per implementation, the *identical* bit positions are used — there is no packing dispute in
code, only in `tests/`:

| Implementation | seq packing | length field | header size | cite |
|---|---|---|---|---|
| libdrc | `((pkt_[0] & 3) << 8) \| pkt_[1]`, wraps at 1024 | 11-bit BE in `b2[2:0],b3` | 16 | `research/libdrc/src/vstrm-packet.cpp:55-57,77-81,112-118`; wrap at `src/video-streamer.cpp:77-80` |
| wozt | identical class, plus explicit `vstrm_seqid = 0` reset on re-init | same | 16 | `wozt-libdrc/src/video-streamer.cpp:390-395,492-496` |
| Barista | `(0xf0 \| (sequence>>8)&3)`, `sequence`, `sequence &= 0x3ff` | `(payload.size()>>8)&7`, `payload.size()` | 16 | `barista-ref/core/drh/encoder/media_streamer.cpp:164-167,812` |
| our local fork | identical to libdrc (class unchanged) | same | 16 | `pc2drc/.../src/vstrm-packet.cpp:91-97` |
| console `[M]` | 2 bits in `b0`, 8 bits in `b1`, mod 1024 (see §0) | 11-bit, max observed 1694 | 16 | `port50120.bin` |

Note the *first* packet of the console session: `f0 01 ce 9e 05 7c 5a 59 80 82 00 83 85 06 00 00`
(`out/evidence/truth/console-messages/video_first_frame.bin` offset 0) `[M]` — `b2 = 0xce` = init+frame_begin+ts+len[10:8]=6,
`len = 0x69e = 1694`, i.e. the console's very first video datagram is simultaneously *init*,
frame-begin, IDR-marked, and a full-size 1694-byte payload.

### 1.2 Payload cap constants — every asserted value

| Constant | Value | Where | Evidence / comment |
|---|---|---|---|
| `kMaxVstrmPayloadSize` | **1400** | `research/libdrc/include/drc/internal/vstrm-packet.h:35-37` | rationale: "DRC MTU is about 1800 bytes" |
| `kMaxVstrmPayloadSize` | **1400** | `research/wozt-libdrc/include/drc/internal/vstrm-packet.h:38-42` | **but with a measurement**: "at 1700 the GamePad stops decoding outright and asks for a keyframe on every frame" — see §5 |
| `kMaxVideoPayload` | **1694** | `barista-ref/core/drh/encoder/media_streamer.cpp:53-56` | "The real console and Vanilla control captures split raw DRH chunks at 1694 bytes" |
| `kMaxVstrmPayloadSize` | **1694** | `pc2drc/.../include/drc/internal/vstrm-packet.h:39` | `1694; //1586; //set to 1600 if this doesn't work pls thx <3 -thefloppydriver` |
| (implicit) | 1694 | `tests/codec_probe.cpp:35-36` | `kMaxVstrmPayload=1694`, `kPacedPayload=1400` |
| (implicit) | 1710 = 16+1694 | `tests/score-live-session.py:26` | `"video_pkt_max": 1710` |
| (assertion) | ≤ 0x7FF | `tests/protocol_test.cpp:92-97` | asserts the cap fits the 11-bit length field |

Console `[M]`: maximum `len` over 73,500 datagrams = **1694**; the datagram size histogram peaks
at 478/469/299 B (typical P-frame chunks) with 2,827 datagrams at exactly 1710 B.

**Differential hint.** 1400 vs 1694 is not "one works, one doesn't" — both work; wozt *measured*
that 1700 breaks the pad (§5). The pad's reassembly buffer therefore sits somewhere in
1694 < cap ≤ 1699 `[M + DOC]`. That single number is the cleanest memory-safety probe in the
whole protocol: `len` is 11 bits (max 2047) and the pad must size a buffer for it.

### 1.3 Chunking: 5 chunks × 6 macroblock rows

All implementations split a frame into exactly five logical chunks of six 16-pixel rows:

- `include/drc/internal/h264-encoder.h` `kH264ChunksPerFrame` (used at `video-streamer.cpp:56-58`).
- Barista: `DrcVideoChunkCount = 5`, `DrcVideoMacroblocksPerChunk = 864/16*6 = 324`
  (`barista-ref/core/drh/encoder/encoder.h:16-18`), documented as `chunk 0: macroblock rows 0..5`
  … `chunk 4: rows 24..29` in `docs/drc-media-packet-datasheet.md:110-118`.
- RE note: `web/docs/re/sc-vstrm.rst:74-89` — "Cut each frame into 5 equal chunks … 854x96 region
  (6 macroblock rows)".

Flag emission (identical in all four, `research/libdrc/src/video-streamer.cpp:86-89`):
`frame_begin` = first packet of chunk 0; `chunk_end` = **last packet of each chunk** (not each
chunk's only packet); `frame_end` = last packet of the last chunk. Barista documents the same
(`media_streamer.cpp:809-811`, `datasheet:100-103`).

A chunk larger than the cap is split into *multiple datagrams*, only the last carrying
`chunk_end`. Measured console behaviour agrees `[M]` — over 14,138 distinct frame timestamps in
`port50120.bin`: **14,128 frames have exactly 5 `chunk_end`s**, 9 have 4 (truncated at an epoch
boundary), 1 has 1; 14,137 have a `frame_end`; average 5.20 datagrams/frame. (GROUND-TRUTH §4
line 77 reports "5 for 13,332 frames" — that figure does not reproduce from the same file with a
`chunk_end` count; the count above does.)

`tests/scheduler_test.cpp:64-69` asserts the split arithmetic
(`ChunkPacketCount(4054,1694)==3`, exact-fit → 1, empty → 0, 1832 needs splitting, 1137 does not).

### 1.4 Ext-option emission and order — the largest real divergence

Option semantics (`web/docs/re/sc-vstrm.rst:50-70`): `0x00` end, `0x80` IDR (no arg),
`0x81` unimplemented (1 arg), `0x82` frame rate (1 arg: 0=59.94,1=50,2=29.97,3=25),
`0x83` force decoding (no arg), `0x84` unset force flag (no arg), `0x85` NumMbRowsInChunk (1 arg).

libdrc's emitter has a quirk that fixes the *order* for everything downstream. `ResetPacket`
pre-fills three options (`vstrm-packet.cpp:48-52`):

```
pkt_[8]  = 0x83   // Force decoding
pkt_[9]  = 0x85   // macroblocks per row, value next
pkt_[10] = 6
```

then `SetIdrFlag`/`SetFrameRate` *append after them* because `SetExtOption` scans for the first
zero byte (`vstrm-packet.cpp:150-159`). Result:

| Emitter | IDR frame bytes 8..15 | P frame bytes 8..15 | cite |
|---|---|---|---|
| libdrc (upstream) | `83 85 06 80 82 00 00 00` | `83 85 06 82 00 00 00 00` | derived from `vstrm-packet.cpp:46-53,95-110,150-166` |
| Barista *baseline* | `83 85 06 80 82 00` + zeros | `83 85 06 82 00` + zeros | `media_streamer.cpp:173-180` |
| Barista *reference_options* | `80 82 00 83 85 06 00 00` | `82 00 83 85 06 00 00 00` | `media_streamer.cpp:181-193`; asserted in `media_streamer.cpp:531-548` |
| our local fork | `80 82 00 83 85 06 00 00` | `82 00 83 85 06 00 00 00` | `pc2drc/.../src/vstrm-packet.cpp:54-89` (`NormalizeExtOptions`) |
| console `[M]` | `80 82 00 83 85 06 00 00` (46 pkts) | `82 00 83 85 06 00 00 00` (73,454 pkts) | option histogram over `port50120.bin` |

Note Barista's *default* still emits libdrc's order and only reproduces console order under
`DRCD_REFERENCE_VIDEO_OPTIONS` (`media_streamer.cpp:684-687`), and Barista works on hardware
either way. Our local fork's comment records the opposite experience:

> `pc2drc/.../src/vstrm-packet.cpp:60-64` — "Upstream libdrc pre-filled pkt_[8..10] with
> 83 85 06 and appended 80/82 after them, emitting "83 85 06 [80] 82 00" - force-decode first
> and the IDR marker in the middle. Measured live on 2026-11-04: **the pad then never starts
> decoding (zero resync requests, pad falls back to its "cannot connect" screen) even though the
> slice data itself is conformant.**"

**Differential hint (important).** The option area is a *linear scan terminated by 0x00* with an
optional argument byte per option. Nothing in the area is positionally fixed: `0x83` at offset 8
vs offset 11 must mean the same thing. If the pad's behaviour genuinely depends on order, then
the pad is **not** rescanning; it is very likely indexing a parsed table positionally
(first-option / second-option slots) — the one behaviour that would explain both Barista (works,
`83 85 06 80 …`) and our observation (fails, `83 85 06 80 …`) being inconsistent. Since the two
observations conflict, the honest reading is: **the option area is a genuine parser with at least
one order-sensitive path, and the exact rule is unknown** `[INFERRED]`. Treat this as the top
fuzz target in VSTRM after the length field: 8 bytes, 5 known opcodes, 2 of them argument-bearing,
one of them (`0x85`) a *count* that the video manager presumably multiplies by the macroblock
width.

Edge cases in the reference parsers themselves, which a pad parser plausibly shares:

- `GetExtOption` returns `false` for a *value-bearing* option found at index 7 (no room for a
  value) — `vstrm-packet.cpp:134-148`, in particular `if (i == 7) return false;`. So `0x82` in
  the **last** option byte means "frame rate unknown", silently. A pad doing the same would
  accept `… 82` at offset 15 with a garbage read of the *next* byte (the first payload byte) if it
  does not bounds-check — INFERRED, but this is exactly the shape of a 1-byte overread.
- `SetExtOption` *asserts* on overflow: `assert((i + required_space <= 8) || "out of space in vstrm ext header")`
  (`vstrm-packet.cpp:161`). Release builds compile it out. An implementation that emits blindly
  can therefore write past `pkt_[15]` into payload. Not a pad bug, but it marks the boundary the
  pad must also check.
- `ClearExtOption` has an index bug: the inner loop increments `i` as well as `j`
  (`vstrm-packet.cpp:171`: `for (int j = i + 1 + has_val; j < 8; ++i, ++j)`), so clearing an
  option shifts twice per byte and can leave stale opcodes behind. Used by
  `SetFrameRate(kUnknown)` and `SetIdrFlag(false)`.

### 1.5 Timestamp handling

| Implementation | Field | Source of value | cite |
|---|---|---|---|
| libdrc | `b4..7` BE µs | `GetTsf(&tsf); return (s32)(tsf & 0xffffffff)` read from `/sys/class/net/<if>/device/tsf` (or `/tsf`) | `src/tsf-linux.cpp:75-99`, `video-streamer.cpp:41-45` |
| wozt | same, but **cached**: a failed TSF read re-uses the last good value, with the comment that a monotonic-clock slew "drags the timestamps into the past at a millisecond a second. Video tolerates it; **the GamePad drops audio that arrives late, and goes silent**" | `wozt-libdrc/src/video-streamer.cpp:51-67` |
| Barista | AP TSF in µs directly; format packet gets `tsf - 1250`, video is stamped with the *same* value and sent ~5000 µs later | `video_packet_schedule.h:10-24`; `media_streamer.cpp:659,830-833`; `datasheet:177-180` |
| our local fork | `DRC_SYNTHETIC_TSF=1` → monotonic µs since first call, plus `DRC_TSF_OFFSET_US` / `/var/run/drc/tsf-offset-us` (re-read 1/s) so the epoch can be aligned to the radio | `pc2drc/.../src/tsf-linux.cpp:80-109,114-159` |
| console `[M]` | live TSF-domain µs; `b4..7` identical across all datagrams of a frame; format packet carries the *same* instant in **little-endian** at offset 8 | `port50120.bin` / `port50121.bin`; §4 lines 74-91 |

The cross-endianness is the trap worth flagging: **the video timestamp is big-endian, the format
message's timestamp is little-endian, and both describe the same instant.** Any pad code that
reuses one conversion routine for both produces a 16-second-scale error. Measured console
samples `[M]`: first frame `b4..7 = 05 7c 5a 59` → `0x057c5a59` = 92,035,673 µs; the
`video_format_message.bin` sample is `02 d8 7b 05` LE → `0x057bd802` = 92,003,074 µs, i.e. the
format precedes its frame by ~32 ms in that particular sample pair (the median lead over the whole
capture is 5.1 ms per Barista). Do not read those two evidence files as one frame pair.

libdrc's `GenerateAstrmPacket` also writes a **fixed** header timestamp `0x00100000`
(`video-streamer.cpp:102`) while putting the live timestamp in the payload only, and emits four
`0x3e80` (16000) clock fields. Console `[M]` writes **zero** in header bytes 4..7 and

```
80 3e 00 00 | 80 3e 00 00 | 08 52 00 00 | 08 52 00 00    (16000, 16000, 21000, 21000 µs)
```

### 1.6 `init` flag and IDR policy

| Implementation | When `init` is set | cite |
|---|---|---|
| libdrc | `bool init_flag = !*vstrm_inited;` — first frame of the process only | `src/video-streamer.cpp:50-54` |
| Barista | `!initialized \|\| (recovery_init && idr)`, where `recovery_init` = `DRCD_IDR_INIT` (default **on**), i.e. every recovery IDR | `media_streamer.cpp:38-45,810` |
| our local fork | first frame only, with a comment explaining why re-asserting it on IDRs is self-defeating | `pc2drc/.../src/video-streamer.cpp:90-104` |
| console `[M]` | **25 datagrams — exactly the first frame**; never again, including after the resync burst at t=74.9 s | `sum(p[2]&0x80)` over `port50120.bin` = 25 |

IDR policy, all four differing:

- libdrc: `send_idr = resync_requested || !vstrm_inited` — every resync request becomes an IDR
  (`video-streamer.cpp:193`), cleared only once the IDR has been sent (`:185-188,200`).
- wozt: rate-limited (`DRC_RESYNC_US`, default 500 ms) and, by default, answered with an x264
  **intra-refresh sweep** rather than an IDR (`video-streamer.cpp:539-551`); the flag is taken
  from the encoder's real NAL type, not from the request
  (`frame_is_idr = encoder_->CurrentFrameIsIdr()`, `:554-559`).
- Barista: `all_idr || frame_number - last_idr_frame >= 60 || (resync_requested && !coalesced) || force_idr`
  (`media_streamer.cpp:751-752`), then "every IDR is followed by a format-only slot"
  (`format_slot_scheduler.h:75-76`), documented as `format + IDR video, one format-only slot,
  format + P` (`datasheet:182-189`).
- our local fork: `IdrPolicy` — first frame, proactive every 60 frames, request-driven only when
  the request cadence *changes* (50 ms debounce) and further capped at 1/s
  (`idr-policy.h:15-50,68-103`); plus the console's format-only recovery slot.
- console `[M]`: ~9 IDR frames in 238 s (46 IDR-marked datagrams / 5 chunks) ≈ one per 26 s, plus
  the single IDR answering the resync burst.

### 1.7 VSTRM differential summary — what the pad tolerates

| Field | libdrc/wozt | Barista | local | console | Verdict / hint |
|---|---|---|---|---|---|
| seq packing | 2+8 bits | 2+8 | 2+8 | 2+8 `[M]` | **all agree** (GROUND-TRUTH §4 was wrong, §0) |
| payload cap | 1400 | 1694 | 1694 | 1694 `[M]` | pad accepts both; wozt measured 1700 fails → pad's buffer edge in (1694,1700] |
| option order | `83 85 06 [80] 82 00` | default same, reference opts console order | console order | console order `[M]` | Barista tolerates both, our run did not → order-sensitive path exists |
| `init` on IDRs | no | yes (default) | no | first frame only `[M]` | pad tolerates both; 25-packet init is the console's shape |
| header ts on format msg | `0x00100000` fixed | n/a (32-byte form) | `00 00 00 00` + `DRC_FORMAT_OUTER` | `00 00 00 00` `[M]` | tolerated |
| format outer length | 24 (`0x18`) | 0 | 0 | 0 `[M]` | **pad tolerates a non-zero declared length with a 24-byte body** — i.e. it sizes the format body by packet length, not by the field |
| clock fields | 16000 ×4 | 16000,16000,21000,21000 | same | same `[M]` | tolerated but matched |
| cadence | 59.94 target, min 1000 µs rearm | 16683 µs period, fixed slot | 16683 µs, 5000 µs format lead | 16,683/16,684 µs `[M]` | pad needs ≤ ~16.7 ms frames |
| per-frame burst | whole frame at once | chunk windows 0/3/6/9/11 ms | same | same (datasheet:193-207) | burst is a *loss* cause, not a parse error |

---

## 2. CMD (command plane, console 50023 → pad 50123)

### 2.1 Outer header (8 bytes, little-endian)

`web/docs/re/sc-cmd.rst:32-37`; `research/libdrc/src/cmd-packet.cpp:44-91`:

| Off | Width | Field | Notes |
|---|---|---|---|
| 0..1 | le16 | packet type | 0 query, 1 query-ack, 2 reply, 3 reply-ack (`cmd-packet.h:36-41`) |
| 2..3 | le16 | query type | 0 generic, 1 UVC/UAC, 2 time (`cmd-packet.h:43-47`) |
| 4..5 | le16 | payload size | "should be packet_size − sizeof(CmdHeader)" (`sc-cmd.rst:50-51`) |
| 6..7 | le16 | sequence id | same for all fragments of one request (`sc-cmd.rst:53-55`) |

`kCmdHeaderSize = 8`, `kMaxCmdPayloadSize = 1400` (`research/libdrc/include/drc/internal/cmd-packet.h:33-34`).

Measured `[M]` (1,475 console→pad datagrams): types {0: 1030, 3: 445}, query types
{0: 1011, 1: 456, 2: 8}, declared lengths {1040: 778, 0: 445, 48: 228, 12: 13, 8: 4, 44: 3,
17: 2, 324: 1, 114: 1}; seq runs 8 → 1044 as a single incrementing u16 across the session.

### 2.2 Generic command header (12 bytes, mixed endianness — this is the trap)

`web/docs/re/sc-cmd.rst:69-79`; `research/libdrc/src/cmd-packet.cpp:105-198`:

| Off (rel. to payload) | Width | Field | Endianness / bit layout |
|---|---|---|---|
| 0 | u8 | magic | always `0x7e` (`cmd-packet.cpp:109`) |
| 1 | u8 | version | always `0x01` (`cmd-packet.cpp:110`); "copied from query to reply" (`sc-cmd.rst:81-83`) |
| 2 | 8 bits | transaction id [11:4] | `tid = (pkt_[2] << 8) \| (pkt_[3] >> 4)` (`cmd-packet.cpp:119-121`); `assert(tid < 0x400)` (`:156`) |
| 3 bits 7..4 | 4 bits | transaction id [3:0] | same |
| 3 bit 3 | 1 bit | final fragment | `(pkt_[3] & 0x8) != 0` (`cmd-packet.cpp:123-125`) |
| 3 bits 2..0 + 4 | 11 bits | fragment id | `((pkt_[3] & 0x7) << 8) \| pkt_[4]` (`:127-129`); `assert(fid < 0x800)` (`:170`) |
| 5 | u8 | flags | query `0x40` (`cmd-packet.h:82-84`); reply `((q.flags>>3)&0xFC)\|1` (`sc-cmd.rst:90-92`) |
| 6 | u8 | service id | |
| 7 | u8 | method id | |
| 8..9 | be16 | error code | **big-endian** (`cmd-packet.cpp:143-145,187-190`) |
| 10..11 | be16 | payload size | **big-endian** (`cmd-packet.cpp:151-153,196-197`) |

**Ambiguity to record.** `research/rce-hunt/mine_cmd.py:50-51` (a sibling tool in this tree)
reads `tid = (g[2] << 4) \| (g[3] >> 4)` and `frag = ((g[3] & 0xF) << 8) \| g[4]` — the same
12-bit tid as libdrc but shifted down 4 bits (the correct form is `(g[2] << 8) \| (g[3] >> 4)`,
whose low nibble `g[3] >> 4` then needs no shift), and a **4-bit** fragment id that includes the
final-fragment bit that libdrc treats separately (11-bit `& 0x7`). Measured resolution `[M]`:
the console's blob header is `7e 01 01 b0 00 42 00 11 …` and its tid field must be `0x10b`
(`BOOT-AND-MODES.md:243` and `run/command-plane.py:10` both say `tid 0x10b`). Only
`(0x01<<8)\|(0xb0>>4) = 0x10b` produces that; `mine_cmd.py`'s form yields `0x1b`. **libdrc's
packing is correct; `mine_cmd.py:50` is buggy** — worth fixing before any cmd fuzzing campaign
trusts its output.

### 2.3 ACK / reply state machine and retries

libdrc (`src/cmd-protocol.cpp`):

```
kTimeoutMs = 1000 ; kMaxRetries = 10                 (:38-39)
query  -> state kQueryAck, arm timer 1000 ms         (:169-183)
PacketReceived: if type==kReply -> SendReplyAck(same seq) UNCONDITIONALLY (:139-141)
                if no state with that seq -> return            (:143-147)
                if type != expected state -> return            (:149-151)
                kQueryAck -> state = kReply                    (:158-159)
                kReply    -> cancel timer, callback(true, payload), remove state (:153-165)
RetryOperation: ++retries; if retries >= 10 -> callback(false), remove state;
                else SendQuery again (fresh timer, state back to kQueryAck) (:193-208)
```

Barista (`core/drh/runtime_transport.cpp`): `kCommandTimeout = 1s`, `kCommandMaxAttempts = 10`
(`:51-52`); stages `Idle → AwaitingAck → AwaitingReply` (`:387-392`); a type-2 reply is acked
*before* validation (`:875-881`); the ACK itself is a bare 8-byte `type 3, query, len 0, seq`
(`BuildCommand(3, query_type, sequence, {})`, `:877`); a type-1 ACK with a **non-empty payload is
rejected** (`:897-903`); a duplicated/unknown reply is logged and ignored (`:883-890`).

Measured pad behaviour `[M]`:

- The pad's query-ack is exactly `01 00 02 00 00 00 08 00` — type 1, query 2, **declared length 0**,
  seq echoed. 1,034 such 8-byte packets pad→console. This confirms both implementations'
  "ACK carries no payload" rule.
- The pad's reply-acks to the console are `03 00 01 00 00 00 29 03`-shaped: type 3, query echoed,
  length 0, seq echoed.
- The pad also *replies* in 24 B (424×), 792 B (5×), 20 B (5×), 28 B (3×), 48 B (3×), 21 B (1×).
- Console acked 445 replies with 8-byte type-3 packets (`[M]`, matches §4 line 110).

**Reliability notes worth carrying into a stress harness** (all `[C]`, libdrc unless stated):

- `RetryOperation` `assert`s the state still exists (`cmd-protocol.cpp:195`); a timer that fires
  after the state was removed aborts a debug build. The timer normally dies because returning
  `false` from a callback drops the event and closes its fd (`events.cpp:145-149`,
  `events.h:38-40`), so the window is narrow — but it is real, because removal happens from the
  receive thread (`PacketReceived` → `RemoveState`, `:165,129-132`) while the timer lives on the
  event thread.
- `AsyncQuery` takes `cmd_st = &cmd_in_flight_[seqid]` under the lock and then uses that raw
  pointer outside it (`:77-91`); `std::map` node stability saves it for inserts of other keys, but
  a concurrent `RemoveState` of the same key is a use-after-free.
- `u16 seqid_` increments with no wrap handling, and `assert(cmd_in_flight_.find(seqid) ==
  cmd_in_flight_.end())` (`:80-81`) is debug-only — after 65,536 queries a sequence id can be
  reused while an older transaction is still in flight.
- libdrc never re-sends its reply-ack as a *stateful* action: `PacketReceived` sends one for any
  type-2 packet **before** the state lookup (`:138-141`), so a duplicated pad reply is acked again
  and then discarded — which is the correct behaviour by accident.
- Barista avoids all three shapes by holding transactions in a fixed array keyed on
  `(query_type, sequence)` and by validating before acting (`runtime_transport.cpp:394-406,
  865-978`).

### 2.4 Fragmentation: flags `0x40` / `0x42`, the final bit, tid and fid

Measured `[M]`, over the 778 four-fragment state messages in `port50123.bin`:

| Property | Value |
|---|---|
| generic flags byte (payload+5) | `0x42` × 584 (continuation), `0x40` × 194 (**final**) |
| final bit (payload+3 bit 3) | set in exactly the 194 packets that carry flags `0x40` |
| fragment id (11-bit) | cycles 0,1,2,3 and restarts — strict **M M M S** grouping, 194 complete messages + 2 trailing M fragments |
| transaction id | `0x10b`, `0x10c`, `0x10d` … (4 fragments per tid) |
| service / method | `0` / `0x11` in all 778 |
| generic payload size (be16 @ +10) | `1028` in all 778 |
| outer declared length | `1040` in all 778, datagram 1048 |

So the pad (or rather: the console's own convention that the pad must accept) marks
continuation with **bit 1 of the flags byte** (`0x40 | 0x02`) and termination with `0x40` alone,
*and* redundantly with the header's final-fragment bit. `sc-cmd.rst:90-92` describes exactly this
("If `flags & 0x3`, this is a multi-fragment query"), and the reply form
`((query.flags>>3)&0xFC)|1` evaluates to `0x09` for both `0x42` and `0x40` — which is precisely
what the pad sent back `[M]` (`7e 01 01 b8 00 09 00 11 …`, flags byte = `0x09`).
**`0x43` does not appear anywhere in the capture or in any implementation** — a query with
`flags = 0x43` would mean "multi-fragment AND bit 0 set"; treat its semantics as unknown and as a
fuzzing candidate.

### 2.5 Max-payload constants — who asserts what

| Constant | Value | Who | Meaning |
|---|---|---|---|
| `kMaxCmdPayloadSize` | **1400** | `libdrc/include/drc/internal/cmd-packet.h:34`, same in wozt and local | whole outer payload (incl. generic header) |
| `kMaxGenericCmdPayloadSize` | **1388** = 1400 − 12 | `cmd-packet.h:77-78`; `assert(size <= kMaxGenericCmdPayloadSize)` at `cmd-packet.cpp:193` | inner generic payload |
| UIC-config inner payload | **772** (`0x304`) | Barista `runtime_transport.cpp:340`; libdrc `streamer.cpp:203-205` expects reply **`0x310` = 784** and loads `reply+0x10` **`0x300` = 768** | console reply is 12 + 772 = 784, datagram 792 `[M]` |
| UIC state blob inner payload | **1028** (`0x404`) | console `[M]`; `sc-cmd.rst:121` records "Max. 1028" for service 0 method 0x03 (firmware data) | the blob **saturates the field** |
| UIC state blob outer | **1040** (`0x410`), datagram **1048** | console `[M]`; `GROUND-TRUTH §4`, `BOOT-AND-MODES.md:239-243`, `run/replay-console-cmd.py:5` | note `BOOT-AND-MODES.md:243` calls the *outer* field `payload_size = 1028`; the bytes say 1040 outer / 1028 inner |
| our own tooling cap | **1016** | `run/pad-state.py:61-62` — `if len(payload) > 1016: raise ValueError("generic payload exceeds kMaxGenericCmdPayloadSize")` | **below what the console actually sends** — this tool cannot build the console's own 1028-byte fragment |
| IRCOM payload/reply | **520** | `sc-cmd.rst:245-246` (service 5 method 0x11) | the only place 520 appears; no implementation asserts it |
| UIC EEPROM write | **258** | `sc-cmd.rst:237` (service 5 method 0x0c) | not asserted in code |
| UVC/UAC packet | **48** | `kUvcUacCmdPacketSize` `cmd-packet.h:119`; console sends `type 0/query 1/len 48`, datagram 56 `[M]` | |
| Time command | **8** | `kTimeCmdPacketSize` `cmd-packet.h:156`; console sends `type 0/query 2/len 8`, datagram 16 `[M]` | |
| recv buffer | **2000** | `libdrc/src/udp.cpp:154-155` (`int msg_max_size = 2000`) vs `CmdPacket` array `8+1400` | see §7 memory note |

**The 1028 number is the interesting one.** The console sends 778 fragments of exactly 1028
inner bytes at ~28/s for the first 28 s of a session and then stops. Whether the pad's cmd parser
has a fixed 1028-byte reassembly buffer, or 1028 is simply the console's own chunking choice, is
not determinable from these sources — **INFERRED**, but the coincidence with
`sc-cmd.rst:121`'s "Max. 1028" for a *different* method points at a shared driver-side maximum.

### 2.6 How replies are matched

- libdrc: by **outer sequence id only** (`FindState(seqid)`, `cmd-protocol.cpp:120-127,143-144`);
  the type must equal the expected next state. Query type is *not* part of the key.
- Barista: by **(query_type, sequence) pair** and only while the transaction is not `Idle`
  (`find_command_transaction`, `runtime_transport.cpp:969-978`), plus a payload **validator**
  per command kind — size, magic `0x7e 0x01`, service/method echo, error==0, inner length
  (`ValidateGenericReply`, `:311-333`; `ValidateCommandReply`, `:335-356`).
- Barista additionally treats a *type* mismatch, an unexpected field, or a duplicate as a
  logged event rather than a resend trigger (`:886-890,899-903,916-919`).

Because the console re-uses one incrementing u16 for the whole session and the pad echoes it,
sequence matching is the only correlation available — which makes the sequence field an obvious
fuzz primitive (see §7).

### 2.7 UVC/UAC and time command details

`sc-cmd.rst:266-308` documents that UVC/UAC (query type 1) uses its **own** 48-byte layout, not
the generic header, that it is issued every second, and — critically for the pad's state machine —
"**Recent versions of the GamePad firmware will only show the video stream after receiving one
such command**". libdrc and Barista disagree on the endianness of the volume fields:

- libdrc `src/cmd-packet.cpp:225-235` reads `(pkt_[6] << 8) | pkt_[7]` (big-endian);
  our local fork flips all three to little-endian (`pc2drc/.../src/cmd-packet.cpp:226-234,258-269`).
- Barista: "Authenticated real-console capture uses little endian for these fields"
  (`runtime_transport.cpp:267-269`, and `SynchronizeUvcUacRequest` at `:358-385`).

Barista also records the empirical gate sequence: `request[0]` changes `0 → 1` after the first
validated reply (`:361-363`), the camera only produces non-black frames if bytes 18–47 carry the
console's image settings (`kConsoleCameraSettings`, `:257-262`), and a pad "reports byte 13 as
set" while the camera runs (`:373-376`).

Time command (query type 2) is 8 bytes: `u16 days; u16 pad; u32 seconds` (`sc-cmd.rst:317-323`),
little-endian in libdrc (`cmd-packet.cpp:303-321`). The console sends 4 of them, `len 8`, *before*
video starts `[M]` (`00 00 02 00 08 00 08 00 a4 ef 00 00 30 5e 00 00` → days `0xefa4`, seconds
`0x00005e30`). Our local fork sends one per second (`uvcuac-synchronizer.cpp` addition,
`DRC_SEND_TIME`) with a 2000-01-01 epoch.

---

## 3. ASTRM (audio + video-format, console 50021 → pad 50121)

### 3.1 Header (8 bytes)

`web/docs/re/sc-astrm.rst:27-35`; `research/libdrc/include/drc/internal/astrm-packet.h` +
`src/astrm-packet.cpp`:

| Off | Bits | Field | Code |
|---|---|---|---|
| 0 | 7..5 | format (0 PCM24k, 1 PCM48k, 2 ALAW24k, 3 ALAW48k, 4 ULAW24k, 5 ULAW48k) | `astrm-packet.cpp:49-51,73-75` |
| 0 | 4 | mono | `:110` |
| 0 | 3 | vibrate | `:111` |
| 0 | 2 | packet type (0 audio, 1 video format) | `:53-55,77-79` |
| 0..1 | 1..0 + 1 | seq id, **10-bit, 2 bits in byte 0, 8 in byte 1** | `:57-59` |
| 2..3 | 16 | payload size, **big-endian** | `:69-71,93-99` |
| 4..7 | 32 | timestamp, **little-endian** | `:61-63,86-91` |

`kAstrmHeaderSize = 8`, `kMaxAstrmPayloadSize = 1700` (`astrm-packet.h:33-34`).

Measured console `[M]` (`port50121.bin`, 41,715 datagrams): PCM packets are 1,672 B with byte 0 ∈
{`0x20`,`0x21`,`0x22`,`0x23`} (PCM48k, stereo, audio-data, seq high bits — the vibrate bit `0x08`
is **never** set in this capture), payload length `0x0680` = 1664 in 27,573/27,573, header
timestamp little-endian, sequence continuous (4 discontinuities in 27,573).

### 3.2 PCM packet size and cadence — three different answers in code

| Implementation | frames/packet | payload | interval | cite |
|---|---|---|---|---|
| libdrc | `kSamplesPerPacket = 384` | 1536 B (datagram 1544) | `1000 / (48000/384)` = **8 ms** | `src/audio-streamer.cpp:40-48` |
| wozt | unchanged (same file) | 1536 | 8 ms | — |
| Barista | `kAudioFramesPerPacket = 416` | **1664** (datagram 1672) | 8,666,666 ns | `media_streamer.cpp:57-62`; asserted at `:549-586` |
| our local fork | `kSamplesPerPacket = 416` | 1664 | 8.666 ms, with the note that 384/8 ms "is not what the pad sees from a real console" | `pc2drc/.../src/audio-streamer.cpp:47-52,89-90` |
| console `[M]` | 416 | 1664 | median 8.67 ms | `port50121.bin` |

libdrc's own comment claims 384 samples is "the best compromise between packet size (must be <
1600 bytes)" (`audio-streamer.cpp:42-47`) — an explicit statement that the *author* believed the
astrm parser had a 1600-byte ceiling, contradicting `kMaxAstrmPayloadSize = 1700` two files away.
The pad obviously accepts 1664. **Differential hint:** the astrm length field is a full 16-bit
big-endian value with no cap asserted on the receive side; a pad that trusts it and copies into a
fixed 1664/1700-byte buffer is the second-most-obvious overflow in the protocol.

Sequence wrap: libdrc `seqid = (seqid + 1) & 0x3FF` (`audio-streamer.cpp:100`), Barista
`sequence &= 0x3ff` (`media_streamer.cpp:1104`).

### 3.3 The 32-byte video-format message

Distinguished by `payload[0] & 0x04` (type bit) — `sc-astrm.rst:52-54`,
`datasheet:154-159`, `media_streamer.cpp:115-117`.

Console layout `[M]` (constant over all 14,142 instances):

```
04 00 00 00 | 00 00 00 00 | <ts LE>     | 80 3e 00 00 | 80 3e 00 00 | 08 52 00 00 | 08 52 00 00 | 00 00 00 00
 ^  ^  ^  ^   ^^^^^^^^^^^   ^^^^^^^^^    ^^^^^^^^^^^   ^^^^^^^^^^^   ^^^^^^^^^^^   ^^^^^^^^^^^   ^^^^^^^^^^^
 |  |  |  |   bytes 4..7    frame ts     16000 µs      16000 µs      21000 µs      21000 µs      zero tail
 |  |  |  +-- outer length = 0x0000 even though a 24-byte body follows
 |  |  +----- outer bytes 1..2 = 0
 |  +-------- type 0x04
 +----------- byte 0 carries no sequence number on this message
```

Per-implementation body construction:

- libdrc `src/video-streamer.cpp:99-117`: header ts fixed `0x00100000`, **declared length 24**,
  payload = ts LE + `80 3e 00 00` ×4 + 4 zero bytes. Sent from the astrm socket immediately
  before the frame's video datagrams, no lead (same timer tick, `:180-183`).
- Barista `media_streamer.cpp:129-157`: 32 bytes, `packet[0]=0x04`, `packet[4..7]=11 11 81 08`,
  ts LE at 8, `16000,16000,21000,21000`, declared length field left zero (comment at `:133-135`:
  "Match all 2,032 authenticated reference format packets: their outer length field is zero
  despite the 24-byte body"). Published at `tsf − 1250 µs`, video ~5000 µs later
  (`video_packet_schedule.h:10-13`).
- our local fork `pc2drc/.../src/video-streamer.cpp:167-201`: identical to Barista but bytes 4..7
  default to `00 00 00 00` with `DRC_FORMAT_OUTER` to restore `11118108`, plus
  `DRC_FORMAT_LEAD_US` (default 5000) before the frame.
- Console `[M]`: as above; median format→first-video lead 5.1 ms (`datasheet:177-180`,
  `GROUND-TRUTH §4`).

The pad's dependency on this message is stated most bluntly in our local fork:

> `pc2drc/.../src/video-streamer.cpp:150-154` — "It is what gives the pad the playback timebase
> for the matching video frame, and **the pad does not start decoding without it** (measured
> 2026-11-04: with this port firewalled off the pad stayed on its "cannot connect" screen and
> never sent a single 50010 message; once the packets were allowed through the pad began
> requesting frames)."

and by wozt for the degenerate case:

> `wozt-libdrc/src/video-streamer.cpp:398-404` — "The synchronisation packet, which is NOT
> optional … a branch that never fills it in sends an empty packet sixty times a second, and the
> **GamePad — which takes its timebase from these — shows nothing at all while the video packets
> arrive perfectly.**"

**Differential hint.** The format message is parsed by a *different* service path than PCM (same
port, same 8-byte ASTRM-like envelope) and it has three tolerances the pad must be exercising:
(a) declared length 0 with a 24-byte body → the pad sizes the body from the UDP length, not the
field; (b) header bytes 4..7 free (`00000000` / `11118108` / `11118188` / `10108108` all observed
across captures per `datasheet:171`); (c) `video_format` (bytes 28..31) zero in every observed
instance, so the pad's use of that field is unknown. Byte 4..7 is a 4-byte unvalidated field
inside a fixed-size message — an excellent candidate for "what does the decoder do with it".

### 3.4 Cadence the pad expects

PCM ~8.67 ms (115.4/s), format once per video frame (59.9/s), video 5 chunk windows per 16.683 ms
slot. `[M]` + `datasheet:193-207`. Also measured `[M]`: format interval median 16.69 ms.

---

## 4. INPUT (pad 50122 → console 50022, 128-byte blob)

### 4.1 Documented layout

`web/docs/re/sc-input.rst:25-43` — the struct is `u16 seq_id; u16 buttons; u8 power_status;
u8 battery_charge; u16 left_stick_x/y; u16 right_stick_x/y; u8 audio_volume;
AccelerometerData(3×s16); GyroscopeData(3×s24); MagnetData(6B); TouchscreenData(10×(2×12-bit
coords in a u16 with 1 pad bit + 3 extra bits)); char unk0[4]; u8 extra_buttons; char unk1[46];
u8 fw_version_neg;` — sent by the pad "180 times per second" (`sc-input.rst:12-13`), generated by
the UIC and passed through unmodified (`:15-16`).

### 4.2 What the implementations actually read

| Field | libdrc `src/input-receiver.cpp` | Barista `runtime_transport.cpp` / `gamepad_home_menu.cpp` |
|---|---|---|
| size gate | `msg.size() != 128 → return` (`:142-145`) | `payload.size() != 128 → return` (`:818-819`); `ReadTouch` also gates (`gamepad_home_menu.cpp:75-76`) |
| sequence | **not read** | `ReadBe16(packet)` — **big-endian** at 0..1 (`:140`) |
| buttons | `(msg[80] << 16) \| (msg[2] << 8) \| msg[3]` (`:149`) | identical (`:141-142`, `gamepad_home_menu.cpp:58-64`) |
| power status | `msg[4]` (`:204`) | `packet[4]` (`:145`) |
| battery | `msg[5]` (`:202`) | `packet[5]` (`:146`) |
| sticks | 4 × le16 at `6+2i` = 6,8,10,12; clamp 900..3200, midpoint, dead zone 0.1 (`:153-172`, constants `:40-45`) | identical clamp/dead-zone (`:184-193`), le16 at `6+i*2` (`:143-144`) |
| audio volume | `msg[14]` (`:203`) | `packet[14]` (`:147`) |
| touch points | 10 × at `36+4i`: x = `((m[b+1]&0xF)<<8)\|m[b]`, y = `((m[b+3]&0xF)<<8)\|m[b+2]`, averaged (`:176-184`) | identical (`gamepad_home_menu.cpp:79-86`) |
| pressure | bits `((msg[37]>>4)&7)`, `39`,`41`,`43` shifted 0/3/6/9 (`:192-196`) | `((report[37+4p]>>4)&7) << (p*3)` (`gamepad_home_menu.cpp:87-89`) |
| "waiting for streaming" | **not read** | `(packet[83] & 1u) != 0` (`:148`) |
| extra buttons (TV/R3/L3) | `kBtnTV=0x200000, kBtnR3=0x400000, kBtnL3=0x800000` originate from `msg[80]`'s bits 5..7 (`input.h:59-61`) | same masks in `kButtons` (`:159-170`) |

**Differential hints (INPUT).**

1. The documented `struct` says `u16 buttons` at offset 2 **little-endian** (`sc-input.rst:25-27`),
   but both implementations read it big-endian (`msg[2]<<8 | msg[3]`). One of the two is wrong;
   the implementations agree with each other, so the doc is the suspect. `[M]`-neutral: our
   capture holds 48,760 input blobs but I did not resolve which button bits were pressed.
2. Byte 83 bit 0 is a pad→console **state oracle** — Barista only discovered it and it is not in
   the RE doc: `input.waiting_for_streaming = (packet[83] & 1u) != 0` (`runtime_transport.cpp:148`),
   surfaced as `pad_streaming=waiting|active` (`media_streamer.cpp:964`) and unit-tested against a
   real captured blob (`core/tests/pairing_tests.cpp:247`). That byte sits inside libdrc's
   "unk1[46]" region — i.e. **the documented struct has a hole where the pad's own state lives.**
3. The touch-coordinate "extra" 3 bits per point are where the UIC firmware version is smuggled
   (`sc-input.rst:105-117`); the pressure derivation used by both implementations takes 3 bits
   from the *high* nibble of the y-coordinate's first byte, so pressure and coordinate share a
   byte. A pad-side parser that validates coordinate range without masking would read pressure
   as coordinate.
4. What the pad expects back: nothing. `sc-input.rst:5-8` and the port table mark 50022 as
   **console→pad only, "To Pad: N"**; no implementation sends on it; the port table in
   `barista-ref/runtime_transport.cpp:36-45` agrees (`50022` console-side only, no pad-side 50122
   send path). `GROUND-TRUTH §4` line 125 confirms "No pad traffic ever reaches 50020/50021" and
   48,760 × 128 B pad→console. **INFERRED:** the pad's input parser is not reachable by us at all
   — the 128-byte blob is pad→console — so the fuzzable surface on this port is our own parser
   (see §7, item 6).

---

## 5. Empirical pad-behaviour notes found in the implementations

Quoted verbatim, with location. These are the observations of pad parser behaviour under stress.
Conflicts between them are noted — a conflict is itself information.

**VSTRM payload ceiling.**

> `research/wozt-libdrc/include/drc/internal/vstrm-packet.h:38-42`
> "Measured: at 1700 the GamePad stops decoding outright and asks for a keyframe on every frame,
> so its reassembly gives out somewhere below that. The ~1793-byte frames a real console sends
> must be its audio rather than its video. At 1400 the packet rate lands within a few of the
> console's own."

(The second sentence is wrong — the console's 1,694-byte frames *are* video, §0/§1.2. The first
sentence stands as the only direct measurement of the pad's VSTRM buffer edge.)

**Keyframe requests: heartbeat vs distress — directly contradictory between forks.**

> `research/wozt-libdrc/src/streamer.cpp:91-99`
> "The GamePad sends this once per frame and never stops: captured off the air, the 3dtest demo -
> which it decodes perfectly - draws the same 58 messages a second as a stream it cannot decode at
> all. So it says "I would take a keyframe", not "I am lost". Obeying every one makes every single
> frame an IDR, which on real video blows the bitrate apart and freezes the picture."

versus our local fork, which measured the console:

> `pc2drc/.../src/video-streamer.cpp:90-100`
> "Measured against a decrypted real console session (2026-11-04, research/GROUND-TRUTH-SESSION.md
> sec.4): the console sets the init flag on exactly the 25 datagrams of the first frame after video
> starts, and never again … An earlier round re-asserted init on every IDR to help a pad that
> associates late; but a pad that cannot decode asks for a resync ~60 times a second, so that marks
> ~16 frames/s as "the stream restarts here", which is the one signal guaranteed to stop a decoder
> from ever completing a frame - and it makes the failure self-sustaining."

> `pc2drc/.../include/drc/internal/idr-policy.h:3-13`
> "the GamePad sends a 4-byte datagram 01 00 00 00 once per frame EVEN WHEN THE PICTURE IS PERFECT
> … Cost, measured on this host (research/CODEC-SPEC.md 2.2): normal desktop stream ...... 0.29
> Mbps / every frame an IDR ......... 8.57 Mbps (17.8 kB/frame, 28x). That cannot fit the link, so
> the pad loses more, asks more, and the picture never recovers."

Resolution available now, from the evidence file: **the console saw three such datagrams in
300 s** (`port50010.bin` = 3 records of `01 00 00 00` from 50110→50010, at t=74.9 s, answered by
one fresh IDR) `[M]`, and `GROUND-TRUTH §6` item 1 says so explicitly. So on a *working* stream the
message is rare; the 58–63/s rate is a symptom. Both forks' comments are consistent with that
only if the message is rate-limited by the pad when it is happy — which is the observed behaviour.

**What a failed answer to a keyframe request looks like (per second, per image).**

> `research/wozt-libdrc/src/video-streamer.cpp:498-516` and `:517-538`
> "Measured: the second an IDR goes out needs 28 packets for one image where five are allowed, and
> draws 48 further requests; the seconds around it sit at exactly 5 and zero. The pad asks, is
> answered with the one frame this protocol cannot carry, and asks again."
> "The FIRST frame of a stream is still an IDR and must be: a sweep repairs a picture, it cannot
> provide one to a decoder that has never had anything. That is `send_idr = !vstrm_inited` above,
> and removing it is how this was tried once and left a black panel."

> `research/wozt-libdrc/include/drc/internal/h264-encoder.h:73-78`
> "DRH gives each of five chunks a single 1400-byte packet, and an intra frame does not fit.
> Measured, the second an IDR goes out is the second the pad needs 28 packets for one image and
> asks for a keyframe 48 times; the seconds either side sit at exactly 5 packets and no requests
> at all."

**A pad that has dropped the session does not come back from IDRs.**

> `research/wozt-libdrc/src/video-streamer.cpp:453-455`
> "It does not help a GamePad that has dropped the session rather than lost the picture - **43
> restarts over 21 seconds changed nothing there, and only reassociating cleared it** - but that is
> a different failure."

**The init flag alone is worse than nothing.**

> `research/wozt-libdrc/src/video-streamer.cpp:468-477`
> "An explicit ReinitStream() … The init flag alone was tried and is worse than nothing: it
> announces the start of a stream and then hands the pad a P-frame predicting from pictures it
> does not have, so there is nothing to start from and it stays stuck for good. A recovery point is
> expensive — an intra frame does not fit DRH's five 1400-byte packets and gets split — but a split
> frame it can sometimes use beats a frame it certainly cannot."

**Encoder-side triggers of the same failure (these are pad decoder limits, not packet limits).**

> `research/wozt-libdrc/src/h264-encoder.cpp:42-46`
> "Anything above "medium" breaks the GamePad's decoder on real video: with "slow" it asks for a
> keyframe on every single frame (60 resync/s) and the picture freezes, while "medium" and below
> hold a steady 0. Flat synthetic content - the 3dtest demo, a test pattern - decodes fine either
> way, which is why libdrc shipped with "slow" unnoticed."

> `research/wozt-libdrc/src/h264-encoder.cpp` (same file, `DRC_DEBLOCK*`/`constrained_intra`
> block) — "The deblocking settings live in the slice header, which DRH never transmits: the
> GamePad filters according to whatever it assumes. Whatever x264 does here has to match, or the
> two reconstructions drift apart at every macroblock edge and the error accumulates frame over
> frame." and "constrained_intra_pred lives in the PPS, which is never transmitted: the GamePad
> decodes with a hardcoded one."

**Ext-option order (our own measurement).**

> `pc2drc/.../src/vstrm-packet.cpp:60-64` — see §1.4: pad "never starts decoding" with libdrc's
> option order.

**Barista's radio-level observations of the same pad.**

> `barista-ref/docs/gamepad-recovery-experiment.md:29`
> "33 are followed by a recovery request within 5–50 ms after full ACK."
> `:965-967`
> "891 recovery requests in 19.81 seconds, approximately 45 per second. … Requests are not
> visible-error counts."

> `barista-ref/docs/drc-media-packet-datasheet.md:330-338`
> "The decisive contrast is therefore not the basic UDP envelope: `recover-v2` became active with
> the same format body and VSTRM envelope layout that appear in the waiting controls. … The
> generic resync message does not identify the internal failure reason, so this is evidence that
> recovery handling matters, not proof that every logged request was a distinct rejected frame."

**The original project's own unresolved pad limits.**

> `research/libdrc/TODO:6-8` — "Fix video streaming timing randomly desyncing. / Fix compatibility
> with recent DRC fw (video stream never syncing)"
> `research/libdrc/TODO:21` — "Find the macroblock type causing random corruptions on PC->DRC video
> data."
> `web/docs/re/sc-cmd.rst:304-308` — "This command is issued every second. **Recent versions of the
> GamePad firmware will only show the video stream after receiving one such command.** Setting f3
> to 1 switches the GamePad to vWii mode, setting it to 3 shuts it down."

**Ground-truth observation that constrains all of the above.**

> `research/GROUND-TRUTH-SESSION.md:63-66` — "75 – 300 | no further resync requests for 225 s,
> video decodes … So a *healthy* session's whole resync history is **three datagrams**, sent once,
> answered with one IDR. **The pad tolerates ~14 s of video it cannot use before it asks.**"

That last number (~14 s) is the pad's own patience timer and is not represented in any
implementation — every implementation reacts within one frame.

---

## 6. What our local build sends today, versus the ground truth, and the knobs a fuzzer can reuse

### 6.1 The live path

`run/drc-up.sh:239` starts the stack as:

```
setsid nohup env DRC_SYNTHETIC_TSF=1 DRC_TSF_OFFSET_US="$TSF_BASE" ${DRC_EXTRA_ENV:-} ...
```

so by default the media clock is the **synthetic monotonic clock** plus a manual offset
(`pc2drc/.../src/tsf-linux.cpp:80-159`), not a radio TSF. `run/04-stream.sh` runs
`out/bin/bin/drcvncclient` linked against `out/libdrc/lib` — the thefloppydriver tree with our
modifications. `tests/run-tests.sh` reports 7/9 with the two socket tests failing because the
production stack owns 50020/50022/50023 (`GROUND-TRUTH §8` item 1).

### 6.2 Field-by-field: local build vs console

| Field | local build emits | console | source |
|---|---|---|---|
| VSTRM seq | 2+8 bits, mod 1024 | same `[M]` | §0 |
| VSTRM payload cap | 1694 | 1694 `[M]` | `vstrm-packet.h:39` |
| VSTRM ext options | `80 82 00 83 85 06` / `82 00 83 85 06` | identical `[M]` | `vstrm-packet.cpp:54-89` |
| `init` | first frame only | first frame only (25 pkts) `[M]` | `video-streamer.cpp:101-104` |
| IDR policy | first + every 60 + debounced request (min 1 s) | ~1 per 26 s + 1 per resync | `idr-policy.h:35-50` |
| in-frame pacing | chunk windows 0/3/6/9/11 ms, deadlines 2.5/5/7.5/10/13 ms | same (datasheet:193-201) | `video-packet-schedule.h:28-30` |
| format message | 32 B, outer `0000`, bytes 4..7 = `00000000`, ts LE, 16000/16000/21000/21000 | identical `[M]` | `video-streamer.cpp:167-201` |
| format lead | 5000 µs before frame, same ts | ~5.1 ms median | `video-streamer.cpp:334-345` |
| PCM | 1664 B payload, 8.666 ms | identical `[M]` | `audio-streamer.cpp:51-52` |
| UVC/UAC | 56 B, byte 0 flips to 1 after first validated reply; LE volumes | identical behaviour | `uvcuac-synchronizer.cpp` + `cmd-packet.cpp:226-269` |
| time command | 1/s, 2000-01-01 epoch | 4× total, before video `[M]` | `uvcuac-synchronizer.cpp` |
| 50025 table | 96 B at 1 Hz from port 50025 | 96 B at ~0.96 Hz `[M]` | `streamer.cpp:69-84,159-171` |
| command plane | UIC config 5/0x06 once, backlight, UVC/UAC, time | + 778×1048 UIC state blobs, 13 generics, 3 one-offs | §2.4 |
| **missing** | — | **778 fragments of the 1048-byte svc 0/0x11 state message** | `GROUND-TRUTH §3, §4` |

### 6.3 Existing experimental knobs a fuzzing harness can reuse (all env vars, all already wired)

Encoder / codec (`pc2drc/.../src/h264-encoder.cpp:141-212`, `run/drc-sweep.sh:60-86`):
`DRC_PRESET`, `DRC_PROFILE` (default `high`), `DRC_QP`, `DRC_KEYINT`, `DRC_SLICES`, `DRC_THREADS`,
`DRC_CABAC`, `DRC_8X8`, `DRC_REFS`, `DRC_BFRAMES`, `DRC_DRH`, `DRC_INTRA_REFRESH`,
`DRC_SCENECUT`, `DRC_DEBLOCK`.

wozt-only (not in the installed build, but copy-ready): `DRC_RESYNC_US`, `DRC_RESYNC_RESTART`,
`DRC_TX_SPREAD_US`, `DRC_REFRESH`, `DRC_NO_I4X4`, `DRC_SUBME`, `DRC_TRELLIS`, `DRC_ME`,
`DRC_DEBLOCK_A`, `DRC_DEBLOCK_B`, `DRC_STATS` (`wozt-libdrc/src/h264-encoder.cpp:42-46,150-212`;
`video-streamer.cpp:270-272`).

Transport / timing / protocol:
`DRC_SYNTHETIC_TSF`, `DRC_TSF_OFFSET_US` (+ `/var/run/drc/tsf-offset-us`, re-read 1/s),
`DRC_FORMAT_OUTER`, `DRC_FORMAT_LEAD_US`, `DRC_FPS`, `DRC_IDR_MIN_US`,
`DRC_QUIET_CMDS`, `DRC_SEND_UIC`, `DRC_SEND_UVCUAC`, `DRC_SEND_TIME`, `DRC_SEND_BACKLIGHT`,
and the pass-through `DRC_EXTRA_ENV` used by `run/drc-up.sh:239`.

Barista's equivalents, for behaviour comparison: `DRCD_IDR_INIT` (**default on** — the opposite
of our default), `DRCD_ALL_IDR`, `DRCD_CHUNK_PACING`, `DRCD_REFERENCE_VIDEO_OPTIONS`,
`DRCD_SEND_TIME_VIDEO`, `DRCD_REFERENCE_AUDIO_TIME`, `DRCD_REAL_REPLAY`,
`DRCD_MEDIA_DUMP_DIR`, `BARISTA_MUG_SOCKET`, `BARISTA_HOME_MENU`
(`barista-ref/core/drh/encoder/media_streamer.cpp:32-36,311-313,659-694`).

Replay harnesses already in-tree that can be repointed at fuzzed bytes (they replay *console*
bytes verbatim, so a mutation layer is the only missing piece):

- `run/replay-console-session.py` — everything (commands, video, audio, 50025) at recorded timing;
  `--no-commands` / `--no-media` give A/B controls, `--ts-shift` restamps both the VSTRM BE and the
  format LE timestamps (`:172-183`).
- `run/replay-console-media.py` — media only, `--loops`, `--ts-shift`.
- `run/replay-console-cmd.py` — re-sends one captured 1048-byte command from an ephemeral port.
- `run/command-plane.py` — owns 50023, replays the console's command bursts (`--mode
  state|blobs|uvcuac|full|arm|arma`) and ACKs replies; its builder is `pad-state.py:build_generic`.
- `run/probe-command.py`, `run/bisect-inject.sh`, `run/phase*.sh` — phase-isolated experiments.
- Scorer: `tests/score-live-session.py` (expects `video_pkt_max 1710`, `audio_len 1672`,
  `format_len 32`, `resync_total_in_300s 3`); analyzer: `tests/analyze_vstrm.py`.

---

## Fuzzable primitives implied by the code

Each row is a field the pad must parse, with the byte offset **into the datagram on the wire**,
endianness, bit width, and the specific way an unvalidated value misbehaves in a reference
implementation. Ordered by my judgement of exploitability.

### P1 — VSTRM `payload_size` (11 bits), offset 2 bits 2..0 + offset 3

- **Layout:** `len = ((b2 & 0x07) << 8) | b3`, big-endian-ish (MSB-3 split across a flags byte).
  Range 0..2047; no implementation asserts the *receive* side.
- **Why it is first:** it is the only field that directly scales a copy. The pad must copy
  `len` bytes out of a UDP datagram whose real length is independent of `len`. Everything in the
  protocol that could overflow a reassembly buffer (chunk buffer, decoder bitstream FIFO,
  format/PCM buffer) is sized from this or from the container length.
- **Evidence it is trusted:** the console's max is exactly 1694 and wozt measured that 1700 makes
  the pad "stop decoding outright" (§5) — i.e. the pad behaves *differently* the moment the number
  crosses a threshold in the 1694..1699 window. That is the signature of a bounds check or a
  buffer boundary, not of a decoder quality limit. `len = 0x7FF` (2047) with a short datagram, and
  `len > UDP length − 16`, are the two canonical probes.
- **Sender-side reference bug to mirror-check:** `VstrmPacket::SetPayload` guards the copy with
  `assert(size <= kMaxVstrmPayloadSize)` and then `memcpy`s unconditionally into the fixed
  `std::array<byte, 1416>` — in a release build (`NDEBUG`, no assert) an oversized `size` overruns
  the packet buffer before the 11-bit length is even written (`vstrm-packet.cpp:112-118`,
  array at `include/drc/internal/vstrm-packet.h:86`). The field itself is masked correctly by
  `InsertBits`, so the *wire* length can never exceed 2047 — which is precisely why an 11-bit
  field facing a buffer sized for 1694 is the interesting mismatch.

### P2 — CMD generic inner `payload_size` (16 bits BE), wire offset 8(outer)+8..9 = **18..19**

- **Layout:** bytes 18..19 of the datagram, **big-endian**, full 16 bits.
- **Why:** it gates the pad's own reassembly, and the console demonstrably uses the *whole* field
  up to 1028 (the state blob), with a documented method maximum of 1028 and an outer length of
  1040. Nothing in any implementation bounds-checks it against the outer length; `CmdPacket`
  exposes `PayloadSize()` straight from bytes 4..5 and `PacketReceived` builds
  `std::vector<byte> repl(pkt.Payload(), pkt.Payload() + pkt.PayloadSize())` from it
  (`cmd-protocol.cpp:162`) — if a datagram declares more than it carries, that is a heap overread
  *in the reference parser itself*. A pad with the same shape does the same thing.
- **Probes:** inner length 0xFFFF; inner length ≫ outer length; inner length 1029..2047 (just
  above the console's ceiling); outer 1040 with inner 1028 but a truncated datagram.
- **Also:** outer length (bytes 4..5, LE) vs `datagram − 8`; Barista rejects a mismatch
  (`runtime_transport.cpp:873`), libdrc does not.

### P3 — VSTRM ext-option area, offsets 8..15 (8 bytes)

- **Layout:** zero-terminated linear list; opcode byte + optional argument byte. Known opcodes
  `0x80..0x85`. `0x82` and `0x85` take arguments; `0x80`, `0x83`, `0x84` do not.
- **Why:** the only place where our own hardware observation contradicts a working implementation
  (§1.4), which means at least one order-sensitive path exists in the pad's scanner. Specific
  hazards the reference parsers exhibit and a pad may share:
  - a value-bearing option at index 7 (`… 82` at offset 15) → `GetExtOption` returns "not found"
    while a *different* parser would read the first payload byte as the value
    (`vstrm-packet.cpp:134-148`);
  - `0x85` argument is a **row count** (6) — a value beyond the picture's 30 rows, or a zero, is
    a count fed straight into a geometry computation;
  - `0x81` is documented as "takes one byte of argument but does nothing" (`sc-vstrm.rst:57-58`) —
    an unknown-opcode path that must skip 1 byte; getting that wrong desynchronises the rest of
    the list;
  - an option list with **no** `0x00` terminator (all 8 bytes used) forces the scanner to stop on
    the count rather than the sentinel;
  - `0x84` (unset force flag) exists only in the docs — no implementation emits it.

### P4 — VSTRM flag bits + chunk/frame structure, offset 2 bit 7..4 combined with offsets 0..1

- **Layout:** `b2` bit7 init, bit6 frame_begin, bit5 chunk_end, bit4 frame_end; with the 10-bit
  sequence at `b0[1:0],b1`.
- **Why:** these four bits are the pad's *reassembly state machine input*, and there is no
  cross-check between them and the sequence number in any implementation. A frame that starts
  without `frame_begin`, ends without `frame_end`, has 4 or 6 `chunk_end`s, repeats a sequence
  number, or resets to 0 mid-stream is exactly what every "sweep" idiom in §5 manipulates — and
  wozt recorded that mis-sequenced recovery points make the pad "not use any of them, and it kept
  asking" (60 requests/s). The pad also accepted a genuinely repeated `init` on every IDR in
  Barista's default configuration, so `init` alone is tolerant; the *combination* is the probe.
- **Probes:** 50 chunks/frame; 5 chunks all marked `chunk_end`; `frame_end` on a non-final packet;
  seq jump backwards; `init` mid-stream; a frame with zero payload packets.

### P5 — PCM `payload_size` (16 bits BE) at offset 2..3 of an ASTRM datagram

- **Layout:** bytes 2..3, **big-endian**, full 16 bits, plus `format`/`mono`/`vibrate`/`type` in
  byte 0 bits 7..5, 4, 3, 2 and the 10-bit seq in byte 0 bits 1..0 + byte 1.
- **Why:** the pad derives "number of samples" from this field for a fixed 48 kHz output path
  (`sc-astrm.rst:48-50`: "The number of samples is inferred from the payload size"), with
  `kMaxAstrmPayloadSize = 1700` asserted only on the *send* side. Console value is always 1664;
  libdrc believed a 1600-byte ceiling existed (`audio-streamer.cpp:42-47`) and sent 1536 — so the
  pad demonstrably tolerates at least 1536..1664 with different sample counts per packet. An odd
  length (odd byte count for s16 stereo), 0, or 0xFFFF is unexamined by every implementation.
  `format` also has two documented-but-never-seen values (ALAW 2/3, ULAW 4/5) that must select a
  *decoder* rather than a copy — a classic switch-table target.

### P6 — CMD fragmentation: final bit (offset 11 bit 3), flags (offset 13), tid (offset 10..11 high nibble), fid (offset 11 low bits + 12)

- **Layout (datagram-relative, generic header starting at offset 8):** flags at **13**,
  tid = `(b10 << 8) | (b11 >> 4)` (12 bits), final = `b11 & 0x08`, fid = `((b11 & 0x07) << 8) | b12`
  (11 bits), service **14**, method **15**, error **16..17** (BE), inner length **18..19** (BE).
- **Why:** the console proves all four are used simultaneously (778 fragments: 194 complete
  4-fragment messages, tid incrementing, strict M M M S), and *none of the four is bounded*:
  `assert(tid < 0x400)` / `assert(fid < 0x800)` are debug-only (`cmd-packet.cpp:156,170`), and a
  pad reassembling fragments by fragment id must allocate or index by it. **`flags = 0x43` never
  appears in the capture or in any implementation** — bit 0 of the flags byte is undocumented.
- **Probes:** fid beyond the message count; fid repeating within one tid; final bit set with
  `flags = 0x42` (contradictory); 194+ fragments in one tid (console's own maximum, then a
  documented mid-message truncation M M); a type-1 ACK carrying a non-empty payload (Barista
  explicitly rejects, `:897-903` — a pad that does not may parse the payload as a reply).

### P7 — CMD outer `packet_type` / `query_type` (offsets 0..1 and 2..3, LE 16-bit each)

- **Why:** both are cast straight into enums with **no range check** in libdrc
  (`static_cast<CmdPacketType>((pkt_[1] << 8) | pkt_[0])`, `cmd-packet.cpp:48-54`), and
  `PacketReceived` then compares them (`:149-151`) and, for any type equal to
  `kReply`, sends a reply-ack and invokes a callback whose payload vector is built from the
  attacker-controlled length. Values 4..65535 are undefined in every implementation. Barista
  rejects `type > 3 || query_type > 2` (`runtime_transport.cpp:873`) — proving the check is
  considered *necessary*; libdrc's absence of it is the gap. A pad that dispatches on query type
  into a 3-entry table is the mirror image.

### P8 — ASTRM format message body (32 bytes, offsets 8..31)

- **Layout:** `ts` LE at 8..11 (unvalidated), `16000/16000/21000/21000` LE at 12..27, `video_format`
  at 28..31 (zero in every observed instance).
- **Why:** the pad "does not start decoding without it" (§3.3), it is parsed by its own path with a
  declared length of **0**, and byte 4..7 is a free 32-bit field that three different real captures
  populate differently (`00000000`, `11118108`, `11118188`, `10108108`) with no implementation
  knowing why. Unknown-but-required, unvalidated, and 32 bits wide.

### P9 — INPUT touchscreen coordinate/pressure packing, offsets 36..75

- **Layout:** 10 points × 4 bytes at `36 + 4i`: `x = ((m[b+1] & 0x0F) << 8) | m[b]`,
  `y = ((m[b+3] & 0x0F) << 8) | m[b+2]` (12-bit values), with pressure taking bits 4..6 of
  `m[37]`, `m[39]`, `m[41]`, `m[43]` — i.e. **the same bytes as the y coordinates**. UIC firmware
  version is smuggled into points 6..8's extra bits (`sc-input.rst:105-117`).
- **Reachability caveat:** this blob is pad→console; we cannot inject it. It is listed because it
  is what the pad *sends*, so a bug here is reachable by anything that can spoof the pad side of
  the link — the same position we occupy. Our own parsers (`input-receiver.cpp:176-200`,
  `gamepad_home_menu.cpp:79-89`) do the shifts without masking on the pressure path and would
  read `ts_pressure` as a 12-bit value in `int` arithmetic — safe, but the pad's own `userif`
  manager parses the same data locally (`web/docs/re/overview.rst:145`).

### P10 — the 50025 panel table (96 bytes) and the UIC state blob (1048 bytes)

- **Layout:** 50025 table: `58 00` at 4..5, magic `5a a5` at 8..9, `58 00` at 10..11, u16 counter at
  **6..7** (increments 0,4,5,6,…), then a monotonic 16-bit ramp `0010,0018,…,00e8,00eb,00eb,00eb`.
  State blob: outer 8 B + generic 12 B + 1028 B whose first 4 bytes are a u32 index running 1..778.
- **Why:** both are completely undocumented and both are *required* by the pad's session logic
  (the 50025 stream starts at the same instant as the console's UVC/UAC polling, `GROUND-TRUTH §4`
  line 118-122; the state push runs only for the first 28 s). Nothing in any implementation parses
  either, so nothing in any implementation constrains them. The counter and the index are the two
  obvious monotonicity assumptions to violate; the 96-byte table's ramp is the obvious place to
  look for a length or table-index field.

### P11 — (our side, for completeness) the reference parsers' own overflow

Not a pad bug, but it defines the shape of the pad-side bug class and is worth fixing before any
fuzzing campaign uses these tools as an oracle:

- `UdpServer` reads up to **2000** bytes (`libdrc/src/udp.cpp:154-155`) into a vector, then
  `CmdPacket::CmdPacket(const std::vector<byte>&)` `memcpy`s `packet.size()` bytes into a
  **1408-byte** `std::array` (`cmd-packet.cpp:37-39`, `cmd-packet.h:73,33-34`) → up to 592 bytes of
  overrun from a single datagram. Same pattern in `VstrmPacket` (1416-byte array) and
  `AstrmPacket` (1708-byte array). Any datagram we accept is copied before any length check.

---

### Appendix — measured constants cheat sheet

| Number | Meaning | Where measured |
|---|---|---|
| 1710 | max console VSTRM datagram = 16 + 1694 | `port50120.bin` |
| 1694 | max VSTRM chunk length field observed | `port50120.bin` |
| 2,827 | datagrams at exactly 1710 B (= 16 + 1694) | `port50120.bin` |
| 5.20 | datagrams per video frame (73,500 / 14,138) | `port50120.bin` |
| 25 | datagrams carrying `init` (the entire first frame) | `port50120.bin` |
| 46 / 73,454 | IDR-marked / P-marked datagrams | `port50120.bin` |
| 1672 / 1664 | PCM datagram / payload | `port50121.bin` |
| 8.67 ms / 16.69 ms | PCM / format cadence medians | `port50121.bin` |
| 14,142 | format messages, all `04 00 00 00 00 00 00 00 <ts LE> …` | `port50121.bin` |
| 1048 / 1040 / 1028 | state-blob datagram / outer len / inner len | `port50123.bin` |
| 792 / 784 / 772 | UIC-config reply datagram / outer len / inner len | `port50023.bin` |
| 778 / 194 | blob fragments / complete 4-fragment messages | `port50123.bin` |
| 0x42 / 0x40 | continuation / final generic flags | `port50123.bin` |
| 0x09 | pad's reply flags (`(0x4x>>3)&0xFC \| 1`) | `port50023.bin` |
| 3 | resync datagrams in the whole 300 s session | `port50010.bin` |
| 96 | 50025 table size, ~0.96/s, 220 datagrams | `port50125.bin` |
| 128 × 48,760 | pad input blobs | `port50022.bin` |
