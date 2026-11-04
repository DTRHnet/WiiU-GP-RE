# Encoder conformance: is our H.264 payload what the GamePad decoder assumes?

**Verdict: the payload is clean.** Our DRH chunks reconstruct to a byte-exact,
valid 854×480 High/L3.2 stream that ffmpeg decodes with **0 warnings/errors**, the
chunking model matches the real console (and Barista's working MiniH264), and every
hardcoded decoder assumption (QP 32, constrained_intra, CABAC, no B-frames, 1 ref,
8×8 off) is honoured. The one deviation an earlier audit flagged — the DRH chunk
flush landing **+2 macroblocks** past the 6-row grid — is **not a defect**: the pad
concatenates the 5 chunks into one CABAC slice, so the byte split point is
irrelevant (proven below). The 31.6 resync/s with the console's *own* media is the
deciding datum: the gate is upstream of the payload, not in the encoder.

## Method (offline: reads files + ffmpeg/tshark, no sockets, no interfaces)

`tests/agent-chunk-audit.py` splits each stream on the VSTRM `frame_begin`/
`chunk_end`/`frame_end` flags, measures per-chunk byte ranges, and decodes two ways:
(a) Barista's model — pad SPS `67640020ac2b406c1ef368` + PPS `68ee060ce8` + one
synthetic slice header (`0x25b804ff` IDR / `0x21e003ff|(frame_num<<13)` P) per
*frame*, chunks joined; (b) each chunk as an independent slice with a correctly
built header (`first_mb_in_slice = i·324`). Console = `out/evidence/truth/
port50120.bin` (73,500 datagrams); ours = `capture/phase4-clock-083704.pcap`.

## Measured numbers

| metric | console | ours |
|---|---:|---:|
| datagrams / frames (complete 5-chunk) | 73,500 / 14,136 (14,128) | 22,007 / 4,207 (4,207) |
| IDR frames | **2** | 72 |
| chunk bytes min / median / mean / max | **3** / 453 / 519 / 7,928 | **1** / 8 / 244 / 8,333 |
| degenerate chunks (0/1/2 B) | **0 / 0 / 0** | 0 / 3,935 / 3,925 (37 %) |
| chunks >1694 B (split across datagrams) | 2,305 | 393 |
| datagrams / chunk (max / mean) · / frame | 5 / 1.04 · 5.2 | 5 / 1.05 · 5.23 |
| frame bytes mean / IDR mean / IDR min | 2,597 / 34,285 / 30,757 | 1,220 / 25,424 / **89** |
| decode, full stream | exit 0, 0 warn/err, 854×480 yuv420p | exit 183 (starts on 15 P frames) |
| decode, from first IDR | exit 0, 0 warn/err | **exit 0, 0 warn/err** |
| first IDR alone (chunks / total) | [7474,7270,7928,7443,7698] / **37,813 B** | [4937,4609,6286,5975,5701] / 27,508 B |
| each chunk as standalone slice | **all fail** (raw cut) | all fail (raw cut) |

## Code-level audit (drc-x264 `encoder/encoder.c`, `h264-encoder.cpp`)

1. **Chunk boundary = raw byte cut, correctly.** The flush (encoder.c:2858-2881)
   only snapshots `cabac_size_bytes()` and emits the NAL; it never calls
   `x264_cabac_encode_flush`/`encode_terminal`. The *only* CABAC flush is at the
   frame tail (encoder.c:2907). This is the intended design — 5 fragments of one
   1620-MB slice — and matches Barista's MiniH264, which flushes once per frame and
   records byte positions with a `+2` allowance (`slice.h:32-33,40`). **The pad
   concatenates**: the console's own chunks, given correct `first_mb=i·324`, all
   fail standalone decode ("no frame!") yet the concatenation decodes perfectly.
2. **The "+2 MB" flag arm is real but harmless.** `if (i_mb_y%6==0 && i_mb_x==0)
   b_cabac_chunk_ending=1` (encoder.c:2883) arms at the *start* of a 6th row; the
   flush runs one iteration later (encoder.c:2858 is after `x264_macroblock_encode`,
   encoder.c:2658), so boundaries land at MB 325/649/973/1297, not 323/647/971/1295.
   Under concatenation the split point only affects transport, not decode — verified:
   0 decode errors. It is a cosmetic deviation from Barista's clean 324-MB grid
   (`slice.h:32`), not a decoder defect. `ProcessNalUnit`'s `i_first_mb/324`
   (`h264-encoder.cpp:300`) labels chunks 0-4 correctly despite the shift.
3. **Deblocking is per-row, independent of chunks** — `x264_fdec_filter_row` runs
   at the top of each row (encoder.c:2622); the chunk flush never skips it.
4. **`mb_qp_delta` continuous** only because QP is pinned: `h->sh.i_qp =
   32+QP_BD_OFFSET`, `i_qp_delta = i_qp - pps->i_pic_init_qp` (encoder.c:2581-2582),
   CQP 32 (h264-encoder.cpp:171), AQ off under CQP. Any `DRC_QP` drift would
   re-quantise at one QP while the pad assumes 32 (latent, not current).
5. **`constrained_intra_pred=1` enforced** (h264-encoder.cpp:162); matches pad PPS.
6. **First frame initialises correctly when it is an IDR.** An IDR is self-contained
   (all 1620 MBs intra, QP 32). Our captures' first frame is a P only because
   tshark starts after the session's initial IDR (the streamer forces IDR-first:
   `send_idr = resync_requested || !vstrm_inited`).

## Dense-first-frame hypothesis — falsified

The console's 37,813 B first IDR decodes to a complete 854×480 frame alone; our
smallest IDR (89 B, solid-colour) also decodes to a complete frame (exit 0, 1
frame). There is **no minimum size or data-distribution requirement** for a first
IDR — an IDR is valid however small it compresses. The 89-B-vs-37-KB difference is
a content artefact, and it cannot explain the failure: replaying the console's
*dense* 37 KB first IDR still yields ~31.6 resync/s (SETUP.md round 14).

## Conclusion and ranked fixes

**Payload: clean bill of health.** The gate is not the encoder. Because the console's
own byte-correct media is rejected at the same rate, the failure is upstream — video
path arming / session choreography / envelope — exactly round 14's conclusion. Fixes:

1. **No encoder change required.** Do not "fix" the +2 MB flush (ranked last, and
   only cosmetic). Barista's AGENTS.md warns against presenting a chunk-boundary
   hypothesis as a proven decoder defect; the standalone-decode evidence refutes it.
2. **Chase the arming gate** (the decisive `svc 5/0x02` 102-byte burst + the full
   pre-video choreography of SETUP.md round 13 §"console's session choreography"),
   scoring only armed runs via the `5/0x15 err=0` oracle.
3. *Speculative (unverified on hardware):* re-align the flush to the 324-MB grid
   (change encoder.c:2883 to `i_mb_y%6==5 && i_mb_x==53`, matching Barista) only if
   residual visual corruption — not total rejection — is ever observed after arming.
   Degenerate 1–2 B chunks (37 % of ours, 0 % console) are likewise a content
   artefact of a static desktop, not a defect, and decode cleanly.
