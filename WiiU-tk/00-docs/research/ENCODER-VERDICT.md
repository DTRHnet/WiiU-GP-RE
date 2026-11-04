# Encoder verdict — reconciling two audits, with my own measurements

Two independent audits of our H.264 payload disagreed. This is the reconciliation, with
the numbers I re-measured myself using `tests/agent-chunk-audit.py` (the audited tool)
against `out/evidence/truth/port50120.bin` (real console) and
`capture/phase4-clock-083704.pcap` (ours).

## The verdict

**The payload is structurally valid and is not the display gate.** The one thing that
survives is a structural anomaly worth one live test (§4).

## 1. What both audits agree on

- Five chunks per frame; both streams' chunks, given the pad's hardcoded SPS/PPS and a
  synthetic slice header **per frame**, decode to **854x480 yuv420p High/L3.2 with zero
  warnings and zero errors from the first IDR onward**.
- A single chunk decoded **standalone** fails for **both** streams (probe result
  `[False, False, False, False, False]`). So the pad does not decode chunks as independent
  slices; it concatenates them into one CABAC slice. Chunk boundaries are **transport-only**.

That second point is what disposes of audit #1's headline claim ("the +2-macroblock chunk
flush is the defect"). The shift is real in code — the flag is armed at `encoder.c:2883` and
the flush runs one macroblock later at `:2858`, so boundaries land at MB 325/649/973/1297
instead of 323/647/971/1295 — but under the concatenation model a byte-split point cannot
change decodability, and the measurements confirm it: clean decode either way.

I had already applied that realignment (`encoder/encoder.c`, verified `first_mb =
0/324/648/972/1296` by driving the rebuilt libx264). It stays because it matches Barista's
MiniH264 grid and is harmless, but **it is cosmetic and explains nothing.**

## 2. Where audit #1 was right and #2 under-weighted: degenerate chunks

| metric | console | ours |
|---|---:|---:|
| chunk bytes: min / median / mean / max | 395 / 730 / 1179 / 7,928 | **1 / 4 / 338 / 6,286** |
| chunks of 1–2 bytes | **0** | **93 of 200 (46 %)** |
| chunks > 1694 B (split across datagrams) | 40 of 200 | 10 of 200 |
| frame bytes mean · first IDR | 5,896 · 37,813 | 1,691 · 27,508 |

An IDR frame from us is a healthy 27.5 kB in five ~5–6 kB chunks; the tiny chunks come from
**P frames on a near-static desktop**, where a 6-row strip has almost nothing to code. The
console never produces a chunk below 395 B because its content is a UI with graphics.

Whether the pad's hardware decoder tolerates a 1-byte strip is **not measured** — but it is
the only remaining structural difference in the payload, and it is cheap to test: stream
**moving content** (scrolling text, video playback) so the strips carry real data, and see
whether the pad behaves differently. If it does, the fix is content/pacing, not the encoder.

## 3. What neither audit can claim

- "Decodes cleanly with ffmpeg" is **not** evidence of conformance with the pad: ffmpeg
  tolerates synthetic headers, mid-slice concatenation and leading partial frames that a
  fixed-function decoder need not. Both audits correctly stopped short of equating the two.
- The reverse is also untested: nothing here shows the pad would *reject* this payload.
  Indeed, the console's own byte-exact media, replayed while the session is armed, is
  rejected at 31–41 keyframe requests/s — so payload differences cannot be the gate by
  itself.

## 4. What I would do next with it

1. **Stream moving content** (the degenerate-chunk test). One run, no code change:
   play a video fullscreen on Kali and watch the pad's keyframe-request rate and screen.
2. If that changes nothing, treat the payload as closed and stop touching the encoder —
   every remaining lead is in the session/arming plane (`research/DISPLAY-GATE-FRONTIER.md`).

## Provenance

- Audits: `research/agents/encoder-conformance.md` (revised version) and the first audit's
  report (superseded on the "+2 MB = defect" claim).
- My re-measurements: `tests/agent-chunk-audit.py --console out/evidence/truth/port50120.bin
  --ours capture/phase4-clock-083704.pcap --max-frames 40`, reproducible.
- Grid check: a throwaway probe driving the rebuilt `out/x264/lib/libx264.so.140` with
  `b_drh_mode=1` and printing `i_first_mb`/`i_last_mb` per NAL.
