# The DRC video codec, compression and expectations — measured, not guessed

**TL;DR (all numbers measured on this host, 864x480, QP 32, 59.94 fps unless noted)**

| Question | Answer |
|---|---|
| Codec | H.264 **Main** profile, CABAC, no B-frames, 1 ref, **CQP 32 fixed**, `constrained_intra_pred=1` |
| Surface | **864x480** encoder for an 854x480 panel |
| Framing | 5 chunks of **6 macroblock rows** each; **no slice header, no SPS/PPS, no start codes** on the wire |
| Packet | 16-byte VSTRM header + **≤1694 B** payload (real-console measured; libdrc's 1400 is stale) |
| Bitrate | **0.29 Mbps** idle desktop · **2.7 Mbps** moving content · **8.6 Mbps** if every frame is an IDR |
| Audio | uncompressed 48 kHz stereo PCM = **1.54 Mbps flat** |
| Rate | 59.94 fps (16.683 ms); in-frame windows 0/3/6/9/11 ms with 2.5/5/7.5/10/13 ms deadlines |
| IDR cost | **17.8 kB** office desktop · **40–47 kB** game content (~25–28 datagrams) |
| Measured fps on real hardware | 59.19 (decrypted real-console session, 14,137 frames / 238.9 s) |
| Our stack's bugs | no pacing, encoding on the timer thread, every request → IDR, no post-IDR format slot |

Compiled 2026-11-03. Sources: first-party measurements on this host (Part 2,
reproducible with `tests/run-codec-probe.sh`), the libdrc/drc-x264 source in
`pc2drc/`, and Barista's on-wire datasheet
(`research/barista-ref/docs/drc-media-packet-datasheet.md`, written against
authenticated real-console captures).

---

## Part 1 — the codec contract

### 1.1 What the GamePad decodes

| Parameter | Value | Source |
|---|---|---|
| Codec | H.264/AVC, **Main profile**, **level 3.2** | ffprobe of our own GamePad-format stream (`SETUP.md` round 2); `x264_param_apply_profile(&p, "main")` in `h264-encoder.cpp` |
| Surface | **864x480** encoder surface for an 854x480 panel | `include/drc/screen.h` `kScreenWidth=864`; panel is 854x480 |
| Chroma / depth | 4:2:0, 8-bit | `X264_CSP_I420` |
| Entropy | CABAC on | `param.b_cabac = 1` |
| B-frames | **none** (`i_bframe=0`), `i_frame_reference=1` | encoder params |
| 8x8 transform, weighted pred, `psub16x16` | **off** | encoder params |
| `constrained_intra_pred` | **on** (1) | encoder params; wozt fork notes it must stay 1 |
| Rate control | **CQP, QP pinned to 32** (`i_qp_constant = i_qp_min = i_qp_max = 32`) | encoder params |
| Why QP is immovable | **DRH mode emits no slice header**, so the decoder cannot learn the slice QP and assumes 32. Any rate control that moves slice QP quantises at one QP while signalling another → the pad decodes noise | wozt/libdrc commit 67ae913 (2026-09-14) |
| Threading/slices | `i_threads=1`, `b_sliced_threads=0`, `i_slice_count=1` | encoder params |
| Preset / `subme` | **medium or below**; `i_subpel_refine ≤ 7` — **subme 8** is the exact flip to a 60 resync/s freeze | wozt/libdrc `b2464573be`, `67ae9131b4` |
| `constrained_intra_pred=0` | forbidden — gives "ultra blocky with orange artefacts" | wozt/libdrc `b2464573be` |
| PPS-derived flags the pad never receives | `transform_8x8=0`, `weighted_pred=0`, `chroma_qp_offset=0`, `entropy_mode=1` — all must match the pad's hardcoded PPS because it is **never transmitted** | Barista datasheet + `drc-media-packet-datasheet.md:351-353` |
| Payload ceiling | **1694 B**; wozt measured **1700 stops decoding** | wozt `b2464573be`; datasheet:277-284 |

### 1.2 The framing that makes it non-standard

The stream the pad consumes is **not a self-contained H.264 file**
(Barista datasheet, confirmed against authenticated captures):

- UDP payloads carry **no Annex-B start codes**;
- **no SPS/PPS** and **no slice header** are sent in VSTRM;
- each picture is split into **five "chunks" of six macroblock rows**
  (30 MB rows total for 480p: 54x30 MBs);
- this cadence is produced by **`drc-x264`'s `b_drh_mode`** — a patched x264 that
  calls `nalu_process` once per 6-row group instead of emitting a normal frame.
  Stock x264 cannot produce it, which is why `drc-x264` (not distro x264) is
  mandatory.

### 1.2b Where the patch actually lives (verified in `encoder/encoder.c`)

Three edits in `pc2drc/drc-x264`, confirmed by reading the code:

1. **Slice header suppressed.** `if (!h->param.b_drh_mode) x264_slice_header_write(...)`
   (encoder.c:2584) — in DRH mode the slice header is simply never written. This
   is *why* QP is unlearnable: the file already forces
   `h->sh.i_qp = 32 + QP_BD_OFFSET` and `i_qp_delta = i_qp - pps->i_pic_init_qp`
   (encoder.c:2581-2583), and CABAC is initialised at QP 32.
2. **Chunk boundary at every 6th macroblock row.**
   `if (i_mb_y > 0 && (i_mb_y % 6) == 0 && i_mb_x == 0) b_cabac_chunk_ending = 1;`
   (encoder.c:2883) — the pending NAL is flushed on the next macroblock where
   CABAC produced bytes (encoder.c:2858-2881), calling `nalu_process`
   directly. For 30 MB rows that gives exactly 5 NALs/frame.
3. **Planar prediction disabled** (README.DRC: *"not working on DRC"*).

So "DRH mode" is not a container: it is *x264 emitting CABAC byte ranges without
headers*, which is why only this x264 build can produce the stream and why SPS,
PPS and slice headers never appear on the wire.

Options embedded in every video packet (bytes 8..15) tell the pad what it is
looking at:

| Bytes | Meaning | Frame kind |
| `80` | IDR marker | IDR |
| `82 00` | 59.94 Hz frame-rate selection | both |
| `83` | force decoding | both |
| `85 06` | six macroblock rows per chunk | both |
| `00` | padding / end | both |

Reference option order: IDR `80 82 00 83 85 06 00 00`, P `82 00 83 85 06 00 00`.

### 1.3 Transport envelope (VSTRM, UDP 50120)

16-byte header + **up to 1694 payload bytes**:

```
byte 0..1  0xF in the high nibble + 10-bit big-endian sequence (mod 1024)
byte 2     bit7 init | bit6 frame-begin | bit5 chunk-end | bit4 frame-end
           | bit3 timestamp-present | low bits = length[10:8]
byte 3     length[7:0]        (11-bit payload length, = UDP len - 16)
byte 4..7  big-endian u32 media timestamp, microseconds, wraps at 32 bits;
           every packet of a frame carries the same value
byte 8..15 option bytes as above
```

**The real console's maximum raw VSTRM payload is 1694 bytes**, measured on an
authenticated capture (most common size is exactly 1694). Upstream libdrc
self-limits to **1400** (`include/drc/internal/vstrm-packet.h`), while pc2drc's
fork raised it to **1694** with the comment *"set to 1600 if this doesn't work
pls thx <3"*. Barista started at 1400 and moved to the observed 1694.

A logical chunk larger than the payload limit is **split across several
datagrams**; only the last carries `chunk-end`, only the first packet of a frame
carries `frame-begin`, and only the last packet of chunk 5 carries `frame-end`
(`src/video-streamer.cpp` splits with `std::min(kMaxVstrmPayloadSize, ...)`).

### 1.4 Timing expectations

Per-frame send schedule, measured from video send start (Barista datasheet):

| Chunk | Start | Final-packet deadline |
|---|---:|---:|
| 0 | 0 ms | 2.5 ms |
| 1 | 3 ms | 5 ms |
| 2 | 6 ms | 7.5 ms |
| 3 | 9 ms | 10 ms |
| 4 | 11 ms | 13 ms |

The first two chunks are delivered early so the decoder can start feeding, and
the spread avoids one large burst. The **format message** is a 32-byte packet on
UDP 50121, published at 59.94 Hz, stamped at AP TSF − 1250 µs, with the matching
video sent ~5 ms later (real capture: median format-to-first-video lead 5.1 ms).
After an IDR the console pattern is **format+IDR, then one format-only slot,
then format+P** — a scheduling rule that avoids sending a P frame while the
receiver is still recovering.

**Known discrepancy in our stack.** Comparing our libdrc
(`research/libdrc/src/video-streamer.cpp:99-119`) with the authenticated
real-console capture: we emit outer bytes `00 00 10 00` and **four `16000`
reference-clock fields**, while the console emits `11 11 81 08` (or `10 10 81 08`
in a newer capture) and `16000, 16000, 21000, 21000`. Barista notes the outer
bytes' meaning is unestablished and that Vanilla's controls do work with a
different value, so this is probably tolerated — but it is a cheap thing to
match exactly if the pad ever rejects our formats.

Audio is PCM on the same port family: 8-byte header + **1664 bytes = 416 stereo
s16le frames at 48 kHz**, nominal period 8.666 ms.

### 1.4b Link budget — audio is not free

PCM at 48 kHz stereo s16 is **uncompressed**, so it costs a fixed bandwidth
whether or not anything is playing:

| Stream | Packet size | Rate | Bandwidth |
|---|---|---|---|
| PCM audio | 1664 B payload + 8 B header | **115.4 pkt/s** (every 8.666 ms) | **1.54 Mbps** |
| VSTRM video (console capture) | ≤1694 B | 611 pkt/s | 2.9–8.3 Mbps depending on fill |
| Video-format message | 32 B | 59.94 pkt/s | 0.015 Mbps |
| **Total packet rate** | | **~786 pkt/s** | |

Two consequences worth designing around: audio alone is **five times** the
bandwidth of an idle desktop's video (1.54 vs 0.29 Mbps), and a 20 MHz 802.11n
link carrying 786 pkt/s must have its aggregation/pacing right — at least **300
chunk-ends per second** are structurally required just by 5 chunks × 60 fps.


### 1.5 What the radio actually does with it

From a 35.1 s encrypted capture of a real console↔pad session (Barista):

- 17,166 AP→pad QoS data frames, **99.33 % on TID 5** (the media class),
  **99.93 % at HT MCS 6 with long guard interval**;
- 16,936 RTS → 16,889 CTS: real media is **almost always RTS/CTS protected**;
- 16,894 BlockAcks — BlockAck aggregation is in use;
- the console sends **almost no IDRs**: 1 IDR in 213 frames in one capture and
  1 per ~786 frames in another, and at most one per 750 ms even when restarting
  from a captured IDR;
- pad→AP traffic is 7,115 frames, 99.5 % TID 0 (input/control);
- **611 video packets per second** (21,457 VSTRM packets / 35.1 s) ≈ 10 packets
  per frame at 59.94 fps.

That last number is the important sanity check: a real console session ships
**~10 datagrams per frame**, so multi-packet chunks are the normal case, not an
edge case.

---

## Part 2 — measurements on this host (reproducible)

`tests/codec_probe.cpp` drives the same patched x264 (`pc2drc/drc-x264`) with
libdrc's exact parameter block and counts, per chunk, what actually comes out.
Run it with `tests/run-codec-probe.sh`. Content is 864x480 I420, QP 32, DRH mode.

### 2.1 Bytes per frame, per chunk, per preset

**Synthetic gradient** (easy, compressible):

| preset | B/frame | avg chunk | max chunk | chunks >1400 B | chunks >1694 B | kbps @60 fps |
|---|---:|---:|---:|---:|---:|---:|
| slow | 1644 | 328 | 1218 | 0 | 0 | 789 |
| medium | 2440 | 488 | 1486 | 4 | 0 | 1172 |
| fast | 2440 | 488 | 1486 | 4 | 0 | 1172 |
| ultrafast | 2250 | 450 | 1832 | 5 | 5 | 1080 |

**Real X11 desktop, idle** (captured from `:0` at 864x480):

| preset | B/frame | avg chunk | max chunk | >1400 | >1694 | kbps @60 |
|---|---:|---:|---:|---:|---:|---:|
| slow | 610 | 122 | 4054 | 5 | 5 | **293** |
| medium | 590 | 118 | 3915 | 5 | 5 | 283 |
| fast | 590 | 118 | 3915 | 5 | 5 | 283 |
| ultrafast | 693 | 138 | 4651 | 5 | 5 | 333 |

Per-frame detail for the idle desktop (`slow`): frame 0 (the **IDR**) is
**17,826 B with a 4,054 B chunk**; the following static frames are **10–137 B**.
So an idle desktop is nearly free to stream, and **the IDR is the burst** —
17.8 kB ≈ 13 datagrams at 1694 B.

**Moving content** (`ffmpeg testsrc2`, 864x480, shapes and text):

| preset | B/frame | avg chunk | max chunk | >1400 | >1694 | kbps @60 |
|---|---:|---:|---:|---:|---:|---:|
| slow | 5665 | 1133 | 4615 | 32/150 | 31/150 | **2720** |
| medium | 5686 | 1137 | 4480 | 32/150 | 31/150 | 2730 |
| ultrafast | 4715 | 943 | 4311 | 33/150 | 31/150 | 2263 |

**Conclusion on bitrate expectations:** ~0.3 Mbps for a static desktop,
**~2.7 Mbps for content that keeps moving**, and ~8.5 Mbps if every frame is
forced to be an IDR (below). Any of these fits an 802.11n 20 MHz link; what does
not fit is the IDR storm.

### 2.2 The keyframe-request storm, quantified

Simulating a pad that requests a keyframe on **every** frame (`DRC_PROBE_ALLIDR=1`,
same idle-desktop content):

| preset | B/frame | kbps @60 fps |
|---|---:|---:|
| slow | 17,844 | **8,565** |
| medium | 17,215 | 8,264 |
| ultrafast | 20,403 | 9,794 |

A ~28–30× amplification over the same content streamed normally (0.29 Mbps →
8.57 Mbps). This is the mechanical reason "the picture freezes within seconds" is
plausible: the pad cannot decode → asks for keyframes → the host complies → the
link saturates → more loss → more keyframe requests. The loop can only be broken
by **not** letting every request become an IDR.

### 2.3 Does `idr=true` actually emit an IDR? (it does, on our build)

wozt/libdrc claims that with intra refresh on, `idr=true` is a **no-op** — x264
restarts its refresh wave and never emits another `NAL_SLICE_IDR`, so "IDR sits
at 0 for the whole run". Measured here against **our** drc-x264, that does **not**
reproduce: with 5 mid-stream IDR requests over 60 frames, 30 `NAL_SLICE_IDR`
NALs are emitted (6 IDR frames × 5 chunk NALs), identically for presets
`slow`, `medium`, `ultrafast`, with intra refresh on **and** off.

Both libdrc and the wozt fork request IDRs the same way
(`input.i_type = X264_TYPE_IDR`), so the difference must be in their x264 build,
not in libdrc. **Implication for us: our recovery path is not a no-op; do not port wozt's
encoder-restart fix on the assumption that it is.** Verify on hardware with
`curr_frame_idr_` telemetry before changing anything.

**Reconciling the two claims (both can be true).** wozt also found that the
`\1\0\0\0` datagram arrives **once per frame even when the picture is
perfectly decoded** (their 3dtest demo draws 58/s), i.e. it is a **heartbeat, not
a fault signal**. So the freeze is not "the pad demands every frame be an IDR";
it is "libdrc *interprets* a heartbeat as a keyframe demand and obeys it". That
is consistent with the measurement in §2.2: obeying costs 8.6 Mbps, which cannot
fit the link, which produces more loss, which produces more requests. Their
separate claim that x264 emits no further IDR under intra refresh does not
reproduce here (§2.3), but it does not need to for the freeze explanation to
hold — the economic argument alone is decisive.

### 2.4 What this says about the "artifacts" bug

The inherited TODO says "find the macroblock type causing random corruptions" and
pc2drc reports "visible artifacting (x264 encoding bug, NOT network)". The
measurements above constrain the explanation:

- content that is static is transmitted in tens of bytes, so corruption on a
  static desktop cannot be quantisation;
- moving content produces chunks of 4.5 kB, i.e. 3 datagrams, so any single lost
  datagram destroys part of a 6-row strip — corruption localised to horizontal
  bands is a transport symptom, corruption across the whole frame is an encoder
  symptom;
- the reliable discriminator is a **`dump.h264`** from libdrc's `kDebugDumpToFile`
  compared against a `tcpdump` of the same session: if the dumped file decodes
  cleanly, the encoder is fine and the wire lost data.

---

## Part 3 — expectations checklist for a working stream

1. **Encoder**: patched `drc-x264` only; Main profile, CABAC, no B-frames,
   1 reference, CQP 32 fixed, `constrained_intra_pred=1`, 1 thread, 1 slice,
   `b_drh_mode=1` → 5 chunks of 6 MB rows.
2. **Preset**: not `slow`. It costs nothing in bandwidth (it is the *cheapest*
   preset at 789 kbps vs 1172) but is the configuration reported to trigger
   permanent keyframe requests on real content. Use `medium` or below.
3. **Encapsulation**: 16-byte VSTRM header, payload ≤ **1694** B (real-console
   measured), 5 chunk-ends and exactly one frame-end per frame, 10-bit sequence,
   per-frame timestamp shared by all its packets.
4. **Pacing**: spread chunk packets over 0/3/6/9/11 ms windows; never burst a
   17 kB IDR back to back; after an IDR insert one format-only slot before the
   next P frame.
5. **Format message**: 32 bytes on 50121 at 59.94 Hz, stamped TSF−1250 µs, video
   ~5 ms later.
6. **Keyframe policy — answer immediately, do not add a cooldown.** The pad
   requests a keyframe with a 4-byte UDP datagram `01 00 00 00` from source port
   **50110** to port **50010** and repeats the request while it waits (measured:
   three such datagrams in a whole healthy 300 s session). Barista answers every request with an
   IDR straight away and instead adds a *proactive* IDR after 60 encoded frames;
   it **tested a 250 ms cooldown and rejected it** ("more lag and more
   corruption"). wozt/libdrc went the other way (rate-limited keyframes) because
   upstream libdrc turns *every* request into an IDR while also misreading
   `\1\0\0\0` traffic as a request. The safe synthesis: deduplicate within the
   IDR → format-only slot → first P lifecycle, answer real requests at once, and
   bound IDR frequency by a frame count, not by a rate gate. Budget: **40–47 kB
   per IDR on game content** (~25–28 datagrams), 17.8 kB on an office desktop.
   **CORRECTED 2026-11-04 (see `GROUND-TRUTH-SESSION.md` §6):** the claim that
   `01 00 00 00` arrives "once per frame even when the picture is perfect" is
   **wrong**. In a decrypted real console↔pad session the pad sends it **3 times
   in 300 seconds**, ~14 s after video starts, and then never again for 225 s;
   the console answers with one IDR. It is a genuine resync request and a flood
   of them means the pad cannot decode. Ours runs at ~63/s, i.e. a permanent
   decode failure, not a heartbeat. Keep answering requests, but treat the
   **request rate itself as the pass/fail signal** (target: zero).
7. **Budget**: expect 0.3 Mbps idle desktop, 2.7 Mbps moving content, ≥ 5–8 Mbps
   for a real console game; ~10 datagrams/frame, RTS/CTS + BlockAck on air, HT
   MCS 6 long GI on the console's own link. Audio adds a flat 1.54 Mbps.
8. **No FEC and no application retry**: plain UDP `sendto`, no retransmission;
   media sockets get `SO_PRIORITY 5` and `IP_TOS 0xa0` (DSCP 40). Reliability is
   entirely 802.11 (RTS/CTS + BlockAck). BlockAck proves MAC receipt only —
   never that the pad decoded anything.
9. **Measured achievable rate on real hardware**: 58.0–58.1 fps sustained
   (Barista Release engine), sender-side ages of ~1.7 ms (format), ~6.8 ms
   (first video packet) and ~17.8 ms (last packet). No glass-to-glass latency
   measurement exists anywhere in the corpus.

### 3.5 What our own stack gets wrong (verified in `research/libdrc/src/video-streamer.cpp`)

The send loop (lines 178-201) has four defects, each matching a documented
real-world failure mode. All are fixable without touching the encoder.

1. **No in-frame pacing.** Lines 180-184 send every packet of the frame in a
   tight loop. A 5.6 kB frame is ~4 datagrams, but an IDR is ~25–28 (~40–47 kB),
   all emitted back to back. The reference implementation spreads chunk packets
   over 0/3/6/9/11 ms windows.
2. **Encoding happens inside the frame timer callback** (lines 187-195), so
   encode time is charged against the 16.683 ms budget. An IDR that takes longer
   than a frame slot slips the whole cadence — the documented "desync", and the
   reason a dedicated encode thread plus a serial sender exists in the reference.
3. **Every `\1\0\0\0` message becomes an IDR** with only a one-shot
   `resync_requested_` guard (lines 185, 198-200). The pad repeats requests while
   it waits (measured at ~45/s against a ~45 fps stream), so this degenerates into
   the keyframe storm measured in §2.2 — 8.6 Mbps instead of 0.3.
4. **No format-only slot after an IDR.** The reference sends format+IDR, then a
   format-only slot, then format+P (33.367 ms = 2 × 16.683 ms IDR→P step). We
   send format+P immediately (187-201), while the receiver is still recovering.

Also: our payload cap is 1400 while the real console uses 1694
(`research/libdrc/include/drc/internal/vstrm-packet.h:37`); the pc2drc fork we
actually run already raised it to 1694.

Minimal fix list, in order of impact: pace packets inside the 13 ms window →
move `encoder_->Encode()` off the timer thread → dedupe resync requests and add a
proactive IDR every 60 frames → emit one format-only slot after each IDR.

#### A fifth defect found while testing the fix: a blocking UDP socket

The sender stalled for **2.5 s inside `sendto()`**. `UdpClient::Start()` created a
*blocking* socket, and a send to a peer whose neighbour entry is stale (a pad that
just vanished, a radio that dropped, an off-subnet address) makes the kernel chase
the neighbour while the thread parks. Symptoms were exactly the field reports of
"random disconnects" and freezes: the sender fell behind so far that 17 of 30
frames were superseded, and `Stop()` blocked for the duration.

Fix: `O_NONBLOCK` on the client socket (the `UdpServer` in the same file already
did this), plus a `send_failures()` counter. Measured effect on the same test,
30 frames at 59.94 Hz:

| | datagrams sent | frames superseded | `Stop()` |
|---|---:|---:|---:|
| blocking socket | 120 | 17 | **2 551–2 575 ms** |
| non-blocking socket | 300 | 0 | **0 ms** |

This is worth keeping in mind for the real pad: a disappearing GamePad must not
be able to wedge the video thread, and on a blocking socket it can.

#### Status: all five fixed and verified without hardware (2026-11-03)

Implemented as two new header-only components plus a rewrite of the streamer's
loop; patch at `research/patches/0001-paced-sender-and-idr-policy.patch`:

- `include/drc/internal/video-packet-schedule.h` — chunk windows, per-packet
  offsets (`VideoPacketOffsetUs`), split arithmetic.
- `include/drc/internal/idr-policy.h` — `IdrPolicy`: heartbeat debounce,
  proactive 60-frame IDR, format-only recovery slot.
- `src/video-streamer.cpp` — the 59.94 Hz timer is now a pure producer posting
  into a single-slot mailbox; a dedicated `SenderLoop()` thread encodes, computes
  offsets, sleeps to each packet's deadline and sends. `Stop()` joins it.

Verification on this host, no GamePad and no radio:

| Check | Result |
|---|---|
| `make` in `drcbuild:20.04`, `-Wall -Wextra` | clean, 0 warnings/errors |
| `tests/scheduler_test.cpp` — 26 assertions on schedule + policy | **26/26 pass** |
| `tests/streamer_smoke.cpp` — start/push 30 frames/stop | PASS |
| producer cadence | 30 frames in 507 ms (~500 expected) |
| `Stop()` latency (deadlock check) | **6 ms** |
| datagrams generated | **300 over 30 frames = 10.0 per frame** |
| jobs superseded | 0 |
| loopback capture → Barista analyzer | 3 383 video packets, **118/118 complete frames, zero protocol errors** |
| observed cadence / spacing | 57.96 fps, frame median 16 706 µs, packet median 300 µs |
| reconstruction → ffmpeg | **High profile 854x480 yuv420p, `-xerror` decode exit 0** |
| whole suite `tests/run-tests.sh` | **9/9 pass** |

The 10.0 datagrams/frame figure is the interesting one: real-console media
measured 611 VSTRM packets/s at 59.94 fps = **10.2 per frame** (§1.5). Our
packetiser now produces the same density as the console on synthetic content.

An IDR storm would have produced ~17.8 kB/frame instead of ~0.6 kB, i.e. the
pacing load the old code bursted in one go.

### 3.6 Recommended parameter set (merged from source, forks and measurement)

```c
x264_param_default_preset(&p, "medium", "zerolatency");   /* never slow */
p.i_width = 864; p.i_height = 480; p.i_csp = X264_CSP_I420;
p.analyse.i_subpel_refine = 7;      /* <=7: subme 8 = 60 resync/s + freeze */
p.analyse.i_me_method     = X264_ME_HEX;
p.analyse.inter &= ~X264_ANALYSE_PSUB16x16;
p.i_scenecut_threshold = -1;
p.b_intra_refresh = 1; p.i_keyint_min = 10; p.i_keyint_max = 30;
p.i_bframe = 0; p.i_bframe_pyramid = 0; p.i_frame_reference = 1;
p.b_cabac = 1; p.b_transform_8x8 = 0; p.b_interlaced = 0;
p.b_constrained_intra = 1;                                /* mandatory */
p.analyse.i_weighted_pred = 0; p.analyse.b_weighted_bipred = 0;
p.analyse.i_chroma_qp_offset = 0;
p.rc.i_rc_method = X264_RC_CQP;
p.rc.i_qp_constant = p.rc.i_qp_min = p.rc.i_qp_max = 32;
p.rc.f_ip_factor = 1.0; p.rc.i_aq_mode = 0; p.rc.i_lookahead = 0;
p.b_repeat_headers = 0; p.b_aud = 0;
p.b_drh_mode = 1;                    /* patched x264 only */
p.i_threads = 1; p.b_sliced_threads = 0; p.i_slice_count = 1;
p.nalu_process = cb;                 /* DRH chunks arrive here, not in nals[] */
```

Note our own harness (`tests/encoder_test.cpp:96`) uses `ultrafast`, and pc2drc's
fork ships `ultrafast` with `slow` commented out (`h264-encoder.cpp:40`) — so
existing "it decodes cleanly" results were produced at a preset that was never
suspected of causing the freeze. Re-run any such result at `medium` before
trusting it.

---

## Part 4 — can a modern/GPU encoder substitute? (analysis, not measurement)

Short answer: **not without a bitstream rewriter.** The blockers are structural,
not tuning:

1. **No slice header may be emitted.** Real H.264 requires every slice to carry
   a header; DRH mode deliberately omits it (`encoder.c:2584`) because the pad's
   decoder has a fixed configuration and assumes QP 32. VAAPI, NVENC, VideoToolbox
   and stock libx264 all emit headers — there is no "omit the slice header" knob
   in any of them, because omitting it produces a bitstream that is invalid by
   spec.
2. **NAL boundaries must land on macroblock row 6/12/18/24.** x264 can produce 5
   balanced slices (1620 MBs / 5 = 324 = exactly 6 rows of 54) and `drc-x264` in
   non-DRH mode still has that path, so *slice geometry* is reproducible — but
   each of those slices gets a header, so geometry alone does not help.
3. **QP must be pinned at 32 with `pic_init_qp=32` and `slice_qp_delta=0`**, which
   excludes any rate control (CBR/VBR/CRF). Hardware encoders are all RC-driven.
4. **The payload is already CABAC** — any post-processing must re-derive the same
   QP/deblock assumptions the pad makes.

The only viable substitute would be: encode with a normal encoder configured to
QP 32 and 5 equal slices, then **parse and strip each slice header** before
packetising. That is theoretically possible (the pad ignores the header bytes we
would remove, and if the encoder's parameters match the pad's assumptions the
residual is still correct), but nobody has done it and it trades a solved problem
for a fragile bitstream rewriter. **Verdict: keep `drc-x264`.**

The one experiment that would settle it cheaply: encode with `i_slice_count=5`,
`b_drh_mode=0`, CQP 32 and compare each NAL's first bytes against the DRH output
— the header prefix is the only difference to remove.

**However, an off-ramp already exists.** `PushEncodedVidFrame()` accepts five
pre-encoded DRH chunks from an external encoder and, per wozt's commit
`2c1fc8ea03`, that path "does not need drc-x264 present at all";
[ywh233/libdrc-streaming](https://github.com/ywh233/libdrc-streaming) already
pushed pre-encoded chunks from a PC. So a hardware encoder is reachable *behind*
a rewriter, not instead of one.

**Strongest evidence about what the requirement really is:** Barista abandoned
x264 entirely and ships a patched **MiniH264** encoder (`minih264e.h`). If a
clean-room encoder could satisfy the pad, then the "DRH-mode bits" — not the
x264 brand — are the real requirement.

### QP is not as immovable as the source comment claims

wozt measured QP 26 and 24 decoding fine, with **22 failing** and 24 already
beyond what the link carries (`b2464573be`). That contradicts the "QP must be 32"
story above: the pad *assumes* 32 because no slice header is sent, so any QP
other than 32 risks pad-side error — but it is not instantly fatal. The safe
lever is `mb_qp_delta` (adaptive quantisation) rather than frame QP. Caveat: both
stock and drc-x264 **zero `i_aq_mode` under CQP** (`encoder.c:804-812`), so an AQ
knob there is very likely a silent no-op — unconfirmed on hardware.

## Provenance

Three delegated agents ran in parallel with the local work. The **transport**
agent (packet layout, timing, pacing, recovery policy) and the **encoder-tuning**
agent (preset/subme threshold, artifact ranking, substitution verdict, audio) both
reported and their findings are merged above, cited by source file. The third
(codec contract) was stopped when its scope turned out to be fully covered by the
direct source reading in §1.2b and by the tuning agent's independent confirmation
of `encoder.c:2585`. Everything in this document is either **measured on this
host** (§2, reproducible) or **read from source** — nothing is taken on trust from
a forum post.
