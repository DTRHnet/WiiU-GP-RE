# The real console↔GamePad session, decrypted — measured ground truth

Compiled 2026-11-04 from `capture/console-truth.pcap` (165 MB, 300 s, monitor on the
console's channel 40, 662,116 frames) with the decryptor in `capture/truth-decrypt.py`.
Everything below is measured, not inferred: the plaintext of a **real** console↔pad
session is in this repo now (`out/evidence/truth/`).

This document supersedes four beliefs that rounds 11b–11o recorded as fact. See §6.

---

## 1. The CCMP recipe (why earlier attempts decrypted nothing but input packets)

Decryption needs three things beyond the PTK, and the project had two of them wrong:

| Element | Correct value | What we had |
|---|---|---|
| PTK | stock PRF-512, then Nintendo's **3-byte left rotation of the whole PTK** (`rot3`) | right (round 11m) |
| Proof | rotated **KCK** reproduces EAPOL msg2's MIC **and** rotated **KEK** AES-unwraps msg3's key data (this also yields the GTK, §5) | only the MIC check |
| AAD | `FC` (as sent) ‖ `A1` ‖ `A2` ‖ `A3` ‖ **`SeqCtl` zeroed** ‖ `QoS control` | SeqCtl sent as captured → failed |
| Nonce | **`priority` octet = the TID** ‖ `A2` ‖ `PN5..PN0` (`PN` taken as `hdr[7],hdr[6],hdr[5],hdr[4],hdr[1],hdr[0]`) | priority = 0 |
| Tag / FCS | 8-byte MIC, strip the 4-byte trailing FCS | right |

The nonce priority octet is the trap: with `priority = 0` **only TID-0 traffic
decrypts** — which is exactly the pad's 128-byte input packets (`50122 → 50022`).
That produced round 11n's conclusion "the console's media is group-key encrypted and
invisible"; it is neither. Media is **pairwise, key id 0, TID 5** and decrypts
**99.9 %** (115,215 of 115,277 frames) once the TID goes into the priority octet.

With that fixed, 167,154 of 167,324 protected frames decrypt (99.9 %). The residue is
frames straddling the three re-key boundaries.

## 2. The capture holds three sessions, not one

Three complete 4-way handshakes, each with its own PTK:

| session | t (s) | note |
|---|---:|---|
| 0 | 0.59 | pad already streaming the console's home screen |
| 1 | 53.98 | pad re-associates |
| 2 | 73.00 | pad re-associates again; media runs to the end |

Round 11n derived one PTK and stopped, which is why only 7,088 frames of that epoch
were ever visible. All three are needed; the tool now attributes frames to epochs.

## 3. Session-start choreography (this is the thing we could never see)

All times relative to capture start; the pad's AV pipeline comes up long after
association, not immediately.

| t (s) | event | evidence |
|---:|---|---|
| 0.59 | 4-way handshake #1 | 12 EAPOL frames |
| 0.92 | console starts a command stream: type 0, **incrementing u16 sequence at bytes 6–7**, every command acked by the pad with a type-3 packet carrying the same sequence | `port50023.bin`, `port50123.bin` |
| 1.1 – 27.9 | **778 × 1048-byte** `type 0 / query 0 / len 1040` UIC state blobs, ~28/s, then never again | `console-messages/cmd_t0_q0_len1040.bin` |
| 53.98 | handshake #2 | |
| 56.8 | audio starts (50021 → 50121) | `port50121.bin` |
| **61.0** | **video starts** (50020 → 50120). First frame = **25 datagrams**, every one carrying the `init` flag **and** the IDR ext-option | `console-messages/video_first_frame.bin` |
| 70.2 | console begins **UVC/UAC query** (56-byte `type 0 / query 1 / len 48`) at ~1/s, and **the 96-byte 50025 table** at ~1/s — same instant | `cmd_t0_q1_len48.bin`, `cmd_50025_table.bin` |
| 73.00 | handshake #3 | |
| **74.9** | pad sends **3 × `01 00 00 00`** from port **50110 → console:50010** — 13.9 s after video began | `port50010.bin` |
| 75.2 | console answers with a fresh IDR | last IDR-marked packet |
| 75 – 300 | **no further resync requests for 225 s**, video decodes | |

So a *healthy* session's whole resync history is **three datagrams**, sent once, answered
with one IDR. The pad tolerates ~14 s of video it cannot use before it asks.

## 4. Ground-truth envelope, per plane

**Video (UDP 50020 → 50120), 73,500 datagrams / 14,137 frames / 238.86 s**

| Property | Measured |
|---|---|
| Frame rate | **59.19 fps** (frame-timestamp deltas: 16,683 µs × 8,894, 16,684 × 5,101) |
| Datagram rate | 307/s over the video span; **5.20 datagrams/frame** |
| Max UDP payload | **1710 B = 16 B VSTRM header + 1694 B chunk** (2,827 packets at exactly 1710 B) |
| Chunks per frame | 5 for 13,332 frames (more only when a chunk splits) |
| Ext options | `82 00 83 85 06 00 00 00` (P, 73,454 pkts) · `80 82 00 83 85 06 00 00` (IDR, 46 pkts) |
| `init` flag | **25 packets only — all of the first frame**; never re-asserted |
| IDR frames | ~9 in 238 s (46 packets / 5 chunks) — one per ~26 s, plus the one after the resync requests |
| **Header bit layout** | `b0 = 0xF0 \| seq[9:8]`, `b1 = seq[7:0]`, `b2 = init\|frame-begin\|chunk-end\|frame-end\|ts-present \| len[10:8]`, `b3 = len[7:0]` — **corrected 2026-11-04** by a full census of all 73,500 datagrams: `b0[3:2]` is never set, `b1` spans the full 0–255, and `seq = (b0&3)<<8 \| b1` is a clean +1 10-bit counter. The console uses exactly libdrc's `SetSeqId()` layout. |

**Correction (2026-11-04, full census of all 73,500 console datagrams - supersedes an
earlier claim in this document):** the console does **not** use a 4+6 bit split. Measured:
`b0[3:2]` is set in 0 of 73,500 packets, `b1` spans the full 0x00-0xFF range (55,099 packets
above 0x3F), and `seq = (b0 & 3) << 8 | b1` is a clean +1 10-bit counter (71 wraps, 9
loss-gaps). That is exactly libdrc's and Barista's packing, so the VSTRM header is
byte-for-byte identical between the real console and our stream - see
`research/agents/vstrm-header-diff.md` for the full census (flags, ext options, length and
timestamp also match). The earlier "4+6" reading came from parsing the wrong bits and is
withdrawn.

**Audio (UDP 50021 → 50121)**: 27,573 packets, 1,672 B payload (`20 00 06 80` + LE µs
timestamp), ~113/s — matches our implementation and Barista byte for byte.

**Video-format message (50121, 32 B)**: 14,142 of them, 59.2/s over the video span:

```
04 00 00 00 | 00 00 00 00 | <ts LE> | 80 3e 00 00 | 80 3e 00 00 | 08 52 00 00 | 08 52 00 00 | 00 00 00 00
              ^^^^^^^^^^^
              the real console sends ZEROES here
```

Our stack (and Barista) send `11 11 81 08` in bytes 4–7 — the datasheet value. A real
console sends `00 00 00 00` in this session and still works for Barista, so this is
tolerated, but the project's "byte-exact console format message" claim (round 11) is
wrong about those four bytes.

**Command channel (50023 → 50123), 1,475 packets**

| count | type/query/len | what |
|---:|---|---|
| 778 | 0/0/1040 | UIC state blob, first 28 s only |
| 228 | 0/1/48 | UVC/UAC query, ~1/s from video start, 3 distinct bodies |
| 445 | 3/–/0 (8 B) | acks of pad replies, sequence echoed |
| 13 | 0/0/12 | `7e 01 …` generic commands (UIC service/method) |
| 4 | 0/2/8 | query type 2 ("time"), only before video |
| 3/2/1/1 | 0/0/44, 0/0/17, 0/0/324, 0/0/114 | one-offs (kept as evidence) |

Pad → console (50023): 1,475 replies — 1,034 × 8 B, 424 × 24 B, **5 × 792 B (the UIC
config blob)**, plus a few 20/28/48 B.

**UDP 50025 → 50125: 220 datagrams of exactly 96 B, ~0.96/s, starting with the video.**
This channel does not exist anywhere in our stack. The payload is a fixed 96-byte table
(magic `5a a5`, `58 00`, a u16 counter at offset 6 that increments 0,4,5,6,…, then a
monotonic 16-bit ramp `0x0010, 0x0018, … 0x00e8, 0x00eb, 0x00eb, 0x00eb`). Barista binds
50025 as a receive port and leaves it "unknown". See `cmd_50025_table.bin`.

**Pad input**: 48,760 × 128 B on 50122 → 50022 (≈163/s), unchanged from ours.
**DHCP**: 6 packets. **No pad traffic ever reaches 50020/50021.**

## 5. Bonus: the console's GTK is recoverable

`msg3`'s key data AES-unwraps with the rotated KEK (independent proof that our PTK is
correct), yielding RSN IE + `dd 16 00 0f ac 01` KDE:

* session 0 GTK: `2ee6bbaac7a9012effa840f6aed71afdbd` (+ trailing `dd 00`)
* sessions 1–2 GTK: `00e6bbaac7a9012effa840f6aed71afdbd`

No group-addressed data frame exists in the capture (0 multicast data frames), so the
GTK is unused in practice — media is pairwise. Keep the extraction anyway: it removes
"group key" as a future excuse.

## 6. Four things this disproves

1. **"`01 00 00 00` is a per-frame heartbeat, not a fault signal"** (CODEC-SPEC §2.3,
   round 11n, following wozt). A real console sees it **3 times in 300 s**. Ours sees
   it at **63/s**. It is a resync request, and a flood of them means the pad cannot
   decode. This is now the best objective success metric we have: *the rate should go
   to zero.*
2. **"The pad never starts its media services"** (rounds 11b–11f). Wrong: the pad is in
   the AV session and asking for keyframes. The absence of 50020/50021 traffic proves
   nothing — those are the pad's camera/mic uplinks (Barista's own port table), and they
   are silent in a healthy session too.
3. **"The console's media is sent under the GTK, so our unicast decryptor cannot see it"**
   (round 11o). Wrong on both halves: no multicast exists, and all media is key-id 0
   pairwise. It failed because of the TID/nonce bug in §1.
4. **"The format message and ext options are byte-exact console values"**. The ext
   options are (`82 00 83 85 06 00 00 00` / `80 82 00 83 85 06 00 00` ✔), but the format
   message's bytes 4–7 are `00 00 00 00` on the console, not `11 11 81 08`, and the
   VSTRM sequence packing differs (§4).

## 7. Where our stack now stands versus the console

| Property | console | ours | verdict |
|---|---|---|---|
| Video source port / dst | 50020 → 50120 | 50020 → 50120 (post round 11 fix) | same |
| Header layout | seq in b0[3:0]+b1[5:0] | seq in b0[1:0]+b1[7:0] (same as Barista) | differs, tolerated by pad |
| Flags / ext options | as measured | identical order and values | same |
| Payload cap | 1694 | 1694 | same |
| Chunks/frame | 5 × 6 MB rows | 5 | same |
| Frame rate | 59.19 | 59.94 target | same |
| `init` flag | first frame only (25 pkts) | every IDR frame (`init_flag = !inited \|\| idr`) | **differs** |
| IDR policy | ~1 per 26 s + one per resync burst | answers resync requests → many IDRs | **differs (symptom)** |
| Format bytes 4–7 | `00 00 00 00` | `11 11 81 08` | **differs** |
| Format/video phase | format ≈5 ms before video, ts = TSF − 1250 µs | same ts, sent together | **differs** (Barista parity) |
| UVC/UAC query | 56 B, 3 bodies, byte[0]→1 after first reply | 56 B, byte[0] stays 0 | **differs** (Barista parity) |
| **50025 / 50125** | 96-B table at ~1/s | **never sent, port not bound** | **missing** |
| UIC state blob (1048 B) | 778 × in the first 28 s | replayed by hand once (round 11o) | different, probably cosmetic |
| Media clock | TSF domain | synthetic + manual offset file | **differs** |

## 8. What to do next, in order

1. **Repeat the console's first frame.** ~~Build the first video frame after start
   exactly like `video_first_frame.bin`~~ **DONE 2026-11-04**: `init` is now asserted on
   the first frame only (`init_flag = !*vstrm_inited`,
   `pc2drc/libdrc-vnc/libdrc-thefloppydriver/src/video-streamer.cpp:95`), libdrc rebuilt
   and installed to `out/libdrc/lib`. Not yet observed on hardware. `tests/run-tests.sh`
   is 7/9 in this state, and both failures are environmental: the two socket-based tests
   cannot bind 50020/50022/50023 while the production stack is running.
2. **Send the 50025 table.** New 1 Hz sender of the captured 96 bytes (counter at offset
   6 increments; ramp constant) from source port 50025 to the pad's 50125. Nothing in the
   corpus explains it, and its start is simultaneous with the console's UVC/UAC polling —
   i.e. exactly when the console believes the pad's AV side is alive.
3. **Match the format/video phase**: send the format packet, then the video frame ~5 ms
   later, with the format stamped TSF−1250 µs (Barista parity).
4. **Set UVC/UAC request byte[0] = 1** after the first validated reply.
5. **Instrument the resync rate as the pass/fail signal** (`pad → 50010` datagrams/s,
   source port 50110). Zero is the target; 63/s is the current state; a healthy console
   session shows 3 in 300 s.
6. Only then re-visit the TSF clock question — with (1)–(5) in place, a faked clock is a
   variable we can finally isolate.

## 9. Reproducing

```sh
python3 capture/truth-decrypt.py capture/console-truth.pcap --outdir out/evidence/truth
```

Writes `udp-payloads.bin` (every decrypted datagram with timestamp/src/dst), per-port
dumps (`port50120.bin` etc.), `flows.json`, `classes.json` (decrypt rate per
direction/TID/epoch) and `console-messages/` (the reference messages listed above).
The tool discovers the AAD/SeqCtl/nonce-priority convention per epoch and per traffic
class instead of assuming one, and prints the per-class hit rate — so a future capture
with different conventions still reports what it can and cannot read.

## 10. Still unknown

* What the 96-byte 50125 table *is* (55 non-zero bytes, one counter, one 16-bit ramp).
* Why the pad needs ~14 s after video starts before requesting a resync in a real
  session, and whether that delay is a firmware "wait for N frames" rule.
* Whether the pad validates the VSTRM sequence packing at all (Barista's 8-bit layout
  suggests not).
* The glass-to-glass latency of any PC-driven session (no capture of a working
  PC-impostor stream exists, so our ground truth starts only at the console).
