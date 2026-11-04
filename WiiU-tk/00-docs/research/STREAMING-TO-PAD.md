# Streaming *to* the Wii U GamePad — current projects, tooling, quality, audio

Compiled 2026-11-03 from three delegated research passes, cross-checked against
measurements in `research/CODEC-SPEC.md`. Companion to `WEB-RESEARCH.md`
(radios/ecosystem) and `gamepad-alternative-paths-report.md` (non-radio routes).

---

## 1. Who streams to a real pad today

### 1.1 The project landscape

| Project | Last activity | What it does | Maturity |
|---|---|---|---|
| **BetaZay/Barista** | 2026-10-31, v0.1.74 | Full desktop: pairs without a console, video+audio, Desktop/Game-mirroring modes, uinput controller, GamePad touch keyboard | most mature; Linux x86_64 packages only |
| **wozt/bottom_screen** (`gamepad/`) | 2026-10-02 | Emulator surface → real pad via libdrc | **measured 58 fps, 0 resync** |
| **wozt/capture2cloud** (`drc_player`) | 2026-10-02 | HDMI/V4L2 capture → pad; takes arbitrary **RGBA 864x480** on stdin | hardware-validated generic pipe |
| **wozt/rtw88_TSF** | 2026-09-14 | Exposes MAC TSF on RTL8821CU | what unblocked the decade-old freeze |
| **ywh233/libdrc-streaming** | 2020-12-13 | Predecessor; failed on TSF drift | dead |
| thefloppydriver/pc2drc | archived 2026-04-05 | the original blueprint | dead; all its forks are build fixes |

Barista's eight forks add packaging/CI/regulatory handling and a radio-lifecycle
change; **none touch the codec path**, so there is no downstream fix for
artifacts or audio to cherry-pick.

Emulator integrations (Cemu `barista-connector-prototype`, Azahar) are
single-sitting prototypes from 2026-09-05/06, unmaintained since, but they do
demonstrate GamePad touch and motion in-app.

### 1.2 The cross-check that matters

`wozt/bottom_screen` reports **60 fps, 492 pkt/s, 2.76 Mbit/s, 0 keyframe
requests, held for 98 s** on real hardware. Our own measured equivalent for
moving content is **2.7 Mbps** (5 665 B/frame at 59.94 fps, §2.1 of
`CODEC-SPEC.md`) and **10.0 datagrams/frame** (console: 10.2). Two independent
implementations landing on the same bandwidth and packet geometry is the
strongest evidence we have that the numbers in `CODEC-SPEC.md` are right.

---

## 2. Tooling for inspecting the stream (mostly already local)

`research/barista-ref/scripts/` is a complete toolchain, and we have used it:

| Tool | Purpose |
|---|---|
| `analyze-media-capture.py` | envelope/length/sequence/5-chunk-end/frame-end checks |
| `reconstruct-media-capture.py` | headerless payloads → Annex-B (re-adds SPS `67640020ac2b406c1ef368`, PPS `68ee060ce8`, slice headers `0x25b804ff` / `0x21e003ff | frame_num<<13`) |
| `capture-analysis/decrypt_capture.py` | **the rot3 decryptor**: EEPROM → PMK, EAPOL MIC check against standard *and* rotated PTK, AES-CCM decrypt, writes both 802.11 and IPv4 pcaps |
| `summarize-wifi-rates.py`, `block_ack.py`, `analyze_format_clock.py` | radiotap PHY/MCS/retry, BlockAck, format-clock analysis |
| `capture-drcd-session.sh` | runs `drcd` + radio capture + plaintext AP-side capture |

Also public: **`memahaxx/drc-wireshark-plugins`** (dissectors for 50120/50121/
50123/50124, decodes the VSTRM header and option bytes; not upstream), and
**`memahaxx/drc-wireshark`** — a whole Wireshark **1.11.3** fork whose PTK
rotation lives in `epan/crypt/airpdcap.c` as an unconditional
`ptk[3:] + ptk[:3]`. Practical alternative: Wireshark 4.4 accepts a raw 16-byte
`tk` key, so pasting the *rotated* TK decrypts without any patched build.

**No public DRC pcap exists** anywhere (Wireshark sample captures: zero hits;
both Bitbucket projects ship none). Every reference capture in the Barista docs
is one they made.

What we already did with this toolbox: loopback capture → analyzer → reconstruct
→ ffmpeg, all clean (`CODEC-SPEC.md` §3.5). The next use is a real radio capture
once an adapter exists.

---

## 3. Reported quality, and what fixes it

**Numbers** (only Barista and wozt publish real ones; nothing is glass-to-glass):

- Barista host cadence **58.0–59.9 fps**, 4 969–5 148 complete frames over ~86 s,
  IDR every 60 frames, encoder 4.28 ms mean / 8.78 ms max in Release vs ~30 ms in
  Debug against a 16.683 ms budget, first-packet lateness p99 144 µs, layout lead
  5.07 ms vs the console's 5.1 ms.
- Stock console→pad latency, measured by Digital Foundry with a camera: **~33 ms**.
  That is the hardware floor; **nobody has published a number for any
  PC-impersonation stack**.
- moonlight-wiiu users: ~5 000 kbps over Wi-Fi and ~13 000 kbps wired before
  `error -1`; one report of "2 Mbit fine, 6 Mbit crashes after a few minutes".

**Artifacts are not (mostly) the network.** Barista logged 33 of 49 *fully
Block-ACKed* IDRs still drawing a recovery request within 5–50 ms. The fix that
actually worked was **zero-motion P prediction with explicit residual coding**
("basically 0 corruption"); 1 694-byte payloads, kernel `SO_TIMESTAMPNS`
timestamps, a Release build, and a proactive 60-frame IDR all helped. Rejected
because they made things worse: faster encoder search, a 250 ms IDR cooldown,
packet-count-aware chunk spacing, scheduled format-timestamp phase.

**Radio:** the real link is HT MCS 6, long GI, 99.33 % TID 5, RTS/CTS on ~99 % of
frames. FullMAC parts (BCM4364, MT7922, QCA9377) fail or drop after ~45 s; a
`country 00` regulatory domain blocks beaconing outright.

---

## 4. Audio — better than expected, with two real gaps

- **pc2drc never shipped audio** ("wishful thinking" in its TODO). **libdrc did**:
  384 samples per 8 ms packet, underflow filled with silence, very loose queue.
- **Barista ships it**: 48 kHz stereo s16le, **416 frames / 1 664 B per 8.666 ms**,
  byte-identical to the console, fed from nothing, paced on a steady clock, missed
  slots dropped rather than replayed.
- **Desktop and Game-mirroring modes are video-only** in Barista: no system audio,
  no touch-mouse, ASCII/US typing only. Audio works in the AppHook path only.
- Known audio bugs, both open: a high-pitched audio bug on an AX200
  ([#7](https://github.com/BetaZay/Barista/issues/7)) and "sound reaches the pad a
  couple of ms early" ([#14](https://github.com/BetaZay/Barista/issues/14)).
- **The headphone jack does not work** with any of these tools, and it is not a
  bug in them: the pad's audio amplifier is not aware of the jack; the UIC must be
  told (command 0x07 power-status bit 5) and the stock firmware reconfigures the
  amp. No project implements that. Plugging headphones will not reroute streamed
  audio.
- Reverse direction, for reference: **mic** = 16 kHz mono s16le, 520 B/16 ms to
  UDP 50021; **camera** = 640x480 H.264, ~25–30 fps, ~300 kB/s to 50020.

Our own budget note stands: uncompressed PCM costs a flat **1.54 Mbps**, ~45 % of
the media budget, and it shares the link with video rather than the video port.

---

## 5. What nobody has answered

- Glass-to-glass latency for *any* PC→pad stream.
- Real achieved Mbps to the pad for desktop vs video content (only wozt's
  2.76 Mbit/s emulator figure exists).
- Audio reliability: causes of stutter, the high-pitch bug, audio latency underflow.
- Headphone routing (UIC 0x07) — unimplemented everywhere.
- Long-session stability: the longest published run is ~98 s; nothing on
  multi-hour drift, reconnects, or thermal behaviour.
- 2.4 GHz co-existence with the DRC link.

## 6. What this changes for us

1. **Switch the desktop path to `drc_player`-style input when possible**: an RGBA
   864x480 pipe is already hardware-proven by wozt, and our own streamer now
   produces byte-correct VSTRM (validated end to end). That combination is the
   shortest route to "Kali desktop on the pad" without adopting Barista wholesale.
2. **Keep our five streamer fixes** — they cover three of the four artifact
   contributors Barista identified (payload size, pacing, proactive IDR) and one
   they never hit (the blocking-socket stall).
3. **Adopt their decryptor** (`decrypt_capture.py`) the moment we have a radio;
   it turns a capture into evidence without a patched Wireshark.
4. **Do not promise audio in desktop mode, and do not promise headphones at all.**
