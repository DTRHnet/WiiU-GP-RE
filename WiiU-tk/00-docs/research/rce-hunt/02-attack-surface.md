# 02 — Attack surface map: every parser the GamePad runs on bytes we control

**Scope.** Authorized local lab. We impersonate the console's DRH (AP + DHCP + all five UDP
services) for the owner's own GamePad. This document is offline analysis only: no radio, no
hardware, nothing transmitted, no existing file modified. New files created:
`research/rce-hunt/02-attack-surface.md` (this file), `research/rce-hunt/tools/*.py`,
`research/rce-hunt/tables/*` (companion work, see §11).

**Goal.** For each parser that consumes attacker-controlled bytes, state (a) the exact fields to
mutate, (b) the primitive if it works, (c) how we would *observe* it remotely with no eyes on the
pad, (d) how to make the test recoverable, (e) confidence and cost — then rank them and hand a
live-hardware harness an ordered experiment list.

---

## 0. Epistemic rules, and the one thing we do not have

| Tag | Meaning |
|---|---|
| **VERIFIED** | Measured by me from `out/evidence/truth/*` (decrypted real console↔pad session) or from a documented live-hardware result in this repo. Byte offsets given. |
| **DOC** | Stated in `research/libdrc/web/docs/re/*.rst`, `research/BOOT-AND-MODES.md`, `research/GROUND-TRUTH-SESSION.md`, `research/CODEC-SPEC.md`, or a cited source comment. |
| **INFERRED** | Follows from VERIFIED/DOC evidence plus standard C/RISC practice, but not directly observed. |
| **SPECULATIVE** | A hypothesis worth one cheap test; no evidence yet. |

**There is no GamePad firmware image in this tree** (searched: no `LVC_`/`UMI_`/`WIFI` blob, no
dump; §11 of `SETUP.md` states the same). Therefore **every statement about the pad's internal
parser code is INFERRED.** What *is* verified is (i) the exact bytes the real console feeds those
parsers, (ii) what the pad demonstrably accepts or rejects in our own hardware runs, and (iii)
other implementations' measured statements about pad-side limits. Everything below is written so
that the INFERRED layer is visible and falsifiable by one experiment.

Corollary that matters for planning: **a negative result is cheap and informative, a positive
result is only recognisable if the observability harness (§6) is running.** Nothing in the
manual operator workflow can see a heap smash; §6 is not optional.

---

## 1. What the pad parses, and who parses it

Boot chain and CPU split are DOC (`overview.rst:17-70`, `BOOT-AND-MODES.md:35-78`):

```
        we control the wire  ┌───────────────────────────────────────────────┐
  802.11 beacons/probes ────►│ BCM4319 Cortex-M3 = Broadcom Wi-Fi firmware    │  ← §5.7
  EAPOL 4-way, ADDBA ───────►│   (Nintendo-modified: rot3 PTK/KDK, a4:c0:e1)  │
  DHCP DISCOVER/REQUEST ────►└───────────────────┬───────────────────────────┘
        (relayed to the LVC's own IP stack)      │ SDIO
  ┌──────────────────────────────────────────────▼────────────────────────────┐
  │ DRC-WUP "LVC" — ARM926EJ-S, eForce/µITRON 4.0                             │
  │  services: cmd(50123) vstrm(50120) astrm(50121) hiddat(50122) msg(50110)  │
  │  managers: cmd nwk con ictag ir nvram sound video draw userif …            │
  └───────┬───────────────────────────────────────────────────────────────────┘
          │ SPI (UIC = slave)               │ i2c / gpio
  ┌───────▼──────────────┐        ┌────────▼─────────────┐
  │ UIC-WUP STM8 (2 KB   │        │ LCD ctrl, amp, backlight, PMIC │
  │ settings EEPROM)     │        │ hardware H.264 decoder (vout)  │
  └──────────────────────┘        └───────────────────────────────┘
```

| # | Parser | Wire | Bytes we control per session | Owner CPU | Basis |
|---|---|---|---|---|---|
| 1 | `cmd` outer + generic header, dispatch, fragment reassembly | 50023→pad 50123 | 1,475 dgrams / 300 s (VERIFIED), max 1048 B each; we can send any size ≤ MTU at any rate | LVC (cmdmgr) | DOC `sc-cmd.rst:27-104` |
| 2 | `svc 0` firmware/EEPROM methods | same | payload ≤ 1028 (DOC "Max. 1028") | LVC (nvram) | DOC `sc-cmd.rst:112-141` |
| 3 | `svc 5` UIC / IR / NFС / LCD methods | same | 0…531 B per DOC table | LVC → UIC STM8 over SPI | DOC `sc-cmd.rst:220-261` |
| 4 | `svc 1/2/3/4` readers | same | reply-shaped (113/272/13/152/448/772 B) | LVC | DOC `sc-cmd.rst:148-213` |
| 5 | `query type 1` UVC/UAC (camera/mic) | same | 48 B struct, ~1/s | LVC → cmos/aamp | DOC `sc-cmd.rst:263-308` |
| 6 | `query type 2` time | same | 8 B, per session | LVC (time mgr) | DOC `sc-cmd.rst:310-325` |
| 7 | `vstrm` header + 8-byte option area + chunk reassembly + H.264 | 50020→50120 | 307 dgrams/s; max 1710 B/dgram (VERIFIED) | LVC (vstrm/video) → HW decoder | DOC `sc-vstrm.rst` |
| 8 | `astrm` audio header + PCM + 32-B format message | 50021→50121 | 27,573 audio + 14,142 format dgrams / 239 s (VERIFIED) | LVC (astrm/sound) → aout/aamp | DOC `sc-astrm.rst` |
| 9 | 96-byte table | 50025→50125 | 96 B @ ~1/s (VERIFIED, 220 dgrams) | LVC (unknown) | **undocumented** (`services.rst:23` ":doc:`???`") |
| 10 | `msg` broadcast/inter-pad | 50110 (pad listens) | arbitrary UDP | LVC (msgmgr) | **undocumented** — `sc-msg.rst` is a 40-byte stub |
| 11 | DHCP client options | 67→68 | one datagram per boot (VERIFIED: 2 DISCOVER + 2 REQUEST + AUTH in the capture) | LVC (nwk) | DOC `wifi.rst`; §5.8 |
| 12 | 802.11: beacons/probe-resp IEs, RSN IE, EAPOL key data/KDE, ADDBA, CSA, WPS | air | entire BSS | **BCM4319 Cortex-M3** | DOC `overview.rst:43-54` |
| 13 | `hiddat` input (pad → us) | pad 50122→50022 | we do not write it; we drive it indirectly | UIC STM8 → LVC | DOC `sc-input.rst` |

Rate sanity: the command plane is *low* rate (≈5 dgrams/s average) but has the **largest method
space** (≈60 service/method pairs, several with attacker-length payloads). The media planes are
*high* rate (307 + 115 dgrams/s) with tiny fixed headers and one length field each — the classic
place where a length is trusted because "the console always sends exactly the right value".

---

## 2. Ground truth re-measured for this document (and 4 corrections to our own docs)

All numbers below are mine, from `out/evidence/truth/`, reproducible with
`research/rce-hunt/tools/cmd_scan.py` and `research/rce-hunt/tools/make_cmd.py selftest`. The dump
record frame is `>d 4s 4s I` (timestamp, src, dst, length) + payload — from
`capture/truth-decrypt.py:558`.

### 2.1 `cmd` outer header — 1,475/1,475 records are self-consistent (VERIFIED)

`port50123.bin` (console→pad), decoded per `sc-cmd.rst:32-37`:

| (packet_type, query_type) | dgram len | count | outer `payload_size` |
|---|---|---|---|
| 0,0 (generic query) | 20 / 25 / 52 / 122 / 332 / 1048 | 13 / 2 / 3 / 1 / 1 / **778** | always `len−8` |
| 0,1 (UVC/UAC) | 56 | 228 | 48 |
| 0,2 (time) | 16 | 4 | 8 |
| 3,x (reply ack) | 8 | 213 / 228 / 4 | 0 |

**Every one of the 1,475 has `payload_size == datagram_len − 8` exactly, and every generic command
has generic `payload_size == datagram_len − 20` exactly.** The console never lies about a length.
Sequence IDs run 8 → 1044 with one ID per logical request.

### 2.2 Generic header — the bit layout the console actually uses (VERIFIED)

`sc-cmd.rst:69-79` gives `magic | version | be12 transaction_id | be12 fragment_id | flags | svc |
method | be16 error | be16 payload_size`. The bytes disambiguate it:

```
off 8   7e            magic
off 9   01            version
off 10  tid[11:8]     transaction id, high nibble
off 11  tid[7:4] << 4 | FIN(0x08) | fid[10:8]      ← one byte carries tid, final, fid
off 12  fid[7:0]
off 13  flags         0x40 = last fragment, 0x42 = more fragments follow
off 14  service       off 15 method
off 16  be16 error    off 18 be16 generic payload_size
```

* `tid = (p[10]<<8) | (p[11]>>4)`; `FIN = (p[11]>>3)&1`; `fid = ((p[11]&7)<<8) | p[12]`.
  libdrc's own reader/enum agrees (`include/drc/internal/cmd-packet.h:95-106`,
  `run/pad-state.py:66-73`).
* **VERIFIED:** across the 778-fragment state push, `tid` increments **once per logical message**
  (195 distinct tids, `0x10B … 0x0D0D`, contiguous) and `fid` cycles 0,1,2,3 with `FIN` set
  exactly on fid 3 — i.e. `tid` is the message key and `fid` the fragment index inside it.
* **VERIFIED:** `flags` and `FIN` agree on 777 of 778 fragments; the exception is
  `t=29.458 svc 4/0x1a` which carries `flags=0x42` ("more follows") **and** `FIN=1`, and the pad
  answered it with a normal `error=0` reply. So the pad does not require the two encodings to agree.
* **VERIFIED:** every pad reply sets `flags = 0x09`, which is exactly
  `((query.flags>>3)&0xFC)|1` for `0x40` and for `0x42` (`sc-cmd.rst:90-92`), echoes `tid`,
  echoes the generic `payload_size`, and sets `error=0000` — the only non-zero error code observed
  anywhere in this project is `9004` (§6.3).

### 2.3 The `svc 0 / method 0x11` state push, decode (VERIFIED)

| Property | Measured |
|---|---|
| Count | **779** records, `t=1.117 … 27.867 s` (~28/s burst) |
| Datagram | 1048 B (778×) and **332 B (1×)** |
| Outer | type 0, query 0, `payload_size = 0x0410` (1040) / `0x014C` (332−8 = 324) |
| Generic | `7e 01`, tid as above, `flags 0x42` (584×) / `0x40` (194+1×), `svc 0`, `method 0x11`, `error 0`, `payload_size 1028` (778×) / `312` (1×) |
| Payload | `u32` **big-endian** index at payload offset 0, running **1 … 779**, zero gaps; bytes 4…1027 are per-message session data (only bytes 0–1 are constant across the 778) |
| Grouping | 194 messages × 4 fragments (`fid 0,1,2,3`, 1028 B each) + **1 message of 3 fragments: 1028 + 1028 + 312 = 2368 B** (tid `0x0D0D`, `fid 0,1,2`, FIN on fid 2) |

**Correction 1.** `BOOT-AND-MODES.md:237-248` says the push ends with "*194 complete messages, then
a trailing `M M`*" — i.e. the console stops mid-message. It does not: the last logical message is
**complete**, with a **short final fragment** (312 B, FIN set). That matters because the pad's
reassembler must therefore handle a final fragment of *arbitrary* length, which is exactly the
freedom we want (§4.1).

**Correction 2.** `BOOT-AND-MODES.md:243` calls the outer field `payload_size = 1028`; the bytes say
outer 1040, inner 1028.

**Correction 3 (important, affects the stream plan).** `GROUND-TRUTH-SESSION.md:81` (and the
derived rows in §7 and §10) claims the console packs the VSTRM sequence as `b0 = 0xF0|seq[9:6]`,
`b1 = seq[5:0]` ("the console puts the low 6 bits in byte 1, libdrc/Barista put 8"). Measured over
all **73,500** VSTRM datagrams in `port50120.bin`: byte 0 takes only 4 values (`f0,f1,f2,f3` = 2
bits of sequence), byte 1 takes all 256 values, and the decode `seq = ((b0&3)<<8)|b1` yields
**73,490/73,499 = +1 deltas** with 9 anomalies, while the documented 6-bit decode yields 941
anomalies. **The console packs exactly like libdrc and Barista: 2 bits in byte 0, 8 bits in
byte 1, mod 1024.** §7's "header layout differs" row and §10's open question should be retired.
(Independently confirmed by `research/rce-hunt/05-pad-parsers-in-code.md:34-75`.)

**Correction 4 (evidence-quality, not protocol).** `out/evidence/truth/console-messages/`
`cmd_t0_q0_len114.bin` (114 B) and `cmd_t0_q0_len44.bin` (44 B) are **truncated copies**: the same
messages in `port50123.bin` are 122 B (`svc 5/0x02`, payload 102, declared 102) and 52 B
(`svc 0/0x10`, payload 32, declared 32). Their apparent "declared > actual" mismatch is an
extraction artefact, **not** a console violation. Do not cite them as tolerance evidence.
(Everything else in `console-messages/` reproduces byte-exactly — my builder regenerates
`cmd_t0_q0_len1040.bin`'s 1048 bytes identically, `make_cmd.py selftest`.)

### 2.4 Every documented cmd method for which the capture shows the real bytes (VERIFIED)

| t (s) | svc/method | tx payload | pad reply | note |
|---|---|---|---|---|
| 0.917 | 0/`0x00` | 0 | 8 B `19 0c 01 17 19 0c 01 17` (LE u32 running/installed = 385,944,601) | matches the oracle run in `out/evidence/pad-state/2026-11-04-oracle.md:19` |
| 0.920 | 4/`0x04` | 0 | 28 B `0000000b 00000040 190c0117 28000058 00080000 0c0221fe 00001ccc` | identical to the live oracle's reply |
| 0.924 | 5/`0x06` | 0 | **792 B**: generic `payload 772` = `28 00 00 58` (UIC fw ver) + 768 B EEPROM | EEPROM dump contains `WiiUccfb65b68169` and the 64-hex PSK |
| 0.936 | 4/`0x05` | 0 | 1 B (state index) | |
| **0.956** | **5/`0x0c`** | **`13 03 02 95 2c`** | 20 B `error=0`, empty | **UIC EEPROM write: index 0x13, length 3, data+crc `02 95 2c`.** Sent *twice* per session (also at 80.724) |
| 1.107 | 0/`0x10` | 32 B `00 0c 29 34 00…` | 20 B empty | undocumented method |
| 1.117 | 0/`0x11` | 1028 B fragments (§2.3) | 24 B `…00 00 00 00` (4 B payload) per fragment | one reply per fragment, `payload_size 4` |
| 27.867 | 0/`0x11` | 312 B, index 779 | 24 B | short final fragment |
| 28.890 | 0/`0x12` | 32 B `00 00 03 0b 00…` | 24 B, payload 4 `00 00 00 00` | undocumented; payload starts with the same BE u32 index form |
| 29.308 | 4/`0x21` | 32 B zeros | 20 B empty | undocumented |
| 29.458 | 4/`0x1a` | 0, `flags 0x42`+`FIN` | 20 B empty | shutdown-if-flags-0x42 method, answered normally |
| 59.198 / 73.328 | 0/`0x00`, 4/`0x04` | 0 | as above | re-queried on every re-association |
| 59.398 | 5/`0x02` | **102 B zeros** (UIC cmd 0x0c) | 20 B empty | 8 bytes are *missing* if you trust the truncated file (§2.3 correction 4) |
| 70.198–299.583 | 0/query 1 | 48 B, `byte[0]` flips 0→1 at t=73.318 | 24 B non-generic, content changes twice | UVC/UAC; the pad's reply body changes at 73.3 s and 81.3 s (`…0158` → `…0100`) |
| 0.901 … 73.313 | 0/query 2 | 8 B `a4ef 0000 305e 0000` (days 61348, secs 24112) | 8 B empty | sent on each associate |

### 2.5 Media plane envelope (VERIFIED)

| Plane | Measured |
|---|---|
| VSTRM | 73,500 dgrams, `t=61.013…299.871`; all `magic=0xF`, packet_type 0; **declared `payload_size` == `len−16` in 73,500/73,500**; max 1694, min 1; 14,137 frames; 13,331 frames with exactly 5 packets and 14,127 with exactly 5 `chunk_end`s; flags combos: `init+fb` 1, `init` 19, `init+ce` 4, `init+ce+fe` 1 (⇒ **25 init-flagged, all in frame 1**), `fb+ce` 13,905, `ce` 42,631, `ce+fe` 14,136, `fb` 231, none 2,572; **two frames deviate**: one with 4 `chunk_end`s (8 frames), one with 9, one with 2 `frame_end`s, one with 0 |
| VSTRM options | exactly two byte strings, ever: `82 00 83 85 06 00 00 00` (73,454) and `80 82 00 83 85 06 00 00` (46) |
| VSTRM seq | 2 bits in b0 + 8 in b1 (§2.3 correction 3); 0 duplicates, 9 discontinuities in 73,499 |
| ASTRM PCM | 27,573 dgrams of 1672 B = 8 B header + 1664 B; header `20 00 06 80` + LE u32 µs timestamp (delta 8,666/8,667 µs); byte 1 = 8-bit seq, +1 in 27,568/27,572, 3 gaps |
| ASTRM format | 14,142 × 32 B: `04 00 00 00 | 00 00 00 00 | ts LE | 80 3e 00 00 ×2 | 08 52 00 00 ×2 | 00 00 00 00`; **declared outer length field (bytes 2-3) = 0x0000 while 24 payload bytes follow**; ts delta 16,683/16,684 µs |
| Resync | 3 × `01 00 00 00` from pad 50110 → 50010 at t=74.93/74.94/74.96 |
| Input | 48,760 × 128 B, ~163/s, `seq` u16 LE at 0–1 (2 resets = 3 sessions), `fw_version_neg`=0xD7 at byte 127 |
| 50125 | 220 × 96 B; **only offset 6 varies** (u16 LE counter 0…0x00de); magic `5a a5` at offset 8; `58 00` at 4–5 and 10–11; ramp `0x0010,0x0010,0x0010,0x0018,0x0020,…,0x00e8,0x00eb,0x00eb,0x00eb` at offsets 28–93 |
| DHCP | 6 pad→broadcast datagrams (300 B): DISCOVER ×3 and REQUEST ×3; `chaddr 40:d2:8a:17:e2:09`, `hlen 6`, cookie `63 82 53 63`; params requested = `01 03 06 33 3a 3b`; option 54 = 192.168.1.10, option 50 = 192.168.1.11; **no option 12/60/61** |

---

## 3. Why a length field is the whole game

Three independent, *measured* facts make length-field abuse the primary hypothesis class:

1. The pad's own implementations treat VSTRM `payload_size` as authoritative and **1694 is the
   console's maximum**: `wozt-libdrc/include/drc/internal/vstrm-packet.h:38-42` records a
   measurement — "*at 1700 the GamePad stops decoding outright and asks for a keyframe on every
   frame*" — while the field holds **11 bits (≤2047)**. A buffer edge in
   `(1694, 1700]` with a field that reaches 2047 is a probe with a known target (§4.4).
2. The pad **does not enforce** at least one declared length: the format message carries
   `payload_size = 0` with 24 real bytes and a working console session (`sc-astrm` + VERIFIED
   §2.5), and libdrc sends `0x0018` in the same field with the same body and also works
   (`05-pad-parsers-in-code.md:278-292`). So the pad sizes that body from the datagram, not the
   field. **That cuts both ways**: it is evidence the pad *is* careful somewhere, and it makes the
   planes where the field is arguably needed (VSTRM chunk data, cmd fragments) the interesting ones.
3. The cmd plane's fragment reassembly **must** sum declared payload sizes to build a message
   (§2.3), because the console's own last message has fragments of 1028, 1028 and **312** bytes.
   Any implementation of that sum is one arithmetic check away from being free.

---

## 4. Plane-by-plane analysis

### 4.1 `cmd`: outer header, generic header, fragmentation

**Parser model (INFERRED from DOC + the console's traffic).** `cmd` service receives a datagram on
50123 → reads `CmdHeader` → dispatches on `query_type` → for type 0 reads `GenericCmdHeader`
(magic, version, tid/fid, flags, svc, method, error, length) → if `flags&0x2` (or `FIN==0`) buffers
the payload and waits for more; on the final fragment reassembles, calls the manager handler, and
replies with `flags=(q>>3)&0xFC|1`, echoed tid/length. Retransmission until ACK is DOC
(`sc-cmd.rst:25` "Until a ACK is received, DRH/DRC will retry sending").

**Mutations and what each would prove**

| Mut | Bytes | Hypothesis | Primitive if true |
|---|---|---|---|
| M1 | outer `payload_size` = 0xFFFF while sending 20 B | outer length used as a copy/reassembly length | OOB read (leak in reply) or memcpy of 64 KB from a socket buffer |
| M2 | outer `payload_size` = 0 with 1028 B of body | the pad might use the *datagram* length (safe) | tells us which field is authoritative → gates M1 |
| M3 | generic `payload_size` = 1028 with 20 B delivered, `FIN=1` | handler reads 1028 B from a 20-B datagram | OOB read of 1008 B of LVC memory; for `svc 5/0x02` those bytes are then **forwarded to the UIC over SPI**, and for `svc 5/0x11` (IRCOM) up to 520 B come back in a reply → **leak channel** |
| M4 | fragment series `fid 0..0x7FF`, each `payload_size 1028`, `FIN` only on the last | reassembly buffer is fixed (≥4 KB, maybe 8 KB) | heap/BSS overflow with our bytes |
| M5 | `fid` out of order (3,0,1,2), repeated (0,0,0,0), or `FIN` on fid 0 followed by more | reassembler trusts fid as an offset/index | write at attacker offset, or partial overwrite of a struct |
| M6 | `tid` reuse: two different svc/method under the same tid, or the same tid interleaved with another | tid keyed state machine can be desynchronised | one message's bytes assembled under another message's service → **dispatch confusion** (send 1028 bytes of ours as `svc 0/0x03` firmware data) |
| M7 | `flags=0x42` with `FIN=1` (the console itself does this once, §2.2) | both encodings are read | established tolerance; useful as a control |
| M8 | `flags=0x43`/`0x41`, `flags&3` combinations never seen | `flags&3` means "multi-fragment" per DOC | undefined path |
| M9 | version byte ≠ 0x01 | version dispatch | unknown method table / default handler |
| M10 | `magic ≠ 0x7E` | hand-rolled parser may skip the check | dispatch of a *different* structure (e.g. 48-byte UVC/UAC body interpreted as generic) |
| M11 | reply ACK games: reply to our own query as type 2 with a foreign seq; never ACK; ACK with wrong seq; duplicate queries with identical seq | state-machine confusion / retransmit storm | pending-transaction table exhaustion, or an uninitialised reply buffer being handed to the handler |
| M12 | `error_code` non-zero in a *query* | does the pad read `error_code` from queries? | if it does, `0x9004`-style paths may be reachable deliberately |

**Observability.** (a) fraction of our type-0 queries that get a type-1 ACK within 200 ms;
(b) reply latency/seq gaps; (c) `svc 4/0x05` state index; (d) input rate + input seq resets;
(e) reply *contents* for methods that echo data (`svc 0/0x0a`, `svc 5/0x06`).

**Why M3/M4 first.** The primitive is a *read* or a *write* of contiguous attacker-adjacent
memory, in a handler that already has a leak channel (`svc 5/0x06` returns 772 B; `svc 5/0x11`
returns up to 520 B; `svc 3/0x05` returns 448 B). A read primitive that returns bytes in a reply is
the ideal first finding: it proves the length is trusted without risking a crash.

### 4.2 `svc 5`: methods that move our bytes into another CPU or into hardware

DOC `sc-cmd.rst:220-261`, plus what the capture shows. Each row is a candidate write/leak channel:

| Method | Doc payload / reply | Our evidence | Attack reading |
|---|---|---|---|
| `0x0c` update UIC EEPROM | 258 B: `u8 index, u8 length, data+crc[]` | **VERIFIED** `13 03 02 95 2c` → index 0x13=19, length 3, `02 95` + crc `2c` (length appears to *include* the CRC byte) | **persistent write into the UIC's 2 KB settings EEPROM** (holds SSID/PSK/language/TV codes, `overview.rst:67-69`). `index` and `length` are single bytes: `index+length` can reach 510, comfortably past the EEPROM end without any wrap. If the LVC stages the write in a 256-B stack array keyed by index, ×255 is a stack overflow |
| `0x02` → UIC cmd `0x0c` | 102 B: `u16, u16, {u8,u8,u8}[32], u16` | **VERIFIED** 102 B of zeros, twice per session | Sends 102 B to the STM8. If the LVC reads *declared* length here (M3), the extra bytes come straight out of LVC memory and go over SPI. Reply is empty → no leak, but a bad `{u8,u8,u8}[32]` could confuse the UIC's own command parser |
| `0x11` IRCOM | ≤520 B payload, **≤520 B reply**; first byte selects connect/send/receive/disconnect | not in the capture | bidirectional attacker buffer in the `ir` manager; buffer sizes unconfirmed |
| `0x10` ICTAG/NFC | 531 B | not in the capture | full NFC stack in the `ictag` manager → the most "real protocol" parser on the pad |
| `0x06` read UIC fw + 768 B EEPROM | reply 772 | **VERIFIED 792-B reply**; contains the SSID and PSK | already a *confirmed info-disclosure of the pad's Wi-Fi secrets* (this is how T2 passed, `BOOT-AND-MODES.md:188`) |
| `0x19` / `0x1a` LCD i2c set/get | 13 B / 13-B reply | not in the capture | **direct panel register writes**. 13 bytes of ours reach the LCD controller over i2c. Register semantics unknown → a sweep is a *panel* experiment, not a memory one |
| `0x17` / `0x18` remocon IDs | 7 B / 10 B (two 5-byte IDs) | not in the capture | stored TV remote codes; write into EEPROM-backed settings |
| `0x00` read UIC table @0xf8d0 | reply 6 B | not in the capture | fixed table read; `0xf8d0` is a *UIC address*, so this is UIC-side, not LVC-side |
| `0x08`, `0x0a`, `0x14`, `0x15`, `0x01`, `0x16`, `0x0b`, `0x0e`, `0x0f` | small | `0x14`/`0x15` **VERIFIED working** (brightness 4 read back) | panel/audio enable, GPIOs; `0x14` out of range (0, 6…255) is a one-command brightness test |

**Live-hardware precedent that this plane is actuated, not just ACKed:** `BOOT-AND-MODES.md:177-200`
and §11 of the same file — a sweep of service 5 methods `0x00–0x1f` with a 1-byte payload put the
panel **black**, and `0x07` with `0x01` produced a visible flicker. So the commands reach hardware,
and the pad tolerates payloads that do not match the documented sizes (many of those methods take
no payload at all).

### 4.3 `svc 0`: firmware and EEPROM as write primitives

| Method | Doc | Attack reading |
|---|---|---|
| `0x02` start product update | 4 B | opens the update state with an attacker-chosen product selector; the only *documented* path that later accepts 1 KB blocks |
| `0x03` update data | **"Max. 1028"**, `struct { u32 block_idx; u8 data[]; }`, reply 4 B | **the highest-value write primitive on the pad.** If `block_idx` indexes `buf + block_idx*N` with no bound, `0xFFFFFFFF` is a wrap to a negative offset; if it indexes flash, we choose the destination region. Counter-hypothesis: the pad checks a signature/version before `0x04` end-update, and `0x03` outside update mode just errors |
| `0x04` end update / `0x05` abort | 0 | the commit and the escape hatch. **Never send `0x04` until `0x03` semantics are understood** |
| `0x0b` / `0x0d` / `0x0f` | 9 B / 4 B / 4 B | TVCode/Service/Screen and language/bank/version update starts and a 4-B setter — smaller write paths into the same settings store as `svc 5/0x0c` |
| `0x0a` read EEPROM field | 1 B index, reply 4 B; documented indices **0..4** | **the cleanest OOB-read candidate on the pad**: a documented 5-entry selector (`language_bank_and_ver, tv_remocon, service_firmware_version, opening_screen_1, opening_screen_2`) with a 1-byte index that reaches 255 |
| `0x09` | 1 B, "returns hardcoded values" | second 1-byte selector with an undocumented table |
| `0x00` LVC version | 0 | reboot oracle: value changes if the running image ever changes |

**A write-what-where buys what.** LVC code runs from RAM (`boot.rst:16-22`: SPL loads `LVC_` to
`RAM_SIZE-64K` and executes it). Anything that writes to an arbitrary address in the LVC's address
space, or that lands an overflow in a region later used as a function table, converts into code
execution **in the process that owns the LCD**: `drvldc`, `vout`, `draw`. That is the objective
(LCD control), and it is more valuable than anything achievable from the radio side (§5.7), because
the framebuffer and panel are behind the LVC.

### 4.4 `vstrm` (50120): the media parser, 307 dgrams/s

**Header (DOC `sc-vstrm.rst:23-36`, VERIFIED layout):**

```
b0 = 0xF0 | ptype(2) | seq[9:8]      b1 = seq[7:0]
b2 = init(0x80) | frame_begin(0x40) | chunk_end(0x20) | frame_end(0x10)
     | has_timestamp(0x08) | payload_size[10:8]
b3 = payload_size[7:0]
b4..b7  u32 BE media timestamp (µs)
b8..b15 option area: read linearly until 0x00 or 8 bytes
        0x80 IDR · 0x81 arg(1B, no-op) · 0x82 arg (fps index) · 0x83 force-decode
        0x84 unset-force · 0x85 arg (NumMbRowsInChunk)
```

| Mut | Bytes | Hypothesis | Primitive if true |
|---|---|---|---|
| **V1** | `payload_size = 0x7FF` (2047) with 20 real bytes | the pad copies/reassembles `payload_size` bytes from a datagram buffer | **read of ~2 KB past a 1694-B buffer → into the decoder's input ring**; the decoder then decodes garbage, and `chunk_end` decides when. Highest-signal test in the media plane because the pad's edge is *measured* at (1694,1700] (§3.1) |
| **V2** | `payload_size` = 1695…2047 with the matching real bytes (send 1700+ in one datagram) | the ceiling is a *buffer* bound, not a policy | direct overflow past the reassembly buffer with our own bytes: `wan` the bytes are ours, so a crash here is a *confirmed* overflow, not a theory |
| **V3** | `0x85` arg = 0, 1, 2, 255 (`NumMbRowsInChunk`) | the decoder is programmed with rows-in-chunk → framebuffer row offsets/stride | 255 rows × 16 px on an 864-wide surface walks ≈5.3 MB past a 854×480 framebuffer. **If the hardware decoder computes an offset from this field, this is an arbitrary-ish write at MCU speed** |
| **V4** | `0x83` (force decoding, DOC: "Forces decoding even if buffer is too small") without `0x85`, or with a chunk whose declared size > delivered | the pad's own documented size-check bypass | the decoder writes macroblocks for data it should have rejected |
| **V5** | `chunk_end` never set (one 4 MB "chunk"); `frame_begin` ×2 in a row; `frame_end` before 5 chunk ends; interleave two frames | reassembly accumulator with no cap | buffer overflow by length accumulation, exactly like cmd M4 |
| **V6** | duplicate seq with different bytes; seq jump backwards; `init` mid-stream repeatedly; `init` on every packet | dedupe/rearm logic | re-arm churn (alloc/free of decoder state) → use-after-free or resource exhaustion. Note our own stack already sets `init` on every IDR and the pad tolerates it, but `init` on *every packet* was never tried |
| **V7** | `0x82` arg 4…255 | a 2-bit fps index read as an array index (DOC lists 4 values) | OOB read in a timing table |
| **V8** | option area = 8 non-zero bytes; `0x81` as the *last* byte (its argument would be the first payload byte); unknown options `0x86`, `0x01`, `0xFF` | the linear option reader's termination rule | option-stream desync → the parser's `payload_size` position shifts, or one byte of chunk data is eaten; combined with V1 this can be used to place payload bytes *inside* the option area |
| **V9** | `has_timestamp=0` (b2 bit3 clear) with b4..b7 present | header shrink from 16 to 8 bytes (`sc-vstrm.rst:15-16`: "8 byte header (4 is also possible but never seen)") | the pad reads the payload from a different offset → every byte of a frame shifts; also the classic "header size from a flag" bug shape |
| **V10** | `payload_size = 0` with a full 1694-B datagram | inverse of the format message's `0` | confirms which field the pad trusts (see §3.2) |

**Observability (media).** Resync rate (`pad → 50010`, target 0, our stack currently ~63/s,
console 3/300 s — VERIFIED); input rate; `svc 4/0x05`; pad re-association in the hostapd log;
ICMP loss to 192.168.1.11. A decoder-side overflow usually shows as: resync storm → input
continues but video never repaints → pad eventually resets (input seq reset).

**Recovery.** Purely sender-side: stop sending, resume the known-good stream
(`run/04-stream.sh` / `tests/run-tests.sh`), and for a wedged decoder, svc 4/0x01 payload 0
(DOC `BOOT-AND-MODES.md:167-169`) or the pad's power button.

### 4.5 `astrm` (50121): PCM + the 32-byte format message

**Layout (VERIFIED, and libdrc's reader `src/astrm-packet.cpp:44-70` agrees):**
`b0 = format(3) | vibrate | mono | type(bit2) | seq[9:8]`, `b1 = seq[7:0]`,
`b2..b3 = be16 payload length` (**big-endian** — 1664 = `06 80` on the wire), `b4..b7 = le32 µs`,
then PCM. Type bit `0x04` set = format message (VERIFIED: audio = `0x20`, format = `0x04`).

| Mut | Bytes | Hypothesis | Primitive |
|---|---|---|---|
| A1 | `b2..b3 = 0xFFFF`, 1664 B present | declared length drives a copy into the audio ring | overflow of the sound ring buffer (~2×1664 B?) with our PCM; or a 65 KB DMA read |
| A2 | `b2..b3 = 0` or 1 with 1664 B present | does the pad use the datagram length? (§3.2 suggests yes for the format message) | gates A1 |
| A3 | odd length (1665, 1663), length not a multiple of 4 | `payload_size % 2` / frame alignment checks (Barista's own reader rejects odd lengths and zero: `core/drh/gamepad_media.cpp:143`) | integer truncation → half-sample writes |
| A4 | format message body: fps fields `16000/21000` → 0, 1, `0xFFFFFFFF`; timestamp backwards; `b0` format bits 6,7 (`0x40`,`0xC0`) | timing/geometry values become divisors or delays | division by zero / hang; wrong video-start delay → black panel |
| A5 | format message with declared length 0xFFFF (24 B present) | the pad sizes by datagram (§3.2) — expected **negative** | *control experiment* that calibrates how the pad treats declared lengths; worth doing first because it costs one datagram |
| A6 | audio `seq` repeats/gaps; timestamp jumps backwards by 2^31 | the sound manager's playout ring | stale-buffer replay, or a ring index computed from the timestamp |

**Note:** the astrm plane is the loudest place to prove a length field is trusted (1664 B of ours
per datagram, 115/s) and the quietest to observe (we hear nothing). Ranked below V1/V2 for
observability, not for likelihood.

### 4.6 The 96-byte 50125 table (undocumented)

VERIFIED: 220 datagrams, `~0.96/s`, starting when video starts; **only offset 6 varies** across all
220 (u16 LE counter 0…222). Constants: `5a a5` at offset 8, `58 00` at 4–5 and 10–11, `00 03` at
12–13, `ff 00` at 16–17, `01 00` at 20–21, and a 30-entry `u16` ramp at 28…87 ending in
`eb eb eb`. Nothing in libdrc, Barista or wozt parses it (`services.rst:23` literally says
`:doc:`???``; `GROUND-TRUTH-SESSION.md:118-122,214` marks it unknown).

Hypotheses worth one probe each, all cheap because the pad asks for nothing back:

| H | Reading | Probe |
|---|---|---|
| H1 | a *table of counters/statistics* (the ramp looks like exponentials/percentages) | change magic only → if the pad rejects the whole datagram, the magic is checked |
| H2 | a **header + fixed array** where offset 6 is an index/count (it increments once per datagram!) | set offset 6 = 0xFFFF, then 0, then 1 with everything else console-exact |
| H3 | a **length field** (`58 00` = 88 = 96−8, appearing twice) | set both `58` bytes to `ff` |
| H4 | i2c/LCD timing parameters (it starts exactly with video) | perturb the ramp |

**Observability:** nothing on the pad's side is expected; the signals are (i) does the pad still
accept/act on the other planes (input rate, resync rate), (ii) `svc 4/0x05` index, (iii) panel
behaviour (only via backlight/`0x1a` reads). This is a *discovery* experiment, not an exploit path —
include it once, in the background, at 1/s while other work runs.

### 4.7 The `msg` service on 50110 — an entirely unmodelled parser

`services.rst:39-44`: 50010/50110 is "Message protocol (broadcast)", DRH-only, and the pad both
sends and receives. `sc-msg.rst` is a stub (`TODO`). VERIFIED: the pad sends exactly one shape,
`01 00 00 00` (4 B) from source port 50110 to our 50010, three times per session.

So the pad runs a UDP server on **50110** that parses a protocol no document and no reference
implementation in this tree describes. We can send it anything: unicast, multicast, broadcast,
any length. Nothing about its parser is constrained by evidence — which is exactly why it is worth
a bounded structured probe:

1. `01 00 00 00` (its own message) → baseline; does it respond, or change anything?
2. `00 00 00 00`, `02 00 00 00` (opcode sweep on byte 0, 1 byte and 4 bytes).
3. lengths 0, 1, 2, 4, 8, 16, 64, 128, 256, 512, 1024, 1472 with zeros.
4. If any response appears, follow it; a *reply* would reveal a reply format, and echo/reflection
   would be a first oracle.

**Value:** unknown but potentially large (an inter-pad message protocol carries text/handles and is
where GamePad-to-GamePad features live). **Cost:** low. **Risk:** low (a service that also handles
broadcast must tolerate junk by design).

### 4.8 DHCP: we are the server, the pad's client parses our options

The pad's client is DOC-standard (`wifi.rst`, `BOOT-AND-MODES.md:93`) and **runs on the LVC's own
IP stack** (`nwk` manager, `overview.rst:139`) — i.e. a DHCP bug here lands on the ARM9, not the
radio. VERIFIED request shape (§2.5): 300-B datagrams, `chaddr 40:d2:8a:17:e2:09`, param list
`01 03 06 33 3a 3b` = subnet, router, DNS, **lease 51, T1 58, T2 59**. No hostname, no vendor class.

Classic embedded-client overflow shapes, all within our gift as the server:

| # | Our reply field | Shape it triggers |
|---|---|---|
| D1 | option 3 (router) with length 8 / 255 instead of 4 | fixed 4-byte destination; a client that copies `len` bytes into it overflows |
| D2 | option 6 (DNS) with length 255 (63 addresses) | fixed `MAX_DNS` array (often 2–3 entries) |
| D3 | option 1 with length ≠ 4; option 28 with length ≠ 4 | short *or* long read |
| D4 | option 51/58/59 with length 1, 2, 8 or 255 | 4-byte read from 1 byte (OOB read) or truncation to a small lease |
| D5 | option 12 (hostname) / 15 (domain) / 60 / 43, length 255 with no NUL | `strcpy` into a 32/64-byte buffer |
| D6 | option 52 (overload) pointing at `file`/`sname` | makes the client re-parse `sname`/`file` as options — the classic recursive-parse bug |
| D7 | no option 255; an option whose length runs past the datagram end; `sname`/`file` not NUL-terminated | length-vs-packet overrun |
| D8 | `hlen = 16` with 16 bytes of `chaddr` | client copies `hlen` bytes into a 6-byte `MACAddress` |
| D9 | duplicated options in one reply, order swapped | first-wins vs last-wins inconsistency; can desync the pad's own state vs what our netboot thinks it assigned |
| D10 | `yiaddr` = 0.0.0.0 / 255.255.255.255 / 127.0.0.1, `siaddr`/`giaddr` odd | state confusion: which address does the pad bind? (recoverable, observable) |

**Observability is excellent and unique**: the pad either gets `.11` (input + cmd planes appear,
`run/_wait-for-pad.sh` semantics) or it does not, and it retries by itself. So a DHCP experiment is
**self-healing** — the safest high-value test we have. The harness signal is "did the pad reach
192.168.1.11 within N s", plus our netboot log.

**Recovery:** restore a good reply; the pad re-DISCOVERs. No persistent state is touched (unless the
pad wrote a bad lease to its own settings — re-pairing fixes it).

### 4.9 The 802.11 layer (BCM4319 Cortex-M3) — and why it ranks lower

We are the authenticator, so we build EAPOL and beacons. What parses them:

* `overview.rst:43-54` — the BCM4319 "runs a fairly standard Broadcom SDIO chip firmware with very
  slight alterations from Nintendo … on a Cortex-M3". The Nintendo alterations are the
  `a4:c0:e1` selectors and the **3-byte PTK/KDK rotation** (`README.DRC`; live patch
  `research/drc-hostap/src/wps/wps_common.c:114-122`; selectors
  `src/common/wpa_common.h:50-54,76-82`). A *modified* supplicant means a code path Nintendo
  touched, which is a legitimate place to look.
* Everything in the RSN IE / WPS IE / EAPOL key-data / KDE / ADDBA / BlockAck space is therefore
  parsed **on the radio**, not on the LVC. Compromise there gives Wi-Fi-side control (and possibly
  the SDIO path toward the LVC, `overview.rst:33-37`), but it does **not** give the framebuffer.

Candidate shapes (all cheap to send, all hard to observe):

| # | Frame | Shape |
|---|---|---|
| R1 | EAPOL msg 3 key-data | KDE with a GTK length that disagrees with the AES-wrap; extra/duplicate `dd 16 00 0f ac 01` KDEs; a key-data blob that unwraps to a malformed RSN IE (the pad *does* parse this: `GROUND-TRUTH-SESSION.md:127-137` shows our rotated KEK unwraps the console's key data) |
| R2 | msg 1/2 replay counters, key-info bits | a replayed msg1 with a fresh ANonce → does the pad rekey/re-derive without a state check? |
| R3 | beacon/probe-resp IEs | duplicated or oversized IEs; RSN IE with pairwise/group counts running past the IE; an HT-capabilities IE with impossible values; vendor IE `dd 09 00 10 18 02 00 00 04 00 00` (we already send it, `run/wiiu_ap_normal.conf.template`) plus a second, contradictory one |
| R4 | WPS | we were the registrar at pairing (`conf/wiiu_ap_pairing.conf`: `wps_state=2`, `config_methods=label push_button`, `device_type=6-a4c0e1f4-1`) → M1…M8 with attacker-controlled attributes, or an over-long `vendor extension` |
| R5 | ADDBA / BlockAck | request a buffer size larger than the pad's, or send a BlockAck whose bitmap length disagrees with the negotiation |
| R6 | CSA / channel-switch, deauth reason codes | state confusion (we already see reason 8 leaves, `run/wiiu_ap_normal.conf.template:18-21`) |

**Rank:** one experiment (R1/R3 combined, done as an IE/attribute fuzz that never breaks the
handshake) is worth scheduling after the LVC-side work, with the explicit expectation that a crash
there appears as *association failure*, not as a pad reset.

### 4.10 The input plane (50122→50022) and what we can drive

We receive; the UIC generates. The documented blob is fixed at 128 B (`sc-input.rst:10-43`,
VERIFIED 48,760 records of exactly 128 B). Two levers, both indirect:

* **Our replies drive the pad's state machine.** `sc-cmd.rst:25`: "Until a ACK is received,
  DRH/DRC will retry sending." So the pad retransmits its replies when we withhold type-3 ACKs. A
  withheld-ACK storm is a *rate amplifier* on the pad's cmd manager — cheap to try, and useful as a
  fault-injection primitive alongside §4.1 M11.
* **The pad's input path is not a parser we own** — but its *send cadence* is the best liveness
  metric we have (163/s VERIFIED), and a `seq` reset is a pad reboot (2 resets in the capture).

---

## 5. Ranked candidate list

Score = **likelihood of real corruption** (L, 1–5) × **value toward code execution / LCD control**
(V, 1–5). Likelihood is judged from: is there a length/index field, is it single-byte or wide, is
there evidence the pad trusts it, is the handler derived from a 2013 vendor codebase (eLua-eForce
style "assert + memcpy" idiom is DOC in `overview.rst:81-83`).

| Rank | ID | Candidate | L | V | Score | Plane | Conf |
|---:|---|---|---:|---:|---:|---|---|
| 1 | **V1/V2** | VSTRM `payload_size` over-claim / over-delivery past the measured 1694–1700 edge | 4 | 5 | **20** | video | INFERRED (edge is measured) |
| 2 | **V3/V4** | VSTRM `NumMbRowsInChunk`=255/0 and `force-decode` geometry | 3 | 5 | **15** | video | SPECULATIVE→INFERRED |
| 3 | **M3/M4** | cmd fragment `payload_size`/`fid` over-claim → reassembly overflow or OOB read leaked in a reply | 3 | 5 | **15** | cmd | INFERRED |
| 4 | **F1** | `svc 0/0x03` update block with unbounded `block_idx` | 3 | 5 | **15** | cmd | INFERRED |
| 5 | **E1** | `svc 0/0x0a` index 5…255 (documented 0..4) → OOB read in reply | 4 | 3 | **12** | cmd | INFERRED |
| 6 | **E2** | `svc 5/0x0c` UIC EEPROM write with `index`/`length` byte at 255 | 3 | 4 | **12** | cmd→UIC | INFERRED (one known-valid tuple) |
| 7 | **D1–D8** | DHCP reply option lengths / `hlen` / overload | 3 | 4 | **12** | DHCP (LVC) | INFERRED |
| 8 | **I1** | `svc 5/0x11` IRCOM 520 B and `svc 5/0x10` ICTAG 531 B | 3 | 4 | **12** | cmd→ir/ictag | SPECULATIVE |
| 9 | **T1** | 50125 96-byte table mutation (index/length/magic/ramp) | 2 | 4 | **8** | unknown | SPECULATIVE |
| 10 | **G1** | 50110 `msg` service structured fuzz | 2 | 4 | **8** | msg | SPECULATIVE |
| 11 | **R1/R3** | EAPOL key-data KDE + beacon IE abuse | 2 | 4 | **8** | radio (M3) | SPECULATIVE |
| 12 | **E3** | `svc 3/0x03..0x06` selector byte, `svc 0/0x09`, `svc 4/0x0a/0x0b/0x19` selectors | 3 | 2 | **6** | cmd (readers) | INFERRED |
| 13 | **A1/A2** | ASTRM declared length 0/0xFFFF vs 1664 real bytes | 2 | 3 | **6** | audio | INFERRED (format msg suggests length is ignored) |
| 14 | **L1** | `svc 5/0x19` LCD i2c 13 B register sweep | 2 | 3 | **6** | panel (i2c) | SPECULATIVE |
| 15 | **M11** | ACK/seq state-machine abuse, retransmit storm, tid reuse | 2 | 2 | **4** | cmd | INFERRED |
| 16 | **X1** | `svc 4/0x01`/`0x1a`/UVC `f3` mode confusion (vWii, shutdown, unknown values) | 1 | 2 | **2** | state | DOC |

**Honest reading of this table.** Nothing here is a confirmed bug. Three of the top four are
"length/index trusted" hypotheses on fields whose *values* the console itself sets to a
documented maximum (1028 for a cmd payload, 1694 for a video chunk, 531/520/258 for the UIC
methods) — which is exactly the pattern that produces these bugs in embedded code, and exactly the
pattern that is *cheap to falsify*: the first three experiments in §8 either leak memory in a reply
or leave the pad silent, and both outcomes are informative.

---

## 6. Observability: how we see a bug without seeing the screen

The operator cannot watch the panel during a fuzz run, so the harness must be the eyes. Signals,
their normal values, and what each one means:

| # | Signal | Acquisition | Normal (this pad) | Deviation means |
|---|---|---|---|---|
| O1 | **input rate** | count 128-B datagrams on 50122 during 1 s | ~163/s (VERIFIED) | <100/s = pad busy/resetting; 0 = dead or off-session |
| O2 | **input `seq` continuity** | u16 LE at blob[0:2] | monotonic | **reset ⇒ pad rebooted** (2 resets seen, = 3 sessions) |
| O3 | **input `fw_version_neg`** | blob[127] | `0xD7` (VERIFIED) | change ⇒ different LVC image is running (i.e. an update landed) |
| O4 | **cmd ACK completeness** | (type-1 ACKs) / (type-0 queries) per 5 s | 1.0 (VERIFIED: 1,475 queries, ACKed each) | <1.0 ⇒ cmd manager wedged/faulted |
| O5 | **reply latency & seq** | per-seq RTT | ~1 ms | timeout ⇒ handler hung |
| O6 | **resync rate** | `01 00 00 00` from pad 50110 | 0 steady; 3/300 s at session start (VERIFIED) | >5/s = decoder failing (our stack today: ~63/s) |
| O7 | **state index** | `svc 4/0x05` reply byte | 0 = its own notice screen (`BOOT-AND-MODES.md:186`) | index change ⇒ mode change (map it) |
| O8 | **LVC version** | `svc 0/0x00` (8 B) | 385,944,601 (`19 0c 01 17`) | change ⇒ **a different firmware is running** (update landed / rollback) |
| O9 | **UIC EEPROM digest** | `svc 5/0x06`, sha256 of the 768-B blob | stable per pad | change ⇒ our `svc 5/0x0c` write landed (`WiiUccfb65b68169` + PSK live at the front) |
| O10 | **brightness** | `svc 5/0x15` | 4 (we set it) | 0/other ⇒ panel state changed |
| O11 | **reachability** | ICMP to 192.168.1.11 | reply (`pad-state` oracle: "reachable by ICMP") | loss ⇒ LVC wedge while the radio still associates |
| O12 | **association events** | hostapd log (`logger_stdout`), deauth/disassoc reason | reason 8 leaves happen (~1/min, `wiiu_ap_normal.conf.template:18-21`) | new reason codes / re-assoc storm |
| O13 | **DHCP retry** | our netboot log | one DISCOVER/REQUEST per boot | retry loop ⇒ the pad rejected our server/reply |
| O14 | **reply contents** | diff `svc 0/0x0a`, `svc 5/0x06`, `svc 3/*` replies across mutations | deterministic | **changed contents = the length/index was read from a different place — that is the leak** |
| O15 | **pad's own reports** | query-type-1 UVC/UAC reply (24 B) | 3 distinct bodies observed (VERIFIED) | change ⇒ camera/mic state changed |

Harness rules that follow from the above:

* **Tick every 5 s**: O7, O8, O10, O11. **Every 1 s**: O1, O4, O6. **On any O2 reset**: log and
  stop the current mutation series (one stimulus at a time, or attribution is lost).
* **A mutation series is exactly one field**, stepped through a fixed value list, ≥3 datagrams per
  value, with a 10 s clean-stream gap between values. Otherwise a crash cannot be attributed.
* Keep `svc 4/0x05` and `svc 5/0x15` probes on a **separate** cmd socket and note that the pad
  answers to `…:50023` regardless of our source port (`BOOT-AND-MODES.md:192-200`) — so the probe
  can run beside the fuzzer as long as each keeps its own `seq` space.

---

## 7. Safety and recovery ladder

Ordered by blast radius; the ladder is also the scheduling constraint for §8.

| Level | Stimulus class | Persistence | Recovery |
|---|---|---|---|
| **S0** | read-only queries (`svc 4/0x05`, `0/0x00`, `5/0x06`, `5/0x15`, `3/*`, `0/0x0a`) | none | none needed |
| **S1** | malformed media datagrams, fragment abuse, DHСP reply abuse, 50110/50125 junk | session-only | stop the stimulus; svc 4/0x01 payload `00` = back to normal mode (DOC); if the pad is wedged, hold the power button |
| **S2** | `svc 5/0x0c` (UIC EEPROM), `svc 5/0x18` (remocon IDs), `svc 0/0x0b/0x0d/0x0f` | **persistent** (settings/language/tv-code) | rewrite the saved 768-B dump (O9 gives you the original); worst case: re-pair via WPS (`conf/wiiu_ap_pairing.conf`) |
| **S3** | `svc 0/0x02/0x03/0x04` (product update) | **persistent, potentially unrecoverable** | `0x05` abort *before* `0x04`; never `0x04` until `0x03` semantics are known; a bad image = the pad may not boot the LVC |

Two hard rules for the harness:

1. **Never send `svc 0/0x04` (end product update) unless the previous experiment was a plain
   `0x02`→`0x05` abort.** `0x04` is the commit; there is no documented rollback
   (`sc-cmd.rst:119-126`), and `boot.rst:57-68` shows the SPL will happily boot whichever volume
   the flash version byte selects.
2. **Snapshot before S2/S3**: `svc 5/0x06` (768-B EEPROM), `svc 4/0x04` (28-B version block),
   `svc 0/0x00` (running/installed), `svc 1/0x05` (SSID/PSK/auth/enc), plus the hostapd config that
   currently works. Store them with the run log so a later run can prove what changed.

---

## 8. Top-10 experiments, in the order a live harness should run them

Each experiment is one field, one value list, one observable, and an explicit "what falsifies it".
Builders: `research/rce-hunt/tools/make_cmd.py` (already reproduces console bytes exactly —
`selftest`). All cmd hex below is **the complete UDP payload** to send from `192.168.1.10:50023` to
`192.168.1.11:50123`; `seq` increments per logical request.

### E1 — `svc 0/0x0a` index sweep (safe, 5 minutes, highest information per risk)

```
in-range control : 0000 0000 0d00 aa00 7e01 0008 0040 000a 0000 0001 00
                   ^outer: type0 q0 len13 seq=0x00aa                        ^payload: index 0
sweep            : same, last byte = 01,02,03,04 (documented) then 05..FF (OOB)
```
Full bytes for index 5 and 0xFF (from `make_cmd.py`):
`000000000d000201 7e0100080040000a0000000105` and `000000000d000101 7e0100080040000a00000001ff`.
*Watch:* reply body (4 B) per index; a reply for 5…255 that is non-zero and not an error is an
OOB read. *Falsified if:* every index ≥5 returns `error≠0` or the same constant value.
*Why first:* read-only, one datagram per index, 256 datagrams total, and the answer (leak vs
bounds check) also tells us how the whole `svc 0` reader family is written.

### E2 — `svc 3/*` and other 1-byte selectors, same sweep (safe, 5 minutes)

`svc 3/0x03` (phy_stats, 13-B reply), `3/0x04` (pkt_stats, 152 B), `3/0x05` (wmm_stats, 448 B),
`3/0x06` (RSSI, 2 B), `0/0x09`, `4/0x0a`, `4/0x0b`, `5/0x16` — each with selector 0x00…0xFF.
Example: `00000000 0d00 bb00 7e01 0008 0040 0305 0000 0001 ff` (`svc 3/0x05` selector 0xFF).
*Watch:* **reply length and content changes**, plus O1/O4. A 448-byte reply that suddenly contains
non-zero bytes where the console's were zero is a leak.

### E3 — media length-trust probes (safe to the pad's flash, directly aimed at the video path)

Run inside a known-good stream (`run/04-stream.sh`), one datagram per probe, 10 s apart:

| Step | Datagram change | Expect if the length is trusted |
|---|---|---|
| E3a (calibration) | format message (50121, 32 B) with bytes 2–3 = `00 18` instead of `00 00` | nothing (already proven tolerated, §3.2) → confirms the harness is sane |
| E3b | one VSTRM datagram: `b2=0x0e` (no flags, ts, len hi=6), `b3=0x9e` (1694) but only 20 B sent | resync spike / silence |
| E3c | same but `b3=0x9f…0xff` + `b2` len hi = 7 (1695…2047) with 20 B sent | the pad reads past its buffer; the boundary where behaviour changes *is* the buffer edge |
| E3d | one datagram with 1700 real bytes (len 1700 = `06 a4`) | wozt measured "stops decoding outright" at 1700 → replicate, then bisect 1695…1700 |
| E3e | 4 KB datagram (len 0x7FF, real 4080 B) | if the pad accepts >MTU-sized chunks, the reassembly buffer is bigger than assumed |

*Watch:* O6 (resync rate) is the primary signal; O1/O2 for a reset. *Recovery:* stop the probe,
the stream continues.

### E4 — VSTRM geometry: `NumMbRowsInChunk` and `force-decode` (LCD path)

Mutate bytes 8–15 of a P-frame packet, one variant at a time:
`82 00 83 85 06 00 00 00` (console) → `82 00 83 85 **FF** 00 00 00`, → `…85 **00** …`, → `…85 **01** …`,
→ `**83** 82 00 85 06 00 00 00` alone, → omit `0x85` entirely, → `84` (unset force) mid-frame.
*Watch:* O6, O1, O7. *Interpretation:* a geometry bug shows as immediate decoder death (resync
storm) with the pad otherwise alive; a *framebuffer* overrun shows as a pad reset (O2) or a
re-association (O12). *Falsified if:* all variants look exactly like the console's own options.

### E5 — cmd fragment reassembly (write/read at a chosen offset)

Series A (over-claim, OOB read): one 1048-B-shaped message where each of 3 fragments delivers 20 B
but declares 1028:
```
f0: 00000000 2000 cc00 7e01 0200 0042 0011 0000 0404 00000001 0000000000000000000000000000
f1: 00000000 2000 cd00 7e01 0201 0042 0011 0000 0404 00000002 …(20 B total each)
f2: 00000000 2000 ce00 7e01 0202 0840 0011 0000 0404 00000003 …
```
Series B (unbounded length): `fid` 0…0x7FF with FIN only on the last, each declaring 1028 →
`0x800 × 0x404` ≈ 2.06 MB of claimed message.
Series C (goofy order/repeats): `fid` 3,0,1,2 / 0,0,0,0 / FIN on fid 0 then `fid 1` again.
Series D (tid confusion): open a message as `svc 0/0x11` and land its last fragment with
`svc 0/0x03` (firmware data) using the same tid.
*Watch:* O4 (ACK loss is the first symptom of a wedged cmd manager), O7, O2 — then verify the pad
still answers `svc 4/0x05`. If a reply's *content* changes for a read method, we have a leak.

### E6 — `svc 5/0x0c` UIC EEPROM write (persistent; run with the digest oracle armed)

```
snapshot : 00000000 0c00 d000 7e01 0008 0040 0506 0000 0000          (svc5/0x06 → 772-B dump)
replay   : 00000000 1100 d100 7e01 0008 0040 050c 0000 0005 130302952c   (console's own write)
var 1    : index 0xFF, length 0x03, data 02 95 2c                       (index out of range)
var 2    : index 0x13, length 0xFF, 255 B of 0x00                        (length out of range)
var 3    : index 0x13, length 0xFF, 3 valid bytes then 252 B of 0x41     (copy past the staging area)
after    : 00000000 0c00 d200 7e01 0008 0040 0506 0000 0000          (dump again, diff)
```
*Watch:* the diff. A changed dump proves the write path accepts our bytes; **no diff** means the
CRC was rejected (then the remaining question is whether we can forge it — we have exactly one
valid `(index,length,data,crc)` tuple to learn from).
*Recovery:* write the original bytes back at the original index. **Do not run var 2/3 before var 1
and the dump-diff have been characterised**, because settings corruption can break Wi-Fi pairing.

### E7 — firmware-update gate, in the least destructive order

```
a) 00000000 1000 e000 7e01 0008 0040 0002 0000 0004 00000000     svc0/0x02 start, product 0
b) 00000000 0c00 e100 7e01 0008 0040 0005 0000 0000              svc0/0x05 abort
```
If (a) returns `error=0` *and* a subsequent `svc 0/0x00` still reports the same LVC version, then
and only then:
```
c) 00000000 1004 e200 7e01 0008 0040 0003 0000 0404 00000000 + 1024×00   block 0, 1028 B
d) same with block_idx = 1, 2, 0x7FFFFFFF, 0xFFFFFFFF                     (bounds probe)
e) 00000000 0c00 e300 7e01 0008 0040 0005 0000 0000              abort again
```
*Watch:* each `0x03` replies 4 B — the value is a status/offset and is the primary oracle; then
O8 (version unchanged = the block went nowhere durable) and O3.
*Never* send `0x04` in this series. **Falsified if (a) errors** → the update path is gated on
something we do not control, and the whole F1 candidate drops to zero.

### E8 — DHCP reply abuse (self-healing; independent of the running stack)

Serve, per boot, one malformed OFFER/ACK and watch whether `.11` still arrives:
1. option 6 with 255 B (63 DNS entries), 2. option 3 with 8 B, 3. option 1 with 1 B,
4. option 51/58/59 with 1 B and with 8 B, 5. option 15 with 255 B of `'A'`, 6. option 52 = 3
(`file`+`sname`) with a fake option list in `file`, 7. `hlen=16` + 16-byte `chaddr`, 8. no `0xFF`,
9. an option length that runs past the datagram end, 10. duplicated options 3/6 in both orders.
*Watch:* O13 (retry loop), O1 (input appears), O11. *Recovery:* serve a correct reply; the pad
retries within seconds. **This is the only high-value experiment whose failure mode is self-healing.**

### E9 — undocumented parsers, structured fuzz at 1/s (background)

50125 (96 B): variant per second — `magic 5a a5` → `00 00`; offset 6 = `FF FF`, `00 00`, `00 01`;
`58 00` fields → `FF FF`; ramp entries → `FF FF`; whole datagram zeros; 96 → 95/97 B.
50110 (`msg`): `01 00 00 00` baseline, then opcode sweep on byte 0 (00…05), then lengths
0/1/2/4/8/16/64/256/1024/1472 with zeros, then the same with `5a a5`/`80`-style prefixes.
*Watch:* O1/O2/O6 — everything, since we have no model of either parser; plus any *reply* the pad
sends to 50110 (that would be the first new fact about the message protocol).

### E10 — 802.11 IE / EAPOL key-data abuse (radio-side; one session, non-destructive)

Order within one association: (a) a beacon with the vendor IE duplicated 4×, (b) RSN IE with
pairwise count = 3 (only one suite present), (c) HT capabilities with an impossible MCS set length,
(d) EAPOL msg3 with the GTK KDE length field inconsistent with the wrap, (e) a WPS M8 with an
over-long vendor extension during a *test* enrolment.
*Watch:* association success (the handshake is the signal), O12 reason codes, and whether the pad
retries the 4-way. **Falsified if** every variant associates normally — which is the expected
outcome for hardened Broadcom firmware, and the reason this ranks last.

---

## 9. Appendix A — byte templates (copy-paste)

Outer + generic for `svc S / method M`, payload `P` (len `L ≤ 1028`), `seq Q`, `tid T`, `fid F`,
final `FIN`, flags `0x40|0x42`:

```
00 00 | 00 00 | (L+12)LE16 | Q LE16          # CmdHeader: type0, query0
7E 01 | T[11:8] | (T[7:4]<<4)|(FIN?8:0)|F[10:8] | F[7:0] | FLAGS | S | M | 00 00 | L BE16 | P…
```

Worked examples (VERIFIED against the console's own capture by `make_cmd.py selftest`):

| Purpose | Exact bytes |
|---|---|
| console `svc0/0x00` | `000000000c0009007e0101580040000000000000` |
| console `svc5/0x0c` EEPROM write | `0000000011000d007e0101980040050c00000005130302952c` |
| console `svc0/0x10` 32-B payload | `000000002c000e007e0101a80040001000000020` + `000c2934` + 28×`00` |
| console `svc0/0x11` fragment #1 (1048 B) | reproduces `out/evidence/truth/console-messages/cmd_t0_q0_len1040.bin` byte-for-byte |
| `svc0/0x0a` index 0xFF (OOB read) | `000000000d0001017e0100080040000a00000001ff` |
| `svc3/0x05` selector 0xFF | `000000000d0004017e0100080040030500000001ff` |
| `svc5/0x06` EEPROM dump request | `000000000c0009017e0100080040050600000000` |
| `svc0/0x02` start update, product 0 | `0000000010000a017e010008004000020000000400000000` |
| `svc4/0x01` payload 00 → normal mode | `000000000d000e017e010008004004010000000100` |
| over-claim fragment (declared 1028, 20 B sent, more-follows) | `00000000200012017e010200004200110000040400000001` + 16×`00` |
| `fid=0x7FF`, final, declared 1028 | `00000000200015017e01021fff4000110000040400000001` + 16×`00` |

Reply parsing for the harness (`run/pad-state.py:79-95` already does this): outer type 2 → `svc =
p[14]`, `method = p[15]`, `error = be16(p[16:18])`, `body_len = be16(p[18:20])`, body at `p[20:]`;
**always ACK with a bare 8-B type-3 packet** (`03 00 | qtype | 00 00 | seq`) or the pad retransmits.

## 10. Appendix B — what each plane would buy if it falls

| Plane | Best realistic outcome | Effect on the objective (LCD control) |
|---|---|---|
| `vstrm` length/geometry | decoder or reassembly write with partially controlled bytes | **direct**: the framebuffer and `drvldc` are downstream; also the first place a working stream's state can be perturbed |
| `cmd` reassembly / `svc 0/0x03` | heap/BSS overflow in cmdmgr/nvram | **direct**: `svc 4/0x01` mode changes, `svc 5/0x08/0x14/0x19` panel commands, and the flash image are all reachable from the same process family |
| `svc 5/0x0c`, `0x18`, `0x0b/0x0d/0x0f` | persistent settings corruption or a UIC-side overflow | indirect but persistent: language/brightness/PSK/TV-code state; a corrupted UIC EEPROM can wedge boot behaviour |
| `svc 5/0x11`, `0x10` | a real protocol stack (IR / NFC) overflow | high value, low evidence: needs the NFC/IR session to be armed at all |
| readers (`svc 0/0x0a`, `3/*`) | memory disclosure in a reply | enables everything else (addresses, layout) but changes nothing by itself |
| DHCP | client overflow **before** any other plane exists | total: code runs at boot, before the pad trusts anything else |
| 50125 / 50110 | unknown parser | unknown; the only planes with no model at all |
| 802.11 (M3) | radio-side compromise | does not reach the framebuffer; enables durable MITM/analysis instead |

## 11. Evidence index and reproducibility

| Artefact | What it is |
|---|---|
| `research/rce-hunt/tools/make_cmd.py` | cmd builder; `selftest` reproduces 4 console datagrams byte-for-byte, including a full 1048-B fragment |
| `research/rce-hunt/tools/cmd_scan.py` | independent decoder for `port50123.bin` / `port50023.bin` (record frame `>d 4s 4s I`) |
| `research/rce-hunt/tools/parse_truth.py` | full per-plane decoder for every file in `out/evidence/truth/` (companion agent) |
| `research/rce-hunt/00-truth-evidence-notes.md` | per-plane measured tables (companion agent) |
| `research/rce-hunt/01-parser-code-notes.md`, `05-pad-parsers-in-code.md` | code-level audit of libdrc / wozt / Barista / local fork, and every pad-tolerance comment found (companion agent) |
| `out/evidence/truth/*.bin` | decrypted real console session (VERIFIED source for every §2 number) |
| `out/evidence/pad-state/2026-11-04-oracle.md` | live pad replies: state 0, LVC 385944601, SSID/PSK, brightness 4 |
| `SETUP.md` rounds 11j–11p, 12 | live-hardware history: init flag, service-5 panel sweep, the 1048-B replay, the capture |
| `research/BOOT-AND-MODES.md`, `GROUND-TRUTH-SESSION.md`, `CODEC-SPEC.md` | prior synthesis (with the four corrections in §2) |
