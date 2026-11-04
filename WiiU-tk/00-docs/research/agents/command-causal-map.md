# Command-channel causal map — what arms the pad's video path

Goal: identify the command (or ordered sequence) that moves the pad from "associated +
ACKing commands, painting its own UI" to "armed, consuming console video". Sources:
`research/libdrc/web/docs/re/sc-cmd.rst` (cited `L<n>`), decrypted console session
`out/evidence/truth/port50123.bin` (measured; "console?" column below), and
`research/BOOT-AND-MODES.md` / `research/GROUND-TRUTH-SESSION.md`. `payload→reply` is bytes.

## 1. Documented UIC/UVC/AV method inventory

**Service 5 — display/AV/UIC (sc-cmd.rst L215–261).**

| m    | payload→reply | documented claim (sc-cmd.rst) | console? |
|------|---------------|-------------------------------|----------|
| 0x00 | 0→?     | 6-byte value from UIC table @f8d0 via UIC cmd 0x0a (L223)        | no |
| 0x01 | 1→0     | sensor bar GPIO enable(01)/disable(00) (L225)                    | no |
| 0x02 | 102→?   | push 102 B to UIC via cmd 0x0c; `u16,u16,{u8,u8,u8}[32],u16` (L227) | **YES ×1 t=58.5** |
| 0x06 | 0→772   | UIC fw version + first 768 B UIC EEPROM (L229)                   | **YES ×5** |
| 0x08 | 1→?     | sent when display off (Home menu); **00 DISABLES video** (L231)   | no (never) |
| 0x0a | 1→?     | sent when display off; 00 disables sound (L233)                  | no |
| 0x0b | 0→1     | unknown, returns -1 or 0 (L235)                                  | no |
| 0x0c | 258→?   | UIC EEPROM update: `idx,len,data+crc[]` (L237)                   | **YES ×2 (5 B)** |
| 0x0e | 5→?     | unknown (L239)                                                   | no |
| 0x0f | 0→?     | unknown (L241)                                                   | no |
| 0x10 | 531→?   | ICTAG/NFC command (L243)                                         | no |
| 0x11 | ≤520→≤520 | IRCOM: 0=connect,1=send,2=receive,3=disconnect (L245)          | no |
| 0x14 | 1→0     | set LCD brightness 1(min)…5(max) (L248)                          | no (ours 1/s) |
| 0x15 | 0→1     | get current LCD brightness (L250)                                | no |
| 0x16 | 1→?     | IRCOM related, 0 or -1 (L252)                                    | no |
| 0x17 | 7→?     | send TV command, first 5 B = remocon ID (L254)                   | no |
| 0x18 | 10→?    | set two remocon IDs (L256)                                       | no |
| 0x19 | 13→?    | set LCD params via i2c to LCD controller (L258)                  | no |
| 0x1a | 0→13    | get LCD params via i2c (L260)                                    | no |

**Service 4 — power/state (sc-cmd.rst L185–213).**

| m    | payload→reply | documented claim (sc-cmd.rst) | console? |
|------|---------------|-------------------------------|----------|
| 0x01 | 1→?     | reboot/shutdown: 0 norm, 2 fw-update, 4/6 off (L191)   | no |
| 0x04 | 0→28    | get version info (L194)                                 | **YES ×3** |
| 0x05 | 0→1     | state index `retvals[current_state]`, `retvals={0,10,4,5,6,1,2,3,9,7,8,11}` (L196) | **YES ×1** |
| 0x08 | 4→?     | unknown (L200)                                          | no |
| 0x09 | 0→4     | unknown (L202)                                          | no |
| 0x0a | 1→?     | unknown (L204)                                          | no |
| 0x0b | 0→1     | unknown (L206)                                          | no |
| 0x14 | 4→?     | unknown (L208)                                          | no |
| 0x19 | 0→12    | unknown (L210)                                          | no |
| 0x1a | 0→?     | "shuts down the GamePad if flags=0x42" (L212)           | **YES ×1 flags 0x42** |

**Service 0 — firmware (sc-cmd.rst L105–141) — only what matters here.**

| m    | payload→reply | claim | console? |
|------|---------------|-------|----------|
| 0x00 | 0→8     | get LVC firmware version (running, installed) (L115) | **YES ×3** |
| 0x10 | 32→0    | undocumented (table ends 0x0f); one-off t=0.21 | **YES ×1** |
| 0x11 | 1028→4  | undocumented; state blob, BE u32 index 1…779, `M M M S` | **YES ×779 (first 28 s)** |
| 0x12 | 32→4    | undocumented; terminator, BE u32 `0x30b`=779 + 28 zeros | **YES ×1 t=27.99** |

**UVC/UAC (query type 1, sc-cmd.rst L263–308) and Time (query type 2, L310–325).**

| item | claim |
|------|-------|
| `UvcUacCommand` (48 B) | `f1, unknown_0, f3, mic_enable/mute/volume/freq, cam_enable/power/freq/auto_expo/expo_absolute/brightness/contrast/gain/hue/saturation/sharpness/gamma/key_frame/white_balance_auto/white_balance/multiplier/multiplier_limit` (L270–300) |
| gate | "issued every second… recent firmware will only show the video stream after receiving one such command" (L304–305) |
| `f3` | 1 = vWii mode, 3 = shut down (L307–308) |
| `TimeCommand` (8 B) | `days_counter, padding, seconds_counter`; "sent when a DRC connects" (L310–325) |

## 2. Measured console usage (port50123.bin, 1475 dgrams)

Generic cmds: `0/0x00 ×3` (t 0.02/58.3/72.4), `4/0x04 ×3` (same ts), `5/0x06 ×5` (t 0.02/58.85/64.05/65.59/72.44),
`4/0x05 ×1`, `0/0x10 ×1`, `0/0x11 ×779` (t 0.22–26.97), `0/0x12 ×1` (t 27.99), `4/0x21 ×1` (t 28.41, 32 zero B),
`4/0x1a ×1` (t 28.56, flags 0x42, 0 B), `5/0x02 ×1` (t 58.50, **102 zero B**), `5/0x0c ×2` (5 B).
Query type 2 (time) ×4 queries (t 0/53.4/58.3/72.4). Query type 1 UVC/UAC ×228 queries
(t 69.3→298.7, ~1/s; byte[0] `00`→`01` after first reply). Type-3 acks: 213 generic + 228 UVC +
4 time = 445 (8 B each, seq echoed). Video starts t=61.0, audio t=56.8. (Sum: 798 generic +
456 UVC + 8 time + 213 generic-acks = 1475.)
Key: **5/0x02 at t=58.5 (2.5 s before video)** is the only service-5 command carrying a config
payload besides the 5/0x0c EEPROM writes and 5/0x06 reads; the console **never** sends 5/0x08
(enable/disable), 5/0x0a, 5/0x14, or any 0x19/0x1a LCD i2c cmd.

## 3. Ranked hypotheses (exact bytes)

Wire = `build_generic(svc, meth, payload, flags=…)`; outer seq/tid are regenerated per run.
MEASURED: the pre-video "arm burst" (`0/0x00, 4/0x04, 5/0x02, 5/0x06`) moves state **12→0**
(Quick Start Menu → session/connecting) and stops `0/0x11` replies returning error 9004.

**H1 — svc 5/0x02, 102-byte zero payload (highest).**
`build_generic(5, 0x02, b"\x00"*102)`. Only service-5 cmd in the whole session, appears 2.5 s
before video, inside the measured arm burst. Docs say it pushes a UIC config block
(`u16,u16,{u8,u8,u8}[32],u16`) — the console's is all-zero = reset/default AV config. This is
the single strongest arm candidate; but the measured arm burst is the *sequence*, not just 0x02.

**H2 — state-push-end trio (t=27.99/28.41/28.56), needed if the state blob ran.**
`(0,0x12, b"\x00\x00\x03\x0b"+b"\x00"*28)` then `(4,0x21, b"\x00"*32)` then
`(4,0x1a, b"", flags=0x42)`. `0x12` carries `0x30b`=779 = the blob count → it is the
"commit/end-of-state-push" terminator; `4/0x21` (undocumented) and `4/0x1a` close the phase.
Note the docs' "0x1a flags 0x42 = shutdown" is **disproven** here: the pad stays up 271 s
longer, so 0x42 does something else (state transition, not power-off). Treat as a precondition
that follows the 0x11 blob push — not a standalone video gate (30 s of silence follows it).

**H3 — svc 5/0x08 payload 0x01 (implied video-enable; LOW).**
`build_generic(5, 0x08, b"\x01")`. Docs: 0x08/00 disables video; 0x01 is the implied enable.
BUT the console never sends 0x08 at all, so "video on" is NOT positively commanded — it is the
pad's default once armed, and 0x08/00 only turns it *off* (Home menu). Send 0x01 only to repair
a pad left disabled by a prior sweep; it is not the causal trigger.

**H4 — the full console pre-video arm burst, in order (the measured 12→0 sequence).**
`0/0x00`, `4/0x04`, `5/0x02`(102 zeros), `5/0x06` — the `arm` plan. This is the sequence with
direct hardware evidence, so probe it first; then add H2's trio before it (the `full` plan,
console order) if the pad is known to have received the 0x11 blob stream.

## 4. Probe usage

```sh
run/agent-arm-probe.py                              # dry run: print exact bytes, no network
sudo run/agent-arm-probe.py --run --plan arm --interval 0.4
sudo run/agent-arm-probe.py --run --plan full --interval 0.4
sudo run/agent-arm-probe.py --run --steps 5/0x02/z102 5/0x08/01
```
