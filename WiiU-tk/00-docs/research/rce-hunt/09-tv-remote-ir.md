# 09 — TV Remote / IR subsystem: what it is, and a ranked testable exploit plan

Scope: the GamePad's IR feature (TV remote blaster). Read-only research; **nothing was sent to the pad
and no file was modified** to produce this document. All new claims below were obtained by (a) re-playing
existing evidence (`out/evidence/rce-ro-1015/uic.fw_and_eeprom.reply.bin`), (b) reading
`research/libdrc` sources, (c) arithmetic on the CRC scheme libdrc implements. Labels: **VERIFIED** (bytes
or code proven locally), **DOC** (a source states it), **INFERRED** (strong local reasoning),
**SPECULATIVE** (guess; a test is named).


## 0. What is new here (vs. 02/05/06/08)

1. The UIC EEPROM dump is **fully decoded**: 27 of the 31 records libdrc parses validate against this pad's
   dump under libdrc's own CRC-16 — **VERIFIED** — giving an objective address map and record boundaries.
2. **Two briefing hypotheses are falsified** (§3.2, §3.3): the "two 0x90-byte blocks at 0x100/0x180 = two
   remocon slots" and the "u16 ramp at 0x270 = IR timing table". Neither is remocon or IR data.
3. **`IT0156` is not a UIC build string** — its leading `I` is the CRC byte of the preceding record; the
   next 10 bytes are one CRC-valid `tv_remocon_id1/2` record (§3.3). Correction to `08-live-results.md` §2.
4. The IR path is **absent from every capture we own and from libdrc's implementation** (grep: only
   `device-config.cpp` reads the two IDs), so §4 is ranked on structure, not on observed console parity.

## 1. What the TV Remote feature actually is on this hardware

| Claim | Evidence | Label |
|---|---|---|
| The pad has **both an IR emitter and an IR window** ("IrDA window + IR LED — TV-remote blaster / toy IR") | `RESEARCH.md` hardware-port table (our own doc, no external citation recorded) | **DOC(own)**; externally **unverified** |
| The **LVC** owns the IR software path: driver `ir - infrared output` **and** manager `ir - handles IR communication` | `research/libdrc/web/docs/re/overview.rst:101,136` | **VERIFIED** (doc) |
| The **UIC is not in the IR path**: libdrc's UIC/STM8 documentation names no IR command; the UIC's documented jobs are input, PMIC, sensors, its 2 KB EEPROM, and its own firmware update | `overview.rst:57-69`; cmd→UIC methods in `sc-cmd.rst:220-261` | **INFERRED** (absence of evidence, from a good source) |
| The **sensor bar** is a *separate* IR function: `svc 5/0x01` toggles it "via a GPIO", and GPIO5 (`F0005118`) is documented as "Controls the sensor bar power" | `sc-cmd.rst:225`; `gpio.rst:25` | **VERIFIED** (doc) |
| The TV-remote emitter is **not** on one of the six used GPIOs (GPIO0 LCD, GPIO2/3 NFC, GPIO4 rumble, GPIO5 sensor bar, GPIO6 CMOS; GPIO1/GPIO7 unused) | `gpio.rst:13-30` | **VERIFIED** (doc) ⇒ the blaster is driven by the `ir` driver's own MMIO/timer block, or by GPIO1/GPIO7 | **INFERRED** |
| A **"TV command for ID X"** becomes a waveform as: `svc 5/0x18` (10 B) stores two 5-byte remocon IDs → `svc 5/0x17` (7 B = 5-byte ID + 2 trailing bytes) asks the `ir` manager to emit → the manager selects the ID's code table from flash **TVcode @0x1900000** and the `ir` driver emits mark/space | `sc-cmd.rst:245-257`; `01-pad-firmware-update.md` §4.1 (flash map, verified) | chain **INFERRED**; the table format is **unknown** |
| The **2 bytes after the ID in `0x17`** are undocumented; they are either a command number or a literal (mark,space) pair | `sc-cmd.rst:254` ("Unknown, sends a TV command") | **SPECULATIVE** — cheapest test: §6 step T8 with ID `T0156` and a swept 2nd field |
| **No public source states IR carrier frequency, mark/space encoding, or entry counts**; the TVcode region has only an internal *name* | `flash_layout` (kuribo64) via `01` §4.1; my searches found no format description (§7) | **VERIFIED-absent** |
| The **102-byte `svc 5/0x02` burst** (`u16,u16,{u8,u8,u8}[32],u16` = 102 B → UIC command `0x0c`) *could* be an IR/LED timing table (32 triples), but the only console instance we hold is **102 zero bytes, twice per session** (`t=59.398 s`, `01` §1.3/`02` §4.2) | `sc-cmd.rst:227`; capture inventory | shape **DOC**; "it is the IR table" **SPECULATIVE** — an all-zero payload is idle-shaped, which fits "cleared/unchanged", not a live command |

**Which CPU drives the IR LED:** the LVC owns both the driver and the manager, and the cmd stack carrying
`5/0x11`, `5/0x16`, `5/0x17` lands in the LVC, so on the software side **the LVC is the IR owner**
(**VERIFIED**, `overview.rst`). Whether the STM8 sits between the LVC and the emitter (e.g. via the
`0x02`→UIC `0x0c` burst) **cannot be settled from any source we have**. Cheapest resolver: `06` route **P-a**
(SPI-clip read of the 32 MB flash, read-only, ~€5) → find the `ir` driver's MMIO writes in `LVC_`; alternative
`P-b` (UART boot). **What IRCOM connects to:** not a port — the pad's `ir` manager. The four-state shape
(`0/1/2/3` = connect/send/receive/disconnect, ≤520 B each way) only makes sense with a **photodiode**, i.e. a
transceiver rather than a pure blaster (**INFERRED**; matches the "IrDA window" in `RESEARCH.md`).

## 2. Where the code data comes from in normal operation

| Question | Best available answer | Label |
|---|---|---|
| Are TV codes **factory-provisioned** in flash? | The flash map names a dedicated partition **`TVcode @0x1900000`, "remote-control data"**, with `Screen1/2` as separate partitions of the same family — a shape that only makes sense for pre-loaded per-region data | **DOC** (kuribo64 `flash_layout`, cross-checked in `01` §4.1) |
| Does the **console push** codes to the pad? | There is a documented console→pad start/end pair for exactly this: `svc 0/0x0b` (9 B) "**TVCode** / Service / Screen1 / Screen2 **start update**" + `0x0c` (0 B) end. The framing of its 9-byte payload is **not documented anywhere** we can find | **DOC** for existence; framing **unknown** |
| Is the push used in practice, and when? | **`0x0b`/`0x0c` are ABSENT from all 300 s of our real console capture**, as are `5/0x11`, `5/0x17`, `5/0x18` (`01` §1.3). That is consistent with "the console only pushes when the user configures a TV / uses the TV Remote app", but it is *also* consistent with "the pad never needs a push"; the capture **cannot distinguish** these | **VERIFIED-absent**; interpretation **INFERRED** |
| Does the **pad's own UI learn** codes? | No learn path is documented in any source; the only TV-remote setters are `5/0x18` (the two IDs) and the `0x0b`/`0x02` update pair. A "point your remote at the pad" learning feature would need `5/0x11` receive + a write primitive that nobody has documented | **INFERRED (absent)** |
| Does the pad **validate/CRC** any of it? | The **UIC EEPROM is CRC-16 protected per record**, and the scheme is now pinned exactly: poly `0x8408` (reflected), init `0xFFFF`, **no final XOR**, CRC stored **little-endian** immediately after the data (`device-config.cpp:39-60`). Our dump validates 27/31 libdrc record offsets — **VERIFIED**. Whether **TVcode flash blocks** carry the same CRC is unknown; the 9-byte `0x0b` payload has room for `{target, length/offset, crc16}` and the analogous EEPROM write (`5/0x0c`) *does* carry a CRC per write (`index, length, data+crc`) | EEPROM scheme **VERIFIED**; TVcode **SPECULATIVE** |
| Does the *console* download codes from Nintendo's servers? | Nothing in our evidence base shows a NUS/CDN fetch of TV data; `06` §5's MLC/NUS table only hunts `drc_fw.bin`. I could not verify a server-side TV-code source | **unverified** — cheapest test: the SPI clip, which shows the codes already sitting in `TVcode` |


## 3. Byte-level reading of the 768-byte UIC EEPROM dump

Container geometry (**VERIFIED**): `svc 5/0x06` payload = 4-byte UIC fw field + 768 B of the 2 KB EEPROM.
The 768 B are **3 pages of 256**, each closed by a 3-byte page marker record:

| Marker | Data | Stored CRC | CRC check |
|---|---|---|---|
| `0x0fd` | `03` | `3d1c` @0x0fe | **VERIFIED** (`crc16(03)=0x3d1c`) |
| `0x1fd` | `05` | `582a` @0x1fe | **VERIFIED** |
| `0x2fd` | `04` | `49a3` @0x2fe | **VERIFIED** |

Record model (**VERIFIED** by arithmetic, `device-config.cpp:39-69`): `[data…][crc16 LE]`, poly `0x8408`,
init `0xFFFF`, no final XOR. My check of every offset libdrc parses: **27/31 records validate**; the 4 that
do not are explained in §3.6 and are the only places where this pad's layout differs from libdrc's reference.

Crucially, this gives an **independent endianness cross-check** of my offset mapping, because `svc 0/0x0a`
serves three of these records live:

| EEPROM record (stored bytes) | Live `svc 0/0x0a` reply | Meaning | Label |
|---|---|---|---|
| `0x25c` = `00 00 00 03` + crc `31ba` | index 1 → `03 00 00 00` | `tv_remocon` version = **3**, stored **big-endian**, served **LE u32** | **VERIFIED** |
| `0x262` = `ea 1d 03 a0` + crc `9e8d` | index 2 → `a0 03 1d ea` | `service_firmware_version` = 3,927,770,016 | **VERIFIED** |
| `0x268`, `0x26e` = `00 00 00 00` + **invalid** CRC | index 3, 4 → `00 00 00 00` | opening screens **never written** (so the CRC check failing is correct, and libdrc's "leave at 0" fallback is the right model) | **VERIFIED** |

### 3.1 Page 1 (`0x000–0x0FF`) — Wi-Fi and wake-on-WLAN, no IR

| Offset | Record | Value in our dump | Label |
|---|---|---|---|
| `0x001` len `0x6a` | Wi-Fi settings blob (+crc `95a4` @0x06b) | SSID len `0x21`=16 → `WiiUccfb65b68169`; auth_mode `0x23`=`0x80`=**WPA2**; enc `0x24`=`0x03`=**AES**; key len `0x65`=`0x40` → the **64-hex-char PSK** at `0x25…0x64` | **VERIFIED** |
| `0x06d` len 16 | wake-on-WLAN key | `98 88 d9 eb … ea 08` | **VERIFIED** |
| `0x07f` len 6 | WoWLAN MAC | `cc fb 65 b6 81 69` | **VERIFIED** |
| `0x087` len 1 | wowl setting | `01` | **VERIFIED** |
| `0x08a` len 1 | last channel | `0x95` = **149** (5 GHz — matches our AP) | **VERIFIED** |

### 3.2 Pages 2-ish: the two identical 0x90-byte blocks at `0x100` / `0x180`

They are **two copies of the same six configuration records** (offset `base+0x00, +0x03, +0x1a, +0x2c,
+0x53, +0x65`), i.e. **redundant settings banks**, and libdrc's parser *encodes exactly this fallback*:
it reads the `0x1xx` copy and falls back to the `0x18x` copy (`device-config.cpp:172-215, 262-278, 297-316`).

| `base+` | Data | Decode | Both banks? |
|---|---|---|---|
| `+0x00` | `8b` | board main version `0xb`, sub `0x8` | **VERIFIED**, identical A/B |
| `+0x03` | `01` | region = **NorthAmerica** (`kRegionNorthAmerica = 0x1`) | **VERIFIED**, identical A/B |
| `+0x1a` | `00 fb` | volume min 0, max 251 | **VERIFIED**, identical A/B |
| `+0x2c` len 19 | `dc 00 00 68 00 00 cc ff ff 72 5e 02 ×3 c8` | gyro calibration: 6 × 24-bit zero/scale + speed `0xc8` | **VERIFIED**, identical A/B |
| `+0x53` len 16 | `35 00 1e 00 22 03 c3 01 45 01 5d 0e 9d 0e a5 01` | touchscreen/panel calibration: 8 × `int16` (ref1/ref2/raw1/raw2) | **VERIFIED**; a **third** identical copy at `0x244` (`device-config.cpp:390-415`) |
| `+0x65` len 4 | `ea 1d 03 a0` | service firmware version (same value as `0x262`) | **VERIFIED**, identical A/B |

**Falsification #1:** these blocks are **not** "two remocon slots". They contain board/region/volume/gyro/
touch calibration and a firmware version — nothing ASCII, nothing 5-byte, nothing IR. (The briefing's
"candidate two remocon slots" reading is refuted by the CRC-validated record boundaries.)

### 3.3 Page 3 (`0x200–0x2FF`) — where the TV-remote settings actually live

| Offset | Record | Value | Decode | Label |
|---|---|---|---|---|
| `0x256` len 1 | language bank | `00` | **CRC invalid** here (`0x0200` stored vs `0x0f87` computed) — see §3.6 | **VERIFIED** |
| **`0x25c` len 4** | **`tv_remocon` version** | `00 00 00 03` | **3** — matches live index 1 | **VERIFIED** |
| `0x262` len 4 | service firmware version | `ea 1d 03 a0` | 3,927,770,016 | **VERIFIED** |
| `0x268`, `0x26e` len 4 | opening screen 1/2 versions | all zero, no valid CRC | unset | **VERIFIED** |
| `0x274` len 1 | initial boot flag | `00` (crc `0f87`) | | **VERIFIED** |
| `0x277` len 13 | **LCD backlight table** | `15 01 2d 01 4d 01 7a 01 b7 01 ff 01 03` | 6 × (level, frequency=1) + threshold `0x03`; the same 13-byte shape the docs give for `svc 5/0x19` "set LCD parameters via i2c" (`sc-cmd.rst:259`) | **VERIFIED** |
| `0x286` len 1 | lcd setting | `04` (crc `a3 49`) | the LV/current brightness class; live `svc5/0x15` read back **4** | **VERIFIED** |
| **`0x289` len 10** | **the two remocon IDs** | `54 30 31 35 36` + `00 00 00 00 00`, crc `6b 32` | **ID1 = ASCII `T0156`**, **ID2 = `00…` (unset)** | **VERIFIED** (CRC) / IDs' meaning **INFERRED** from `device-config.cpp:470-474` |
| `0x296` len 1 | airwave setting | `87` | **CRC invalid** (`0x020f` stored vs `0xff30` computed) — §3.6 | **VERIFIED** |

**Falsification #2 (the IT0156 string).** `08-live-results.md` §2 records "`0x0288 IT0156` (UIC build
string)". Arithmetic says otherwise: `0x288` is `0x49` `'I'`, and `0x287..0x288` = `a3 49` is the **stored
CRC of the `lcd_setting` record at `0x286`**, which validates exactly (`crc16(04)=0x49a3`). The bytes are
therefore `[04][crc a3 49]` followed by the **CRC-valid 10-byte TV-remocon-ID record** `"T0156"` + 5 zero
bytes. So the pad's only textual TV-remote datum is **remocon ID1 = `T0156`**, and there is **no UIC build
string at 0x288**. (Residual doubt: a 1-in-65536 CRC coincidence; two independent records argue against it,
and the alternative reading would leave *no* valid remocon-ID record anywhere in the dump.) **VERIFIED
arithmetic**, conclusion **INFERRED (very strong)**.

**Falsification #3 (the "u16 ramp").** `0x270–0x285` is not a u16 ramp and not IR timing: `0x274` is the
`initial_boot_flag` record, and the "ramp" `15 01 2d 01 4d 01 7a 01 b7 01 ff 01 03` is the 13-byte **LCD
backlight level/frequency table** (record `0x277`, crc `8c26` — verified). It has the same shape as the
`svc 5/0x19` i2c payload, and its six levels are the brightness ladder behind `svc 5/0x14` (1…5). It is
**display data, not IR data**.

### 3.4 The tail journal `0x295–0x2A9`, and the one known-valid EEPROM write

A brute-force scan for CRC-valid records in `0x280–0x2B0` yields a **compact journal of seven micro-records**:

```
0x295 {00}      0x298 {02 95}      0x29b {00}      0x29e {00}
0x2a1 {03}      0x2a4 {00}         0x2a7 {08 00}
```

all with valid trailing CRCs (`crc16(00)=0f87`, `crc16(02 95)=002c`, `crc16(03)=3d1c`, `crc16(08 00)=3e78`).
The bytes `02 95 2c` are **byte-identical to the data+crc of the only over-the-air EEPROM write ever
observed on this pad**: `svc 5/0x0c` payload `13 03 02 95 2c` = index `0x13`, length 3, `02 95` + crc `2c`
(`01` §2, sent twice per console session). **INFERRED:** `index` selects a *record*, not a byte offset, and
the pad re-writes that record into this journal area. **Unresolved:** the index↔address mapping
(`0x13`=19 vs journal offset `0x298`; `0x298−19 = 0x285` and `0x298 & 0xFF = 0x98` are both unclean).
Cheapest resolver: one **gated** write (`5/0x0c`) followed immediately by a `5/0x06` re-dump and a byte
diff — needs the operator's explicit approval, and is fully reversible with the dump we already hold.

### 3.5 What remains a guess

* Is ID2 (zero on this pad) a second TV or a second code bank? Is `T0156` a table ID or a user string? Both
  **INFERRED** only — `sc-cmd.rst` says no more than "sets the two remocon IDs (5 byte strings)".
* Does flash TVcode use this same CRC-16, and what are its entry fields (carrier, mark/space, counts)? No
  public source, no local evidence.
* Does the `0x295` journal *shadow* the canonical records or replace them on this newer firmware (`0x256` and
  `0x296` fail at libdrc's offsets while a valid `{00}` record sits at `0x295`)? **INFERRED**, not proven.

## 4. Ranked exploit candidates on the TV-remote path

Datagram = `CmdHeader(8) ‖ GenericCmdHeader(12) ‖ payload`; generic `payload_size` is `be16` at generic-byte
10, `flags 0x40` = single/final, `svc 5`. Score = likelihood × value (1–5 each).

| # | ID | Trigger (exact shape) | Primitive if it works | Pre-conditions | Destructive | Remote observation | L·V |
|---|---|---|---|---|---|---|---|
| 1 | **TV1** | `0x11` payload `02` (receive) with **no** prior `00`/`01`, and `00` connect with no send | Uninitialised/stale **IR-receive buffer echoed in a ≤520 B reply** → RAM disclosure; a receive with no IR light has ~0 real bytes to return, so the length is the tell | cmd plane reachable; `ir` manager answers (unknown) | RAM-only | `body_len` ≫ 0 with non-zero, structured, *repeating* content across tids; no ACK/input disruption | 4·4 |
| 2 | **TV2** | `0x11`, `01`+19×`00` (**20 B delivered**), generic `payload_size` **declared 520**, `FIN=1`; repeat at 1028 and `0xFFFF` | Handler reads the **declared** length from a 20-B datagram: 500–1000 B OOB read, and a copy into a fixed `ir` buffer is **BSS corruption past 520** | IRCOM must not check declared-vs-actual (family M3, untested) | RAM-only (crash possible) | Reply ≈520 B and ≠ our 20 bytes; ACK still arrives; pad survives | 3·5 |
| 3 | **TV3** | `0x11` state abuse: `03`→`01`, `00`,`00`, `02`→`01`; opcode byte `04,05,7f,80,ff` (doc: 0–3 only) | Session-struct confusion / use-after-free in `ir`, or opcode used as a table index | none | RAM-only | Unexpected error codes; a later `02` returning *another* session's bytes | 3·3 |
| 4 | **TV4** | `0x16` with payload `00,01,ff,02,7f,80` (doc: "should be either 0 or -1") | Unchecked 1-byte selector into an `ir` mode/route switch | none | RAM-only | Per-value reply/error change; sweep 0–255 only if one differs | 2·3 |
| 5 | **TV5** | `0x17` 7 B: `ff×5`+`0000`, `00×7`, `T0156`+`0000`, plus 3-B and 16-B payloads | 5-byte ID lookup miss → OOB read in the code table; length-trust on the 7-byte body | none | RAM-only, but **physically emits IR** on an ID match | Reply/err change, no crash expected; IR emission is the visible side effect | 2·3 |
| 6 | **TV6** | `0x02`, 102 B `u16,u16,{u8,u8,u8}[32],u16` with attacker triples (all-zero is the only observed value) | 102 B into the STM8 via UIC `0x0c`; trusted length sends LVC memory over SPI (reply empty → no leak, UIC parser confusion); timer triples actuate LEDs | none | RAM-only (UIC state unknown) | No reply body: watch ACK presence, input continuity, `svc 4/0x05`, `5/0x15` | 2·3 |
| 7 | **TV7** | `0x18` (10 B IDs) then `0x17` with that ID | Proves ID→slot mapping; arbitrary 5-byte value in a persisted record | **operator approval** | **PERSISTENT** (1 record, reversible: we hold the pre-image) | `5/0x06` re-dump diff at `0x289`; `0x17` reply | 3·2 |

**Rationale.** TV1/TV2 are the only candidates that return *attacker-positioned memory through a documented
520-B reply* — the primitive the hunt lacks (our sole confirmed disclosure is the fixed `5/0x06` read). TV4/TV5
are ranked low on purpose: the one sweep we own shows this firmware *does* validate a 1-byte selector
(`svc 0/0x0a` → `err=14` for `0x05…0xF5`, `08` §3). **Does the path need the TV-remote UI open?** Unknown; the
`ir` **manager** sits behind the cmd service and every measured `svc 5` method answers with no on-pad UI
(`5/0x06`, `5/0x14`, `5/0x15`), so **INFERRED: no** — and probe T1 settles it in one datagram.

## 5. Remote-observable leak math

* **Per-request ceiling = 520 B** — the only number in the protocol that bounds payload *and* reply
  (`sc-cmd.rst:245-247`), implying a `2 × 520 B` buffer pair in the `ir` manager.
* **TV1 yield:** no IR light in band ⇒ `reply_len − 0 ≈ 520 B` per request. **TV2 yield:** `520 − 20 = 500 B`
  read window past our payload, of which only what the reply can carry leaves the pad.
* **Amplification:** if the reply length follows our declared length, walk it in 20 B steps (20…520) and
  reconstruct the window linearly instead of guessing. Each request is 1 datagram; a 540 B reply is cheap.
* **What is adjacent:** the `ir` tx/rx pair, then likely the `cmd` reply-assembly buffer and other manager BSS.
  **Objective check:** we hold ground truth for `WiiUccfb65b68169`, the 64-hex PSK, `ea 1d 03 a0` and `T0156`
  — any IRCOM reply containing one of them is **confirmed cross-object disclosure**; their absence bounds the
  leak to the IR buffers.
* **Anti-self-deception controls:** (a) repeat 3× with different `tid`/`seq` — deterministic bytes are *stale
  data*, transmitted IR is not; (b) send an honest 520 B first (T4) so "520 B came back" is not a size echo;
  (c) log length *and* the first 32 bytes of every reply.

## 6. Ordered, ROE-compliant test list

Preconditions per step: exclusive `192.168.1.10:50023` (`ss -lunp` shows no peer — `08` §4), `run/drc-up.sh`
healthy so the input stream is the crash detector, `svc 4/0x05` before/after each case, and
`research/rce-hunt/ir-probe.py` as the vehicle (it implements T1–T9; T10 is not implemented and is gated).

| # | Step | Exact bytes | Falsifies if |
|---|---|---|---|
| T0 | Gate: `ss -lunp`, baseline `svc 4/0x05` + `5/0x15` | — | (aborts the run) |
| T1 | IRCOM **connect** — does the path answer at all? | `000000000d0001027e010118004005110000000100` (21 B) | `err≠0`/NOREPLY ⇒ reachability dead; ranking gated on pad state |
| T2 | IRCOM **receive**, fresh `tid`, no prior connect | `000000000d0002027e010128004005110000000102` (21 B) | body empty/all-zero on 3 repeats ⇒ TV1 dead |
| T3 | IRCOM **send, over-claim** 20 real / 520 declared | `00000000200003027e010138004005110000020801`+19×`00` (40 B) | reply ≤ ~20 B or `err≠0` ⇒ declared length untrusted (TV2 dead) |
| T4 | IRCOM **honest 520-B send** (control for T3) | `0x11`, `01`+519×`00`, generic size 520, `flags 0x40` | 520 B back here ⇒ T3's length is a *size echo*, not a leak |
| T5 | **disconnect→send**, **double connect**, **receive→send** | `0x11` payloads `03`, `01`+8×`00`, `00 00`, `02`+8×`00` | identical errors everywhere ⇒ TV3 dead |
| T6 | **opcode confusion** `04,05,7f,80,ff` | `0x11`, `op`+8×`00` | all errors equal to T1 ⇒ opcode range-checked |
| T7 | **`5/0x16`** `00,01,ff,02,7f,80` | `000000000d0005027e0101580040051600000001ff` (`ff`, 21 B); others differ in last byte + `seq` | no value differs from `00` ⇒ TV4 dead; only then sweep 0–255 |
| T8 | **`5/0x17`** `ff×5`, `00×5`, `T0156`, 3-B, 16-B | `00000000130006027e0101680040051700000007ffffffffff0000` (27 B) | in-table and out-of-table IDs give identical errors ⇒ no lookup oracle. **Cover the pad's IR window or get operator OK — a `T0156` match really emits** |
| T9 | Repeat T1–T8 twice in one session, alternating tids | same bytes, `tid` 0x110…/0x120… | byte-identical replies across rounds ⇒ deterministic stale buffer, not changing memory |
| T10 | **GATED:** `5/0x18` one ID, then `5/0x0c` `13 03 02 95 2c`, then `5/0x06` re-dump + diff | 10 B / 258 B / 0 B frames | journal at `0x295–0x2A9` unchanged ⇒ §3.4 mapping wrong |

**Stop conditions:** `svc 4/0x05` stops answering, input rate 0 for >2 s, or two consecutive un-ACKed
datagrams → stop, power-cycle, record the case. T1–T9 are RAM-only and a power cycle is within the ROE.

## 7. Public prior art

* **libdrc** is the only public description of `IRCOM`, `0x16`, `0x17`, `0x18` (`sc-cmd.rst:245-257` — four
  rows, no framing, no reply semantics) and the only public code parsing the EEPROM TV-remote fields
  (`src/device-config.cpp:427-474`). It **implements no IR client** (grep of `research/libdrc/src`).
* [kuribo64 `flash_layout`](https://kuribo64.net/wup/doku.php?id=flash_layout) names `TVcode @0x1900000` with
  no format; [`uic_eeprom_structure`](https://kuribo64.net/wup/doku.php?id=uic_eeprom_structure) documents the
  2 KB EEPROM layout (cited in `01` §4.3); [wiiubrew GamePad](https://wiiubrew.org/wiki/GamePad) covers
  hardware/ports, not IR.
* **No published IR/TV-remote exploit, fuzzing run, or code database** was located; searches on
  TVcode/remocon/IR format returned only a GBAtemp thread on
  [adding a custom TV remote](https://gbatemp.net/threads/adding-custom-tv-remote-to-wii-u-gamepad.476735/)
  and unrelated LIRC tables. Treat "never fuzzed publicly" as **VERIFIED-absent-in-our-sources**, not as
  proven novelty.
* melonpad implements I2C/SPI/LCD/framebuffer/DMA/input and **not** IR (`04` §5), so the custom-firmware scene
  offers no IR driver to cross-check against.

## 8. Corrections this document makes to earlier files

| File / claim | Correction | Basis |
|---|---|---|
| briefing + `02` §4.2: two `0x90`-byte blocks at `0x100`/`0x180` = "two remocon slots" | They are **A/B copies of six calibration/config records**; the TV-remote IDs are one 10-byte record at `0x289` | CRC-validated boundaries, `device-config.cpp:172-316,470-474` (**VERIFIED**) |
| briefing + `02`: u16 ramp at `0x270` is a candidate IR timing table | It is the **13-byte LCD backlight level/frequency table** at `0x277` (crc `8c26`), same shape as the `5/0x19` i2c payload | arithmetic (**VERIFIED**) |
| `08` §2: `0x0288 IT0156` = UIC build string | `0x288` (`'I'`=`0x49`) is the **CRC byte** of the `lcd_setting` record; the content is **remocon ID1 = `T0156`**, ID2 unset | `crc16(04)=0x49a3`, id record crc `0x326b` (**VERIFIED**) |
| `02` §4.2: `0x17`/`0x18` "write into EEPROM-backed settings" | `0x18` writes one CRC'd 10-byte record (`0x289`); `0x17` is a read/emit path, not a store | doc + §3.3 (**INFERRED**) |
| `06` §2: `5/0x15` = brightness setter | `0x14` = **set** (1…5), `0x15` = **get**; our live `0x14`→`0x15`=4 pair agrees with the doc | `sc-cmd.rst:249-251` (**DOC**) |
| `06` §2: "`5/0x11` … 4 B ×195 (acks)" | those 4-byte bodies are `svc 0/0x11` state-push replies (`01` §1.3); **IRCOM was never on the wire** | capture inventory (**VERIFIED**) |

**Cheapest experiment that upgrades this whole document:** the SPI-clip flash read (`06` route **P-a**,
read-only) → dump `0x1900000`, test the §3 CRC-16 against each TVcode block, read off carrier/count/mark-space
structure, and locate the `ir` driver in `LVC_` to settle whether the UIC sits between the LVC and the emitter.
