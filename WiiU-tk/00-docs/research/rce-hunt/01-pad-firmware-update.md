# The GamePad firmware-update ("blink") path — full map, and whether we can push our own LVC

Compiled 2026-11-05 for the Wii U GamePad DRC lab (`/home/kali/Wiiu`). Pure research: nothing in this
document was executed against hardware, no network interface was touched, no existing file was modified.

**Answer in one line:** the update transport (cmd service 0, methods 0x02/0x03/0x04/0x05) is a documented,
unauthenticated RPC pair over the *same* 50023→50123 command plane we already drive; the image format is
fully public and **carries no signature — only CRC32s**; modified LVC images are already known to boot on
retail pads (GaryOderNichts' DRXUtil ships LVC patches and flashes them). So the only thing standing between
us and persistent code execution on the pad is *driving the transport correctly*, not defeating crypto.

Confidence vocabulary used throughout:

| Tag | Meaning |
|---|---|
| **VERIFIED** | read directly in a local capture / local source, or quoted from a primary source with a URL |
| **INFERRED** | follows from verified facts by a short chain; not directly observed; do not quote as fact |
| **UNCERTAIN** | genuinely unknown; the cheapest resolving test is named in §8 |

---

## 0. Bottom line for the mission

| Question | Verdict | Confidence |
|---|---|---|
| Is there an authenticated-free code-execution primitive on the pad? | **Yes, the firmware-update path.** No signature, no key exchange, no console identity check beyond the WLAN link we already own. | **VERIFIED** (format + prior art) / **INFERRED** (works from *our* DRH) |
| Can our DRH drive it? | The method table is public (libdrc) and these are ordinary generic commands on port 50023→50123, which we already send and get ACKed. **Never attempted by this project.** | **INFERRED (high)** |
| Is it the cheapest route to the LCD? | Probably not the *fastest*. It is the cheapest route to *arbitrary code on the pad*, which makes the LCD problem trivial. The UVC/UAC and svc 0/0x11 work in `BOOT-AND-MODES.md` is cheaper to try first and costs nothing. | **INFERRED** |
| Brick risk | Real but bounded: A/B partitions plus a CRC-verified image plus UART-boot recovery. The dangerous sub-paths are the UIC/language/Service ones (0x0b–0x0f), not the product (LVC) update. | **INFERRED**, see §4 |

---

## 1. What the update path actually is (verified fact base)

### 1.1 It is the same cmd plane we already speak

`research/libdrc/web/docs/re/sc-cmd.rst` (local copy; online:
[libdrc sc-cmd.rst](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html),
[bitbucket source](https://bitbucket.org/memahaxx/libdrc/src/5c26ba6d45920c8609466d00994e2bb313325ba9/web/docs/re/sc-cmd.rst)):

> "The command protocol, also known as `cmd`, is used as a lightweight RPC between the Wii U and a GamePad.
> Using this protocol, the Wii U can send commands to a GamePad and get a reply from it. This protocol has
> various uses, from **firmware upgrade** to NFC communication."

> "Generic commands … allow access to most of the features of the GamePad not already exported through the
> input protocol. **It is also used for firmware upgrade.**"

> "Transaction and Fragment ID — Used for commands that require payloads larger than the size of a 802.11n
> packet. **Currently only seen in use for firmware upgrades.** Set to 0 for most commands."

Those three sentences are the whole reason this path is interesting: the update rides the protocol we have
already proven end-to-end (association → 4-way with the 3-byte-rotated PTK → DHCP `.11` →
50023/50123 queries with type-1 ACKs, type-2 replies, type-3 ACKs).

**VERIFIED** locally: `out/evidence/truth/port50023.bin` / `port50123.bin` contain exactly that state machine,
e.g. the first console query and the pad's two answers:

```
# console -> pad:  type 0, query 0, payload_size 12, seq 9, svc 0 method 0x00 (get LVC version)
00 00 00 00 0c 00 09 00  7e 01 01 58 00 40 00 00 00 00 00 00
# pad -> console:  type 1 (ACK), same seq            <- 8-byte bare ack
01 00 00 00 00 00 09 00
# pad -> console:  type 2 (reply), same seq, generic flags 0x09, payload 8 bytes
02 00 00 00 14 00 09 00  7e 01 01 58 00 09 00 00 00 00 00 08  19 0c 01 17 19 0c 01 17
```

Note the reply's generic flag byte: `0x40` query → `((0x40>>3)&0xFC)|1 = 0x09` reply, exactly as the doc says.
The ACK is a bare 8-byte `<HHHH>` = (type, query_type, 0, seq) in both directions.

**Correction to an existing project note (worth recording):** `BOOT-AND-MODES.md` §5.1 reports svc 0/0x00 as
`385944601` (little-endian read of `19 0c 01 17`) and svc 4/0x04's third word as opaque. On the wire the pad
returns the bytes `19 0c 01 17` **big-endian**, i.e. the DRC firmware **image version `0x190C0117`** — the same
constant `DRXUtil` uses to identify a stock retail image (`source/screens/FlashScreen.cpp`: *"Invalid image
version to patch"* when `GetImageVersion() != 0x190c0117`). **VERIFIED** from the capture bytes plus the
DRXUtil constant; this makes `0x190C0117` our pad's image version.

### 1.2 The method table (verbatim from libdrc)

Service ID 0, "contains mostly firmware related commands". Payload/reply sizes as documented:

| Method | Payload | Reply | Documented meaning |
|---|---|---|---|
| `0x00` | 0 | 8 | Get LVC firmware version — two u32: running, installed |
| `0x01` | 0 | ? | Unknown |
| **`0x02`** | **4** | **0** | **Start product update** |
| **`0x03`** | **max 1028** | **4** | **Update data. Input is `struct { u32 block_idx; u8 data[]; }`** |
| **`0x04`** | **0** | **4** | **End product update** |
| **`0x05`** | **0** | **0** | **Abort update** |
| `0x09` | 1 | ? | Returns hardcoded values |
| `0x0a` | 1 | 4 | Version from EEPROM: 0 lang, 1 tv_remocon, 2 service_firmware_version, 3 opening_screen_1, 4 opening_screen_2 |
| `0x0b` | 9 | ? | TVCode / Service / Screen 1 / Screen 2 **start update** |
| `0x0c` | 0 | ? | TVCode / Service / Screen 1 / Screen 2 **end update** |
| `0x0d` | 4 | ? | Lang 1 / Lang 2 **start update** |
| `0x0e` | 0 | ? | Lang 1 / Lang 2 **end update** |
| `0x0f` | 4 | ? | Lang 1 / Lang 2 update language, bank and version |

And the mode-changer, service ID 4:

| Method | Payload | Meaning |
|---|---|---|
| `0x01` | 1 | "Shuts down or reboots to a different mode. Payload **0** reboots to normal mode (if not already), **2** reboots to **firmware update mode**, 4 or 6 shuts down." |
| `0x04` | 0 | 28-byte version information |
| `0x05` | 0 | 1 byte = `retvals[current_state]`, `retvals[] = {0,10,4,5,6,1,2,3,9,7,8,11}` |

libdrc explicitly leaves the update sub-protocol undocumented — **this is a documented gap, not a discovered
secret**:

> "Contains mostly firmware related commands. For more information about firmware update related commands,
> read the (non-existing yet) **Firmware Update Commands** documentation."

Nobody in the public scene has published a reverse-engineered description of the 0x02/0x03/0x04 exchange
itself (searched: libdrc docs + site, wiiubrew, kuribo64.net/wup, melonpad, DRXUtil, drc-fw-patches,
drxtool, GBAtemp threads, wiiu.hacks.guide). The *pad-side* method IDs are known; the *numbering/verification
semantics* are not. §2 is therefore split into "verified layout of the artefact" and "inferred semantics of
the exchange".

### 1.3 Nothing in the local capture uses the update methods

`out/evidence/truth/port*.bin` is 300 s of a real console↔pad session, decrypted to 99.9 %
(`GROUND-TRUTH-SESSION.md`). Full inventory (`research/rce-hunt/inventory_cmd.py`, new file, read-only):

```
file            type svc  method  payload sizes:count
port50023.bin   2    0    0x00    8:3          (pad reply)   LVC version
port50023.bin   2    0    0x10    0:1          (pad reply)
port50023.bin   2    0    0x11    4:195        (pad reply)   svc0/0x11 acks
port50023.bin   2    0    0x12    4:1          (pad reply)   undocumented, u32 = 0
port50023.bin   2    4    0x04    28:3         (pad reply)   version info
port50023.bin   2    4    0x05    1:1          (pad reply)   value 0x0c
port50023.bin   2    4    0x21    0:1          (pad reply)   undocumented
port50023.bin   2    5    0x02    0:1          (pad reply)
port50023.bin   2    5    0x06    772:5        (pad reply)   UIC fw version + 768 B EEPROM
port50023.bin   2    5    0x0c    0:2          (pad reply)   EEPROM write ack
port50123.bin   0    0    0x00    0:3          (console query)
port50123.bin   0    0    0x10    32:1
port50123.bin   0    0    0x11    312:1,1028:778
port50123.bin   0    0    0x12    32:1
port50123.bin   0    4    0x04/0x05/0x1a/0x21
port50123.bin   0    5    0x02/0x06/0x0c
```

Presence check for every update-related method — **all ABSENT** from all four `port*.bin` dumps
(50023, 50121, 50123, 50125):

```
svc 0 0x02 start product update              ABSENT
svc 0 0x03 update data                       ABSENT
svc 0 0x04 end product update                ABSENT
svc 0 0x05 abort update                      ABSENT
svc 0 0x0b/0x0c/0x0d/0x0e/0x0f  (TVCode/Service/Screen/Lang)  ABSENT
svc 4 0x01 reboot to mode (FWUPDATE = 2)     ABSENT
```

Also: no local project document records ever sending them (`grep -rn 'product update\|svc 0/0x0[2345]'
SETUP.md PLAN.md RESEARCH.md research/*.md` → only the BOOT-AND-MODES table row for svc 4/0x01). So the
"never tested on this pad" claim in §4/§6 is **VERIFIED-absent**, not assumed.

Two useful incidental measurements from the same sweep (both **VERIFIED** bytes, meaning **UNCERTAIN**):

* svc 4/0x05 (state oracle) answered **`0x0c` = 12** during the real console session — but the documented
  `retvals[]` array has only 12 entries (max value 11), so the oracle's value cannot be `retvals[state]` as
  libdrc describes, or the array is longer/not the one documented. Our own live pad answered `0` in §5.1 of
  `BOOT-AND-MODES.md`. Treat the state oracle as a *correlate-with-eyes* signal, not a decoded state.
* svc 5/0x06's 772-byte reply starts `28 00 00 58` (§1.4) — the pad's UIC firmware version.

### 1.4 Cross-checks that pin the versions

From the same capture, **VERIFIED**:

```
# svc 0 / 0x00 reply, 8 bytes:  running = installed = 0x190C0117  (DRC image version)
19 0c 01 17 19 0c 01 17

# svc 4 / 0x04 reply, 28 bytes:
00 00 00 0b | 00 00 00 40 | 19 0c 01 17 | 28 00 00 58 | 00 08 00 00 | 0c 02 21 fe | 00 00 1c cc
                            ^ image version  ^ UIC fw version (see below)

# svc 5 / 0x06 reply, 772 bytes = u32 UIC fw version + first 768 EEPROM bytes:
28 00 00 58  ...  "WiiUccfb65b68169" ... <PSK hex> ...
```

`0x28000058` appears in both independent replies, and its field layout matches the `UMI_` blob version
encoding in the libdrc changelog (`0x26050051` for system update 4.0.0). So: **our pad runs DRC image
`0x190C0117` with UIC firmware `0x28000058`** — **INFERRED (high)** that these are the two values an update
would change and therefore our acceptance signals.

---

## 2. The artefact: exact image format, CRCs, block sizes

This is the strongest part of the answer, and it is *fully public*. The format comes from
[`GaryOderNichts/drc-fw-patches/fwpack.py`](https://github.com/GaryOderNichts/drc-fw-patches/blob/master/fwpack.py)
(**VERIFIED**, read in full) and is independently corroborated by
[`GaryOderNichts/DRXUtil`](https://github.com/GaryOderNichts/DRXUtil) `source/Firmware.hpp` / `Firmware.cpp`
and by WulfyStylez' drxtool documentation
([gamebrew](https://www.gamebrew.org/wiki/Drxtool_Wii_U),
[GBAtemp 453143](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/)).

### 2.1 `drc_fw.bin` (the file the console flashes) — byte-exact

```
off 0x0000  BlobHeader          (ALL FIELDS BIG-ENDIAN; 0x10 bytes)   <- "a big-endian header used by IOS"
  +0x00  u32be imageVersion          e.g. 0x190C0117 for our pad
  +0x04  u32be blockSize             value not public -> see §8 unknown U1
  +0x08  u32be sequencePerSession    purpose not public
  +0x0C  u32be imageSize             == 0x5000 + len(firmwareData)

off 0x0010  FirmwareHeader      (0x5000 bytes)                        <- little-endian
  +0x0000  u32le type                0x01010000 = DRC, 0x00010000 = DRH
  +0x0004  u32le superCRC[4]         crc32 over each 0x1000-byte chunk of the subCRC table
  +0x0014  ..pad..  to 0x0FFC
  +0x0FFC  u32le headerCRC           crc32 over header bytes 0x0000..0x0FFB
  +0x1000  u32le subCRC[0x1000]      one crc32 per 0x1000-byte (4096 B) block of firmwareData

off 0x5010  firmwareData
  +0x0000  section table ("INDX"): N x 16 bytes, per entry:
             u32le offset (relative to firmwareData start)
             u32le size
             char[4] name
             u32le version
           stock order and count: INDX, VER_, LVC_, WIFI, ERR_, UMI_, IMG_  -> N = 7, table = 0x70 bytes
  +0x0070  section payloads
```

Three derived rules, all **VERIFIED** from `fwpack.py`'s implementation:

1. **CRCs are plain zlib CRC32** (`binascii.crc32`) — no key, no nonce, no MAC, **no signature field anywhere
   in the header**. The header is *exactly* 0x10 + 0x5000 bytes and every byte of it is accounted for.
2. **The granularity that the pad can verify is 0x1000 bytes**, because `subCRCs` has one entry per 0x1000-byte
   block of `firmwareData` (0x1000 entries reserved; the last one covers a short tail).
3. **Rebuilding is mechanical**: change section bytes → recompute subCRCs → recompute superCRCs → recompute
   headerCRC → fix `imageSize`. That is exactly what `build_firmware_header()` does, and DRXUtil does the same
   in C++.

### 2.2 What travels over the air vs what lands on flash

drxtool's own instructions (GBAtemp 453143, bold added):

> "Other update methods include potentially using **libdrc to push an update directly to the GamePad
> (strip the first 0x10 as this is a big-endian header used by IOS)**, or by **writing the payload directly to
> the serial EEPROM (strip the first 0x10+0x1000+0x4000)**, which is useful for unbricking."

That single sentence resolves the most important structural question:

| Artefact | Bytes |
|---|---|
| Full `drc_fw.bin` | what lives on the console's MLC (inside the update title's `content/drc_fw.bin`) |
| **Over the DRC link** | `drc_fw.bin[0x10:]` — i.e. the 0x5000-byte header **plus** all sections |
| **On pad SPI flash at partition base** | `drc_fw.bin[0x5010:]` — i.e. the section table + sections only |

So the pad receives the CRC table too, which is what lets it verify each block locally. **INFERRED (high)** —
this is the only structure in which the pad can check `subCRC[i]` for a block it just received.

Sizes, from the libdrc changelog (`changelog.rst`, **VERIFIED**): LVC_ 682872, WIFI 250790, ERR_ 441688,
UMI_ 28351, IMG_ 1428246 → `firmwareData` ≈ **2.83 MB**, painted image ≈ 2.85 MB. At 1024 data bytes/packet
that is ≈ **2 850 `0x03` packets**; the console's command cadence in our capture is 7–29 packets/s for bulk
traffic, so an update is expected to take **~2–7 minutes** of command-plane time. **INFERRED.**

On-flash layout of the launch firmware, as measured by a scene member in that same GBAtemp thread
(**VERIFIED as a quoted 32 MB hardware dump**, **UNCERTAIN as to completeness**): with the partition at
0x0100000 — INDX at `0x100000`, LVC at `0x100070`, VER at `0x100070` (sic), WIFI at `0x195AD8`,
ERR at `0x1D2D8E`, UMI at `0x23EEEE`, IMG at `0x245830`. The arithmetic that matters is corroborated by
`flash_layout` (below): the section table sits *at the partition base* and the first section's data starts
right after the 0x70-byte table.

### 2.3 Block numbering, block size, per-block CRC — what is known vs what is inferred

| Property | Value | Confidence |
|---|---|---|
| `0x03` payload = `u32 block_idx` + data | yes | **VERIFIED** (libdrc table) |
| Max `0x03` payload = 1028 = 4 + **1024** | ⇒ **data unit is 1024 bytes per block** | **INFERRED (high)**: 1028 is otherwise an inexplicable number; 1024 is the only natural split |
| Max outer UDP payload observed on the cmd plane | **1048** = 8 (CmdHeader) + 12 (GenericCmdHeader) + 1028 | **VERIFIED** (`port50123.bin`, 778 × 1048-byte datagrams) |
| libdrc's own hard cap | `kMaxCmdPayloadSize = 1400` ⇒ generic payload ≤ 1388 | **VERIFIED** (`include/drc/internal/cmd-packet.h`) |
| Per-block CRC | crc32, one per **4096-byte** block of `firmwareData` (`subCRCs[0x1000]`) | **VERIFIED** in the file format; that the *pad* checks them per received block is **INFERRED** |
| `block_idx` numbering base (0 or 1) | unknown | **UNCERTAIN** |
| `block_idx` unit (1024 B vs 4096 B) | 1024 B most consistent with the 1028-byte payload | **INFERRED** |
| `blockSize` field in BlobHeader | unknown (0x400 and 0x1000 are the only plausible values) | **UNCERTAIN** |
| Whether `block_idx` is relative to the *painted image* (starting inside the 0x5000 header) or to `firmwareData` | unknown | **UNCERTAIN** |

Precedent for "u32 index + bulk data, gaps detectable": the console's svc 0/0x11 push uses **exactly** the
same shape — `u32 index` running **1…778 with zero gaps**, one per datagram, 1028 data bytes
(`BOOT-AND-MODES.md` §7b, **VERIFIED** locally). Two independent confirmations of the pattern in this
protocol family:

* the index is *per datagram*, monotonically increasing, and the pad asked for nothing (it ACKed each packet);
* grouping into logical messages uses the GenericCmdHeader `tid`/`fid`/final-bit, measured layout
  (**VERIFIED** against both `port50123.bin` and libdrc's codec):

```
tid  = (b2<<8 | b3) >> 4            (12 bits,  per message, increments per message)
final= (b3 >> 3) & 1                (bit 3 of byte 3)
fid  = ((b3 & 0x07) << 8) | b4      (11 bits, 0,1,2,… within a message)
flags: 0x40 query / 0x42 continuation ("more follows") / 0x09 reply
```
Measured example of one 4-fragment console message (svc 0/0x11), **VERIFIED**:

```
00 00 00 00 10 04 0f 00  7e 01 01 b0 00 42 00 11 00 00 04 04  00 00 00 01 ...   tid 0x01b fid 0 final 0
00 00 00 00 10 04 10 00  7e 01 01 b0 01 42 00 11 00 00 04 04  00 00 00 02 ...   tid 0x01b fid 1 final 0
00 00 00 00 10 04 11 00  7e 01 01 b0 02 42 00 11 00 00 04 04  00 00 00 03 ...   tid 0x01b fid 2 final 0
00 00 00 00 10 04 12 00  7e 01 01 b8 03 40 00 11 00 00 04 04  00 00 00 04 ...   tid 0x01b fid 3 final 1
```

(The outer `seq` increments per *datagram* here, contradicting the doc's "stays the same between packets of
the same request" — use the measured behaviour.)

### 2.4 Completion / verification sequence (console side, decoded from DRXUtil)

`DRXUtil source/screens/FlashScreen.cpp` (**VERIFIED**, read in full) is the only public implementation of a
DRC flash and it shows the *semantic* sequence that the pad-side methods must implement. Reading it as the
console's state machine:

```
1. CCRSysCaffeineSetCaffeineSlot(0xff)          # "invalidate caffeine"; only for images >= 0x180a0000
2. CCRCDCSoftwareAbort(DRC0)                    # ~ matches svc 0 / 0x05 (abort)
3. ReattachDRC(DRC0, CCR_CDC_DRC_STATE_FWUPDATE)  # ~ matches svc 4 / 0x01 payload 2
   -> CCRCDCSysSetDrcState(state.state = FWUPDATE)
   -> __CCRSysWaitReattach(...)                 # waits for the pad to come back on the link
   -> WaitForEeprom(slot)                       # CCRCFGGetCachedEeprom must answer
   -> CCRCDCSysGetDrcState() must now equal FWUPDATE
4. CCRCDCSoftwareUpdate(DRC0, path, cb)         # ~ matches svc 0 / 0x02 + N x 0x03
   poll CCRCDCGetFWInfo().updateProgress (0..100 %) every 200 ms
5. on callback success -> CCRCDCSoftwareActivate(DRC0)   # ~ matches svc 0 / 0x04 (+ reboot)
6. ReattachDRC(DRC0, CCR_CDC_DRC_STATE_ACTIVE)  # "put the gamepad back into active mode"
   on any failure      -> CCRCDCSoftwareAbort + Reattach(ACTIVE)
```

Mapping each console API onto the documented pad methods is **INFERRED**, but the 1:1 shape is strong: the
pad exposes exactly "abort", "start", "data", "end", and the console exposes exactly "abort", "update",
"activate" plus a DRC-state enum that contains a `FWUPDATE` value and a `STANDALONE` value. Note step 3→4
proves the *pad is expected to remain reachable over the DRC link while in firmware-update state*: the
update is streamed over the very link being negotiated. See §5.

Two safety-relevant lines in DRXUtil (**VERIFIED**):

* `// Don't allow downgrading lower than the version on NAND, otherwise this might cause bricks without
  flashing the language files?` and the same check against `originalFirmwareHeader.version` — i.e. the
  console-side library refuses a downgrade. Assume the pad does too.
* drxtool: *"Updating VER_.bin is unnecessary, as the GamePad and drh are **indifferent to their versions;
  only IOS matters**."* ⇒ version *labels* are not what the pad verifies; the CRCs are.

`updateProgress` (step 4) is a pad-sourced percentage — the console sees it via `CCRCDCGetFWInfo`, so the pad
does report progress. Whether that number comes out of one of the documented `0x03` **replies** (which are
4 bytes each!) is unknown; a 4-byte reply per block is exactly enough for `u32 accepted_blocks` or
`u32 status`. **INFERRED** — and it gives us a per-block acceptance signal for free.

### 2.5 What service 0 methods 0x0b–0x0f are, and why they are the dangerous ones

`0x0b`/`0x0c` (9-byte start / 0-byte end) target **TVCode / Service / Screen1 / Screen2**; `0x0d`–`0x0f` target
the **language banks**. These correspond to the flash regions in `flash_layout`: TVcode `0x1900000`,
Screen1 `0x1B00000`, Screen2 `0x1B80000`, Lang1 `0x900000`, Lang2 `0x1100000`, **Service `0x1C00000`**.

* "Service" here is the **diagnostics firmware partition at 0x1C00000** that the SPL boots when UIC state = 7.
  Overwriting it destroys Nintendo's own recovery payload on our pad.
* The UIC/language updates touch the **UIC's own firmware** (`UMI_`) path, and the kuribo64 wiki documents that
  upload as *untested and irreversible-by-design*: "WARNING: the following is **theoretical and has not yet
  been successfully replicated so far. A firmware upload gone wrong can and will brick the UIC.**" plus, on UIC
  command `0x09` (begin firmware update): "the UIC **remembers the 'waiting for firmware update' state even
  after a full power-off**." ([kuribo64 uic](https://kuribo64.net/wup/doku.php?id=uic))

**Recommendation: never send 0x0b–0x0f on this pad.** They buy nothing for our objective (0x02–0x05 replaces
LVC, which owns the LCD) and they can leave the UIC waiting for a firmware that we cannot deliver
(the UIC firmware upload additionally requires the stock LVC to run the SPI bootloader dance with a CRC on
every one of ~220 × 128-byte chunks).

---

## 3. Is there any signature or encryption on LVC_/UMI_/WIFI? (the three-way distinction)

**Answer: structural absence, corroborated by working prior art.** Not "nobody looked", and not "present but
bypassed with a key". The evidence is positive and threefold.

**(a) The image format has no room for one — VERIFIED.**
`fwpack.py` defines `FirmwareHeader` as `type + superCRC[4] + 0xFE8 padding + headerCRC + subCRC[0x1000]` =
exactly 0x5000 bytes, and `BlobHeader` as four big-endian u32 = 0x10 bytes. Every byte is named and verified by
`verify_firmware_header()`, which only recomputes CRC32s. There is no signature block, no key id, no MAC, no
"encrypted" flag. `FirmwareType` has two values (DRC/DRH) and nothing else. Compare with the console's own
titles, which *are* signed (Wii U title encryption/signatures) — the DRC image is not built that way.

**(b) The pad boots *modified* LVC images on real hardware today — VERIFIED prior art.**
`DRXUtil` is a shipped, released Wii U homebrew whose headline feature is: "This option allows flashing a new
firmware to the Gamepad (DRC). DRXUtil comes with built-in patches which can be applied to the original
firmware. These patches allow writing to EEPROM values which are usually inaccessible. The gamepad startup
screen is modified to show **'Modified Firmware'** while this firmware is installed."
([DRXUtil README](https://github.com/GaryOderNichts/DRXUtil)) The patches are concrete code edits
(`FlashScreen.cpp::PatchFirmware`): jumptable bytes at LVC file offsets `0x0003c9c4` and `0x0003c9c7`, config
table entries at `0x000b28d0..`, a bitmap blit into IMG_ resource `0x2001`, and `VER_` set to `0xFE000000`.
It then CRC-checks the *result* against known-good **modified** CRCs (`0xd13694f3` JPN / `0xb0aed5b6` USA /
`0x2d177dfb` EUR) and flashes it. A pad that demanded a Nintendo signature would reject every one of those.
The documented condition for the built-in patch is `imageVersion == 0x190c0117` — **the exact image version our
pad reports** (§1.4).

**(c) The only checks in the ecosystem are CRC + an anti-downgrade rule — VERIFIED.**
drxtool (2016): "to flash binaries with ios-level hax, try bumping up the first big-endian u32 in
blob_header.bin by 1, as well as bumping up the version in app.xml." — i.e. the *only* gate encountered in
practice was the console's IOS version comparison. DRXUtil's downgrade guard is on the *console* side
(`mFirmwareHeader.version < originalFirmwareHeader.version`).
WulfyStylez' 2016 tool and Gary's 2025 tool both rebuild and reflash arbitrary images.

**What is still unproven for *our* path (be precise):**

| Statement | Status |
|---|---|
| LVC_/WIFI/UMI_/IMG_/ERR_ carry no signature or encryption | **VERIFIED** (format + patches accepted on hardware) |
| The *pad* (not the console) accepts a CRC-valid modified image pushed over **wifi** | **INFERRED (very high)** — it is the same artefact the console flashes; the pad is the component that runs it |
| The pad does not additionally authenticate against something in the console's DRH identity | **INFERRED absent** — nothing in the artefact can reference it; but not directly tested |
| Nobody documented it because nobody tried | **No** — it *is* documented implicitly by two working tools; the wifi transport details are the undocumented part |

---

## 4. Which volume is written, is a bad image recoverable, and what is the realistic brick risk

### 4.1 Flash map (verified, two independent sources)

[`kuribo64.net/wup flash_layout`](https://kuribo64.net/wup/doku.php?id=flash_layout) (**VERIFIED**;
"internal names come from the diagnostics firmware's FLASH viewer utility"), cross-checked against
`research/libdrc/web/docs/re/boot.rst`:

| Offset | Internal name | Meaning |
|---|---|---|
| `0x0000000` | SPL | second-stage bootloader (4-byte LE length at 0x0, vectors at 0x4→0x0, code at 0x44→0x3F0000) |
| `0x000E000` | ErrorLog | error data subsector |
| **`0x000F000`** | **Bank** | **active firmware partition selector** |
| **`0x0100000`** | **Product1** | **firmware partition 0** |
| **`0x0500000`** | **Product2** | **firmware partition 1** |
| `0x0900000` / `0x1100000` | Lang1 / Lang2 | language banks |
| `0x1900000` | TVcode | remote-control data |
| `0x1B00000` / `0x1B80000` | Screen1 / Screen2 | ? |
| `0x1C00000` | **Service** | **diagnostics firmware** |
| `0x1FDE000` … `0x1FF0000` | InspData / Seq&Conf / InspLog1 / InspLog2 | diagnostics only |

SPL policy, quoted verbatim: *"If the UIC state is **7**, the diagnostics firmware is loaded. Otherwise, the
byte at **0xF000** indicates which firmware partition to load from: **0 = 0x100000, 1 = 0x500000**"*, and
*"the second stage bootloader assumes the **third** entry to be the ARM9 binary, and loads it at 0x0 in main
RAM"* (entry order INDX, VER_, **LVC_**, WIFI, ERR_, UMI_, IMG_). `fwpack.py::pack_firmware` enforces the same
two invariants (`sections[0].name == "INDX"`, `sections[2].name == "LVC_"` → *"This firmware is not
bootable!"*).

Note the correction versus `boot.rst`: libdrc guessed a "debugging device on the extension port"; the
authoritative trigger is **UIC state 7**, and the extension port (I2C USB jig) is only how Nintendo *gets* the
UIC into that state ([kuribo64 uic](https://kuribo64.net/wup/doku.php?id=uic), "Expansion port").

### 4.2 Which partition does an update write?

**A/B, write-inactive-then-flip: INFERRED (strong), not documented anywhere.**
Evidence for: two equal 4 MB partitions with a single one-byte selector named "Bank"/"Active firmware
partition"; the console-side flow ends in `CCRCDCSoftwareActivate()` — an *activate* step that is separate from
the data transfer, which only makes sense if the image is staged and then selected; `DRXUtil`'s
`CCRSysCaffeineSetCaffeineSlot(0xff)` is described as "invalidate caffeine", i.e. invalidating a *slot*.
Evidence against: nothing published describes the swap; `sequencePerSession` (a BlobHeader field) is
unexplained and might be part of the same bookkeeping.

Consequences we can plan around either way:
* if it is A/B: an interrupted update leaves the running image intact at the other base — recoverable by
  power-cycling, which is the whole point of the design.
* if it is in-place: an interrupted LVC write leaves a corrupt LVC_ at the active base → SPL loads garbage at
  0x0 → the pad does not reach the radio → **only UART boot / external flash repair recovers it**.

The cheapest way to disambiguate without writing anything: after an update, read the *other* partition (both
`VER_` versions) — but that needs the Service firmware's flash viewer. So in practice: **assume the worse case
until the UART harness works** (see §7, §6.0).

### 4.3 Recovery paths, ranked by evidence quality

| # | Path | Evidence | Cost |
|---|---|---|---|
| 1 | **UART boot** from the 4-pad header under the battery connector — boot ROM loads a blob over UART1 into RAM at 0x0 and runs it, no flash involved | **VERIFIED**: [wiiubrew GamePad §UART header](https://wiiubrew.org/wiki/GamePad) (*"This functionality could be used to restore a bricked Gamepad"*), [kuribo64 uart](https://kuribo64.net/wup/doku.php?id=uart) + [test_points](https://kuribo64.net/wup/doku.php?id=test_points) (TP229/TP237 = UART-boot enable, TP231/232 = UART1 TX/RX) | open the pad, 2.8 V USB-serial, ground pad 2 |
| 2 | **Re-write the flash directly** (external SPI programmer on TP36/37/38/40, or FPGA flash emulation) | **VERIFIED** as prior art: drxtool ("writing the payload directly to the serial EEPROM … useful for unbricking"), [kuribo64 fpgapad](https://kuribo64.net/wup/doku.php?id=fpgapad) | desolder / clip the Micron 25Q256A |
| 3 | **Service/diagnostics firmware** at 0x1C00000 (UIC state 7) — has a "FLASH viewer utility" and UIC menu | **VERIFIED** that it exists and how it is selected; **not** verified reachable from a dead-LVC state (the LVC is what commands the UIC) | must be entered *before* the failure, or via EEPROM tricks |
| 4 | **EEPROM-driven service mode** — board config bits 0–1 ≠ 1 ⇒ "the gamepad will enter service mode upon boot"; shipment-unshipped ⇒ "only boot into the Service Menu" | **VERIFIED** as documented behaviour ([uic_eeprom_structure](https://kuribo64.net/wup/doku.php?id=uic_eeprom_structure), DRXUtil README); **UNCERTAIN** whether the *stock* LVC lets us write those EEPROM IDs over cmd svc 5/0x0c (DRXUtil needs an LVC patch precisely because it does not) | cheap to *test* read-only-ish; writes EEPROM |
| 5 | Console-side re-flash (DRXUtil with our own homebrew on the console) | **VERIFIED** working tool | needs a homebrew-capable console — we own one |

### 4.4 Brick risk of an experiment, honestly stated

The risk is **staged**, and the stages have very different consequences:

| Stage | Action | Worst case | Recoverable? |
|---|---|---|---|
| **P0** | read-only probes (svc 0/0x00, 4/0x04, 4/0x05, 1/0x05, 5/0x06, 5/0x15) | none | n/a |
| **P1** | svc 0/0x05 (abort) and svc 0/0x04 (end) with nothing in progress | pad replies with an error code; no state change expected | yes |
| **P2** | svc 4/0x01 payload `2` — reboot into firmware-update mode | pad reboots into FWUPDATE state; if that state does not bring up the radio, **the pad is off the air until power-cycled — and if it persists, only UART boot recovers it**. | probably; this is the "commitment point" |
| **P3** | svc 0/0x02 + one `0x03` with **deliberately wrong data** (bad CRC) | should be rejected by the CRC check; if the pad instead writes it, we have written one 1 KB block of the *inactive* (or active) partition | likely yes (1 block of the LVC area, and only if numbered inside it) |
| **P4** | full image push + svc 0/0x04 | if A/B: old image survives, SPL keeps booting it. If in-place and interrupted: **dead pad, UART only** | depends on §4.2 |
| **P5** | svc 0/0x0b–0x0f (Service / UIC / Lang / Screen / TVCode) | UIC stuck in "waiting for firmware update"; Service partition destroyed | **no** (UIC upload is documented as unreplicable; Service partition is Nintendo's own recovery firmware) |

Two published warnings that back P2's and P4's risk, **VERIFIED** quotes:

* melonpad README: *"the only way to upload code to the gamepad is via the wifi update functionality. However,
  this requires having a functional stock firmware running on the gamepad. **IF YOU UPLOAD THIS TO YOUR
  GAMEPAD, YOU WILL BE UNABLE TO RESTORE IT TO STOCK FUNCTIONALITY, OR UPLOAD A NEW BINARY, UNLESS YOU RESORT
  TO HARDWARE MODDING.**"* ([melonpad](https://github.com/Arisotura/melonpad))
* kuribo64 fpgapad: *"Since the firmware runs on the bare metal, **you need a functional firmware to do
  anything, including uploading new code to the gamepad.** This excludes any sort of reverse-engineering work
  because it would be way too easy to brick the gamepad."*

Note that both quotes are about pushing *custom, non-update-protocol* code. Our path is different in one
important way: we would push a **structurally valid update image** that the pad's own update path installs,
which is why A/B + CRC verification is likely to protect us. That difference is exactly the value of this
route — but it is **INFERRED**, not measured.

---

## 5. What happens to the network when the pad enters firmware-update mode

There is **no published description** of the pad's networking in FWUPDATE mode. Here is the evidence that
constrains the answer, then the inference.

**VERIFIED constraints:**

1. The console streams the whole image over the DRC link *after* putting the pad in FWUPDATE state
   (`DRXUtil` step 3 → 4). If the pad dropped off the link, Nintendo's own update could not work. ⇒ **the pad
   must be reachable over the DRC wireless link in update mode.**
2. `ReattachDRC()` calls `__CCRSysWaitReattach()` and then `WaitForEeprom()` (reads EEPROM through the DRC
   channel), and finally asserts `CCRCDCSysGetDrcState() == FWUPDATE`. So the console's model is: *the pad
   tears down and re-establishes the DRC link, and announces its new state*.
3. The firmware, not the bootloader, brings up the radio: *"The firmware is responsible for loading the
   BCM4319 and UIC firmwares. The BCM4319 firmware needs to be loaded on each boot."*
   ([flash_layout](https://kuribo64.net/wup/doku.php?id=flash_layout)) — so whatever runs in update mode must
   load the `WIFI` blob itself, from flash, every time.
4. The UIC has a dedicated state for this: **state 6 = "FWUpdate"**, and it is reachable from state 0 (Active)
   — i.e. the running LVC can command it without a full reboot-and-fall-over path
   ([kuribo64 uic](https://kuribo64.net/wup/doku.php?id=uic), state table row 0: X at columns 1,3,4,5,6,8,9,10,11,14).
5. The BCM4319 runs a **full-MAC Broadcom firmware with a custom WPA implementation** that only supports 5 GHz
   and "doesn't support standard WPA" ([kuribo64 wifi](https://kuribo64.net/wup/doku.php?id=wifi)). There is no
   separate "update-mode AP blob" documented anywhere; the blob is loaded from flash each boot, so an update
   mode that also wanted Wi-Fi would load the same blob we already satisfy.

**INFERRED (high):**

* The pad **stays on the same DRC network and re-associates** using the same Nintendo-selector WPA2 with the
  same PSK from UIC EEPROM. Our AP must therefore be up *before* we send svc 4/0x01 payload 2, and it must keep
  beaconing the console's cloned BSSID/hidden SSID throughout.
* The pad will most likely **re-DHCP** (a fresh association normally means a fresh lease request; the console's
  DHCP answered `.11` in the truth capture). Our DHCP must be running; the IP may or may not stay `.11`.
* While in FWUPDATE mode the pad probably **stops** the normal services we rely on (no input on 50122, no video
  or audio handling, no state pushes) but **keeps `sc_cmd` on 50123** — because the update traffic *is* `sc_cmd`.
  Consequence for us: after P2, the only signal to watch is "do `svc 0/0x00` probes still answer, and with what
  installed-version".
* The UIC state during an LVC update is most plausibly **6 (FWUpdate)**, *not* 7 (Service). 7 is documented to
  make the SPL load the diagnostics firmware, which is not what an over-the-air update wants. **UNCERTAIN**
  whether the pad reboots at all in P2 (state 0→6 is an allowed live transition, so the "reboot" in libdrc's
  wording for svc 4/0x01 might be a soft state change plus a service restart).

**The cheapest measurement** that resolves this whole section is P2 itself plus passive observation: send
svc 4/0x01 payload 2, then watch (a) `iw dev` / hostapd log for deauth/reassoc, (b) the DHCP server log for a
new DISCOVER/REQUEST, (c) whether `svc 0/0x00` answers again and how long it takes, (d) whether traffic on
50122/50120 stops. That is one datagram in, ~30 s of observation, and it is the single most informative
experiment in this document — see §6 P2.

---

## 6. Ordered experiment plan (read-only first; nothing destructive until UART works)

Preconditions, all on our side, none touching the pad:

* the pad is paired to **our** PSK (`run/pairing.env`) — check with svc 1/0x05 (T2 in `BOOT-AND-MODES.md` §10);
* our AP + DHCP are up (`run/drc-up.sh`), the **console is unplugged** (identity collision, §8 of BOOT-AND-MODES);
* **exactly one** socket owns `192.168.1.10:50023` — `run/drc-down.sh` first, then our tool, nothing else
  (`BOOT-AND-MODES.md` §5.1 records a real failure caused by two `SO_REUSEADDR` binders);
* **the UART harness is built and tested on the pad before any P3+ step** (§7). Opening the pad is a
  prerequisite for experimentation, not a recovery-after-the-fact option.

All packets below use the **verified** field layout (outer `<HHHH>` little-endian, generic header mixed
endianness, `7e 01 | tid_hi | tid_lo<<4|final<<3|fid_hi | fid_lo | flags | svc | method | be16 err | be16 len`).
Hex strings are the exact bytes to put on the wire, generated by the same builder that `run/pad-state.py` and
`run/command-plane.py` already use.

### P0 — read-only baseline (zero risk)

Send from `192.168.1.10:50023` to `192.168.1.11:50123`; expect an 8-byte type-1 ACK, a type-2 reply, then
send the 8-byte type-3 ACK. `seq` in the examples is arbitrary but must match within one exchange.

```python
# svc 0 / 0x00  — LVC version (running, installed)          reply 8 B
00 00 00 00 0c 00 64 00  7e 01 00 08 00 40 00 00 00 00 00 00      seq=100
# svc 4 / 0x04  — version information                      reply 28 B
00 00 00 00 0c 00 65 00  7e 01 00 08 00 40 04 04 00 00 00 00      seq=101
# svc 4 / 0x05  — state oracle                             reply 1 B
00 00 00 00 0c 00 66 00  7e 01 00 08 00 40 04 05 00 00 00 00      seq=102
# svc 1 / 0x05  — SSID/PSK as stored                      reply 113 B
00 00 00 00 0c 00 67 00  7e 01 00 08 00 40 01 05 00 00 00 00      seq=103
# svc 5 / 0x06  — UIC fw version + 768 B EEPROM           reply 772 B
00 00 00 00 0c 00 68 00  7e 01 00 08 00 40 05 06 00 00 00 00      seq=104
# svc 5 / 0x15  — LCD brightness                           reply 1 B
00 00 00 00 0c 00 69 00  7e 01 00 08 00 40 05 15 00 00 00 00      seq=105
```

Record and *save to a file*: image version (expect `0x190C0117`), UIC fw version (expect `0x28000058`),
state byte, 772-byte EEPROM blob, brightness. These are the "before" values that make acceptance objective
later.

Also snapshot, without the pad: on the console, copy `storage_mlc01:/usr/tmp/drc_fw.bin` (or the update
title's `content/drc_fw.bin`) and run `fwpack.py unpack` on it. That hands us `blobHeader.blockSize`, the
stock section versions, and the **exact stock image** we can always re-flash. This step is free and it removes
unknowns U1/U2 (§8) offline.

### P1 — state probes on the update methods themselves (no data, no flash address computed)

```python
# svc 0 / 0x05  — abort update (nothing in progress)        reply 0 B
00 00 00 00 0c 00 6a 00  7e 01 00 08 00 40 00 05 00 00 00 00      seq=106
# svc 0 / 0x04  — end product update (nothing in progress)  reply 4 B  (documented)
00 00 00 00 0c 00 6b 00  7e 01 00 08 00 40 00 04 00 00 00 00      seq=107
```

Acceptance/state signals: reply `error` field (generic bytes 8–9, big-endian) is authoritative; a reply of 4
bytes to 0x04 gives a second code. **Expected** on a pad that is not in update mode: a non-zero error, i.e.
"no update in progress". If instead 0x04 returns 0 and 0x05 returns silently, the methods are *unconditional*
— which is itself an important finding, and it means 0x04 alone must never be sent after a partial push.

Do **not** send 0x03 at this stage: 0x03 computes a flash address from `block_idx`, and we do not yet know its
base or unit (§2.3), so an unannounced 0x03 is the only "read-only-looking" packet here that can actually
write.

### P2 — the state transition (commitment point; needs UART harness ready)

```python
# svc 4 / 0x01 payload 0x02 — reboot to firmware update mode   reply: unknown (doc says "XXX")
00 00 00 00 0d 00 6c 00  7e 01 00 08 00 40 04 01 00 00 00 01 02  seq=108
```

Observe for 60 s (this is §5's measurement):

1. hostapd log: deauth/reassoc of the pad's MAC;
2. DHCP log: new DISCOVER/REQUEST, and whether the address is still `.11`;
3. our one socket on 50023: does `svc 0/0x00` (P0 packet, new seq) answer again, after how many seconds;
4. ports 50122/50120: does input/media traffic stop;
5. `svc 4/0x05` return value (record it — this is the FWUPDATE-mode state byte we are looking for).

Recovery if the pad does not come back in 2 min: power-cycle the pad (hold power ~10 s). If two power cycles
do not restore the link, go to §7 (UART). Note libdrc's `svc 4/0x01` payload `0` = "reboot to normal mode" as
the intended undo — it is only usable if the pad is still on the air.

```python
# svc 4 / 0x01 payload 0x00 — back to normal mode (the undo)   seq=109
00 00 00 00 0d 00 6d 00  7e 01 00 08 00 40 04 01 00 00 00 01 00
```

### P3 — one block, deliberately wrong (proves the state gate and the CRC rule)

Only after P2 works and the pad is confirmed back on the air. Purpose: learn (a) whether 0x02 is required
first, (b) whether the pad answers each 0x03 with 4 bytes, (c) what a bad block yields.

```python
# svc 0 / 0x02 — start product update. Payload 4 bytes; MEANING UNKNOWN (§8 U3).
# First attempt: the image version we intend to push, big-endian, matching the BlobHeader field.
00 00 00 00 0c 00 6e 00  7e 01 00 08 00 40 00 02 00 00 00 04 19 0c 01 17   seq=110 (~=0x190C0117)
# svc 0 / 0x03 — one block, block_idx 0, 4 data bytes of 0xAA (payload = 8, not 1028)
00 00 00 00 14 00 6f 00  7e 01 00 08 00 40 00 03 00 00 00 08 00 00 00 00 aa aa aa aa  seq=111
# svc 0 / 0x05 — abort (the undo)
00 00 00 00 0c 00 70 00  7e 01 00 08 00 40 00 05 00 00 00 00   seq=112
```

Interpretation table:

| Observation | Meaning |
|---|---|
| 0x02 replies 0 with no error, then 0x03's 4-byte reply is non-zero | the pad is streaming-verifying; block_idx semantics still unknown but the channel is live |
| 0x03 reply is `error 0x????` | the pad rejected the block (bad CRC, or wrong base/unit) — **we learn the error vocabulary**, which is the goal |
| 0x03 accepted a 4-byte payload with block_idx 0 | the pad tolerated a short block ⇒ data length is taken from the payload size, and a 0xAA block was written into block 0 of *something*; abort immediately and re-read P0 versions |

### P4 — full image (only with UART harness proven, and preferably on a second/donor pad)

Ordered, and every step gated on the previous one's reply being clean:

1. Build the image we intend to push. Two candidate objectives:
   * **(safe)** stock image, bit-identical, only `imageVersion` bumped — proves the transport without changing
     pad behaviour at all. **Do this first.**
   * **(the real goal)** a patched LVC (e.g. `DRXUtil`'s built-in patch set, or our own patch that makes
     `mc_video` treat the incoming stream as armed — the direct answer to the display gate).
2. `fwpack.py pack` → verify `verify_firmware_header()` passes; compute `crc32` of the file and record it.
3. Strip `0x10` (drxtool rule) → that is the byte stream to push.
4. `svc 0/0x02` with the 4-byte payload (U3), then `0x03` for `ceil(len/1024)` blocks at the console's
   observed cadence (**~7–29 packets/s measured**; do not exceed it — the pad's command handler is an ARM926
   at 400 MHz-class doing SPI flash writes), ACKing? — **no**: our side only sends type 0 and answers type 2
   with type 3; the pad's ACKs are type 1.
5. On every 0x03, require a type-1 ACK (retransmit on loss, as the console does: "Until an ACK is received,
   DRH/DRC will retry sending"). If a packet is lost and we skip it, the pad's per-block CRC must reject the
   image at the end — that is the safety net, and also the reason a correct in-order transfer matters.
6. `svc 0/0x04` → 4-byte reply. Then poll `svc 0/0x00`: "installed" should change to our imageVersion.
7. `svc 4/0x01` payload `2` then `0` (or a power cycle) to boot the new image; watch the link come back and
   re-run P0. If the pad's startup screen shows our modification, we own the pad.

### P5 — nothing

Do not touch `0x0b`–`0x0f` (Service/TVCode/Screen/Lang) on this pad. §2.5.

### Detecting acceptance, summarised

| Signal | Where | Expected on success |
|---|---|---|
| type-1 ACK per packet | our socket | always present (transport-level) |
| `error` field in the 0x03 reply | generic header bytes 8–9 | 0 |
| the 4 bytes of the 0x04 reply | reply payload | 0 / success code (**UNCERTAIN**) |
| `svc 0/0x00` "installed" u32 | reply bytes 4–7 | changes to our `imageVersion` |
| `svc 4/0x04` word[2] | reply bytes 8–11 | changes after activation |
| pad's startup screen | eyes on the glass | the patched artwork / our content |
| keyframe-request rate (50110→50010) | passive | drops from ~63/s to ~0 if our LVC also fixes the display gate |

---

## 7. The guaranteed fallback: UART boot

### 7.1 The mechanism (verified, primary source)

[wiiubrew.org/wiki/GamePad](https://wiiubrew.org/wiki/GamePad) — "UART header", quoted verbatim:

> "The Wii U Gamepad features a UART header near the battery connector: 1 (black): RXD · 2 (green): **UART boot**
> · 3 (blue): TXD · 4 (yellow): Vcc (2.8V). Ground can be found in the battery connector or on nearby test point
> TP128. The Gamepad runs this UART at **115200 bauds, with 8 data bits, 1 stop bit, no parity**. The service
> firmware uses this as a serial console … **The Gamepad can also boot code over UART.** Here is how to use this
> feature: Tie the UART boot signal (pad 2) to ground. This enables UART boot. Turn on the Gamepad. It will
> appear to do nothing. Over serial, send **the length of your code blob (4 bytes, LSB first), then send the code
> blob itself**. The code will be **loaded at address 0x0 in RAM**. The first 32 bytes are the **ARM exception
> vectors**. When the code is completely loaded, it will be launched, starting at the reset vector. This
> functionality **could be used to restore a bricked Gamepad**, but also to develop and run custom code."

Corroboration (**VERIFIED**): [kuribo64 uart](https://kuribo64.net/wup/doku.php?id=uart) documents UART1 at
`0xF0004C00`, "connected to the test points under the battery connector, and is used as a debug console by the
diagnostics firmware", the complete register set and the baud-rate formula
(`baudrate = (inputclock/16) * multiplier / divider1 / divider2`; for a 16 MHz input, 115200 = mul 72, div2 625,
div1 1). [memory_map](https://kuribo64.net/wup/doku.php?id=memory_map): *"The boot ROM supports three ways of
loading code: SPI (from FLASH), **UART (from the UART1 serial header)**, and I2C."*
Test points: TP229 / TP237 = UART-boot enable, TP231 = UART1 TX, TP232 = UART1 RX, TP236 = pad-4 Vcc 2.8 V,
TP235/TP128 = GND.

So the loader contract is *exactly* the SPL's contract minus the flash: 4-byte LE length, blob, run at 0x0.
This is not a bootloader exploit; it is a documented product feature.

### 7.2 What code do we need, and how do we make it draw on the panel?

Two viable blob designs:

**(a) The honest minimum: a "hello panel" blob.** Requirements, all documented:

1. **RAM map**: 4 MB main RAM at 0x0, mirrored; boot ROM overlay at 0x0–0xFFF is *disabled* once the CPU is
   reset for the second stage, and writes go to RAM anyway
   ([memory_map](https://kuribo64.net/wup/doku.php?id=memory_map)). Our blob lands at 0x0 and runs in ARM
   state — ARM926EJ-S, so ARMv5TE; build with `-mcpu=arm926ej-s`, no Thumb-only assumptions.
2. **Exception vectors**: first 32 bytes at 0x0 (reset vector jumps to our entry). `fwpack`/SPL convention:
   vectors 0x0–0x1F, code after.
3. **UART debug first** (this is the whole point of the UART path): configure UART1 at `0xF0004C00` +0x14
   (8N1), +0x30 bit0 = enable, +0x24/0x28/0x2C per the baud table, then print. Do this *before* touching the
   LCD — that is exactly the lesson Arisotura records: *"I was pretty much working blindly. My only output was
   the rumble motor GPIO. Getting the LCD to display something requires some amount of initialization, and I
   wasn't really able to debug my faulty init code."* ([fpgapad](https://kuribo64.net/wup/doku.php?id=fpgapad))
4. **LCD controller** at `0xF0009400` (register map from
   [lcd_controller](https://kuribo64.net/wup/doku.php?id=lcd_controller)):
   `+0x00 = 1047` horizontal total, `+0x04 = 510` vertical total, `+0x10 = 96` H start, `+0x14 = 8` V start,
   `+0x18 = 950` H end, `+0x1C = 488` V end, framebuffer `+0x60..+0x6C` (x, w, y, h) `/ +0x70` stride
   `/ +0x74` address (22-bit, must be inside main RAM), `+0x80` display control (**bit 1 = enable display**),
   `+0x0xB0` pixel format, palette at `0xF0009500` (+0x00 index, +0x04 data) if using a palette mode.
   Pixel clock comes from `0xF0000034`. Panel is RGB888 854×480.
5. **The panel itself** needs its own init over I2C / the LCD controller (Arisotura: "Getting the LCD to display
   something requires some amount of initialization"), and the PMIC/backlight enables.
6. **Where to get working code instead of writing it**: [`Arisotura/melonpad`](https://github.com/Arisotura/melonpad)
   already implements exactly this — its README lists "I2C · SPI · **LCD and framebuffer initialization** · DMA ·
   Input" as working, with an `lvgl` UI on top, and the wiki that resulted from it is the reference above. A
   UART-boot blob that prints to UART and paints a solid colour is a weekend port of `melonpad`'s
   `loader_flash/source/wup/` (`crt0.s`, `spi.c`, `flash.c`, `dma.c`, `regs.h`) plus its LCD init.

**(b) The interesting design: a loader, not a test pattern.** melonpad's own roadmap is the right architecture
for us: *"The plan is to eventually provide a loader of sorts, that retains compatibility with the original
firmware update functionality (so new binaries can be flashed this way). The loader would also support launching
the stock firmware, and restoring stock functionality entirely (basically uninstalling the loader)."* A
UART-booted blob that (i) prints over UART, (ii) initialises the LCD, (iii) opens the SPI flash and **serves as
a RAM-resident reflasher** gives us a permanent recovery harness — no soldering beyond the 4-pad header.

### 7.3 Cost, and why it must happen before P3

| Cost item | Detail |
|---|---|
| Opening the pad | battery cover + the 4-pad header near the battery connector; no desoldering. The wiki pins are TP229–TP239, i.e. they are already broken out |
| Adapter | USB-serial at **2.8 V logic** (pad 4 provides 2.8 V Vcc; do not feed 3.3/5 V into it). A level shifter or a 1.8/2.5/3.3-selectable adapter set to 2.5 V is the pragmatic choice |
| UART-boot enable | hold pad 2 to GND at power-on (a jumper wire or a switch you can leave installed) |
| Software | ~200–600 lines of ARM926 bare-metal (or melonpad's existing code, built with an arm-none-eabi toolchain) |
| Risk | low — this path never writes flash; a failed blob just does nothing |
| Payoff | turns every subsequent experiment into a *recoverable* one, which is what makes P4 acceptable at all |

**Judgement:** the UART harness is not a fallback, it is the licence to experiment. §4.2 (A/B vs in-place)
cannot be resolved from public documentation, so the difference between "P4 is safe" and "P4 can brick the pad"
is precisely whether §7 exists yet.

---

## 8. Unknowns, ranked, each with its cheapest resolving test

| # | Unknown | Cheapest resolution | Cost |
|---|---|---|---|
| **U1** | `BlobHeader.blockSize` value, and hence the real block unit on the wire | get `drc_fw.bin` off the console (MLC or update title) and run `fwpack.py unpack`; the field prints as `blockSize` | **free**, no pad involvement |
| **U2** | `sequencePerSession` semantics; whether the pad uses it | same dump + the LVC disassembly below | free |
| **U3** | What the 4-byte `0x02` payload means (image size? image version? blockSize? session id?) | **disassemble the svc-0 handler in `LVC_`**: load `LVC_.bin` in Ghidra/IDA as ARM LE ARMv5TEJ at 0x0, then `explore-file.py` + `find-uitron-apis.py` + `name-funcs-by-src-str.py` from [`drc-re-scripts`](https://github.com/GaryOderNichts/drc-re-scripts), and look for the `sc_cmd`/`mc_cmd` method table and the `mc_nvram` flash routines | free, offline, zero brick risk — **do this before P2** |
| **U4** | `block_idx` base (0/1) and reference point (image start vs `firmwareData` start) | same disassembly; empirically by P3's error codes | free / low |
| **U5** | Whether the pad verifies `subCRC` per block, at the end, or not at all | same disassembly (`mc_nvram`); empirically P3 | free / low |
| **U6** | A/B write-then-flip vs in-place | disassembly of the update completion path (look for a write to flash `0xF000` and a reset); or the Service firmware's flash viewer after one update | free / medium |
| **U7** | Does the link survive svc 4/0x01 payload 2, on the same IP? | **P2**, one datagram | low, needs UART ready |
| **U8** | Whether the svc 4/0x05 oracle's value can be decoded (`0x0c` observed vs documented array of 12) | P0 on our pad vs the capture; build the index→screen table by hand | free |
| **U9** | Whether the pad even consults `VER_`/imageVersion for an anti-downgrade rule | disassembly + one P4 with a bumped version | low |
| **U10** | Does the LVC-in-update-mode load the `WIFI` blob itself (i.e. is `blockSize`/session info needed *before* the link exists) | P2 observation | low |

**The single highest-value action in this whole document** is U3/U4/U5 via disassembly of `LVC_` from our own
console's `drc_fw.bin`. It converts every remaining wire-format question into a fact without touching the pad,
and it is the same corpus that produced libdrc's method table in the first place.

---

## 9. What this changes about the current project plan

1. **The display gate may be irrelevant.** `BOOT-AND-MODES.md` is trying to satisfy a firmware gate inside a
   black box. The update path removes the box: a patched LVC can arm `mc_video`/`drvldc` on our command, or
   simply paint a frame itself. Keep the UVC/UAC and svc 0/0x11 experiments running as the cheap parallel track
   — they cost nothing and one of them may still win — but stop describing the display gate as the *only* route.
2. **This primitive is stronger than "video":** it is persistent, unauthenticated, no-console code execution on
   a device we already talk to. It deserves its own entry in whatever the project calls its findings, with the
   brick risk of §4.4 attached, and it should be gated on the UART harness.
3. **Two cheap wins to bank immediately, no pad risk:** (a) dump `drc_fw.bin` from our console and unpack it —
   U1/U2 answered, and we hold the exact stock image for restoration; (b) run the P0 packet set and save the
   "before" values.
4. **One documentation correction to propagate:** `19 0c 01 17` is the DRC image version `0x190C0117` in
   big-endian, not `385944601`; and the SPL's service-firmware trigger is **UIC state 7**, not "a debug device
   on the extension port".

---

## 10. Evidence index

**Local, read for this document (unmodified):**

| Claim | Path |
|---|---|
| cmd protocol, all svc/method tables, svc 4/0x01 mode payloads, UVC/UAC display rule | `research/libdrc/web/docs/re/sc-cmd.rst` |
| boot chain, INDX blob table, 0x1C00000 service volume, 0xF000 selector | `research/libdrc/web/docs/re/boot.rst` |
| firmware versions/sizes/SHA1 per system update | `research/libdrc/web/docs/re/changelog.rst` |
| drivers/services/managers, `mc_nvram` = "Flash and firmware management (upgrade, etc.)", `mc_video` | `research/libdrc/web/docs/re/overview.rst` |
| `kMaxCmdPayloadSize = 1400`, tid/fid/final codec | `research/libdrc/include/drc/internal/cmd-packet.h`, `src/cmd-packet.cpp` |
| verified packet builder + ACK/round-trip logic | `run/pad-state.py` (and `run/command-plane.py` which reuses it) |
| measured console session, state oracles, port-collision hazard, fragmentation re-parse | `research/GROUND-TRUTH-SESSION.md`, `research/BOOT-AND-MODES.md` |
| svc0/0x00, svc4/0x04, svc4/0x05, svc5/0x06, fragmentation, ACK formats | `out/evidence/truth/port50023.bin`, `port50123.bin` |
| absence of every update method in a real session | new tool `research/rce-hunt/inventory_cmd.py` |

**New files created by this analysis:**

| File | Purpose |
|---|---|
| `research/rce-hunt/inventory_cmd.py` | read-only inventory of every svc/method in the decrypted capture, with the correct tid/fid/final decode, plus the update-method presence check |
| `research/rce-hunt/mine_cmd.py` | read-only generic miner for the `port*.bin` dumps |
| `research/rce-hunt/fetch_page.py` | read-only page-to-text helper used for the citations |
| `research/rce-hunt/pad-update-probe.py` | dry-run-by-default implementation of the §6 P0/P1 packet set (and P2 behind an explicit flag) |

**External, cited with URLs:**

* libdrc command protocol — [garyodernichts.github.io/libdrc/docs/re/sc-cmd.html](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html) · [bitbucket source](https://bitbucket.org/memahaxx/libdrc/src/5c26ba6d45920c8609466d00994e2bb313325ba9/web/docs/re/sc-cmd.rst)
* GamePad hardware, **UART header + UART boot** — [wiiubrew.org/wiki/GamePad](https://wiiubrew.org/wiki/GamePad)
* LVC firmware modules and MMU map — [wiiubrew.org/wiki/GamePad/LVC](https://wiiubrew.org/wiki/GamePad/LVC)
* **Flash layout, partitions, bank byte, boot policy, section table** — [kuribo64.net/wup flash_layout](https://kuribo64.net/wup/doku.php?id=flash_layout)
* **UIC command set, UIC states, firmware upload, expansion port** — [kuribo64.net/wup uic](https://kuribo64.net/wup/doku.php?id=uic)
* UIC EEPROM structure (firmware-install flag `A5 5A` @0x1010, board config → service mode, CRC16 rules) — [kuribo64.net/wup uic_eeprom_structure](https://kuribo64.net/wup/doku.php?id=uic_eeprom_structure)
* UART registers/baud — [kuribo64.net/wup uart](https://kuribo64.net/wup/doku.php?id=uart) · test points incl. TP229/TP237 — [kuribo64.net/wup test_points](https://kuribo64.net/wup/doku.php?id=test_points) · memory map / boot ROM load paths — [kuribo64.net/wup memory_map](https://kuribo64.net/wup/doku.php?id=memory_map)
* LCD controller registers and timing values — [kuribo64.net/wup lcd_controller](https://kuribo64.net/wup/doku.php?id=lcd_controller)
* BCM4319 full-MAC firmware, 5 GHz only, custom WPA — [kuribo64.net/wup wifi](https://kuribo64.net/wup/doku.php?id=wifi)
* FPGApad: why a wifi update needs functional firmware, and how code is normally injected — [kuribo64.net/wup fpgapad](https://kuribo64.net/wup/doku.php?id=fpgapad)
* melonpad: working LCD/framebuffer init, loader plan, brick warning — [github.com/Arisotura/melonpad](https://github.com/Arisotura/melonpad)
* **DRXUtil**: console-side flasher, patched-LVC acceptance, FWUPDATE reattach sequence, EEPROM unlock patches — [github.com/GaryOderNichts/DRXUtil](https://github.com/GaryOderNichts/DRXUtil) (`source/screens/FlashScreen.cpp`, `source/Firmware.hpp`, `source/Firmware.cpp`)
* **fwpack.py**: byte-exact `drc_fw.bin` format, CRC32 rules — [github.com/GaryOderNichts/drc-fw-patches](https://github.com/GaryOderNichts/drc-fw-patches/blob/master/fwpack.py)
* drxtool: "strip the first 0x10" over-the-air, "strip 0x10+0x1000+0x4000" for flash, unbricking — [gamebrew drxtool](https://www.gamebrew.org/wiki/Drxtool_Wii_U) · [GBAtemp release thread](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/)
* DRC RE tooling/method (`explore-file.py`, `find-uitron-apis.py`) — [github.com/GaryOderNichts/drc-re-scripts](https://github.com/GaryOderNichts/drc-re-scripts)
* Scene context on the wifi-update-only limitation — [GBAtemp "Hacking the Wii U GamePad"](https://gbatemp.net/threads/hacking-the-wiiu-gamepad.661890/)
