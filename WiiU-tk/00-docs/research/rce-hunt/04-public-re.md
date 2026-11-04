# Public reverse-engineering review for a GamePad code-execution primitive

**Scope of this document:** open-source / public-information research only, for the owner's own
Wii U console + GamePad pair at `/home/kali/Wiiu`. No network interfaces were touched, no existing
files were modified, nothing was sent to the pad during this pass.

**Goal being served:** we already impersonate the DRH (the console-side half) over the proprietary
5 GHz DRC link — association, 4-way, DHCP, GamePad input, and the `cmd` plane all work against a real
pad — but the pad never paints our video stream. We are looking for a *remotely triggerable*
code-execution primitive on the pad (ARM926EJ-S `LVC_` firmware, BCM4319 Wi-Fi firmware, UIC STM8,
hardware H.264 decoder) that would let us drive the LCD directly.

## Label legend

| Label | Meaning |
|---|---|
| **VERIFIED** | Stated by a primary source (the project's own code, wiki, or documentation), or reproduced by me from source I read directly. Where I quote, the quote is verbatim from the cited page/file. |
| **UNCERTAIN** | One credible source says it, but it is unreplicated, marked provisional/theoretical by its own author, or contradicted elsewhere. |
| **RUMOUR** | Second-hand/journalistic/forum hearsay, or inference I could not trace to a primary source. |
| **CONFLICT** | Two sources disagree; both positions given. |

A note on sourcing: the libdrc RE documentation is published as HTML at
`https://garyodernichts.github.io/libdrc/docs/re/…` and is generated from the reStructuredText in the
libdrc repository. I read and quote that in-tree RST (`web/docs/re/*.rst`) from the local clone at
`research/libdrc` (git remote `https://github.com/opencma/libdrc.git`); the published page names are
given alongside so every quote is independently checkable. The upstream RE documentation historically
lived at `http://libdrc.org/docs/re/` (memahaxx/opencma lineage; a bitbucket mirror of the same RST is
at `https://bitbucket.org/memahaxx/libdrc/src/master/doc/docs/re/`).

---

# 1. GamePad firmware internals and protection

## 1.1 What the four firmwares are

The GamePad contains **three CPUs plus an input MCU**, and its firmware image is a container of named
blobs. libdrc's overview is the canonical statement:

> **DRC-WUP** — "This is the main chip that runs the GamePad firmware. It is also referred to as 'the
> ARM9' or 'the LVC' in this documentation (LVC is the name of the firmware unit ran by DRC-WUP).
> This SoC is based on an ARM926EJ-S CPU and seems to be custom made for this device. It presents no
> external markings that would allow identification of a designed/manufacturer, but it is assumed to
> have been designed by MegaChips Corporation. The hardware H.264 decoder present inside seems to also
> be of a custom design." **VERIFIED** — [overview](https://garyodernichts.github.io/libdrc/docs/re/overview.html)

> **BCM4319XKUBG** — "A Broadcom Wi-Fi chip that is not so custom … The firmware running on it is a
> fairly standard Broadcom SDIO chip firmware with very slight alterations from Nintendo." … "The
> firmware on this Broadcom chip runs on a Cortex-M3 CPU, which is amusingly more recent than the
> ARM926EJ-S running the main firmware." **VERIFIED** — same page

> **UIC-WUP** — "A small embedded chip based on an STM8 CPU. It runs its own firmware loaded from an
> on-chip EEPROM (upgradable)." **VERIFIED** — same page

The UIC is pinned down further on the wup wiki: "The UIC is a STM8 microcontroller. It is likely a
STM8L151R8. It has 4KB of RAM, 2KB of EEPROM and 64KB of FLASH."
**VERIFIED** — [uic_internals](https://kuribo64.net/wup/doku.php?id=uic_internals)

CPU identity of the ARM9 is measured, not guessed: `c0,c0,0 = 0x41069265` (ARM926EJ-S), 16K I/D
caches, 32-byte lines, 4-way, **no TCMs**. **VERIFIED** —
[hardware_overview](https://kuribo64.net/wup/doku.php?id=hardware_overview)

The DRH (console side) is the same class of chip running the same firmware family:
"The DRH contains an ARM926EJ-S CPU which runs the `LVC_` part of the firmware blob."
**VERIFIED** — [wiiubrew Hardware/DRH](https://wiiubrew.org/wiki/Hardware/DRH)

## 1.2 Flash layout, INDX, and the blob table

Flash is a 32 MB SPI part (Micron 25Q256A on the WUP-010 board).
**VERIFIED** — [wiiubrew GamePad](https://wiiubrew.org/wiki/GamePad)

Full internal map, "from the diagnostics firmware's FLASH viewer utility" (**VERIFIED** —
[flash_layout](https://kuribo64.net/wup/doku.php?id=flash_layout)):

| Address | Internal name | Description |
|---|---|---|
| `0x0000000` | SPL | Second-stage bootloader |
| `0x000E000` | ErrorLog | Subsector used to write error data |
| `0x000F000` | Bank | Active firmware partition |
| `0x0100000` | Product1 | Firmware partition 0 |
| `0x0500000` | Product2 | Firmware partition 1 |
| `0x0900000` | Lang1 | Language bank partition 0 |
| `0x1100000` | Lang2 | Language bank partition 1 |
| `0x1900000` | TVcode | Remote control data |
| `0x1B00000` | Screen1 | ?? |
| `0x1B80000` | Screen2 | ?? |
| `0x1C00000` | Service | Diagnostics firmware partition |
| `0x1FDE000` | InspData | Diagnostics use |
| `0x1FDF000` | Seq&Conf | Diagnostics use |
| `0x1FE0000` | InspLog1 | Diagnostics use |
| `0x1FF0000` | InspLog2 | Diagnostics use |

Partition-table entry format and the boot selection rule are **VERIFIED** (same page):

> "The table is made of 16-byte entries: `0x00` 4 Data offset (relative to partition start); `0x04` 4
> Data length; `0x08` 4 Entry identifier; `0x0C` 4 Version." … "If the UIC state is 7, the diagnostics
> firmware is loaded — Otherwise, the byte at `0xF000` indicates which firmware partition to load from:
> 0 = `0x100000`, 1 = `0x500000`."

> "When loading the firmware, the second stage bootloader assumes the third entry to be the ARM9
> binary, and loads it at 0x0 in main RAM." … "The BCM4319 firmware needs to be loaded on each boot.
> The UIC firmware is only loaded when an update is needed."

Blob identifiers in stock images, in order: `INDX`, `VER_`, `LVC_`, `WIFI`, `ERR_`, `UMI_`, `IMG_`
(**VERIFIED**, same page). libdrc's boot RE gives the same `BlobPointer` structure with `name[4]` and
notes "The first of these blobs, named `INDX`, represents the volume header itself. To get the number
of blobs to check for, use `INDX.length / 16`." **VERIFIED** —
[boot](https://garyodernichts.github.io/libdrc/docs/re/boot.html)

Boot ROM capability (relevant later for recovery) — **VERIFIED**,
[memory_map](https://kuribo64.net/wup/doku.php?id=memory_map):

> "The boot ROM supports three ways of loading code: SPI (from FLASH), UART (from the UART1 serial
> header), and I2C."

## 1.3 Are LVC/UMI/WIFI compressed, encrypted or signed? — the container format

**Answer: no compression, no encryption, and no signature — integrity is plain CRC32.** This is
**VERIFIED** from working code, not inference. `fwpack.py` in GaryOderNichts/drc-fw-patches parses the
over-the-air/update image as:

```python
BlobHeader   = imageVersion(u32be), blockSize(u32be), sequencePerSession(u32be), imageSize(u32be)   # 0x10
FirmwareHeader = type(u32le), superCRCs[4](u32le), Padding(0xFE8), headerCRC(u32le), subCRCs[0x1000](u32le)  # 0x5000
FirmwareFile = blobHeader, firmwareHeader, firmwareData[imageSize - 0x5000]
```

and validates it with nothing but CRC32:

```python
header_crc = binascii.crc32(FirmwareHeader.build(fw.firmwareHeader)[0:0xFFC])
sub_crc    = binascii.crc32(firmwareData[offset:offset+0x1000])   # one CRC per 0x1000 bytes
super_crc  = binascii.crc32(subcrc_data[i*0x1000:i*0x1000+0x1000])
```

**VERIFIED** — <https://github.com/GaryOderNichts/drc-fw-patches> (`fwpack.py`; `FirmwareType.DRC =
0x01010000`, `DRH = 0x00010000`). An independent reimplementation of the same container with the same
CRC-only model exists in GaryOderNichts/DRXUtil (`source/Firmware.cpp`: `crc32` over `0x1000` blocks,
`0x4000` super-CRC table, header CRC over `0xFFC`): <https://github.com/GaryOderNichts/DRXUtil>.
**VERIFIED**

That LVC_/UMI_/WIFI inside the container are raw loadable images is confirmed by three independent
practitioners:

* `fwpack.py` prints sections with names/offsets/sizes and writes each `NAME.bin` verbatim; a section
  list must have `INDX` first and `LVC_` third or it refuses to pack ("This firmware is not
  bootable!"). **VERIFIED** (fwpack.py, quoted above)
* WulfyStylez (SALT, author of drxtool): "you can tear into the main ARM processor's firmware by
  loading `LVC_.bin` as ARM little-endian at address 0x0 in your tool of choice."
  **VERIFIED** — [GBAtemp drxtool thread, post #1](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/)
* drc-fw-patches patches LVC_ at fixed file offsets with armips (`.open "unpacked/LVC_.bin",0`,
  `.org 0x0003c9c4`, `.org 0x000b28d0`), i.e. file offset = virtual address. **VERIFIED** —
  `LVC_.s`, <https://github.com/GaryOderNichts/drc-fw-patches/blob/main/LVC_.s>

Per-version blob sizes/SHA-1s are published (useful for identifying what we hold): firmware `17080114`
(console 4.0.0, NUS 5896) → `LVC_` 682,872 B SHA-1 `23f214b06851496fcaa101588a9191a59b459dbc`, `WIFI`
250,790 B `e1b33915f736b25a1619fa905869d5962d264db2`, `UMI_` 28,351 B
`10273a7b3c5f0c10fc1d659fafb00dbd6ea2a673`; plus the 2012/2013 predecessors.
**VERIFIED** — [changelog](https://garyodernichts.github.io/libdrc/docs/re/changelog.html)

**CONFLICT (minor, worth recording).** A French news item announcing drxtool says the tool
"permet de décrypter le firmware du gamepad" ("decrypts the gamepad firmware"). No decryption exists in
the actual format or in drxtool's documented behaviour; the container is CRC-only. Treat the news word
"décrypter" as loose usage. **RUMOUR** —
[logic-sunrise](https://www.logic-sunrise.com/forums/topic/75512-wii-u-la-team-salt-hack-le-firmware-du-gamepad/)
vs **VERIFIED** `fwpack.py`.

## 1.4 What LVC_ actually contains (attack-surface element list)

LVC is eForce/µITRON4.0, and its `ASSERT` macros leak source file names. The module list is public and
is effectively the pad's attack surface:

> Drivers — aamp, acapt, aout, blit, cmos, dma, evt, fifo, flash, gpio, i2c, ir, lcd, mem, spi, uic,
> vcapt, vout, wifi.
> Services — astrm, cmd, hiddat, msg, vstrm, wii.
> Managers — cmd, con, devif, draw, gamectrl, ictag, ir, msg, nvram, nwk, resource, sound, state,
> sync, time, userif, video.

**VERIFIED** — [overview](https://garyodernichts.github.io/libdrc/docs/re/overview.html); mirrored with
slightly different driver spellings (`drvldc`, `drvvout`, `mc_video`, `mc_nvram`, …) at
[wiiubrew GamePad/LVC](https://wiiubrew.org/wiki/GamePad/LVC). Note `mc_nvram` — "handles Flash and
firmware management (upgrade, etc.)" — is the component that would receive anything we push in §2.

The MMU/translation setup is flat (no translation), which means a memory-corruption primitive in the
pad's network parsers maps 1:1 onto physical addresses, including MMIO:

| Start | End | Size | Description |
|---|---|---|---|
| `0x00000000` | `0x00157FFF` | `0x158000` | Cached memory |
| `0x00158000` | `0x003F7FFF` | `0x2A0000` | Uncached memory |
| `0x003F8000` | `0x003FFFFF` | `0x8000` | MMU translation table |
| `0xE0000000` | `0xFFFFFFFF` | `0x20000000` | MMIO |

**VERIFIED** — [wiiubrew GamePad/LVC](https://wiiubrew.org/wiki/GamePad/LVC). The MMIO map that a
write primitive would land in (LCD controller at `0xF0009400`, H.264 at `0xF0008400`, GPIO at
`0xF0005000`/`0xF0005100`) is **VERIFIED** —
[memory_map](https://kuribo64.net/wup/doku.php?id=memory_map) and
[register_map](https://kuribo64.net/wup/doku.php?id=register_map).

## 1.5 UIC STM8 (`UMI_`) firmware

* Memory map: RAM `0x00000–0x00FFF`, EEPROM `0x01000–0x017FF`, boot ROM `0x06000–0x067FF`, FLASH
  `0x08000–0x17FFF`. **VERIFIED** — [uic_internals](https://kuribo64.net/wup/doku.php?id=uic_internals)
* Boot logic: "The 'boot ROM' at 0x6000 is just a slide of jumps to 0x8000. The real UIC bootloader is
  at 0x8000. The firmware binary is installed at 0x9000. The bootloader checks the two bytes in EEPROM
  at 0x1010: if these bytes are set to `A5 5A`, the bootloader jumps to the firmware entry point at
  0x9000, otherwise it enters firmware update mode and waits for incoming firmware data."
  **VERIFIED** — same page
* UIC internal command `5` = "enter firmware upload mode"; `3` = "commit config writes to EEPROM";
  `1`/`2` = backlight on/off. **VERIFIED** —
  [uic_firmware_re_notes](https://kuribo64.net/wup/doku.php?id=uic_firmware_re_notes)
* UIC internal LVC-side commands: `0x09` "begin firmware update", `0x0B` "get UIC firmware version",
  `0x12` "toggle backlight", `0x15` "reboot in state 11", `0x16` "shutdown",
  `0x7F` "get UIC firmware ID/type" returning "0x2F or 0x3F when a firmware is installed. 0x79 when a
  firmware needs to be uploaded." **VERIFIED** — [uic](https://kuribo64.net/wup/doku.php?id=uic)
* The upload protocol itself (STM8 bootloader, SPI only, 128-byte chunks, `0x31 0xCE` write-memory,
  `0x21 0xDE` finalize which writes `A5 5A` at `0x1010` and resets) is documented but explicitly
  untested: "WARNING: the following is theoretical and has not yet been successfully replicated so
  far. A firmware upload gone wrong can and will brick the UIC." **UNCERTAIN (self-labelled) /
  protocol detail VERIFIED as documented** — same page
* Worse: "WARNING: the UIC remembers the 'waiting for firmware update' state even after a full
  power-off." **VERIFIED** — same page. This is a persistent-brick failure mode with no software exit.

Note the *practical* asymmetry: the UIC has **no radio**. It is reachable only over SPI from LVC. So
"remote UIC code execution" is not a thing; a UIC firmware can only be installed by LVC (i.e. by
`mc_nvram` during a product update), which makes it a payload target, not an entry point.

## 1.6 Checksum/decompression tooling that exists publicly

| Tool | What it does | Where |
|---|---|---|
| `drxtool` v2.0 (WulfyStylez / SALT, 2016) | extract / modify / rebuild DRC and DRH firmware + language files | [gamebrew](https://www.gamebrew.org/wiki/Drxtool_Wii_U), [GBAtemp release thread](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/) |
| `fwpack.py` (GaryOderNichts, 2024) | unpack/pack + **rebuild CRCs correctly** after modification | <https://github.com/GaryOderNichts/drc-fw-patches> |
| DRXUtil (GaryOderNichts, 2024) | on-console flashing UI + built-in patches + region/EEPROM editing | <https://github.com/GaryOderNichts/DRXUtil> |
| `ERR_` decoder | none needed: "Basically just a bmp file, stripped of all its encoding info" (1024-byte palette then 8bpp rows padded to 4 bytes) | [boot](https://garyodernichts.github.io/libdrc/docs/re/boot.html) |

**Implication for the RCE hunt.** The pad's software trust model is **CRC32 of an attacker-supplied
image, with no cryptographic signature anywhere in the documented format**. Two independent tools
recompute those CRCs after arbitrary patching, and one of them (DRXUtil) flashes such an image to a
real pad. Everything therefore hinges not on defeating crypto but on (a) whether the pad re-verifies
anything we do not know about, and (b) whether we can drive the update protocol from our own DRH
impersonation — see §2, which is where the real answer lives.

**Next action.** Obtain our own pad's `drc_fw.bin` (console MLC/NUS, or `drxtool` extraction from a
32 MB flash dump) and run it through `fwpack.py unpack` to confirm the section table and CRC model on
hardware we own; then locate `mc_nvram`'s update entry point in `LVC_.bin` (ARM, load at 0) to see what
validation it performs on `INDX`/block indices before writing flash.

---

# 2. Firmware update over the air

This is the highest-value item in the whole review, so it is documented in detail.

## 2.1 The protocol is documented in libdrc

`cmd` (UDP 50023 ↔ 50123), generic-command header, service 0 = "mostly firmware related commands"
(**VERIFIED** — [sc-cmd](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html)):

| Method | Payload | Reply | Description (verbatim) |
|---|---|---|---|
| `0x00` | 0 | 8 | "Get LVC firmware version. Returns two u32 values: running version and version installed." |
| `0x02` | 4 | 0 | "Start product update." |
| `0x03` | Max. 1028 | 4 | "Contains update data. Input is `struct { u32 block_idx; u8 data[]; }`." |
| `0x04` | 0 | 4 | "End product update." |
| `0x05` | 0 | 0 | "Abort update." |
| `0x0b` | 9 | ? | "TVCode / Service / Screen 1 / Screen 2 start update." |
| `0x0c` | 0 | ? | "TVCode / Service / Screen 1 / Screen 2 end update." |
| `0x0d` | 4 | ? | "Lang 1 / Lang 2 start update." |
| `0x0e` | 0 | ? | "Lang 1 / Lang 2 end update." |
| `0x0f` | 4 | ? | "Lang 1 / Lang 2 update language, bank and version." |

Plus, on the fragmentation mechanism: "Transaction and Fragment ID — Used for commands that require
payloads larger than the size of a 802.11n packet. **Currently only seen in use for firmware
upgrades.**" **VERIFIED** — same page.

Mode control lives in service 4: method `0x01`, payload size 1 — "Shuts down or reboots to a different
mode. Payload 0 reboots to normal mode (if not already), **2 reboots to firmware update mode**, 4 or 6
shuts down." **VERIFIED** — same page. (Also method `0x05` returns the pad's UIC state via
`retvals[] = {0,10,4,5,6,1,2,3,9,7,8,11}` — the state index space includes a diagnostics/`7`
observation point, see §2.5.)

So the entire console→pad firmware update mechanism is *on the link we already own*, on the port we
already drive. That is the single most important structural fact in this report.

## 2.2 The console side confirms the same sequence (independent implementation)

DRXUtil flashing flow, read from source (**VERIFIED**,
<https://github.com/GaryOderNichts/DRXUtil/blob/main/source/screens/FlashScreen.cpp>):

```cpp
// Abort any potential pending software updates
CCRCDCSoftwareAbort(CCR_CDC_DESTINATION_DRC0);
// Reattach the DRC in update mode
ReattachDRC(CCR_CDC_DESTINATION_DRC0, CCR_CDC_DRC_STATE_FWUPDATE, FALSE);
CCRCDCSoftwareUpdate(CCR_CDC_DESTINATION_DRC0, mFirmwarePath.c_str(), SoftwareUpdateCallback, this);
// poll progress: CCRCDCGetFWInfo(...).updateProgress
CCRCDCSoftwareActivate(CCR_CDC_DESTINATION_DRC0);      // "Activate the newly flashed firmware"
ReattachDRC(CCR_CDC_DESTINATION_DRC0, CCR_CDC_DRC_STATE_ACTIVE, FALSE);
```

This maps one-to-one onto `svc 0 / 0x05` (abort) → `svc 4 / 0x01` payload `2` (reattach in FWUPDATE
state) → `svc 0 / 0x02`+`0x03…`+`0x04` (start/data/end) → activate/reattach active. **VERIFIED** for the
console API; the mapping onto the wire services is my reading of libdrc's service table (**UNCERTAIN**
as to byte-identical equivalence, but the libdrc table calls 0x02–0x05 "Start/…/End/Abort product
update", which is the same four-phase shape).

DRXUtil's README states plainly that a **custom** image is accepted:

> "**Flash firmware** — This option allows flashing a new firmware to the Gamepad (DRC). DRXUtil comes
> with built-in patches which can be applied to the original firmware. … Additionally a **custom DRC
> firmware image can be flashed from the SD card**."

**VERIFIED** — <https://github.com/GaryOderNichts/DRXUtil> (README). Also from the same file:
`MCP_TitleListByAppType(handle, MCP_APP_TYPE_DRC_FIRMWARE, …)` — the stock firmware lives in the MLC
as an app-type-`DRC_FIRMWARE` title, and the tool refuses images whose `mFirmwareHeader.version` is
lower than the one on NAND ("Not allowing versions lower than version on NAND"). That is a *tool-side*
policy, not evidence of pad-side version checking.

## 2.3 …and the 2016 generation says the same, including the exact wire framing

drxtool's own instructions (**VERIFIED** —
[GBAtemp post #1](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/),
also reproduced at [gamebrew](https://www.gamebrew.org/wiki/Drxtool_Wii_U)):

> "to flash binaries with ios-level hax, try bumping up the first big-endian u32 in `blob_header.bin` by
> 1, as well as bumping up the version in `app.xml`. updating `VER_.bin` isn't necessary as the gamepad
> and drh don't care what version they're on, only IOS.
> other update methods include **potentially using libdrc to push an update directly to the gamepad
> (strip the first 0x10 as this is a big-endian header used by IOS)** or by **writing the payload
> directly to the serial eeprom (strip the first 0x10+0x1000+0x4000), which is useful for unbricking**.
> good luck, and try not to brick!"

Three separate, extremely useful claims:

1. **A patched/tampered image is accepted** — the only gate the author knows is IOS's own bookkeeping
   (blob version bump + `app.xml`), and he explicitly says "the gamepad and drh don't care what version
   they're on".
   **VERIFIED (as the author's tested claim; he says it works)** vs the DRXUtil-side version check,
   which is a UI guard — **not** a pad guard (**CONFLICT resolved in favour of: no pad-side version
   gate**).
2. **Over-the-air framing**: the wire payload is the file *minus* the first `0x10` bytes — i.e. the
   `BlobHeader` is an IOS-side artefact and the pad receives `FirmwareHeader (0x5000) + data`.
   **VERIFIED** as a claim; matches `fwpack.py`'s split exactly (`BlobHeader` 0x10 / `FirmwareHeader`
   0x5000). This tells us precisely what to put into `svc 0 / 0x02/0x03/0x04` — and note that
   `0x5000`? No: our `0x03` payload is capped at 1028 bytes, so the 0x5000-byte header alone is ~20
   blocks, and `block_idx` presumably indexes 0x1000-byte blocks of exactly that stream.
   **UNCERTAIN** — the block size is not documented; `fwpack`'s CRC granularity (0x1000) is the strong
   hint.
3. **Recovery**: "writing the payload directly to the serial EEPROM" — the SPI flash — is the unbrick
   route, which corroborates the hardware-path recovery in §2.6.

## 2.4 Has anyone documented a *remote* (non-console) update push?

Searched specifically; result: **no public record of a third party completing an over-the-air update
from a non-console DRH**. drxtool says "potentially"; libdrc's own documentation defers the detail:

> "Contains mostly firmware related commands. For more information about firmware update related
> commands, read the (non-existing yet) **Firmware Update Commands** documentation."
> **VERIFIED** — [sc-cmd](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html)

and libdrc's `TODO` still lists "CMD protocol handlers" as unimplemented, i.e. libdrc itself never
implemented the update methods. **VERIFIED** —
<https://github.com/opencma/libdrc/blob/master/TODO>. So: the protocol is described, the console-side
implementation is public, but the over-the-air path from an impersonated DRH appears **unpublished —
nobody has said they failed, but nobody has shown it done either.** **UNCERTAIN / apparently unexplored.**

Barista (the most mature 2026 impersonation stack) does **not** implement it either: its `cmd` plane
carries exactly four command kinds — `UicConfig`, `UvcUac`, `LcdBrightness`, `CameraSetup`
(**VERIFIED** — `research/barista-ref/core/drh/runtime_transport.cpp`, `enum class CommandKind`). It
deliberately does not touch firmware update.

## 2.5 Which state must the pad be in?

Three mutually consistent sources say an "update mode" exists and is entered by command, not by
holding buttons:

* libdrc: `svc 4 / 0x01` payload `2` = "reboots to firmware update mode". **VERIFIED**
* DRXUtil: `ReattachDRC(..., CCR_CDC_DRC_STATE_FWUPDATE, FALSE)` before the update; the UIC command
  list has `0x15` "reboot in state 11", and `svc 4 / 0x05` exposes the state table. **VERIFIED** for
  the APIs, **UNCERTAIN** that UIC state 11 == firmware-update mode (the wup wiki's UIC state table
  lists 15 states with `0` Active and `1` WiiActive documented; the full table was not enumerated in
  what I read).
* drxtool/DRXUtil both then run start/data/end/activate.

Also relevant to us operationally: our own lab notes record that the pad must already be reachable on
the link in normal mode to receive that reboot command, and that a wrong mode request leaves the pad on
its vWii / update screen — recoverable with `svc 4 / 0x01` payload `0`
(`research/BOOT-AND-MODES.md`, lab notes: "Pad on vWii/firmware-update screen — Someone issued UVC/UAC
`f3=1`, or svc 4/`0x01` payload 2. Recover with svc 4/`0x01` payload `0`").

## 2.6 Brick reports and recovery

| Failure mode | Evidence | Recovery |
|---|---|---|
| UIC firmware upload interrupted → UIC stuck in "waiting for firmware update" **across power cycles** | **VERIFIED**: "the UIC remembers the 'waiting for firmware update' state even after a full power-off" ([uic](https://kuribo64.net/wup/doku.php?id=uic)); "A firmware upload gone wrong can and will brick the UIC" | none documented in software; UIC SPI write from a hardware rig |
| Bad LVC_ image / SPL cannot boot firmware | implied by `ERR_` panic blob (pad draws its own error screen) — [boot](https://garyodernichts.github.io/libdrc/docs/re/boot.html) | UART boot, or SPI flash reprogram (see below) |
| "Modifying the DRC firmware can cause permanent damage." | **VERIFIED** — both tools ship this exact disclaimer ([drc-fw-patches](https://github.com/GaryOderNichts/drc-fw-patches), [DRXUtil](https://github.com/GaryOderNichts/DRXUtil)) | — |
| Region mismatch causes update to fail (pad connect ok, update fails) | **RUMOUR** (forum speculation, unresolved in-thread) — [drxtool thread](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/) posts ~#17–19 | flash correct-region image |

**The recovery path that actually matters to us** is fully documented and needs only the hardware the
owner already has on the bench — a soldered 4-pad header behind the battery cover (**VERIFIED**,
[wiiubrew GamePad](https://wiiubrew.org/wiki/GamePad) and
[wupbootdump README](https://github.com/Arisotura/wupbootdump)):

* pad pinout: `1 RXD, 2 UART boot, 3 TXD, 4 Vcc (2.8 V), 5 GND`, 115200 8N1
* "Tie the UART boot signal (pad 2) to ground. This enables UART boot. … Over serial, send the length
  of your code blob (4 bytes, LSB first), then send the code blob itself. The code will be loaded at
  address 0x0 in RAM." **VERIFIED**
* boot-load blob layout per the dumper: "first, you send 4 bytes, which are the length of your code
  blob … The code blob is loaded in RAM at address `0x00000000`. The first 64 bytes are the ARM
  exception vectors … Your code will run right after the boot ROM, with the CPU running at 16 MHz."
  **VERIFIED** — [boot ROM dumper thread](https://gbatemp.net/threads/release-wiiu-gamepad-boot-rom-dumper.670837/)
  (note the 32-vs-64-byte discrepancy with wiiubrew's page, which says "The first 32 bytes are the ARM
  exception vectors" — **CONFLICT**, minor, resolve by reading the boot ROM once dumped).
* Arisotura's dumper proves the feature works and even documents the expected boot ROM hash:
  <https://github.com/Arisotura/wupbootdump> — "This dumper allows to dump your gamepad's boot ROM
  without a hardware glitching attack." **VERIFIED**
* Working example code for the boot-loaded blobs: <https://github.com/Arisotura/melonboot/blob/main/source/wup/wup.c>
  (IRQ table setup, `REG_IRQ_*`, hardware init, timer prescaler depending on `REG_HARDWARE_ID & (1<<16)`).
  **VERIFIED**

**Implication for the RCE hunt.** The update plane is the strongest candidate by a wide margin: it is
*on our link*, *documented*, *unsigned (CRC only)*, *demonstrated to accept patched and fully custom
images*, and its payload would run as native ARM926EJ-S code with full MMIO access — which is exactly
"drive the LCD directly" (melonpad already does LCD+framebuffer init from custom code, §5.3). The risks
are bricks in the UIC path and the SPL path, both survivable with a soldering iron given §2.6.

**Next action.** Non-destructively characterise the gate before committing: (1) `svc 0 / 0x00` to read
running vs installed version; (2) `svc 0 / 0x02` with the *stock* image's own first blocks (no flash
write risk if it aborts — verify with `0x00` and `0x05`); (3) watch for a version/`INDX` check by
sending a deliberately wrong `block_idx` and seeing whether the reply's 4-byte error code is
"invalid block" vs "accepted". Do all of it with UART pads soldered *first* so recovery is a
38-second reflash, not a bench teardown.

---

# 3. Known vulnerabilities and exploit research touching the GamePad / DRC stack

## 3.1 The one serious published bug in this stack: IOSU `ccr_uvc` / `ccr_uac`

The required read: Rambo6Glaz's write-up, **7 Sep 2026**,
<https://ramboglaz.github.io/wiiu/2026/09/07/iosu-exploit-ccr-uvc-uac.html> (**VERIFIED**, read in
full; exploit at <https://github.com/RamboGlaz/wiiu_ios_uvc_uac_exploit>).

Its shape, verbatim/paraphrased from the post:

> "This is a short write-up about vulnerable code in the IOS gamepad microphone/camera driver which
> allows for arbitrary code execution in IOS from the PowerPC userland."

The drivers are `/dev/ccr_uac` (GamePad microphone) and `/dev/ccr_uvc` (GamePad camera), which "directly
talk to the DRH (through USB / OHCI)". Each implements four IOCTLVs: `1 SETUP`, `3 GET_FRAME`,
`4 MANAGE_STATE`, `6 GET_MPS`. The bug:

> "Each of these IPC commands takes an endpoint number (verified to be 0 or 1, in real usage it should
> always be 0). The command handlers verify this value for all IOCTLV except for IOCTLV 4 for some
> reason which allows for a very powerful integer overflow."

The overflow lands in a computed control-buffer address —
`0x12131424 + 0x6940 * endpointNumber + 0x7858` (UVC) and
`0x1213F940 + 0x1060 * endpointNumber + 0x1820` (UAC) — and because `endpointNumber` is unvalidated the
write is "semi-arbitrary". Exploitation: overwrite a UVC function-handler pointer
(`g_UVC_FUNCTION_HANDLERS`, `0x11FF8098`) with a `pop {pc}`, use the UAC variant with
`endpointNumber 0x5a13897e` to reach `0x11ff80cc`, and two more magic endpoint numbers
(`0xc9196784`, `0xc7d11959`) to lay out a ROP chain on the IOSU thread stack, then trigger with a normal
`type 0x101` UVC getter. "IOS has no ASLR, only NX/DEP, we have to use a ROP chain to execute code."

**What this is and is not.** It is **console-side (IOSU/Starbuck) code execution from PowerPC
userland**, triggered by *our own process* on the console. It is **not** a primitive on the GamePad, and
it does not by itself give LCD control. Its relevance to us is threefold:

1. It is the only public proof that the **GamePad's UVC/UAC data path is a fruitful bug surface** —
   the same struct family (`UVCRequest{endpointNumber,type,readOrWrite,size}`) that our own `cmd`
   query type 1 drives from the other direction (§5.1).
2. It is a *documented* way, from console userland with IOSU access, to reach
   `CCRCDCSoftwareUpdate`-class functionality — i.e. an alternative front door to §2 if we ever put the
   real console back in the loop. (Note DRXUtil already gives that on a homebrew-capable console
   without any exploit.)
3. It sets a precedent: Nintendo's DRC-facing code validates *some* fields and not others. **UNCERTAIN**
   whether an analogous unchecked field exists in the pad's own `sc_cmd`/`mc_nvram`; the pad-side code
   is a different codebase.

**Searches for GamePad-side (LVC/DRC) CVEs produced nothing.** No CVE identifier referring to the
GamePad LVC firmware, the vstrm/astrm/cmd protocols, or the BCM4319 firmware appeared in any search I
ran. Treat "no public GamePad RCE" as an accurate description of the public record, not as proof that
none exists. **VERIFIED (negative result of the search).**

## 3.2 BCM4319 / Broadcom full-MAC firmware

* The pad runs "a fairly standard Broadcom SDIO chip firmware with very slight alterations from
  Nintendo" on a Cortex-M3; the LVC loads it from flash **on every boot**; the driver in the stock
  firmware "is a port of open-source BCM43xx drivers". **VERIFIED** —
  [overview](https://garyodernichts.github.io/libdrc/docs/re/overview.html),
  [wifi (wup)](https://kuribo64.net/wup/doku.php?id=wifi)
* "In practice, the gamepad's wifi card includes only a 5 GHz amplifier, which makes it incompatible
  with the 2.4 GHz band." **VERIFIED** — same wup page
* "Non-Nintendo BCM4319 firmwares can be found online, and function to some extent. They're the
  opposite of the Nintendo firmware in that they only support the 2.4 GHz band. They perform very
  poorly on this band." **VERIFIED** — same page. Arisotura's plan: "I'll try to see if I can embed
  some open-source BCM43xx firmware, so one wouldn't need to dump firmware from the stock gamepad
  firmware" — [GBAtemp, Oct 22 2024](https://gbatemp.net/threads/hacking-the-wiiu-gamepad.661890/page-2)
  **VERIFIED (stated plan, not completed in that post)**
* No public CVE or exploit write-up for BCM4319 firmware was found. The nearest *analogue* is a
  host-side Linux bug in the brcmfmac interface-event path
  ([CVE-2026-43110](https://mallory.ai/vulnerabilities/CVE-2026-43110)) — **that is host kernel code,
  not pad firmware**, and it is cited here only as evidence that Broadcom full-MAC event handling has
  had OOB bugs. **UNCERTAIN as an analogue; not applicable to the pad.**

**Reachability note (important for scoping).** We reach the pad over 802.11. The BCM4319's *upper*
firmware interface (SDIO/`brcmf`-style event rings) is between the pad's ARM9 and the Cortex-M3 — not
on the air. Malformed-air-frame bugs would have to be in the Cortex-M3 firmware's 802.11/CCMP/WPS
handling. Nothing public describes fuzzing that.

## 3.3 WPS / WPA2 weaknesses on the pad's supplicant

We are the AP, so these are "what the pad will accept from a hostile AP", not "how we break in". Both
facts are ours to abuse already:

* Nintendo modified WPS so a stock supplicant fails at M2: "In Nintendo's implementation, *AuthKey* is
  computed from `KDF(KDK_ROT)` where `KDK_ROT` is `KDK` rotated 3 bytes to the left," and the pairing
  PIN's second half is hardcoded `5678`. **VERIFIED** —
  [wifi](https://garyodernichts.github.io/libdrc/docs/re/wifi.html)
* Normal mode is "a slight modified version of WPA2": Nintendo-OUI (`a4:c0:e1`) cipher/PSK selectors,
  and "The only difference between the Nintendo Pairwise CCM and the standard pairwise CCM is a 3 bytes
  rotation of the `PTK` to the left after it's computed." **VERIFIED** — same page
* Implementations exist: `CONFIG_TENDONIN` in opencma/drc-hostap ("WPA PTK rot3 and WPS KDK rot3",
  "Changes the RSN selectors to use the Nintendo selector values (a4-c0-e1)")
  **VERIFIED** — `research/drc-hostap/README.DRC`, <https://github.com/opencma/drc-hostap>; a patched
  Wireshark existed too (`memahaxx/drc-wireshark`, cited by libdrc).
* Journalistic framing of the WPS weakness ("the hilariously insecure WPS that is triggered when the
  gamepad's sync button is pressed") **RUMOUR** (accurate in substance but not a primary source) —
  [Hackaday, 8 Jan 2026](https://hackaday.com/2026/01/08/the-issue-with-wii-u-gamepads-and-how-to-clone-them/)

**Nothing here gives code execution.** The pad's supplicant is the *client*; a hostile AP cannot do more
through WPA than deliver IP packets, which we already do. The interesting sub-question is whether a
malformed EAPOL/WPS M-series message can corrupt the pad before association completes (pre-auth attack
surface, no public work found). **UNCERTAIN / unexplored.**

## 3.4 Protocol fuzzing of 5xxxx services

**No public fuzzing of 50020/50021/50023/50125 (or the pad-side 50120/50121/50123) exists that I could
find.** libdrc's own bug list is the closest thing, and it is descriptive rather than fuzz-derived:

> "* Find the macroblock type causing random corruptions on PC->DRC video data." and
> "* Fix compatibility with recent DRC fw (video stream never syncing)"

**VERIFIED** — <https://github.com/opencma/libdrc/blob/master/TODO>. The second line is directly relevant
to our "pad never paints" problem and is discussed in §5.5.

**Implication for the RCE hunt.** The public record contains exactly one serious memory-safety bug in
the DRC stack family (IOSU-side), zero pad-side CVEs, and zero fuzzing of the pad's parsers. Everything
on the pad side is greenfield — which cuts both ways: no shortcuts, and no known dead ends.

**Next action.** Treat §3.1 as a template: the wins came from *unvalidated index fields in a request
struct*. Enumerate the pad-side equivalents we can already reach (vstrm option bytes and lengths, cmd
`block_idx`, `fragment_id`/`transaction_id`, `payload_size`, UVC/UAC f2/f3 bytes, ICTAG 531-byte and
IRCOM 520-byte payloads) and diff the *documented* validation against observed behaviour — the same
"one field unchecked" pattern is the highest-yield hypothesis.

---

# 4. The H.264 decoder

## 4.1 What decodes video, and what it is fed

* "The gamepad features a hardware H264 codec. It can decode a video feed to the screen, and encode the
  video feed from the camera." Register block is `0xF0008400`–`0xF00084B8`, with `0xF00084B0` "Decoding
  IRQ status/ack" and IRQ `0x12` = "Decoding event". Almost every register in the map is still `???`.
  **VERIFIED** — [h264_codec](https://kuribo64.net/wup/doku.php?id=h264_codec)
* The IP is Nintendo-custom: "The hardware H.264 decoder present inside seems to also be of a custom
  design," on a SoC "assumed to have been designed by MegaChips Corporation."
  **VERIFIED** — [overview](https://garyodernichts.github.io/libdrc/docs/re/overview.html)
* The pad also has a framebuffer overlay path independent of the decoder, which is where "drive the LCD
  directly" actually lands: `0xF0009474` framebuffer address (22 bits → main RAM only), `0xF0009480`
  display control (`bit1` enable display, `bit2` enable video feed, `bit4` enable overlay), pixel
  formats 8bpp/4bpp paletted/ARGB1555/RGB565, palette at `0xF0009500/04`, and "The MSB of color values
  seems to actually function as an alpha value, which suggests that the LCD controller may be able to
  blend the framebuffer with something else, presumably output from the video decoder."
  **VERIFIED** — [lcd_controller](https://kuribo64.net/wup/doku.php?id=lcd_controller)
* The LCD itself is on **I²C bus 3, device 0x39**, identified by ID (`0x08922201` JDI R69208,
  `0x00000002` Panasonic MN838985), initialised by a GPIO pulse + magic byte sequences, with brightness
  set through UIC command `0x12`.
  **VERIFIED** — [lcd](https://kuribo64.net/wup/doku.php?id=lcd)

**What it is fed** — this is the crux of the attack surface (**VERIFIED**,
[sc-vstrm](https://garyodernichts.github.io/libdrc/docs/re/sc-vstrm.html)):

> "It is using H.264 with a custom wrapper around the VCL instead of NAL."

Barista's datasheet turns that into specifics (**VERIFIED** —
`research/barista-ref/docs/drc-media-packet-datasheet.md`, which records its own observations against
authenticated real-console captures):

> "the UDP payload does not include Annex-B start codes; SPS, PPS, and the slice header are not sent in
> VSTRM; and emulation-prevention bytes are inserted only when reconstructing an ordinary H.264 stream
> for desktop tools." … "The GamePad has a fixed decoder configuration for the 864x480 surface."

and the reconstruction tool re-inserts known constants to make a decodable stream: SPS
`67640020ac2b406c1ef368`, PPS `68ee060ce8`, slice headers `0x25b804ff` / `0x21e003ff | frame_num<<13`
(recorded in `research/STREAMING-TO-PAD.md` §2).

## 4.2 The attacker-controllable decoder inputs — and the 5-chunk constraint

Every byte the decoder sees after the 16-byte vstrm header is attacker-controlled. The *structural*
constraints are also attacker-controlled, which is the interesting part:

| Field | Range | Note |
|---|---|---|
| `payload_size` | 11 bits (max 2047) | must equal `UDP payload − 16`; MTU ~1800, real console uses 1694 |
| `chunk_end` / `frame_begin` / `frame_end` | flags | define chunk boundaries the decoder trusts |
| option `0x83` **Force Decoding** | no arg | "Forces decoding even if buffer is too small." (**VERIFIED**, sc-vstrm) |
| option `0x85` **NumMbRowsInChunk** | 1 byte arg | "Usually 6 (6 * 16px * 5 chunks = 480px)" (**VERIFIED**) |
| option `0x82` Frame Rate | 1 byte arg | 0=59.94, 1=50, 2=29.97, 3=25 |
| option `0x80` IDR, `0x84` Unset Force Flag | no arg | |
| ext-header terminator | `0x00` | "options are read linearly … until either 8 bytes were read or a 0x00 byte was read" |

> "To separate a frame into several packets, the `vstrm` protocol does the following: Cut each frame
> into 5 equal chunks. Each chunk represents a 854x96 region of the decoded image (6 macroblock rows).
> Send as many packets as needed for each chunk, but the last packet of a chunk needs to have the
> `chunk_end` flag set." **VERIFIED** — sc-vstrm

**CONFLICT (real, and it matters for frame geometry).** libdrc and the wup hardware docs say the display
is **854×480** (`0xF0009418 = 950`, `0xF0009424 = 854`; "854x480 60Hz" display mode).
Barista's datasheet says the *decoder* surface is **864×480 = 54×30 macroblocks** and draws "chunk 0:
rows 0..5 … chunk 4: rows 24..29". Both can be true (a 864-wide coded surface cropped to 854 by the
display window), but **nobody has published which is the decoder's actual output buffer width** —
that is precisely the number a `NumMbRowsInChunk`/geometry mismatch bug would depend on.
**UNCERTAIN.**

This gives three concrete, *cheap-to-test* malformed-bitstream hypotheses, none of which requires
knowing the decoder internals:

1. **`NumMbRowsInChunk ≠ 6`.** If the decoder allocates per-chunk line buffers sized from option `0x85`
   but writes macroblock rows derived from the actual slice, a value like `0xFF` (255 rows × 16 px =
   4080 lines) or `0x01` should mis-size a buffer. Also try 5 chunks × 7 rows (= 35 rows > 30).
2. **`0x83` Force Decoding.** The option exists *specifically* to make the pad decode when a buffer is
   "too small". If our understanding is right, that is a firmware-sanctioned OOB-write switch reachable
   from the wire. Send a frame whose declared chunk payload exceeds what fits and set `0x83`.
3. **Option-order / option-count abuse.** The real console emits `80 82 00 83 85 06 00 00` (IDR) /
   `82 00 83 85 06 00 00 00` (P). Barista experimented with order because it suspected "possible
   firmware side effects" (**VERIFIED** — `docs/gamepad-recovery-experiment.md`: "possible firmware
   side effects are the hypothesis being tested, not a confirmed cause of corruption"). Eight full
   option bytes with no `0x00` terminator is a documented edge case worth fuzzing.

Also note the *emulator-side* analogue of a real firmware defect: Barista's strongest empirical result
was that **zero-motion prediction eliminated essentially all corruption** ("Omg, its pretty much all
gone", "I saw basically 0 corruption that time") while ordinary integer motion search did not — i.e.
the pad's decoder deviates from a reference decoder in its motion-compensation/chroma path.
**VERIFIED as an observation** (Barista `docs/gamepad-recovery-experiment.md`), **UNCERTAIN as a
diagnosis** ("The result points toward motion-compensated prediction, but simultaneously avoids nonzero
vector coding, spatial predictor interactions and interpolation"). A decoder that mis-handles MC is a
decoder with parser/interpolator assumptions of its own — good hunting ground, **UNCERTAIN** whether
it is memory-unsafe or merely wrong.

## 4.3 Comparable RCE in embedded H.264 decoders (analogues, not claims about the pad)

* **H.26Forge / "The Most Dangerous Codec in the World: Finding and Exploiting Vulnerabilities in
  H.264 Decoders"** (Vasquez et al., USENIX Security 2023) — a grammar-aware H.264 generator used to
  fuzz *fixed-function/hardware-assisted* decoders; found exploitable bugs across multiple platforms.
  This is the single best methodological template for item 4. **VERIFIED** —
  <https://www.usenix.org/conference/usenixsecurity23/presentation/vasquez>
* **CVE-2022-22675 — AppleAVD: overflow in `AVC_RBSP::parseHRD`** — a bitstream *parser* (not the
  transform pipeline) overflow reachable from media; exploited in the wild. Directly analogous to the
  kind of bug a custom parser would have. **VERIFIED** —
  <https://googleprojectzero.github.io/0days-in-the-wild//0day-RCAs/2022/CVE-2022-22675.html>
* **CVE-2017-0761 — Android `libavc` remote code execution** — the classic "malformed H.264 slice
  reaches a memory-unsafe decoder" case on ARM. **UNCERTAIN (secondary source only)** —
  <https://exploit-intel.com/vuln/CVE-2017-0761>; I did not verify against the Android bulletin.
* A claimed "crash-only reproducer for CVE-2026-112689 in Apple's H.264 hardware decoder" exists at
  <https://github.com/Lak453/CVE-2026-112689-poc>. I did not read the code or confirm the CVE's
  provenance — **RUMOUR**, listed only so nobody wastes time re-discovering it.

The lesson from that literature: **parsers and header/geometry handling break; IDCT/motion pipelines
usually do not.** For the pad that means option bytes, `NumMbRowsInChunk`, chunk-length declarations and
slice-header-adjacent state are where to aim — not at CABAC coefficient streams. This coincides with
Barista's empirical finding that geometry/timing/options, not coefficient content, changed visible
outcome.

**Implication for the RCE hunt.** The decoder is the *only* continuously-fed, fully attacker-controlled
parser on the pad that we already reach at line rate (up to ~2.7 Mbit/s, 59.94 frames/s, ~10
datagrams/frame). It is also the least documented silicon in the device (essentially every register is
`???`), and its input format is *not* standard H.264 — so off-the-shelf H.26Forge-style corpora will not
apply directly; the wrapper has to be regenerated, which is a real but bounded piece of work.

**Next action.** Build a malformed-frame matrix and run it against the pad with UART pads connected so a
crash is observable: vary `0x83`, `0x85` (1/5/6/7/0xFF), chunk counts (1–8), declared vs actual payload
sizes, truncated slices mid-chunk, and option strings without a `0x00` terminator. Watch for: session
drop without re-association, `Err_` panic screen (pad draws its own bitmap → detectable remotely by
capture!), UIC state change via `svc 4 / 0x05`, and Wi-Fi reset (BCM reload). The `ERR_` screen is a
**remotely observable crash oracle** — that is the single most useful lab capability available here.

---

# 5. Prior art on "make the pad show our screen"

## 5.1 The documented display gate: the UVC/UAC command (query type 1)

This is the answer the brief asked for, and it is stated outright by libdrc (**VERIFIED**,
[sc-cmd](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html)):

> "This command is issued every second. **Recent versions of the GamePad firmware will only show the
> video stream after receiving one such command.**"

> "Setting `f3` to 1 switches the GamePad to vWii mode, setting it to 3 shuts it down (this is how the
> GamePad is shut down in vWii mode)."

The wire form is *not* the generic header — it is `cmd` query type 1 with its own 48-byte payload
(mic enable/mute/volume/volume2/freq, camera enable/power/exposure/brightness/contrast/gain/hue/
saturation/sharpness/gamma/keyframe/WB/multiplier…). **VERIFIED** — same page. libdrc implements the
1 Hz keepalive exactly as documented:

```cpp
void UvcUacStateSynchronizer::InitEventsAndRun() {
  NewRepeatedTimerEvent(1000 * 1000 * 1000, [&](Event*) {      // 1 s
    bool success = cmd_client_->Query(CmdQueryType::kUvcUacCommand, …);
```
**VERIFIED** — `research/libdrc/src/uvcuac-synchronizer.cpp`

Barista (the current state of the art) does the same and treats the reply as a *session gate*:

* `queue_status("UVC/UAC keepalive synchronized; media may start")` and
  `if (m_session_ready_announced || !m_input_seen.load() || !m_uvc_uac_reply_seen.load()) return;` …
  `queue_status("DRC session ready: input active and UVC/UAC keepalive synchronized");`
  **VERIFIED** — `research/barista-ref/core/drh/runtime_transport.cpp`
* Its own compatibility note matches libdrc's "recent firmware" caveat: "the real console changes byte 0
  from 0 to 1 after its first exchange. Its precise meaning remains unconfirmed." **VERIFIED** — same
  file. Its pairing tests even assert "UVC/UAC byte 0 must be zero initially and one after a valid
  reply" and "transport did not gate readiness on input plus UVC/UAC response"
  (`core/tests/pairing_tests.cpp`). **VERIFIED**

Our own lab already implements the command plane and the UVC/UAC exchange and still does not paint
(`research/BOOT-AND-MODES.md`, `research/GROUND-TRUTH-SESSION.md`), so on our pad the UVC/UAC command
alone is **necessary but not sufficient**, or our instance differs from the console's in a field the pad
cares about. The differences our own capture recorded: the console's 56-byte query has **3 distinct
bodies** over time, and byte[0] flips 0→1 after the first reply (**VERIFIED as lab capture** —
`GROUND-TRUTH-SESSION.md` §"UVC/UAC query | 56 B, 3 bodies, byte[0]→1 after first reply | 56 B, byte[0]
stays 0 | differs").

## 5.2 The second, less-documented half of the gate: the ASTRM video-format message

libdrc and Barista both send a **32-byte "video format" message on the audio port (50121)** ahead of
every video frame. libdrc:

```cpp
void GenerateAstrmPacket(AstrmPacket* pkt, u32 ts) {
  pkt->SetPacketType(AstrmPacketType::kVideoFormat);
  pkt->SetTimestamp(0x00100000);
  byte payload[24] = { 0,0,0,0, 0x80,0x3e,0,0, 0x80,0x3e,0,0, 0x80,0x3e,0,0, 0x80,0x3e,0,0, 0,0,0,0 };
  payload[0..3] = ts;   // LE
```
**VERIFIED** — `research/libdrc/src/video-streamer.cpp`

Barista's capture-derived description (**VERIFIED** —
`research/barista-ref/docs/drc-media-packet-datasheet.md`) is that the format message is an ASTRM packet
with `0x04` in byte 0, a **little-endian timestamp**, and four clock fields:

| Offset | Meaning |
|---|---|
| 8..11 | format timestamp (matches the following video frame's big-endian timestamp) |
| 12..15, 16..19 | LE `16000` — "Reference clock fields. **The firmware selects one as the video start delay.**" |
| 20..23, 24..27 | LE `21000` — "Reference clock fields; semantics are not completely established" |
| 28..31 | zero padding |

and it states the timing relationship that must hold: "It stamps the format at AP TSF minus 1250
microseconds and sends the matching video about 5000 microseconds later" — matching the real capture's
"median format-to-first-video lead was about 5.1 ms".

**CONFLICT**: libdrc sends `16000,16000,16000,16000`; the authenticated real-console captures show
`16000,16000,21000,21000`. Barista chose the console values. **UNCERTAIN** which matters (the firmware
"selects one as the video start delay") — this is a cheap, high-value experiment for us because it is
exactly the sort of field that would silently prevent painting.

Barista's data is also the strongest evidence about what *actually* changes receiver behaviour: in six
Vanilla-control captures with byte-identical format bodies, one pair ended `waiting` and another
`active`, and the difference correlated with **recovery policy** (restarting from a captured IDR at most
once per 750 ms), not with the envelope. **VERIFIED as observation**, with the authors' own caveat:
"this is evidence that recovery handling matters, not proof that every logged request was a distinct
rejected frame".

## 5.3 Arisotura/melonpad — proof the LCD is driveable from custom code

> "I2C, SPI, **LCD and framebuffer initialization**, DMA, Input" — "Currently supported"
> "Figuring out how to turn on the gamepad's LCD was what I was stuck on, and the FPGA debug output
> helped me a lot there." … "I am currently using a FPGA to upload custom code to the gamepad."

**VERIFIED** — <https://github.com/Arisotura/melonpad> (README). And on the hardware requirement:

> "If your gamepad isn't equipped with that kind of hardware mod, the only way to upload code to the
> gamepad is via the wifi update functionality. However, this requires having a functional stock
> firmware running on the gamepad. IF YOU UPLOAD THIS TO YOUR GAMEPAD, YOU WILL BE UNABLE TO RESTORE IT
> TO STOCK FUNCTIONALITY, OR UPLOAD A NEW BINARY, UNLESS YOU RESORT TO HARDWARE MODDING."

**VERIFIED** — same README. Note what this sentence concedes: **melonpad itself assumes the wifi update
path works for uploading custom binaries** ("this requires having a functional stock firmware running on
the gamepad"). That is the author's acknowledgement that §2 is the delivery vehicle for custom code.
Also see the thread (LCD up, checkerboard/Lucario displayed, UIC comm, DMA): **VERIFIED** —
[GBAtemp, 13 Oct 2024](https://gbatemp.net/threads/hacking-the-wiiu-gamepad.661890/). The same thread
records an FPGA replacing the SPI flash as the alternative uploader.

The corresponding *hardware* documentation for driving the LCD — GPIO `0xF0005100` sequence, I²C
commands, brightness tables, UIC command `0x12` — is the [lcd](https://kuribo64.net/wup/doku.php?id=lcd)
page, and the framebuffer/display controller registers are
[lcd_controller](https://kuribo64.net/wup/doku.php?id=lcd_controller). Both are complete enough to
re-implement melonpad's LCD init from public information alone. **VERIFIED.**

## 5.4 BetaZay/Barista — does it work today, and what mechanism does it use?

**Works today**, on real hardware, with an honest evidence trail: v0.1.74 (2026-10-31) per
`research/STREAMING-TO-PAD.md`; upstream README claims pairing a real pad and streaming
video+audio+input (<https://github.com/BetaZay/Barista>). **VERIFIED (project self-report + local
notes).**

Mechanism relevant to us, all **VERIFIED** from `research/barista-ref`:

* it is a **full DRH impersonation**: hostapd AP on the chosen 5 GHz adapter, the Nintendo cipher/PTK
  rotation, DHCP, then the five UDP services — i.e. the same architecture we run;
* the pad-side content gate it implements is `input_seen && uvc_uac_reply_seen` before "media may
  start" (`runtime_transport.cpp`);
* camera enable needs *more* than the enable bit: `BuildCameraReadCommand()` / `BuildCameraWriteCommand()`
  replicate the console's `svc 4 / 0x09` → `svc 4 / 0x08` write (`0002 0fbc`) dance and the 30-byte
  camera setting block, with the comment "With them left at zero the camera runs but every frame is
  black." **That is a directly transferable lesson: the pad accepts a UVC/UAC request with zeroed
  sub-fields and silently renders black rather than nothing.** **VERIFIED** (source comment) — and a
  strong candidate for our own symptom.
* media gate "not yet": its own docs never claim to have reverse-engineered a display *authorisation*;
  they document corruption and recovery, not a lock. **UNCERTAIN (absence of evidence).**

## 5.5 PC2DRC and the "requires a Wii U" constraint

pc2drc is archived as of 2026-04-05: "As of april 5th of 2026, this project is archived. I don't plan on
working on it in the future." and, at the time of writing, "**WiiU** (Currently working on removing this
requirement. Will update when finished.)" **VERIFIED** —
<https://github.com/thefloppydriver/pc2drc>. So the original blueprint **did not solve** the
console-free problem; that work was completed later by Vanilla/Barista-class stacks. Its archived notes
are therefore useful for the *streaming* pipeline (hostapd `CONFIG_TENDONIN`, TSF patching) but not for
the display gate.

## 5.6 Vanilla Wii U and the state of the art

* `vanilla-wiiu` org, `vanilla` project + `drc-hostap` fork — the project that made a Linux host look
  like a console; covered by Hackaday (**RUMOUR** on the details) —
  <https://github.com/vanilla-wiiu>, <https://hackaday.com/2026/01/08/the-issue-with-wii-u-gamepads-and-how-to-clone-them/>
* The pad's TSF (802.11 timing sync) is the pacing clock the pad expects; libdrc "currently only
  supports Linux operating systems patched to export the Wi-Fi TSF as a /sys file", and its TODO still
  says "Fix video streaming timing randomly desyncing" and "Fix compatibility with recent DRC fw (video
  stream never syncing)". **VERIFIED** —
  <https://github.com/opencma/libdrc> (README, TODO). Barista encodes the same rule: format stamped at
  AP TSF −1250 µs, video ≈5 ms later.
* **The single most interesting unexplored field** for the gate, found in our own captures and in *no*
  public documentation: UDP **50025 → 50125**, 96 bytes, ~1 Hz, starting at the same instant as the
  UVC/UAC polling, payload "55 non-zero bytes, one counter, one 16-bit ramp", which libdrc lists only as
  "???" and never sends (`research/GROUND-TRUTH-SESSION.md`; libdrc
  [services](https://garyodernichts.github.io/libdrc/docs/re/services.html) row `50025/50125` →
  "???", direction "To Pad: Y, To Console: N"). **VERIFIED as our measurement; UNCERTAIN as to
  function; not documented by any public source.**

## 5.7 The mechanism, stated as plainly as the evidence allows

Putting §5.1–5.6 together, a pad paints a stream from a non-console source when **all** of the
following hold:

1. **Session**: associated under the Nintendo cipher selectors, DHCP'd (`console=192.168.1.10`,
   `pad=192.168.1.11`), and the `cmd` plane live with `time`-command and UIC-config exchange.
   **VERIFIED** (libdrc wifi/sc-cmd, and our own lab).
2. **UVC/UAC keepalive at ~1 Hz with a body the pad accepts**, byte[0] flipping 0→1 after the first
   reply, and non-zero camera sub-fields if camera is involved. **VERIFIED** (libdrc: "will only show
   the video stream after receiving one such command"; Barista: zeroed fields ⇒ "every frame is black").
3. **A matching ASTRM video-format message ~5 ms before each frame**, carrying the frame's timestamp and
   the `16000/…/21000` clock fields. **VERIFIED as behaviour of both implementations and of the real
   console; UNCERTAIN as to whether the pad *requires* it (Barista: one control became active with the
   same format body as the waiting ones).**
4. **vstrm geometry the decoder accepts**: 5 chunks × 6 macroblock rows, `chunk_end`/`frame_end` flags,
   `init` set on the first frame, option order `80 82 00 83 85 06 00 00`, timestamps derived from AP TSF.
   **VERIFIED** (capture-derived, two independent implementations).
5. **The pad's recovery loop satisfied** — the pad issues IDR/resync requests when it rejects something,
   and whether it ever leaves that loop depends on how quickly a fresh IDR arrives.
   **VERIFIED as observation, UNCERTAIN as mechanism** (Barista).
6. **Possibly** the 50025 96-byte 1 Hz table. **UNCERTAIN, our measurement only.**

**No public source describes a cryptographic or "authorisation" gate on the display** — no pairing-time
display permission, no per-app gate, no signature check on the media. The gate is a state machine, and
state machines can be satisfied. That is the most valuable single fact in this review.

**Implication for the RCE hunt.** Getting the pad to paint our stream is *not* the RCE problem and does
not require RCE — it is a protocol-fidelity problem, and there is at least one unexamined input (the
50125 table) plus one field-value conflict (16000 vs 21000) plus one known black-render trap (zeroed
UVC/UAC sub-fields). Conversely, if our goal is *arbitrary* LCD content (a framebuffer we control
pixel-by-pixel, text, UI, not a compressed mirror), no protocol path gives that: only code on the ARM9
can. melonpad proves that code can do it, and §2 proves we can deliver code.

**Next action.** Split the problem: (a) close out the paint gate with pure protocol work — capture a real
console session with a matching pcap and diff *every* 1 Hz message against ours, especially the 50025
table and the format clock fields; (b) in parallel prepare the §2 firmware path as the "we want the LCD
as a framebuffer, not a video sink" route.

---

# 6. Public dumps, images and boot blobs available for static analysis

| Artefact | Public? | What is actually available | Practicality / licensing |
|---|---|---|---|
| **DRC firmware container** (`drc_fw.bin`, app-type `DRC_FIRMWARE`) | **No public download found**; hashes and per-version sizes are published | Console-side copy lives in MLC / NUS; tools (`drxtool`, `fwpack.py`, DRXUtil) all assume you supply it from your own console: "Place the original `drc_fw.bin` version `0x190c0117` from your MLC or NUS into this directory." **VERIFIED** — drc-fw-patches Makefile/README | Nintendo-copyrighted; obtain from the owner's console. Catalogue entries exist (e.g. No-Intro "DRC Firmware (Japan) (System Application)" <https://datomatic.no-intro.org/index.php?page=show_record&s=107&n=4953>) but those are hash catalogues, not files. **RUMOUR** that any public mirror of the binary exists — I found none. |
| **Full 32 MB flash image** | No | A forum poster lists where each blob sits in "the full DRC firmware (32MBs - you can obtain it by hardware-dumping)": `INDX 0x100000`, `LVC 0x100070`, `VER 0x100070`, `WIFI 0x195AD8`, `IMG 0x245830`, `UMI 0x23EEEE`, `ERR 0x1D2D8E` **RUMOUR/UNCERTAIN** (single forum post, one version, and `VER` = `LVC` looks like a typo) — [drxtool thread](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/) | readout requires SPI clip/desolder or the pad-side SPI test points (`TP` list: UIC SPI MISO/CLK at TP100/TP102, FLASH CS/MOSI/MISO/CLK on DRC-WUP balls J/K/L: [pinouts](https://kuribo64.net/wup/doku.php?id=pinouts)) |
| **Boot ROM** | **The dumper is public; the dump is not published as a file** | `wupbootdump` + `dump.py` produce it over the pad's UART header without glitching, and the expected SHA-256 is published in the README so you can verify your own dump: <https://github.com/Arisotura/wupbootdump> **VERIFIED** | reusable loading byte types are in the repo |
| **UART-boot / boot-loader blob source** | **Yes — full source** | `melonboot` (`source/wup/wup.c`) and `wupbootdump` demonstrate the load-at-0 convention, IRQ table, MMIO init. **VERIFIED** — <https://github.com/Arisotura/melonboot> | open source (see repo licence); this is the *uploader*, not Nintendo code |
| **Custom-code framework** | **Yes — source** | `melonpad`: I2C/SPI/LCD/framebuffer/DMA/input proven, wifi+audio planned. **VERIFIED** — <https://github.com/Arisotura/melonpad> | licence as per repo; note the README's own "cannot restore" warning |
| **UIC EEPROM (2 KB)** | Readable by command, not published as dumps | `cmd svc 5 / 0x06` returns "the 4 byte UIC firmware version followed by the first 768 bytes of the UIC EEPROM"; the 2 KB layout (region, tv remocon, language bank, device info, board config) is documented. **VERIFIED** — [sc-cmd](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html), [uic_eeprom_structure](https://kuribo64.net/wup/doku.php?id=uic_eeprom_structure) | ours to read from our own pad; note Barista's docs reference a companion `drc-eeprom-exporter` project used to authenticate captures — **UNCERTAIN** whether it is public; I could not locate a public repository for it |
| **Diagnostics / service firmware volume** (`0x1C00000`) | No | Bootable by faking a debug device on the expansion port; "The service firmware uses this [UART] as a serial console, it outputs debug information over the console and also accepts commands that can modify various settings." **VERIFIED** — [wiiubrew GamePad](https://wiiubrew.org/wiki/GamePad) | this is the most valuable *debugging* artefact in the whole list — see next section |

## 6.1 The debug artefact nobody uses: service firmware + serial console

Two independent, verified statements make this a first-class lab capability:

* SPL: "The SPL first interrogates the UIC to know if a debugging device is present on the extension
  port. If it is, the SPL will load data from the volume header at address `0x1C00000`, which is the
  service firmware used for diagnostics and repairs." **VERIFIED** —
  [boot](https://garyodernichts.github.io/libdrc/docs/re/boot.html); the wup version phrases it as
  "If the UIC state is 7, the diagnostics firmware is loaded" **VERIFIED** —
  [flash_layout](https://kuribo64.net/wup/doku.php?id=flash_layout)
* that firmware gives a **running shell**: serial console, debug output, and "commands that can modify
  various settings", plus a FLASH viewer (the source of the internal partition names) and access to
  `InspLog1/2`, `InspData`, `Seq&Conf`. **VERIFIED** — [wiiubrew GamePad](https://wiiubrew.org/wiki/GamePad),
  [flash_layout](https://kuribo64.net/wup/doku.php?id=flash_layout)
* the UIC state table is visible from the wire (`svc 4 / 0x05` returns an index into
  `{0,10,4,5,6,1,2,3,9,7,8,11}`), and the pad can be told to reboot into states (`UIC cmd 0x15`
  "reboot in state 11"). **VERIFIED** — [sc-cmd](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html),
  [uic](https://kuribo64.net/wup/doku.php?id=uic). **UNCERTAIN** whether a *remote* command can force
  state 7 (the "debug device present" state) — the wiki attributes that decision to the SPL polling the
  UIC, and the extension-port device is the physical trigger.

If state 7 is reachable by command rather than by hardware, we get: **a UART shell on the pad, a flash
viewer, and a live RAM/debug channel — the difference between blind fuzzing and debugging.**

**Implication for the RCE hunt.** We do not need to *guess* whether a malformed frame crashes the pad if
we can read the service firmware's console. The gap is a physical/state gate that may or may not be
command-reachable; the wup wiki's [FPGApad](https://kuribo64.net/wup/doku.php?id=fpgapad) page documents
an FPGA-based edge-connector device that is exactly the kind of "debug device" the SPL looks for.
**UNCERTAIN** whether FPGApad presents itself as one.

**Next action.** (1) Enumerate UIC state transitions over SPI (`cmd svc 5 / 0x02`/`0x0c` cover some UIC
paths; the direct LVC↔UIC command set is documented) and try to reach state 7 while watching for a
serial console on the UART header. (2) Read
[FPGApad](https://kuribo64.net/wup/doku.php?id=fpgapad) and
[test_points](https://kuribo64.net/wup/doku.php?id=test_points) to see whether the expansion-port
signature is documented. (3) Regardless of outcome, dump the boot ROM with `wupbootdump` first — it is
free, verified, and needed for any future UART-boot recovery work.

---

# 7. Ranked hypotheses

Effort: S = hours, M = days, L = weeks. "Pad code exec" means native code on the ARM926EJ-S (which
implies MMIO → LCD).

| # | Hypothesis | Why it could give pad code exec or LCD control | Effort | How we verify in our lab |
|---|---|---|---|---|
| **1** | **Push a patched/custom `LVC_` image over the air via `cmd svc 0 / 0x02,0x03,0x04`** (after `svc 4 / 0x01` payload `2`), using the `FirmwareHeader+data` framing (strip the 0x10-byte `BlobHeader`), with CRCs recomputed by `fwpack.py` | The container has **no signature — CRC32 only**; two independent tools flash *custom* images to real pads; melonpad proves custom ARM9 code can init the LCD and framebuffer. This is the only path that gives arbitrary LCD pixels rather than a compressed mirror. | M (protocol) + S (payload) | Non-destructive first: read `svc 0/0x00` versions, then `0x02`/`0x05` start+abort and watch reply error codes and UIC state. Then a **benign** payload (stock image with a changed `ERR_` bitmap, or a boot-time solid-colour framebuffer) rather than melonpad's terminal payload. **UART pads soldered before the first `0x03` block.** Grade: paint observed = success. |
| **2** | **Memory corruption in the vstrm/decoder geometry fields** — option `0x85 NumMbRowsInChunk ≠ 6`, option `0x83 Force Decoding` ("forces decoding even if buffer is too small"), chunk counts ≠ 5, declared-vs-actual `payload_size`, missing `0x00` terminator | Every one of those is attacker-controlled on the wire, is consumed by a Nintendo-custom decoder with essentially no public register documentation, and `0x83` exists precisely to override a size sanity check. Empty public fuzzing record ⇒ greenfield. | M | Broadcast the malformed matrix (§4 next action) while watching the **`ERR_` panic screen over the radio** as a crash oracle, plus `svc 4/0x05` UIC state, plus BCM4319 re-init. Attach UART for register-level confirmation. |
| **3** | **`mc_nvram` / update-handler bugs** — `block_idx` (u32) in `svc 0/0x03`, `fragment_id`/`transaction_id` (12-bit), 1028-byte payloads, `INDX` length/offset arithmetic during start | The update manager writes flash (and can write `UMI_`/`WIFI`/`ERR_`/`IMG_`) from wire data; the same "unchecked index/offset" pattern as the one published IOSU bug; a primitive here is *pre-installation* code exec with no firmware we have to author. | M | Send `svc 0/0x02` then `0x03` with `block_idx` at `0`, `0xFFFFFFFF`, `0x7FFFFFFF`, and a 4-byte payload with a 1028-byte declared size; watch reply codes and whether the pad reboots/paints `ERR_`. Static confirmation: disassemble `mc_nvram` in our own `LVC_.bin` (ARM, load at 0) around the `0x02/0x03/0x04` dispatch. |
| **4** | **Force the diagnostics firmware (state 7) → UART shell + flash viewer** | Not an exploit, a *capability*: it converts every other hypothesis from blind to debuggable, and the service firmware can modify settings and inspect flash. | S | Try to reach UIC state 7 by command (`svc 4/0x05` to observe, `svc 4/0x01`, UIC `0x15` "reboot in state 11", UIC internal cmd 6 "set UIC state"); if unreachable, read `FPGApad`/`pinouts` to build the expansion-port device. Grade: serial console banner on the UART header after boot. |
| **5** | **Swap/alter the `WIFI` blob in the same update** (Cortex-M3 code exec) | Same unsigned container, one more CPU: gives control of the 802.11 MAC/firmware — removes the Nintendo-cipher dependency, enables pre-auth attacks on the pad, and could let us dump/instrument the ARM9's traffic. Also the path Arisotura intends for open-source BCM43xx firmware. | M | After hypothesis 1 works, replace `WIFI` with the stock blob byte-identical (control) then with a one-byte-patched stock blob, and verify the pad still associates (proves the loader accepts and runs it). |
| **6** | **UIC STM8 (`UMI_`) payload** | Full code exec on the input MCU: backlight, LCD power sequencing, input spoofing, power control — persistent and invisible to the ARM9. **But** no radio: only installable through hypothesis 1's update, and the pad's own wiki says the upload is "theoretical" and can brick the UIC across power cycles. | M | Only after hypothesis 1, on a spare pad, with the UIC SPI lines (TP100/TP102 + UIC CS) on a logic analyser so a stuck bootloader is visible. |
| **7** | **Malformed-input fuzzing of the pad's supplicant** (WPS M-series, EAPOL, association) pre-authentication | Unfuzzed, pre-auth, and we control the AP — the cheapest possible trigger surface. Zero public work ⇒ unknown potential; historically this class (Broadcom/`wpa_supplicant`) does produce bugs. | M | Build a malformed WPS/EAPOL generator against a second (lab) pad while capturing on a monitor interface; look for the `ERR_` screen or a dropped BCM4319 init. Note the pad only speaks the Nintendo-modified handshake, which we already implement. |
| **8** | **Reuse the published IOSU `ccr_uvc`/`ccr_uac` bug in the pad→console direction** | The published bug is triggered by *our* process on the console, so it needs PowerPC userland on the real console. If the pad→console `GET_FRAME` path has a symmetric unchecked length, a hostile pad could reach IOSU — that is console compromise, not pad RCE, and does not paint our LCD. | L | Out of scope for the LCD goal; revisit only if the objective changes to "own the console". Note DRXUtil already gives console-side flashing with no exploit at all. |

## Ranking rationale

* **#1 wins on evidence density.** It is the only hypothesis where every link of the chain is
  independently **VERIFIED**: the protocol is in libdrc's service table; the wire framing is described by
  drxtool; the container is CRC-only (two codebases); custom/patched images are flashed to real pads by
  two public tools; and custom ARM9 code driving the LCD is demonstrated by melonpad. Nothing needs to be
  discovered — only implemented and survived.
* **#2 and #3 are the "real" exploit hunt** and the only ones that would be *remotely* triggerable against
  a stock pad without flashing anything. Both are unvalidated, and both suffer the same handicap: no
  ground-truth on the pad's internals without hypothesis #4 or a UART log.
* **#4 is not a hypothesis so much as an enabler**, and it is cheap. It should be attempted before #2/#3
  go deep, because blind fuzzing of a custom decoder with a brick-shaped failure mode is bad tradecraft.
* **#5/#6 ride on #1** and should be sequenced after it, not in parallel.
* **#7 is the only pre-auth surface** and is therefore the right thing to run *while* #1 is being built.
* **#8** is ranked last because it does not answer the question we asked.

## Biggest unknowns (ranked by how much they could change the plan)

1. **Does the pad trust the DRH for firmware update, or is there an undocumented check?** If it trusts
   us, #1 is days away. If there is a signature/state check nobody has published, #1 collapses and #2/#3
   become the whole plan.
2. **Can UIC state 7 (service firmware) be reached by command?** If yes, every other hypothesis becomes
   debuggable, and #2/#3 stop being blind.
3. **The 50125 / 50025 1 Hz 96-byte table.** Undocumented, unsent by every public implementation, started
   by the console at exactly the moment the display phase begins — the best remaining candidate for the
   paint gate we have not satisfied.
4. **The decoder's real output-buffer geometry** (854 vs 864 wide, 30 vs 32 rows) — determines whether
   the `NumMbRowsInChunk` class of bug is even capable of overflowing anything.

---

## Appendix A — source list actually used

Primary (project's own code/docs):
`https://kuribo64.net/wup/doku.php?id=start|flash_layout|memory_map|hardware_overview|h264_codec|lcd|lcd_controller|uic|uic_internals|uic_firmware_re_notes|uic_eeprom_structure|sdio|wifi|test_points|pinouts|fpgapad|gpio` ·
`https://wiiubrew.org/wiki/GamePad` · `…/GamePad/LVC` · `…/GamePad/DRC` · `…/Hardware/DRH` ·
`https://garyodernichts.github.io/libdrc/docs/re/overview.html|boot.html|wifi.html|services.html|sc-cmd.html|sc-vstrm.html|gpio.html|changelog.html` ·
`https://github.com/opencma/libdrc` (README, TODO, `src/uvcuac-synchronizer.cpp`, `src/video-streamer.cpp`) ·
`https://github.com/opencma/drc-hostap` (`README.DRC`) ·
`https://github.com/GaryOderNichts/drc-fw-patches` (`fwpack.py`, `Makefile`, `LVC_.s`) ·
`https://github.com/GaryOderNichts/DRXUtil` (README, `source/Firmware.cpp`, `source/screens/FlashScreen.cpp`) ·
`https://github.com/Arisotura/melonpad` · `https://github.com/Arisotura/wupbootdump` ·
`https://github.com/Arisotura/melonboot` ·
`https://github.com/BetaZay/Barista` (local clone: `docs/drc-media-packet-datasheet.md`,
`docs/gamepad-recovery-experiment.md`, `core/drh/runtime_transport.cpp`, `core/tests/pairing_tests.cpp`) ·
`https://github.com/thefloppydriver/pc2drc`

Vulnerability research:
`https://ramboglaz.github.io/wiiu/2026/09/07/iosu-exploit-ccr-uvc-uac.html` ·
`https://github.com/RamboGlaz/wiiu_ios_uvc_uac_exploit` ·
`https://www.usenix.org/conference/usenixsecurity23/presentation/vasquez` ·
`https://googleprojectzero.github.io/0days-in-the-wild//0day-RCAs/2022/CVE-2022-22675.html` ·
`https://exploit-intel.com/vuln/CVE-2017-0761` · `https://mallory.ai/vulnerabilities/CVE-2026-43110`

Community/secondary:
`https://gbatemp.net/threads/hacking-the-wiiu-gamepad.661890/` (Arisotura/melonpad, Oct 2024) ·
`https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/` ·
`https://gbatemp.net/threads/release-wiiu-gamepad-boot-rom-dumper.670837/` ·
`https://www.gamebrew.org/wiki/Drxtool_Wii_U` ·
`https://hackaday.com/2026/01/08/the-issue-with-wii-u-gamepads-and-how-to-clone-them/` ·
`https://www.logic-sunrise.com/forums/topic/75512-wii-u-la-team-salt-hack-le-firmware-du-gamepad/` ·
`https://datomatic.no-intro.org/index.php?page=show_record&s=107&n=4953`

Leads I found but did **not** review (explicitly unverified, listed so they are not lost):
delroth's 30C3 talk "Reverse engineering the Wii U Gamepad"
(`https://app.media.ccc.de/v/30C3_-_5322_-_en_-_saal_g_-_201312292030_-_reverse_engineering_the_wii_u_gamepad_-_delroth`) ·
`https://github.com/Lak453/CVE-2026-112689-poc` (claimed Apple H.264 decoder crash) ·
`memahaxx/drc-wireshark` dissectors (cited by libdrc; Bitbucket).

## Appendix B — internal cross-references

Local files this report leans on (unmodified):
`research/libdrc/web/docs/re/*.rst` and `research/libdrc/src/*`,
`research/barista-ref/docs/*`, `research/drc-hostap/README.DRC`, `research/pc2drc` → `../pc2drc/README.md`,
and the engagement's own captures: `research/GROUND-TRUTH-SESSION.md`, `research/BOOT-AND-MODES.md`,
`research/STREAMING-TO-PAD.md`, `research/CODEC-SPEC.md`.
