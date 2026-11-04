# Getting an analysable GamePad firmware image into this lab

Compiled 2026-11-04 for the rce-hunt mission. Scope: **read-only / non-destructive** routes to the
bytes of the pad's `LVC` firmware, ranked by cost. Prior work is not repeated here:
`01-pad-firmware-update.md` (update path, `INDX/VER_/LVC_/UMI_/WIFI/ERR_/IMG_` container, CRC rules,
UART boot, flash map), `02-attack-surface.md` (cmd plane), `GROUND-TRUTH-SESSION.md` (rot3 PTK
recipe + `capture/truth-decrypt.py`), `04-public-re.md` (public RE survey).

**Label key.** `V` = verified this session against a primary source (quote/URL below) or against our own
measured bytes. `V-local` = verified in our own earlier documents/measurements, not re-derived here.
`U` = uncertain — plausible, untested; the text says what would settle it.

---
## 1. What we can read over the air right now, risk-free

Reply sizes are the **libdrc `sc-cmd.rst` table** (`V`: local copy
`research/libdrc/web/docs/re/sc-cmd.rst:105-260`; online
[sc-cmd.html](https://garyodernichts.github.io/libdrc/docs/re/sc-cmd.html)). "Leaks" column is ours.
"Measured" = what we have actually seen on this pad.

| Primitive | Doc. | Measured by us | What it leaks | Label |
|---|---|---|---|---|
| `svc 0 / 0x00` | 8 | **8 B `19 0c 01 17` ×2** | running + installed DRC image version — the *acceptance signal* for any flash experiment | `V-local` |
| `svc 0 / 0x0a` ×5 (idx 0…4) | 4 each | not yet | language bank+version, TV-remote code version, **service-firmware version**, opening-screen 1/2 versions — five free 4-byte EEPROM reads, one per call | `U` (untested; cheapest test in this document) |
| `svc 1 / 0x05` | 113 | **113 B** (09:13 run) | 13 B `WL_CONFIG_VARS` + auth mode + enc type + 32 B SSID + SSID len + **64 B PSK** + PSK len | `V-local` |
| `svc 1 / 0x08` | 16 | not yet | **Wake-on-WLAN key** (16 B) — a second key schedule we never analysed | `U` |
| `svc 2 / 0x0c` | 272 | not yet | **16 B device ID + 256 B device certificate** — the only console-independent identity material in the pad | `U` |
| `svc 3 / 0x03` | 13 | not yet | `phy_stats` from the BCM4319 — per-antenna RF state | `U` |
| `svc 3 / 0x04` | 152 | not yet | `pkt_stats` — 152 bytes of radio counters (a BCM firmware struct, i.e. its layout is itself RE material) | `U` |
| `svc 3 / 0x05` | 448 | not yet | **`wmm_stats`, 448 B** — largest documented wifi-side read | `U` |
| `svc 3 / 0x06` | 2 | not yet | RSSI, two antennas | `U` |
| `svc 4 / 0x04` | 28 | **28 B, exact layout** | version tuple incl. image version `0x190C0117` and UIC fw `0x28000058` | `V-local` |
| `svc 4 / 0x05` | 1 | **1 B** (saw `0x0c` in capture, `0` on our pad) | UIC state oracle (value does **not** match the documented `retvals[]`) | `V-local` |
| `svc 4 / 0x19` | 12 | not yet | undocumented 12-B read | `U` |
| `svc 5 / 0x00` | ? | not yet | 6-B UIC table entry at UIC `@f8d0`, via UIC cmd `0x0a` | `U` |
| `svc 5 / 0x06` | 772 | **772 B, verified live** | u32 UIC fw + **768 B UIC EEPROM**: stored SSID, 64-hex PSK, key blob, string `IT0156` | `V-local` |
| `svc 5 / 0x11` | ≤520 | 4 B ×195 (acks) | IRCOM passthrough: **the one documented method that both takes ≤520 B and returns ≤520 B** — the read/write pair for a bug hunt | `V-local` (caps) |
| `svc 5 / 0x15` | 1 | **1 B** (`4`) | LCD brightness; a cheap liveness oracle | `V-local` |
| `svc 5 / 0x1a` | 13 | not yet | **13 B of LCD-controller I²C readback** (bus 3, dev 0x39) — panel register state | `U` |

**Total risk-free byte budget available today: ≈1,900 B in ~14 requests** (everything above), which is
~0.2 % of the 1 MB `LVC_` blob. State that plainly: **the over-the-air read primitives cannot yield the
firmware image.** They yield *version numbers, keys, identity, and EEPROM*, i.e. oracles for experiments —
not code.

### 1.1 The `9004` state-dependence finding (matters for this document)

Our 09:13 baseline answered `svc1/0x05` = 113 B, `svc5/0x15` = `4`, `svc0/0x00` = 8 B. The **10:15:52**
re-run (`out/evidence/rce-ro-1015/results.json`) returned **`error 9004`** for `svc1/0x05` and `svc5/0x15`,
and **zero ACKs / no reply** for `svc0/0x00` — while `svc0/0x0a`×5, `svc2/0x00`, `svc4/0x04`, `svc4/0x05`
and `svc5/0x06` (772 B) answered normally and input still flowed at 63–77/s. Known confound: two sockets
bound to `192.168.1.10:50023` (`SO_REUSEADDR`), which is "indistinguishable from a dead pad"
(`BOOT-AND-MODES.md` §11). **`9004` is the only non-zero error code this project has ever seen.**
`V-local` bytes, `U` interpretation. Consequence for the plan below: **every acquisition step that reads
over the air must first prove single-binder plus a repeat of the 09:13 baseline**, or a `9004` will be
misread as "the pad is bricked" exactly when we are mid-experiment.

---
## 2. Passive capture of a console-driven pad update

**Does the console push pad firmware at all?** `V` (public precedent): the only way to run
[drc-fw-patches](https://github.com/GaryOderNichts/drc-fw-patches) on real hardware is `make` → a
`patched_drc_fw.bin` "which can be flashed to the gamepad", i.e. the console's ordinary update mechanism
carries *whatever the console has* — that is the whole basis of the DRC-firmware-patching scene. `V`
(negative control): a vanilla pad can also get **stuck** in that update
([GBAtemp 671925, "Vanilla gamepad stuck on update (EU console)"](https://gbatemp.net/threads/vanilla-gamepad-stuck-on-update-eu-console.671925/)) —
so the flow exists, runs unprompted, and is allowed to fail dangerously. `U`: *when* it is triggered —
candidates, ranked: (a) pad's installed ≠ running version (the version query `svc 0/0x00` is the second
command of every session, `V-local`), (b) a pad paired to a console whose DRC image version differs
(region/mixed-pad pairing threads), (c) system update that bumps the DRC image. We have **no** capture of
one; §1.3 of `01-pad-firmware-update.md` proves all update methods are absent from our 300 s session —
because versions matched.

**Can we decrypt it?** `V-local`: yes, on the console's own channel, with the recipe in
`GROUND-TRUTH-SESSION.md` §1 — stock PRF-512 PTK, then Nintendo's **3-byte left rotation (`rot3`)**,
AAD with **SeqCtl zeroed**, nonce priority octet = **TID**, 8-byte MIC, strip FCS. 167,154/167,324 protected
frames (99.9 %) decrypted. The PSK input is already on disk: `svc 1/0x05` (113 B) / `svc 5/0x06` (772 B)
both hand us SSID + 64-hex PSK, and the console's GTK is recoverable from msg3 (§5). The cmd plane
is key id 0 / TID 0 pairwise, which is exactly the plane the update rides — **no new crypto work**.

**What the traffic would look like** (`V` for the shapes, `U` for the sequence):
1. `svc 4 / 0x01` payload `02` — reboot to firmware-update mode (`V`, libdrc) → session drops, pad
   re-associates, `LVC` comes up in update mode (`svc 4/0x05` state changes).
2. `svc 0 / 0x02` payload 4 B — start product update.
3. **N × `svc 0 / 0x03`, payload exactly 1028 B = u32 block_idx + 1024 B data** (`V`: "Max. 1028,
   `struct { u32 block_idx; u8 data[]; }`", and 1028 is the only natural split). Wrapped in the ordinary
   generic header with `tid` = message, `fid` 0…3, `flags 0x42` … `0x40`, one datagram of 1048 B each —
   *byte-identical in shape* to the console's `svc 0/0x11` state push we already decoded
   (`02-attack-surface.md` §2.3, 778 × 1048 B datagrams, 4 fragments/message).
4. `svc 0 / 0x04` — end product update, 4 B reply. Then the pad reboots into the new image.

**Volume estimate:** ≥ `LVC_` 682,872 B + `WIFI` + `UMI_` + `IMG_` + `ERR_` ≈ **>1 MB ⇒ ≥1,000 `0x03`
datagrams ⇒ a few seconds of capture at 1048 B/datagram.** Our existing 300 s capture is 165 MB; this is
smaller than one video frame burst. Nothing about the capture is hard — **the only hard part is making the
console push**, and every way of forcing it writes to the pad. So:

**Concrete capture plan (opportunistic, zero pad risk).**
1. Snapshot `svc 0/0x00` and `svc 4/0x04` from the pad → running/installed versions + UIC fw.
2. Start the monitor capture **before** the pad powers on, on the console's channel (previously **ch 40**,
   `V-local`), 60 s pre-roll, ≥15 min, promiscuous, filtering nothing.
3. Perform a benign console-side action that may refresh DRC firmware (system-update check; re-pair a
   donor/other-region pad if one is ever borrowed). Never `svc 4/0x01`/`0x02` from our side.
4. Decrypt with `capture/truth-decrypt.py` unchanged; then grep the decrypted `50023/50123` streams for
   `svc 0 method 0x02/0x03/0x04`. Reassembly: `u32 block_idx` + 1024 B, concatenate in index order.
5. Acceptance: reassembled payload must equal our console-side `drc_fw.bin[0x10:]` byte-for-byte, and
   `fwpack.py unpack` must pass every CRC. That also settles **`01`'s unknowns U1/U2** —
   `BlobHeader.blockSize` and `block_idx` numbering — with no risk at all.

**Verdict:** cheap to run in the background, *not* on demand. `U` (probability of a push during a normal
session) is low for a healthy matched pair.

---
## 3. Console-side files — the cheap route we have been ignoring

**`V` (primary source, verbatim).** [drc-fw-patches README](https://github.com/GaryOderNichts/drc-fw-patches):
> "Place the original `drc_fw.bin` version `0x190c0117` from your **MLC or NUS** into this directory.
> Running `make` will build a `patched_drc_fw.bin` which can be flashed to the gamepad."

That single sentence is the answer to this whole mission and it matches our pad exactly: our pad reports
image version **`0x190C0117`** (`svc 0/0x00`, `svc 4/0x04`, `V-local`). So a copy of *our* version of
`drc_fw.bin` exists **on the console we own**, in one of two places:

| Route | What to do | Expectation | Label |
|---|---|---|---|
| **MLC copy** | Bring up `wupserver` (recovery_menu / Aroma plugin), then `wupclient` recursive listing of `storage_mlc01:`; grep every path for `drc_fw`; copy the file out unchanged | Highest-probability single win. Prior doc's guess `/usr/tmp/drc_fw.bin` is **untested**, do not assume the path | `V` that the file is "on the MLC"; `U` path |
| **NUS/CDN** | Pull the system-update title that carries the DRC firmware with a NUS downloader (JNUSTool / NUSspli / `wiiu-nus`), decrypt with the matching ticket from the console's `/sys`, then `fwpack.py unpack` | Works only if we identify the carrying title; system titles' keys live in the console's own files, which is why the MLC route is simpler | `U` title id |

**What it gives us.** `drc_fw.bin` = `0x10` BE `BlobHeader` + `0x5000` LE `FirmwareHeader` (subCRCs) +
section table (`INDX`, `V`, from
[fwpack.py](https://github.com/GaryOderNichts/drc-fw-patches/blob/master/fwpack.py)):

```
firmwareData:  INDX | VER_ | LVC_ | WIFI | ERR_ | UMI_ | IMG_     (7 × 16-byte entries at 0x0)
```

`fwpack.py unpack` therefore hands us **all six payload blobs at once**, including `LVC_` (**the ARM926
eForce/µITRON image we want to fuzz**, 682,872 B for 4.0.0/`V-local`), the BCM4319 `WIFI` blob, the UIC
`UMI_` blob, the `ERR_` panic image and `IMG_`. `V`: `LVC_` 682,872 B / SHA-1
`23f214b06851496fcaa101588a9191a59b459dbc` for 4.0.0 (local `04-public-re.md` §…, from a public dump list).
The image is *also* exactly what lands on pad flash: partition payload =
`drc_fw.bin[0x5010:]`, over the air = `drc_fw.bin[0x10:]` (`V-local`, `01` §2.2). **One file, three uses:
static RE target, wire-format ground truth, and the base for a patched reflash later.**

**Tools that already assume you have it:** `fwpack.py` (pack/unpack + CRC repair), `DRXUtil`
(flash screen / verify sequence), `drxtool` ([gamebrew](https://www.gamebrew.org/wiki/Drxtool_Wii_U),
[GBAtemp 453143](https://gbatemp.net/threads/release-drxtool-gamepad-drh-firmware-hacking-utility.453143/)).
**No extractor is needed beyond `fwpack.py unpack` — the container is documented and CRC-only.**

**What does *not* contain pad firmware (`U`, negative evidence, do not spend time):** `fw.img` is the
**IOSU** (console ARM) firmware image, and `iosuhax`/`fw_img_patches` patch IOSU — nothing in that
toolchain parses `LVC_`/`UMI_` blobs, and no public report puts pad blobs in `fw.img`. The DRC image is
delivered to IOSU as an opaque file by the update title. `V`: `iosuhax` patches are IOSU-only (public
repo); the *absence* of pad blobs inside `fw.img` is `U` because we have not dumped it.

**Do this first, today, before anything else in this document.** It costs one console session, touches no
pad flash, and unblocks `01`'s U1/U2 and every static-analysis plan in `05-pad-parsers-in-code.md`.

---
## 4. Public dumps

Searched: No-Intro, GBAtemp, kuribo64.net/wup, gamebrew, archive.org, GitHub, melonDS news.

| Candidate | Status | Label |
|---|---|---|
| **No-Intro "DRC Firmware (Japan) (System Application)"** — dat-o-matic record `s=107&n=4953` ([record](https://datomatic.no-intro.org/index.php?page=show_record&s=107&n=4953)) | Page exists and is a **hash catalogue entry, not a file**. I fetched it; the page is JS-driven and I could **not** reliably scrape the hash fields, so I will not quote a hash I did not read. Use it only to *verify* a dump we already have | `V` record exists / `U` hash values |
| `Arisotura/melonpad`, `Arisotura/melonboot` | Source code, **no firmware image**. `V`: README says the flash "is soldered to the motherboard" and the wifi update "requires having a functional stock firmware" | `V` |
| `Arisotura/wupbootdump` | **Boot ROM** dumper (not firmware). `V`: expected result SHA256 `1ba084d39f36f3fa2d8d4b671e762e08d8893651f94c8f31a0892dc9e12a7fc1` | `V` |
| archive.org snapshots of melonpad/melonboot | Source mirrors (e.g. [archive.org melonpad](http://archive.org/details/github.com-Arisotura-melonpad_-_2025-04-26_21-54-13)) — no blobs | `V` |
| GBAtemp 453143 (drxtool thread) | Contains the *only* public offset list for a 32 MB full-flash dump: `INDX 0x100000`, `LVC 0x100070`, `WIFI 0x195AD8`, `UMI 0x23EEEE`, `IMG 0x245830`, `ERR 0x1D2D8E` — a single post, one version, `VER`=`LVC` looks like a typo | `U` (and GBAtemp now blocks non-JS fetches, so I could not re-read it) |
| GBAtemp 660486 "Extract Wii U Gamepad firmware?" | Thread exists (search result title only). **Could not read it** — Cloudflare interstitial. Do not cite its contents | `U` (unread) |
| bitbuilt / GBAtemp hardware threads | Nothing found that publishes a blob; hardware-dump *methods*, not files | `U` (not exhaustive) |

**Bottom line:** `V` — **I found no publicly downloadable GamePad firmware image, and there is no public
extractor for one**, because the only documented consumer (`fwpack.py unpack`) takes a file you are
supposed to supply from your own console. Anything claiming otherwise is a hash catalogue or a hardware
dump method. **Integrity check for any image we obtain** (public and mechanical, `V`): zlib CRC32 —
`headerCRC` over header `0x0000..0x0FFB`, four `superCRC`s over the `0x1000`-byte chunks of the subCRC
table, and one `subCRC` per `0x1000`-byte block of `firmwareData`. **No signature, no MAC** anywhere in
the container, which is simultaneously why it is verifiable offline and why the pad accepts a patched
image.

---
## 5. Physical routes

| # | Route | What you get | Mechanics (verified where cited) | Risk to stock firmware |
|---|---|---|---|---|
| P-a | **SPI flash read-back (clip)** | **the whole 32 MB**: SPL, both product partitions (`0x100000`/`0x500000`), Lang1/2, TVcode, Screen1/2, **`0x1C00000` diagnostics**, plus the error/seq/inspection areas. `V` ([flash_layout](https://kuribo64.net/wup/doku.php?id=flash_layout)) — matches our prior map exactly | 32 MB SPI part (`04-public-re.md` says Micron 25Q256A on WUP-010: `V-local`, **verify the marking by eye**) on a 3v3 rail (`V`: [wiiubrew Hardware/DRH](https://wiiubrew.org/wiki/Hardware/DRH) shows a 3v3 card-edge bus with FLASH CS/MOSI/MISO/CLK; DRC-WUP equivalents per [pinouts](https://kuribo64.net/wup/doku.php?id=pinouts)). CH341A + matching SOIC clip ≈ €5; **remove the battery**, clip, read 32 MB (~10 min at 1 MHz) **twice and compare** | **None — read-only.** The only risks are mechanical/ESD, plus a clip that back-powers the rail |
| P-b | **UART boot + RAM-resident flash reader** | full flash **or** selective partitions; also an infinite reflash/recovery harness; UART console | `V` ([wiiubrew GamePad](https://wiiubrew.org/wiki/GamePad)): header pads 1 RXD / 2 UART-boot / 3 TXD / 4 Vcc 2.8 V, GND at TP128 or the battery connector; **115200 8N1**; tie pad 2 to GND, power on, send **4-byte LE length then the blob, loaded at `0x0`**, first 32 B = ARM exception vectors, runs at reset. `V`: no welding needed beyond 4 pads; wupbootdump documents a **solderless dongle** from USB spring contacts + a spare battery plug, and warns some USB-UART adapters prevent boot unless RXD is disconnected | **None — this path never writes flash.** Flash access requires *our* code to drive `drvflash`/`drvspi` (§P-b needs ~200–600 lines of ARM926 or a port of melonpad's `loader_flash/source/wup/{crt0.s,spi.c,flash.c,dma.c}`) |
| P-c | **Fork `wupbootdump` as the acceptance test** | proof our UART harness works, *before* we trust it with a flash dump | `V` ([wupbootdump](https://github.com/Arisotura/wupbootdump), announced [on nesdev](https://forums.nesdev.org/viewtopic.php?t=26020)): `python dump.py <port> bootrom.bin`, ~6 min upload, HOME LED flashes once, result SHA256 `1ba084d…a7fc1`. Same boot mechanism as P-b, so a working P-c = a working P-b | None |
| P-d | **Over-the-air push of *our* image** (`svc 4/0x01`→ `0/0x02`→`0/0x03`×N →`0/0x04`) | arbitrary code on the pad; the update path itself | `V-local` (`01` §§1–4). **The one route that can lose the firmware**: melonpad's own README (`V`) — *"IF YOU UPLOAD THIS TO YOUR GAMEPAD, YOU WILL BE UNABLE TO RESTORE IT TO STOCK FUNCTIONALITY, OR UPLOAD A NEW BINARY, UNLESS YOU RESORT TO HARDWARE MODDING."* | **Yes, it can** — unless P-a/P-b already exist, because the update path itself is what breaks |

**Brick/restore implications.** `V` curve from public RE: `SPL` at `0x0` picks Product1 or Product2 by the
byte at `0xF000`, and **UIC state 7 boots the diagnostics firmware** instead ([flash_layout](https://kuribo64.net/wup/doku.php?id=flash_layout)) —
so "pad draws nothing" is *not* the same as "pad is dead": the recovery assets are in the same chip a clip
can read. `V`: a `UMI_`/UIC upload can stick the UIC in "waiting for firmware update" **across power cycles**
([uic](https://kuribo64.net/wup/doku.php?id=uic) per `04-public-re.md`), which no clip on the DRC SPI flash
fixes — that is the one irreversible-feeling state, and it belongs to the `0x0b–0x0f` UIC paths, not to the
product (`LVC`) update. **Rule: full 32 MB dump *before* any write, kept twice, off-box.**

---
## 6. Recommendation

**1. Cheapest analysable image (do this first):** copy `drc_fw.bin` off **our own console** (MLC via
`wupserver`+`wupclient`, else the NUS title), run `fwpack.py unpack`, keep the container plus the seven
blobs under `research/rce-hunt/artifacts/`. Cost: one console session, **zero pad risk, zero soldering**,
and it is `V` that the file must exist there with exactly our version string `0x190c0117`. It also answers
the format unknowns (`blockSize`, block numbering) that block the wire-level experiments.

**2. If the console copy is unavailable:** SPI clip read (P-a). It is the only route that yields
*everything* — including the diagnostics firmware and the SPL — and it is **read-only**. Budget the pad
opening; buy the clip and read twice.

**3. Build the UART harness anyway (P-b/P-c) if we ever intend to write flash.** Not for the image — for
the *licence to experiment*. Verified acceptance test: `wupbootdump`'s SHA256.

**4. Opportunistic capture (§2)** runs in the background during every console session; it costs nothing
and the one time it fires it hands us a real `0x03` stream to validate the reassembler against.

**5. If no image is obtainable at all — next-best static targets.** (a) **UIC EEPROM**: we already hold
768 B free (`svc 5/0x06`); the UIC EEPROM is `0x1000..0x17FF` = 2 KB `V`
([uic_eeprom_structure](https://kuribo64.net/wup/doku.php?id=uic_eeprom_structure)), with **`0x1010` = `A5 5A` =
"firmware installed"** and SSID at `0x1101` — so our dump is already structurally checkable, and the *tail*
of the EEPROM is a read gap (`svc 5/0x0c` writes only). (b) **BCM4319 `WIFI` blob** — it is a *section of
`LVC_`'s container*, so it arrives with step 1 and not otherwise; its runtime upload happens over SDIO
inside the pad, unobservable from the air. (c) **Hardware H.264 decoder** — fixed-function, no analysable
firmware, black-box only (that is the vstrm fuzzing plan in `02`). (d) **Purely black-box, no image at
all**: the whole method-mutation matrix (`02` §4, M1–M12), the length-trust read primitive (declare 1028,
deliver 20 → OOB read forwarded to a reply), and the five untouched 4-byte EEPROM reads in §1 — those are
code-free but they *find bugs*, and a working OOB **read** that walks `LVC` memory is a poor-man's
firmware image: it can leak the very code we cannot obtain, page by page, with no flash write.

### Decision table

| Route | What you get | Effort | Risk | Keeps stock firmware | Next action |
|---|---|---|---|---|---|
| **Console `drc_fw.bin` (MLC)** | full container + all 7 blobs (`LVC_` 682 KB, `WIFI`, `UMI_`, `IMG_`, `ERR_`, `INDX`, `VER_`) | **S** (1 console session, no pad) | none | yes | Start `wupserver`; recursive `wupclient` listing of `storage_mlc01:`; grep `drc_fw`; copy out; `fwpack.py unpack`; record SHA-1s |
| **NUS/CDN system title** | same bytes, encrypted-in-transit until the ticket is applied | M (title ID hunt + keys) | none | yes | Only if the MLC file is absent: enumerate update titles, look for a content named `drc_fw.bin` |
| **Passive capture of a console push** | wire-exact `0x03` stream; settles `blockSize`/index base; no new code bytes | S to arm, **unbounded wait** | none (monitor only) | yes | Arm capture on ch 40 before power-on; watch `svc 0/0x02/0x03/0x04`; validate against the MLC file |
| **SPI clip read (CH341A)** | **entire 32 MB**: SPL, both products, Service/diagnostics, lang, TVcode | M (open pad, clip, 2 reads) | mechanical/ESD only | **yes** | Verify chip marking + 3v3, remove battery, read twice, diff, store off-box |
| **UART boot (+ fork wupbootdump)** | boot ROM + our own flash dumper + permanent recovery | M–L (2.8 V adapter, dongle, ARM code) | low; never writes | yes | Build `wupbootdump` first; accept on SHA256 `1ba084d3…a7fc1`; then port a `drvflash` reader |
| **Over-the-air push of our image** | arbitrary code on the pad (the goal) | M (needs `01` unknowns resolved) | **high — can strand the pad** | **no** | Only after a verified 32 MB backup *and* P-b, on a donor pad if one exists |

**What I could not verify.** (i) The exact MLC/NUS path and title ID of `drc_fw.bin` — only that it is there
(`V`, drc-fw-patches README). (ii) The flash part number (25Q256A) — inherits from our own notes, not
re-checked today. (iii) Every `U` row in §1's table — all are untested reads; each is one command. (iv) The
`9004` cause — note the `SO_REUSEADDR` confound before concluding anything about state gating. (v) No
No-Intro hash values: the catalogue page did not render them to a non-JS fetch. (vi) No GBAtemp contents —
Cloudflare blocked the fetches; only titles and search snippets were used, and no claim above rests on an
unread GBAtemp page.
