# Boot, states and modes of the Wii U GamePad — and which of them we are streaming into

Compiled 2026-11-04. Companion to `RESEARCH.md` (link protocol), `GROUND-TRUTH-SESSION.md`
(measured console session) and `CODEC-SPEC.md` (payload). This document answers one
question that keeps coming back in different shapes:

> *"The pad boots into a mode that isn't full mode — icons, some messages, then a
> loading screen when it tries to reach the console. Are we streaming into one mode or
> another? Console on or off? Are we faking the console up, or hooking the stream? Does
> the screen it happens to be on matter?"*

Confidence tags used throughout:

| Tag | Meaning |
|---|---|
| **[D]** | Documented — read in `research/libdrc/web/docs/re/` (boot, overview, wifi, cmd, vstrm, services) |
| **[M]** | Measured — from our own captures (`capture/`, `out/evidence/`) or on air with our stack |
| **[I]** | Inferred — consistent with [D]/[M] but not directly observed; do not cite as fact |

---

## 1. Short answers

| Question | Answer |
|---|---|
| Does the pad have distinct "modes" at boot? | **Yes, and they are firmware states, not link modes.** The LVC firmware's `main` is a state machine **[D]** that decides which managers/services/drivers to initialise. The panel is painted by *either* the pad's own local UI (`draw`/`userif` + `resource`) *or* by decoded H.264 from a DRH. What you see on the glass is which of those two owns the panel right now. |
| Which mode do we stream in? | Exactly one: **DRC normal-operation mode** — WPA2 with Nintendo-OUI selectors, DHCP `192.168.1.11`, and the five UDP services on 50010/50020/50021/50023/50025 **[D][M]**. There is no second streaming protocol. What changes is the pad's *state*: the stream is only painted once the pad has armed its AV path. |
| Console on or off during a stream? | **Fully off** (not standby). Two reasons, both mechanical: (a) we clone the console's identity down to the BSSID, so the pad cannot tell us apart and may serve the *console's* screen mid-test **[M]**; (b) the console's DRH also owns the session-start sequence, so its presence makes the result uninterpretable. Console **on** is required for exactly two things: pairing route A and ground-truth capture. |
| Are we faking the console, or hooking its stream? | **Faking it — total impersonation.** We are the DRH: AP + DHCP + all five services. Nothing is hooked, tapped or MITM'd. The pad's only trust anchors are the Nintendo cipher selectors and the PSK stored in its UIC EEPROM **[D]** — no console certificate, no BSSID pinning — so "console" is a role anyone holding the PSK can take. |
| Does the pad's current screen matter? | **Yes, twice.** (1) The pad paints its own UI until its AV path is armed; an armed-but-unpainted session looks identical to a broken one from the outside. (2) When the pad runs an on-pad application (`userif`) it consumes input locally, so input tests taken on that screen measure the wrong consumer. The console also explicitly *disables* pad video when the Home menu hides it (cmd service 5, method `0x08`, payload `00`) **[D]** — the pad's display is a commanded state, not an emergent one. |
| Is "associated + ACKing commands" enough? | **No.** We have proven association, 4-way, DHCP, input, UIC config replies and command ACKs, while the panel kept showing the pad's own notice **[M]**. The remaining gate is inside the pad's session/display logic, and libdrc documents one firmware rule that fits: *"Recent versions of the GamePad firmware will only show the video stream after receiving one [UVC/UAC] command"* **[D]**. |

---

## 2. What the pad actually is: four processors and one dumb panel

The GamePad is not "a screen with Wi-Fi". It is a small computer whose only job is to
decode a stream, draw a local UI, and ship input upstream **[D]**:

```
                        ┌──────────────────────────────────────────────┐
                        │  LCD 854x480 RGB888 + resistive touch         │
                        │  (painted by whoever owns drvldc right now)   │
                        └───────────────▲──────────────────────────────┘
                                        │ parallel RGB / i2c panel ctrl
┌───────────────────────────────────────┴──────────────────────────────────────┐
│ DRC-WUP  ("LVC", "the ARM9")   ARM926EJ-S, MegaChips, eForce/µITRON 4.0      │
│   drivers:  lcd blit vout vcapt cmos aout acapt aamp dma wifi uic spi i2c    │
│   services: vstrm astrm hiddat cmd msg wii                                   │
│   managers: cmd con nwk devif draw gamectrl ictag ir msg nvram resource      │
│             sound state sync time userif video                               │
│   main: a state machine choosing what to init, moment to moment              │
└───────┬───────────────────────────────┬───────────────────────┬──────────────┘
        │ SPI (UIC = slave)             │ SDIO                  │ i2c/gpio
┌───────▼───────────────┐   ┌───────────▼────────────┐  ┌───────▼──────────────┐
│ UIC-WUP (STM8)        │   │ BCM4319 (Cortex-M3)    │  │ PMIC / panel / amp   │
│ input, touch, accel,  │   │ Wi-Fi firmware, 5 GHz  │  │ power rails, LEDs,   │
│ gyro, magnet, PMIC,   │   │ 802.11n, own fw image  │  │ backlight, headphone │
│ LEDs, 2 KB settings   │   │ from flash blob "WIFI" │  │ amp routing          │
│ EEPROM                │   └────────────────────────┘  └──────────────────────┘
└───────────────────────┘
        ▲
        │ 128-byte input blob, 180/s, straight from UIC to the DRC over SPI
        └── "generated on the UIC and received unmodified by IOSu on the console"
```

Three consequences that shape everything below **[D]**:

1. **The radio is a second CPU with its own firmware image.** The pad's 802.11 does not
   exist until that image is running. This is the literal answer to *"it looks like it's
   loading something deeper in the hardware"*: it is. (libdrc lists *when* the Wi-Fi blob
   is booted as an open TODO — the ordering is not documented.)
2. **The H.264 decoder is a hardware block the firmware must bring up** (`video` manager
   over `vout`/`vcapt`). Decode is not free-standing: it is armed as part of a session.
3. **The panel has no idea what a stream is.** It is a framebuffer target. Local UI and
   streamed video are two paint sources competing for one `drvldc`.

---

## 3. The boot chain, stage by stage

Sources for the hardware stages: `research/libdrc/web/docs/re/boot.rst` and
`overview.rst` **[D]**. On-air/screen evidence is ours **[M]**; anything else is tagged.

| # | Stage | What runs | What is on the glass | What is on the air | Our leverage |
|---|---|---|---|---|---|
| **S0** | On-chip boot ROM | Reset vector at `0x0`; reads first 4 bytes of SPI flash = bootloader size, loads SPL (`N-32` bytes) to `RAM_SIZE-64K` **[D]** | nothing (backlight off) | none | none — this is before the radio exists |
| **S1** | Secondary bootloader (SPL) | Interrogates the **UIC** over SPI for a debug device on the extension port; if present loads the *service* firmware volume at `0x1C00000`. Otherwise reads the firmware-version byte at flash `0xF000` and picks the volume at `0x100000` (ver 0) or `0x500000` (ver 1) **[D]** | still nothing | none | A debug device on the expansion port would make the pad boot **service/diagnostic firmware instead of its normal firmware** — an unreached option, noted for completeness |
| **S2** | Volume header + image load | Parses `INDX` (blob table: `INDX/VER_/LVC_/UMI_/WIFI/ERR_/IMG_`), loads `LVC_` (ARM9 firmware), `UMI_` (UIC firmware), `WIFI` (BCM4319 Cortex-M3 firmware) **[D]** | nothing, then a first local frame | none | none |
| **S3** | LVC firmware start-up | eForce/µITRON scheduler; drivers up: `flash`, `spi`, `i2c`, `gpio`, `dma`, `uic`, `lcd`, then `resource`+`draw` load `IMG_` assets and the EEPROM "opening screen" entries (cmd svc 0/`0x0a` indexes 3–4 are literally `opening_screen_1/2`) **[D]** | **local splash / local UI begins** — the panel is now owned by the pad itself | none yet | Observability only: the pad's own UI is `draw` painting `resource` assets |
| **S4** | Network bring-up | `wifi` driver + BCM4319 firmware; `con` (low-level Wi-Fi) then `nwk` (IP/UDP); services `vstrm/astrm/hiddat/cmd/msg` bound on `50120/50121/50122/50123/50110` **[D]** | local UI continues (icons/messages); connect attempt begins | **beacons from our AP must already exist**; pad scans 5 GHz, sends directed probes for the SSID it learned at pairing (normal-mode AP hides its SSID) **[D][I]** | **This is our first attach point**: if our AP is up and carries the Nintendo selectors + the pad's stored PSK, association succeeds |
| **S5** | Association + keying | 4-way handshake with PTK rotated 3 bytes left; PSK from pad EEPROM (UIC settings) **[D][M]** | connect/"loading" screen **[I]** | 12 EAPOL frames per epoch in the console capture **[M]** | Proven repeatedly: pad joins, 4-way completes **[M]** |
| **S6** | DHCP + session open | DHCP `192.168.1.10`→`.11`; console starts `cmd` (query type 0, incrementing u16 seq; pad ACKs), then a **time command** ("DRH usually sends a time command when a DRC connects to it") **[D][M]** | still local UI until a session arms the AV path | In the real capture: handshake at 0.59 s, first command at 0.92 s, DHCP 6 packets **[M]** | Proven: pad gets `.11`, exchanges commands, sends 128-B input at ~163–172/s **[M]** |
| **S7** | AV session arm | `video` manager + `vout` decoder bring-up; **UVC/UAC command (query type 1) is the documented gate**: "Recent versions of the GamePad firmware will only show the video stream after receiving one such command" **[D]** | "loading" → stream **[I]** | Console: audio at 56.8 s, video at 61.0 s, UVC/UAC polling starts 70.2 s **[M]** | **This is where we are stuck**: pad accepts media, never paints; resync requests at ~63/s vs the console's 3 per 300 s **[M]** |
| **S8** | Steady stream | `video`+`sound` managers decode/present; `hiddat` upstream | the remote framebuffer | 59.19 fps, 5.20 dgrams/frame, ≤1710 B, IDR ~1/26 s **[M]** | Not yet reached |

**The ordering fact that matters most** **[M]**: in a real console session the pad is
associated and its services are alive for **~60 seconds before video starts** (0.59 s →
61.0 s). The pad's AV pipeline is armed *after* the session exists, and the single
`init`-flagged first frame comes at the *start of that video*, not at streamer start-up.
Our stack historically started media first and hoped the pad arrived — which is why the
`init` flag was measurably absent from 1508 of 1508 packets during the pad's session
(SETUP.md round 11j). Re-asserting `init` on every IDR fixed the symptom but broke console
parity (the console sets it on 25 packets, once); the structural fix is **start the media
stream when the pad enters the session**, exactly as `run/_wait-for-pad.sh` and Barista
("gates media on input seen + UVC/UAC reply seen") already encode.

---

## 4. One panel, two paint sources

This is the model that makes the observed screens make sense.

```
                      ┌───────────────── the LCD ─────────────────┐
   local paint path   │                                           │   stream paint path
   (always available) │                                           │   (session-gated)
        resource ───► draw ─────────────► drvldc ◄──── vout ─────┘
        (IMG_, EEPROM  │  "icons,        (panel)     ▲
         opening_      │   messages,                  │ hardware H.264 decode
         screens")     │   notice,                    │
                       │   on-pad apps"      video manager (armed by session)
                       └──────────────────────────────────────────┘
                               ▲                              ▲
                          userif (local input parsing      vstrm service (50120)
                           for on-GamePad applications)    gated by cmd/UVC-UAC
```

Consequences:

- The pad can be **fully associated, DHCP'd, ACKing every command, streaming input to us,
  and still be painting its own notice screen**. That is not a failure of the link; it is
  the pad choosing (or being told) to keep local ownership of `drvldc`. We have measured
  exactly this state **[M]**.
- The "icons and some other messages" screen the operator describes is **local UI**: the
  pad's own `draw`/`resource` output, plus on-pad applications (`userif` exists precisely
  to parse input "for on-GamePad applications" **[D]**). It is not a reduced console
  menu — the console is not painting it.
- *Which* local screen you are on matters for **input tests**: on a local screen, input is
  consumed by `userif`; under a session it goes to `hiddat`→VNC/keyboard. Same buttons,
  different consumer.
- The pad's display is **commanded**, and we can command it: cmd service 5 method `0x08`
  payload `00` disables video, `0x0a` payload `00` disables sound, `0x14` sets brightness
  1–5, `0x19/0x1a` push/pull LCD controller parameters over i2c **[D]**. Round 11p already
  drove the panel black and flickered it from userspace with a service-5 sweep **[M]**, so
  the display surface is reachable — the missing piece is the *state*, not the reach.

---

## 5. The firmware state machine, and how to ask the pad where it is

The pad will tell us which state it is in. Three documented read-only commands over the
cmd service (port 50023→50123) make the "which screen are we on?" question objective
instead of visual **[D]**:

| Command | Reply | What it proves |
|---|---|---|
| svc **4**, method **`0x05`** | 1 byte: `retvals[current_state]` where `retvals[] = {0,10,4,5,6,1,2,3,9,7,8,11}` (index read from the UIC) | **the pad's current state index** — a stable oracle even though the index→meaning map is undocumented |
| svc **4**, method **`0x04`** | 28 bytes version info | which LVC/UIC/firmware revision we are actually talking to |
| svc **1**, method **`0x05`** | 113 bytes: WL config vars, auth mode, enc type, **SSID and PSK as stored in the pad** | **which network the pad thinks it belongs to** — the direct test for "is this pad paired to us or to the console?" |
| svc **0**, method **`0x00`** | 8 bytes: running + installed LVC version | firmware identity |

Mode *changers* we can also issue **[D]**:

| Command | Effect |
|---|---|
| svc **4**, method **`0x01`** | reboot to a mode: payload `0` = normal, `2` = **firmware update mode**, `4`/`6` = shut down |
| UVC/UAC command field `f3` | `1` = switch pad to **vWii mode**, `3` = shut the pad down |
| svc **4**, method **`0x1a`** | shut down the pad if `flags = 0x42` |

So the pad's mode space is: **normal (streaming-capable)**, **firmware-update**, **vWii**,
**shutdown** — plus within normal, the UI/AV sub-states that `draw`/`video`/`userif`
arbitrate. We only ever want the first, and we should be *asserting* it rather than
assuming it. `run/pad-state.py` implements all of these as queries (dry run by default,
`--send` to transmit). **Verified on live hardware on 2026-11-04** — see §5.1.

### 5.1 First live measurement (2026-11-04 ~09:13, pad associated to `WiiUAP`)

Run before any other tool held port 50023, on the pad as it was last left — associated,
input flowing, still painting its own notice screen:

| Query | Reply | What it establishes |
|---|---|---|
| svc 5/`0x15` | `4` | LCD brightness level 4 = **our own 1/s `SetLcdBacklight` command got through**, so the command plane demonstrably actuates panel state |
| svc 0/`0x00` | `385944601` (running == installed) | LVC firmware identity; running and installed agree, so the pad is not mid-update |
| svc 4/`0x05` | **state index 0** | first calibration point for the oracle: **index 0 == pad showing its own notice screen under an active session** (the UI the operator described). Record it next to what the glass shows each time |
| svc 4/`0x04` | 28 B | `0000000b 00000040 190c0117 28000058 00080000 0c0221fe 00001ccc` |
| svc 1/`0x05` | `ssid="WiiUccfb65b68169"`, auth 2, enc 0, 64-hex PSK | **T2 PASS, and it is no longer an assumption: the pad's stored SSID and PSK are byte-identical to `run/pairing.env`** (sha256 prefix `36ef436c8412`). The pad belongs to us, not to the console |

Two operational lessons came out of that same run:

- **The oracle must own `192.168.1.10:50023`.** libdrc and the replay tools bind that port
  with `SO_REUSEADDR`/`SO_REUSEPORT`, so a second binder *succeeds silently* and the kernel
  splits the pad's replies between sockets. The symptom is indistinguishable from a dead
  pad: `NO REPLY` on some queries, and a spurious `error 9004` reply on another. Stop the
  stack (`run/drc-down.sh`) before probing, and never probe during someone else's phase
  test — a live `phase5-full-session.sh` was already holding the port minutes later.
- **The pad replies to `…:50023` regardless of the query's source port**, which is why the
  ephemeral-port fallback "works" sometimes and fails silently other times.

---

## 6. What "session" means, measured from a real console

From `GROUND-TRUTH-SESSION.md` §3 — the choreography we should be reproducing (times
from association):

| t (s) | Console does | Pad does |
|---:|---|---|
| 0.59 | completes 4-way | associates, keying done |
| 0.92 | starts `cmd` stream, u16 seq at bytes 6–7, **acks every pad reply (type 3)** | ACKs every command (type 1), replies (type 2) |
| 1.1 – 27.9 | pushes a **fragmented state message** to svc 0 / method `0x11` (see §7) | replies with 8 B acks, 24 B, and 5 × 792 B UIC config blobs |
| 56.8 | audio starts 50021→50121 (416 frames / 1664 B per 8.666 ms) | — |
| **61.0** | **video starts** 50020→50120; frame 1 = 25 datagrams, **all `init`-flagged**, all IDR | — |
| 70.2 | UVC/UAC query (56 B) begins, ~1/s; 50025 96-byte table begins, ~1/s | — |
| 74.9 | — | **3 × `01 00 00 00`** from port **50110 → console:50010** (resync request, 13.9 s after video start) |
| 75.2 | answers with one fresh IDR | — |
| 75 → 300 | nothing further | decodes for the remaining 225 s |

Read that as a state machine: **keyed → command plane alive → state pushed → AV armed →
media → (mistake) resync → repaired → steady**. Our stack is at "keyed → command plane
alive → media", with the pad in the *wrong* state for painting and asking for keyframes
30–60× more often than a healthy console session.

---

## 7. Two open leads this framing exposes

**(a) The UVC/UAC gate is a *command-plane* gate, and we may be sending it in the wrong
phase.** libdrc's rule ("no video display until it receives one") is the only documented
firmware gate we have not satisfied by construction. Console ordering: video at 61.0 s,
UVC/UAC polling from 70.2 s, and the request's `byte[0]` flips to `1` after the first
validated reply (GROUND-TRUTH §8 item 4, not yet implemented). Sequencing it *exactly*
as the console does — during an already-open session, with the reply acknowledged — is a
cheap, hardware-free experiment.

**(b) The console's dominant command traffic is a *4-fragment message*, and round 11o
replayed it wrongly.** Re-parsed from the decrypted capture
(`out/evidence/truth/port50123.bin`, 778 datagrams of 1048 B between t=1.12 and t=27.86 s):

| Property | Measured |
|---|---|
| Outer header | type 0, query 0, `payload_size = 1028`, u16 seq contiguous 15 → 792 |
| Generic header | magic `7e`, ver `01`, tid `0x10b`, **svc 0, method `0x11`**, error 0, payload_size `0x0404` |
| Payload | first 4 bytes = **u32 index, running 1…778 with zero gaps** |
| Flags | `0x42` on 584 pkts (multi-fragment: "more follows"), `0x40` on 194 pkts (final) |
| Grouping | strict **M M M S** cycle — each logical message is 3 continuation fragments + 1 final |
| Count | `778 = 4×194 + 2`: **194 complete messages, then a trailing `M M`** — the console stops mid-message at 27.86 s, which is worth remembering when we try to reproduce it |
| Cadence | ~7.3 messages/s, ~4 KB/message, ~240 kbit/s on the command plane |

Round 11o replayed *three individual fragments, all carrying "more follows"*, at 200 ms
apart, from an ephemeral port, without any final fragment — so no complete message was
ever delivered and the negative result does not rule this path out. The correct test is a
whole `M M M S` group at console cadence, from 50023, with our ACKs flowing. This is now
the highest-value command-plane experiment, because a ~240 kbit/s state push that runs
only for the first 28 s of a session is exactly the shape of a session/display-state
handshake.

---

## 8. Which mode we stream in, and the console on/off decision

There is one link mode. What we choose is the pad's *environment*:

| Configuration | Pad finds | Console's role | Verdict |
|---|---|---|---|
| **Console fully off** (unplugged / powered down, not standby) | only our AP | none | **The test configuration.** Deterministic: one DRH on the air, the pad's only option is us. |
| Console in standby (Quick Start enabled) | our AP *and* the console's | still alive — standby keeps the pad link to serve the Quick Start menu **[I]** | **Avoid.** This is very likely the "icons and other messages" screen the operator saw: the console in standby serving Quick Start over DRC. Also the one state where a test can silently measure the console instead of us. |
| Console on, pad connected to console | the console | full session | **Ground-truth capture only.** Needed for a console↔pad capture; never for our own streaming numbers. |
| Console on, SYNC ×2 | console's open `WiiU<mac>_STA1` AP | pairing registrar | **Pairing route A only.** The pad is deliberately in pairing mode here; our normal-mode AP is not the target. |

Two mechanical reasons the console must be gone for measurement, not just "for tidiness":

1. **Identity collision.** `run/drc-up.sh` sets our AP's BSSID to the console's MAC
   (`ip link set $APIF address cc:fb:65:b6:81:69`) and uses the console's PSK from
   `run/pairing.env` **[M]**. Same BSSID, same hidden SSID, same PMK = the pad sees one
   network with two radios and roams to whichever wins. There is no preference rule we
   control.
2. **Two session owners.** Even if the pad stays with us, the console's DRH is beaconing
   the same identity and the pad's state machine may react to it. Observed in practice:
   `run/replay-console-cmd.py` carries an explicit wait loop with the comment *"the pad
   prefers the real console when that is powered on"* **[M]**.

**Channel note.** Our AP runs ch149; the console used ch40 **[M]**. The pad found us on a
different channel, so no channel pinning is required — but the pad remembers the network
it learned at pairing, and its first scan target is plausibly the console's channel. Moving
our AP to the console's channel *with the console off* is a cheap robustness test (and a
good A/B for association latency).

**Pairing ownership, and why it matters later.** Today our PSK is the *console's* PSK
(route A), so the console remains a valid alternative AP for this pad forever. For a lab
end-state where the pad can only ever belong to us, re-pair via route B — we host
`wiiu_ap_pairing.conf`, we choose the PIN, and the pad stores *our* PSK **[D]**. Then the
console's beacons are cryptographically useless to the pad, and standby becomes harmless.
Cost: the console is then unavailable as ground truth until it re-pairs the pad itself
(SYNC ×2 restores it).

---

## 9. Impersonation, hijack, or observation — pick one

| Model | What it requires | What it gives | Status here |
|---|---|---|---|
| **A. Impersonation (what we do)** | Nintendo cipher selectors + the pad's stored PSK. Run an AP, DHCP, and the five services yourself. | A complete DRH: video/audio out, input/commands in. The pad needs no console at all. | **Working up to the display gate** **[M]** |
| **B. Active hijack / MITM of a live console session** | The above, *plus* winning BSSID/association against a co-located console (stronger RSSI or a faster 4-way), or injecting into a live PTK stream | Nothing extra — you end up doing A anyway, with a competitor on the air | **Not needed, not attempted.** Strictly harder and less reproducible |
| **C. Passive observation** | A 5 GHz monitor on the console's channel + the PSK to derive the PTK | Plaintext of a real session = ground truth (what we used to find every real defect) | **Done.** `capture/console-truth.pcap`, 99.9 % decrypted **[M]** |

Why impersonation is possible at all — the pad has exactly three trust anchors, and none
of them is an identity **[D][M]**:

1. **Cipher selectors** in the beacon/probe response: pairwise+group cipher and key mgmt
   all `a4:c0:e1` (Nintendo OUI) with AES-CCM. A supplicant that does not advertise these
   gets error `0x000c`. That is a *format* check, not a vendor check.
2. **The PSK**, stored in the pad's UIC settings EEPROM after a WPS enrolment, retrievable
   by us over the cmd service (svc 1/`0x05`). Whoever ran the WPS owns the pad.
3. Optionally the **SSID string** learned at pairing (the normal AP hides its SSID, so the
   pad must probe for it by name).

There is no console certificate and no key derived from console hardware. On BSSID
pinning, be precise: **prior art settles it, our own tests do not** — Barista and pc2drc
pair the pad to an AP on the *PC's* adapter (that is the whole point of pairing route B)
and stream happily, so the pad does not require the console's MAC **[D]**, but every test
in this repo has cloned the console's BSSID (`run/drc-up.sh` sets it explicitly), so *we*
have never exercised a different one. Our AP does prove the rest: a different radio, a
different channel, and a different throughput/latency profile than the console are all
accepted **[M]**.

What C did *not* do and cannot be confused with: recovering the console's PTK/GTK from a
passive capture is **decryption with a known PMK**, not a hijack. It required no attack on
the live session, and it is orthogonal to A — the capture's value was the *truth about the
protocol*, not access to the pad.

---

## 10. Test matrix: what state, what evidence, what counts as pass

Channel state, console state, pad state and the objective signal — the pad's screen cannot
be observed remotely, so these are the signals to record **[M]**:

| Test | Console | Pad state at start | Objective pass signal |
|---|---|---|---|
| T1 link | off | any (power on after AP is up) | 4-way + DHCP `.11` + input 50122→50022 ≥ 40 pkt/s |
| T2 identity | off | any | svc 1/`0x05` reply's SSID/PSK == our `run/pairing.env` (proves the pad is *ours*) — **PASS 2026-11-04, §5.1** |
| T3 session state | off | any | svc 4/`0x05` state index recorded before/after session open — build the index→UI map by correlating with what the operator sees (baseline: **index 0 = notice screen**, §5.1) |
| T4 media arm | off | session open, input flowing | `init`-flagged frame #1 is the **first** frame after session open; then pad resync rate (target **0**, console baseline 3/300 s; ours ~63/s today) |
| T5 UVC/UAC phase | off | session open | pad stops asking for keyframes after a console-timed UVC/UAC exchange (byte[0]→1 after first reply) |
| T6 state push | off | session open | whole `M M M S` svc 0/`0x11` group at ~7.3 msg/s from 50023, ACKs flowing; watch resync rate |
| T7 display commands | off | session open | negative controls: svc 5/`0x08 00` blanks our picture, `0x14` changes brightness — proves our command plane reaches the panel |
| T8 recording | **on** | pad on console | capture → decrypt (99.9 %) → diff against ours; the only configuration where console and pad are both meaningful |

Rules of thumb that fall out of the above:

- **Never derive conclusions from a run with the console powered.** Two DRHs on the air
  means the pad's screen may belong to neither participant you think it does.
- **Never treat "pad is sending input" as "pad is in our session"** — it can be true while
  the pad paints its own UI (measured) or while the console owns it.
- **Start media after session open**, not before: `init` is a first-frame-of-session flag.
- Keep the pad awake; a sleeping pad still pings but stops sending input
  (`run/_wait-for-pad.sh` encodes exactly this distinction).

---

## 11. Failure modes worth knowing before the next hardware session

| Symptom | Real cause |
|---|---|
| Pad associates, then leaves | Another beacon with the same identity (console on/standby), or our AP died: NetworkManager took `WiiUAP`, or `iw set type` flipped the vif back to `managed` **[M]** |
| A probe reports `NO REPLY` (or `error 9004`) while the pad is alive | Two sockets are bound to `192.168.1.10:50023` with `SO_REUSEADDR`/`SO_REUSEPORT`, so replies are split between them — the stack, a replay script and `pad-state.py` all claim that port happily **[M]** |
| Pad silent on the AV ports | Its AV path is not armed; check the command plane first (UVC/UAC + time command), not the encoder |
| Pad floods `01 00 00 00` | It is in the AV session and cannot decode (resync requests). A healthy console session has this 3× in 300 s, ours ~63/s **[M]** — the most useful pass/fail metric we have |
| Screen goes black mid-test | A service-5 command we sent (`0x08`, `0x14`, power-status `0x07` bit sweeps) — the panel is a commanded state **[M]** |
| Audio/format vanish | Egress on `udp/50121` blocked (it carries the 32-byte video-format/timing message too) **[M]** |
| Input tests look wrong | Pad is on a local screen (`userif` consumes it) instead of under session (`hiddat`) |
| Pad on vWii/firmware-update screen | Someone issued UVC/UAC `f3=1`, or svc 4/`0x01` payload 2. Recover with svc 4/`0x01` payload `0` |

---

## 12. Open questions, ranked

1. **Does a complete `M M M S` svc 0/`0x11` group (with ACKs, at console cadence) change
   the pad's display state?** Cheapest high-value test; round 11o never actually delivered
   one (§7b).
2. **Is the UVC/UAC exchange with `byte[0]=1` after the first reply the paint gate?**
   Documented as a firmware rule; we have never matched the console's *phase*.
3. **What does the svc 4/`0x05` state index actually enumerate?** Building that map is what
   turns "which screen is it on" from a guess into a measurement.
4. **When is the `WIFI` blob booted, and does the pad defer probes until then?** libdrc
   marks this TODO; it decides whether our AP being up "early" matters.
5. **Does the pad pin the channel it learned at pairing?** Test by moving our AP to ch40
   with the console off.
6. **Is the pad's decoder baseline-only?** (Bourdon/Dolphin claim, SETUP round 11k.) One
   env var (`DRC_PROFILE`) apart — resolve it with the resync rate, not the eye.
7. **Standby behaviour**: confirm experimentally whether the console in standby keeps the
   pad link (assumed **[I]** from Quick Start requiring it) — it determines whether "console
   off" must mean *unplugged*.

---

## 13. Evidence index

| Claim | Where |
|---|---|
| Boot chain, SPL/volume header/blob names, UIC debug volume | `research/libdrc/web/docs/re/boot.rst` |
| Four CPUs, driver/service/manager lists, `main` = state machine | `research/libdrc/web/docs/re/overview.rst` |
| Pairing WPS rot3, normal-mode Nintendo selectors, PTK rot3, DHCP | `research/libdrc/web/docs/re/wifi.rst` |
| cmd protocol, all service/method tables, UVC/UAC display rule, mode reboots | `research/libdrc/web/docs/re/sc-cmd.rst` |
| vstrm header/options, 5×6-MB-row chunking | `research/libdrc/web/docs/re/sc-vstrm.rst` |
| services/ports incl. broadcast msg on 50110 | `research/libdrc/web/docs/re/services.rst` |
| 128-byte UIC input blob, 180/s | `research/libdrc/web/docs/re/sc-input.rst` |
| Measured console session, session-start timeline, resync baseline | `research/GROUND-TRUTH-SESSION.md` |
| Our on-air state: association, DHCP, input proven, panel blacked by svc 5 sweep | `SETUP.md` rounds 11, 11b, 11p |
| Re-parsed `M M M S` fragment pattern (§7b) | `out/evidence/truth/port50123.bin` (this document) |
| Impersonation mechanics, BSSID/PSK cloning | `run/drc-up.sh`, `run/pairing.env` |
| Live state/PSK/brightness/firmware measurements (§5.1), and the port-collision failure | `out/evidence/pad-state/2026-11-04-oracle.md`, `out/evidence/pad-state/pad-state-091401.log` |
| The oracle itself | `run/pad-state.py` |
