# Wii U GamePad as a Linux screen — the non-radio routes (Nov 2026)

Fetched from the cited page unless marked UNCERTAIN.

## 1. Linux on the Wii U console

**State — CONFIRMED, active but stalled.** `linux-wiiu/linux-wiiu` (GitLab): default branch `rewrite-6.6`, last activity **2025-09-17**. Adélie, ArchPOWER, Debian and Gentoo images at [linux-wiiu.org](https://linux-wiiu.org/).

**Boot — CONFIRMED.** The [install guide](https://linux-wiiu.org/install.html) assumes "you already have Cafe OS homebrew set up and working… set up Aroma before continuing"; no ISFShax requirement is stated. Boot is `fw_img_loader` from the Aroma menu (hold **B on the GamePad** at power-on) → Petitboot → distro, and a **USB keyboard is mandatory** to select it. Storage: SD, USB 2.0 ("might feel slow and unresponsive"), or SATA. Boot time is unpublished — **UNCERTAIN**.
**Hardware — CONFIRMED** ([wiki.wii-linux.org](https://wiki.wii-linux.org/index.php?title=Wii_U)): triple-core PowerPC 750-class Espresso, R700-class GX2 GPU, 2 GB RAM, 4× USB 2.0, SD, and **Broadcom 43362 802.11b/g/n — 2.4 GHz only**. That is not the 5 GHz DRC radio.

**Display — TV yes, GamePad video no (CONFIRMED).** `drivers/gpu/drm/wiiudrm/` (branch `wiiudrm`, 2024-05-17) plus `r600fb` handle TV output. But the GamePad driver is **input-only**: `drivers/hid/hid-wiiu-drc.c` (503 lines, © 2021 linkmauve / 2019 Ash Logan) exposes touch (854×480), stick axes, accelerometer, gyro and battery, with **no video, panel, DSI or stream code**. GamePad video never shipped (**#23** "Gamepad FB being overwritten", 2021-08-08 → 2024-10-31, pad "flooded with garbage"; **#9** "Integrate swapDRC", 2018-05-09), and acceleration is absent (**#19**, **#18** open since 2020-01-27). **You cannot drive the console's own GamePad with published Linux software.**

## 2. Homebrew on the console — the route that works

**Moonlight Wii U — CONFIRMED working.** GaryOderNichts, [GitHub](https://github.com/GaryOderNichts/moonlight-wiiu): last push **2026-02-14**, release **v1.6** (2024-02-20); [HBAS listing](https://hbas.bdns.dev/wiiu/moonlight-wiiu/) updated **30/01/2025**. Its controller list leads with "**Gamepad** (can be disabled with the `disable_gamepad` option)" — the stream renders on the pad — and since v1.3 "**Use the GamePad touchscreen for mouse emulation**". The listing says "try using **sunshine** instead" if your PC is unsupported, so a Linux host works without NVIDIA. A live desktop on the GamePad with a pointer; **typing is unproven** (no on-screen keyboard documented — UNCERTAIN).

**Wii U VNC — CONFIRMED, view-only.** rw-r-r_0644 & Compucat, v0.5, updated **30/01/2025**: "**Currently does not have support for controlling the remote computer**". No DRC streamer bypassing the console and no credible browser-based remote desktop found.

## 3. Driving the GamePad LCD directly

**Panel — CONFIRMED.** [wiiubrew](https://wiiubrew.org/wiki/GamePad): "RGB888 854 x 480 TFT-LCD… with a resistive touchscreen"; the 5 GHz module "pairs to the console via WPS" and carries **H.264 video both ways**. [kuribo64](https://kuribo64.net/wup/doku.php?id=lcd) (modified 2025-03-16) gives the panel ID (**JDI R69208** / **Panasonic MN838985**), I2C bus 3 addr 0x39 and init sequences; its [display controller](https://kuribo64.net/wup/doku.php?id=lcd_controller) has a framebuffer overlay *and* a "video feed" from the **H.264 decoder** — it renders a decoded stream, never raw pixels.

**Interface is LVDS — CONFIRMED.** [BitBuilt worklog](https://bitbuilt.net/forums/threads/worklog-wii-u-gamepad-original-screen-custom-lcd-driver-board.5947/): the panel is IPS and **LVDS**, not TTL. The author built an **RTD2660** board with custom firmware for "854x480, not 800x480", but firmware and PCB sources "will be released when everything is confirmed to be working" — **no release exists**, and a reply states "the Wii U LCD can't be driven by standard video outputs yet."

**UART boot — CONFIRMED, the real discovery.** wiiubrew documents a 4-pad header by the battery (RXD, UART boot, TXD, Vcc 2.8 V; GND on TP128) at **115200 8N1**. **UART boot** works by tying pad 2 to ground, powering on, then sending a 4-byte length (LSB first) plus the blob; code loads at `0x0` in RAM whose first 32 bytes are **ARM exception vectors**. Arisotura confirmed it ("gamepad supports UART boot", [kuribo64](https://kuribo64.net/board/thread.php?id=2855), 2025-11-05).

**Nobody has driven the display over UART (no evidence found — UNCERTAIN-negative)**, and the arithmetic kills it: 115200 baud ≈ 11.5 KB/s against 854×480×3 = 1.23 MB per frame (~107 s/frame). UART is a loader, not a video pipe. No camera-free LCD capture method found.

## 4. "Just buy the right dongle"

**For console impersonation — CONFIRMED, and archived.** [pc2drc](https://github.com/thefloppydriver/pc2drc) wants "**802.11n 5GHz rt2800usb-compatible USB WiFi Adapter (RT5572-based adapters are known to work)**" and **a Wii U for pairing**. It now opens: "**As of april 5th of 2026, this project is archived.**" `GaryOderNichts/libdrc` last imported 2025-01-24.

**The maintained card list is Project Vanilla's** ([Wireless-Compatibility](https://github.com/vanilla-wiiu/vanilla/wiki/Wireless-Compatibility)): ✅ RT5572 (TP-Link TL-WDN3200), RTL8812AU/8821AU (with `lwfinger/rtw88`), MT76x0 (Archer T2UH/T3U Plus), MT7610U, AR9462, and many **Intel laptop cards**. **Caveat:** that table covers the *gamepad→console* direction (PC joins the console's AP), not hosting the DRC AP, which needs AP mode + TSF control + injection. Do not buy an AX210 expecting pc2drc to work.

**AR9285 vs AR9280 — CONFIRMED.** The AR9285/HB95 is sold as "**802.11n b/g** wifi 1x1 PCIe half-size mini card" ([datasheet](https://www-onepage.taiwantrade.com/EP/resources/member/1329/productcatalog/00e4ffff-9c7a-4a61-836d-58d43150239e_DNXA95_datasheet.pdf)) — b/g only, so **2.4 GHz and unusable**; the AR9280 is the dual-band part ([ath9k docs](https://wireless.docs.kernel.org/en/latest/en/users/drivers/ath9k.html)).

**Prices — mostly UNCERTAIN.** Verified: Chocolate dongle **$59** ([GBAtemp](https://gbatemp.net/threads/worlds-first-wii-u-gamepad-to-pc-dongle-called-chocolate-announced-initial-wave-of-pre-orders-sold-out-immediately.681035/), May 2026); [pricecharting](https://www.pricecharting.com/console/wii-u) today: **"Wii U Console Deluxe Black 32GB" ~$118.71 loose / $141.35 complete**. No trustworthy current figure for RT5572/RTL8812AU dongles (camelcamelcamel's TL-WDN3200 tracker is stale to 2015), so none is invented.

## 5. What is new in 2025–2026

**Project Vanilla — CONFIRMED, the big one.** [vanilla-wiiu/vanilla](https://github.com/vanilla-wiiu/vanilla): 2,373 stars, last push **2026-10-22**; a "**software clone of the Wii U gamepad**… **alpha** at best". A PC, Steam Deck, Linux Switch, Android or Pi acts as a GamePad *for a real console*. It ships `nexmon` (BCM4356), `rtl8720dn` patches, `lkl`, a `hostap` fork and a refreshed **`drc-hostap` fork pushed 2026-08-26**.

**Project Chocolate — CONFIRMED announced, apparently dead.** Announced ~2026-05-17 ([Distant Arcade](https://distantarcade.co.uk/chocolate-is-the-worlds-first-wii-u-gamepad-adapter-for-pc/)): a $59 USB dongle by "Famidawg" giving PC use of the real GamePad with "**desktop mirroring/virtual display**". 30 units sold out, Fall 2026 delivery; latest GBAtemp posts: "**no source code. shipping cancelled. no updates in a month, all the discord invites are expired.**"

**melonpad — CONFIRMED, best unfinished work.** [Arisotura/melonpad](https://github.com/Arisotura/melonpad), commits to **2026-04-26**. Working: **I2C, SPI, LCD and framebuffer initialization, DMA, input**; **Wi-Fi is still roadmap**. It needs the pad's soldered QSPI flash replaced by a **FPGA** that "wouldn't even fit in the gamepad's case", and warns that uploading makes stock restore impossible without hardware modding. Docs: [kuribo64.net/wup](https://kuribo64.net/wup/doku.php?id=start).

**New console-side RE — CONFIRMED.** Rambo6Glaz published an IOS exploit in `/dev/ccr_uac` and `/dev/ccr_uvc`, the GamePad mic/camera drivers, giving IOS code execution from PowerPC userland ([2026-09-07](https://ramboglaz.github.io/wiiu/2026/09/07/iosu-exploit-ccr-uvc-uac.html)).

**Nothing bypasses the console for pairing *and* drives the real pad's display:** pc2drc needed a console and is archived; Chocolate promised exactly that and appears dead.

## Comparison

| Route | Works today? | Hardware | Cost | Destructiveness | Linux-desktop fidelity | Input path |
|---|---|---|---|---|---|---|
| **Radio impersonation** (libdrc / pc2drc) | ⚠️ Worked for its author; **archived 2026-04-05**, needs console to pair | 5 GHz 802.11n SoftMAC USB NIC (RT5572) + dedicated host + console | Console ~$119 + adapter (unverified) | None | Full desktop; touch = absolute mouse | GamePad→libdrc, proven |
| **Linux on console** | ✅ boots to TV; ❌ **no GamePad video driver** | Console + Aroma SD + USB/SATA + USB keyboard | ~$119 | Low (SD; SATA mod if used) | Poor: no accel (#18/#19 open since 2020), USB 2.0 | GamePad input works (`hid-wiiu-drc`) |
| **Homebrew on console** (Moonlight Wii U) | ✅ **Yes — v1.6, works with Sunshine** | Console + Aroma + SD + LAN adapter recommended | ~$119 | None | Good: H.264, 854×480, touch = absolute mouse; typing unproven | GamePad fully supported |
| **LCD hardware mod** (RTD2660/LVDS) | ❌ firmware + PCB unreleased | GamePad panel + custom driver board | Unknown; panel salvaged | **High** — pad gutted, LVDS wired direct | Native 854×480 | None — video only |
| **UART display driving** | ❌ no reports; ~11.5 KB/s vs 1.23 MB/frame | 3 wires on 4-pad header + USB-serial | Trivial | Low (solder 3 pads) | Unusable for video; loader only | Separate; UART boot is the real use |
| **Chocolate dongle** | ❌ May 2026, sold out, **shipping cancelled**, no source | Dongle | $59 announced | None | Would have been ideal | Promised all features |

## Verdict

The radio is not the only path, and today it is not the best one. **Moonlight Wii U on an Aroma-hacked console is the only approach that actually puts a PC/Linux desktop on a real GamePad with a working pointer**: maintained into 2026, with GamePad output and GamePad-touch-as-absolute-mouse explicitly supported, and Sunshine named as the fallback host. It costs one used console (~$119 loose, verified) and zero modification; test keyboard entry before committing. Linux-on-console is a dead end *for the screen* — `hid-wiiu-drc.c` is input-only and the GamePad framebuffer never shipped (#9, #23) — so it buys a TV-bound, unaccelerated box, not a handheld terminal. The LCD mod and UART are real discoveries (an LVDS panel with documented I2C init; UART boot running custom ARM code), but neither has a published success at putting video on that panel, and UART's bandwidth makes it arithmetically hopeless. Watch melonpad (LCD, framebuffer and input working; only Wi-Fi missing) and Vanilla's `drc-hostap` fork, where live DRC work migrated. Project Chocolate, the one product promising GamePad-on-PC with display mirroring, sold 30 units and went silent — do not wait for it.
