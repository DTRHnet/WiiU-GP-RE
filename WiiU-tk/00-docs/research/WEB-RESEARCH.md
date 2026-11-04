# Web research — a Linux screen on the Wii U GamePad, with GamePad control

Compiled 2026-11-03. Companion to `RESEARCH.md` (protocol), `SETUP.md` (runbook),
`gamepad-alternative-paths-report.md` (non-radio routes).

Question: given everything already built here, what is the shortest real path to
"Kali desktop on the GamePad, GamePad input driving Kali"?

**Headline: a 2026 project called Barista does exactly this, and it needs neither
our kernel patch nor VNC nor a Wii U console.** The work below explains why, and
what to keep from our stack.

---

## Part 0 — verified on this host, not taken from the web

### 0.1 Only one kernel change is needed, and it is the TSF export

`pc2drc/kernel-patch-files/patches/` holds exactly three patches:

| Patch | Content |
|---|---|
| `kernel_above_5_11_mac80211.patch` | 98 lines, 5 hunks, adds `/sys/class/net/<iface>/tsf`; its own `README.DRC` says only *"Added a new /sys node for mac80211 devices: tsf"* |
| `kernel_below_5_12_mac80211.patch` | same, older layout |
| `mac80211_rx.patch` | one line: `ieee80211_data_to_8023_exthdr(..., data_offset, true)` |

**There is no cipher patch in it.** This matters: `SETUP.md` rounds 4-6 concluded
the next step was patching `mac80211` to accept Nintendo's `a4:c0:e1` selectors.
Source inspection says that patch is not needed on usable hardware.

### 0.2 Where `a4:c0:e1` is and is not validated

- `drc-hostap/src/common/wpa_common.h` — under `CONFIG_TENDONIN`,
  `RSN_CIPHER_SUITE_CCMP` *becomes* `a4:c0:e1:04` and
  `RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X` becomes `a4:c0:e1:02`. The same constants
  drive both RSN-IE generation and `rsn_selector_to_bitfield()` parsing, so
  userspace emits *and* accepts the Nintendo suite. That side is complete.
- `drc-hostap/src/drivers/driver_nl80211.c:2529` `wpa_alg_to_cipher_suite()` maps
  `WPA_ALG_CCMP` → **standard** `WLAN_CIPHER_SUITE_CCMP`. The Nintendo OUI never
  reaches the kernel key API; the kernel is asked for ordinary CCMP.
- `mac80211` transmits whatever RSN IE hostapd hands it, and on every driver
  without `WIPHY_FLAG_HAVE_AP_SME` association is handled by hostapd in
  userspace, parsing the pad's IE with the TENDONIN-aware parser.
- So the `-22 EINVAL` on the Pi was the **brcmfmac firmware** rejecting the
  beacon (`brcm_configure_wpaie: ivalid OUI`), not mac80211. That confirms SETUP
  round 6 and retires round 4's "patch mac80211 for ciphers" plan.

### 0.3 Which radios can work (Kali kernel 7.1.5 sources, extracted and grepped)

`WIPHY_FLAG_HAVE_AP_SME` is set only by `qtnfmac`, `mwifiex`, `wil6210`,
`ath6kl` — every practical candidate lets hostapd own association.

`.get_tsf` registered in `drivers/net/wireless/`:

| Driver | `.get_tsf` | 5 GHz AP | Verdict |
|---|---|---|---|
| `rt2800usb` (RT5572/RT3572) | `rt2800_get_tsf` | yes | documented libdrc hardware |
| `ath9k` (AR9280) | `ath9k_get_tsf` | yes | needs a slot |
| `ath9k_htc` (AR9271) | yes | **2.4 GHz only** | unusable |
| `mt76` mt7921/mt7925 | `mt792x_get_tsf`, real LPON UTTR registers | yes (AP on USB since 5.19) | **best modern candidate** |
| `rtw88` / `rtw89` | no / no op | yes | what Barista actually uses (see Part 2) |
| `iwlwifi` (AX210) | **no** | yes, no AP_SME | zero-cost experiment, 0.5 |
| `brcmfmac` (Pi 5) | no | yes | **proven dead end** |
| `mac80211_hwsim` | yes | virtual | bench testing |

### 0.4 The 2013 hostapd is obsolete — 2.12 builds natively here

`vanilla-wiiu/drc-hostap` is **hostapd/wpa_supplicant 2.12** (upstream 2026) with
the DRC patches carried forward. Built on this host, no root, no Ubuntu 20.04
container, no gcc 9, no OpenSSL 1.0.1u:

```
hostapd v2.12          Nintendo CCMP selector 0xa4c0e104 present x6
wpa_supplicant v2.12   Nintendo CCMP selector 0xa4c0e104 present x4
wpa_cli v2.12
```

with Kali gcc 16.2 + OpenSSL 3.6. Dev headers were fetched with
`apt-get download` + `dpkg-deb -x` into a local prefix; the only link tweak was
dropping libssl-dev's static archives so the system shared `libcrypto.so.3` is
used. Recipe: `build/build-hostap-2.12-native.sh`.

Its HEAD is `a2f705d "conf: disable unused backends"` (2026-08-26) — **the exact
revision Barista pins** (Part 2), so this build is what Barista would consume.

Config parse with the real console SSID/PSK reaches nl80211 init (fails only on
the deliberately fake interface):

```
Configuration file: /tmp/drc-check.conf
nl80211: Driver does not support authentication/association or connect commands
Could not read interface __drc_check0 flags: No such device
```

Porting note: 2.12 keeps a *real* SSID in `ssid=` and hides it with
`ignore_broadcast_ssid=2`; it rejects a literal empty `ssid=`.

### 0.5 A zero-purchase experiment exists

`iwlwifi`/AX210: AP mode present (`BIT(NL80211_IFTYPE_AP)` in
`mvm/mac80211.c`), no AP_SME flag, **no `.get_tsf`**. With
`DRC_SYNTHETIC_TSF=1` it could host the Nintendo-OUI AP today — but only if it
is not also the uplink, so **Ethernet must be connected first** (`eth0`/`eth1`
are `NO-CARRIER`). Unknown: whether iwlwifi firmware accepts `a4:c0:e1` in the
beacon. Costs nothing but root and a cable.

---

## Part 1 — radios

### 1.1 rt2800usb: still documented, still exports TSF

`rt2800usb_mac80211_ops` carries `.get_tsf = rt2800_get_tsf` on current master,
reading `TSF_TIMER_DW1/DW0`
([rt2800usb.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/wireless/ralink/rt2x00/rt2800usb.c)).
Caveats: a standing "rt2x00 regression" tracker exists
([lore](https://lore.kernel.org/all/d0648a69-e34b-95ae-d291-6cba56526915@leemhuis.info/t.atom)),
the AP/IBSS large-transfer TX bug is historic but real
([lore 2011](https://lore.kernel.org/all/201103171316.02636.helmut.schaa@googlemail.com/T/)),
distros still carry out-of-tree rt2800usb fixes
([Fedora](https://src.fedoraproject.org/rpms/kernel/raw/ac67590916a449d1e71a791f6a0c3688251ec074/f/rt2800usb-slow-down-TX-status-polling.patch)),
and RT5572 5 GHz AP reportedly fails on **DFS** channels
([SuperUser](https://superuser.com/questions/1326654)). No confirmed fresh
"broken on 6.x/7.x" bisect was found.

### 1.2 MT7921AU is the strongest modern softmac+TSF option

morrownr's matrix (2026-05-17) lists MT7921au in-kernel since 5.18, **AP ✓**, and
records that "AP mode support added to the **mt7921u** driver in kernel **5.19**"
([USB_WiFi_Chipsets.md](https://raw.githubusercontent.com/morrownr/USB-WiFi/main/home/USB_WiFi_Chipsets.md))
— AP works on the *USB* transport. Limits are feature-shaped, not fatal: no
WDS/4addr in AP mode on mt7921u while MT7612U passes
([#392](https://github.com/morrownr/USB-WiFi/issues/392)); Bluetooth
misdetection needs `modprobe -r btusb`
([#107](https://github.com/morrownr/USB-WiFi/issues/107)).

MT7925 is riskier: in-kernel 6.7+, first USB adapter (Netgear A9000) July 2025,
AP-mode crashes fixed only in 6.17+
([#603](https://github.com/morrownr/USB-WiFi/issues/603)), DFS CAC failures
([istoreos #2679](https://github.com/istoreos/istoreos/issues/2679)).

### 1.3 Shortlist

| Adapter | Chipset / driver | softmac | get_tsf | 5 GHz AP reported | Confidence |
|---|---|---|---|---|---|
| Alfa AWUS036AXML | MT7921AU / `mt7921u` | yes | yes | yes (since 5.19) | high |
| Alfa AWUS036ACM | MT7612U / `mt76x2u` | yes | not seen | yes, cleanest reports | high (TSF unconfirmed) |
| TP-Link TL-WDN3200 | RT5572 / `rt2800usb` | yes | yes | yes, non-DFS | medium |
| TP-Link Nano AC600 | RTL8821AU / `rtw88` | yes | **no** | yes — **Barista-tested** | high for Barista |
| RTL8852BE (M.2) | `rtw89` | yes | no | yes — **Barista's dev target** | high for Barista |

### 1.4 Bench-testing without hardware

`mac80211_hwsim` "can be used to test most of the mac80211 functionality and
user space tools (e.g., hostapd and wpa_supplicant)", uses software encryption,
and ignores regulatory rules
([docs](https://wireless.docs.kernel.org/en/latest/en/users/drivers/mac80211_hwsim.html)).
Two radios let a virtual GamePad join our AP and exercise beaconing, RSN IEs,
association and EAPOL. It cannot test RF, DFS, firmware OUI rejection, real TSF,
or the pad itself.

---

## Part 2 — ecosystem: the stack we built has a live successor

### 2.1 Status of the repos we depend on

| Repo | Last push | State |
|---|---|---|
| [opencma/libdrc](https://github.com/opencma/libdrc) | 2017-07-14 | dead (original) |
| [GaryOderNichts/libdrc](https://github.com/GaryOderNichts/libdrc) | 2025-01-24 | maintained fork, docs-only change; 1 open issue [#1 "Where to continue development"](https://github.com/GaryOderNichts/libdrc/issues/1) |
| [memahaxx/libdrc](https://bitbucket.org/memahaxx/libdrc) | last commit 2014 | tracker gone (HTTP 410) |
| [duanemach/drcvncclient](https://github.com/duanemach/drcvncclient) | 2015-07-04 | 0 issues, dead |
| [thefloppydriver/pc2drc](https://github.com/thefloppydriver/pc2drc) | 2026-04-05 | **archived**, 7 open issues, 77★ |

Fork `pushed_at` dates in late 2026 are fork-sync noise; their newest *commits*
are still 2017-2025.

### 2.2 THE finding: BetaZay/Barista (active, and it is our goal)

[github.com/BetaZay/Barista](https://github.com/BetaZay/Barista) — created
2026-09-06, **last push 2026-10-31**, VERSION 0.1, live Discord. README:

> Use a Wii U GamePad as a wireless second screen, controller, and audio device
> for your Linux desktop.

What it does, from the README and `docs/user-guide.md`:

- **Pairs a real GamePad with no console involved at all**, then reconnects from
  saved credentials. `docs/user-guide.md`: *"When **Pair now** and the four
  symbols appear, press SYNC on the GamePad and enter the symbols from left to
  right… Each Barista launch generates a new pattern for new pairings."* That is
  exactly `PLAN.md` Phase 4 **option B** (we host the pairing AP, we choose the
  code, no console), which `SETUP.md` recorded as "documented as possible; less
  proven". It is now shipping code.
- **Video + audio streaming**, GamePad input.
- **Desktop mode**: mirrors a monitor or an application window, "and uses the
  sticks and buttons as a mouse and keyboard", on both X11 and Wayland.
- **Built-in GamePad touch keyboard** ("Tap keys, or use D-pad + A; B deletes,
  X toggles Shift"), plus AppHook text prompts — this closes the "you cannot
  type over VNC" gap that killed the drcvncclient path.
- **`uinput` controller mode** and **Game mirroring** for Steam/PC games.
- Ships a **bundled hostapd** = the `vanilla-wiiu` 2.12 fork, pinned at
  `a2f705daa143791180754100194c91714f7e8801` — the commit built in §0.4.
- Tested hardware: **RTL8852BE (`rtw89_8852be`)** and the **TP-Link Nano AC600
  (`rtw_8821au`)** USB adapter; notes that Intel `iwlwifi` self-manages its
  regulatory domain and can mark every pairing channel `NO-IR` in AP mode (AX201
  confirmed, AX200 worked in one test). Same "use Ethernet or a second adapter"
  constraint we already documented.
- Status honestly stated: video can still show artifacts or lag, audio can
  stutter, touch/motion need broader testing.

**Why this changes our plan:** Barista derives the playback clock from
**monitor-mode radiotap TSF** (`core/drh/monitor_tsf_clock.h`,
`core/drh/runtime_transport.h`: *"Optional monitor-mode interface on the same
PHY. Linux radiotap RX…"*), with the `/sys/class/net/*/tsf` exporter as the
*preferred* path and radiotap as the fallback. That is why it works on
`rtw88`/`rtw89`, which have no `get_tsf` hook — **no mac80211 patch is
required**. It also replaces VNC entirely (direct capture + encode).

Caveats: install packages exist for Ubuntu 24.04 / Fedora 44 / Arch (Kali is
Debian-based and untested — a source build needs Qt6, PipeWire, libnl, libssl
dev packages, i.e. root), and it is v0.1 with real quality problems.

### 2.2b Barista's hostapd patch set — the fixes our build does not have

`third_party/hostapd-drc/patches/` holds 15 patches on top of hostap 2.12. They
are the accumulated knowledge of getting a real pad to associate:

```
0001 add CONFIG_TENDONIN build toggle
0002 wpa: Tendonin RSN selectors + PTK rot3
0003 wps: Tendonin KDK rot3
0004 nl80211: use standard ccmp selector for driver keys   <- matches §0.2
0005 wps: Nintendo vendor type and WPS1
0006 wps: match Wii U registrar advertisement
0007 hostapd: match Wii U HT advertisement
0008 tendonin: match Wii U vendor IE order
0009 nl80211: translate tendonin AP crypto selectors
0010 nl80211: retry tendonin initial group key
0011 nl80211: defer tendonin GTK until station key
0012 nl80211: retry tendonin pairwise key
0013 tendonin: reassert station state after assoc ack
0014 ap: rescan and retry when channel selection hits a regression
0015 restore Nintendo WPS discovery
```

0009-0013 are exactly the class of failure we hit on the Pi (key install
rejected, station dropped after assoc) and they do not exist in the vanilla fork
we built.

Verified here: the series is **not drop-in**. Applying in order gave **7/15 on the
vanilla pin `a2f705d`** (the rest are already present in the fork) and **10/15 on
pristine `hostap_2_12`** — so it was generated against a base slightly different
from both public candidates. Treat it as a documented reference implementation to
port from, and read 0009-0015 against our tree.

### 2.3 wozt/libdrc — the only fixes for the bugs that would have killed us

[wozt/libdrc](https://github.com/wozt/libdrc) (fork of GaryOderNichts, pushed
2026-09-15, seven commits 09-13→09-15, no README/announcement) fixes exactly the
two inherited TODOs ("video streaming timing randomly desyncing", "compatibility
with recent DRC fw (video stream never syncing)"). Mechanism it documents:

- libdrc always encoded with x264 preset **slow**; the GamePad then asks for a
  keyframe on **every single frame** (60/s on the wire) and the picture freezes
  within seconds. Presets **medium and below** produce zero requests (`subme>=8`
  alone is enough to break it).
- `constrained_intra_pred` must stay 1; QP is immovable at 32 because DRH mode
  emits no slice header.
- The `"\1\0\0\0"` message-port traffic is a **heartbeat misread as a keyframe
  request**; `idr=true` is a no-op under intra-refresh.
- Bursting a keyframe's ~25 packets caused the freeze. Fixes claimed: medium
  preset, rate-limited keyframes, real IDR via encoder restart, packet pacing on
  a monotonic clock.

**Corrections from the codec/transport round — see `CODEC-SPEC.md`:**

- Two of those claims **do not reproduce on our build**. With 5 mid-stream IDR
  requests over 60 frames, our drc-x264 emits 30 `NAL_SLICE_IDR`s (6 IDR frames),
  identically for presets slow/medium/ultrafast and with intra refresh on *and*
  off — so on this stack `idr=true` is **not** a no-op, and the encoder-restart
  fix should not be ported on that assumption.
- The "3.2 ms median inter-packet gap" is a comment in wozt's code with no
  capture, no range and no packet class, and it cannot be reconciled with
  Barista's measured 11.16–11.25 ms total frame span. Unverified.
- Barista **rejected** a 250 ms IDR cooldown ("more lag and more corruption") and
  answers every request immediately plus a proactive IDR every 60 frames. So
  "rate-limit keyframes" is not the right default; dedupe within the
  IDR → format-only → P lifecycle instead.

Known-working GamePad **firmware versions are undocumented** anywhere.

### 2.4 Upstreaming the DRC patches

A user asked the hostap list about getting Wii U support upstream
([2024-11-23](https://lists.infradead.org/pipermail/hostap/2024-November/043127.html),
[reply thread 2025-01](https://lists.infradead.org/pipermail/hostap/2025-January/043262.html)).
Nothing landed; the compile-time `CONFIG_TENDONIN` switch and the need for two
builds remain the obstacle. Conclusion: a patched fork stays necessary.

### 2.5 Documented AP settings that make a real pad associate

From `vanilla-wiiu/drc-hostap/conf/wiiu_ap_normal.conf` (2.12):

```
hw_mode=a
channel=36
beacon_int=100
dtim_period=3
macaddr_acl=0
auth_algs=3
ieee80211n=1
# wiiu uses greenfield, my driver doesn't support it
#ht_capab=[GF]
ssid=WiiUaabbccddeeff
ignore_broadcast_ssid=2
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
```

Interface setup from pc2drc's working recipe: `iw reg set US` → link up/down →
`hostapd -B` → `ip a a 192.168.1.10/24 dev WiiUAP` → **`ip l set mtu 1756 dev
WiiUAP`** (libdrc docs say 1800) → `netboot ... <gamepad-bssid>` so DHCP is
pinned to the pad's MAC. Barista searches a nine-channel plan when 36 fails; no
project documents a hostapd `bssid=` override.

---

## Part 3 — input, VNC and encoder

### 3.1 What the VNC path can and cannot do (two different clients)

Our `pc2drc` copy of drcvncclient (`libdrc-vnc/drcvncclient/src/drcvncclient.cpp`)
adds a keysym layer that upstream `duanemach` lacks:

| GamePad | pc2drc fork (ours) | upstream duanemach |
|---|---|---|
| touchscreen | absolute pointer | absolute pointer |
| ZL/ZR | RFB button 1 | button 1 |
| L/R | RFB button 3 | button 3 |
| middle button | — | — (no button 2 anywhere) |
| wheel | SDL wheel → buttons 4/5 | buttons 4/5 |
| A/B/X/Y | Enter / Backspace / Space / Tab | nothing |
| d-pad ←/→ | arrow keysyms | nothing |
| +/− | Paste / Copy | nothing |
| HOME | Escape | nothing |
| TV | mouse ↔ joystick mode | mode toggle (with `-joystick`) |

So a stock drcvncclient **cannot type at all** — keysyms only arrive from a
physical keyboard on the SDL window. Our fork emulates a handful of keys, which
is still not a desktop. Two known defects in our copy: `prev_x`/`prev_y` are
uninitialised (a button press before any touch jumps the pointer to 0,0), and
the touch mapping still uses compile-time `drc::kScreenWidth` (864 in libdrc's
`screen.h`), so after the 848x480 patch the right strip mis-maps.

`-joystick` switches to libdrc's system input feeder (uinput gamepad); otherwise
mouse mode. `/dev/uinput` is `chmod 777`'d by pc2drc's stage-4.

### 3.2 Typing on an X11 VNC desktop

Run the keyboard **on the Kali `:0` display**, not on the pad side; XTEST
injection into the same X server means x11vnc sees ordinary local input:

| Tool | X11 | Mechanism | Fit at 848x480 |
|---|---|---|---|
| matchbox-keyboard | yes | libfakekey/XTEST | tiny, XML layouts, `-xid` embed options |
| onboard | yes (Wayland experimental) | libxtst/XTEST | biggest keys, dockable; heavy (GTK3) |
| florence | yes | XTEST | scalable, ageing |
| wvkbd / squeekboard | **no** | Wayland IM protocols | not usable on X11 |

### 3.3 VNC / encoder numbers

x11vnc ([man page](https://manpages.debian.org/bookworm/x11vnc/x11vnc.1.en.html)):
`-scale 848x480` once; **`-nonc`** (the libvncclient here does not cooperate with
`-ncache`); **keep XDAMAGE** (don't pass `-noxdamage` — it helps a mostly-idle
desktop); `-defer 5 -wait 5` for latency (defaults 20/20); `-threads`; `-nopw`
only silences a warning. Xvnc alternative: `-FrameRate 30 -CompareFB 2`.

pc2drc's own pipeline was `tigervncserver :1 -FrameRate 59.94 -depth 24
-geometry 640x480` then force the size with `xtigervncviewer :1
-DesktopSize=854x480` — a hack because Xvnc does not resize itself.

libdrc's encoder ([h264-encoder.cpp](https://bitbucket.org/memahaxx/libdrc/src/9e8de8d0b5554e0596ab6cd172dfe3ca8a5d52db/src/h264-encoder.cpp)):
preset **slow** + zerolatency, CQP **32** fixed, `b_drh_mode=1` (one NAL per 6 MB
rows = 5 chunks/frame), intra-refresh on (`keyint_min=10, keyint_max=30`), 59.94
Hz timer, 1400 B payload cap against the ~1800 MTU. Per §2.3 the preset should
become **medium** — that is the freeze fix.

No published measured bitrate/latency exists; 8 Mbps ≈ 17 kB/frame at 59.94 fps
is an estimate, not a measurement.

VNC is tolerable but costs a double encode (RFB → ARGB → BGRA → x264). A
~200-line direct `XShmGetImage` → `PushVidFrame(..., kBGRA)` grabber removes it —
which is essentially what Barista does.

---

## Part 4 — the non-radio routes

1. **Moonlight Wii U on an Aroma-hacked console — works today.** Verified at
   source level: `src/wiiu/wiiu.c` creates `WHBGfxGetDRCColourBuffer()` and draws
   the decoded video into the **DRC (GamePad) colour buffer** every frame; v1.3
   added `MOUSE_MODE_TOUCHSCREEN` so the GamePad touchscreen is an absolute mouse
   ([releases](https://github.com/GaryOderNichts/moonlight-wiiu/releases),
   [README](https://github.com/GaryOderNichts/moonlight-wiiu)). Sunshine is the
   documented host, so a Linux desktop qualifies. Suggested config:
   `width=854 height=480 fps=30 bitrate=1500`, then raise. Gap: no on-screen
   keyboard for typing.
2. **Linux on the console cannot drive its own GamePad** — `hid-wiiu-drc.c` is
   input-only (503 lines, no video/DSI/stream code); GamePad framebuffer work was
   abandoned (linux-wiiu #9, #23).
3. **LCD hardware mod** — panel is LVDS (JDI R69208 / Panasonic MN838985); a
   BitBuilt user built an RTD2660 board but never released firmware or PCB.
4. **UART (115200 8N1, 4-pad header)** supports UART boot of custom ARM code, but
   nobody has driven the panel over it, and ~11.5 kB/s vs 1.23 MB/frame is
   arithmetically hopeless for video.
5. **Project Vanilla** (2.4k★) does the opposite direction (PC as GamePad);
   **melonpad** has LCD/framebuffer/input working but no Wi-Fi; **Project
   Chocolate** ($59 GamePad→PC dongle) cancelled shipping with no source.

---

## Part 5 — recommendation, ranked

**1. Run Barista on the Kali host with a supported 5 GHz adapter.** It is the
only actively developed project that does "Linux desktop on the GamePad with
GamePad input", it pairs without a console, needs **no kernel patch**, needs no
VNC, and ships the GamePad touch keyboard that every other route lacks. Start
with the adapter Barista's own docs tested — **TP-Link Nano AC600
(`rtw_8821au`)** or an **RTL8852BE** card; an MT7921AU is a reasonable second
choice given AP-on-USB since 5.19. Expect artifacts and audio stutter at v0.1.
Blockers to clear first: Kali is not a packaged target (source build needs Qt6 +
PipeWire + libnl + libssl dev packages = root), and the radio must be dedicated
(use Ethernet).

**2. Zero-cost experiment before buying anything.** Put an Ethernet cable in,
free `wlan0` (AX210), and try our *existing* patched-hostapd stack against it
with `DRC_SYNTHETIC_TSF=1`. It answers the only open question that costs money —
does a modern firmware accept `a4:c0:e1` in a beacon — for the price of a cable.
`run/03-ap.sh` + `run/05-diagnose.sh` are already the right tools.

**3. Fall back to our own stack if Barista will not run here.** Everything is
built: patched mac80211 TSF module, hostap 2.12 (native, §0.4), drc-x264, libdrc,
drcvncclient, x11vnc display half proven. Buy an **MT7921AU** (softmac + in-tree
`.get_tsf` + AP-on-USB) or an RT5572. Then import two fixes from `wozt/libdrc`
before judging quality: x264 preset **medium**, rate-limited keyframes with real
IDR and paced transmission — without those the pad requests 60 keyframes/second
and the picture freezes within seconds. Add an XTEST on-screen keyboard on `:0`
for typing.

**4. If the goal is "a Linux desktop on the pad today" and hardware shopping is
unwelcome:** use the Wii U console already owned, with **Moonlight Wii U +
Sunshine** on Kali. Verified GamePad-screen rendering and touch-as-mouse; costs
nothing; accept no keyboard.

**Do not**: patch mac80211 for Nintendo cipher OUIs (unnecessary), chase
brcmfmac/CYW43455 (double-dead at the firmware boundary), or wait for Project
Chocolate.
