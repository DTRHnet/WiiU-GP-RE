# Plan — Kali desktop on the Wii U GamePad, with GamePad controls

Goal: Kali Linux host's screen visible on the Wii U GamePad screen, and the GamePad
(d-pad, sticks, buttons, touchscreen) driving the Kali host.

Decision already taken with the user: **wireless only**, GamePad stays intact.

## Architecture

Single machine (Kali) if the dongle supports `get_tsf`; otherwise the identical stack
runs on the spare box and bridges to Kali over VNC.

```
  Wii U GamePad                     Kali host
  ┌────────────┐  5 GHz 802.11n   ┌──────────────────────────────────────┐
  │ H.264 dec  │◄──── video ──────│ libdrc  (drc-x264 encoder)           │
  │ PCM dec    │◄──── audio ──────│   ▲                                  │
  │ touch/btn  │───── input ─────►│   │ framebuffer + input events       │
  │ LCD 854x480│  (VNC protocol)  │ drcvncclient                         │
  └────────────┘                  │   │  TCP 5900                        │
        ▲                         │ x11vnc → Kali :0 (real desktop)      │
        │ proprietary WPA2-CCMP   │                                      │
        │ (PTK rot3, Nintendo OUI)│ drc-hostap AP on WiiUAP @ ch36       │
        └─────────────────────────│   + netboot DHCP → 192.168.1.11      │
            192.168.1.11         │ wlan1 = DRC radio (dedicated)        │
                                 │ wlan0 = AX210, unchanged uplink      │
                                 └──────────────────────────────────────┘
```

Because `drcvncclient` speaks VNC, the GamePad's touch and buttons arrive at the VNC
*server* as native pointer/keyboard events. That is what makes "GamePad controls Kali"
fall out for free, and it also means the same bridge works whether the DRC radio lives
on Kali or on a second box.

## Hardware

| Item | Role | Status |
|---|---|---|
| Wii U GamePad | the display+input | have |
| Wii U console | convenient pairing path only (optional) | have |
| 5 GHz USB dongle with `.get_tsf` — **RT5572 / rt2800usb** preferred | the DRC radio | have one, chipset TBC |
| AX210 (built-in) | left alone as internet uplink | have |

If the existing dongle is not rt2800usb/ath9k/carl9170, buy an RT5572 (~$15-25) — it is
the one combination libdrc documents as tested, and it is the lowest-risk spend in the
whole project.

## Phases and gates

### Phase 1 — identify the radio (no root)
`lsusb` + `iw dev` + driver bind. Decide: `rt2800usb` (easy) vs Realtek (needs
`wozt/rtw88_TSF`) vs unusable.
**Gate:** a driver that implements `.get_tsf` and can do 5 GHz AP mode.

### Phase 2 — TSF export (root, kernel rebuild)
Port the ~45-line `net/mac80211/iface.c` block + the 1-line `rx.c` change from
`pc2drc/kernel-patch-files/patches/` to Kali's 7.1.5 kernel, rebuild `mac80211`,
reload, then bring the interface up.
**Gate:** `test -f /sys/class/net/$IFACE/tsf && echo ok`, and the value *advances*
(`od -An -tu8 /sys/class/net/$IFACE/tsf` twice).
Fallback if 7.1.5 porting fights back: build kernel 5.11.22 from the pc2drc script on
the spare box/VM and bridge over VNC.

### Phase 3 — build the userland radio (root-free build)
`drc-hostap`: `cp conf/hostapd.config hostapd/.config && make` — needs
`CONFIG_WPS=y` and `CONFIG_TENDONIN=y` (PTK rot3, WPS KDK rot3, Nintendo OUI
`a4:c0:e1`, Wii U pairing-AP detection). Build both hostapd and wpa_supplicant.
**Gate:** binaries build and `hostapd -v` shows the DRC options.

### Phase 4 — pairing, get the PSK
Two routes:
- **A (console, documented):** run patched `wpa_supplicant -Dnl80211 -i wlan1 -c get_psk.conf`,
  press SYNC twice on the console, `scan`, find `WiiU<mac>_STA1`, note BSSID,
  `wps_pin <BSSID> <PIN>`, expect `WPS-SUCCESS`, then read the PSK out of `get_psk.conf`.
  PIN half is the symbols on the TV (♠0 ♥1 ♦2 ♣3) + hardcoded `5678`.
- **B (no console):** host `wiiu_ap_pairing.conf` ourselves (we choose the PIN) and
  enter the matching 4 symbols on the GamePad. Documented as possible; less proven.
**Gate:** PSK + SSID + BSSID in hand.

### Phase 5 — raise the DRC AP
Generate `wiiu_ap_normal.conf` with the real SSID/PSK, `channel=36` (fall back to the
channel the console actually used, e.g. 165, if the GamePad won't join), virtual iface
`WiiUAP`, MTU 1800, host `192.168.1.10`, and run `netboot` to lease `192.168.1.11`.
**Gate:** GamePad associates (hostapd logs the station), gets `192.168.1.11`,
`ping` succeeds, and it keeps streaming packets.

### Phase 6 — video path
Build `drc-x264` (patched — GamePad H.264 is non-standard), then `libdrc-vnc`
(`libdrc-thefloppydriver` + `drcvncclient`), run `x11vnc` on Kali's `:0`, point
`drcvncclient` at it, size it 854x480.
**Gate:** Kali desktop visible on the GamePad LCD.

### Phase 7 — input path
Touch → pointer, sticks/buttons → keys/mouse, verify realistically (move a window,
type in a terminal, open a browser).
**Gate:** the GamePad genuinely drives Kali.

## Known risks

- **Kernel port.** The patch is small but Kali 7.1.5 is a 2026 kernel; `ieee80211_if_add`
  / `_if_remove` / `_remove_interfaces` context and the `rx.c` signature may have moved.
  Mitigation: patch is ~3 KB, and the 5.11.22 fallback is pre-built for us.
- **Channel legality.** `channel=165` (pc2drc) is UNII-3 and not permitted everywhere;
  `channel=36` (upstream sample) is the safer default. DFS channels are out.
- **`x264` artifacts + random disconnects** are known-open bugs in pc2drc.
- **Uplink coexistence.** The DRC radio must be a *separate* card from the internet
  uplink; sharing one card breaks both.
- **Disable NetworkManager on the DRC interface** or hostapd will lose it.

## Locally staged sources

- `pc2drc/` — complete vendored bundle: `drc-hostap`, `drc-x264` (has `README.DRC`),
  `libdrc-vnc/{libdrc-thefloppydriver,drcvncclient,vncconfig-files}`,
  `kernel-patch-files/patches/`, and the stage scripts.
- `research/libdrc/`, `research/drc-hostap/` — clean upstream clones for diffing.
- `RESEARCH.md` — the protocol facts with citations.

---

## Status after round 1 of autonomous work (2026-11-03)

Verified done: TSF mac80211 patch ported to Kali 7.1.5 and **built as a loadable
module** (vermagic matches, `dev_attr_tsf`/`tsf_show` present); full userland stack
built (hostapd/wpa_supplicant/wpa_cli with CONFIG_TENDONIN, netboot, drc-x264,
libdrc, drcvncclient) and all binaries execute on Kali; display half proven by
capturing the real `:0` desktop over RFB at 848x480.

Design changes forced by reality:
- Build moved into a `drcbuild:20.04` container image. Kali's gcc 16 cannot compile
  2013-era hostapd, and 2016 hostapd cannot use OpenSSL 1.1+ opaque structs, so the
  image bakes in gcc 9 + OpenSSL 1.0.1u (pc2drc's own recipe).
- `libdrc.so` linked libraries *before* objects; under `--as-needed` it silently
  dropped libswscale/libx264. Fixed the rule so it carries real `DT_NEEDED` entries,
  and switched x264 to a shared build (a static non-PIC archive cannot be linked into
  a shared object).
- `drcvncclient` de-hardcoded from 854x480 to the server's actual size.

Still blocked on: the 5 GHz dongle (absent from `lsusb`) and root (sudo wants a
password; approval prompts are disabled in this session).

### Round 2

Video path proven without hardware: 5 DRH row-chunks per frame, and a GamePad-format
stream that decodes (854x480 High profile, zero ffmpeg errors, luma within 1.03 of the
source at CQP 32). Added `DRC_SYNTHETIC_TSF=1` to `GetTsf` so the stack can run on a
radio with no `get_tsf()` - which means the built-in iwlwifi AX210 becomes usable, and
the USB dongle stops being a hard requirement (synthetic-epoch playback scheduling is
the open question). Suite: `tests/run-tests.sh`, 5/5 pass, no root, no GamePad.

### Round 3 status (2026-11-04, see SETUP.md round 11 for detail)

**GamePad → Kali input is PROVEN on hardware**: the pad associates to our AP,
the 4-way handshake completes, it DHCPs `192.168.1.11`, and touching the pad
moves the Kali cursor. The pad also emits its per-frame messages to `50010`
where it used to be silent.

**Video still not displayed** (pad stays on "could not connect"; no media return
traffic to `50020`/`50021`). Five console-parity defects were found and fixed to
get this far: vstrm ext-option order, a firewalled `udp/50121` (audio + the
per-frame video-format/timing message), the format-message body, the 59.94 fps
cadence, and the media source ports plus UVC/UAC little-endian fields.

Remaining unknown is inside the console's own session-start or DRH payload: the
next experiment is to capture a real console↔pad session from before
association, decrypt it with the known PSK, and diff it against ours. That needs
the console/pad in normal mode and one manual monitor setup.
