# Wii U GamePad — how the link actually works (verified from source/docs)

Companion documents: `BOOT-AND-MODES.md` (boot chain, firmware states, which mode we
stream into, and the console on/off decision), `GROUND-TRUTH-SESSION.md` (a real
console↔pad session, decrypted), `STREAMING-TO-PAD.md` (prior art), `CODEC-SPEC.md`.

Sources read directly (not inferred):
- `libdrc` README + `web/docs/network.rst` + `web/docs/installation.rst` (git clone, read locally)
- `drc-hostap` `README.DRC` + `conf/wiiu_ap_normal.conf` / `wiiu_ap_pairing.conf` / `drc_pair.conf`
- https://libdrc.org/docs/re/ — `wifi.html` (pairing + cipher spec)
- https://wiiubrew.org/wiki/GamePad + `/wiki/GamePad/LVC` (hardware + firmware services)
- `thefloppydriver/pc2drc` — `kernel-patch-files/patches/*.patch`, stage scripts, `generated_ap_normal.conf`

## 1. There is no cable path

The GamePad's only physical connectors:

| Connector | Reality |
|---|---|
| Proprietary charge jack | Power in only. No data. |
| 3.5 mm jack | Analog audio out. |
| IrDA window + IR LED | TV-remote blaster / toy IR. No video. |
| 4-pad UART header (inside, near battery) | **The only data port.** 115200 8N1, pads: RXD / UART-boot / TXD / Vcc 2.8 V. Runs the LVC firmware serial console. |

There is no USB port and no video input on the GamePad. The front-panel USB ports belong
to the *console* and are host-only. So "stream to the GamePad by cable" would mean
disassembly + driving the panel/LVC firmware over UART, or gutting it for an
HDMI→RGB888 board. Both are destructive and were declined in favour of wireless.

The LCD is RGB888 854x480 with a resistive touchscreen.

## 2. The wireless link (the only real interface)

The GamePad ("DRC" = Display Remote Controller) talks to the console ("DRH") over a
**slightly obfuscated 802.11n 5 GHz + WPA2-CCMP** link. Crucially, from libdrc's docs:

> the required modifications for support of this obfuscated Wi-Fi protocol can be
> applied **in userland without any kernel modification**.

So the radio obfuscation lives in patched hostapd/wpa_supplicant, not the kernel.

### Pairing
In pairing mode (SYNC pressed twice) the console raises an **open** AP named
`WiiU<mac2><mac>_STA1` and runs a modified WPS handshake:

- Nintendo's AuthKey = `KDF(KDK_ROT)` where **KDK_ROT = KDK rotated 3 bytes left**.
  Stock WPS computes `KDF(KDK)` and fails at message M2.
- PIN = 8 digits: first 4 shown on the TV as symbols (♠=0 ♥=1 ♦=2 ♣=3),
  **second 4 hardcoded `5678`**. e.g. ♠♠♦♣ → `0023 5678`.
- Because *we* can act as the registrar: "If you are trying to associate a gamepad to
  your computer (and not your computer to a Wii U), **you get to choose the code**, as
  long as you enter the same on the GamePad it should work."
  → a Wii U console is **not strictly required**; it is only the easy, documented path.

After WPS: SSID + BSSID (AP MAC) + **PSK** are known.

### Normal operation
The AP beacons an **empty SSID** WPA2-PSK AP with Nintendo-OUI selectors:

| Selector | Value |
|---|---|
| Pairwise cipher | `a4:c0:e1` (Nintendo OUI) AES-CCM |
| Group cipher | `a4:c0:e1` AES-CCM |
| Auth key mgmt | `a4:c0:e1` PSK |

The only real difference from standard CCMP: **PTK is rotated 3 bytes left after
computation**. If the supplicant does not advertise these selectors the GamePad
refuses with error `0x000c`.

Network layout: console/PC = `192.168.1.10`, GamePad = `192.168.1.11` via DHCP,
interface MTU **1800**.

### Radio parameters actually used by working configs
```
hw_mode=a          channel=36 (upstream sample) / 165 (pc2drc working config)
beacon_int=100     dtim_period=3      ieee80211n=1
wpa=2  wpa_key_mgmt=WPA-PSK  wpa_pairwise=CCMP
ignore_broadcast_ssid=2        # normal mode: empty SSID
interface=WiiUAP               # pc2drc uses a *virtual* iface on top of wlanX
```

### Payload
- Video: **H.264** console→GamePad (854x480), and GamePad→console (camera).
- Audio: **16-bit PCM** both directions.
- Input: `sc_hiddat` / `mc_gamectrl` HID-style packets GamePad→console
  (buttons, sticks, touch, gyro/accel).
- GamePad-side firmware services: `sc_vstrm` (video stream), `sc_astrm` (audio),
  `sc_hiddat` (input), `mc_video` (decode/playback), `drvldc` (LCD), `drvwifi`.

## 3. The one kernel requirement: TSF

`libdrc/src/tsf-linux.cpp` does a binary `pread()` of 8 bytes from
`/sys/class/net/<iface>/device/tsf`, falling back to `/sys/class/net/<iface>/tsf`.
That 64-bit **TSF** is the AP's hardware clock, used to timestamp video frames for
playback scheduling (`uvcuac-synchronizer`). Without it the stream desyncs.

Stock Linux does not export TSF to userland. The patch (`pc2drc`,
`kernel-patch-files/patches/`, ~3 KB total) is:

1. `kernel_above_5_11_mac80211.patch` / `kernel_below_5_12_mac80211.patch`
   — add to `net/mac80211/iface.c`:
   ```c
   static ssize_t ieee80211_tsf_show(struct device *dev, struct device_attribute *attr, char *buf)
   {
       ... sdata = IEEE80211_DEV_TO_SUB_IF(ndev); ...
       output = drv_get_tsf(sdata->local, sdata);
       memcpy(buf, &output, sizeof(u64));
       return sizeof(u64);
   }
   DEVICE_ATTR(tsf, S_IRUGO, ieee80211_tsf_show, NULL);
   ```
   plus `device_create_file(&ndev->dev, &dev_attr_tsf)` in `ieee80211_if_add()` and
   matching `device_remove_file()` calls. (Original: delroth, 2013.)
2. `mac80211_rx.patch` — 1 line: `ieee80211_data_to_8023_exthdr(..., data_offset, true)`.

**This means the driver must implement `drv_get_tsf`.** That is the real hardware
gate, not the kernel version:

| Driver | `.get_tsf` | Notes |
|---|---|---|
| `rt2800usb` (RT5572) | yes | **documented working**, libdrc's primary target |
| `ath9k` / `carl9170` | yes | works, TSF drift ⇒ more desync |
| `iwlwifi` (AX210 in this laptop) | **no** | unusable; also this is our internet uplink |
| `rtw88` | no in mainline | `wozt/rtw88_TSF` (2026-09) patches it for libdrc |

Verification one-liner: `test -f /sys/class/net/$IFACE/tsf && echo ok`

## 4. Software stack (all Linux, all userland above the TSF patch)

```
drc-x264        patched x264 — GamePad H.264 is non-standard   (bitbucket memahaxx, ALIVE)
  └─ libdrc     video/audio stream encode→GamePad, input←GamePad
       └─ libdrc-vnc / drcvncclient   VNC client that renders a VNC desktop to the GamePad
drc-hostap      hostapd + wpa_supplicant with CONFIG_TENDONIN (PTK rot3, WPS KDK rot3,
                Nintendo OUI, Wii U pairing-AP detection)      (bitbucket memahaxx, ALIVE)
netboot         tiny DHCP server → hands the GamePad 192.168.1.11
```

Why this maps cleanly onto the goal: `drcvncclient` speaks **VNC**, so
GamePad → VNC input events → the VNC *server's* machine. Point it at a VNC server on
the Kali desktop and the GamePad becomes a real touch/mouse/keyboard for Kali, with
Kali's framebuffer rendered on the GamePad. No `/dev/uinput` plumbing needed — VNC
carries both directions.

## 5. Prior art / inventory

| Project | What it is | State |
|---|---|---|
| `thefloppydriver/pc2drc` | End-to-end PC→GamePad streaming, vendored full stack + kernel patches | archived 2026-04, still the best blueprint |
| `opencma/libdrc`, `GaryOderNichts/libdrc` | The library | alive |
| `duanemach/drcvncclient` | VNC→GamePad client | 2015, works |
| `opencma/drc-sim` | Reverse: PC *as* a GamePad (wrong direction) | not needed |
| `cinm-25h2/wiiu-gamepad-pc-control` | Ubuntu 24.04 wrapper/GUI, notes Intel Wi-Fi trouble | **ChatGPT-generated**, treat as notes only |
| `wozt/rtw88_TSF` | rtw88 + TSF for modern kernels | 2026-09, useful if dongle is Realtek |
| `WiFiZero/drc-mac80211` | 4.0.8 kernel tree with the patch | mirror fallback |

## 6. DRC network services (from libdrc.org/docs/re/services.html, cross-checked
against `include/drc/streamer.h`)

Console (us) = `192.168.1.10`, GamePad = `192.168.1.11`.

| Flow | Console side | Pad side | Direction |
|---|---|---|---|
| video | (ephemeral, doc says 50020) | **50120** | us → pad |
| audio | 50021 | **50121** | us → pad |
| input | **50022** (bind) | 50122 | pad → us |
| command | **50023** (bind) | 50123 | both |
| message | **50010** (bind) | — | — |

libdrc's actual bind/dest constants: `kDefaultMsgBind=192.168.1.10:50010`,
`kDefaultInputBind=...:50022`, `kDefaultCmdBind=...:50023`,
`kDefaultVideoDest=192.168.1.11:50120`, `kDefaultAudioDest=...:50121`,
`kDefaultCmdDest=...:50123`.

This gives a real "is it working?" test: ping proves nothing, but traffic on
`50122 -> 50022` proves the GamePad's DRC stack is live and talking to us
(`run/05-diagnose.sh`).

## 7. Wire field widths (found by round-trip testing)

`VstrmPacket::SetSeqId()` stores only **10 bits** (2 bits in `pkt_[0]` + `pkt_[1]`);
the payload-length field in `pkt_[2..3]` is **11 bits** (max 2047, and
`kMaxVstrmPayloadSize = 1694` fits). A 16-bit sequence counter is therefore
truncated by design - that is correct behaviour, not a bug, but it is worth knowing
before "fixing" it. The command header is a flat 8-byte header + payload.
