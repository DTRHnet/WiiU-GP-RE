# LVC firmware architecture — the page that explains 9004

Source (fetched 2026-11-04): <https://wiiubrew.org/wiki/GamePad/LVC>
Companion reading: <https://kuribo64.net/wup/doku.php?id=start> (hardware wiki;
`lcd_controller`, `h264_codec`, `uic`, `uic_eeprom_structure`, `general_registers`,
`memory_map`, `flash_layout`, `wifi`). See `WIKI-CMD-AND-CLOCK-FINDINGS.md` for the
protocol/hardware digest and `research/wozt-libdrc/web/docs/re/sc-cmd.rst` for the
service/method map.

## Why this matters

Our pad answers some commands with **err 0** (state, backlight, firmware version)
and refuses the session-level ones with **err 9004**. That is not an authorisation
model — it is the firmware's **manager** structure. Each manager is a separate
module that has to be running before its methods work, and the video path is a
manager of its own.

## LVC = the firmware on the DRC-WUP (the GamePad's own SoC)

Runs eForce uC3 / μITRON4.0. `APLMAIN` is the task that brings up drivers,
services and managers.

### Drivers

| driver | role |
|---|---|
| `drvaamp` | audio amplifier |
| `drvacapt` | audio capture |
| `drvaout` | audio output |
| `drvblit` | screen surface blit |
| `drvcmos` | video camera |
| `drvdma` | DMA |
| `drvevt` | events and callbacks |
| `drvfifo` | |
| `drvflash` | SPI flash |
| `drvgpio` | GPIO |
| `drvi2c` | I²C |
| `drvir` | infrared |
| **`drvldc`** | **LCD** |
| `drvmem` | memory allocation/stats |
| `drvspi` | SPI |
| `drvstc` | System Time Clock (named only in the factory app) |
| **`drvuic`** | **communication with the UIC** |
| `drvvcapt` | video capture |
| **`drvvout`** | **video output** |
| `drvwifi` | Wi-Fi |

### Services

`sc_astrm` (audio streaming), **`sc_cmd`** (command protocol), `sc_hiddat` (input),
`sc_msg`, **`sc_vstrm`** (video streaming protocol), `sc_wii`.

### Managers — the gate

| manager | role |
|---|---|
| **`mc_cmd`** | handles commands from `sc_cmd` |
| `mc_con` | low-level networking |
| `mc_devif` | |
| `mc_draw` | screen drawing routines |
| `mc_gamectrl` | |
| `mc_ictag` | NFC |
| `mc_ir` | infrared |
| `mc_msg` | |
| `mc_nvram` | flash and firmware management |
| `mc_nwk` | networking |
| `mc_resource` | flash resource loading |
| `mc_sound` | |
| **`mc_state`** | **GamePad state management** |
| `mc_sync` | |
| `mc_time` | |
| `mc_userif` | input parsing for on-pad applications |
| **`mc_video`** | **video stream decoding and playback** |

### Memory map (MMU, no translation)

| start | end | size | use |
|---|---|---|---|
| `0x00000000` | `0x00157FFF` | 0x158000 | cached memory |
| `0x00158000` | `0x003F7FFF` | 0x2A0000 | uncached memory |
| `0x003F8000` | `0x003FFFFF` | 0x8000 | MMU translation table |
| `0xE0000000` | `0xFFFFFFFF` | 0x20000000 | MMIO |

## What this explains about our measurements

- `svc 4/0x05` (UIC state, via `drvuic`/`mc_state`) → **err 0**, returns state 0.
- `svc 5/0x14` (backlight) and `svc 0/0x00` (firmware versions) → **err 0**.
- `svc 0/0x11` state push, `svc 0/0x12` terminator → **err 9004** = `mc_cmd` refuses:
  the manager that method belongs to is not up.
- The pad shows its own menu (drawn by `mc_draw`/`mc_userif`) while emitting
  **~54 resync/s**, because `sc_vstrm` is receiving our datagrams but **`mc_video`
  (decoding and playback) was never started**. Resync rate therefore measures "video
  arriving with no decoder running", not picture quality — consistent with every
  measurement that made resync rate a misleading metric.
- Nothing in the video *media* plane can start `mc_video`; it is started by the
  pad's own state/session machinery (`mc_state`, `mc_sync`, `mc_con`) driven by the
  console's command traffic.

## Consequence for the next attempt

1. The arming step must start **`mc_video`**, and our constructed arm burst does not
   (`svc 5/0x02` with 102 zeros → no reply; zero-length → err 5). Both were tried.
2. The faithful test is to replay **the console's own command stream** — the exact
   datagrams, in the recorded order and cadence — rather than reconstructing them:
   `07-protocol/command-plane.py --mode console` (or `--mode arm` for the 4-command
   burst alone). It already logs the arming oracle `svc 5/0x15` on change.
3. Go/no-go is objective: `svc 5/0x15` returning **0** (armed) instead of 9004.
   Only then is a display test meaningful.

## Also worth knowing from the same sources

- The UIC EEPROM (`0x1000..0x17FF`) stores Wi-Fi SSID/auth/PSK, the **WoWL key**,
  and per-block **CRC16**-checked calibration (touchscreen, accelerometer, gyro,
  volume, **LCD brightness levels**) — e.g. CRC16 over `0x1101..0x116A` at `0x116B`.
  Any command that writes such a block with a bad CRC should be refused, which is a
  plausible explanation for `svc 5/0x02` returning err 5 when handed 102 zero bytes
  (`sc-cmd.rst` describes it as `u16, u16, {u8,u8,u8}[32], u16` = 102 bytes).
- `sc-cmd.rst` documents `svc 5/0x08` payload `00` as "disables video" (sent when the
  Home menu turns the display off) and `svc 5/0x0a` payload `00` as "disables sound";
  `svc 4/0x01` payloads: 0 = reboot to normal, 2 = reboot to firmware-update mode,
  4 or 6 = shut down; `svc 5/0x19`/`0x1a` set/get LCD parameters over I²C.
- The hardware wiki says the LCD controller register `0xF0009480` bit2 is
  "Enable video feed (camera/H264)" and that stock 854x480 modes leave it **off** —
  i.e. the pad's display swap is a firmware action (`drvldc`/`drvvout`) taken when
  `mc_video` is running.
