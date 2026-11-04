# Running the DRC stack — the tools that actually work

Everything here is measured behaviour on the operator's GamePad, not intent. The
long-form story is `research/DISPLAY-WORKS.md`; this file is the operator's
runbook.

## The one command that matters

```bash
sudo ./run/uvc-live.sh        # stream the Kali desktop until stopped
sudo ./run/uvc-stop.sh        # stop it (pad returns to its own menu)
```

`uvc-live.sh` does, in order: take the hardware lock → free the console ports →
wait for the pad → ensure x11vnc → **seed the media clock from the AP's real TSF**
→ start `drcvncclient` in mouse mode → run the light clock guard → report status
every 10 s.

Detached variants, for when the session must outlive your shell:

```bash
sudo ./run/uvc-start.sh                 # supervisor in the background, returns immediately
sudo ./run/uvc-kill-live.sh             # stop everything (safe; see the warning below)
journal=$(ls -t out/logs/live-supervisor-*.log | head -1); tail -f "$journal"
```

**Never `pkill -f run/uvc-live.sh` from an interactive shell.** The pattern
matches the command line of the shell you typed it in and kills your own
session. `run/uvc-kill-live.sh` exists because of exactly that, several times.

## The media clock is the whole trick

The pad schedules playback against the AP's TSF, so the timestamp on every video
datagram must be in that domain. iwlwifi has no TSF node, so libdrc runs on
`monotonic + /var/run/drc/tsf-offset-us`, and that offset must be **the AP's TSF
at streamer start**. Get it wrong and the pad shows nothing while the wire looks
perfect.

| symptom | meaning |
|---|---|
| video on the wire at ~57 fps, pad shows its menu | clock epoch wrong — reseed |
| `tsf_offset` negative or far from the live TSF | the phy reset; restart the session |
| `ap-health.sh` says not transmitting | firmware crash; `ap-recover.sh` |

```bash
sudo ./run/uvc-live.sh                   # reseeds automatically
sudo ./run/tsf-keeper.py --once          # one TSF sample, for manual checks
```

## Why a static desktop used to send nothing

`drcvncclient` only pushed a frame when VNC reported a *change*, so a static
desktop produced **no stream at all** (measured 1 packet/s) while the process
looked healthy. The client now re-pushes the last frame every 16.7 ms from its own
thread — a static desktop streams at ~520 pkt/s. `DRC_NO_REPUSH=1` turns that off
if you need the old behaviour for a comparison.

If video is missing, check `tx_packets` growth on `WiiUAP` first: if it is flat,
nothing is being transmitted and no amount of clock or pad debugging will help.

## Radio health (the AX210 crashes)

`iwlwifi: Device error - SW reset` leaves the AP alive but silent: hostapd runs,
no beacons go out, `tx_packets` stops growing, the pad cannot associate. Every
pid check passes. Detect and repair:

```bash
sudo ./run/ap-health.sh        # exit 0 = actually transmitting
sudo ./run/ap-recover.sh       # driver reload + 5 GHz unlock + drc-up + streamer
sudo ./run/drc-watchdog.sh &   # do the above automatically (polls every 30 s)
```

`ap-recover.sh` handles the part that always bites: after a reload iwlwifi's LAR
marks every 5 GHz channel `no IR` until an idle `wpa_supplicant` (country=CA)
exists **and** a scan runs. Without both, hostapd dies with `Could not select
hw_mode and channel (-3)`.

## Input

`drcvncclient` runs in **mouse mode** (no `-joystick`). In joystick mode every
button goes to a uinput feeder that nothing on the desktop reads, which is why
the buttons looked dead for so long.

| control | action |
|---|---|
| touchscreen | move pointer, tap = left click (press/release) |
| left stick | relative pointer motion (`DRC_STICK_SPEED`, default 240 px/s) |
| right stick | wheel up/down |
| A / B / X / Y | Enter / Backspace / Space / Tab |
| d-pad | arrow keys |
| ZL / ZR | left / right mouse button |
| Plus / Minus | Copy / Paste |
| Home | Escape |
| TV | toggle mouse ↔ joystick mode |

Debug what the pad actually sends:

```bash
sudo DRC_INPUT_LOG=1 ./run/uvc-live.sh
grep '\[input\]' out/logs/live-*.log | tail -20
```

Each line prints the raw bitmask and the buttons that are down
(A `0x8000`, B `0x4000`, X `0x2000`, Y `0x1000`, Up `0x0200`, L `0x20`, R `0x10`,
ZL `0x80`, ZR `0x40`, Plus `0x08`, Minus `0x04`).

## Measuring a run

```bash
sudo ./tests/uvc-exchange.py capture/foo.pcap        # UVC exchange + resync + input trend
sudo ./tests/score-live-session.py capture/foo.pcap  # media parity vs the console
sudo ./tests/stability-watch.py --minutes 8          # sample every 30 s, flags stalls
```

**Do not score anything by resync rate.** The pad emits 20–60 resync/s *while
displaying video correctly*. Use `score-live-session.py` for media parity and
your eyes for the display.

## Environment knobs that matter

| variable | effect |
|---|---|
| `DRC_SYNTHETIC_TSF=1` | use the synthetic clock + offset file (set by the runner) |
| `DRC_SESSION_PUSH_ON_START=1` | replay the console's 782-datagram state push immediately |
| `DRC_INPUT_LOG=1` | log raw button bitmasks |
| `DRC_STICK_SPEED`, `DRC_STICK_INVERT_Y` | stick tuning |
| `DRC_QUIET_CMDS=1`, `DRC_SEND_UVCUAC=0`, `DRC_SEND_TIME=0` | bisect the command plane |
| `DRC_NO_REPUSH=1` | stop the independent frame pusher (old VNC-change-driven behaviour) |
| `DRC_NO_TOUCH_CLICK=1` | restore move-only touch handling |
| `DRC_NO_CLOCK_REINIT=1` | ignore the `tsf-reset` marker (no re-arm/re-init) |
| `JOYSTICK=1` | start in joystick (uinput) mode instead of mouse mode |
| `DRC_UVC_EXACT=1` | send the console's byte-exact UVC payload instead of libdrc's zeros |
| `DRC_FORMAT_LEAD_US` | shift the per-frame format message lead |

## Things that will waste your afternoon

1. **One hardware owner.** `run/uvc-live.sh` takes
   `flock /var/run/drc/hw.lock`; two streamers silently deauthenticate the pad
   under each other because `SO_REUSEADDR` hides the second binder.
2. **`udp.length` includes the 8-byte UDP header.** A 1056-byte datagram is a
   1048-byte payload — which is exactly what the console sends.
3. **The pad replies to console port 50023** whatever port your query came from;
   libdrc sends from an ephemeral port and listens on 50023.
4. **The pad only establishes a DRC session at its own boot/connect.** If the
   stack was down when it booted, it sits on "could not connect" with input still
   working. Power-cycle the pad after a repair.
5. **The pad sleeps after ~30–90 s untouched.** Touch it; the stream resumes.
