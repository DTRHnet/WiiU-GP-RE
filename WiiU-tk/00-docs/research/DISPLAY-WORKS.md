# IT WORKS: Kali desktop on the GamePad, driven by the GamePad (2026-11-04)

## Outcome

The PLAN.md goal is met on real hardware:

- **The Kali host's live desktop is displayed on the GamePad screen** at ~57 fps.
- **The GamePad drives the Kali host**: left stick moves the cursor, touchscreen
  taps/clicks land on the desktop. Confirmed by the operator, three separate
  runs, plus a large fullscreen video (`~/Videos/aext.mp4`) played on the Kali
  screen and watched on the pad.
- The console stays stock; the pad is untouched (no hardware mod, no homebrew).

Run it:

    sudo ./run/uvc-live.sh      # streams until stopped
    sudo ./run/uvc-stop.sh      # done

## The bug that cost this project its whole search

**The VSTRM frame timestamp must be in the AP's real TSF domain.**

The pad schedules video playback against the TSF it syncs from *our* beacons.
`GetTsf()` has no `/sys/class/net/<if>/tsf` on iwlwifi, so libdrc falls back to
the monotonic clock plus an offset read from `/var/run/drc/tsf-offset-us`:

    frame_timestamp = (monotonic_now - streamer_start) + offset

`offset` therefore has to equal **the AP's TSF at the moment the streamer
started**. Ours was stale at `2000000` (2 s) from an earlier session while the
live AP TSF was **1637 s**, so every frame was stamped ~27 minutes in the past
and silently discarded — the pad asked for a keyframe once per frame (~50-60/s)
and showed nothing.

`run/tsf-from-monitor.py` already computed the right value
(`TSF - elapsed(streamer_pid)`), but it **silently writes nothing when
`/var/run/drc/streamer.pid` is stale or the streamer is not yet running** — it
`continue`s with no output — and the runner started it *before* the streamer.
It could never have fixed the offset in that order.

### A/B proof (same content, same pad, ~56 fps both times)

| run | capture | clock domain | pad shows video |
|---|---|---|---|
| correct epoch | `capture/uvc-122918.pcap` | 1734.9 s -> 1840.5 s (AP TSF) | **yes** (operator) |
| correct epoch (verify) | `capture/uvc-123248.pcap` | 1954.2 s -> 2059.9 s | **yes** (operator) |
| **epoch left at 0** (control) | `capture/uvc-123522.pcap` | 0.5 s -> 90.0 s | **no** (operator) |
| desktop only, correct epoch | `capture/uvc-123823.pcap` | 175.3 s -> 268.8 s | yes |

Everything else was identical: 56.5 fps, median timestamp delta 16683 us
(console 16683), 5.05-5.11 datagrams/frame, 0 sequence discontinuities, same
arming and session push.

### The fix, in code

- `run/tsf-from-monitor.py --once` prints one TSFT sample, so the offset can be
  seeded *before* any streamer exists.
- `run/uvc-live.sh` (and `run/uvc-session.sh`) seed the offset from it, then
  start the pid-based refiner so the offset follows a TSF reset, and print the
  resulting domain from the capture at the end of every run.

## Why the previous search could never converge

The whole effort was scored by **keyframe-request ("resync") rate**, on the
premise that the pad requests ~60/s when it rejects video and ~0/s when it
accepts it. That premise is false:

- **The pad emits 20-60 resync/s while displaying video perfectly.** Measured in
  the three working runs (`uvc-122918` 41.8/s, `uvc-123248` 22.0/s, live capture
  60/s).
- The console's "3 requests in 300 s" was three datagrams inside 23 ms at
  t=74.9 s — one early hiccup, then silence. It is not a validity signal, it is
  a transient.
- So every parameter sweep in `out/evidence/VIDEO-PARAMSET-FINDING.md` and
  `research/DISPLAY-GATE-FRONTIER.md` was optimising noise. The best config
  scored "bad" and the worst scored "good" for reasons unrelated to the display.

**Rule for future work: the pad's screen is the only judge. Never score by
resync rate.**

## Also retired this round (with measurements, so nobody re-tests them)

- **UVC/UAC "won't show video until it receives one"** — the pad answers every
  query, 1/s, sequence-matched (`tests/uvc-exchange.py`, which must classify by
  payload signature: replies are 24-byte datagrams, queries are 56-byte). Gate
  met all along.
- **Degenerate chunks / static content** — 8.98 fps of static desktop versus
  55.5 fps of moving video made no difference; this was a clock problem.
- **The state-push payload** — byte-identical to the console (`frags[0] ==
  ours[0]`, 1048 B x 778).
- Protocol reference and hardware wiki findings (service maps, `5/0x08` video
  off, `0xF0009480` bit2 feed enable, UIC state table): see
  `research/WIKI-CMD-AND-CLOCK-FINDINGS.md`.

## Known limits / next work

1. **IDR rate 1.4-2.0/s** versus the console's ~1 per 26 s. Costs bandwidth and
   is a plausible source of the remaining stutter. Next: raise the keyframe
   interval toward console behaviour and re-check the screen.
2. **The pad auto-sleeps after ~30-90 s untouched** (input stops, video keeps
   being sent). While it is being used this does not matter; recovery on wake is
   under test (`tests/stability-watch.py`).
3. **Audio** is streamed but has not been verified on the pad speaker.
4. **Touchscreen calibration** has not been checked against the pad's panel
   reference points.

## Gotchas worth keeping in mind

- One hardware owner only: `flock /var/run/drc/hw.lock`. Children must be
  started with `9>&-` or they inherit the lock fd and hold it after the parent
  dies (this blocked a run until the orphan was killed).
- `width` confusion that cost an hour: `udp.length` includes the 8-byte UDP
  header. A 1056-byte datagram is a 1048-byte payload, which is what the
  console sends.
- The pad replies to console port **50023** no matter which local port our
  query came from (libdrc sends from an ephemeral port and listens on 50023).

---

# Part 2: why it "worked, then stopped" — the radio, not the streamer

Everything below was measured on 2026-11-04 between 12:30 and 13:30, after the
display was first confirmed working.

## The AX210 firmware crashes, and the AP dies with it

    iwlwifi 0000:03:00.0: Unhandled alg: 0x71b              (repeating, ~30-50 s apart)
    iwlwifi 0000:03:00.0: Unhandled alg: 0x3000707
    iwlwifi 0000:03:00.0: Device error - SW reset
    iwlwifi 0000:03:00.0: restart completed

After `SW reset` **the AP stops transmitting entirely**. hostapd stays "running"
and every pid/socket check passes, but:

- `iw dev WiiUAP station dump` is empty,
- `tx_packets` grows by **0** in 5 s (no beacons at all),
- the pad therefore cannot associate, shows *"could not connect"*, and eventually
  sleeps,
- and our streamer keeps blasting video at a non-existent station (the ARP entry
  is static, so ~500 pps still goes on the air — which looks healthy in a capture
  and is completely fake).

Recovery is only a **driver reload**: `modprobe -r iwlmvm iwlwifi; modprobe
iwlwifi`, then the 5 GHz unlock (idle `wpa_supplicant` with `country=CA` + a scan,
otherwise LAR leaves ch149 `no IR` and hostapd dies with
`Could not select hw_mode and channel (-3)`), then `drc-up.sh`, then a fresh
supervised streamer.

Every firmware reset also **resets the phy TSF**, which corrupts the media clock:
measured offsets went 1003 s -> 173 s -> 87.5 s -> 71 s -> 61 s -> **6 s** across
successive resets. A stale offset means our frame timestamps are minutes off the
pad's clock, so the pad discards every frame and the screen stays on its menu even
though video is on the wire.

## What now heals itself

| tool | job |
|---|---|
| `run/ap-health.sh` | exit 0 only if the AP is really transmitting: `tx_packets` must grow ≥5 in 5 s (with no stations, beacons are the only traffic). Catches the exact state every pid check misses. |
| `run/ap-recover.sh` | full radio rebuild: stop processes → reload iwlwifi → recreate the idle supplicant, force a scan to clear `no IR` → `drc-up.sh` → start the supervised streamer. |
| `run/drc-watchdog.sh` | polls `ap-health.sh` every 30 s; two consecutive failures → `ap-recover.sh`. Also keeps doing what it did before (missing vif / dead hostapd / dead streamer → `drc-up.sh`), and after any repair replaces drc-up's bare streamer with the supervised one, because drc-up's streamer has **no media clock**. |
| `run/tsf-guard.sh` | one TSF sample per minute (not a permanent monitor capture — that load made the crashes more frequent). On a >2 s step it rewrites the offset **and** drops `/var/run/drc/tsf-reset`; `drcvncclient` consumes that marker and re-arms + re-inits the video stream so the pad decodes from a fresh `init` frame instead of chasing a backwards jump. |
| `run/uvc-start.sh` | starts the supervisor fully detached (several restarts were lost because the launching shell's timeout took the session down with it). |
| `run/uvc-kill-live.sh` | stops it safely — `pkill -f run/uvc-live.sh` from an interactive shell matches the caller and kills your own shell, which happened repeatedly. |

## Input: what was actually broken

All measured with `DRC_INPUT_LOG=1`, which prints the raw `InputData` bitmask on
every change (without it, "the buttons do nothing" is unfalsifiable).

- The pad sends every button correctly, one bit each: A `0x8000`, B `0x4000`,
  X `0x2000`, Y `0x1000`, Up `0x200`, L `0x20`, R `0x10`, ZL `0x80`, ZR `0x40`,
  Plus `0x08`, Minus `0x04`.
- **Buttons were dead by configuration**: `drcvncclient` defaults to
  `drcJoystickMode = TRUE` and our runners passed `-joystick`, so every button
  went to the uinput gamepad feeder instead of the VNC session. Running without
  `-joystick` (mouse mode) maps them to A=Enter B=Backspace X=Space Y=Tab
  d-pad=arrows ZL/ZR=left/right click Plus/Minus=Copy/Paste Home=Escape.
- **A tap could never click**: the touch handler only ever sent pointer *moves*.
  Added: touch-down presses `rfbButton1Mask`, touch-up releases it, and the
  pointer now starts at the middle of the desktop instead of (0,0).
- **The sticks had no code path at all in mouse mode** — they only fed the same
  dead uinput feeder. Added: left stick = relative pointer motion, right stick =
  wheel. First attempt used a fixed step per report (~630 px/s) which was unusable;
  it is now time-based at `DRC_STICK_SPEED` px/s (default 240) with a squared
  response curve, `DRC_STICK_INVERT_Y=1` to flip the vertical sense.

## Still open

1. **The firmware crash loop itself.** ~every 1-2 minutes under streaming load,
   with `Unhandled alg: 0x71b / 0x3000707` in between. Suspects: 600+ pps with
   `11n_disable=2` (no A-MPDU) and `rts_threshold=0` (RTS/CTS on every frame), and
   key reinstallation on each pad rejoin. A different AP radio (the Pi's 5 GHz
   brcmfmac path noted in `out/evidence/VIDEO-PARAMSET-FINDING.md`) sidesteps it.
   The watchdog now hides it, but it is the difference between "works" and "works
   for an hour".
2. The pad sleeps when untouched for ~30-90 s. It wakes on a touch and the stream
   resumes; a real console session never idles like that, and the console's only
   continuous command (`svc 0/0x00`, ~0.8/s) is now sent too, but that alone did
   not keep it awake.
3. Audio has never been verified on the pad's speakers.

---

# Part 3: the stall — "it worked, then stopped" was never a regression

Operator-reported symptom: video worked (footage timestamped 12:41 and 12:43) and
then never worked again, with nothing obviously changed.

## What was actually happening

`drcvncclient` called `Streamer::PushVidFrame()` **only from the libvncclient
framebuffer-update callback**. VNC reports *changes*, so with a static desktop the
callback never fires, `VideoStreamer` never latches a frame, its 59.94 Hz timer has
nothing to send, and the media plane is completely silent.

Measured on a static desktop: **1 packet/s** on the air. Meanwhile the process was
healthy — `gdb` showed the main thread in `select()` inside
`libvncclient:WaitForMessage`, i.e. waiting for a screen change that never came.

Every earlier "it works" run had a fullscreen video playing (`~/Videos/aext.mp4`),
so the screen changed constantly and frames flowed. Every run after that — which is
every run where video "failed" — had a static desktop, so **nothing was ever sent**.
The responses to that silence were all false conclusions: the clock, the keepalive,
mouse mode, the pad session, the encoder, the client rebuild. None of them were the
cause; there was simply no stream to display.

Note this also explains an earlier observation that had been misfiled as evidence
("the console's own recorded media replayed at 31-41/s"): replaying pre-captured
media from a socket *does* send continuously, so the two experiments were not
comparable at all.

## The fix

1. Cache the normalised 854x480 BGRA frame (`g_last_frame`, mutex-guarded) whenever
   a real VNC update arrives.
2. Push it every 16,683 us from a **dedicated thread** (`FrameRepushLoop`), not from
   the VNC loop — because `WaitForMessage` was observed blocking indefinitely even
   with a 16 us timeout, so anything placed after it can stall forever.
   `DRC_NO_REPUSH=1` disables the behaviour.

Verified with a static desktop: **1 pkt/s -> 527 pkt/s** on the air, frame
timestamps advancing with a median delta of exactly 16,683 us.

## Tooling bugs found while chasing this (each silently wasted a run)

| bug | effect |
|---|---|
| `tsf-guard.sh` sampled a monitor vif it never created | after the first phy reset the clock was never corrected again — the offset stayed minutes off forever |
| the monitor vif was never tuned to ch149 | it captured **zero** frames, so every sample returned empty |
| `tsf-keeper.py` used `tshark -c 1` | it stopped on the first frame; if that frame had no radiotap TSFT the sample was silently empty → now it takes a 3 s window and uses the first frame that has one |
| the runner deleted `mon0` right after seeding | the guard then had nothing to sample — the two fought over the vif |
| `_wait-for-pad.sh` gated on **ICMP** | the pad answers ARP but not ping, so starts blocked for the full 600 s timeout while input was flowing at 280 pkt/s |
| the hardware-TSF path was tried again | the patched mac80211 exports `/sys/class/net/<if>/tsf` but iwlwifi has no `get_tsf()`, so it reads `UINT64_MAX` forever — the offset route is the only one on this radio |

## Bisect knobs added, so this can be re-tested without rebuilding

| variable | effect |
|---|---|
| `DRC_NO_REPUSH=1` | stop the independent frame pusher (returns to VNC-change-driven streaming) |
| `DRC_NO_TOUCH_CLICK=1` | restore the original move-only touch handling |
| `DRC_NO_CLOCK_REINIT=1` | ignore the `/var/run/drc/tsf-reset` marker (no re-arm/re-init) |
| `DRC_KEEPALIVE=0` | stop the `svc 0/0x00` keepalive |
| `JOYSTICK=1` | start the client in joystick (uinput) mode instead of mouse mode |

## What still limits an end-to-end run

1. **The AX210 firmware crash loop.** Under streaming load it resets every 1-2
   minutes and then the AP stops transmitting entirely (hostapd alive, `tx_packets`
   flat). Only a driver reload restores it, which also briefly drops the host's
   uplink — and the recovery is slower than the crash rate, so unattended operation
   thrashes. `ap-health.sh` / `ap-recover.sh` / `drc-watchdog.sh` automate it.
2. **The pad sleeps within ~30-60 s of the last touch**, which makes every
   measurement dependent on an operator holding a finger on the screen. Several
   "still no video" reports in this session were simply a sleeping pad: the pad was
   not associated and sent zero packets while the stream ran.
3. Whether the pad accepts degenerate (identical-frame) P-frames from the re-push
   path is still unproven: with the re-push in place the pad went from 0 resync to
   ~23/s and started answering commands again (12/s), which is the closest it has
   been to the confirmed-working signature (input ~180/s, resync ~42/s) — but the
   screen was not confirmed.

---

# Part 4: the clock model, and what is actually still closed

## The console's video clock is NOT the TSF

Measured from `capture/console-truth.pcap` (beacon radiotap TSFT) against the
decrypted video timestamps (`out/evidence/truth/port50120.bin`), at five points
across the 300 s session:

| capture t | video ts | console TSF at t | difference |
|---|---|---|---|
| 61.027 s | 92.036 s | 224.405 s | −132.369 s |
| 122.988 s | 153.998 s | 286.366 s | −132.369 s |
| 181.948 s | 212.956 s | 345.326 s | −132.370 s |
| 240.907 s | 271.915 s | 404.284 s | −132.369 s |
| 299.866 s | 330.874 s | 463.244 s | −132.369 s |

So the VSTRM timestamp runs at the TSF's **rate** but in a different domain: a
per-boot constant of **−132.369 s** (the video subsystem started after the phy).
"The timestamp must be the AP's TSF" was therefore only an approximation — it
happens to land inside the band the pad tolerates (the console itself is 132 s
"wrong" by that model). Consequences:

- the clock only has to be **monotonic, in the TSF's rate, and inside the pad's
  tolerance band**; it does not have to equal the TSF;
- **one validated seed per session is enough** (our monotonic clock supplies the
  rate), and re-writing the offset mid-stream is actively harmful;
- measured accuracy achieved with a single seed: **11 ms** from the TSF.

## What broke "it worked, then stopped"

`drcvncclient` pushed a frame only from the libvncclient framebuffer-update
callback. A static desktop therefore produced **no stream at all** — measured
**1 packet/s**, with the process healthy (gdb: main thread in `select()` inside
`WaitForMessage`). Every run that "worked" (12:27-12:43) had a fullscreen video
playing; every run that "failed" had a static desktop.

Fix: cache the normalised frame and re-push it every 16.7 ms from a dedicated
thread, **but only after ~50 ms of VNC silence** — re-pushing while live content
is arriving makes the encoder alternate between a stale cached frame and the real
one (measured: moving content fell to ~28 fps and stopped displaying).
`DRC_NO_REPUSH=1` disables it.

Static desktop now: **527 pkt/s**. Moving content: ~265 pkt/s at 50 fps, delta
16,683 us, no interference.

## The blocker that remains: the pad never arms

Objective test (`run/probe-awake.py`, and tallying the pad's reply error codes):

| pad reply | count | meaning |
|---|---|---|
| `4/0x05` → err **0**, body `00` | 1 | **UIC state 0 (Active)**, query answered |
| `0/0x00` → err 0 | 17 | simple methods work |
| `5/0x14` → err 0 | 14 | backlight works |
| `0/0x11` → err **9004** | 60-90 | the 782-datagram state push is **refused** |
| `0/0x12` → err 9004 | 1 | push terminator refused |
| `5/0x02` (102 zero bytes) | no reply | |
| `5/0x02` (zero-length, console-exact) | err **5** | refused |

`9004` is the pad's "not in a session" code. The pad sits in UIC state 0, answers
the simple methods, but refuses every session-level method — so it never leaves its
own menu, no matter how correct the media plane is. This is why resync runs at
**54/s while the screen shows the menu**: resync rate reflects "I have video
datagrams and no decodable session", not picture.

The arming chain that worked at 12:27-12:43 (`svc 5/0x15` returning 0) no longer
does, and neither payload form of `svc 5/0x02` changes that. Next: replay the
console's arm-burst datagrams byte-for-byte (`07-protocol/command-plane.py
--mode arm` does this from the captured bytes) instead of constructing them, and
treat `5/0x15 → 0` as the go/no-go before scoring anything.

## Tools added this round

| tool | job |
|---|---|
| `run/watch-live.sh` | one line per sample: pad AWAKE/ASLEEP, input, video, resync, clock error, and whether the pad is engaging. Ended the recurring "operator and tooling looking at different moments" problem. |
| `run/probe-awake.py` | waits for the pad's own input stream, then fires `4/0x05` and `5/0x15` and reads the replies off the wire (the streamer owns 50023). |
| `run/watch-firmware.sh` | samples the firmware reset counter alongside health, which produced the load/crash correlation. |

---

# Part 5: arming is real, it expires, and our own burst was breaking it

This is the direct answer to "why does a correct stream not display". Everything
below is measured with the pad's own replies (`run/probe-awake.py` /
`run/probe-display.py` read them off the wire, because the streamer owns
`192.168.1.10:50023`).

## 1. The pad CAN be armed, and the state oracle confirms it

Replaying the console's *own* command stream (`run/command-plane.py --mode console`)
produced, at the start:

```
GATE 5/0x15 -> 0 body=05     <- armed, backlight level readable
STATE ? -> 0  (retvals[0]=0)
```

Then, later in the same replay: `GATE 5/0x15 -> 9004` — it disarmed by itself.

With our streamer running and a corrected burst, both oracles agree:

```
state  seq=0 error=0 body=00   -> UIC state 0 (Active)
gate   seq=1 error=0 body=05   -> ARMED
```

## 2. `svc 5/0x02` was knocking the pad out of Active state

`svc 5/0x02` is "102 bytes to UIC command 0x0c" — a UIC **write** (`sc-cmd.rst`;
`uic` page lists command `0x0C` as 102 parameters). We were sending **102 zero
bytes** as part of the arm burst.

A/B on periodic re-arming (`--arm-period 5`):

| burst | result |
|---|---|
| with `5/0x02` (102 zeros) | arms, then `STATE 0 -> 12` and `GATE -> 9004` |
| **without `5/0x02`** | `STATE 12 -> 0`, `GATE -> 0 body=04`, **stays armed across re-sends** |

So our own arm burst was walking the pad from Active (0) into state 12 and leaving
it unarmed. `svc 5/0x02` is now **opt-in** in `Streamer::ArmSession()`
(`DRC_ARM_5_02=1` restores it); the recorded console instance of that command had a
zero-length payload, and 102 zero bytes is invalid for a UIC write.

## 3. The armed state expires, so arming must repeat

The pad goes back to `9004` on its own after a while (measured repeatedly). Our
client only armed on a pad rejoin (~80 s apart), which is far too slow. The
command-plane test that held it armed re-sent the burst every 5 s.

`drcvncclient` now runs an **arm keepalive thread** (`ArmKeepaliveLoop`, period
`DRC_ARM_EVERY_MS`, default 15000, `DRC_NO_ARM_KEEPALIVE=1` to disable).

## 4. Armed + state 0 + video + correct clock, and still no picture

The remaining gate is inside the video pipeline itself. Candidates, in order:

1. **The display swap.** The hardware wiki says LCD controller `0xF0009480` bit2 is
   "Enable video feed (camera/H264)" and that stock 854x480 modes leave it *off*
   (`0x2` vs `0xA`). The pad flips it when its video manager runs.
2. **`mc_video` startup** (`wiiubrew.org/wiki/GamePad/LVC`: `mc_video` = "video
   stream decoding and playback", a manager separate from `mc_cmd`). Arming `mc_cmd`
   is not the same as starting `mc_video`.
3. `svc 5/0x08` payload `01` was tried as a display enable (payload `00` is the
   documented "disable video" the Home menu sends) — the pad did not report a reply
   in the window it was awake, so this is **untested**, not refuted.

## Reproduction of the armed state (what to do next)

```bash
sudo ./run/uvc-kill-live.sh                     # free 50023
sudo python3 run/command-plane.py --mode arm --arm-period 5 --seconds 60
#   expect: GATE 5/0x15 -> 0 body=0x ; STATE -> 0
# with the streamer:
sudo ./run/uvc-start.sh                          # seeds the clock, arms on rejoin
sudo python3 run/probe-awake.py                  # state + gate, the instant it wakes
sudo ./run/watch-live.sh 120 3                   # pad AWAKE? engaging? clock error
```

---

# Part 6: the pad leaves its menu and goes BLACK (patched driver)

The operator's observation, and the first pad-side change since the project started:
with the **patched mac80211** loaded, the pad stops showing its own menu and shows a
**black screen** instead of "could not connect". A black screen is the display
switching to the video feed with nothing decoded — i.e. the pad has finally taken the
step that `0xF0009480` bit1/bit2 describes (display on, feed selected, no picture).

Measured in that same run, with the video-enable (`svc 5/0x08` payload `01`) now part
of the arm burst by default:

```
17:06:06  AWAKE  input 161/s  video 263/s  resync 54/s  eng YES
state -> 0 (Active)   gate 5/0x15 -> 0 body=05   (armed)
```

So the full session signature is reachable on the patched driver: associated,
armed, state 0, video flowing, clock verified.

## What changed vs the working 12:29 runs

| | 12:29 (picture, we are told) | now |
|---|---|---|
| mac80211 | **stock** | **patched** |
| arm burst | `0/0x00`, `4/0x04`, `5/0x02`, `5/0x06` | same, `5/0x02` now opt-in, plus **`5/0x08=01`** |
| client | `-joystick`, no touch-click, no re-push | mouse mode, touch-click, idle-only re-push |
| pad display | showed our desktop | **black** (feed mode, nothing decoded) |

Two live hypotheses, both testable:

1. **The patched driver is what makes the pad enter feed mode** (operator's
   hypothesis, and it is the only change that moved the pad off its menu). If so the
   remaining problem is purely the decoder/picture, not the session.
2. **`5/0x08=01` + arming + the patched driver together** are required; the stock
   driver never reached feed mode no matter what the command plane did.

Either way the next test needs one window in which all of these hold at once:
pad awake (hold a finger on it), freshly restarted session (so the clock is seeded
after the last firmware reset — a stale clock measured **381 s** off after one), and
then a fresh `init`+IDR on the video plane.

```bash
sudo ./run/uvc-kill-live.sh && sudo ./run/uvc-start.sh   # reseed + stream
sudo ./run/watch-live.sh 120 3                           # look when AWAKE + YES
```

---

# Part 7: the black screen is not a decodability problem

With the patched driver loaded the pad reliably goes **black** instead of showing its
menu: it has selected the video feed and is decoding nothing it can display. Three
objective checks on the live stream (`tests/agent-chunk-audit.py`, which rebuilds
Annex-B with the pad's hardcoded SPS/PPS *and* Barista's synthetic slice header):

| check | result |
|---|---|
| frames complete (5 chunks each) | 60/60 |
| datagrams per frame | 5.02 – 5.27 |
| **decode from the first IDR under the pad's SPS/PPS** | **exit 0, 0 errors, 854x480 yuv420p** |
| first IDR alone | decodes clean, 5.7–18.5 kB |
| standalone chunk decode (raw cut) | all False — same as the console's chunks (expected) |
| degenerate chunks | 118 of 300 are 1–2 bytes |

The degenerate count looked damning until the working capture was measured the same
way: it carried **~390 B per frame**, ours carries **277–1282 B**, i.e. the same order.
Small chunks are a property of this content, not a regression.

So the pad is in feed mode, receiving frames it could decode, and showing black. That
points away from the media plane entirely and at the pad's **display/LCD
configuration**:

- `svc 5/0x19` — "Set LCD parameters via i2c to the LCD controller chip" (13-byte
  payload); `5/0x1a` reads them back. **We have never sent this with real values.**
  It is the only documented command that configures the LCD controller itself, and
  the hardware wiki's note that `0xF0009480` bit2 (video feed) is left OFF by stock
  854x480 modes suggests the panel needs configuring before the feed is visible.
- The `50025 → 50125` 96-byte panel table is the other display-related artefact we
  do send.
- Reading `5/0x1a` first (13 bytes back) would give the parameters the pad currently
  believes, which is the natural starting point for a correct `5/0x19`.

## Also automated this round

- `run/reset-watcher.sh` — watches `dmesg` for `restart completed`; on a firmware
  reset it restarts the supervised session so the clock is **reseeded**. This is the
  robust replacement for a live TSF refiner, because a monitor vif **cannot be
  re-tuned while the AP is running on this radio** (measured: `iw dev mon0 set
  channel 149 HT20` exits 0 and leaves the vif with no channel, so it captures
  nothing — which is why every "live correction" scheme silently stopped correcting).
- `run/load-patched-mac80211.sh` / `run/restore-stock-mac80211.sh` — A/B the module.
