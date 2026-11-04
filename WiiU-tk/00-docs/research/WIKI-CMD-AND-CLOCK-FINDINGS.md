# Wiki + cmd-reference read, and the media-clock root cause (2026-11-04, ~12:30)

Two things happened this round: the kuribo64 WUP hardware wiki and libdrc's
`web/docs/re/sc-cmd.rst` were read for a documented display lever, and two
instrumented live sessions produced a concrete, independently-verifiable defect
in our media clock. Everything below is measured, not assumed.

---

## 1. Protocol reference: what a console actually sends

`research/wozt-libdrc/web/docs/re/sc-cmd.rst` is the authoritative cmd-protocol
reference, and it settles several things we had guessed at.

**The cmd protocol is a 4-state machine** (`query -> ack -> reply -> ack`) where
*"Until an ACK is received, DRH/DRC will retry sending."* `query_type` is 0
(generic), 1 (UVC/UAC) or 2 (time).

**Complete service/method map** (only 0, 4 and 5 are ever used by a console):

| svc | methods |
|---|---|
| 0 | `0x00` LVC firmware versions (2×u32), `0x02` start product update, `0x03` update data (max 1028), `0x09` hardcoded values, `0x0a` version from EEPROM, `0x0b`/`0x0c` TVCode/Service/Screen update, `0x0d`-`0x0f` language bank |
| 1 | `0x05` WL_CONFIG_VARS + auth + enc + SSID + PSK (113 B), `0x08` Wake-on-WLAN key (16 B) |
| 2 | `0x00` no-op, `0x0c` device ID + certificate (272 B) |
| 3 | `0x03` phy_stats, `0x04` pkt_stats, `0x05` wmm_stats, `0x06` RSSI |
| 4 | `0x01` reboot/shutdown (**payload 0 = normal, 2 = firmware-update mode, 4 or 6 = shutdown**), `0x04` version info, `0x05` UIC state, `0x1a` "shuts down the pad if flags = 0x42" |
| 5 | `0x00` UIC table @f8d0, `0x01` sensor bar on/off, **`0x02` 102 B to UIC cmd 0x0c**, `0x06` UIC fw version + 768 B EEPROM, **`0x08` payload 00 disables video** (sent when the Home menu turns the display off), **`0x0a` payload 00 disables sound**, **`0x19` set / `0x1a` get LCD parameters over I2C to the LCD controller**, `0x0c` UIC EEPROM update, `0x10` NFC ICTAG, `0x11` IRCOM, `0x14` backlight, `0x15` read backlight, `0x17`/`0x18` TV remote codes |

**The one claim that looked like our symptom:**

> "This command is issued every second. **Recent versions of the GamePad
> firmware will only show the video stream after receiving one such command.**"
> (the UVC/UAC command, query type 1)

Tested and **retired** — see §3.

`0x08`/`0x0a` are still worth a positive control: sending `5/0x08` payload `00`
should blank the pad's video, so if it does nothing, service-5 writes are not
reaching the display path at all.

## 2. Hardware wiki: the feed bit is pad-internal

- LCD controller `0xF0009480`: bit1 "Enable display (0 = black screen)", **bit2
  "Enable video feed (camera/H264)"**, bit3 feed input select, bit4 overlay.
  Stock 854x480 modes write `0x2` (display on, **feed off**); mode 2 writes `0xA`.
- H264 codec page: incoming bitstream buffer `0xF00084A4`, decode IRQ status
  `0xF00084B0`, IRQ `0x12`; the page itself says *"TODO: figure out what
  enables/disables the encoder/decoder."*
- UIC (`STM8L151R8`, 15 states, reachable over SPI): 0 Active, 3 Sleep,
  4 Standby, **5 Pairing to WiiU**, 6 FWUpdate, 11 WOWLSetting (idle boot
  state), **12 DKSetting** (set if L+ZL are held at boot). `0x05` queries the
  state, `0x01` sets it, `0x0F` returns previous+current, `0x12` toggles the
  backlight.

**Consequence:** the video-feed gate is a register inside pad firmware. No
documented remote command reaches it, which is consistent with everything we
have measured — so the remaining levers are the untested service-5 writes
(`0x08`, `0x19`) and session state, not a hidden "enable feed" RPC.

## 3. Corrections to my own earlier notes

1. **`port*.bin` files are keyed by DESTINATION port.** `port50123.bin` is
   console->pad (1475 datagrams), `port50023.bin` is pad->console (1475). The two
   equal counts are a genuine 1:1 command/reply pairing, not a writer artefact.
2. The 4-byte `si`/`di` fields in those record headers are **payload slices
   (`buf[12:16]`, `buf[16:20]`), not IP addresses** (`capture/truth-decrypt.py`
   line 516). Direction must be read from the sport/dport pair.
3. **State 12 is normal.** The real console queried `svc 4/0x05` exactly once, at
   t=0.019 s, and the pad answered `0x0c` = 12. So "12 = Quick Start Menu" was a
   guess; state 12 is simply where the pad sits at session start, and our oracle
   matching 12 -> 0 after arming mirrors the console.
4. The console's only `svc 5/0x02` carried a **zero-length** payload (20-byte
   datagram = 8 CmdHeader + 12 GenericCmdHeader, `payload_size = 0`), so our
   replayed arm burst is correct; the "102 zero bytes" in my notes came from the
   documented form, not the captured instance.
5. **The state push is byte-identical**, not 8 bytes long. The console's is 1048
   bytes of UDP payload x 778; ours matches `frags[0] == ours[0]` exactly. My
   "8 extra bytes" reading was confusing UDP header bytes with payload.
6. Our commands egress from **ephemeral source ports** (`36045`, `48069`) while
   the pad replies to console:50023. That is libdrc's design (`UdpClient` sends,
   `UdpServer` listens on 50023), not a defect.

## 4. Instrumented live sessions (new tooling)

`run/uvc-session.sh` takes the hardware flock, waits for the pad, starts x11vnc,
seeds and refines the media clock, optionally plays moving content, captures
plaintext UDP on `WiiUAP`, and scores everything. `tests/uvc-exchange.py` scores
the UVC/UAC exchange **by payload signature** (the pad's reply is a 24-byte
datagram while the query is 56, so scoring by length silently reports 0 replies).

### UVC/UAC is NOT the gate — retired with measurements

| run | queries | replies | note |
|---|---|---|---|
| `capture/uvc-122015.pcap` | 101 | 47 | all 47 within the pad's awake window; replies stop at exactly t=58.0 s |
| `capture/uvc-122451.pcap` | 84 | 50 | 0 replies while the pad is asleep |

Replies match the query sequence numbers one for one (`seq 6, 9, 0x11, 0x14,
0x17, ...` = 1/s), so the pad accepts and answers our UVC command exactly as it
does the console's (228/228). The documented precondition is **met**.

Reply vs resync timing is the giveaway: **resync requests occur only while the
pad is awake and replying, and both stop together** (58.0 s / 58.6 s in run A).
So the pad is not "waiting for UVC"; it is asking for keyframes for as long as it
is in session at all.

### The requests are per-frame and identical to the console's

The resync datagram is 4 bytes `01 00 00 00` on both sides. The console's pad sent
**3 in 23 ms at t=74.9 s and never again** in 300 s; ours are ~17 ms apart
(~50-60/s) for as long as the pad is awake. That is one request per frame: the
pad fails to decode or display every frame we send.

### Degenerate chunks are NOT the gate — retired with measurements

Static VNC content gave 8.98 fps with 1-2 byte P-frames. Playing a real video
fullscreen on the served display gave **285.7 video datagrams/s, 55.5 fps, 5.15
datagrams/frame, 0 sequence discontinuities** — and the pad still asked 47-53/s
while awake. Content shape is not the gate either.

## 5. The media-clock defect (root cause found, fix in progress)

`GetTsf()` has no `/sys/class/net/<if>/tsf` on iwlwifi. Without
`DRC_SYNTHETIC_TSF=1` it returns -1 and every frame is stamped from an
uninitialised value — run A measured **median frame-timestamp delta 0 us** where
the console's is **16683 us**. With the synthetic clock the delta becomes exact
(16683 us), but the *epoch* comes from `/var/run/drc/tsf-offset-us`, and:

- the streamer stamps frames as `elapsed_since_start + offset`;
- the pad schedules playback against the **AP's TSF**, which it syncs from our
  beacons, so `offset` must be the AP's TSF at streamer start;
- `run/tsf-from-monitor.py` computes exactly that (`TSF - elapsed(pid)`) **but
  silently writes nothing when `/var/run/drc/streamer.pid` is stale or the
  streamer is not yet running** — it `continue`s with no output;
- my runner started it *before* the streamer and the file was stale at
  `2000000` us (2 s) from 12:00.

Measured consequence: run B stamped **2.667 s -> 101.98 s** while the live AP TSF
was **1637.06 s** (`tshark -i mon0 -e wlan_radio.timestamp`), i.e. **every frame
looked ~27 minutes stale** to the pad. That is a mechanism for "discard the frame
and ask for a keyframe", and it is precisely a once-per-frame request rate.

For reference, the console's own timestamps are a 1:1 real-time us clock:
92.036 s at the first frame, 330.874 s at the last, span 238.839 s over 238.8 s
of wall clock, median delta 16683 us.

Fix implemented: `tsf-from-monitor.py --once` prints a single TSFT sample; the
runner seeds the offset from it *before* starting the streamer, then starts the
pid-based updater to refine, and prints the resulting clock domain from the
capture at the end of every run.

## 6. Method rules learned here

1. Score a payload/command exchange **by signature, not by length** — the pad's
   replies are a different size from the queries on every query type.
2. Never start the clock helper before the process whose elapsed time it needs:
   it fails silently by design.
3. A timestamp `delta` of 0 and a timestamp `epoch` of 0 are different bugs.
   Check the absolute value against a live TSF sample, not just the delta.
