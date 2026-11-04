# The GamePad video-playback clock: what we can and cannot read

Scope: offline only. Sources: `research/libdrc/web/docs/re/*.rst`, the decrypted
session (`out/evidence/truth/port50123.bin` console→pad, `port50023.bin`
pad→console, `port50022.bin` pad input) and the pc2drc source. Every capture
number below is reproduced by `python3 tests/agent-pad-clock-scan.py`.

## 1. What the docs say about pad time

- **Time command** (`sc-cmd.rst:310-325`): query type 2, 8-byte payload
  `struct TimeCommand { u16 days_counter; u16 padding; u32 seconds_counter; }`
  little-endian, "counting from an unknown point in time". It is a one-way clock
  *set*: DRH sends it when a DRC connects. The pad replies with an **empty body**
  (it echoes nothing back).
- **Service 3** (`sc-cmd.rst:168-183`) is the only documented read path that can
  return counters: `0x03` phy_stats (13 B), `0x04` pkt_stats (152 B),
  `0x05` wmm_stats (448 B), `0x06` RSSI (2 B) — all "from the Wi-Fi adapter".
  Their field layout is **undocumented** and no repo code implements them.
- Every other documented reply is fixed/static, not a clock: `0/0x00` LVC fw
  (8 B), `4/0x04` version (28 B), `4/0x05` state (1 B), `5/0x06` UIC fw+EEPROM
  (772 B), `2/0x0c` device cert (272 B).
- The real playback clock lives in the **media plane**, not cmd: `vstrm` header
  bytes 4..7 (BE u32 µs, `sc-vstrm.rst:23-36`) and the video-format message bytes
  8..11 (LE u32 µs, `sc-astrm.rst:63-71`, "should match the vstrm timestamp").

## 2. What the capture shows (numbers)

Time commands (console→pad), 4 total, all before video starts:

| t (s) | days (0x) | seconds (0x) | seconds-of-day |
|---|---|---|---|
| 0.901 | 61348 (0xEFA4) | 24112 (0x5E30) | 06:41:52 |
| 54.296 | 61348 | 24165 (0x5E65) | 06:42:45 |
| 59.192 | 61348 | 24169 (0x5E69) | 06:42:49 |
| 73.313 | 61348 | 24183 (0x5E77) | 06:43:03 |

- `seconds` advances +1/s → genuinely seconds-of-day; `days` is constant 61348.
  61348 "days since 2000" would be year ~2168, so either the field is not
  days-since-2000 (our `uvcuac-synchronizer.cpp:85` assumes that epoch) or the
  console's RTC is unset/garbage. Unverified; cosmetic to the video clock.
- The pad's time-command reply is empty in all 4 cases — it never reports time.

Monotonic pad→console fields (full scan of every reply + the input plane):

1. `svc 0/0x11` reply = **4-byte big-endian u32**, strictly monotonic
   `4, 8, 12, … 779` (delta +4 ×193, +3 ×1), one per 4-fragment state message,
   ~28/s, but **only t=1.1–28.9 s** (tracks the 778-fragment UIC-state push and
   stops when the push stops). A transfer cursor/ack, not a clock.
2. Input protocol (pad→50022) `u16` LE seq_id: 48,760 records, 162.9/s, deltas
   +1 ×48,736 / +2 ×21, 2 wraps of 2^16 across 300 s. Monotonic all session, but
   a sample counter, not a timebase.
3. `svc 5/0x06` UIC EEPROM (792 B datagram): static config (SSID
   `WiiUccfb65b68169`, cert hash, LCD/touch calibration). Its only change is a
   **one-time** 3-byte flip at offsets 674–676 (`ff ff 00` → `00 87 0f`) between
   t=0.93 s and t=59.8 s. Not monotonic, not a clock.
4. UVC/UAC 16-byte reply, `0/0x00` LVC reply (running=installed 0x17010c19),
   `4/0x04` version reply: all constant across the session.

**No pad reply anywhere carries an 8-byte TSF, a running µs counter, or any continuously-advancing clock.** The console never queries service 3.

## 3. Does a monotonic pad-side field exist?

Yes, but not a clock: (a) a transfer cursor (28 s only) and (b) an input sample
counter (u16, ~163/s); neither disciplines microsecond media timestamps. **No
channel in the capture or docs returns the pad's own timebase.** The only
unobserved possibility is `svc 3/0x04` (pkt_stats, 152 B) or `3/0x05` (wmm_stats,
448 B), which *might* embed the BCM4319's TSF/counters — pure speculation: layout
unknown, never captured, no implementation exists.

## 4. Recommended media-clock derivation

The pad schedules video against the **AP TSF** (µs) it syncs from our beacons;
the pad's TSF tracks our AP's TSF. So the timebase is obtained by reading *our
own radio*, not by any pad query:

```
media_ts  = AP_TSF_us & 0xFFFFFFFF            # 32-bit µs
format_ts = (AP_TSF_us - 1250) & 0xFFFFFFFF   # console offsets the format msg
```

- vstrm: `SetTimestamp(media_ts)` → **big-endian** at bytes 4..7.
- video-format: `BuildVideoFormatPacket(format_ts)` → **little-endian** at bytes 8..11.
- Send format first, video ~5 ms later (already done via `DRC_FORMAT_LEAD_US`).

Code: the single clock source is `GetTsf()` in
`pc2drc/libdrc-vnc/libdrc-thefloppydriver/src/tsf-linux.cpp:110-180`; it reads
`/sys/class/net/<if>/device/tsf` then `/tsf` (patched mac80211), and falls back
to `CLOCK_MONOTONIC + TsfOffsetUs()` when absent (`:129-177`).
`video-streamer.cpp:80-84` truncates it to u32; `:167-201` writes the LE format
byte; `GenerateVstrmPackets` (`:86-147`) stamps the BE video bytes.

**Fix in order of preference:** (1) a `.get_tsf()` radio (RT5572/rt2800usb,
ath9k) so `GetTsf()` returns the real TSF; (2) `wozt/rtw88_TSF` on an RTL8821CU;
(3) keep the synthetic clock but drive `tsf-offset-us` from the monitor-vif
radiotap TSFT (`run/align-clock.sh`). All three land the timestamp in the AP-TSF
domain; the current `drc-up.sh:200` `(epoch_ms mod 2^32)` is wall-clock (~2800 s),
unrelated to the radio's TSF.

## 5. Is the epoch hack "good enough"? No — unproven, and confounded

The "0.0 resync/s" that made `(epoch_ms mod 2^32)` look correct was measured
before the **armed/unarmed gate** was known (`SETUP.md` round 14): an *unarmed*
pad sends 0 resync requests regardless of the clock. Once armed, even the
console's own recorded bytes replay at 31.6 resync/s (clock ~92 s) vs 32.8
(clock rebased to 0 s) — "clock base is not the lever" there. So the acceptable
range of values cannot be stated from these measurements; the only established
fact is that a base far *behind* the pad's current TSF (0 s or 92 s) is rejected.
The correct base is our AP's current TSF, obtainable only via (1)/(2)/(3) above.
**The epoch hack is unverified, in the wrong domain, and is not a substitute for
a real TSF.**

## 6. How to verify this offline

1. `python3 tests/agent-pad-clock-scan.py` — re-derives §2 (time commands, reply
   grouping, the 4-byte BE cursor, UIC-blob diff, input seq_id).
2. `python3 research/rce-hunt/tools/parse_truth.py 1 3 4` — independent framing +
   service/method mapping of the same files.
3. The one thing that cannot be verified offline is the value of our own AP's TSF
   on the AX210; that is a live hardware read (`.get_tsf` or radiotap TSFT), and
   it is precisely the gap the epoch hack papers over.
