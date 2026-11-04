# Systematic audit: everything that could stop the pad displaying

Method: measure the current system, then diff it against the artefacts from the runs
that *did* work (12:27–12:43). Sources of "then": `capture/uvc-122918.pcap`,
`uvc-123248.pcap`, `uvc-123823.pcap` (stream profiles), `out/logs/live-124226.log`
etc. (stack behaviour), and the operator's own footage timestamps.

Verdicts: **IDENTICAL** (measured same), **DIFFERENT** (measured change),
**RULED OUT** (measured and excluded), **UNKNOWN** (cannot measure retroactively),
**UNTESTED**.

---

## 1. Kernel / modules — the one real difference found

| item | during working runs | now | verdict |
|---|---|---|---|
| `mac80211` build | **stock** — `libdrc: no TSF sysfs node` in every log before 15:10 | **patched** (custom build for 7.1.5): `/sys/class/net/{wlan0,wlan1,WiiUAP}/tsf` all exist, node returns `UINT64_MAX` | **DIFFERENT** |
| clock path consequence | synthetic clock + `/var/run/drc/tsf-offset-us` | same (libdrc detects `UINT64_MAX` and falls back: `libdrc: TSF unavailable (UINT64_MAX) - using synthetic monotonic clock`) | IDENTICAL |
| `cfg80211` | stock | stock | IDENTICAL |
| `iwlwifi` / `iwlmvm` | loaded | loaded | IDENTICAL |
| `iwlwifi 11n_disable` | 2 | 2 | IDENTICAL |
| `iwlwifi power_save` | N | N | IDENTICAL |
| `iwlwifi bt_coex_active` | Y | Y | IDENTICAL |

**Why this matters:** the patched mac80211 is a *locally compiled* module (kernel
patch `01-radio-kernel/tsf-kali-7.1.5.patch`). Even though the added sysfs node is
inert for us (it returns `UINT64_MAX`), a different build of mac80211 changes the
AP/driver behaviour it implements — beaconing, HT handling, aggregation, timing.
Every confirmed-good run used the **stock** module. This is the single clearest
structural difference between "it worked" and "it doesn't".

Timeline caveat, stated honestly: the failures began at ~12:52, *before* the patched
module was loaded at ~15:10. So this cannot explain the whole window — but it is a
real difference in the current state and must be reverted to match the working
configuration.

## 2. hostapd settings (`/var/run/drc-ap.conf`, rendered by `drc-up.sh`)

| setting | value | note |
|---|---|---|
| `interface` / `bssid` | `WiiUAP` / `cc:fb:65:b6:81:69` | console's BSSID ✔ |
| `hw_mode` / `channel` | `a` / `149` | 5745 MHz, matches the working runs |
| `beacon_int` / `dtim_period` | 100 / 3 | console parity |
| `ieee80211n` | 1 | required |
| `wmm_enabled` / `uapsd_advertisement_enabled` | 1 / 0 | console parity |
| `rts_threshold` | **0** (RTS/CTS on every frame) | measured console behaviour, but a heavy firmware load — see §9 |
| `vendor_elements` | `dd09001018020000040000` | console's Broadcom IE ✔ |
| `ignore_broadcast_ssid` | 2 | hidden SSID, console parity |
| `ap_max_inactivity` | **86400** | deliberately raised — no more inactivity deauths |
| `disassoc_low_ack` | 0 | do not drop the pad on TX failure |
| `wpa` / `pairwise` | 2 / CCMP, `wpa_key_mgmt=WPA-PSK` | with the `CONFIG_TENDONIN` patch |

Verdict: **IDENTICAL to the working configuration** (same renderer, same template).

## 3. Addressing, ports, bindings

| item | value | verdict |
|---|---|---|
| us (console) | `192.168.1.10/24` on `WiiUAP` | IDENTICAL |
| pad | `192.168.1.11`, leased by our `netboot` | IDENTICAL — DHCP DISCOVER/OFFER/REQUEST/ACK + ARP both ways verified |
| uplink | `192.168.86.30` (`wlan1`) | unrelated to DRC |
| video | send from 50020 → pad 50120 | IDENTICAL |
| audio + format | send from 50021 → pad 50121 | IDENTICAL |
| input | bind 50022 ← pad 50122 | IDENTICAL |
| command | bind 50023 ↔ pad 50123 | IDENTICAL |
| resync | bind 50010 ← pad 50010 | IDENTICAL |
| panel table | 50025 → pad 50125 at 1 Hz | IDENTICAL |

## 4. Media plane — measured identical to the working runs

| metric | working 12:29 | working 12:32 | **now** |
|---|---|---|---|
| frames/s | 56.2 | 56.5 | **56.9** |
| video datagrams/s | 283 | 285 | **290** |
| format messages/s | 57.2 | 57.5 | **57.9** |
| audio datagrams/s | 114 | 114 | **114** |
| median timestamp delta | 16683 µs | 16683 µs | **16683 µs** |
| payload size range | 25..1718 | 25..1718 | **25..1718** |
| IDR rate | 6.8/s | 7.2/s | 10.6/s (higher, same order) |

Verdict: **RULED OUT** — the stream is indistinguishable from the one that displayed.

## 5. Media clock

| item | working | now | verdict |
|---|---|---|---|
| seed method | one seed from a monitor-vif TSFT sample | one validated seed (two agreeing samples) | equivalent |
| measured accuracy | not measured then | **11 ms – 0 s** from the AP TSF | better than then |
| mid-stream rewrites | none | none (guard is diagnostic-only) | IDENTICAL |
| console's own domain | — | VSTRM ts = **TSF − 132.369 s** (constant, measured) | model corrected |

Verdict: **RULED OUT as the current cause** (it is verifiably correct now).

## 6. Order of operations

| step | working runs | now | verdict |
|---|---|---|---|
| 1. AP up, pad associates, DHCP | yes | yes | IDENTICAL |
| 2. seed clock | before the streamer starts | before the streamer starts (two-sample validation) | IDENTICAL |
| 3. start streamer | `-joystick`, `tsf-from-monitor.py` once | mouse mode (or `JOYSTICK=1`), same | equivalent |
| 4. arm session | `ArmSession()` on first input + on rejoin | same **plus** a 15 s arm-keepalive thread | DIFFERENT (added) |
| 5. session push (782 datagrams) | on each arm | same | IDENTICAL |
| 6. video-format message | per frame | per frame | IDENTICAL |
| 7. re-arm on pad rejoin | yes | yes | IDENTICAL |

## 7. Command plane — the arming findings

| item | finding |
|---|---|
| `svc 5/0x15` (arming oracle) | **0 = armed, 9004 = not armed.** Confirmed both ways |
| `svc 4/0x05` (UIC state) | returns **0 (Active)** now; **12** when unarmed/menu |
| `svc 5/0x02` (102 bytes → UIC cmd 0x0c, a UIC *write*) | included once in the working burst; sending it **repeatedly** drives state 0 → 12 and 9004. Now opt-in (`DRC_ARM_5_02=1`) |
| armed state lifetime | **expires on its own** — needed re-arming every 5 s to hold it in the command-plane test; client now re-arms every 15 s |
| `0/0x11` (782-datagram push) | answered **9004** even when `4/0x05` and `5/0x15` return 0 — the push belongs to a manager that is not up |
| `5/0x08` payload `01` ("video enable"; `00` = the Home menu's disable) | **UNTESTED** — the pad slept before the reply; needs one clean window |

## 8. Pad-side (cannot be measured retroactively)

| item | now | verdict |
|---|---|---|
| UIC state | 0 Active (when armed) | measured |
| arming | `5/0x15 → 0` achieved, then expires | measured |
| association | associates, DHCPs, ARPs, sends input at ~180/s | measured |
| rejoin cadence | every 35–85 s when awake | as before |
| sleep | **15–40 s** after last input | worst operational problem; every "no picture" report so far coincided with a sleep window |
| `mc_video` (decode/playback manager) | **never observed started** — see `LVC-ARCHITECTURE-AND-MANAGERS.md` | the remaining gate |

## 9. Physical / RF

| item | value |
|---|---|
| channel / width / txpower | 149 (5745 MHz) / HT20 / 22 dBm — unchanged |
| RTS/CTS on every frame (`rts_threshold=0`) + A-MPDU disabled (`11n_disable=2`) | console-parity settings, but ~600 pps of RTS/CTS traffic is a heavy firmware load; correlates with the AX210 firmware resets (70–233 s while streaming vs 758–1033 s idle) |
| firmware resets | `iwlwifi: Device error - SW reset` → **AP stops beaconing** until a driver reload |

## 10. Ranked suspects (what to test, in order)

1. **Revert mac80211 to the stock module** and re-test — the only module difference
   between the working runs and now. Requires a driver reload (brief uplink drop).
2. **`svc 5/0x08` payload `01`** in a clean awake window, with the pad armed. It is
   the documented video *enable* and has never actually been tested.
3. **`mc_video` startup**: the pad answers `mc_cmd`-level methods but never starts
   the decode/playback manager; find what starts it (the console's traffic at
   session start is the reference — replay `command-plane.py --mode console`).
4. **Remove the arm-keepalive's `5/0x02`** (already default) and confirm the pad
   stays at state 0 through a 60 s window while streaming.
5. **Firmware-crash mitigation** (lower pps: `DRC_FPS=30`, no audio) so a session
   survives long enough to test the display at all.

## 11. Ruled out — do not re-test

Media plane (fps/dgram/format/audio/timestamp/sizes/IDR), clock accuracy, addressing
and ports, hostapd configuration, DHCP/ARP, the UVC/UAC "must receive it" claim, the
degenerate-chunk theory, the state-push byte content, resync rate as a success metric.

---

## 12. Firewall, and the exact behaviour of the live streamer

| item | result |
|---|---|
| `iptables` rules touching 50010/50020/50021/50023 | **none** — only Docker chain rules (`FORWARD DROP` for docker bridges, irrelevant). The stale `OUTPUT DROP` on UDP/50121 that once discarded 120 MB is **not** present. RULED OUT. |
| live streamer cmdline | `drcvncclient 127.0.0.1:5900` — **no `-joystick`**, i.e. **mouse mode**. The confirmed-working runs were `-joystick`. DIFFERENT (but joystick mode was tested at 16:26 and also failed). |
| live streamer env | only `DRC_SYNTHETIC_TSF=1`. So *all* of the new defaults are active: `DRC_KEEPALIVE` on, frame re-push on, arm-keepalive every 15 s, `5/0x02` skipped. |
| pad station entry | empty at audit time (pad asleep) — consistent with every "no picture" report |

### To reproduce the 12:29 behaviour exactly

```bash
sudo env JOYSTICK=1 DRC_KEEPALIVE=0 DRC_ARM_EVERY_MS=0 DRC_ARM_5_02=1 \
     DRC_SYNTHETIC_TSF=1 ./run/uvc-start.sh
```
plus, as step 1 of §10, the **stock mac80211** instead of the patched build.

## 13. What the audit changes about the plan

The media plane, clock, addressing, ports, hostapd settings and firewall are all
either identical to the working state or measurably correct. The differences that
remain are:

1. **mac80211 build** (stock → patched) — the only module-level change.
2. **client mode** (joystick → mouse) — tested, not sufficient on its own.
3. **new defaults on by default** (keepalive, re-push, arm-keepalive) — all
   individually switchable; keepalive-off was tested at 15:38 and did not restore
   the picture, but that test ran with the patched module and possibly a stale clock.
4. **the pad's own `mc_video` never starting** — the remaining structural gap, which
   no amount of stream-side correctness addresses.

So the next experiment must control for (1) and (3) *together* — stock mac80211 plus
the old behaviour flags — before any further protocol theory is worth testing.
