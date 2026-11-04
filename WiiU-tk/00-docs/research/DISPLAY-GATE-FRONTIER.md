# The display-gate frontier — what is ruled out, with numbers

> **SOLVED (2026-11-04 ~12:30). The display works. Read
> `research/DISPLAY-WORKS.md` first — it supersedes the premise below.**
>
> The root cause was the **VSTRM timestamp epoch**: the pad schedules playback
> against the AP's TSF, which it syncs from our beacons, so the media clock has
> to be *the AP's real TSF*. Our offset file was stale at 2 s while the live AP
> TSF was 1637 s, so every frame looked ~27 minutes stale and was discarded.
> A/B on the same 56 fps stream: correct epoch → video on the pad; epoch 0 → no
> video. Video and input are both confirmed working.
>
> **The "invariant" below is wrong and cost this project its entire search
> direction:** the pad keeps emitting ~22-43 resync/s *while it is displaying
> video correctly*. Resync rate does not measure rejection. Console rate measured
> as 3/300 s simply reflects a pad that had one early hiccup, not a validity
> signal. Do not score anything by resync rate.

One page to start the next session from. Everything below is measured on the operator's real
GamePad (40:d2:8a:17:e2:09 / 192.168.1.11) from this host as the impersonated console
(192.168.1.10), or read out of a decrypted real console↔pad session
(`capture/console-truth.pcap` → `out/evidence/truth/`).

**The invariant that frames everything:** the pad requests keyframes at **~60/s whenever it
is armed and awake**, and at **~0/s when it is unarmed or asleep**. A real console session
gets **3 requests in 300 s**. So "resync 0" is only meaningful when the arming oracle says
the pad is armed — otherwise it is just the pad ignoring video. Every earlier "quiet"
measurement that did not record arming was void.

Arming oracle: `svc 5/0x15` (brightness read) returns **error 9004** until the pad's
managers are armed, **err=0** after (`research/rce-hunt/10-tv-remote-live.md` §6/§8). Use it
before scoring any run. State oracle: `svc 4/0x05` → 12 = Quick Start Menu, 0 = "connecting",
3 = observed once at ~47 s.

## Ruled out — each with the measurement that kills it

| Candidate | How it was tested | Result |
|---|---|---|
| H.264 payload / encoder | two audits + `tests/agent-chunk-audit.py`; console-vs-ours chunk census | decodes 854x480 from the first IDR, 0 errors, both; see `research/ENCODER-VERDICT.md` |
| VSTRM header (seq packing, flags, ext options, length, timestamp) | census of all 73,500 console datagrams | **byte-for-byte identical**; the repo's "4+6 bit sequence" claim was an error, now withdrawn |
| Payload ceiling / chunking / 5 chunk-ends per frame | wire census both sides | identical (1694 B cap, 5x6 MB rows) |
| Beacon / association tags | hostapd's own beacon hexdump vs the decrypted console beacon | identical: RSN Nintendo OUI, HT cap 0x001c, A-MPDU 0x19, RIFS, **no** Ext-Cap IE, console's Broadcom vendor IE |
| Link delivery (aggregation, RTS/CTS, rate) | measured console delivery (98.2 % single MPDU, RTS/CTS on 98.6 %) then applied `iwlwifi 11n_disable=2` + `rts_threshold=0` | resync unchanged at 61/s |
| Media clock source | monitor-vif radiotap TSFT gives the real phy TSF (731 s / 296 s / 12 s at different moments; hostapd age claimed 4574 s → my earlier offsets were wrong) | clock can now be correct; behaviour unchanged |
| Media clock *value* | epoch-derived, 0, hostapd-age, AP-TSF | 32–53/s in all cases; not the lever |
| Format message (bytes 4–7, 5 ms lead, cadence) | console-exact values implemented | unchanged |
| 50025→50125 96-byte table at 1 Hz | implemented from the capture | unchanged |
| `init` flag placement | first frame only (console behaviour) | unchanged |
| IDR policy / storm | 15.3 IDR/s → 1 IDR/s, 3.29 → 0.59 Mbps | unchanged |
| UVC/UAC timing | console's 56-byte query at 1/s with byte[0] flip | unchanged (and console's own starts *after* video, so it gates camera/mic) |
| Arm burst alone | `svc 5/0x02` (102 zero bytes) + `0/0x00`, `4/0x04`, `5/0x06` | moves state 12→0 and clears 9004; video still refused |
| Time-command value | console sends `days=61348` (not days-since-2000); now sent verbatim | 41/s vs 53–61/s — suggestive, unproven |
| Session lifecycle | pad re-arms needed every ~80 s (measured resets); `ArmSession`+`ResetVideoStream` on rejoin | unchanged |
| 779-fragment `svc 0/0x11` state push + tail | implemented in the streamer (`session-push.cpp`), replayed per session at 29 dgram/s | 60/s in the only valid window |
| **The console's own recorded media** | replayed while armed | **rejected at 31–41/s** — the strongest single fact in this file |

## Not yet tested (the remaining frontier)

1. **Moving content / degenerate chunks.** Our P-frame chunks are 1–2 bytes on a static
   desktop (46 % of chunks); the console never goes below 395 B. Cheap test: play video
   fullscreen on Kali while streaming. See `research/ENCODER-VERDICT.md` §4.
2. **`svc 5/0x08` payload `01`** (display enable — the docs say `00` disables video; we have
   never sent either). Scripted in `run/sweep-gate.sh` with the `5/0x15` oracle.
3. **The terminator trio alone** (`0/0x12` carrying the 0x30b count, `4/0x21`, `4/0x1a`
   flags 0x42) without the preceding push, and `svc 5/0x0c` / `0/0x10` one-offs.
4. **The pad's own state machine**, which is the only oracle left that we cannot emulate:
   the pad's radio/firmware side (`research/BOOT-AND-MODES.md`), the UART-boot path, or
   `melonpad`-style firmware work.

## Method rules learned the hard way (violate these and the run is void)

1. Score arming (`5/0x15`) in the same run as the media measurement.
2. Never score a window in which the pad's input rate is falling — it is going to sleep.
3. One hardware owner at a time: `SO_REUSEADDR` hides a second binder on port 50023 and two
   sessions will deauthenticate the pad under each other.
4. Check `netboot` reports **no** "Can not bind" — a failed unicast socket leaves the pad
   looping on DHCP (observed: 204 requests, no input, no replies).
5. iwlwifi LAR can wedge to `no IR` on every 5 GHz channel; `drc-up.sh` will not clear it.
   Reload `iwlmvm`/`iwlwifi` and force a scan with the idle supplicant.
