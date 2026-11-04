# SETUP — runbook

## Where the project stands (verified 2026-11-03)

| Stage | Status | Evidence |
|---|---|---|
| Protocol/pairing understood | **done** | `RESEARCH.md`, sourced from libdrc.org + wiiubrew + drc-hostap source |
| Patched mac80211 (TSF) for Kali 7.1.5 | **built** | `kernel/.../mac80211.ko`, vermagic `7.1.5+kali-amd64`, `dev_attr_tsf` + `tsf_show` present |
| TSF patch as a portable patch file | **done** | `kernel/tsf-kali-7.1.5.patch`, 5 hunks, re-applies cleanly |
| hostapd with CONFIG_TENDONIN | **built + runs** | `hostapd v2.1-devel`, Nintendo OUI bytes `a4 c0 e1` present in binary |
| wpa_supplicant / wpa_cli (WPS PIN) | **built + runs** | `v2.1-devel` |
| netboot DHCP | **built** | 22 KB binary |
| drc-x264 (patched) + libdrc | **built** | `libx264.so.140`, `libdrc.so` with correct `DT_NEEDED` |
| drcvncclient | **built + runs** | reaches libdrc's streamer, fails only with no GamePad |
| Display half proven over VNC | **done** | captured `:0` at 848x480 over RFB — 6292 distinct colours |
| GamePad actually joins / screen on GamePad | **BLOCKED** | needs the 5 GHz dongle + root |
| GamePad input driving Kali | **BLOCKED** | same |

Blockers: **(a) no 5 GHz USB dongle is attached** (`lsusb` shows none; the earlier
`-71` enumeration failures were the Logitech keyboard replugging), and **(b) sudo
requires a password**, which approval-disabled sessions cannot supply.

## Preconditions

1. A 5 GHz USB Wi-Fi dongle whose driver implements `.get_tsf`:
   **rt2800usb / RT5572** (documented working) or ath9k. **Not** iwlwifi.
2. Root.
3. A Wii U console (for the easy pairing route) or willingness to use direct pairing.

## Execution order

```bash
cd /home/kali/Wiiu/run
chmod +x *.sh

# 0. identify the radio; confirm it is not iwlwifi
lsusb; ip -br link
iw dev            # expect a new wlanX

# 1. load the patched mac80211 -> /sys/class/net/<iface>/tsf
sudo ./01-load-tsf.sh wlan1        # expect: "PASS: TSF is advancing"

# 2. pair, capture PSK (console in pairing mode, SYNC twice)
sudo ./02-pair.sh wlan1            # writes run/pairing.env

# 3. raise the DRC AP + DHCP -> GamePad at 192.168.1.11
sudo ./03-ap.sh                    # CHANNEL=165 sudo ./03-ap.sh if it won't join

# 4. Kali desktop -> GamePad
./04-stream.sh
```

Every step prints an explicit PASS/FAIL gate. Evidence for a working setup is:
`01` prints `PASS: TSF is advancing`; `03` prints `GamePad associated: <mac>` and
`PASS: GamePad answers at 192.168.1.11`; `04` puts the desktop on the GamePad LCD
and the touchscreen moves the pointer.

## Runtime library path

Binaries were built in Ubuntu 20.04 and run on Kali, so the focal ffmpeg sonames are
bundled:

```bash
export LD_LIBRARY_PATH=/home/kali/Wiiu/out/libs:/home/kali/Wiiu/out/libdrc/lib:/home/kali/Wiiu/out/x264/lib
```

`04-stream.sh` should export this itself (check before first run).

## Known constraints and tuning knobs

- **Resolution.** `drcvncclient` upstream required an 854x480 VNC source and
  segfaulted otherwise. It is patched here to follow the server's real size, because
  `x11vnc` rounds scaled widths to a multiple of 4 and therefore yields **848x480**
  from a 1024-line screen — never 854. Both the SDL path and the touch→pointer
  mapping now use the actual dimensions.
- **Channel.** Template defaults to 36 (safe, UNII-1). pc2drc's working config used
  165 (UNII-3, not legal everywhere). If the GamePad refuses to associate, try the
  channel the console actually used.
- **BSSID.** WPS credentials carry an SSID *and* a BSSID. `03-ap.sh` derives the SSID
  as `WiiU<console-mac-hex>` from the pairing AP's name. If the GamePad still won't
  join, pin the interface MAC to the console's MAC so the BSSID matches too
  (`ip link set dev wlan1 address <console-mac>` before hostapd starts) — this is the
  most likely single tuning step needed.
- **The Wi-Fi uplink goes down** during `01`, because mac80211 is one shared module
  and the stock one must be replaced. The patched `.ko` is insmod'ed from
  `kernel/`, never installed into `/lib/modules`, so a reboot always restores stock.
- **Secure Boot is off, lockdown is `[none]`** on this host, so the unsigned module
  will load.

---

## Round 2 additions (2026-11-03): hardware-free validation + a way past the dongle

### The video path is proven end-to-end, without a GamePad

`tests/run-tests.sh` (no root, no hardware) now covers:

| Check | Result |
|---|---|
| TSF clock source | synthetic fallback PASS (hardware node absent) |
| libdrc DRH chunking contract | **12/12 frames → exactly 5 chunks** |
| GamePad-format stream decodes | **ffmpeg: 60 frames, zero errors, 854x480** |

Two details worth recording:

- `b_drh_mode` is genuinely in the x264 we built (`x264.h`: *"Compatibility mode for
  Wii U Gamepad video encoding"*; `encoder.c` has the 6-MB-row chunking emulation) and
  libdrc sets `param.b_drh_mode = 1`. At 480p there are 30 macroblock rows, so
  6 rows/chunk = **5 chunks/frame**, which matches `kH264ChunksPerFrame = 5` and the
  300 slice NALs / 60 frames measured on the wire.
- The chunk payloads are **not** standalone slices — `b_drh_mode` only emits through
  the `nalu_process` callback, and libdrc re-frames them (`DumpH264Frame`) as one NAL
  per frame behind a synthetic 4-byte header with the frame number baked in. Enabling
  libdrc's own `kDebugDumpToFile` produced a stream ffprobe reads as **High profile,
  854x480, yuv420p, level 3.2**, decoding with zero errors and luma within
  **mean |err| = 1.03** of the encoder input at CQP 32. So the encoder, the patched
  x264, and libdrc's framing are all correct.

### The dongle is no longer strictly required

`GetTsf` used to hard-fail without the patched-mac80211 sysfs node. It now has a
`DRC_SYNTHETIC_TSF=1` fallback that substitutes the monotonic clock in microseconds:

```
DRC_SYNTHETIC_TSF=1 ./out/bin/encoder_test tsf
  [tsf] 8 -> 250089  (delta 250081 us over ~250000 us)   PASS
```

Consequence: the AP can run on **any** 5 GHz AP-capable radio, including the built-in
**iwlwifi AX210**, because `get_tsf` was the only driver feature we needed. The
uncertainty is behavioural, not mechanical: the GamePad schedules playback against the
AP's real TSF carried in beacons, so a synthetic epoch may cause frames to be played
early/late or stall. Treat it as the experiment to try first if no RT5572 is on hand —
it costs one environment variable, and `01-load-tsf.sh` / the kernel patch remain the
guaranteed path.

---

## Round 3 additions

**`run/05-diagnose.sh`** - answers "is the GamePad actually talking DRC, or just
associated?". Ping proves nothing; the DRC link is live when the pad sends on
`50122 -> 50022` (input stream). The script lists associated stations, checks ARP/ICMP,
captures UDP for `DUR` seconds and summarises the observed flows against the port map
in `RESEARCH.md` §6. This is the gate to run when the AP comes up but nothing streams.

**`01-load-tsf.sh` now rolls back automatically.** It discovers dependents generically
via `/sys/module/mac80211/holders` (on this host that is `iwlmvm`; `cfg80211` is a
*dependency*, so it stays loaded and disruption is minimal), unloads depth-first, and
on any failure re-inserts the stock `mac80211` and the recorded driver modules. A
failed load can no longer leave the machine without Wi-Fi.

**AP MAC pinning.** `03-ap.sh` now creates a virtual `__ap` interface (`WiiUAP`) and
optionally pins its MAC to the console's MAC, because the GamePad learns an SSID *and*
a BSSID during WPS pairing and may refuse an AP presenting a different BSSID.
`02-pair.sh` records `CONSOLE_MAC` in `run/pairing.env` for this. Disable with
`PIN_MAC=0`.

Tests: `tests/run-tests.sh` is now **6/6**, adding the vstrm/cmd round-trip suite.

---

## Raspberry Pi 5 (Kali aarch64) — build and radio findings

Target: `kali@192.168.86.28`, Kali 2026 arm64, kernel `6.12.34+rpt-rpi-2712`,
Cortex-A76 x4, 8 GB. `sudo` is NOPASSWD. Sources at `~/wiiu-work`.

**The whole stack builds natively on aarch64** (gcc-12, no container): hostapd,
wpa_supplicant, wpa_cli, netboot, drc-x264 (shared), libdrc, drcvncclient — all
verified as `ELF 64-bit ARM aarch64`. Three things had to be fixed for this:

1. **OpenSSL 1.0.1u must be built SERIALLY.** `make -j4` races the `ar` step and
   produces a `libcrypto.a` missing `objects/obj_dat.o`, which shows up much later as
   `undefined reference to OBJ_obj2nid` when linking hostapd. Use
   `make build_libs` with no `-j`, then confirm `ar t libcrypto.a | grep obj_dat.o`.
2. **`LDFLAGS` is expanded BEFORE the objects** in hostapd/wpa_supplicant
   (`$(LDO) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)`), so static OpenSSL must go in `LIBS`,
   wrapped in `-Wl,--start-group -lssl -lcrypto -Wl,--end-group`.
3. **libdrc needs `<cstddef>`/`<cstdio>`** in its headers/sources; gcc-12 rejects them
   where the container's gcc 9 tolerated the transitive includes. Patched.

**Radio: the Pi 5's brcmfmac can do a 5 GHz AP, but not while also being the uplink.**

- `wlan0` (CYW43455, brcmfmac, nexmon fw) advertises `* AP` and Band 2 with 30
  channels; country CA, ch36 legal at 20 dBm.
- brcmfmac advertises APSTA: `#{ managed } <= 1, #{ AP } <= 1, #channels <= 1`, so AP
  and STA must share one channel. The uplink sits on **ch149**.
- With `interface add wlanAP type __ap`, hostapd reaches `AP-ENABLED` on 5745 MHz and
  the STA link survives — **but beacons fail** (`Beacon set failed: -100`, then
  persistent single failure) and the SSID never appears in an air scan from another
  station. The AP is enabled without actually transmitting.
- Giving the vif its **own MAC** (not wlan0's) is required, otherwise beacons fail
  outright; and the vif must be removed with **`iw dev wlanAP del`** — `ip link del`
  leaves it registered, and the leftover state returns `-16 EBUSY` /
  `Register frame ... Operation already in progress` on the next attempt.

**Conclusion: dedicate a radio to the DRC AP.** Either plug Ethernet into `eth0`
(present, currently no carrier) to free `wlan0` entirely, or use a USB 5 GHz
adapter. Do not try to share the Pi's single radio between the uplink and the DRC AP.

### Unattended radio self-tests (no Ethernet needed)

Because taking `wlan0` over kills SSH, the Pi tests are **fire-and-forget**: each
script logs to a file, always restores networking via an EXIT trap plus a hard timer,
then POSTs its log to a receiver on Kali (`run/report-receiver.py`, port 8899). The
result survives the outage.

Scripts: `run/pi-radio-selftest.sh`, `run/pi-ap-wlandown.sh`, `run/pi-ap-downonly.sh`.

**Result: the Pi 5's built-in radio cannot serve a working AP.**

hostapd's own output every time:

```
wlan0: Could not connect to kernel driver
Failed to set beacon parameters
wlan0: AP-ENABLED
wlan0: Could not connect to kernel driver
```

It reaches AP-ENABLED but **never sets beacon parameters and nothing appears on air**
(air scan from Kali never sees the SSID; `tx_packets` does not grow). Verified across
ch149 and ch36, HT20 and pure 11a, as a vif with its own MAC, and with `wlan0` taken
down-then-up or left down for hostapd to raise — all the same failure.

Causes and constraints found:

- `brcmfmac` here is the **nexmon DKMS module** (`6.12.2-nexmon`, firmware
  `nexmon.org 2.2.2`) — a monitor-mode-oriented fork, not the stock driver.
- **No stock `brcmfmac.ko` exists** in this kernel package, so removing nexmon with no
  Ethernet cable would leave the Pi with no network at all. Not safe to attempt.
- After `ip link set wlan0 down`, `ip link set wlan0 up` does **not** bring brcmfmac
  back (stays `DOWN <NO-CARRIER>`). Only a NetworkManager restart re-initialises it.
  That is why the down/up variants fail even before hostapd runs.
- A monitor vif cannot be created on this driver, so we cannot self-sniff beacons.
- hostapd's stdout is block-buffered when redirected, so 10 s-after-start liveness
  greps under-report; read the log after the process exits instead.

**Conclusion: use a USB 5 GHz adapter for the DRC AP.** This Pi already has
`88XXau.ko` (RTL8812AU) and `8814au.ko` DKMS drivers installed, so a Realtek dongle
should work immediately — with `DRC_SYNTHETIC_TSF=1`, since those have no `get_tsf()`.
An RT5572 remains the only combination with a hardware TSF path.

---

### CORRECTION (supersedes the "cannot serve a working AP" conclusion above)

**The Pi 5 *can* serve a working 5 GHz AP.** The earlier failures were not a firmware
limitation — they were self-inflicted. Two preconditions, both now known:

1. **`wlan0` must not be the uplink.** With `wlan0` (brcmfmac, 5 GHz) carrying the
   network connection, hostapd reaches `AP-ENABLED` but beaconing fails. Connect a
   **second** adapter and let it be the uplink:
   `0bda:f179 Realtek RTL8188FU` → `rtl8xxxu` → `wlan1` works (2.4 GHz is fine for the
   uplink; it cannot host the DRC AP itself).
2. **Never bounce the link.** `ip link set wlan0 down` then `up` leaves brcmfmac
   `DOWN <NO-CARRIER>` permanently; only a NetworkManager restart recovers it, and
   hostapd runs attempted afterwards fail with `Could not connect to kernel driver`
   and `Failed to set beacon parameters`. Detach from NM with `managed no` and leave
   the interface up.

With those two conditions met, verified live:

```
sudo nmcli dev set wlan0 managed no
sudo ip link set wlan0 up
sudo hostapd /tmp/ap-live.conf           # interface=wlan0, hw_mode=a, channel=149, HT20

  wlan0: AP-ENABLED
  (no beacon errors, no driver errors, tx_packets climbing)

scan from another station:
  B8:27:EB:74:F2:6C  DRC-RF-TEST  Infra  5 GHz  149  1170 Mbit/s  90  WPA2
```

So the DRC radio layer is solved on the Pi 5 with no purchase. Remaining work is
pairing (needs the GamePad) and the video/input stream.

Note: `run/03-ap.sh` has been corrected to stop bouncing the interface.

---

## Round 4: WPS pairing SUCCEEDED — and the real remaining blocker

**We obtained the console's real credentials.** The GamePad was put in Settings->SYNC
(pairing mode); the console was in pairing mode showing symbols on the TV
(♥♦♦♥ = digits 1221, suffix hardcoded 5678 => PIN **12215678**). Running the *patched*
`wpa_supplicant` as a WPS client against the console's pairing AP completed Nintendo's
modified handshake (KDK rotated 3 bytes left, the step a stock supplicant fails at M2)
and the console handed over:

```
CONSOLE_SSID=WiiUccfb65b68169
PSK=<redacted-psk>
```

Saved in `pairing.env`. This is the one secret that cannot be sniffed (the console
generates the PSK randomly and ships it inside the encrypted WPS credential) and
cannot be derived from the PIN — so obtaining it was the crux of the whole project.

Other hard-won findings this round:

- The console's pairing AP is **hidden** (no SSID in beacons). It is found as the
  BSSID equal to the console's Wi-Fi MAC (`cc:fb:65:b6:81:69`, derived from
  `WiiUccfb65b68169`) on **5200 MHz / ch40**. Grepping scans for "WiiU" finds nothing.
- `hostapd` must be invoked by **full path** (`~/wiiu-work/pc2drc/drc-hostap/hostapd/hostapd`).
  A bare `hostapd` runs `/usr/sbin/hostapd` — the stock binary — which silently has no
  Nintendo selectors.
- `CONFIG_TENDONIN` does activate correctly; verify it by searching the binary for the
  **little-endian u32** `0xa4c0e104` / `0xa4c0e102`, not the byte string `a4 c0 e1`
  (RSN selectors are u32 constants, not arrays).
- A wedged brcmfmac (after failed mode changes) refuses both AP mode and vif creation
  with `-16 EBUSY`; **`modprobe -r brcmfmac && modprobe brcmfmac` clears it** — and
  after enough cycles the chip stops answering entirely
  (`brcm_attach: dongle is not responding: err=-84`), which needs a **power cycle**.

**The remaining blocker: the kernel rejects Nintendo's cipher selectors.**

With `CONFIG_TENDONIN` active, hostapd tries to advertise `a4:c0:e1` for the CCMP and
PSK selectors, and beacon/key setup fails:

```
nl80211: set_key failed; err=-22 (Invalid argument)
Beacon set failed: -22 (Invalid argument)
```

`-22 EINVAL` — Linux does not accept cipher OUIs it doesn't know. Before the rebuild
actually enabled `CONFIG_TENDONIN`, the AP beaconed perfectly (SSID visible on air,
tx climbing) precisely because it was using standard CCMP — which the GamePad will
never accept. So:

**Next step: patch the Pi's mac80211 (6.12.34+rpt-rpi-2712) to accept the Nintendo
cipher selectors**, the same way the original `drc-mac80211` does. Our Kali port only
carried the TSF export; the cipher-relaxation part is missing. Approach is proven:
fetch `linux-source-6.12`, add the `iface.c` TSF block plus cipher acceptance, build
`net/mac80211` out-of-tree against the Pi's kernel headers (already installed).

### Round 5: the AP now genuinely broadcasts — but the pad still won't join

With the console's real SSID+PSK on a **standard-WPA2** AP (stock hostapd), the beacon
finally went out and was confirmed from another station:

```
WiiUccfb65b68169   B8:27:EB:74:F2:6C   5 GHz   ch36   signal 79
```

No association from `40:d2:8a:17:e2:09`. So the missing ingredient is the
**Nintendo cipher selectors**, exactly as libdrc's note implies: the GamePad has the
network stored as `a4:c0:e1` and will not join an AP advertising standard CCMP.

And with `CONFIG_TENDONIN` active (which is what puts `a4:c0:e1` on the air), brcmfmac
refuses the beacon:

```
nl80211: set_key failed; err=-22 (Invalid argument)
Beacon set failed: -22 (Invalid argument)
```

`set_beacon` is handled by the **firmware** on brcmfmac (note
`Setup AP(wlan0) - device_ap_sme=1 use_monitor=1`), and the CYW43455 firmware does not
recognise `a4:c0:e1`. On `rt2800usb` the beacon is built in mac80211/driver rather than
validated by a closed firmware, which is why libdrc's documented hardware is RT5572.

**Conclusion: the Pi 5's built-in radio cannot impersonate the console's AP.** Not a
config problem — a firmware limitation. Options:
  1. **RT5572 USB adapter** (rt2800usb) - the documented working hardware, where the
     Nintendo OUI can actually be transmitted. Recommended.
  2. Patch the Pi kernel's cfg80211/mac80211 to accept the Nintendo OUIs - worth trying,
     but pointless if the firmware rejects the beacon.
  3. Keep experimenting with brcmfmac AP-mode quirks (it also needs
     `modprobe -r/+ brcmfmac` after failed mode changes, and a power cycle after
     enough of them: `brcm_attach: dongle is not responding: err=-84`).

### Round 6: PROVEN — the Pi's built-in radio cannot impersonate the console

dmesg gives the answer explicitly when hostapd (configured with the Nintendo cipher
selectors via CONFIG_TENDONIN) tries to start the AP:

```
ieee80211 phy3: brcmf_configure_wpaie: ivalid OUI
ieee80211 phy3: brcmf_cfg80211_start_ap: brcmf_parse_configure_security error
```

The **CYW43455 firmware refuses `a4:c0:e1`**. `start_ap` fails, so no beacons are ever
transmitted - which is exactly the "type=AP, hostapd running, beaconErr=0, but invisible
on air and `iw station dump` empty" behaviour seen repeatedly. Not a config bug, not
driver-state corruption (that was a separate, real issue: `modprobe -r/+ brcmfmac`
clears `-16 EBUSY`, and a power cycle clears `dongle is not responding: err=-84`).

Meanwhile the same radio **does** serve a perfectly good AP with standard ciphers
(beacon visible from another station, group key installed, SSID on air) - but the
GamePad has the network stored with Nintendo selectors and will not join standard CCMP.

So on brcmfmac the two requirements are mutually exclusive:
  * standard ciphers -> AP works, pad refuses
  * Nintendo ciphers -> firmware refuses (invalid OUI), AP never comes up

**This is why libdrc's documented hardware is RT5572/rt2800usb**: there the beacon is
assembled in mac80211/driver rather than validated by closed firmware, so the Nintendo
OUI can actually be transmitted. An RT5572 USB adapter is the remaining dependency.

Also fixed along the way (keep these):
  * `wlan0` kept getting reclaimed by NetworkManager, silently knocking the AP down.
    Make it permanent: /etc/NetworkManager/conf.d/99-wlan0-unmanaged.conf
    with `[keyfile]` + `unmanaged-devices=interface-name:wlan0`, then restart NM.
    The dongle (wlan1) stays managed and keeps the uplink/SSH alive.

### Round 7: driver patched - the OUI barrier is GONE; the pad now reaches us

`brcmfmac` is a **DKMS out-of-tree module** here (`/usr/src/brcmfmac-nexmon-6.12.2`),
so it is patchable without touching the kernel. `brcmf_valid_wpa_oui()` only accepted
`00:0f:ac` (RSN) / `00:50:f2` (WPA). Added `a4:c0:e1` to the accepted set (the trailing
suite bytes 4=CCMP and 2=PSK are already standard values). Rebuilt with
`dkms build/install -m brcmfmac-nexmon -v 6.12.2 --force`.

**Result: `brcm_configure_wpaie: ivalid OUI` is gone**, and with the Nintendo selectors
plus the console's MAC the AP comes up and is visible from another station:

```
WiiUccfb65b68169   CC:FB:65:B6:81:69   ch36   signal 90
```

The GamePad now **engages** - hostapd logs it repeatedly:

```
wlan0: STA 40:d2:8a:17:e2:09 IEEE 802.11: disassociated
Disassociation notification for unknown STA 40:d2:8a:17:e2:09
nl80211: Drv Event 20 (NL80211_CMD_DEL_STATION) received
```

but it is dropped during association, **by the firmware** (`CMD_DEL_STATION` comes from
the driver/firmware, and there is no EAPOL/4-way activity at all). Note hostapd reports
`Setup AP(wlan0) - device_ap_sme=1 use_monitor=1`: on brcmfmac the *firmware* handles
association, so the pad's own RSN IE (also carrying `a4:c0:e1`) is parsed inside the
closed firmware, which is not patchable from the driver.

Tested and ruled out:
  * standard CCMP + console SSID + console BSSID + real PSK -> pad does not even attempt
  * Nintendo selectors + Pi MAC -> pad reaches us but is dropped (same as above)
  * Nintendo selectors + console MAC -> ditto

Remaining options, in order:
  1. **RT5572 (rt2800usb)** - association and beaconing are done in mac80211, not closed
     firmware, so the Nintendo OUI is never handed to a black box. This is libdrc's
     documented hardware and remains the reliable finish.
  2. Go after `device_ap_sme` at the mac80211 level so hostapd handles association in
     userspace, bypassing the firmware's OUI check. Deeper kernel work, uncertain payoff.

Useful leftovers: set the AP MAC to the console's owns every time (`cc:fb:65:b6:81:69`) -
that is what finally made the pad take our AP seriously. Also keep
`/etc/NetworkManager/conf.d/99-wlan0-unmanaged.conf` so NM stops reclaiming wlan0.

### Round 8: option 2 (userspace AP SME) explored and exhausted

Removing firmware AP SME looked promising - and all three driver patches applied and
built cleanly - but each one exposed the next firmware limit:

1. **OUI acceptance** (`brcmf_valid_wpa_oui` +`a4:c0:e1`) - WORKS. `ivalid OUI` gone,
   AP beacons with Nintendo selectors and the console's MAC, visible on air at 95+.
2. **Drop `WIPHY_FLAG_HAVE_AP_SME`** - WORKS. hostapd then reports
   `Setup AP(wlan0) - device_ap_sme=0` and creates `mon.wlan0` (this needed patch 3).
3. **Add MONITOR to the AP interface combination** (it previously existed only in the
   combo *without* AP, so `cfg80211_check_combinations()` returned -EBUSY) - WORKS:
   `New interface mon.wlan0 created: ifindex=10`, `AP-ENABLED=1`.

...and then the firmware refuses to enter monitor mode:

```
brcmf_net_mon_stop: BRCMF_C_SET_MONITOR error (-5)
```

`mon.wlan0` disappears, tx stops, nothing beacons. Userspace AP SME *requires* a
monitor vif to receive auth/assoc frames, and this firmware cannot provide it.

So both paths are closed at the firmware boundary:
  * firmware AP SME  -> firmware parses the pad's assoc request and rejects a4:c0:e1
  * userspace AP SME -> needs monitor mode, firmware returns -5

**Driver state left on the Pi**: pristine nexmon source restored except patch 1 (the OUI
acceptance, harmless and useful), rebuilt and installed. `HAVE_AP_SME` and the interface
combination are back to stock so ordinary AP mode still works. wlan0 MAC restored,
`/etc/NetworkManager/conf.d/99-wlan0-unmanaged.conf` retained.

**Recommendation stands: RT5572 (rt2800usb).** There, association is done in mac80211 -
no closed firmware anywhere in the path - so the Nintendo OUI is never handed to a black
box. Patches 1-3 above are ready to re-apply if ever useful; they are in /tmp/patch_*.py
on the Pi and documented here.

---

## Round 9: web research round — the stack has a live successor, and one plan item was wrong

Full detail with citations: `research/WEB-RESEARCH.md`. Three things that change
the plan:

**1. "Patch mac80211 to accept Nintendo's cipher selectors" (round 4) is not
needed.** `drc-hostap` maps `WPA_ALG_CCMP` to the *standard*
`WLAN_CIPHER_SUITE_CCMP` in `driver_nl80211.c:2529`, so the kernel never sees
`a4:c0:e1`; the Nintendo OUI lives only in userspace-built RSN IEs, which
`CONFIG_TENDONIN` both emits and parses. The `-22` on the Pi was brcmfmac's
firmware, not mac80211. `pc2drc`'s own kernel patch set confirms it: TSF + one
`rx.c` line, no cipher work.

**2. The 2013 hostapd container is obsolete.** `vanilla-wiiu/drc-hostap` is
hostap **2.12** with `CONFIG_TENDONIN`, and it builds natively on Kali with gcc 16
+ OpenSSL 3, no root:

```
build/build-hostap-2.12-native.sh      # verified 2026-11-03
hostapd v2.12, wpa_supplicant v2.12, wpa_cli   (selectors 0xa4c0e104 present)
```

Dev headers come from `apt-get download` + `dpkg-deb -x`; only tweak is dropping
libssl-dev's static archives so the shared `libcrypto.so.3` is linked. Its HEAD
`a2f705d` is the exact revision **Barista** pins.

**3. There is an actively developed project that already does the goal.**
[`BetaZay/Barista`](https://github.com/BetaZay/Barista) (pushed 2026-10-31,
v0.1): pairs a real GamePad **without a console**, streams video+audio, mirrors a
monitor or window on X11 **and** Wayland, uses sticks/buttons as mouse+keyboard,
ships a **GamePad touch keyboard**, and offers `uinput` controller mode. It
derives the playback clock from **monitor-mode radiotap TSF** instead of the
patched-mac80211 sysfs node — which is why it works on `rtw88`/`rtw89` and needs
**no kernel patch at all**. Tested on RTL8852BE and TP-Link Nano AC600
(`rtw_8821au`). Caveat: packages target Ubuntu 24.04 / Fedora / Arch, not Kali,
and it is alpha-quality.

Also worth importing if we keep our stack: `wozt/libdrc` (unannounced fork,
2026-09) fixes the freeze — libdrc encodes with x264 preset `slow`, the pad then
requests a keyframe on *every* frame and the picture dies in seconds; preset
`medium`, rate-limited keyframes, real IDR via encoder restart and paced
transmission are the fix. Barista's `third_party/hostapd-drc/patches/` (15
patches) documents key-install retries/deferrals for exactly the association
failures seen in rounds 7-8; it is not drop-in (7/15 apply on our tree), but it
is the best reference available.

**Cheapest next experiment, no purchase:** put Ethernet in, free `wlan0` (AX210 —
AP-capable, no AP_SME flag, no `.get_tsf`), run `run/03-ap.sh` with
`DRC_SYNTHETIC_TSF=1`. That answers the one open question that costs money:
whether a modern firmware accepts `a4:c0:e1` in a beacon. Then `run/05-diagnose.sh`.

---

## Round 10: onboard uplink restored (networking fix, 2026-11-04)

The "networking is fucked" state was two leftovers from the capture rounds, not a
broken radio:

1. `run/capture5.sh` / `run/find-console-channel.sh` each free wlan0 with
   `nmcli dev set wlan0 managed no` and restore it at exit — but the *persistent*
   `/etc/NetworkManager/conf.d/99-wlan0-unmanaged.conf` (kept "just in case" in round 8)
   made that state permanent across reboots. NetworkManager never touched wlan0 again.
2. The `drc-uplink` profile pinned the whole uplink to the RTL8188FV dongle (2.4 GHz,
   1x1), so even a manually raised wlan0 had no reason to take traffic.

Fix applied: conf renamed `99-wlan0-unmanaged.conf.disabled` (`.bak` kept), wlan0 managed
and auto-connected via the existing `Sir Connects A Lot` profile (pinned to wlan0,
route metric 100), `drc-uplink` kept as fallback pinned to wlan1 (metric 700).
Result: 5745 MHz / 80 MHz VHT / 2x2, 526 Mbit rx, default route on wlan0, internet verified.
Evidence: `out/evidence/netfix-2026-11-04.log`.

Correction to the round-8 note: iwlwifi LAR does **not** mark all 5 GHz no-IR — with a
5 GHz association up, UNII-3 (ch149-165) is `IR` and only ch36-48 stay `no IR`. The phy
also advertises STA+AP concurrency (`#{managed}<=1`, `#{AP}<=1`, `#channels<=1`), so a
DRC AP on the onboard card is testable on ch149 while the uplink stays associated.
No USB radio is needed for that experiment any more.

---

## Round 10: codec/transport measured, and the streamer defects fixed

Full detail: `research/CODEC-SPEC.md`; raw numbers: `research/codec-measurements.txt`.

**Measured on this host (no GamePad, no radio), 864x480 @ QP32 @ 59.94 fps:**

| Content | B/frame | kbps |
|---|---:|---:|
| idle Kali desktop (`:0`) | 590–693 (IDR 17.8 kB) | 0.29 |
| moving content (testsrc2) | 5,665 | 2.7 |
| every frame forced to IDR | 17,844 | **8.6** |

PCM audio is uncompressed: **1.54 Mbps flat**, ~45 % of the media budget.
Real console media = 611 VSTRM packets/s (10.2 per frame), 1694 B max payload.

**The freeze explained and quantified:** the GamePad sends `01 00 00 00` once per
frame *even when the picture is perfect* — it is a heartbeat. libdrc treats each
one as a keyframe demand, so every frame becomes an IDR: 0.29 → 8.6 Mbps, which
cannot fit the link, so more loss and more requests. Also, `subme` 7 → 8 is the
exact cliff (medium is fine, `slow` is not).

**Fixed here** (`research/patches/0001-paced-sender-and-idr-policy.patch`):
in-frame pacing over the console's 0/3/6/9/11 ms windows, encoding moved off the
frame-timer thread onto a dedicated sender, heartbeat debounce plus a proactive
60-frame IDR, and a format-only slot after every IDR. Verified without hardware:
clean build in `drcbuild:20.04` (-Wall -Wextra, 0 warnings), 26/26 scheduler
assertions, streamer smoke test PASS with **10.0 datagrams/frame** (console:
10.2) and `Stop()` in 6 ms, suite **8/8**.

Still unverified without a pad: whether the pad accepts our stream end to end,
the true meaning of the heartbeat, and glass-to-glass latency (nobody publishes
a figure).

### Round 10 addendum: streaming research + a bug that explains "random disconnects"

Three delegated passes over the public record (`research/STREAMING-TO-PAD.md`):

- **Our numbers are corroborated.** wozt/bottom_screen reports 60 fps, 492 pkt/s,
  **2.76 Mbit/s**, 0 keyframe requests on real hardware. Our moving-content
  measurement is **2.7 Mbps** and **10.0 datagrams/frame** vs the console's 10.2.
- **`wozt/capture2cloud`'s `drc_player` accepts arbitrary RGBA 864x480 on stdin** —
  a hardware-proven generic pipe into the pad, i.e. our streamer plus a capture
  source is a complete path.
- **Toolchain we should adopt:** `research/barista-ref/scripts/capture-analysis/
  decrypt_capture.py` (the PTK-rot3 decryptor), `memahaxx/drc-wireshark-plugins`,
  or Wireshark 4.4's raw `tk` key with the *rotated* TK. No public DRC pcap exists.
- **Audio:** Barista delivers 48 kHz stereo PCM, but Desktop mode is video-only,
  and **the headphone jack cannot work** without UIC command 0x07 to reconfigure
  the amplifier — unimplemented everywhere.
- **No glass-to-glass latency has ever been published** for any PC→pad stack; the
  only measured figure is the stock console's ~33 ms (Digital Foundry).

**Fifth streamer defect found while testing the fix.** `UdpClient` used a
*blocking* socket, so one `sendto()` to a peer with a stale neighbour entry parked
the sender for **2.5 s**: 17 of 30 frames were superseded and `Stop()` blocked for
the same. With `O_NONBLOCK` (the `UdpServer` in the same file already did this):
300/300 datagrams sent, 0 superseded, `Stop()` 0 ms. On a real pad this is one
mechanism behind the reported "random disconnects" — a pad that disappears must
not be able to wedge the video thread.

End-to-end validation now in the suite (section 7): loopback capture → Barista
analyzer (**118/118 complete frames, zero protocol errors**, 57.96 fps, frame
median 16 706 µs, packet median 300 µs) → reconstruction → **ffmpeg `-xerror`
decode of High profile 854x480 with exit 0**. Suite is **9/9**.

---

## Round 11: five real defects found and fixed — input proven, video still rejected

Working end-to-end state reached again on 2026-11-04 (~03:19): pad associates to
`WiiUAP` (ch149, BSSID `cc:fb:65:b6:81:69`), completes the 4-way handshake,
DHCPs `192.168.1.11`, its **touch and buttons drive the Kali cursor**, and the
pad now emits its per-frame `01 00 00 00` messages to `50010` (~30-70/s) where
it was previously silent. Video is still not displayed: the pad stays on its
"could not connect" screen and sends **no media return traffic** to `50020`/
`50021`, so its AV pipeline never starts.

Evidence: `out/evidence/live-fmtfix-0313/` (`wire.txt`, pcaps, station dump).

### Defect 1 — vstrm ext-option order was not the console's
`libdrc` pre-filled the option bytes with `83 85 06` and appended the IDR/rate
options after them, so every packet went out as `83 85 06 [80] 82 00` — force-
decode first and the IDR marker in slot 3. The console's reference order is
`80 82 00 83 85 06 00 00` (IDR) / `82 00 83 85 06 00 00 00` (P).
Fixed in `pc2drc/.../src/vstrm-packet.cpp` by rebuilding bytes 8..15 in console
order (`NormalizeExtOptions()`), called from `SetIdrFlag`/`SetFrameRate`/
`SetPayload` so call order cannot break it. Verified on the wire.

### Defect 2 — an `iptables` DROP rule starved the pad of audio *and* the video-format message
A leftover `-A OUTPUT -p udp --dport 50121 -j DROP` rule was discarding the whole
audio/format service (93,064 packets / 120 MB counted). UDP 50121 is not "just
speech": it carries the 32-byte per-frame **video-format/timing message** the pad
uses as its playback timebase. With the port blocked the pad received no formats
at all and never asked for video. Rule removed; `run/drc-up.sh` now deletes it if
present and warns if 50121 egress is still blocked.

### Defect 3 — the format message body did not match the console
`GenerateAstrmPacket` emitted a 24-byte length field (`0x0018`), zeros in outer
bytes 4..7, and 16000 µs four times. The console sends length **0**, outer bytes
`11 11 81 08`, and clocks `16000, 16000, 21000, 21000`. Replaced with
`BuildVideoFormatPacket()` producing the datasheet's 32 bytes exactly. Verified:
`04 00 00 00 11 11 81 08 <ts LE> 80 3e 00 00 80 3e 00 00 08 52 00 00 08 52 00 00 00 00 00 00`.

### Defect 4 — the stream was VNC-driven, not 59.94 fps
Frames were pushed only when the VNC framebuffer changed, and the main loop
slept up to 500 ms in `WaitForMessage`, so the wire carried ~27 fps with gaps up
to 250 ms — nothing like the console's continuous 59.94 fps. Now the loop wakes
every 16 ms and pushes every iteration (the existing limiter caps at 59.94 fps),
so static content is re-sent as tiny P frames exactly like a console. Measured:
402-518 frames/10 s, median inter-frame gap **16683 µs**, 5 chunks/frame, zero
sequence gaps, payload ≤1694 B.

### Defect 5 — wrong media source ports and big-endian UVC/UAC fields
The console sources video from UDP **50020** and audio + video-format from
**50021**, and the pad addresses its media return traffic to those ports; libdrc
used ephemeral ports. Both sockets are now bound to the console ports (PCM and
format messages share 50021 via `SO_REUSEPORT`, as the console does).
Separately, the UVC/UAC query fields (mic volume, jack volume, sampling rate) were
serialised big-endian although the console and pad use little-endian, so our
"16000" went out as `3E 80` and read back as 32830. Now `80 3E`.

### Also fixed in the runbook (both were session-killers)
- `iw dev <radio> down` + `iw dev <if> set type __ap` on iwlwifi returns `-EBUSY`
  and silently flips the vif back to `managed`; hostapd then cannot see any 5 GHz
  channel. Create the AP vif with `interface add ... type __ap` and never call
  `set type` on it again.
- The DRC AP radio only has 5 GHz channels IR-capable while a
  `wpa_supplicant` with `country=CA` runs on that phy (iwlwifi LAR is
  self-managed; `iw reg set` is ignored, and hostapd's own `country_code=`
  applies too late). An *idle* supplicant (no network, no association) is
  enough; `drc-up.sh` starts and tracks one.
- NetworkManager must not manage `WiiUAP` (permanent
  `/etc/NetworkManager/conf.d/99-wiiuap-unmanaged.conf`); when it does, the vif
  and the beacon die within seconds.
- Background children need `setsid`: `nohup ... &` under `sudo sh -c` dies with
  the wrapper, which silently killed the streamer while the pad was connected.

### What is still unknown (and the one experiment that resolves it)
The pad receives substantially console-identical media and still refuses to
display it. Everything measurable without the console's plaintext now matches.
The remaining possibilities are (a) the DRH chunk *payload* bytes themselves,
(b) a session/console-state message we never send, or (c) a startup sequence
detail (e.g. how many IDRs before a P frame).

Decisive next step (unchanged from the earlier finding, now with less noise in
front of it): capture a real console↔pad session **from before association** so
the in-force 4-way handshake is included, decrypt it with the PSK from
`run/pairing.env` (`out/evidence/decrypt_h264.py`), and diff the console's
session-start sequence and per-chunk payloads against ours. That needs the
console and pad in normal mode (pad talks to the console, not to us) plus a
5 GHz monitor — i.e. one manual step from the operator.

### Round 11b (autonomous, 2026-11-04 ~03:25): control plane proven; media still refused

The UIC/session control plane is **verified correct**, not suspected:

- Our UIC query payload on `50023` is `7e 01 00 08 00 40 05 06 00 00 00 00`,
  byte-identical to Barista's known-good `BuildUicConfigQuery()`.
- The pad answers it with a **792-byte** UDP packet (8-byte command header +
  the 784-byte `0x310` config blob libdrc expects), so `SyncUICConfig()` really
  completes and the pad has handed over its panel calibration.
- The pad also answers our UVC/UAC queries (`02000100 1000 ...` replies) and
  emits `01 00 00 00` to `50010` at 30-70/s, which Barista's source confirms is
  an **IDR resync request** and is *not* meant to be answered on that socket.

What is still missing, and now clearly isolated: the pad sends **no traffic at
all to the media service ports `50020`/`50021`**, i.e. its own video/audio
services never start. Everything we can measure from the console side matches
the reference implementation (Barista) byte for byte.

`run/12-capture-truth.sh` was added to settle it: it frees the AX210, records a
real console↔pad session on the console's channel, and prints exactly when to
make the pad reconnect so the in-force 4-way handshake lands in the capture.
Decrypt with `tests/decrypt-capture.sh` and diff the console's session-start
sequence and DRH chunk payloads against ours.

Evidence for this round: `out/evidence/live-fmtfix-0313/` (`uic.txt`,
`uic-raw.txt`, `wire.txt`, `pad.pcap`).

### Round 11c (autonomous, 2026-11-04 ~03:35): negative sweep, and why it matters

Three live encoder configurations were tried against the connected pad, with the
pad's media return traffic (`pad -> 50020/50021`) as the objective success
signal because the pad's screen cannot be observed remotely:

| config | video pkts/12 s | pad input | pad msgs | media return traffic |
|---|---:|---:|---:|---:|
| baseline (ultrafast, intra-refresh, keyint 30) | 3498 | 2103 | 710 | **0** |
| `DRC_KEYINT=1` (every frame an IDR) | 8152 | 1652 | 563 | **0** |
| `DRC_PRESET=medium` | 32 | 0 | 0 | **0** |

Findings: forcing an IDR on *every* frame does not make the pad start decoding,
and `medium` starves the single-threaded DRH encoder (the pad stops seeing input
and our video collapses to 32 packets) - so preset is not the lever either. The
pad's behaviour is identical across all three, which further supports the
conclusion that the gate is not in the media plane at all.

Baseline configuration restored and left running.

### Round 11d (autonomous, 2026-11-04 ~03:50): two environment defects + the next real hypothesis

**NetworkManager reclaim is now fixed permanently.** Observed live this round:
NM took `wlan0` back (default route reappeared on it, a `p2p-dev-wlan0` vif
appeared), which deleted the `WiiUAP` vif and left hostapd holding a dead
interface — the pad dropped and the AP was gone. The round-8 `99-wlan0-unmanaged.conf`
had been renamed `.disabled`; it is replaced by a permanent
`/etc/NetworkManager/conf.d/99-wlan0-unmanaged.conf` that unmanages both
`wlan0` and `WiiUAP`. `wlan1` stays the Internet uplink (`drc-uplink`).

**The idle supplicant could silently fail to start**, leaving 5 GHz `no IR` and
so making hostapd fail channel selection. Cause: a stale
`/var/run/wpa-idle` control socket / pid file from a previous instance makes
`wpa_supplicant` exit immediately. `run/drc-up.sh` now removes those files
before starting it and polls the phy's channel flags for up to 12 s instead of
checking once after a fixed sleep.

**Next hypothesis to test (not yet implemented): media QoS/TID.** Barista's
transport reports "media QoS TID 5", i.e. the console sends video/audio in
WMM access category VO. libdrc sets no `SO_PRIORITY`/`IP_TOS` on any socket
(verified: no occurrences in `src/`), so our media currently leaves in the
default best-effort access category. If the pad's media path only accepts its
UVC/UAC traffic in the VO category, that alone would explain a pad that never
starts its media services. Implementation to try: `setsockopt(SO_PRIORITY)` =
5 on the vstrm (50020) and astrm/format (50021) sockets only, then watch for the
first ever `pad -> 50020/50021` traffic. Verify the access category with
`tc -s qdisc show dev WiiUAP` (per-queue packet counters) plus on-air QoS
control field inspection in a monitor capture.

Stability note (same round): the AP was found dead twice with a *graceful*
hostapd teardown (`nl80211: Unsubscribe mgmt frames ... deinit`) and the vif
removed, which is what a device-level reclaim or a phy reset looks like from
hostapd's side. After the permanent NM rule above, `drc-up.sh` was re-run and
verified stable for a full minute: `WiiUAP` UP with `192.168.1.10/24` on
`channel 149`, hostapd and the streamer alive, all six sockets bound. The pad
was asleep (it dropped when the AP vanished earlier); it re-associates on wake,
so the proven input path resumes automatically.

### Round 11e (autonomous goal round 2, 2026-11-04 ~04:10): the payload layer is proven clean

Following `research/STREAMING-TO-PAD.md` (Barista ships a complete stream-inspection
toolbox), our *live* wire stream was validated with Barista's own tools:

- `scripts/analyze-media-capture.py` on a 6 s capture of our `50120` stream:
  **285 complete frames, 57.3 fps, 5 chunks/frame**, frame pacing median 16702 µs,
  no sequence/length errors.
- `scripts/reconstruct-media-capture.py` (re-adds the pad's SPS `67640020ac2b406c1ef368`,
  PPS `68ee060ce8` and synthetic slice headers) → 6 IDR + 239 predicted frames,
  then `ffmpeg -f h264` decoded **242/242 frames with zero errors**
  (150,645,600 B = 242 × 622,080).

So the DRH chunk payload, the 6-row chunking, the ext-option order, the cadence
and the envelope are all *correct on the wire*, not just in theory. Every layer we
control in the media plane is now proven: framing, options, payload decodability,
59.94 fps pacing, console source ports, byte-exact format message, PCM audio,
UIC/UVC control plane, and WMM priority.

**What that leaves.** The pad still refuses to start its media services (no
traffic to `50020`/`50021`). A media-clock experiment was also run this round: a
new `DRC_TSF_OFFSET_US` knob shifts the synthetic clock into the AP's TSF epoch
(offset = measured hostapd age, ~209 s for the current AP), with the pad
associated and video+input flowing - still zero media return traffic.

Two independent working implementations get their media clock from the radio's
real TSF: `wozt/bottom_screen` (58 fps, 0 resync on real hardware) via
`wozt/rtw88_TSF`, and Barista via a **monitor-derived media clock**;
`STREAMING-TO-PAD.md` states plainly that exposing the MAC TSF "is what unblocked
the decade-old freeze". Our AX210 has no `.get_tsf`, so the patched-mac80211 TSF
node returns `UINT64_MAX` and every timestamp we send is synthetic.

**Conclusion and recommendation:** the remaining defect is almost certainly the
absent real media timebase, not any userspace detail. The documented fix is a
radio whose driver actually implements `.get_tsf` — RT5572/rt2800usb (this
project's own PLAN.md recommendation) or an ar9271/ath9k part, or else the
`wozt/rtw88_TSF` patch on a RTL8821CU-class dongle (which explicitly exists for
this purpose). That is now the single highest-value purchase/step, and it is
consistent with every negative result gathered in rounds 11 through 11e.

### Round 11f (autonomous goal round 3, 2026-11-04 ~03:36): TSF is genuinely unavailable here; stack made self-healing

Attempted to obtain a real media timebase from the hardware we already have, to
avoid the RT5572 purchase:

- A **monitor vif alongside the AP** *is* permitted on this iwlwifi phy
  (`iw dev wlan0 interface add mon0 type monitor` succeeds, and the AP keeps
  beaconing). So the idea was to read the TSF out of our own beacons.
- It does not work: a same-radio monitor captures **only other networks'
  beacons** on the channel (the neighbouring AP `9c:4f:5f:93:09:06`, SSID
  "Sir Connects A Lot"), never our own transmissions — filtered
  `wlan[10..11] = cc:fb` returned 0 frames out of a 30-frame capture.
  `iwlwifi` also does not populate radiotap TSFT, and there is no
  `/sys/class/net/*/tsf`, no iwlwifi debugfs TSF node, and no `.get_tsf` op.
  So the AP's clock cannot be observed on this radio at all.

Consequence: the media clock cannot be fixed in software on the AX210. The
options remain exactly (a) a `.get_tsf`-capable radio (RT5572/rt2800usb or
ath9k/ar9271), (b) the `wozt/rtw88_TSF` patch on a RTL8821CU-class dongle, or
(c) a monitor-derived clock with a second 5 GHz radio (what Barista does).

**New: `run/drc-watchdog.sh`** — checks every 30 s that `WiiUAP` exists, hostapd
is alive, the streamer is alive and listening on `192.168.1.10:50022` and
`0.0.0.0:50021`, and re-runs `drc-up.sh` when any of those is missing (the stack
died twice unattended in round 11d). It tolerates a stale pid file by falling
back to a process-name check. Started with:

    sudo setsid nohup ./run/drc-watchdog.sh > out/logs/watchdog.log 2>&1 &

State after this round: `WiiUAP` UP on ch149 with `192.168.1.10/24`, hostapd and
streamer alive, watchdog armed, video ~1422 packets/5 s to the associated pad,
input flowing, media return traffic still 0 (the pad's own services never start).

### Round 11g (goal round 4): self-correction on the success signal

Worth recording before anyone builds on it: rounds 11c-11f used "the pad sends
no traffic to `50020`/`50021`" as the objective proof that its media services
never start. That inference rests on Barista's `m_video_packets_received` /
`m_audio_packets_received` counters and its port table ("Inbound 50020, 50021 -
video/audio service return traffic"). The *existence* of those counters proves
such traffic is expected, but it was never confirmed to be non-zero in a known-
good session, because no known-good session has been captured here. A future
round must not treat "zero media return traffic" as proof of failure on its own;
it is weak evidence, not a gate.

What is solid, and remains the basis for the remaining work:
- every media-plane property we control is byte-correct on the wire (round 11e:
  242/242 frames decoded with zero errors by Barista's own reconstruction tool);
- the pad is not rendering, per direct operator observation on three occasions;
- the radio cannot expose a media timebase (round 11f);
- the pad needs no NM-registered radio state from us, but it does have to be
  awake - it is asleep at the end of this round, so no further observation was
  possible.

Blocking condition (unchanged over goal rounds 2-4): progress needs physical
access, i.e. either a `.get_tsf`-capable radio (RT5572/rt2800usb, ath9k/ar9271,
or a RTL8821CU with `wozt/rtw88_TSF`) or one operator-assisted console capture
via `run/12-capture-truth.sh`. Everything reachable in software has been done,
verified, and documented.

### Round 11h (retry after the blocked round): console is off, capture impossible

Tried to run the ground-truth capture without operator help: stopped our AP (so
the pad would fall back to the console), freed the AX210, put it in monitor mode
and swept every 5 GHz channel for beacons from the console's own AP
(BSSID `cc:fb:65:b6:81:69`).

Result: **the console is not transmitting on any 5 GHz channel** (no beacons from
that BSSID on 36/40/44/48/149/153/157/161/165), i.e. it is powered off or its
wireless is disabled. The pad therefore has nowhere to fall back to and no
console session can be captured. This is a hardware-state dependency, not
something a script can work around.

Stack restored afterwards and verified: `WiiUAP` UP on ch149 with
`192.168.1.10/24`, hostapd and streamer alive (listening 50010/50022/50023 plus
the media sockets), watchdog re-armed, Internet intact on wlan1.

Also recorded: a `pkill -f 'bash ./run/drc-watchdog.sh'` killed the invoking
shell again (the pattern matches the caller's own command line). Use
`ps -eo pid,args | awk '/drc[-]watchdog\.sh/ ...'` and `kill <pid>` instead -
the bracket trick keeps the pattern from matching itself.

### Round 11i (operator present): clock command + console-exact audio

Two more console-parity gaps closed while the operator was at the pad:

1. **The console's clock command was never sent.** libdrc *defines* `TimeCmdPacket`
   (query type `kTimeCommand` = 2) but no caller anywhere in `src/` used it. It is
   now published every second from the UVC/UAC synchroniser (days since
   2000-01-01 + seconds of day). Verified on the wire: 16-byte command packets to
   `50123` at 1/s.
2. **Audio was not the console's packetisation.** libdrc sent 384 frames / 1536 B
   every 8 ms; the console (and Barista, which reproduces it byte-for-byte) sends
   **416 frames / 1664 B every 8.666 ms**. Now matched: 1672-byte datagrams at
   ~110/s, verified on the wire. (Also fixed a units bug introduced while doing
   it: the event timer takes NANOSECONDS, so the first attempt fired ~1000x too
   fast; caught by measuring 3400 packets/s and corrected to `us * 1000`.)

Both are verified on the wire; neither changed the GamePad's screen.

Also learned: the operator paired the pad to *our* impersonated network, and the
console's own AP was independently confirmed silent on all 5 GHz channels with a
*working* monitor (an earlier sweep was invalid because `iw dev wlan0 set type
monitor` silently failed while the interface was up - it must be brought down
first). So no console session exists to capture until the console is powered on.

### Round 11j (operator's theory: pad receives and ignores): two more real gaps

Operating on the operator's read - the pad is connected, receiving, and choosing to
show its own notice - two further console behaviours turned out to be missing:

1. **We had never sent the pad a single display command.** `Streamer::SetLcdBacklight`
   (UIC service 5, method `0x14`, level 0-4) is public in libdrc, but
   `drcvncclient` never called it. It is now asserted once a second at level 4.
   Verified on the wire: 21-byte generic command packets
   (`7e 01 00 08 00 40 05 14 ... 01 05`) to `50123`, ~1/s, and the pad ACKs them
   (8-byte reply packets ~21 in 8 s).

2. **The pad had never received a stream-start packet.** The vstrm `init` flag
   (byte 2, bit 7) was set exactly once per *streamer lifetime*: measured **0 of
   1508** video packets carried it while the pad was connected, because the one
   init packet had gone out long before the pad joined. `init` is now re-asserted
   on every IDR frame, so a pad that joins, stalls or resyncs is told a stream is
   starting. Verified after the change: **128 init-flagged packets matching 128
   IDR-marked packets** in an 8 s capture.

Both are console-parity fixes independent of the timebase question, and both were
invisible until the payload was inspected at byte level rather than by summary
statistics. Neither has been confirmed to change the pad's screen yet - the
operator was away from the pad at the time.

Limits worth stating plainly: the GamePad firmware is closed and no dump exists
here, so "attaching to the machine code" is not possible from this session; the
low-level evidence available is the pad's own protocol messages, the reference
implementations' receiver contract, and on-air behaviour.

### Round 11k: the "receives and ignores" theory, and the baseline-profile discrepancy

Acting on the operator's read (pad is connected, receives frames, and keeps its own
notice screen), two more console behaviours were found missing and fixed:

- **No display command was ever sent.** `Streamer::SetLcdBacklight` (UIC service 5
  method `0x14`, level 0-4) was public in libdrc but never called by
  `drcvncclient`. Now asserted once a second at level 4; verified on the wire
  (`7e 01 00 08 00 40 05 14 ... 01 05`, ~1/s) and the pad ACKs each one.
- **No stream-start packet during the pad's session.** The vstrm `init` flag was
  set once per *streamer lifetime*: measured **0 of 1508** packets carried it while
  the pad was connected. Now re-asserted on every IDR (verified: 128 init-flagged
  packets matching 128 IDR-marked packets in an 8 s capture).

Then the Dolphin-team interview (Bourdon et al.) supplied a decisive discrepancy:
they state the pad's video is **H.264 baseline profile, no B-frames**, and that
input is sent ~180/s (we measure ~172/s - consistent). Our encoder defaults to
`high`, and libdrc's bundled pad parameter sets are High + CABAC. If the pad's
decoder really is baseline-only, a High/CABAC bitstream is exactly the kind of
input it would receive without displaying.

`DRC_PROFILE` already exists as an env hook, so this is a no-rebuild experiment:
the stack is currently running with `DRC_PROFILE=baseline` (which also makes x264
emit CAVLC rather than CABAC). Note the conflict that must be resolved by
experiment: baseline+CAVLC cannot be decoded against the pad's CABAC parameter
set, so if the pad is genuinely CABAC-capable this change will make things worse,
not better. Both directions are now one env var apart.

### Round 11l (final attempt): the media clock is now in the pad's real TSF domain

The one property every working implementation has and we lacked is a real media
clock. The AX210 has no `.get_tsf`, but the monitor vif reports the phy TSF as the
radiotap **TSFT** field and it *can* coexist with the AP:

    mon0 (monitor, ch149) -> "345384302us tsft"

So the clock was aligned for real:

- `src/tsf-linux.cpp` now re-reads its offset once a second from
  `/var/run/drc/tsf-offset-us` (env `DRC_TSF_OFFSET_US` still works);
- `run/align-clock.sh` samples the phy TSFT, subtracts the streamer's elapsed
  synthetic value and writes the offset, making our timestamps land in the same
  domain the pad syncs from our beacons.

Verified: after aligning, the 32-byte format message carried `0x1776baa0`
(~393.7 s) while the phy TSF read ~393 s, where before it carried ~20 s of
streamer-relative time. Re-run `align-clock.sh` after any streamer restart, since
the synthetic epoch resets with the process.

**Result: the pad still shows its notice screen.** With this, every layer is now
either proven correct or made console-identical: envelope, vstrm options,
5x6-MB-row chunks, payload (242/242 frames decode at zero errors), 59.94 fps
pacing, console source ports, byte-exact format message, console-exact PCM audio,
WMM priority, UIC config exchange, UVC/UAC little-endian fields, per-second clock
command, per-second display/backlight command, stream-start flag on every IDR, and
finally a TSF-domain media clock. Our stack now differs from a real console in no
way this project can measure - and the pad still refuses to display.

That is the honest end state of the software-only line of attack. What remains
needs hardware the session does not have (a `.get_tsf` radio) or a console session
to capture, which requires the console powered on - it was confirmed silent on all
5 GHz channels when last checked.

### Round 11m: the real console was captured (console powered on by the operator)

With the operator powering the console on, the hunt finally had a target. Two
things had been hiding it, and both are now recorded so nobody repeats them:

- **`tcpdump` without `-e` never prints a BSSID for beacons**, so sweeping with
  `grep BSSID:cc:fb` produced false negatives on channels where the console *was*
  beaconing. Sweep with `-e` (or filter with tshark on `wlan.bssid`).
- The console's normal AP is **hidden and on ch40 (5200 MHz)**, beacon interval
  100, and its beacon carries the Nintendo OUI `a4:c0:e1` (136 matching beacons in
  15 s). That signature positively identifies it as the console, not our own AP
  (our hostapd was confirmed stopped at the time).

Capture: `capture/console-truth.pcap` (monitor on ch40, 300 s). In the first 75 s it
already contained **12 EAPOL frames** and **95 254 frames from the pad** - i.e. a
real pad/console session, which is the ground truth this project has needed all
along.

Decryption attempt with our own tool (`out/evidence/decrypt_h264.py`, PSK from
`run/pairing.env`):

    ANonce (console): fe38f1c2...b667
    SNonce (pad)    : 65a8d2be...b0c7
    PTK             : 5570b8b5...b7ad   (16 B KCK | 16 B KEK | 16 B TK)
    KCK MIC check on EAPOL msg2: wire == calc   <- the PTK is CORRECT
    [-] no AAD variant validated - PTK is probably wrong

The MIC match proves the key derivation is right; only the data-decryption
convention is missing. That is the known Nintendo quirk: the *data* TK is rotated
3 bytes left and the CCMP AAD must include the QoS control field. Our script tries
several AAD variants but none wins, and it does not implement the rotation.

**Next step, precisely:** either port the rotation+AAD handling from Barista's
`scripts/capture-analysis/decrypt_capture.py` (which documents exactly this, ported
from drc-wireshark's `airpdcap.c`) or supply a console EEPROM dump so that tool can
run unmodified (`--eeprom`). Both are small, concrete tasks, and after them the
capture yields the console's plaintext session start and DRH payloads for a direct
diff against ours.

### Round 11n: the console's session decrypted — and the message we never send

Ground truth achieved. The console was captured on ch40 (`capture/console-truth.pcap`,
165 MB), and decryption succeeded once the reference conventions were used
(rotate the whole 48-byte PTK 3 bytes left, then CCMP with the QoS-aware AAD and a
nonce of `priority || A2 || PN bytes (7,6,5,4,1,0)`): **7,088 unicast frames
decrypted** (the rest are group-key/multicast frames our script skips).

Decrypted traffic, console<->pad:

| flow | count |
|---|---:|
| pad input `50122 -> 50022` | 5,093 |
| console commands `50023 -> 50123` | 995 |
| pad replies `50123 -> 50023` | 996 |
| DHCP | 2 |

**The decisive finding.** Grouping the console's command traffic by size and type:

| console -> pad | count | what it is |
|---:|---|---|
| **1048 bytes**, type `00` (query), UIC | **780** | **service 0, method `0x11`, 1040-byte state blob** |
| 8 bytes, type `03` | 204 | reply-acks |
| 20/52/16/25/332 bytes | 5/3/1/1/1 | one-offs |

The console spends almost all of its command bandwidth on a **1040-byte UIC
command we have never sent** (service 0, method `0x11`), roughly 5 times a second;
our stack instead sends a 56-byte UVC/UAC query. Three of the console's exact
payloads are saved as `capture/console-cmd-{0,1,2}.bin` (1048 B each) for replay:

    0000000010040f00 7e0101b000420011 0000040400000001 0000010100000000 ...
    ^ type/len/seq  ^ generic cmd: magic 7e01, service 00, method 11
       then a 1040-byte blob (686 non-zero bytes, mostly in offsets 40..814)

This is the strongest remaining candidate for the pad's display gate: the pad is
handed a console-state blob five times a second by a real console and never by us.
Next: replay those captured payloads from our side (source port 50023) and watch
whether the pad leaves its notice screen.

### Round 11o: the console's state command replayed - and ruled out

The captured 1048-byte UIC state command (service 0, method `0x11`) was replayed
to the pad every 200 ms for several minutes while the stack streamed normally
(pad associated, video ~2300 packets/5 s, input ~860/5 s). Confirmed on the wire:
`192.168.1.10.49771 > 192.168.1.11.50123: UDP, length 1048`.

**Result: no change.** The pad still shows its notice screen and still accepts
input. So that message is not the display gate (or it is session-specific: the blob
has a high-entropy region at offsets 40..814, consistent with per-session signing).

Also worth recording: the decrypted console capture contained **no video or audio
packets at all** - only input, commands and DHCP. Everything decryptable was
unicast; media is almost certainly sent to the pad under the **group key (GTK)**, so
our unicast-only decryptor cannot see it. Capturing the console's actual video
requires either decrypting the group key as well, or capturing on the pad's side.

State of the objective: input path works end to end (proven repeatedly), the media
plane is console-identical in every measurable respect, and the display gate is
still unidentified. Remaining candidates, in order: (1) media clock again - the one
property every working project has and this AX210 cannot provide a genuine value
for; (2) the console's group-key-encrypted media, which we have never actually
observed. Both need either a `.get_tsf` radio or an extended decryptor.

### Round 11p: the pad's UIC takes a live power-status command (new capability)

With the pad connected and the operator watching, the UIC command space was
swept live. Two observations, both operator-confirmed:

- **A sweep of service 5, methods `0x00`-`0x1f` (1-byte payload `0x01`) put the
  pad's screen into a BLACK state** (it had been showing its notice screen). It
  later reverted, so the effect is transient/latched rather than permanent.
- **Service 5 method `0x07` with payload `0x01` produces a visible flicker of
  light** - the operator saw it - and a follow-up single-bit sweep
  (`0x01,0x02,...,0x80`) was sent to isolate which bit drives the panel.

Method `0x07` is the documented **power-status** command (STREAMING-TO-PAD notes
the UIC must be told command `0x07` power-status bit 5 for the headphone amp), so
it is a genuine hardware control surface reachable from our stack - the first one
we can actuate besides the backlight (`0x14`, which the operator also confirmed
working earlier).

Practical value: the pad's display power/state *can* be driven from userspace over
the DRC command channel. The open question is whether one combination of
power-status bits enables the panel *and* permits our stream to be displayed; the
bit sweep above is the first data point. Commands used are logged in
`out/logs/uic-bisect.log` with timestamps.

## Round 12 (2026-11-04): the real console session is decrypted — ground truth in hand

The blocker that rounds 11m–11o could not get past was a **two-line mistake in the
CCMP convention**, not a missing capability. The capture we already had
(`capture/console-truth.pcap`, 662,116 frames, three complete handshakes) was
undecryptable only because:

- the **CCMP nonce priority octet must be the TID**, not 0 — with 0, only TID-0
  traffic (the pad's 128-byte input packets) verifies, which is exactly what round
  11n saw and then misread as "media is group-key encrypted"; and
- the **SeqCtl field is zeroed inside the AAD** (Nintendo deviates from 802.11 here).

With both fixed, **167,154 of 167,324 protected frames decrypt (99.9 %)** and the
full console↔pad session is now plaintext: `out/evidence/truth/` (per-port dumps,
`console-messages/` with the reference video/audio/format/command payloads).
Tool: `capture/truth-decrypt.py` (per-epoch, per-class convention discovery;
prints what it can and cannot decrypt instead of guessing).

New, verified facts (full detail in `research/GROUND-TRUTH-SESSION.md`):

- The pad's `01 00 00 00` → console:50010 (source port **50110**) appears **3 times
  in a whole healthy session**, ~14 s after video starts, and the console answers
  with one IDR. Ours sends ~63/s. This is the objective pass/fail signal we lacked;
  the "per-frame heartbeat" reading in `CODEC-SPEC.md` was wrong and is now
  corrected. Likewise "the pad never starts its media services" (rounds 11b–11f)
  and "media is sent under the GTK" (round 11o) are disproven — there are zero
  multicast data frames, all media is key-id 0 pairwise, and the pad *is* in the AV
  session asking for keyframes.
- Console video: **59.19 fps**, 5.20 datagrams/frame, max payload **1710 B = 16 B header
  + 1694 B chunk**, ext options exactly `82 00 83 85 06 00 00 00` / `80 82 00 83 85
  06 00 00`, **`init` set only on the 25 datagrams of the very first frame**, ~9 IDR
  frames in 238 s. VSTRM sequence packing differs from both libdrc and Barista
  (`b0 = 0xF0|seq[9:6]`, `b1 = seq[5:0]`); the pad tolerates the 8-bit variant.
- Format message bytes 4–7 are **`00 00 00 00`** on the console, not the datasheet's
  `11 11 81 08`; clocks 16000/16000/21000/21000 confirmed; published 59.2/s.
- Command channel: console keeps an incrementing u16 sequence at bytes 6–7 and the
  pad acks every command with type 3 echoing that sequence; the 1048-byte UIC state
  blob is sent 778× in the **first 28 s only**; the 56-byte UVC/UAC query starts
  ~9 s after video.
- **New channel: UDP 50025 → 50125, 96-byte table at ~1 Hz**, starting simultaneously
  with the UVC/UAC polling. Nothing in our stack sends it and no port is bound. The
  96 bytes are constant except a u16 counter at offset 6 (see
  `out/evidence/truth/console-messages/cmd_50025_table.bin`).
- The console's GTK is also recoverable (msg3 key data unwraps with the rotated KEK —
  independent proof of the PTK), recorded for completeness.

Concrete next changes, in order: `init` only on the first frame; send the 50025
table; format-then-video phase (format 5 ms ahead, ts − 1250 µs); UVC/UAC request
byte[0] = 1 after the first reply; then re-measure the resync rate. All five are
console-measured or Barista-parity, none needs new hardware.

Fix #1 from that list is already implemented and built (2026-11-04): `init` is now
asserted on the first frame only, matching the console, instead of on every IDR.
`./build/build-libdrc-in-container.sh` rebuilds and installs `out/libdrc/lib/libdrc.so`;
`run/drc-up.sh` already puts that path in `LD_LIBRARY_PATH`, so the change takes effect
on the next stack restart. `tests/run-tests.sh` reports 7/9 in that state — the two
socket-based tests (streamer smoke, end-to-end validation) cannot bind 50020/50022/50023
while the production stack is running, which is an environment conflict, not a
regression. Fixes #2-#4 (50025 table, format/video phase, UVC/UAC byte[0]) are not
implemented yet.

## Round 13 (2026-11-04): ground truth decrypted, the pad's state oracle, and AP-parity fixes

The line of attack that had blocked rounds 11m–11o was a **two-line CCMP mistake**, not a
missing capability. Detail in `research/GROUND-TRUTH-SESSION.md`; the operational facts:

- **Decryption recipe.** PTK = stock PRF-512 then Nintendo's 3-byte-left rotation of the
  *whole* PTK (proved twice: the rotated KCK reproduces EAPOL msg2's MIC, and the rotated
  KEK AES-unwraps msg3's key data, which also yields the GTK). CCMP then needs
  **AAD = FC ‖ A1 ‖ A2 ‖ A3 ‖ SeqCtl-zeroed ‖ QoS-control** and
  **nonce = priority(=TID) ‖ A2 ‖ PN**. With priority=0 only TID-0 traffic verifies, which
  is exactly the earlier "media must be GTK-encrypted" misreading. Result: **167,154 of
  167,324 frames decrypt (99.9 %)** across the capture's three handshakes.
- Tool: `capture/truth-decrypt.py` (per-epoch, per-class convention discovery; prints what
  it can and cannot read). Evidence: `out/evidence/truth/` incl. `console-messages/`.
- **The 3 core beliefs corrected:** `01 00 00 00` → console:50010 (from source port 50110)
  is a **resync request**, not a heartbeat (3 in a whole healthy 300 s session, ~14 s after
  video starts, answered with one IDR; ours ran at 63/s). The pad **does** start its media
  services (so the "no 50020/50021 return traffic" signal in rounds 11b–11f was void). The
  console sends **no** traffic to the pad's 50010 at all: session establishment is entirely
  on the command channel.

### The pad's state oracle (calibrated on hardware)

`run/pad-state.py` reads `svc 4/0x05` → `retvals[current_state]`. Calibrated live against
the glass:

| index | what is on the screen |
|---|---|
| **12** | Quick Start Menu (pad-local idle UI; console absent) |
| **0** | "connecting" → "could not connect to the Wii U console" |

Tapping a tile drives 12 → 0 → (falls back) 12. So the pad *does* attempt a session and
gives up. Any future wire metric must be recorded **together with the state index**: several
earlier comparisons were between different pad states, which invalidated them.

### The link loop behind "could not connect"

`/var/log/drc-ap.log` shows the pad **leaving the BSS itself** — `reason_code=8` ("sending
STA is leaving BSS") — roughly once a minute, then rejoining (120 cycles observed). Each
cycle is a fresh 4-way + DHCP + session attempt. Signal strength is not the cause (−35…−45
dBm), so this is the pad's own retry logic.

### AP parity fixes (all verified in hostapd's beacon hexdump)

Comparing our AP's beacon against the decrypted console beacon found four tag-level
differences; all fixed under `CONFIG_TENDONIN`:

| IE | console | we sent | now |
|---|---|---|---|
| HT Capabilities | `0x001c` (greenfield able) | `0x000c` | `0x001c` |
| A-MPDU params | `0x19` | `0x17` | `0x19` |
| HT Operation | RIFS permitted | not permitted | permitted |
| Extended Capabilities | absent | present | absent |
| Broadcom vendor IE `dd09 001018 02 0000040000` | present | **missing** | present |

Sources: `pc2drc/drc-hostap/src/ap/ieee802_11_ht.c`, `beacon.c`, `ap_drv_ops.c`,
`ieee802_11.c`. Barista carries the same HT fix as
`third_party/hostapd-drc/patches/0007-hostapd-match-Wii-U-HT-advertisement.patch`; Vanilla's
maintained `drc-hostap` fork (checked 2026-11-04, commit `a2f705d`) has no equivalent video
fix and deliberately does *not* advertise greenfield.

Also enabled: **RTS/CTS for every frame >256 B** (`rts_threshold=256`; iw 6.17 has no
`tidconf`) — the console's link is RTS/CTS-protected on ~99 % of media frames — and
**U-APSD advertisement off** (we advertised it from the console's beacon but iwlwifi-as-AP
may not implement the pad's power-save schedule).

### Media-plane findings

- **Media clock epoch matters.** Replaying a real console's own bytes with the console's
  original ~92 s clock left the pad requesting keyframes at 59.7/s; the *same bytes* with
  the clock rebased to `(epoch_ms mod 2^32)` µs — in the pad's own epoch — made it go
  **silent (0.0/s for 70 s)** while staying awake (input 179/s). `drc-up.sh` now sets this
  base (`DRC_TSF_BASE_US`), which supersedes `align-clock.sh` (AP TSF is the wrong domain).
- **The IDR storm was real:** 15.3 IDR frames/s, 3.29 Mbps, encoder starved to 43 fps. Now
  capped at 1 IDR/s (first frame + proactive every 60 frames always go; request-driven IDRs
  need to clear a 50 ms debounce *and* a 1 s spacing, `DRC_IDR_MIN_US`).
- **Our payload is exonerated:** our own captured datagrams, replayed through a bare socket
  with the clock in the pad's epoch, hold the pad at **0.0 resync/s**.
- Console-parity items now implemented: format bytes 4–7 = `00 00 00 00`, format→video lead
  5 ms (windows compressed to fit the slot), `init` on the first frame only, the **UDP
  50025→50125 96-byte table at 1 Hz** (a channel we never sent before), console source ports.

### The console's session choreography (the remaining target)

Anchored on the pad's DHCP ACK, from the decrypted capture: the console's **first command
arrives 285 ms after the lease**, then within 60 ms five generic queries, then the
1040-byte `svc 0/0x11` state-blob burst (~29 fragments/s, strict `M M M S` grouping) for
28 s, then `svc 0/0x12`, `svc 4/0x21`, `svc 4/0x1a` (flags 0x42) as the burst ends, and the
pre-video burst at t≈58: `svc 0/0x00`, `svc 4/0x04`, **`svc 5/0x02` (102-byte payload — the
only service-5 command in the session)**, `svc 5/0x06`, with video at 61.0 s. We have never
sent most of these, and every replay so far started seconds late relative to the lease.

### Tooling added this round

`capture/truth-decrypt.py`, `run/pad-state.py`, `run/command-plane.py` (owns
192.168.1.10:50023, ACKs replies, replays the console command stream in recorded order,
polls the state oracle), `run/replay-console-media.py`, `run/replay-console-session.py`,
`tests/pcap-to-replay.py`, `tests/score-live-session.py`, `run/_wait-for-pad.sh`,
`run/phase2…phase11` experiment drivers, `run/bisect-commands.sh`, `run/bisect-inject.sh`.

Command-plane knobs for A/B without rebuilds: `DRC_QUIET_CMDS=1`, `DRC_SEND_TIME=0`,
`DRC_SEND_UVCUAC=0`, `DRC_SEND_BACKLIGHT=0`, `DRC_SEND_UIC=0`, `DRC_SEND_50125=0`,
`DRC_IDR_MIN_US`, `DRC_FORMAT_OUTER`, `DRC_FORMAT_LEAD_US`, `DRC_TSF_BASE_US`.

### Environment gotcha worth keeping

After repeated restarts the iwlwifi 5 GHz AP unlock (LAR) can wedge: every channel reports
`no IR` and hostapd fails with "Could not select hw_mode and channel (-3)". Retrying
`drc-up.sh` does **not** clear it — reloading `iwlmvm`/`iwlwifi` and then forcing a scan with
the idle supplicant does (`modprobe -r iwlmvm iwlwifi; modprobe iwlwifi; wpa_supplicant -i
wlan0 -c /var/run/wpa-idle.conf -B; iw dev wlan0 scan`). Fold this into `drc-up.sh`.

## Round 14 (2026-11-04): the pad has an "armed" state - and it invalidates every quiet measurement

Two findings this round change how the video path must be tested.

**1. The command service has an armed/unarmed gate.** Sending the console's pre-video arm
burst (`svc 0/0x00`, `4/0x04`, **`svc 5/0x02` (102 B)**, `svc 5/0x06`) moves the pad's state
index **12 (Quick Start Menu) → 0** and stops `svc 0/0x11` state-push replies coming back as
**error 9004**. Measured on live hardware: an armed run returns **0 error replies** and
hundreds of normal replies; an unarmed one returns 9004 to anything but a few methods. A
parallel line of work (research/rce-hunt/) hit the same gate from the IR side.

**2. `--mode full` in `run/command-plane.py` never sent the arm burst** - only `arm`/`arma`
did - so every "full" run in rounds 13 was unarmed. Fixed; `full` now arms first.

**Consequence for measurement (the important part).** With the pad unarmed it silently
ignores the video plane and sends **0 resync requests** - so the "0.0/s" results that looked
like success in round 13 were the pad *not trying*. Armed, it does exercise the video path
and the numbers become meaningful:

| configuration | pad resync/s | interpretation |
|---|---|---|
| media only, unarmed | **0.0** | pad ignores video (not a success) |
| armed + our media | **41** | pad tries, fails |
| armed + the console's own recorded media | **31.6** | pad tries, fails on real console bytes too |
| armed + console media, media clock rebased to 0 s | **32.8** | clock base is not the lever |

So: (a) never score a run without checking the pad answered commands (`done: N reply
packets received`, N > 0) and without recording the state index; (b) once armed, even the
console's own bitstream is rejected, which points at the *video-path arming* rather than at
payload bytes, envelope or clock.

**Tooling:** `run/phase12-armed-stream.sh` (arm first, then media 2 s later; `TRUTH=` selects
console vs our media, `TS_BASE=` sets the media clock start), and `run/command-plane.py
--mode full` now includes the arm burst.

**Operator observation worth chasing:** while the pad is attempting to connect, pressing the
TV-remote button, waiting, then exiting leaves it on a **black screen**. If that screen is
the decoder owning the panel (rather than the panel being off), it is the one state where a
correct stream should paint, and the state oracle will say so: a new index, with the pad
still reachable and sending input.

**Environment conflicts seen this round (both broke runs):**
- A parallel `research/rce-hunt/dhcp-probe.py` bound `0.0.0.0:67`, which stopped `netboot`
  binding its **unicast** socket ("Can not bind server address"). The pad then looped on
  DHCP (204 requests, no input, no replies) and every run was void. `netboot` must own both
  `255.255.255.255:67` and `192.168.1.10:67`; check `sudo grep -c "Can not bind"
  /var/log/drc-dhcp.log` before trusting a run.
- iwlwifi LAR can wedge as described in round 13; reload the module and force a scan.

### Round 14b (2026-11-04): doc corrections, the per-manager 9004 map, and two operational bugs

**Corrections owed to the record:**
- The "console packs VSTRM sequence as 4+6 bits" claim in round 12 / GROUND-TRUTH-SESSION.md
  is **withdrawn**. A full census of all 73,500 console datagrams (`research/agents/vstrm-header-diff.md`)
  shows `b0[3:2]` never set, `b1` spanning 0x00-0xFF, and `seq = (b0&3)<<8 | b1` a clean +1
  10-bit counter - i.e. exactly libdrc's `SetSeqId()` layout. The VSTRM header is byte-for-byte
  identical between the console and our stream.
- `sc-cmd.rst:212`'s "svc 4/0x1a shuts the pad down if flags = 0x42" is **disproven**: the console
  sent exactly that at t=28.56 s and the session ran 271 s longer.

**The 9004 error is a per-manager gate, not authorisation** (measured, `research/rce-hunt/10-tv-remote-live.md` §6/§8):
methods the `cmd` manager serves directly (`0/0x00`, `4/0x04`, `4/0x05`, `5/0x06`) always answer;
methods needing the `video`, `sound`, `ir` or `nwk` managers return `9004` until the session is
armed. A full UIC EEPROM dump (including the network PSK in plaintext via `svc 5/0x06`, 772 B)
is allowed while reading the *brightness level* is refused - so 9004 cannot be authorisation.
Arming (the console's pre-video burst, decisive member `svc 5/0x02` with a 102-byte all-zero
payload) moves the state index 12 -> 0 and makes `5/0x15` (brightness read), `1/0x05` (Wi-Fi
config) and `5/0x11` (IRCOM) answer. **`5/0x15` returning `err=0` is therefore a sharper
"video manager armed" oracle than the state index** - use it when testing arming.

**Two operational bugs, both ours:**
1. `pc2drc/drc-hostap/netboot` sends its DHCP OFFER **only as broadcast**; the pad answers with a
   fresh-xid DISCOVER ~2x/s instead of a REQUEST. Adding a **unicast** copy of the same OFFER to
   192.168.1.11:68 yields an immediate REQUEST->ACK and restores the input stream. This is the real
   cause of the "pad flapping / all runs void" episodes; `research/rce-hunt/dhcp-probe.py` implements
   a correct responder. Patch netboot or run that instead.
2. **One hardware owner at a time.** `SO_REUSEADDR` lets a second binder on 192.168.1.10:50023
   succeed silently, splitting the pad's replies between sockets, and two sessions can deauthenticate
   the pad under each other (this voided a 15-case sweep and two of our runs). Take an `flock` on
   `/var/run/drc/hw.lock` around anything that deauths the pad or binds 50023.

## Round 15 (2026-11-04, later): four more console-parity fixes, all measured, none sufficient

Every change below is real console parity. None of them made the pad paint, and the
results are recorded as negatives so nobody repeats them.

**1. The pad tears its session down every ~35-85 s - and that was corrupting our method.**
Measured from a 200 s armed capture: input 180/s and resync 61/s, then *both* go to exactly
zero for ~5 s (pad leaves the BSS, reason 8), then resume unchanged. Each rejoin is a NEW
session: its command service is unarmed again and it never saw a VSTRM `init` frame. Fix
implemented: `Streamer::ArmSession()` + `Streamer::ResetVideoStream()`, called from
`drcvncclient` whenever the pad's input resumes after a >2 s gap. **Measured effect: none** -
resync resumes at the same 61/s.

**2. Link delivery now matches the console and it did not matter.** A measured comparison of
the real console's on-air delivery (`research/agents/link-delivery-parity.md`) shows: video is
QoS TID 5, HT MCS6/20 MHz/long GI, **98.2 % single-MPDU (no A-MPDU aggregation at all)**,
RTS/CTS on **98.6 %** of video frames *including* the ~174 B frame-end chunks, 0.054 % retries.
Applied: `iwlwifi 11n_disable=2` (no TX aggregation) and `rts_threshold=0` (RTS/CTS on every
frame). Rerun: resync **61/s**, unchanged. Link delivery is not the gate.

**3. The time command was carrying a value the console never sends.** The console sends
`a4ef0000305e0000` = days `0xefa4` (61348), seconds-of-day 24112; 61348 is not days-since-2000
(~9800), so our computed value was wrong. The streamer now sends the console's observed value
by default (`DRC_TIME_EXACT=1`, old behaviour with `DRC_TIME_EPOCH=2000`). First measurement:
41/s vs 53-61/s - suggestive, not proven, and still nothing like the console's 0.01/s.

**4. The media clock now has a real source, and my earlier ones were all wrong.**
`run/tsf-from-monitor.py` derives the AP's TSF from a monitor vif's radiotap TSFT
(`wlan_radio.timestamp` via a streaming tshark) and keeps
`/var/run/drc/tsf-offset-us = TSF_now - streamer_elapsed`, i.e. Barista's monitor-TSF
approach. Measured: the pad's own frames carry `radiotap.present.tsft` and the phy TSF was
**731 s / 296 s / 12 s** at different moments today, while hostapd's process age claimed
4574 s - so every "AP-TSF domain" clock set earlier in round 15 was wrong by thousands of
seconds. Caveat: the phy TSF restarts when the radio/vif is recreated, so this daemon must run
alongside the streamer rather than being a one-shot offset.

**Also measured (encoder):** two independent audits disagree. The first called the +2-MB DRH
chunk flush "the defect"; the retry disproved that - the console's own chunks fail *standalone*
decode and succeed *concatenated*, so the pad concatenates the 5 chunks and boundary byte
positions are transport-only (`research/agents/encoder-conformance.md`). The flush realignment
implemented in `pc2drc/drc-x264/encoder/encoder.c` (`first_mb` 0/324/648/972/1296, verified by
driving the rebuilt libx264) is therefore **cosmetic**, kept only because it matches Barista.

**Where the gate is not:** payload (clean), envelope, ext options, sequence packing, beacon
tags, link delivery/aggregation, media clock source, arming alone, session lifecycle, UVC/UAC
timing. **Where it still is:** something in the pad's own session/AV-arming state machine that
we can observe (state index, `5/0x15` gate) but have not satisfied.

## Round 16 (2026-11-04, latest): the console's session-state push is now emitted by the streamer

**Implemented: the 779-fragment `svc 0/0x11` state push + its tail, per session.**
`out/evidence/truth/console-messages/session-push.bin` holds the console's own 782
datagrams (779 push fragments + `svc 0/0x12` whose payload carries `0x0000030b` = the
fragment count, `svc 4/0x21`, `svc 4/0x1a` flags 0x42) with their recorded relative times.
`include/drc/internal/session-push.h` + `src/session-push.cpp` replay them verbatim on their
own thread at the console's ~29 datagram/s cadence (28.6 s), and `Streamer::ArmSession()`
kicks a replay - so every pad session (the pad starts one roughly every 80 s) now gets
arm burst + state push. Verified sender-side: 782 datagrams sent, visible on the wire as
965 x 1048-byte command datagrams (the extra count is command retries).

**Cadence measured and fixed as far as it goes:** the delivered stream runs at 57.3 fps with
a **median timestamp delta of exactly 16683 us** - i.e. the pacing is console-identical and
the missing ~4% are *dropped frames*, not jitter. Cause is frame conversion, not the mailbox
(a two-deep job queue was added - `VideoStreamer::Job`/`jobs_`, `kMaxPendingJobs=2` - and the
rate did not change: 57.27 fps before and after). Left as a known 4% deficit; it cannot
explain the display gate because the console's own media replayed at 59 fps is rejected too.

**Live result with the push (confounded):** resync fell 58 -> 12/s across the run, but the
pad's input rate fell 177 -> 23/s over the same window (it was going to sleep), so the drop is
not attributable to the push. Needs a re-run with an operator keeping the pad awake.

---

## Round 17 — THE DISPLAY WORKS (2026-11-04 ~12:30)

The display gate was the **media clock domain**, not the protocol. Full story and
A/B evidence in `research/DISPLAY-WORKS.md`; operator runbook in `run/README.md`.

**Root cause.** The pad schedules video playback against the AP's TSF, which it
syncs from our beacons. With no TSF node on iwlwifi, libdrc stamps frames as
`(monotonic - streamer_start) + offset`, so `offset` must equal the AP's TSF at
streamer start. Ours was stale at `2000000` us (2 s) while the live AP TSF was
1637 s: every frame carried a timestamp ~27 minutes in the past and was
discarded. Measured: frames stamped 2.667 s -> 101.98 s against a TSF of
1637.06 s. `run/tsf-from-monitor.py` computed the right value but silently wrote
nothing because it needs the streamer's pid, and it was being started *before*
the streamer.

**A/B proof** (same content, same pad, ~56 fps both times): correct epoch ->
video on the pad (three runs, operator-confirmed, captures `uvc-122918`,
`uvc-123248`, `uvc-123823`); epoch left at 0 -> nothing (capture `uvc-123522`).

**The metric that misled every earlier round.** Resync rate does not measure
rejection: the pad emitted 41.8/s, 22.0/s and 60/s *while displaying video
correctly*, and the console's "3 in 300 s" was three datagrams inside 23 ms —
one transient. Every parameter sweep in `VIDEO-PARAMSET-FINDING.md` and
`DISPLAY-GATE-FRONTIER.md` was optimising noise.

**Retired with measurements this round:** the UVC/UAC "won't show video without
it" claim (the pad answers every query 1/s, sequence-matched — the earlier "0 of
101" was my length-based classifier, replies are 24 B and queries 56 B), and the
degenerate-chunk theory (8.98 fps static vs 55.52 fps moving, no difference).

**Input fixes** (all verified with `DRC_INPUT_LOG=1`): buttons were dead because
the client defaulted to joystick mode and fed a uinput feeder nothing reads; a
tap could never click because the touch handler only sent pointer moves; and the
sticks had no code path in mouse mode at all. All three fixed, sticks now
time-based at `DRC_STICK_SPEED` px/s with a squared curve.

**New failure mode, now automated:** the AX210 firmware crashes
(`Unhandled alg: 0x71b` → `Device error - SW reset`) every 1-2 minutes under
streaming load, and the AP then stops transmitting entirely — hostapd alive,
`tx_packets` flat, no beacons, pad stuck on "could not connect". Each reset also
resets the phy TSF (offsets went 1003 -> 173 -> 87.5 -> 71 -> 61 -> 6 s).
`run/ap-health.sh`, `run/ap-recover.sh`, `run/drc-watchdog.sh` and
`run/tsf-guard.sh` detect and repair that automatically; the watchdog fired for
real during bring-up.

**Still open:** the firmware crash loop itself (suspects: 600+ pps with A-MPDU
disabled and RTS/CTS on every frame), audio on the pad speakers (unverified), and
the pad sleeping after ~30-90 s untouched.
