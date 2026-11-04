# WiiU-tk — Wii U GamePad (DRC) toolkit

A curated, self-contained collection of **the original tooling from this workspace**: every
script, probe, patch and test that was written here to make a Wii U GamePad act as a
wireless display + input device for a Linux host, to capture and decrypt the real
console↔GamePad link, and to map the pad's attack surface.

**Collection snapshot:** 2026-11-04 (Round 17 — the display works; see `00-docs/research/DISPLAY-WORKS.md`).
Every file here is documented in [What each tool does](#what-each-tool-does), fingerprinted in
`MANIFEST.sha256`, and traced back to its workspace origin in `_meta/source-map.tsv`;
library changes are in `11-patches/` and re-apply cleanly.

It is an archive of the *work*, not of the *supply chain*: vendored upstream trees
(hostapd/wpa_supplicant, libdrc, Barista, kernel source) are **not** copied here — the
patches that modify them are. See [Collection policy](#collection-policy).

```
   Wii U GamePad                          Linux host (Kali)                    upstream refs
 ┌────────────────┐  802.11n 5 GHz  ┌──────────────────────────────────┐   ┌──────────────┐
 │ H.264 + PCM dec│◄─── video ─────│ libdrc (drc-x264) ── drcvncclient│◄──│ pc2drc,      │
 │ touch/buttons  │───► input ─────│   ▲                    ▲         │   │ libdrc,      │
 │ LCD 854x480    │  (DRC "VNC")   │   │ x11vnc :5900       │         │   │ drc-hostap,  │
 └────────────────┘                │ drc-hostap AP on a free radio    │   │ Barista      │
        ▲ weird WPA2-CCMP          │  + netboot DHCP → 192.168.1.11   │   └──────────────┘
        │ Nintendo OUI a4:c0:e1    │ patched mac80211 → /sys/.../tsf   │   (referenced only)
        └──────────────────────────└──────────────────────────────────┘
```

Everything below was verified on real hardware by the scripts themselves — each one prints
`PASS`/`FAIL` gates and writes evidence rather than asserting success.

---

## Status snapshot (as of 2026-11-04, from `00-docs/SETUP.md`)

| Stage | State | Basis |
|---|---|---|
| Protocol, pairing (WPS variant, KDK rot-3, PIN = 4 symbol digits + `5678`) | **understood + used** | real pairing succeeded, credentials in `run/pairing.env` (not copied here) |
| Patched mac80211 with `/sys/class/net/<if>/tsf` for Kali 7.1.5 | **built, patch re-applies** | `01-radio-kernel/tsf-kali-7.1.5.patch`, `02-bringup/01-load-tsf.sh` |
| Nintendo cipher selector `a4:c0:e1` accepted by cfg80211 | **patched** | `01-radio-kernel/patch-cfg80211-nintendo-oui.py` |
| hostapd + wpa_supplicant with `CONFIG_TENDONIN` | **built, AP comes up** | `10-build/` |
| libdrc + patched drc-x264 + drcvncclient | **built, streams** | `11-patches/pc2drc-local-work.patch` |
| Pad associates, DHCP, handshake, sends input | **working** | `04-stack/drc-up.sh` (ch149, pad 192.168.1.11, ~69 input pkt/s) |
| Pad **displays** our video | **SOLVED (Round 17)** | the media clock must be the AP's real TSF; A/B: correct epoch → picture, epoch 0 → nothing (`00-docs/research/DISPLAY-WORKS.md`) |
| Pad **input** → desktop (stick, touch-tap, buttons) | **SOLVED (Round 17)** | mouse mode + touch-click + stick mapping; bitmask verified per button (`04-stack/README.md`) |
| Radio stays up under load | **NOT solved** | AX210 firmware `Device error - SW reset` every 1-2 min while streaming; `04-stack/ap-recover.sh` + `drc-watchdog.sh` rebuild it, ~60-90 s outage each time |
| Hardware-free video-path validation | **passes** | `08-tests/run-tests.sh`, `08-tests/run-stream-validation.sh` |
| Pad attack surface (command plane, IR, firmware-update path) | **mapped, probes written** | `09-rce-hunt/` |

The display gate turned out **not** to be a protocol defect at all. With the pad armed it
requests ~20-60 resyncs/s *even when it is displaying video correctly*, so resync rate was
never a decode-failure metric — every sweep scored against it was optimising noise. What
actually gated the display was the **media clock domain**: each video datagram carries a
microsecond timestamp that must live in the AP's TSF domain, because that is what the pad
schedules playback against. Ours was stamped from a 2 s epoch while the live AP TSF was
1637 s, i.e. ~27 minutes in the past, and every frame was discarded. Round 17 fixed it and the
desktop appeared (`00-docs/research/DISPLAY-WORKS.md` has the A/B table).

What remains is the radio: this AX210's firmware crashes every one to two minutes under
streaming load, and after each reset the AP stops transmitting entirely — hostapd alive,
`tx_packets` flat, no beacons — so the pad cannot associate. `ap-health.sh` detects exactly
that state and `ap-recover.sh` rebuilds the radio, which is a ~60-90 s outage rather than a
fix. The crash interval correlates with load (70-233 s while streaming, 758-1033 s in the
idle gaps), so lowering the packet rate is the obvious next experiment.

---

## Collection policy

**Copied** (the unique work product of this workspace):

* every shell/python/C/C++ tool written here (**105** files — 64 shell, 33 python, 6 C++, 2 C),
* the local changes to `pc2drc` (uncommitted work-tree edits on upstream `d9fc018`) as a patch — `11-patches/pc2drc-local-work.patch`, 39 files, +1636/−227,
* portable kernel/userland patches,
* the research documents the tools cite (ground truth, codec spec, boot modes, RCE notes),
* small reference tables the probes parse (`09-rce-hunt/tables/`).

**Not copied** (referenced by path in the tables below):

| Excluded | Why | Where it lives |
|---|---|---|
| `pc2drc/`, `research/drc-hostap/`, `research/libdrc/`, `research/wozt-libdrc/`, `research/barista-ref/`, `build/hostap-2.12/` | vendored/cloned upstream code (git-clean clones; only `pc2drc` has local edits, shipped as a patch) | `/home/kali/Wiiu/...` |
| `kernel/linux-source-7.1/`, `kernel/linux-source-7.1_*.deb`, `build/deps/` | 162 MB+ kernel source/tarball | workspace |
| `capture/*.pcap` (≈26 MB), `out/evidence/truth/` (182 MB), `out/evidence/replay-ours/` (20 MB), `out/*/*.so`, `out/bin/*` | evidence and build artifacts, not tools | workspace |
| `run/pairing.env`, `run/get_psk.conf`, `/pairing.env` | **contain the console PSK** — deliberately withheld; regenerate with `02-bringup/02-pair.sh` | workspace |
| `core.1`, `core.9`, `core.15`, `us` | crash dumps and a stray fragment | workspace |

Nothing in this toolkit needs the excluded binaries to be *read*; the two that need a real
`libdrc.so`/`libx264.a` to *run* say so in their own headers (`08-tests/streamer_smoke.cpp`,
`08-tests/codec_probe.cpp`).

---

## Provenance and verification

Every file here is byte-identical to its source in the workspace (verified by hash), and the
one derived artifact is reproducible from git:

```bash
cd WiiU-tk
sha256sum -c MANIFEST.sha256                  # all 149 tracked files
head -30 INVENTORY.md                         # file → purpose → source path
column -t -s$'\t' _meta/source-map.tsv | less # machine-readable provenance
./_meta/generate-inventory.py                 # regenerate all three manifests
```

* `INVENTORY.md` — every file with line count, byte count, a purpose line extracted from its
  own header, and the workspace path it was copied from (matched **by sha256**, so the table
  is a provenance record rather than a human claim).
* `MANIFEST.sha256` — `sha256sum -c` compatible.
* `_meta/source-map.tsv` — `toolkit-path ⇥ workspace-path ⇥ sha256`.
* `_meta/generate-inventory.py` — the generator; re-run it after adding files. It walks the
  workspace read-only, skips the vendored trees, and maps copies back by digest.

Files are grouped by *function* here, not by their original directory (e.g. `tests/decrypt-capture.sh`
lives in `05-capture/`); the `source` column in `INVENTORY.md` and `_meta/source-map.tsv` always give
the true origin.
* `11-patches/pc2drc-local-work.patch` (+ `.diffstat.txt`) — **derived**, not copied:
  `cd pc2drc && git diff` against upstream `d9fc018`.

---

## Directory map

| Path | What is in it |
|---|---|
| `00-docs/` | The research record the tools cite: `PLAN.md`, `RESEARCH.md`, `SETUP.md` (the ~1550-line runbook/lab log, rounds 1–17), codec spec, ground-truth session, boot/modes, RCE notes, agent reports, findings. |
| `01-radio-kernel/` | Portable patches: TSF sysfs export for Kali 7.1.5, Nintendo-OUI cfg80211 patcher, out-of-tree module builder; plus the upstream `pc2drc` kernel patches kept for reference. |
| `02-bringup/` | The documented five-step bring-up that gates each stage with PASS/FAIL: `01-load-tsf` → `02-pair` → `03-ap` → `04-stream` → `05-diagnose`. |
| `03-pi/` | Raspberry Pi 5 (Kali aarch64) deployment, radio self-tests, WPS pairing from the Pi, fake-console builds, SD/USB recovery. Every one is detached + self-restoring because taking the radio down kills SSH. |
| `04-stack/` | Day-to-day lifecycle of the live stack: `drc-up` / `drc-down` / `drc-watchdog`, encoder parameter sweep, clock alignment, pad wait-helper, VNC/report utilities — plus the **Round-17 supervised stack**: `uvc-live.sh` (the one command that works), `uvc-start/stop/kill-live`, `ap-health.sh` / `ap-recover.sh` (radio health + rebuild), `tsf-keeper.py` / `tsf-guard.sh` (media clock) and a `README.md` operator runbook. |
| `05-capture/` | Monitor-mode capture of a real console↔pad session, channel hunting, and the two independent decryptors (EAPOL/PTK derivation + H.264 extraction). |
| `06-experiments/` | The controlled experiments (phase 2–12) and the two bisects that establish causality (which command, which message). |
| `07-protocol/` | The protocol-plane instruments: pad state oracle, command plane driver, arm-trigger causal probe, byte-exact console replays, and the fuzzer. |
| `08-tests/` | Hardware-free validation (no pad, no radio, mostly no root): streamer smoke, codec probe, stream validation with ffmpeg, packet round-trip, schedule/IDR policy, offline census/audit of console vs our wire bytes. Live instruments added in Round 17: `uvc-exchange.py` (UVC/UAC query:reply ratio by payload signature, plus input trend) and `stability-watch.py` (30 s sampling of a live session, summarised). |
| `09-rce-hunt/` | Attack-surface work against the pad: read-only enumeration, safe sweeps, fragment/IR/firmware-update probes, DHCP responder; `tables/` holds the parsed reference data, `tools/` the builders/parsers. |
| `10-build/` | Reproducible builds: the `drcbuild:20.04` container (+ its five inner-build rounds), native hostap 2.12 build for Kali, arm64 Pi build, container rebuilds for x264/libdrc/drcvncclient. |
| `11-patches/` | `pc2drc-local-work.patch` (the ~1.1 kLOC of local changes: paced sender, IDR policy, TSF offset, console-parity command plane) and the earlier formatted `0001-paced-sender-and-idr-policy.patch`. |
| `_meta/` | Inventory generator + source map. |

---

## Paths: read this before running anything

Every script is **archived verbatim**, and they hardcode `ROOT=/home/kali/Wiiu` (the Pi
scripts use `/home/kali/wiiu-work`). They are not rewritten here on purpose — the copies stay
byte-identical to the versions whose PASS/FAIL evidence is in `00-docs/SETUP.md`.

Two options:

```bash
# A. Run them from a workspace layout (what the paths expect)
#    i.e. keep this archive at /home/kali/Wiiu/WiiU-tk and reconstruct the tree, or
#    put the toolkit back in place:  cp -a WiiU-tk/{run,tests,capture,kernel,build} …

# B. Repoint the copies at a new root (then they are no longer byte-identical)
grep -rl '/home/kali/Wiiu' . | xargs sed -i 's#/home/kali/Wiiu#/opt/wiiu#g'
grep -rl '/home/kali/wiiu-work' . | xargs sed -i 's#/home/kali/wiiu-work#/opt/wiiu#g'
```

Note the scripts do **not** source each other except `_wait-for-pad.sh` (sourced by the
phase/bisect scripts via `$ROOT/run/_wait-for-pad.sh`), so if you relocate, keep the `run/`
naming or edit those five call sites.

---

## What each tool does

Legend — **root**: needs root (radio/DHCP/raw sockets) · **HW**: needs the GamePad powered
and associated · **destructive**: can wedge or reboot the pad, or drop the host's network.

### 00-docs — the research record every tool cites

| File | What it records |
|---|---|
| `PLAN.md` | The project goal and the constraints that shaped it: wireless only, console stays stock, pad stays intact — and the alternative routes that were rejected (console homebrew/Moonlight, LCD hardware mod, UART video) with the reasoning. |
| `RESEARCH.md` | Running research log: what was looked up, what was tried, what it changed. |
| `SETUP.md` | The round-by-round runbook and lab log (rounds 1–17, ~1550 lines). Each round states the hypothesis, the measurement, the fix and the outcome — including the rounds that were wrong. Round 17 is the media-clock fix. |
| `gamepad-alternative-paths-report.md` | Why the "just install Moonlight on the console" family of routes was excluded, with the evidence that forced the DRC-impersonation approach. |
| `reports/VIDEO-PARAMSET-FINDING.md` | The `log2_max_frame_num` root cause (pad wants 8-bit `frame_num`, x264 emitted 5) with the offline proof (90/90 frames decodable under the pad's hardcoded SPS/PPS) and the live parameter sweep that followed. |
| `reports/pad-state-oracle-2026-11-04.md` | The `svc 4/0x05` state oracle: which indices the pad returns and what they correspond to. |
| `reports/BUILD-MANIFEST.txt` | sha256 of every built binary (hostapd, wpa_supplicant, netboot, drcvncclient, libdrc, x264, mac80211) so a rebuild can be diffed. |
| `reports/pi-report.log` | Raspberry Pi self-test output posted back by the Pi (its network drops on purpose during radio tests). |
| `research/DISPLAY-WORKS.md` | **The Round-17 resolution.** The media-clock gate, the A/B table (correct epoch → picture, epoch 0 → nothing), why resync rate misled every earlier round, both retired candidate answers, the input bug list, and the AX210 firmware crash loop with the recovery architecture. |
| `research/DISPLAY-GATE-FRONTIER.md` | The 18-candidate ruled-out list with the measurement that kills each. Its opening now carries a correction: the "resync rate = rejection" invariant it was built on is false. |
| `research/FAILURE-CAUSES-AUDIT.md` | Systematic audit of every candidate that could stop the pad displaying — kernel/modules, driver params, hostapd settings, addressing/ports, media plane, clock, order of operations, command plane, pad-side state, RF — each measured now and diffed against the artefacts from the runs that worked. Headline: the media plane is byte-for-byte equivalent to the working runs; the one module-level difference is the **patched mac80211** (working runs used the stock build). |
| `research/LVC-ARCHITECTURE-AND-MANAGERS.md` | The LVC firmware's internal structure (wiiubrew `GamePad/LVC`): drivers, services and **managers**. This is what explains error `9004` — it is a **per-manager gate** (`mc_cmd` for commands, **`mc_video` for decoding/playback**, `mc_state` for state), not an authorisation check. Also records the UIC EEPROM's CRC16-checked blocks and the LCD feed-bit consequence. |
| `research/WIKI-CMD-AND-CLOCK-FINDINGS.md` | The kuribo64 WUP hardware wiki and libdrc `sc-cmd.rst` read, the full service/method map, the UVC/UAC claim that was tested and retired, and six corrections to my own earlier notes (port-file direction, `si`/`di` fields, state 12, the 5/0x02 payload, push byte-equality, ephemeral source ports). |
| `research/ENCODER-VERDICT.md` | Reconciles two conflicting encoder audits: the payload is structurally valid and the 1–2 byte degenerate chunks are the only anomaly — a theory later retired by the moving-content run. |
| `research/GROUND-TRUTH-SESSION.md` | Everything measured from the decrypted console session: the CCMP derivation recipe and its two non-obvious details, flow table, wire formats, and the corrections made to earlier claims. |
| `research/CODEC-SPEC.md` | The H.264/DRH chunking specification (six-macroblock-row strips, five chunks per frame) and the defect list it was written against. |
| `research/BOOT-AND-MODES.md` | Pad boot behaviour, modes, the state oracle, and the panel commands observed. |
| `research/STREAMING-TO-PAD.md` | The console-programmer's view of the video path (GX2 scan buffers, hardware artefacts of the wire format) and what a clean-room non-console encoder proves. |
| `research/WEB-RESEARCH.md` | Digest of the public research that informed the approach. |
| `research/codec-measurements.txt` | Raw encoder/codec measurements (frame counts, sizes, timings) behind `CODEC-SPEC.md`. |
| `research/agents/vstrm-header-diff.md` | Agent report: the VSTRM header against the console's, field by field (concluded byte-identical; the "4+6 bit sequence" claim was withdrawn). |
| `research/agents/command-causal-map.md` | Agent report: which console command has which observable effect on the pad. |
| `research/agents/pad-clock.md` | Agent report: the pad's clock behaviour and how it relates to the media timeline. |
| `research/agents/encoder-conformance.md` | Agent report: encoder conformance against the pad's parameter sets. |
| `research/rce-hunt/01-pad-firmware-update.md` | Full map of the GamePad's firmware-update ("blink") path and whether it can be used to push a custom LVC. |
| `research/rce-hunt/01-parser-code-notes.md` | Every parser that runs on data the fake console sends to the pad, with the code that implements each. |
| `research/rce-hunt/02-attack-surface.md` | Ranked map of all parser surfaces reachable with bytes we control. |
| `research/rce-hunt/03-harness.md` | The live mutation harness (`09-rce-hunt/fuzz-pad.py`) and its safety envelope. |
| `research/rce-hunt/04-public-re.md` | Review of public RE work for a GamePad code-execution primitive — what is already known and reusable. |
| `research/rce-hunt/05-pad-parsers-in-code.md` | The pad-facing wire formats as the actual implementations believe them (vs. what the docs claim). |
| `research/rce-hunt/06-obtaining-pad-firmware.md` | How to get an analysable firmware image into the lab, and the constraints on doing it non-destructively. |
| `research/rce-hunt/07-synthesis-plan.md` | One ranked, decision-ready plan under a non-destructive rules-of-engagement. |
| `research/rce-hunt/08-live-results.md` | Live results, including one contaminated run and why it was voided. |
| `research/rce-hunt/09-tv-remote-ir.md` | TV-remote / IR subsystem analysis and a ranked testable exploit plan. |
| `research/rce-hunt/10-tv-remote-live.md` | What is verified about the IR path, what is falsified, and the ready-to-fire probes. **This is where the arming breakthrough was found** — `svc 5/0x15` (brightness read) returns `9004` until the pad's managers are armed, which gave every later experiment an objective gate oracle. |

### 01-radio-kernel — portable patches

| File | Purpose |
|---|---|
| `tsf-kali-7.1.5.patch` | The 5-hunk port of `pc2drc`'s TSF export to Kali 7.1.5 (`net/mac80211/iface.c` `dev_attr_tsf`/`tsf_show` + the 1-line `rx.c` change). libdrc needs the AP's hardware TSF to stamp pad video frames; stock Linux never exports it. |
| `patch-cfg80211-nintendo-oui.py` | Rewrites Nintendo's `a4:c0:e1` CCMP selector in `cfg80211`'s key-cipher path to standard CCMP, so iwlwifi/mac80211 will install the key (they otherwise fail `-EINVAL` because the driver advertises no such cipher). The beacon still carries `a4:c0:e1` because hostapd builds that IE in userspace and does the 3-byte PTK rotation there. |
| `build-patched-wireless.sh` | Builds patched `cfg80211` + `mac80211` **out of tree** against the running kernel and reloads, so nothing is installed system-wide. |
| `upstream-pc2drc-patches/` | Reference copies of the upstream patches this work ports (`kernel_above_5_11_mac80211.patch`, `kernel_below_5_12_mac80211.patch`, `mac80211_rx.patch`) and pc2drc's own `build-patched-kernel.sh`. |

### 02-bringup — the documented path (start here)

| Tool | root | HW | Purpose |
|---|---|---|---|
| `01-load-tsf.sh [iface]` | ✔ | – | Loads the patched `mac80211.ko` **out-of-tree** (never installed into `/lib/modules`, so a reboot restores stock) to get `/sys/class/net/<if>/tsf`. The Wi-Fi uplink necessarily drops while the shared module is swapped; the script restores everything on exit and rolls back to stock if the module fails. `DRC_SYNTHETIC_TSF=1` alternative documented in `00-docs/SETUP.md`. |
| `02-pair.sh [iface]` | ✔ | ✔ | Route A (console in pairing mode, SYNC ×2): acts as a WPS client of `WiiU<mac>_STA1`, gets past M2 with `AuthKey = KDF(KDK rot-3)` and the `PIN = <4 symbol digits>5678`, writes `run/pairing.env` (`IFACE`, `SSID`, `PSK`). Route B: direct pairing against our own AP. |
| `03-ap.sh` | ✔ | ✔ | Raises the DRC AP (patched hostapd: Nintendo cipher selectors + PTK rotation) on `CHANNEL` (default 36; `CHANNEL=165 sudo ./03-ap.sh` when the pad refuses) plus `netboot` DHCP → pad at `192.168.1.11`. |
| `04-stream.sh` | – | ✔ | `X desktop → x11vnc → drcvncclient → H.264 → pad`; touch/buttons return as VNC pointer/key events, so they drive the machine running the VNC server. Two layouts: all-in-one, or bridge (`VNC_HOST=<desktop-ip>`). |
| `05-diagnose.sh` | ✔ | ✔ | Distinguishes "associated" from "actually speaking DRC": counts traffic per documented port in both directions. Ping alone proves nothing. |

### 03-pi — Raspberry Pi 5 as the radio host

All of these are written to survive losing the network (they `setsid`/`nohup`, log, and an
`EXIT` trap restores NetworkManager and POSTs the log back to Kali via
`run/report-receiver.py`).

| Tool | Purpose |
|---|---|
| `pi-bootstrap-headless.sh` | Post-flash config: headless, low power, and — the one that matters — `usb_max_current_enable=1`, because Pi 5 otherwise browns out a 5 GHz dongle. |
| `pi-flash-usb.sh <img> <disk>` | Flash Kali ARM to a USB SSD/NVMe enclosure and pre-apply that config so the first boot is already right. |
| `pi-push-tree.sh [dest]` | Push `pc2drc` + `run/` to the Pi, excluding x86-64 artifacts. |
| `pibuild.sh` (`10-build/`) | Native arm64 build of the whole stack (needs the vendored OpenSSL 1.0.1u; see `00-docs/SETUP.md` "Raspberry Pi 5"). |
| `pi-pair-wps.sh` | Route A from the Pi: WPS **client** of the console's pairing AP, `PIN=0123 …`. |
| `pi-sync-search.sh` | Raises a fake pairing console for a pad sitting in Settings→SYNC and logs every auth/assoc attempt. |
| `pi-be-the-console.sh` | Clones the console: same SSID, same PSK, same BSSID, Nintendo selectors, then serves `.11` over DHCP. |
| `pi-capture-pair.sh` | Sniffs the real pairing (a monitor vif cannot coexist with an associated STA on brcmfmac, so networking is sacrificed on purpose and always restored). |
| `pi-ap-test.sh` / `pi-ap-wlandown.sh` / `pi-ap-downonly.sh` | brcmfmac AP experiments: APSTA on ch149 with a **distinct** AP MAC (`-100 Network is down` if the MAC is duplicated); the `wlandown` variants do an explicit `NM detach → ip link down → up → AP vif → hostapd` because detaching alone leaves brcmfmac refusing beacon parameters. |
| `pi-radio-selftest.sh`, `pi-radio-selftest2.sh` | ~3-minute unattended radio test that gives up the network, verifies each hypothesis three ways (hostapd AP-ENABLED, beacon on a second vif, client association), then restores and reports. The `2` variant is the corrected second pass. |
| `pi-standard-ap.sh` | Tests whether the GamePad accepts a **plain** WPA2 AP carrying the console's SSID+PSK — which would avoid needing Nintendo's selectors in the kernel at all. |
| `pi-fix.sh` / `pi-fake-console-dual.sh` | Correct dual-radio topology: dongle = uplink under NetworkManager, 5 GHz radio = AP. Explicitly does **not** touch the AP MAC (`-16 EBUSY`) or stop NetworkManager (kills the uplink). |
| `pi-deploy-videofix.sh` | Pushes the SPS/`frame_num` fix and drives on-pad verification (`out/evidence/VIDEO-PARAMSET-FINDING.md`: the pad decodes against a **hardcoded** SPS with `log2_max_frame_num_minus4 = 4`; stock x264 emits 5 bits and desynchronises every slice header). |
| `sd-repair.sh` | Repairs the unclean-shutdown state on the Pi's boot card and reports whether the device is electrically healthy first (a 182 k-suppressed-error card is not worth `fsck`). |

### 04-stack — the live stack, day to day

| Tool | root | HW | Purpose |
|---|---|---|---|
| `drc-up.sh` | ✔ | ✔ | One-shot bring-up or clean failure. Verified state: `WiiUAP` on ch149, pad associates, 4-way handshake, DHCP `.11`, video 143 pkt/s → 50120, input 69 pkt/s ← 50122, 0 resync. Enforces: never use the radio carrying the default route; only recorded PIDs are killed; children started with `setsid`; idempotent. Starts an **idle** `wpa_supplicant` with `country=CA` on the AP phy — without it iwlwifi LAR marks every 5 GHz channel `no IR` and hostapd dies with `-3`. Honours `RADIO=`, `CHANNEL=`, `DRC_WAIT_PAD`, `DRC_EXTRA_ENV`. |
| `drc-down.sh` | ✔ | – | Teardown from recorded PIDs only — deliberately no `pkill -f`, which matched the invoking shell and killed this project's own terminal several times. Restores the radio MAC. |
| `drc-watchdog.sh` | ✔ | ✔ | Re-runs `drc-up.sh` when the AP vif disappears (NetworkManager reclaiming the phy) or hostapd exits gracefully. |
| `drc-sweep.sh [candidates…]` | ✔ | ✔ | Sweeps encoder parameters live via env (`keyint`, `drh0`, `fps30/60`, `qp26/40`, `8x8`, `deblock`, `intra_refresh`, and combinations). **Its scoring metric is wrong**: it ranks candidates by the pad's resync rate, which does not measure decode failure (see the status note). Use `08-tests/score-live-session.py` for media parity plus your eyes for the display. |
| `align-clock.sh` | ✔ | ✔ | Puts media timestamps in the radio's real TSF domain: reads phy TSF from a monitor vif's radiotap TSFT, subtracts the streamer's synthetic elapsed value, writes `/var/run/drc/tsf-offset-us` (re-read every second by the patched `tsf-linux.cpp`). Re-run after every streamer restart. |
| `_wait-for-pad.sh` | – | ✔ | Sourced helper: waits for the pad to be associated **before** capture/media start, so the one frame carrying the VSTRM `init` flag is not lost while the pad is still joining (`DRC_WAIT_SECS`). |
| `vnc-grab.py <host> <port> <out.ppm>` | – | – | Minimal RFB client: handshake, one raw framebuffer update, save PPM — proves the desktop half at the size `drcvncclient` will consume, no pad needed. |
| `report-receiver.py [port]` | – | – | One-shot HTTP sink for the Pi's self-test reports (the Pi loses the network on purpose, so evidence is POSTed back). |
| `uvc-live.sh` | ✔ | ✔ | **The one command that matters (Round 17).** Takes `flock /var/run/drc/hw.lock`, frees the console ports, waits for the pad, ensures x11vnc, **seeds the media clock from the AP's real TSF**, starts `drcvncclient` in mouse mode, runs the clock guard, reports status every 10 s. Runs until stopped. |
| `uvc-start.sh` | ✔ | – | Starts `uvc-live.sh` fully detached (`setsid`) and returns immediately. Exists because several restarts were lost when the launching shell's timeout or Ctrl-C took the session down with it. |
| `uvc-stop.sh` | ✔ | – | Stops the streamer and clock helper, leaves the AP and the pad alone. |
| `uvc-kill-live.sh` | ✔ | – | Stops the supervisor *and* its children. Use this instead of `pkill -f run/uvc-live.sh`, which matches the caller's own command line and kills the shell you typed it in. |
| `ap-health.sh [--quiet]` | ✔ | ✔ | Exit 0 only if the AP is **really transmitting**: `tx_packets` must grow ≥5 in 5 s (with no stations, beacons are the only traffic). This is the only check that catches the post-firmware-reset state where hostapd is alive and every pid/socket test passes. |
| `ap-recover.sh` | ✔ | ✔ | Full radio rebuild after a firmware reset: stop processes → reload `iwlwifi` → recreate the idle supplicant and force a scan (clears `no IR`, otherwise hostapd dies with `-3`) → `drc-up.sh` → supervised streamer. |
| `tsf-keeper.py [--once] [--pid N]` | ✔ | ✔ | The low-load media-clock keeper: one TSF sample every `--period` seconds (never a permanent monitor capture — that load made the firmware crashes more frequent), writes `/var/run/drc/tsf-offset-us`, and on a >5 s step leaves `/var/run/drc/tsf-reset` so the streamer re-inits. `--once` prints a single TSFT sample. |
| `tsf-guard.sh [--period 60]` | ✔ | ✔ | The loop version of the above, started by `uvc-live.sh`: one sample a minute, rewrites the offset on a step and asks the streamer to re-arm + re-init. |
| `tsf-from-monitor.py` | ✔ | ✔ | The original continuous version: keeps the offset aligned by holding a monitor capture open. Superseded by `tsf-keeper.py` (same maths, far less radio load), kept because `--once`/`--dry-run` are handy for inspecting the TSF. |
| `load-patched-mac80211.sh` | ✔ | ✔ | Loads the locally built mac80211 (TSF sysfs node) **without** `01-load-tsf.sh`'s liveness gate, which always rolls back on iwlwifi (its TSF returns `UINT64_MAX`). Costs a driver reload, so the uplink drops ~15-30 s. With this module loaded the pad leaves its menu and goes **black** (feed selected, nothing decoded) - the first pad-side change in the project. |
| `restore-stock-mac80211.sh` | ✔ | ✔ | The inverse: unload every wireless driver, `modprobe` the distro mac80211, reload the drivers, verify the uplink, then `drc-up.sh`. The confirmed-working 12:27-12:43 runs used the stock build. |
| `reset-watcher.sh` | ✔ | ✔ | Watches `dmesg` for `restart completed`; on a firmware reset it restarts the supervised session so the media clock is **reseeded**. This exists because a monitor vif cannot be re-tuned while the AP runs on this radio (`iw dev mon0 set channel` exits 0 and leaves no channel), so no live TSF refiner can work — the trigger has to be the reset event. |
| `poll-state.py [seconds]` | ✔ | ✔ | Waits for the pad, then polls `svc 4/0x05` every 2 s and prints a state timeline (reading replies off the wire). Use it while doing something physical on the pad - e.g. tapping a profile tile - so the effect is measured instead of guessed. |
| `watch-live.sh [seconds] [period]` | ✔ | ✔ | One line per sample: pad **AWAKE/ASLEEP**, its input rate, our video transmit rate, its resync rate, the media-clock error against the AP TSF, and whether it is engaging (command replies or resyncs). Several "still no picture" reports coincided with a sleeping pad while the stream carried on one-way; this ended that ambiguity. |
| `probe-display.py [--timeout]` | ✔ | ✔ | Same wait-for-wake behaviour, then fires `4/0x05`, `5/0x15`, `5/0x08=01`, `5/0x08=00`, `5/0x0b`, `5/0x19` and prints each reply's error code — the display-path probe. |
| `probe-awake.py [--timeout]` | ✔ | ✔ | Waits for the pad's own input stream (the only reliable awake signal), then fires `svc 4/0x05` (UIC state) and `svc 5/0x15` (arming oracle) from an ephemeral port and reads the replies off the wire, because the streamer owns `50023`. |
| `watch-firmware.sh [minutes] [interval]` | ✔ | ✔ | Samples radio health, the firmware reset counter (`iwlwifi: Device error - SW reset`), pad association and the pad's resync rate once per interval, and flags each new reset. This is how the load/crash correlation was measured: resets every 70-233 s while streaming versus 758-1033 s in the idle gaps. |
| `README.md` (this directory) | – | – | Operator runbook for the Round-17 tools: the one command, the clock table, radio health, the input map, measurement commands, env knobs, and the five traps that waste afternoons. |

### 05-capture — real-session capture and decryption

| Tool | root | Purpose |
|---|---|---|
| `12-capture-truth.sh` | ✔ | The operator-procedure version of "capture a real console↔pad session from **before** association" (the PTK only exists in the handshake that is in force). |
| `capture2.sh` → `capture3.sh` → `capture5.sh` | ✔ | The three corrected attempts, each header records the bug it fixed: (2) iwlwifi is single-channel so the uplink must be dropped and the pad power-cycled; (3) the console hops channels (36→40) so the monitor hops, and it waits for the console to be visible for 20 s; (5) the version that does **not** disrupt connectivity — `wlan1` carries the uplink while `wlan0` monitors. |
| `capture-console-session.sh` | ✔ | Capture + decrypt in one pass using the PSK; documents why the EAPOL exchange is mandatory (`PTK = PRF-512(PMK, …nonces…)`, WPA2 is not forward-secret but the PSK alone is not enough). |
| `find-console-channel.sh` | ✔ | Sequential per-channel sweep that reports which channel carries the console (`cc:fb:65:b6:81:69`) and the pad (`40:d2:8a:17:e2:09`) — sequential because a background hop loop launched under `exec > >(tee …)` silently stopped changing channel. |
| `truth-decrypt.py` | – | Ground-truth decryptor: derives the PTK from EAPOL nonces (CCMP pairwise key id 0), decrypts every protected frame, and writes per-port record dumps (`>d4s4sI` + payload / `>d4s4sHH` + payload) that the whole offline toolchain parses. Written after a `tshark` build hid EAPOL nonce fields and `airdecap-ng` refused the hidden-SSID handshake. |
| `decrypt_h264.py` | – | Independent decryptor that also pulls the console's SPS/PPS — the reason we know libdrc sends `b_repeat_headers=0` and the pad relies on its own parameter sets. |
| `decrypt-capture.sh` | ✔ | Convenience wrapper: report whether a capture *can* be decrypted, then decrypt and extract H.264. |

### 06-experiments — controlled experiments, in the order they were run

Each phase file exists to remove exactly one variable; the headers state the hypothesis and
the prior result it reacts to.

| Tool | root | What it isolates |
|---|---|---|
| `phase2-console-parity.sh` | ✔ | Restarts only the media streamer (the pad stays associated) and captures from *before* the restart, so the first-frame `init` flag is actually observed; tests the three console deltas (1 Hz `50025→50125` table, format bytes `00 00 00 00`, ~5.15 ms format→first-video lead). |
| `phase3-replay-console.sh` | ✔ | Replays the console's **own** decrypted datagrams (73,500 video + 41,355 audio/format) with its source ports and timing — the isolating experiment that exonerates envelope/pacing and indicts payload or arming. |
| `phase4-clock-domain.sh` | ✔ | Same bytes, clock rebased into `(epoch_ms mod 2^32)` µs — the knob that first made the pad go quiet (later explained by arming, see `phase12`). |
| `phase5-full-session.sh` | ✔ | Replays a **complete** console session including its fixed session-start handshake (clock command, 13 generic UIC commands, 778-fragment state push on `svc 0/0x11`). |
| `phase6-state-machine.sh` | ✔ | Media replay held constant; one command mode at a time (`state` / `blobs` / `uvcuac` / …), with `command-plane.py` ACKing replies and polling `svc 4/0x05` → a state timeline instead of an opinion. |
| `phase7-full-cmd-media.sh` | ✔ | Media **+** the whole command plane with *our* ACKs (earlier replays replayed the console's recorded ACKs, whose sequence numbers no longer match). |
| `phase8-arm.sh [arm|arma] [secs]` | ✔ | The console's pre-video **arm burst** with media already flowing. |
| `phase9-pad-initiated.sh` | ✔ | Operator taps a Quick Start Menu tile while media + command plane run: those taps arrive in the 128-byte input stream and a real console would answer by starting a session. |
| `phase11-session-anchored.sh` | ✔ | Starts the command stream **0.3 s after the pad's DHCP ACK** (the console's measured +285 ms) instead of whenever a tool was launched — tests whether the pad arms against a deadline. |
| `phase12-armed-stream.sh [secs]` | ✔ | **Arm first, then media 2 s later** (`TRUTH=` console vs our media, `TS_BASE=` media clock start). This is the configuration in which measurements became meaningful: armed pad → 41 resync/s on our media, 31.6/s on the console's own. |
| `bisect-commands.sh [secs]` | ✔ | Which command-plane message keeps the pad asking for keyframes: re-enables everything except one command per run (`DRC_QUIET_CMDS`, `DRC_SEND_TIME`, `DRC_SEND_BACKLIGHT`, `DRC_SEND_UVCUAC`, …). |
| `bisect-inject.sh [secs]` | ✔ | The complement: inject **one** captured console payload at a time into a quiet session, from the console's own source port (possible because the replayer binds only 50020/50021). |

### 07-protocol — the protocol-plane instruments

| Tool | root | HW | Purpose |
|---|---|---|---|
| `pad-state.py` | ✔ | ✔ | The state oracle: three documented read-only queries — `svc 4/0x05` → state index (`retvals[] = {0,10,4,5,6,1,2,3,9,7,8,11}`), `svc 4/0x04` → 28-byte version, `svc 1/0x05` → 113-byte WL config including the SSID and PSK **as stored in the pad**. Also the shared packet builders/parsers the other tools reuse. |
| `command-plane.py [--mode …]` | ✔ | ✔ | Drives the command plane like a console and records the state index while doing it. Modes include `arm`/`arma`/`full` — `full` was fixed in Round 14 to include the arm burst (before that every "full" run was silently unarmed). |
| `agent-arm-probe.py` | ✔ | ✔ | Causal probe for arming: sends candidate triggers from `192.168.1.10:50023`, ACKs every reply, records state index **and** each reply's error code after every step, so "which command arms the video path?" is measured. |
| `probe-command.py` | ✔ | ✔ | Injects exactly one command kind into a quiet session; settles causality that the bisects could not (they still sent the other four commands). |
| `replay-console-cmd.py` | ✔ | ✔ | Replays just the console's 1048-byte `svc 0/0x11` UIC state command (~5×/s), from an ephemeral port, to test whether the display gate depends on it. |
| `replay-console-media.py` | ✔ | ✔ | Byte-for-byte media replay from the decrypted capture, on the console's source ports and recorded pacing. |
| `replay-console-session.py` | ✔ | ✔ | Complete session replay: commands (in the console's order), video, audio, format messages, 50025 table. |
| `fuzz-pad.py` | ✔ | ✔ | 3,200-line protocol-plane fuzzer + crash oracle: plays the console side, pushes one mutated case at a time, and continuously samples a liveness oracle so a case that kills/wedges/reconfigures the pad is attributed to exact bytes and can be replayed. **Destructive by design — authorized hardware only.** |

### 08-tests — hardware-free validation (no pad, no radio, mostly no root)

| Tool | Needs | Purpose |
|---|---|---|
| `run-tests.sh` | libdrc built | The suite: TSF clock source (patched sysfs node or synthetic fallback), the DRH chunking contract (**12/12 frames → exactly 5 chunks**), and a GamePad-format stream that ffmpeg decodes (60 frames, zero errors, 854×480). |
| `run-stream-validation.sh` | libdrc built | Drives the patched `VideoStreamer` at loopback, captures the VSTRM datagrams, verifies packet-level correctness and reconstructs Annex-B H.264 → ffmpeg. Proves encoder + DRH chunking + packetisation + pacing without hardware (not that the pad accepts it). |
| `run-streamer-smoke.sh` | libdrc built | Thread-lifecycle smoke test: deadlock on `Stop()`, frames arriving faster than they are sent, unbounded memory growth. |
| `run-codec-probe.sh` | drc-x264 built | Builds `codec_probe.cpp` and measures bytes/frame and per-chunk sizes per preset against the vstrm payload ceiling, on synthetic *and* real X11 content, and whether asking for a mid-stream IDR actually yields one. |
| `codec_probe.cpp` | – | The measurement program above. |
| `encoder_test.cpp` | libdrc built | Encodes exactly as the streamer does (`854×480`, I420, CQP 32, main, cabac, `b_drh_mode=1`) and checks the 5-row-chunk contract; `file` mode emits a standalone stream for `ffprobe`. |
| `streamer_capture.cpp` | libdrc built | Loopback streamer driver that writes raw-IPv4 pcap (linktype 101) for Barista's reconstructor. |
| `streamer_smoke.cpp` | libdrc built | The smoke-test program. |
| `protocol_test.cpp` | – | Serialise→parse→compare round-trip tests for libdrc's hand-packed video/command bitfields (an asymmetry between `Set*` and the accessors would silently corrupt every frame). |
| `scheduler_test.cpp` | libdrc built | Tests the two replacement components for the streamer defects: the in-frame **packet schedule** and the **IDR policy** (previously every heartbeat became an IDR, and there was no in-frame pacing). |
| `sps_probe.c` | drc-x264 built | Dumps the SPS/PPS our x264 actually emits, to diff byte-for-byte against the pad's hardcoded sets (`67 64 00 20 ac 2b 40 6c 1e f3 68` / `68 ee 06 0c e8`). |
| `encode_dump.c` | drc-x264 built | Encodes with libdrc's exact settings, then prepends those exact pad parameter sets and decodes with ffmpeg — proves pad-compatibility offline (a `frame_num` width mismatch fails immediately). |
| `analyze_vstrm.py` | – | Live-stream reassembly and envelope check against `CODEC-SPEC.md` §1.3. |
| `score-live-session.py` | – | Scores a live capture against decrypted ground truth: fps, datagrams/frame, chunk-end/frame-end counts, payload sizes, ext-option bytes, IDR marking, and whether `init` appears **only** on the first frame. |
| `uvc-exchange.py <pcap>` | – | Scores the UVC/UAC (query type 1) exchange and the pad's input trend from a plaintext AP capture. **Classifies by payload signature, not length** — the pad's reply is 24 B while the query is 56 B, and a length test scores every reply as missing (that mistake produced a confidently wrong root cause). Reports the query:reply ratio, the resync rate, and the input rate per 10 s bucket so a sleeping pad cannot be mistaken for a working one. |
| `stability-watch.py --minutes 8` | ✔ | Samples a live session every 30 s (short plaintext captures) and records video rate, fps, timestamp delta, clock domain, input rate and resync rate per window, then summarises: windows with no video, windows where the pad was idle, min/median/max fps and delta. This is how the "video dies but the wire looks perfect" states were separated from "the pad went to sleep". |
| `pcap-to-replay.py` | – | Turns a capture of **our** stream into a replayable media file, so console bytes and our bytes can be A/B'd through the identical replayer and clock path. |
| `agent-chunk-audit.py` | – | Bit-level audit of the H.264 payload at the level the pad's decoder consumes: per-frame, per-chunk CABAC byte ranges with no SPS/PPS/slice headers. |
| `agent-pad-clock-scan.py` | – | Read-only scan for any pad→console field that ticks like a clock/counter. |
| `agent-vstrm-census.py` | – | Full byte census of the VSTRM header, console vs ours (this is what withdrew the "4+6-bit sequence" claim: `seq = (b0&3)<<8 | b1` is a clean 10-bit counter, byte-identical to libdrc). |

### 09-rce-hunt — attack surface of the pad

> Scope note: all of this was run against the owner's own GamePad on an isolated 5 GHz link,
> from the impersonated console side. Probes are tiered so read-only work is separable from
> state-changing work.

| Tool | Class | Purpose |
|---|---|---|
| `probe-readonly.py` | read-only | Enumerates the command plane using only documented *read* methods (`sc-cmd.rst`) and records exactly what replies — the recon instrument, not the fuzzer. |
| `inventory_cmd.py`, `mine_cmd.py`, `tools/cmd_scan.py`, `tools/parse_truth.py` | offline | Parse the decrypted console dumps: which methods the console actually uses, with tid/fid decoding matching `pad-state.py`. `parse_truth.py` is the reproducible 1,000-line parser every other offline tool's formats derive from. |
| `tools/make_cmd.py` | offline + builder | Builds console-shaped `50023 → 50123` packets and self-tests the builder against the console's own captured bytes. |
| `safe-sweep.py` | state-probing | E1+E2: does a 1-byte selector passed to `svc 0/0x0a` / `svc 4/0x01` index a table out of bounds — OOB read leaked in the reply, or a wedged handler? Neither outcome touches flash. |
| `frag-probe.py` | state-probing | E5: keeps the outer envelope identical and lies about the inner `payload_size` (`0x0404 = 1028` in the real `M M M S` groups) to test whether reassembly trusts the declared size over the datagram size. |
| `ir-probe.py` | state-probing | The `ir` manager (TV-remote path, payload *and* reply capped at 520 B): over-claim, reply-length, and selector hypotheses. |
| `ir-sniff-probe.py` | state-probing | Same probes without owning `udp/50023` (needed when another session holds it): send from an ephemeral port and read the pad's type-1 ACKs / type-2 replies off the AP interface. |
| `ir-deep.py` | state-probing | Deep IR probes, run while the pad is **armed** — before arming, `ir` answers nothing but `9004`; armed, `svc 5/0x11` opcode `02` returns a 520-byte body, the largest attacker-readable reply the pad offers. |
| `pad-update-probe.py` | **tiered** | The firmware-update path. Dry-run by default; `--send` transmits only P0 (read-only queries); P1 (abort/end) needs `--send --state-probes`; P2 (reboot into firmware-update mode) needs an explicit further flag. |
| `await-and-probe.sh` | wrapper | Waits for the pad to be awake (liveness signal = its own 50122→50022 input stream) and then immediately runs the sniffing probes. |
| `dhcp-probe.py` | network | Minimal DHCP responder used to diagnose a pad stuck in DISCOVER: `netboot`'s OFFER omits options 1 and 3 and advertises `PXEClient`. The fix it proved: also send a **unicast** OFFER to `192.168.1.11:68` (see Round 14b). |
| `fetch_page.py` | offline | Doku-wiki page → plain text (read-only research helper). |
| `tables/` | data | `facts-06-vstrm.txt`, `port50023-records.tsv`, `port50123-records.tsv`, `frame0-packets.bin`, `uic-1040-record0.bin`, `uic-792-reply0.bin` — the parsed reference data the probes use as ground truth (the `uic-*.bin` files are single captured records/replies from the pad). |

### 10-build — reproduce the binaries

| File | Purpose |
|---|---|
| `Dockerfile` | `drcbuild:20.04` — Ubuntu 20.04 because `drc-hostap` is 2016-era code that dereferences OpenSSL structs made opaque in 1.1+, plus the ffmpeg/nl/SDL deps. |
| `inner-build.sh`, `inner-build2.sh`, `inner-build3.sh`, `inner-build4.sh`, `inner-build5.sh` | The five build rounds, each fixing the previous failure (OpenSSL 1.0.1u, `-fPIC` for the static x264, library link order, `DT_NEEDED` via a shared x264). Their headers are the changelog of every build failure in this project. |
| `build-hostap-2.12-native.sh` | Builds hostapd/wpa_supplicant **2.12** with `CONFIG_TENDONIN` natively on Kali (gcc 16 / OpenSSL 3) — no container, no 2013 toolchain. Verified: Nintendo selectors `0xa4c0e104`/`0xa4c0e102` present in the binaries. |
| `build-libdrc-in-container.sh`, `build-client-in-container.sh`, `rebuild-x264-container.sh` | Targeted container rebuilds against our x264/libdrc into `out/`. |
| `pibuild.sh` | The arm64 equivalent for the Pi (vendored OpenSSL 1.0.1u, gcc-12 for old C or glibc or libdrc's `<cstddef>` needs — see `00-docs/SETUP.md`). |

### 11-patches — what was actually changed

`pc2drc-local-work.patch` (**39 files, +1636/−227**, regenerated 2026-11-04 Round 17) — the
local work on top of upstream `thefloppydriver/pc2drc`. Verified to apply cleanly to a fresh
`git archive HEAD` of the vendored tree (`git apply --check` clean; the applied tree contains
the keepalive, the UVC exact-payload path, the new `session-push` files, the client's touch/
stick/input-log changes and the x264 `log2_max_frame_num` fix).

| Area | Files | Change |
|---|---|---|
| Paced sender | `src/video-streamer.cpp`, `include/drc/internal/video-packet-schedule.h` (new) | Spreads a frame's datagrams across the frame interval instead of bursting them (`DRC_FPS`, no in-frame pacing before). |
| IDR policy | `include/drc/internal/idr-policy.h` (new), `src/streamer.cpp` | Stops turning every heartbeat into an IDR; rate-limits to `DRC_IDR_MIN_US`. |
| TSF domain | `src/tsf-linux.cpp` | `DRC_TSF_OFFSET_US` (read every second from `/var/run/drc/tsf-offset-us`) and the `DRC_SYNTHETIC_TSF` fallback. |
| Console parity | `src/streamer.cpp`, `src/uvcuac-synchronizer.cpp`, `src/cmd-packet.cpp`, `src/audio-streamer.cpp`, `src/vstrm-packet.cpp` | Console-measured envelopes: format message bytes, `DRC_FORMAT_OUTER`/`DRC_FORMAT_LEAD_US`, the 1 Hz `50025→50125` table, `DRC_QUIET_CMDS`/`DRC_SEND_UIC`/`DRC_SEND_UVCUAC`/`DRC_SEND_TIME` bisect knobs, `DRC_ARM_BURST`. |
| Encoder knobs | `src/h264-encoder.cpp` | The `DRC_*` x264 knobs used by `drc-sweep.sh`. |
| drcvncclient | `src/drcvncclient.cpp` | Follows the VNC server's real size (x11vnc yields **848×480**, never 854) for both the SDL path and touch→pointer mapping. **Round 17:** touch-down/up now press and release `rfbButton1Mask` (a tap could never click before), the pointer starts at desktop centre instead of `(0,0)`, left stick = relative pointer motion / right stick = wheel (`DRC_STICK_SPEED`, `DRC_STICK_INVERT_Y`), `DRC_INPUT_LOG=1` prints the raw button bitmask, and a `/var/run/drc/tsf-reset` marker makes it re-arm + re-init after a phy clock step. |
| Session push | `include/drc/internal/session-push.h` (new), `src/session-push.cpp` (new), `src/streamer.cpp` | Replays the console's 782-datagram `svc 0/0x11` state push (plus the `0/0x12`+`4/0x21`+`4/0x1a` tail) per pad session, from the console's own captured bytes and cadence. |
| Command keepalive | `src/uvcuac-synchronizer.cpp` | Sends the console's continuous `svc 0/0x00` query (~1/s for the whole session; we previously sent it once), `DRC_UVC_EXACT=1` to send the console's byte-exact 48-byte UVC capsule instead of libdrc's memset zeros, a reply-size guard before the stock `d[0..14]` decode, and `DRC_UVC_LOG=1` per-attempt logging. |
| hostapd | `src/ap/{beacon,ieee802_11,ieee802_11_ht,ap_drv_ops}.c`, `defconfig` | Nintendo OUI advertisement / HT-IE handling; `CONFIG_TENDONIN` on. |
| x264 | `encoder/{encoder.c,set.c}` | DRH mode packaging + forcing `log2_max_frame_num_minus4 = 4` (8-bit `frame_num`), without which every slice header desynchronises against the pad's hardcoded SPS. |

* `pc2drc-local-work.diffstat.txt` — the per-file diffstat of that patch (39 files, +1636/−227), the quickest way to see the blast radius before applying it.

`0001-paced-sender-and-idr-policy.patch` is the earlier, formatted subset of the same work
(`research/patches/`), kept because it is `git am`-able on its own.

---

## Reference data

**Addressing** (as configured by `drc-up.sh` / `03-ap.sh`):

| Role | Value |
|---|---|
| Console address we impersonate | `192.168.1.10` |
| GamePad | `192.168.1.11` |
| Pad MAC (observed) | `40:d2:8a:17:e2:09` |
| Console BSSID / SSID | `cc:fb:65:b6:81:69` / `WiiUccfb65b68169` |

**Ports** (from libdrc `include/drc/streamer.h`, cross-checked against
`libdrc.org/docs/re/services.html`):

| Service | Our side | Pad side |
|---|---|---|
| Video | sends from `50020` | → `50120` |
| Audio + format | sends from `50021` | → `50121` |
| Input | binds `50022` | ← `50122` |
| Command | binds `50023` | ↔ `50123` |
| Message / resync | binds `50010` | ← `50010` (4-byte `01 00 00 00` per failed frame) |
| Extra table | sends from `50025` | → `50125` (1 Hz, 96 B) |
| DHCP | `netboot` (broadcast **and** unicast to `.11:68`) | ← `68` |

**Environment knobs** (implemented in the patched `pc2drc` tree, i.e. inside
`11-patches/pc2drc-local-work.patch`; settable through `DRC_EXTRA_ENV` in `drc-up.sh`):

| Knob | Default | Effect |
|---|---|---|
| `DRC_SYNTHETIC_TSF` | unset | `1` = use the monotonic clock instead of the patched-mac80211 sysfs TSF node. |
| `DRC_TSF_OFFSET_US` | `0` | Media clock offset into the pad's epoch; `align-clock.sh` maintains it. |
| `DRC_QUIET_CMDS` | `0` | `1` = media only, no command plane (bisect baseline — but see the arming caveat). |
| `DRC_SEND_UIC`, `DRC_SEND_UVCUAC`, `DRC_SEND_TIME`, `DRC_SEND_BACKLIGHT`, `DRC_SEND_50125` | `1` | Individually switch off one command-plane message. |
| `DRC_ARM_BURST` | `0` | Send the console's pre-video arm burst. |
| `DRC_FORMAT_OUTER`, `DRC_FORMAT_LEAD_US` | console-parity values | Video-format message bytes 4..7 and the format→first-video lead. |
| `DRC_FPS` | `59.94` | Frame interval used by the pacer. |
| `DRC_IDR_MIN_US` | – | Minimum spacing between forced IDRs. |
| `DRC_PRESET`, `DRC_PROFILE`, `DRC_QP`, `DRC_KEYINT`, `DRC_DEBLOCK`, `DRC_SLICES`, `DRC_THREADS`, `DRC_CABAC`, `DRC_8X8`, `DRC_REFS`, `DRC_BFRAMES`, `DRC_DRH`, `DRC_INTRA_REFRESH`, `DRC_SCENECUT` | libdrc defaults (`preset=slow`, CQP 32, `drh=1`) | x264 parameters, swept by `drc-sweep.sh`. |
| `DRC_WAIT_PAD`, `DRC_WAIT_SECS` | `1` / – | Wait for the pad before streaming (keep this on). |
| `DRC_EXTRA_ENV` | unset | Pass-through for any `DRC_*` above. |
| `RADIO`, `CHANNEL`, `VNC`, `TRUTH`, `TS_BASE` | `wlan0`, `149` (drc-up) / `36` (03-ap), `127.0.0.1:5900` | Script-level selectors. |

---

## Operating rules this project learned the hard way

These are load-bearing; every one of them was written after a run was voided or a machine
lost its network.

1. **Never use the radio that carries the default route.** `drc-up.sh` refuses to start; the
   uplink must be a different card (`wlan1`/dongle).
2. **No `pkill -f <pattern>`.** It matches the invoking shell's own command line — it killed
   this project's terminal several times. Kill recorded PIDs only (`drc-down.sh`).
3. **One hardware owner at a time.** `SO_REUSEADDR` lets a second binder on
   `192.168.1.10:50023` succeed silently and split the pad's replies; two sessions can
   deauthenticate the pad under each other. Take an `flock` on `/var/run/drc/hw.lock` around
   anything that deauths the pad or binds 50023.
4. **Check arming before believing a score.** Unarmed, the pad ignores video and requests
   **0** resyncs — that is not success. A valid run shows `done: N reply packets received`
   with N > 0, a recorded state index, and `svc 5/0x15` (brightness read) returning `err=0`.
5. **`netboot` must own both DHCP sockets** (`255.255.255.255:67` **and**
   `192.168.1.10:67`) and must also send a unicast OFFER to `192.168.1.11:68`. Check
   `sudo grep -c "Can not bind" /var/log/drc-dhcp.log` before trusting any run.
6. **Start children with `setsid`.** A plain `nohup … &` inside a `sudo sh -c` wrapper dies
   with the wrapper, leaving the pad talking to a closed port.
7. **The pad must be associated before capture/media start** (`_wait-for-pad.sh`), or the one
   frame carrying the VSTRM `init` flag is emitted before the pad can receive it.
8. **iwlwifi is single-channel and self-managed.** A monitor vif follows the uplink's channel;
   LAR marks 5 GHz `no IR` while the radio is idle, so an idle `wpa_supplicant country=CA` is
   started on the AP phy or hostapd dies with `-3`.
9. **A capture needs the handshake in force for that session** — start capturing before the
   pad associates, and power-cycle the pad inside the window.
10. **Monitor vif and associated STA cannot coexist on brcmfmac** (`-95`), and a plain
    down/up of `wlan0` breaks it for good; the Pi scripts sacrifice networking deliberately
    and always restore it in an `EXIT` trap.

---

## Round 17 rules (learned the expensive way)

- **The pad's screen is the only judge.** Resync rate is *not* a decode-failure metric: the pad
  emitted 20-60/s while displaying video correctly, in three separate operator-confirmed runs.
  The console's "3 resyncs in 300 s" was three datagrams inside 23 ms — one transient.
- **The media clock must be the AP's TSF.** Video datagrams carry a µs timestamp the pad
  schedules against; an epoch from "when the streamer started" is a domain the pad cannot
  resolve. Seed it from a live TSF sample *before* starting the streamer.
- **A helper that fails silently costs you the project.** `tsf-from-monitor.py` computed the
  right offset, needed a pid that did not exist yet, printed nothing and wrote nothing — so the
  offset stayed at 2 s for every run of the project.
- **Classify packets by content, not length.** The pad's UVC reply is 24 B while the query is
  56 B; a length filter scored 101 answered queries as 0 and produced a confidently wrong root
  cause.
- **`udp.length` includes the 8-byte UDP header.** Twice an "8-byte discrepancy" was arithmetic.
- **A monitor capture alongside the AP is expensive.** It made this AX210's firmware crashes
  more frequent; sample the TSF once a minute instead.
- **`pkill -f run/uvc-live.sh` kills your own shell** (the pattern matches the invoking command
  line). Use `04-stack/uvc-kill-live.sh`.
- **Check whether the radio is transmitting, not whether its daemon is running.** `hostapd`
  alive with flat `tx_packets` is a dead AP; `04-stack/ap-health.sh` is that check.

---

## Where to start

| I want to… | Do this |
|---|---|
| understand the link without any hardware | read `00-docs/RESEARCH.md`, then `00-docs/research/CODEC-SPEC.md`; run `08-tests/run-tests.sh` |
| get a pad on screen from scratch | `00-docs/SETUP.md` §Execution order → `02-bringup/01…05` |
| run the stack I already built | `04-stack/drc-up.sh`, then `04-stack/drc-sweep.sh` |
| reproduce the "display is rejected" result | `06-experiments/phase12-armed-stream.sh` (arm first), then `08-tests/score-live-session.py` |
| capture and decrypt a real console session | `05-capture/12-capture-truth.sh` → `capture5.sh` → `truth-decrypt.py` |
| study the pad's parsers and attack surface | `00-docs/research/rce-hunt/` notes, then `09-rce-hunt/probe-readonly.py` (dry) |
| rebuild everything | `10-build/Dockerfile` → `inner-build*.sh`; or `10-build/build-hostap-2.12-native.sh` |

---

## Attribution

This toolkit is only the local layer. It stands on, and expects to be applied on top of:

* **[pc2drc](https://github.com/thefloppydriver/pc2drc)** (thefloppydriver) — patched drc-hostap,
  drc-x264, libdrc fork, netboot DHCP, kernel patches. `11-patches/pc2drc-local-work.patch`
  applies on top of its `main`.
* **[libdrc](https://github.com/opencma/libdrc)**, **[wozt/libdrc](https://github.com/wozt/libdrc)**,
  **[drc-hostap](https://github.com/opencma/drc-hostap)** (opencma) and
  **[Barista](https://github.com/BetaZay/Barista)** (BetaZay) — local reference clones in
  `research/`, used for docs (`libdrc.org/docs/re/`) and for on-wire tooling.
* **[wiiubrew.org](https://wiiubrew.org/wiki/GamePad)** and libdrc's RE docs — the published
  protocol knowledge (services, `sc-cmd.rst`, cipher details) the tools are written against.

`00-docs/research/WEB-RESEARCH.md` and `00-docs/research/STREAMING-TO-PAD.md` record what was
read, from where, and which claims were later withdrawn.
