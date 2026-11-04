# 07 — Synthesis: one ranked, decision-ready plan (non-destructive ROE)

**Inputs read for this pass:** `01-pad-firmware-update.md`, `02-attack-surface.md`, `04-public-re.md`,
`05-pad-parsers-in-code.md`, plus `BOOT-AND-MODES.md` §5.1/§7 and `GROUND-TRUTH-SESSION.md` §3–§8.
This document creates no new evidence: it merges, ranks and sequences what those four reports already
claim, and says where they disagree. Tool flags below were verified with `--help` / `--list`, not from memory.
**Catalogue correction:** the brief cites "251 cases, 240 SAFE, 11 brick-gated". `run/fuzz-pad.py --list`
actually prints **243 cases (cmd=127, vstrm=62, astrm=54): 232 SAFE, 11 BRICK** (`--only SAFE` is the default).

## 1. Executive summary

1. **Two promising RCE primitives, different in kind.** (a) The **firmware-update path** (`cmd svc 0 / 0x02,0x03,0x04`)
   is the only route where every link is independently verified — CRC32 only, no signature (01 §3), two public tools
   flash custom images to real pads, melonpad proves custom ARM9 code drives the LCD. (b) **VSTRM structural fields**:
   declared `payload_size` vs delivered bytes at the 1694 edge, the 8-byte ext-option area, chunk/frame bookkeeping.
2. **For today's campaign (b) is ranked #1 and (a) is the ranked #1 capability** — (a) is destructive and parked (§4).
3. **The likeliest way to end up driving the LCD is not memory corruption**: 04 §5.7 finds no crypto/authorisation
   gate on the display, only a state machine — so protocol fidelity (UVC/UAC `byte[0]`→1, ASTRM format ~5 ms ahead,
   console option order, 50025 table, resync rate → 0) is the cheap route; arbitrary pixels need ARM9 code, i.e. (a).
4. **No candidate in any report is a confirmed bug** (02 §5). (a)'s artefact facts are VERIFIED, its transport from
   our DRH is INFERRED (very high) and untested; every other row is INFERRED or SPECULATIVE.

## 2. Ranked candidate table

Merged across the four reports; duplicates collapsed. `D?` = destructive under the operator's ROE.
Confidence: **V**=VERIFIED, **I**=INFERRED, **S**=SPECULATIVE.

| id | primitive | where | pre-conditions | what it buys | conf | D? | evidence pointer |
|---|---|---|---|---|---|---|---|
| **F1** | update start/block/end = **unauthenticated code install** (`svc0 0x02/0x03/0x04`) | cmd → LVC loader + SPI flash | `svc4/0x01` payload 2 first; `0x02` payload meaning + `block_idx` base/unit + CRC rule all **unknown** (U3/U4/U5) | arbitrary ARM9 code → framebuffer, LCD, persistence; the display gate stops mattering | V (no sig, CRC-only) / I (transport) | **YES — parked** | 01 §0,§2,§3,§4.4; 04 §2 + #1; 02 F1; cases `cmd/brick.update_*` |
| **F2** | `svc0/0x03` `block_idx` u32 bounds (0 / 0x7FFFFFFF / 0xFFFFFFFF) | cmd → nvram | F1's state gate must be open | OOB flash-index write inside the update manager | I | **YES — parked** | 04 #3; 02 §4.3; `cmd/brick.update_block` |
| **V1** | VSTRM declared `payload_size` (11 bits, b2[2:0]+b3) vs bytes actually delivered, at the 1694 edge | 50120 | pad associated + in AV session; needs a stream it parses at all | reassembly/decoder copy whose size comes from the wire — the only field that scales a copy | I (edge measured by one fork only) | no | 05 §1.2, P1; 02 V1/V2, E3; cases `vstrm/size.{grow,shrink,jumbo}`, `vstrm/plen=*` |
| **V2** | ext-option area bytes 8–15: `0x85` NumMbRowsInChunk, `0x83` Force Decoding, order, terminator | 50120 b8–15 | as V1 | per-chunk buffer sizing from our count; `0x83` is a firmware-sanctioned "decode anyway" switch | I (order-sensitivity unresolved, §3.2) | no | 05 §1.4, P3,P4; 04 §4.2 + #2; 02 V3/V4; cases `vstrm/ext.*` |
| **V3** | chunk/frame bookkeeping: 25 datagrams all `chunk_end`, no end flags, reversed, duplicated head, two frames interleaved | 50120 flags b2 | as V1 | geometry/framebuffer overrun; decoder state confusion | S | no | 02 E4, §4.4; `vstrm/chunk.*` |
| **M1** | cmd fragment reassembly: 12-bit `fid`/`tid`, FIN rules, declared 1028 vs short delivery | 50123 | cmd plane live, **single** owner of 50023 | heap/BSS overflow in cmdmgr, or OOB read leaked back in a reply | I | no | 02 M3/M4, E5; 05 §2.4, P6; `cmd/fragmenta`, `cmd/payload.{t,e,i}` |
| **M2** | generic inner header: magic/version/tid/fid/flags/error/size, `svc`/`method` 255 | 50123 | as M1 | parser confusion, dispatch into unmapped handlers, oversized declared length | I | no | 05 §2.2, P2, P7; `cmd/gen.*`, `cmd/outer.*` |
| **E1** | `svc0/0x0a` index 5…255 (documented 0…4) | 50123 | as M1 | 4-byte OOB read → memory disclosure (addresses for everything else) | I | no | 02 E1 — **no catalogue case**, see §4 step 6 |
| **E2** | `svc3/*` (0x03 phy, 0x04 pkt, 0x05 wmm, 0x06 rssi) selector 0…255 | 50123 | as M1 | up to 448-byte OOB read | I | no | 02 E2 — **no catalogue case** |
| **E3** | `svc5/0x11` IRCOM 520 B, `svc5/0x10` ICTAG 531 B | 50123 → IR/NFC | IR/NFC session armed (**unknown, never observed**) | a real peripheral-stack overflow | S | no | 02 I1; 05 §2.5 |
| **A1** | ASTRM PCM declared 16-bit length vs 1664 real; 32-byte format body | 50121 | stream live | audio-parser copy; format-message parser (pad sizes it by datagram length, measured) | I (format) / I (PCM) | no | 05 §3.2, §3.3, P5, P8; 02 A1/A2; `astrm/*` |
| **T1** | the 96-byte 50025 table (magic `5a a5`, u16 counter@6, ramp) | 50125 | stream live | unknown parser, unmodelled anywhere; also a display-gate input (§5) | S | no | 02 §4.6, T1; GT §4; 04 unknown #3 — **no catalogue cases** |
| **G1** | 50110 `msg` service (also the resync channel) | 50110→50010 | cmd plane live | unknown parser; the first new fact would be any reply | S | no | 02 §4.7, G1 — **no catalogue cases** |
| **D1** | DHCP reply options (1/3/6/15/51/52/58/59, `hlen`, overload, no `0xFF`, overlong option) | pad's DHCP client | pad must (re)associate/boot with our DHCP | code exec **before** everything else; **self-healing** | I | no | 02 §4.8, E8 — **no catalogue cases**; `--dhcp-port 16767` |
| **R1** | EAPOL key-data KDE + beacon/RSN IE abuse | 802.11 M3 (pad's BCM4319) | pre-auth, we own the AP | radio-side compromise; does **not** reach the framebuffer | S | no | 02 R1/R3, E10; 04 #7 |
| **U1** | `svc5/0x0c` UIC EEPROM write (index/len, 258 B) | 50123 → UIC EEPROM | 768-byte dump taken first (we already have one) | persistent settings/UIC-side overflow | I (one known-valid tuple) | persistent — **gated** | 02 E6; `cmd/brick.eeprom_write` |

**Where the reports disagree on ranking.** 04 puts the firmware path at #1 on *evidence density*; 02 puts it
4th because it scores only what is remotely reachable against a *stock* pad without flashing; 01 calls it the
cheapest route to *code* but "probably not the fastest" to the LCD and tells us to keep the UVC/UAC track.
All three can be true: F1 is the strongest capability, V1–V3 is the best thing to do **today** under this ROE.
04 §4.2 also flags that the decoder's real output width (854 vs 864) is unpublished, which decides whether the
`0x85` class can overflow anything at all — 02 and 05 both assume it can.

## 3. The three contradictions, and what the live tests must assume

**(3.1) VSTRM sequence packing — GROUND-TRUTH is wrong; 05 §0 is right. Assume 05 §0.**
`GROUND-TRUTH-SESSION.md` §4 (and the rows built on it: §6 item 4, §7, §10) says the console puts
`b0 = 0xF0 | seq[9:6]`, `b1 = seq[5:0]` — 4+6 bits, and concludes our 2+8 packing "differs, tolerated".
05 §0 re-derived the same file and measured: byte 0 takes **4 distinct values** (`f0`–`f3`, i.e. a 2-bit
field), byte 1 takes **all 256 values** (impossible for a 6-bit field), and the 2+8 decode yields **9**
sequence discontinuities in 73,499 transitions versus **941** for the 4+6 decode. So console == libdrc ==
Barista == our build. *Live-test consequence:* any seq/continuity oracle reused from GROUND-TRUTH (or from
`tests/analyze_vstrm.py:37`, a third 12-bit variant) is mis-specified and will report phantom loss —
standardise on `seq = ((b0 & 0x03) << 8) | b1`, mod 1024, and void the GROUND-TRUTH §7/§10 rows.

**(3.2) Ext-option ordering — genuinely unresolved, treat any "order matters" result as unproven.**
Structural conflict inside 05 §1.4: libdrc pre-fills `83 85 06` then appends `80`/`82`, and our local fork
measured on 2026-11-04 that with `83 85 06 [80] 82 00` *"the pad then never starts decoding (zero resync
requests)"* — yet **Barista runs that same default order on real hardware** and only reproduces console order
under `DRCD_REFERENCE_VIDEO_OPTIONS`. Two observations, opposite outcomes, different everything-else. The
honest reading (05's own word): *an order-sensitive path exists, the rule is unknown, INFERRED.*
*Live-test consequence:* always emit console order (`80 82 00 83 85 06 00 00` IDR / `82 00 83 85 06 00 00 00` P)
— our build already does — and when testing order, vary **only** bytes 8–15 of an otherwise byte-identical
console frame, one option per case, ≥3 datagrams per value, and read the resync rate. Never attribute a paint
failure to option order when another field also changed: that is exactly how the 2026-11-04 conclusion got made.

**(3.3) Payload-cap edge — 1694 is measured, 1700 is one fork's comment. Assume 1694 safe, 1695–1699 unknown.**
Three numbers are asserted: **1400** (libdrc/wozt `kMaxVstrmPayloadSize`, rationale "MTU ≈1800"), **1694**
(console max, measured `[M]`; Barista `kMaxVideoPayload`; local fork), **1700** (wozt's single comment: "at 1700
the GamePad stops decoding outright"). 02 §5 derives the buffer edge as **(1694, 1699]**; 05 §1.7 writes
**(1694, 1700]**. 02's tighter bound is the one to trust — wozt's "stops at 1700" implies the cap is ≤1699 —
but it rests on one un-repeated measurement, and the "the ~1793-byte frames are audio not video" clause in the
same comment is demonstrably wrong (05 §5), which weakens the whole note. *Live-test consequence:* 1694 is
console-proven safe and stays the default; 1695–1700 is the probe band, bisected one byte at a time. Note the
catalogue's first over-delivery step is `grow+1` (1695) then `grow+16` (1710) — **there is no case at exactly
1696…1700**, so this band needs `--mutate-from`, not the built-in list.

**Not a contradiction between reports, but the live-test trap to settle first (step 2):** `error 9004` /
`NOREPLY` on a pad that is demonstrably alive. `BOOT-AND-MODES.md` §11 attributes exactly this pair to two
sockets bound to `192.168.1.10:50023` (SO_REUSEADDR split: "indistinguishable from a dead pad"). The 10:15:52
run in `out/evidence/rce-ro-1015/results.json` shows a pattern that is *not* obviously random: `svc1/0x05`,
`svc5/0x15`, `svc0/0x00` — all of which returned real bodies at 09:13 in §5.1 (113 B / `4` / 8 B) — returned
`9004`, `9004` and **zero ACKs, no reply**, while `svc0/0x0a` (×5), `svc2/0x00`, `svc4/0x04`, `svc4/0x05` and
`svc5/0x06` (772 B) answered normally and input flowed at 63–77/s. That run's probe would not have completed if
a competing non-reuse binder owned 50023 (its working socket binds plainly), but its own competition check sets
`SO_REUSEADDR` (`probe-readonly.py:205-217`) and so cannot see a reuse-flagged peer — **so "the pad really said
9004" is the better reading, and a per-method/state gate is the better hypothesis, still unproven.** Confirm
with `ss -lunp | grep ':50023'` before/after (step 2) before building anything on it.

## 4. One ordered live-test campaign (pad powered, one session, ROE-compliant)

Preconditions: console **off** (identity collision, BOOT-AND-MODES §8); pad associated to `WiiUAP` on our PSK;
AP radio ≠ uplink radio; pad reachable at `192.168.1.11`. Every command below uses only flags verified by
`run/fuzz-pad.py --help` and `research/rce-hunt/probe-readonly.py --help`. **Never pass
`--i-understand-brick-risk`, never pass `--force`.**

**Step 0 — offline preflight (transmits nothing).**
`python3 run/fuzz-pad.py --selftest` → `python3 run/fuzz-pad.py --dry-run --record /tmp/fz0 --plane cmd --family payload`
→ `python3 research/rce-hunt/probe-readonly.py` (dry run = hexdump).
*Pass:* selftest green including the exclusive-bind guard; dry-run writes `case-N.bin`. *Fail:* stop — the
codecs or the binder guard are broken and nothing after this is attributable.

**Step 1 — take the air, then free 50023 for exactly one owner.**
`sudo run/drc-down.sh` → `sudo run/drc-up.sh` (AP + DHCP + full stack; pad re-associates in ~10 s) →
`kill "$(cat /var/run/drc/streamer.pid)"; rm -f /var/run/drc/streamer.pid` → `ss -lunp | grep -E ':(50023|50022)\b'`.
*Watch:* hostapd assoc of `40:d2:8a:17:e2:09`; pad input datagrams on 50122.
*Pass:* `ss` output **empty** for 50023 (AP+DHCP live, cmd plane free). *Kill criterion:* anything still bound
→ do not run any fuzzer; that state is the 9004/split trap and every verdict afterwards is noise.

**Step 2 — baseline + the 9004 discriminator (this is a gate, not a formality).**
`sudo python3 research/rce-hunt/probe-readonly.py --send --out out/evidence/rce-ro-$(date +%H%M)`; wait 10 s;
run the identical command again into a second `--out` dir; compare both against `rce-ro-1015` and §5.1.
*Pass:* the same query set answers both times (bodies and 9004 alike reproduce) **and** `ss -lunp |
grep ':50023'` shows only the probe ⇒ it is a real method/state gate; record it as the diff baseline for the
whole campaign. *Fail/informative:* the set **changes** between two passes with nothing else touching 50023, or
`ss` shows a second socket, ⇒ reply-splitting or a live state transition — stop and re-do step 1.
*Watch:* `svc 4/0x05` index, `svc 0/0x00` 8-byte version, `svc 5/0x06` 772-B digest.

**Step 3 — cmd plane, SAFE only, one family at a time** (`--only SAFE` is the default but state it; SAFE
excludes all 11 `brick` cases by construction and the driver re-checks every datagram):
`sudo run/fuzz-pad.py --live --record out/fuzz/cmd1-$(date +%H%M) --only SAFE --plane cmd --family control --family outer --family gen --deadman 3 --max-rate 20`,
then repeat with `--family fragmenta`, then `--family payload`. *Watch:* the per-case verdicts (`OK/LATENCY/NOACK/NOREPLY/STATECHANGE/GONE`) plus the
oracle columns (state index, LVC version, input rate) and `verdicts.jsonl`.
*Pass:* every case `OK`/`NOACK`, state index constant, LVC version constant. *Lead:* `LATENCY`, `NOACK`, or any
`reply_changes` > 0 — replay that case alone (`--replay out/fuzz/cmdN-*/case-K.bin --replay-port 50123`).
*Kill:* 3 consecutive `GONE` (deadman fires) → power-cycle the pad, then replay only the last case; if the pad
does not return after two cycles, halt (UART is not yet built — §4 parking lot).

**Step 4 — VSTRM, the ranked-#1 memory surface.** Same shape, but the pad's *decode* signal is invisible to
this tool (it does not listen on 50110→50010 — see §6): the only signals here are input rate, cmd replies and
state index. `sudo run/fuzz-pad.py --live --record out/fuzz/vstrm1-$(date +%H%M) --only SAFE --plane vstrm --family size --deadman 3`, then `--family ext`, `--family header`, `--family chunk`, `--family control`.
*Watch:* `GONE` inside `size.grow+1226`, `size.jumbo-4096`, `size.jumbo-65000`, `ext.all-0xff`,
`chunk.*` — a crash-shaped verdict on a length/structure case **is** the finding.
*Pass/fail:* silence + steady input = "no corruption at this value, keep bisecting"; `GONE`/`STATECHANGE` =
replay those cases immediately and treat 1695–1700 (§3.3) as the band to close next.

**Step 5 — ASTRM** (`--plane astrm --deadman 3`), then stop fuzzing. Families `format`, `pcm`, `header.*`;
this is the cheapest path to the paint gate's second half (§5), not to memory corruption.

**Step 6 — the two sweeps the catalogue does not carry** (E1/E2, 256 datagrams each, read-only):
`--mutate-from out/evidence/truth/console-messages --corpus-plane cmd --corpus-port 50123` for a structured
single-byte sweep, or defer to a `probe-readonly` `--only` prefix run. Decide before the session: if the answer
is "defer", say so in the run log rather than discovering it live.

**Step 7 — display gate** (only if steps 3–5 produced no crash): bring the stack back
(`sudo run/drc-up.sh`) and run the §5 ladder. It is the fallback, not the warm-up: it needs 50023 and the
fuzzer needs it exclusive.

### Parking lot (destructive — **not in this campaign**)

| Item | Why parked | Pre-requisite before it may be un-parked |
|---|---|---|
| `svc0/0x02/0x03/0x04` (`brick.update_*`) — F1/F2 | flash write → possible dead pad; ROE forbids 0x02–0x05 and 0x0b–0x0f data/start/end entirely | **UART boot harness built and tested**: pads opened, 2.8 V USB-serial wired, boot ROM dumped/verified via `wupbootdump`; stock `drc_fw.bin` unpacked with `fwpack.py` and held for re-flash; a second/donor pad preferred |
| `svc4/0x01` payload 2 (`brick.reboot_firmware`) | ROE forbids it; if the pad does not re-enter the link, only UART recovers it | same UART harness; verify first that payload `0` is accepted as the undo |
| `svc0/0x0b–0x0f` (`brick.lang_update`) | Service partition is Nintendo's own recovery firmware; UIC upload is documented unreplicable | never on this pad (01 §2.5) |
| `svc5/0x0c` (`brick.eeprom_write`) | persistent settings; the tool classes it BRICK | an explicit operator sign-off + the 768-B dump in hand for rollback. This is the *only* parked item arguably inside the ROE's letter — treat it as a separate decision, not a default |
| `svc4/0x1a` flags 0x42, UVC `f3=1/3` | shuts the pad down / vWii mode — recoverable by the power button, but they end the session and buy nothing | after steps 3–6, one at a time, at the very end of a session |

## 5. The display gate — "the pad never paints our stream", ranked

04 §5.7 is the frame: **no public source describes a crypto or authorisation gate on the display**; the gate
is a state machine. So ranked by "most likely explanation for a silent panel", with the cheapest test that
*separates* it from the others. The discriminator for every row is the same number: **resync datagrams/s from
source port 50110 to our 50010** (console: **3 in 300 s**; our stack: **63/s**). Zero is success.

| # | Explanation | Why it is ranked here | Cheapest discriminating test |
|---|---|---|---|
| 1 | **The pad is stuck in its recovery loop** (we answer a 63/s "would take a keyframe" flood with IDRs, which is the one signal guaranteed to stop a frame completing) | measured on both forks and in GT §6: a healthy session asks 3× in 300 s, ours asks 60×/s; 05 §5 shows "an earlier round re-asserted init on every IDR … makes the failure self-sustaining" | rate-limit IDR (≥1 s debounce, `DRC_IDR_MIN_US`), `init` on the first frame only, and log 50110 datagrams/s. Pass = rate falls. Nothing else changes. |
| 2 | **UVC/UAC keepalive not satisfied** — `byte[0]` must flip 0→1 after the first validated reply, and libdrc says "recent firmware will only show the video stream after receiving one such command" | GT §7 records ours staying at 0 while the console flips; Barista gates readiness on `input_seen && uvc_uac_reply_seen` | one A/B session: `DRC_SEND_UVCUAC=1` with byte[0]→1 after the reply vs `DRC_SEND_UVCUAC=0`, same content, compare resync/s and panel |
| 3 | **ASTRM format message phase/fields** — `16000,16000,21000,21000` (libdrc sends 16000×4 — a real conflict), format ≈5 ms ahead, little-endian ts of the *same* instant, bytes 4–7 zero | 04 §5.2 + 05 §1.5: both are "silently prevent painting" shaped; Barista's decisive capture differed in recovery policy, not the envelope, so this is cheaper to rule out than to prove | byte-diff our 32-byte body against `out/evidence/truth/.../video_format_message.bin`; then vary **only** the `21000` pair and **only** the lead (`DRC_FORMAT_LEAD_US`), one knob per session |
| 4 | **The 50025 table** is absent or wrong (96 B, `5a a5`, counter@6) — 04's unknown #3, "started at exactly the moment the display phase begins" | our build now sends it (`pc2drc/.../src/streamer.cpp:67-125`, socket 50025 → 50125); historically the port was never bound, so "we do not send it" is a *stale* explanation, and "we send it and it still fails" is informative | `ss -lunp | grep 50125` + a capture on 50125 during a session; the sender has **no env knob** (verified in `streamer.cpp`), so the A/B is with it compiled/present vs absent. Pass = no difference (rules it out in one boot) |
| 5 | **Option order / geometry** (§3.2, V2) | our build already emits console order, so this is only live if order-sensitivity is real — and Barista's success with libdrc order says it may not be | one session with `83 85 06 80 82 00` vs console order, byte-identical otherwise, resync/s as the metric |
| 6 | **Encoder output not in the pad's assumptions** (deblocking and `constrained_intra_pred` live in headers DRH never transmits; "anything above medium breaks the decoder") | wozt measured it, and Barista's zero-motion result points at the motion-compensation path | `DRC_PRESET=medium` + `DRC_CABAC=0` A/B, one session, resync/s only |
| 7 | **Not a protocol problem at all** — the pad is in the wrong mode/state (state index 0 = its own notice screen; standby console serving Quick Start looks identical to the operator) | BOOT-AND-MODES §5.1/§8; cheap to exclude and it poisons every other measurement | `svc 4/0x05` before and after the paint attempt; console unplugged, not standby. If the index never moves, stop blaming the stream |

## 6. Gaps, and the cheapest route to closing each

| Missing evidence | Why it blocks | Cheapest route |
|---|---|---|
| **The pad firmware image** (`LVC_`/`WIFI`/`UMI_`) — nothing in this tree (02 §0) | every pad-internals statement in all four reports is INFERRED; no fuzzing result can be explained without it | copy `drc_fw.bin` off **our own console** (MLC or the update title) and `fwpack.py unpack`. Offline, free, no pad involvement. Closes U1 (`blockSize`) and U2 (`sequencePerSession`) today |
| **An `LVC_` disassembly** (U3/U4/U5/U6/U9: `0x02` payload meaning, `block_idx` base/unit, CRC rule, A/B-vs-in-place, anti-downgrade) | this is what gates F1/F2 — the strongest capability in §2 | Ghidra, ARM LE ARMv5TEJ at 0x0, plus `drc-re-scripts` (`explore-file.py`, `find-uitron-apis.py`, `name-funcs-by-src-str.py`); hunt the `sc_cmd`/`mc_cmd` method table and `mc_nvram`. 01 calls this "the single highest-value action in this document" — agree |
| **A console-driven update capture** | the only way to learn the 0x02/0x03 cadence, ACK discipline and block unit without guessing | needs a *donor* pad: run DRXUtil on the console while capturing on a monitor interface. Destructive to that pad ⇒ belongs behind the UART harness, i.e. after the parking-lot pre-requisites |
| **A debug channel** (UIC state 7 ⇒ service firmware: UART shell + flash viewer) | would turn every remaining hypothesis from blind to debuggable | read `FPGApad`/`pinouts` for the expansion-port signature, and test whether state 7 is command-reachable. Also: `wupbootdump` the boot ROM first — free, verified, and needed for UART recovery anyway |
| **1696–1700 exactly**, and "declared 1694 / 20 B delivered" | the catalogue jumps 1695 → 1710; the classic over-claim (02 E3b) has no case (nearest is `vstrm/size.shrink-64`) | `--mutate-from` over a one-datagram seed dir, one value at a time, `--replay` any crash |
| **A resync counter in the oracle** | the fuzzer does not listen on 50110→50010, so a VSTRM case that breaks the *decoder* without killing the pad reads as `OK`. This is the single biggest measurement hole in step 4 | ~3 lines in `fuzz-pad.py`'s oracle (count 50110 datagrams/s, flag a >5/s spike). Not done here — this pass writes no code |
| **`error 9004` semantics** | the §3 note: we cannot tell "unsupported method" from "wrong session state" | step 2's double pass, plus one `svc 2/0x00` (documented "does nothing, returns 0") as a negative control |
| **Decoder output width (854 vs 864)** | decides whether the whole `0x85` class can overflow anything (04 §4.2) | the `LVC_` disassembly above, or Barista's datasheet geometry against a known-good capture — no hardware needed |

**Bottom line.** Run steps 0–5 of §4 to close or refute V1/V2/V3 and M1/M2 with evidence, and run step 7's
ranked ladder for the panel in parallel on a second session. F1 remains the only route that ends with *us*
drawing pixels, and it stays parked until a UART harness and a stock image exist — which are also, conveniently,
the two items that would make every INFERRED row in §2 a fact.
