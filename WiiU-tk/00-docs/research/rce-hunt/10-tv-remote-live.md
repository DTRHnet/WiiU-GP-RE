# 10 — TV Remote / IR: what is verified, what is falsified, and the ready-to-fire probes

Session 2026-11-04 ~10:31–10:40. Non-destructive ROE (no flash writes, no `svc 0` 0x02–0x05/0x0b–0x0f,
no mode reboots, no persistent settings writes). Companion to `09-tv-remote-ir.md` (the research pass)
and `02-attack-surface.md` §4.2 (the ranked candidate list this refines).

## 1. Independently verified: the pad's TV-remote identity is in the UIC EEPROM

I re-derived the EEPROM decode myself with libdrc's own routine
(`research/libdrc/src/device-config.cpp:39-60`: CRC-16, poly `0x8408`, init `0xFFFF`, no final XOR,
CRC stored little-endian immediately after each record) against the dump we took over the air at 10:15
(`out/evidence/rce-ro-1015/uic.fw_and_eeprom.reply.bin`, body = 4-byte UIC fw field + 768 B EEPROM):

| Claim | Check | Result |
|---|---|---|
| Page markers at `0x0fd`/`0x1fd`/`0x2fd` are `03`/`05`/`04` with valid CRCs | `crc16([3])` vs stored u16 | `0x3d1c`, `0x582a`, `0x49a3` — **all three match** |
| `tv_remocon_id1` @ `0x289`, `tv_remocon_id2` @ `0x28e` (libdrc `device-config.cpp:470-473`) | dump bytes | ID1 = **`T0156`**, ID2 = *unset* (`00 00 00 00 00`) |
| that 10-byte record's CRC | `crc16(ee[0x289:0x293])` vs stored u16 @ `0x293` | `0x326b` == `0x326b` — **match** |
| `tv_remocon_version` @ `0x25c` | bytes | `00 00 00 03` → **3** (matches the live `svc 0/0x0a` index-1 reply `03000000`) |

So the pad is configured with exactly one TV-remote code ID, `T0156`, and remote-code version 3. That
`T0156` datum is the only attacker-relevant *value* on this path we can prove, and it makes
`svc 5/0x17` (7-byte payload, first 5 bytes = remocon ID) testable with a real key instead of a guess.

## 2. Two of my own earlier readings were wrong (corrected here)

| Earlier claim | Where | Now |
|---|---|---|
| "the two identical 0x90-byte blocks at 0x0100/0x0180 are TV-remote / remocon slots" | my 10:29 working notes, `09` briefing | **wrong** — they are the A/B duplicated settings banks (board version `8b`, region `01`=North America, volume, gyro cal, touch cal, service version), matching libdrc's read-then-fallback (`device-config.cpp:172-316`) |
| "`IT0156` is the UIC build string" | `08-live-results.md` §2 | **wrong** — `0x288`'s `I` = `0x49` is the page-3 marker CRC byte; the real datum is the CRC-valid record at `0x289`, i.e. remocon ID1 `T0156` |

Also settled: **no IR waveform data lives in the UIC EEPROM.** The 13-byte table at `0x277` is the LCD
backlight level/frequency table (same shape as the `svc 5/0x19` payload), not IR. Carrier frequency and
mark/space data therefore live in the flash **TVcode region at `0x1900000`**
(`01-pad-firmware-update.md` §2.5), which we do not have an image of.

## 3. What that leaves as the exploit hypothesis

The TV-remote path has one property no other path in this hunt has: **`svc 5/0x11` (IRCOM) replies with up
to 520 bytes** (`sc-cmd.rst:245-247`, payload *and* reply capped at 520). If the `ir` manager trusts a
declared length, or echoes a stale receive buffer, the reply is an attacker-readable window into LVC
memory — the memory-disclosure primitive the hunt is missing (our only confirmed disclosure so far is the
fixed 772-byte `svc 5/0x06` read).

| # | Case | Datagram (console→pad, `192.168.1.10`→`192.168.1.11:50123`) | If it works |
|---|---|---|---|
| TV1 | bare `receive` (opcode `02`), no prior connect/send | `000000000d00<seq>7e0100080040051100000001 02` | stale IR-receive buffer echoed → RAM disclosure |
| TV2 | 20 B delivered, `payload_size` declared **520** | `000000002000<seq>7e0100080040051100000208 01` + 19×`00` | OOB read of ~500 B, and a copy past a 520-byte IR buffer |
| TV5 | remocon ID `T0156` (the verified ID) + 2 bytes | `000000001300<seq>7e0100080040051700000007 5430313536 0000` | ID resolves → real IR emission (harmless in the lab, but it is a physical side effect) |

## 4. Tooling, ready to fire

| Tool | Purpose | State |
|---|---|---|
| `research/rce-hunt/ir-sniff-probe.py` | 35 IR/TV cases (IRCOM baselines, over-claim `H1*`, opcode confusion `H2*`, `0x16` selector `H3*`, `0x17` ID lookup incl. `T0156` `H4*`, `TV1*` stale-receive repeats) — **never binds 50023**: sends from an ephemeral port and reads the pad's ACKs/replies off `WiiUAP` with an `AF_PACKET` sniffer, so it works while another tool owns the console port | implemented, `--dry-run` clean, `--filter` for subsets |
| `research/rce-hunt/ir-probe.py` | same case set with a proper type-0/1/2/3 state machine and liveness oracle; needs exclusive `50023` | implemented, blocked by port contention in this session |
| `research/rce-hunt/await-and-probe.sh` | waits for the pad's input stream to prove it is awake, then runs the sniffer probe and stores evidence under `out/evidence/rce-ir-live-*` | running |
| `research/rce-hunt/dhcp-probe.py` | diagnostic DHCP responder with a complete option set (mask/router/DNS/lease/T1/T2), used to test why the pad sits in a DISCOVER loop when `netboot`'s offer lacks options 1 and 3 | implemented |

## 5. Why there is no live IR result yet

The pad would not hold still long enough. In this window it oscillated: input streaming at ~180/s
(10:30:35, lease fine) → asleep/DISCOVER loop at 2 Hz (10:31–10:40, `src 68 → dst 67` every ~500 ms, no
`50122` traffic, and every `50023` query unanswered). Two independent contributors, both measured:

1. **Port contention**: a parallel operator session bound `192.168.1.10:50023` (pid 2522640) and
   `50020/50021` (2522946) and was deauthenticating the pad as part of its own anchored-session work
   (`out/logs/phase11b.log`), which is also what produced the spurious "wedge at 0xF6" in
   `08-live-results.md` §4.
2. **The pad sleeps**, and a sleeping pad answers neither `50122` nor `50023` (`BOOT-AND-MODES.md` §10).

The probes need ~40 s of an awake pad. Nothing in the catalogue is destructive, so the moment the pad is
awake with the console port free (or even taken — the sniffer path does not need it) the 35 cases run.

## 6. Live results: the whole IR path is behind `error 9004`

All 37 IR/TV-remote cases were sent to a live, associated, input-streaming pad
(`out/evidence/rce-ir-live-104011/`, 185 replies captured). **Every one answered
`error=9004`, 0-byte body, 5× (the pad retransmits until acked).** No case was
distinguishable from another — payload, opcode, declared size, the real `T0156` ID:
all the same 9004.

So the gate is not in the IR parser; it is above it. The method-gate map measured in the same
pad state (sniffer probe, exclusive sequence numbers):

| Method | Result |
|---|---|
| `5/0x06` UIC EEPROM dump | **`err=0`, 772 B** |
| `4/0x04` version info | `err=0`, 28 B |
| `4/0x05` state index | `err=0`, 1 B (index **12**) |
| `0/0x00` LVC versions | `err=0`, 8 B |
| `5/0x15` LCD brightness (read) | **`err=9004`** |
| `5/0x14` LCD brightness (write) | `err=9004` |
| `1/0x05` Wi-Fi SSID/PSK | `err=9004` |
| `5/0x11` IRCOM (all 22 variants) | `err=9004` |
| `5/0x16` / `5/0x17` (incl. `T0156`) | `err=9004` |

Two conclusions:

1. **The gate is per-manager, not per-sensitivity.** A full UIC EEPROM dump (SSID + PSK) is
   allowed while reading the *brightness level* is refused, so `9004` is not an authorisation
   check. The methods that work are the ones the `cmd` manager serves directly (`0x00`, `4/0x04`,
   `4/0x05`, `5/0x06`); the ones that fail are those needing the `video`, `sound`, `ir` or `nwk`
   managers to be armed. That is the same S7 "AV session arm" state of `BOOT-AND-MODES.md` §3.
2. **Nothing we know how to send arms them.** Sending the console's own captured
   **time command** (`type 0 / query 2 / 8 B`: `a4ef0000305e0000`), the **UVC/UAC query**
   (`type 0 / query 1 / 48 B`, replayed verbatim), and the **state-push fragments** (`svc 0/0x11`,
   1048 B) changed nothing: brightness, Wi-Fi config and IRCOM still returned 9004 afterwards.

**Implication for the TV-remote exploit hunt:** TV1/TV2 (the two candidates that could leak memory
through the 520-byte IRCOM reply) are currently **unreachable**. The parser cannot be exercised until
the pad's `ir` manager is armed, which is the same unsolved session/display gate that blocks video.
The IR path therefore converges with the main problem rather than offering a shortcut around it —
but the moment the gate opens, `ir-sniff-probe.py` runs in 40 s and answers TV1/TV2.

## 7. Unrelated but important: the pad's DHCP oscillation is now explained

While waiting for the pad, the real cause of the "alive ↔ asleep/DISCOVER-loop" flapping was found,
and it is ours, not the pad's:

* `pc2drc/drc-hostap/netboot` sends its OFFER **only as broadcast** to `255.255.255.255:68`.
* The pad never sends a REQUEST against those offers; it re-DISCOVERs with a **fresh xid ~2×/s**
  (measured: `1c32ae37`, `1c38a2e3`, `1c3e9983`, … — a restarted state machine, not a retransmit).
* Adding a **unicast** copy of the same OFFER (to `192.168.1.11:68`, which the pad already holds)
  produced an immediate `REQUEST` → `ACK` → the input stream returned (177 pkt/2 s) and the gated
  methods above became measurable at all.

A DHCP responder that unicasts is in `research/rce-hunt/dhcp-probe.py`
(bind `0.0.0.0:67`, wildcard in **and** unicast out). Any future session that needs the pad to hold
`192.168.1.11` reliably should use it instead of `netboot`, or `netboot` should be patched to
unicast its replies.

## 8. BREAKTHROUGH: the arming replay opens the gate (and what it then exposes)

The console-parity replay already existed as `run/command-plane.py --mode full` (it replays the
captured console's early generic/clock commands, the 4-packet "arm" burst, the 778-fragment
`svc 0/0x11` state push and the post-push tail, ACKing everything). Two runs on 2026-11-04:

```
[7095.114] STATE ? -> 3  (retvals[7]=3)         # run 2
[7060.241] STATE 12 -> 0  (retvals[0]=0)        # run 1 — the pad CHANGED STATE
[7062.250] reply svc 0/0x11 error 9004          # the pad rejects our state push, but the session is open
```

**This is the first time anything we sent changed the pad's state index** (`12 -> 0`, i.e. from the
undocumented "12" into `retvals[0]=0`). With the pad in that state the whole gated surface answers.
Measured back to back, same second, state index 0 (`out/evidence/rce-ir-deep-*`):

| Method | Before arming | **After arming** |
|---|---|---|
| `4/0x05` state | `err=0` body `0c` (index 12) | `err=0` body **`00`** (index 0) |
| `5/0x15` LCD brightness | `err=9004`, 0 B | **`err=0`, 1 B = `04`** |
| `1/0x05` Wi-Fi SSID/PSK | `err=9004`, 0 B | **`err=0`, 113 B** |
| `5/0x11` IRCOM connect (`00`) | `err=9004`, 0 B | **`err=0`, 1 B = `00`** |
| `5/0x11` IRCOM receive (`02`) | `err=9004`, 0 B | **`err=0`, 520 B** |

### TV1 result: a 520-byte reply, but not yet a disclosure

`svc 5/0x11` opcode `02` ("receive") with **no** prior connect/send returns the full 520 bytes:

* state 0: `ff ff ff … ff` (520 × 0xff)
* state 3: `0c 00 00 00 …` (byte 0 = `0x0c`, rest zero, 2 distinct values)

Tests that bound the interpretation:

1. **Not an echo.** We sent 520 bytes of `0xAA` with opcode `01` (send, accepted: 1-byte `00` reply),
   then `02` → the reply was **unchanged** (`0c 00 00…`, no `0xAA`). So the firmware does not hand
   back what it was given.
2. **Deterministic per state.** Three consecutive bare receives returned byte-identical bodies
   (same SHA-256 prefix), so it is a firmware-maintained buffer, not free-running stale RAM.
3. Conclusion: **TV1 currently yields a 520-byte read of an `ir`-owned buffer whose content is
   state-determined.** That is not (yet) cross-object disclosure, but it is the largest
   attacker-readable reply the pad produces, it is reachable with one datagram, and its first byte
   (`0x0c`) is plausibly a length/type field — the obvious next experiments are to make that buffer
   hold something interesting (a send that the pad queues but never transmits, e.g. with no IR
   target/`ir` mode set) and to read it back in a different state.

### TV2 result: sane over-claims are handled; `0xFFFF` is a candidate wedge

Delivering 20 bytes while declaring `payload_size` = 64 / 255 / 520 / 1028 each returned the normal
1-byte `00` (accepted, no extra data, no length echo) — **no leak, and no crash**. Declaring
**`0xFFFF`** was followed by **no reply at all**, and every subsequent case in the run also got no
reply; the pad concurrently showed a fresh association (`connected time 32 s`) and its input stream
stopped.

That is a *candidate* remotely-triggerable wedge of the cmd/`ir` path, but it is **not confirmed**:
a parallel operator session was active, the pad was also drifting into its sleep/DHCP cycle, and the
arming window had ended. It must be replicated as an isolated A/B (N × `declare=520` control vs
N × `declare=0xFFFF`, arm → single case → state poll → 15 s liveness) before it is called a finding.

### Tool notes from this run

* `run/command-plane.py --mode full` exited right after the arm burst on the second run (4 log
  lines, no pump/ACKs), where the first run kept pumping — so the arming is currently a *one-shot*
  window of a few seconds, which is enough (the state change persisted at least ~20 s) but fragile.
  A dedicated arming helper should keep the plane open (pump + ACK) for the whole probe.
* Ops ordering that worked: DHCP responder first (unicast OFFER — `dhcp-probe.py`), confirm the pad's
  input stream > 100 pkt/2 s, then arming replay, then probe within seconds.
