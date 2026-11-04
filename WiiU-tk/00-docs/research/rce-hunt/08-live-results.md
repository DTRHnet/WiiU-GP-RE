# 08 — Live results, and one contaminated run (2026-11-04 10:15–10:26)

Everything here was executed against the operator's powered GamePad
(`40:d2:8a:17:e2:09`, `192.168.1.11`) from this host as the impersonated console
(`192.168.1.10`). Rules of engagement for the session, set by the operator: **non-destructive
only** — no flash writes, no firmware-update data blocks (`svc 0` 0x02–0x05, 0x0b–0x0f), no
reboot-to-update-mode (`svc 4/0x01` payload 2). Malformed-packet probing that the pad survives
with a power cycle is allowed. Nothing in this file wrote to the pad.

## 1. What ran, in order

| # | Time (EST) | Tool | Port 50023 ownership | Verdict |
|---|---|---|---|---|
| 1 | 10:15 | `research/rce-hunt/probe-readonly.py --send` (25 documented read methods) | **shared** with the running `drcvncclient` streamer (both sockets set `SO_REUSEADDR`) | see §2 — partially contaminated |
| 2 | 10:17–10:19 | `run/drc-down.sh`, stale `netboot` cleanup, `run/drc-up.sh` | — | AP + DHCP + streamer healthy; pad associated, input flowing |
| 3 | 10:22 | `safe-sweep.py --send --max-index 24` (96 cases) | exclusive (streamer stopped) | clean |
| 4 | 10:23:15–10:24:14 | `safe-sweep.py --send --max-index 255` (256 cases) | **exclusive until 10:24:01**, then a competing operator process | first 246 cases clean, last 10 unusable |
| 5 | after 10:24 | `probe-readonly.py --send` liveness re-checks | competing `command-plane.py` had claimed the port with `SO_REUSEADDR` | **invalid**, discarded |

## 2. Result 1 — the UIC EEPROM read (the one real information disclosure)

`svc 5 / method 0x06` returns **772 bytes** over the DRC link: a 4-byte UIC firmware field
followed by the **first 768 bytes of the UIC EEPROM**, in the clear, to anyone holding the PSK
(i.e. anyone the pad accepts as its console). Measured at 10:15 and verified offline from the
saved reply (`out/evidence/rce-ro-1015/uic.fw_and_eeprom.reply.bin`):

```
0000  00 57 69 69 55 63 63 66 62 36 35 62 36 38 31 36   .WiiUccfb65b68169
0020  00 10 00 80 03 32 66 31 65 37 37 39 39 61 63 64   .....2f1e7799acd
0030  34 34 31 35 63 66 33 33 61 38 31 35 39 30 31 39   4415cf33a8159019
...                                                        (64-hex PSK, verbatim)
0288  49 54 30 31 35 36                             IT0156  (UIC build string)
```

| Offset | Contents | Value |
|---|---|---|
| 0x0001 | SSID (null-terminated) | `WiiUccfb65b68169` — matches `run/pairing.env` |
| 0x0025 | key material | `2f1e7799…f69b71` = the **network PSK in plaintext** |
| 0x0068 | further key blob | 32 bytes, unknown |
| 0x0289 | **TV-remote ID1** (5 B, CRC-valid record at 0x289, crc 0x326b @ 0x293) | `T0156` — CORRECTED: this is not a build string; see `10-tv-remote-live.md` §2 |
| 0x028e | TV-remote ID2 | unset |
| — | non-zero bytes | 362 of 768 |

Severity: post-association information disclosure of the pad's pairing secrets and UIC identity.
It is not an RCE, but it is the cheapest and only *confirmed* leak we have, it needs nothing but
the PSK we already hold, and it is a good candidate for a standalone write-up because it defeats
the pad's own UIC-secret boundary (the UIC is a separate STM8 with its own 2 KB EEPROM).
Caveat: the 10:15 run shared port 50023 with the streamer, so the *other* 24 queries in that run
(mostly `error=9004`, and `state index 12`) are **low confidence** and should be re-measured in a
clean, exclusive-port window. The 772-byte reply itself is internally consistent and decodes
cleanly, so it is recorded as high confidence.

## 3. Result 2 — E1: the `svc 0/0x0a` index sweep is bounds-checked (hypothesis falsified)

`safe-sweep.py` sent `svc 0 / method 0x0a` with the 1-byte EEPROM selector for **every value
0x00–0xFF**, one datagram each, exclusive port, 0.3 s apart, with the pad's input rate sampled
before and after every case (`out/evidence/rce-sweep-full-1023/sweep.jsonl`).

| Selector | Reply | Note |
|---|---|---|
| 0x00 | `err=0`, 4 B `00170200` | `language_bank_and_ver` = 136,960 — matches the 09:14 run |
| 0x01 | `err=0`, 4 B `03000000` | `tv_remocon` = 3 |
| 0x02 | `err=0`, 4 B `a0031dea` | `service_firmware_version` = 3,927,770,016 |
| 0x03, 0x04 | `err=0`, 4 B `00000000` | `opening_screen_1/2` unset |
| **0x05 … 0xF5** | **`err=14`, 0 B** | 241 cases, uniform — invalid argument |
| 0x05 … 0xFF (short run, 10:22) | `err=14` | reproduced independently in the 25-case run |

**Conclusion (high confidence):** the pad's `svc 0` reader family validates its 1-byte selector
against the documented range and returns error 14 otherwise. There is **no OOB read** in this
handler, and no evidence leak. That is a clean negative on candidate **E1** (ranked #5, score 12)
of `02-attack-surface.md`, and — more useful than the negative — it is the first hard evidence
about *how this firmware writes its argument checks*: it does check. The ranking must move the
"index trusted" family down and the "length trusted" family (V1/V2, M3/M4) up.

The reply bodies for selectors 0x00–0x02 are themselves a useful by-product: they give the pad's
`service_firmware_version` (3,927,770,016) and remocon bank number, i.e. more of the firmware
identity that a fuzzing campaign needs as an oracle (O8).

## 4. The contaminated run, and why the "wedge at 0xF6" is *not* a finding

The 256-case sweep's last 10 cases (`0xF6`–`0xFF`) returned `NOREPLY` and the pad's input stream
went to zero at `t=46.21 s`. That looked like a remotely-triggerable wedge of the pad's cmd
service — the kind of result the whole hunt is looking for. It was not. The timeline refutes it:

| Time | Event | Source |
|---|---|---|
| 10:23:15 | my sweep starts, exclusive `192.168.1.10:50023` | `sweep.jsonl` mtime of parent dir |
| 10:23:45 | **a concurrent operator session creates `run/phase11-session-anchored.sh`** and its first phase **deliberately deauthenticates the pad** to force a fresh DHCP anchor | `out/logs/phase11b.log`: "forcing a fresh association … OK deauthenticated the pad" |
| ~10:24:01 | my cases `0xF6`… go `NOREPLY` — the pad is re-associating | `sweep.jsonl` |
| 10:24:14 | my sweep ends, its own deadman (10 consecutive failures) fires | `anomalies.json`: `"stopped": "deadman: 10 consecutive failures at eeprom_ver.idxff"` |
| 10:24:34 | that session's `command-plane.py` binds 50023 (`SO_REUSEADDR`, mode=console) | `out/logs/command-plane-102438.log` |
| 10:24:42+ | my liveness re-probe binds the same port too, so pad replies are split → `NOREPLY` | observed |

Two lessons, both already documented in this repo and both violated by me:

1. **`SO_REUSEADDR` makes a second binder succeed silently** (`research/BOOT-AND-MODES.md` §5.1).
   My "is the port free?" check set `SO_REUSEADDR` on the probe socket, so it cannot detect a peer
   that did the same. The fix is to check `ss -lunp` for any peer on 50023 (and to abort if the
   operator's own phase scripts are running) — `run/fuzz-pad.py` should do this before every run.
2. **One hardware owner at a time.** A concurrent session did not just split replies, it
   *deauthenticated the pad mid-run*. Nine minutes of measurement, one spurious "finding".

Consequence: the wedge hypothesis is **discarded**, not queued. If it is ever re-tested it must be
a dedicated run (control: 250 in-range queries; test: 250 out-of-range) with the operator's other
sessions stopped, `ss -lunp` proving exclusive ownership, and wall-clock timestamps in the JSONL.

## 5. State of the tools after this session

| Tool | State | Notes |
|---|---|---|
| `research/rce-hunt/probe-readonly.py` | working | 25 documented read methods, ACK/reply/type-3 state machine, liveness sampling, evidence dir. Needs a real port-ownership check (see §4). |
| `research/rce-hunt/safe-sweep.py` | working | E1/E2 selector sweeps, deadman, reply-content diffing, anomaly JSON. Same port-check caveat. |
| `research/rce-hunt/frag-probe.py` | dry-run only | E5 series A/B/C/D (`M M M S` reassembly over-claim, fid sweep, order/repeat, flag confusion). **Never sent** — the hardware was contended. Deliberately excludes the `svc 0/0x03` tid-confusion variant (could start an update). |
| `run/fuzz-pad.py` | 243-case catalogue, selftest running (264 mock cases) | Built by the harness pass; its own doc says it does not listen on 50110→50010, so a VSTRM case that kills the decoder without killing the pad verdicts `OK` — fix before trusting VSTRM results. |
| `run/replay-console-media.py` (pre-existing) | running under the other session | byte-exact console media replay; the vehicle for E3/E4 once the port is free. |

## 6. What the next clean window should do, in order

1. **Serialise**: confirm no `phase11*`/`command-plane*` process and `ss -lunp` shows no 50023
   peer; record wall-clock per case.
2. **Re-measure the `9004` matrix** with exclusive ownership (which methods answer in which pad
   state) — this decides *which parsers are reachable at all*, which every other ranking depends on.
3. **E5 (`frag-probe.py`)** — the highest-ranked *non-destructive* memory-safety hypothesis left
   after E1's negative: 1028-byte declared / short-delivered reassembly.
4. **E3/E4 (VSTRM length and geometry)** only after the codec is actually decoding our stream
   (check the resync rate first: if the pad asks for a keyframe at ~60/s, it is not decoding, so a
   decode-path corruption test is inconclusive).
5. Park `svc 0/0x02–0x05`, `svc 4/0x01 payload 2`, `svc 5/0x0c` until the operator lifts the
   non-destructive ROE **and** a UART-boot recovery harness is proven.
