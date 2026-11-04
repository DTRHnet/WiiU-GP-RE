# 03 — `run/fuzz-pad.py`: the live mutation harness

**Scope.** Authorized local lab, owner's own GamePad at `192.168.1.11`. Operator manual for `run/fuzz-pad.py` v1.0 —
every flag below was verified against `--help` and the source, nothing invented. The tool plays the **console** side of
the DRC link (`192.168.1.10`: `50023→50123` cmd, `50020→50120` vstrm, `50021→50121` astrm, UDP/67 DHCP) and pushes one
mutated protocol case at a time while sampling the oracles — `svc 4/0x05` state index, `svc 4/0x04` version, `svc 0/0x00`
LVC id, the pad's `50122→50022` input rate, ICMP and the hostapd log — so a pad that dies, wedges or changes mode is tied
to one byte sequence and can be replayed exactly.

## CLI surface — `python3 run/fuzz-pad.py --help` (verbatim)

```text
usage: fuzz-pad.py [-h] [--version] [--target TARGET] [--live]
                   [--local-ip LOCAL_IP] [--selftest] [--list] [--dry-run]
                   [--replay FILE] [--replay-port REPLAY_PORT]
                   [--replay-plane {cmd,vstrm,astrm,dhcp}]
                   [--replay-speed REPLAY_SPEED]
                   [--plane {cmd,vstrm,astrm,dhcp}] [--family FAMILY]
                   [--case CASE] [--max-cases MAX_CASES] [--only {SAFE,ALL}]
                   [--i-understand-brick-risk] [--mutate-from FILE|DIR]
                   [--corpus-port CORPUS_PORT]
                   [--corpus-plane {cmd,vstrm,astrm,dhcp}] [--seed SEED]
                   [--cmd-sport CMD_SPORT] [--cmd-dport CMD_DPORT]
                   [--video-sport VIDEO_SPORT] [--audio-sport AUDIO_SPORT]
                   [--input-port INPUT_PORT] [--dhcp-port DHCP_PORT]
                   [--dhcp-seconds DHCP_SECONDS]
                   [--dhcp-max-requests DHCP_MAX_REQUESTS]
                   [--max-rate MAX_RATE] [--deadman DEADMAN]
                   [--case-timeout CASE_TIMEOUT]
                   [--oracle-timeout ORACLE_TIMEOUT] [--retries RETRIES]
                   [--settle SETTLE] [--latency-ms LATENCY_MS] [--force]
                   [--record DIR] [--ap-log FILE] [--no-icmp] [--verbose]

Protocol-plane fuzzer and crash oracle for the Wii U GamePad DRC link.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --target TARGET       pad address (default 192.168.1.11)
  --live                required to transmit to 192.168.1.11 at all
  --local-ip LOCAL_IP   console address (default 192.168.1.10)
  --selftest            run the whole pipeline against a loopback mock pad
  --list                print the case catalogue
  --dry-run             print packets as hex, transmit nothing
  --replay FILE         re-transmit a recorded case-N.bin (or any port*.bin)
  --replay-port REPLAY_PORT
                        destination UDP port for replay
  --replay-plane {cmd,vstrm,astrm,dhcp}
                        plane to use when the file carries no metadata
  --replay-speed REPLAY_SPEED
                        timestamp compression factor for replay (default 1.0)
  --plane {cmd,vstrm,astrm,dhcp}
                        plane(s) to fuzz (default cmd+vstrm+astrm)
  --family FAMILY       only families matching this prefix (repeatable)
  --case CASE           only this case index (repeatable)
  --max-cases MAX_CASES
                        stop after N cases
  --only {SAFE,ALL}     SAFE (default) never sends flash writes or reboots
  --i-understand-brick-risk
                        allow BRICK-risk cases (flash writes, reboots)
  --mutate-from FILE|DIR
                        seed messages to mutate (file or directory)
  --corpus-port CORPUS_PORT
                        destination port for --mutate-from (default 50123)
  --corpus-plane {cmd,vstrm,astrm,dhcp}
  --seed SEED           deterministic mutation seed (default 1234)
  --cmd-sport CMD_SPORT
  --cmd-dport CMD_DPORT
  --video-sport VIDEO_SPORT
  --audio-sport AUDIO_SPORT
  --input-port INPUT_PORT
                        local port counting the pad's input stream
  --dhcp-port DHCP_PORT
                        responder port (67 = real DHCP; needs --force while
                        netboot holds it)
  --dhcp-seconds DHCP_SECONDS
  --dhcp-max-requests DHCP_MAX_REQUESTS
  --max-rate MAX_RATE   datagrams per second cap (0 = unlimited, default 20)
  --deadman DEADMAN     abort after N consecutive GONE cases (0 = never)
  --case-timeout CASE_TIMEOUT
  --oracle-timeout ORACLE_TIMEOUT
  --retries RETRIES
  --settle SETTLE       seconds between a case and its post-case sample
  --latency-ms LATENCY_MS
  --force               bind even if the port is taken (splits replies -
                        avoid)
  --record DIR          mandatory for a transmitting run: write every datagram
  --ap-log FILE         tail hostapd log for deauth/assoc of 40:d2:8a:17:e2:09
  --no-icmp
  --verbose

Run --selftest first: it proves the codecs and the whole pipeline on loopback without touching hardware.
```

## Operator runbook (this order, no shortcuts)

1. **Stop the production stack first:** `sudo run/drc-down.sh` (recorded PIDs only; removes `WiiUAP`, restores the
   radio MAC). Not optional: libdrc and the replay tools bind `192.168.1.10:50023` with `SO_REUSEADDR`/`SO_REUSEPORT`, so
   a second binder *succeeds silently* and the kernel splits the pad's replies — indistinguishable from a dead pad
   (`NO REPLY`, spurious `error 9004`). See `research/BOOT-AND-MODES.md` §5.1.
2. **Verify no competing binder.** `bind_udp()` sets neither reuse flag unless `--force`; on `EADDRINUSE` it names
   the holders and exits 3. By hand: `sudo ss -lunp 'sport = :50023'`.
3. **Bring up the AP only** (association + DHCP lease, *no streamer*): `sudo run/03-ap.sh`, not `run/drc-up.sh` — that
   starts the streamer too, which binds `50010/50022/50023` and steals replies. Expect `192.168.1.11`, input, no video.
4. **Confirm liveness:** `python3 run/pad-state.py --send` returns state / LVC id / input rate; index 0 == the pad's
   own notice screen on the glass.
5. **SAFE sweep, cmd first:** `sudo python3 run/fuzz-pad.py --live --record out/fuzz/$(date +%H%M%S) --only SAFE
   --plane cmd`, then `--plane vstrm astrm`, then `--plane dhcp` (UDP/67 fights netboot: `--dhcp-port 67 --force`
   only once netboot is down).
6. **Escalate** last, owner present: more `--plane` values, `--max-rate 5`, `--deadman 2`, then `--only ALL
   --i-understand-brick-risk` for the 16 BRICK cases.

## Verdict semantics — what each one means on the glass

| Verdict | Rule in `classify()` | Physical meaning on the pad |
|---|---|---|
| `OK` | reply + type-1 ack, state unchanged, under `--latency-ms` | parsed, stayed in the same UI/mode: no observable effect |
| `LATENCY` | reply slower than `--latency-ms` (250 ms) | pad took a slow path (retry, queue flush, new message class) — a hint, not a fault |
| `NOACK` | reply with no preceding type-1 ack | answered off the documented `query→ack→reply→ack` order: ACK path/state machine moved |
| `NOREPLY` | reply expected, none came, input still flowing | parser **rejected** the datagram. Silence + live input = dropped, not crashed |
| `STATECHANGE` | `svc 4/0x05` index differs before vs after | pad **moved**: redraw, dialog, mode change — highest-value corruption signal |
| `GONE` | no reply **and** input rate 0 | pad/link dead: crash, hang, reboot, 5 GHz drop — or two sockets on `50023`. Re-probe, then blame the case |

## Rails: rate limit, deadman, brick gate, target guard

* `--max-rate` (default **20 datagrams/s**, `0` = unlimited) is a `TokenBucket` around every send on every plane,
  retransmits included. Use 5–20 against real hardware.
* `--deadman N` (default **5**, `0` = never) aborts the run after N *consecutive* `GONE` verdicts: exit code 4,
  `aborted` in `verdicts.jsonl`; any other verdict resets the counter.
* `--only SAFE` (default) plus a second gate in `CmdPlane.guard()`: `svc 0/0x02-0x05`, `0x0b-0x0f`, `svc 4/0x01`,
  `svc 4/0x1a`+`flags 0x42`, `svc 5/0x0c`, `svc 5/0x19` and UVC `f3=1|3` raise `BrickRisk` *before* `sendto`;
  generated mutations are re-classified at build time, so a random flip onto a flash method is BRICK, not SAFE.
* Target guard: nothing goes to `192.168.1.11` without `--live` (exit 2); loopback always allowed; any other
  `--target` only *warns* — type the target yourself every time.

## Recovering a wedged pad

1. Rule out the harness first: `ss -lunp 'sport = :50023'`, then re-probe with `run/pad-state.py`.
2. Genuinely silent → **power cycle** (hold POWER until the screen blanks, or pull the battery pack), let it
   re-associate to `WiiUAP`, confirm input flow.
3. Awake but in a non-normal mode → the documented way back is `svc 4/0x01` payload `0x00`, case **128**
   `cmd/brick.reboot_normal`: `sudo python3 run/fuzz-pad.py --live --only ALL --i-understand-brick-risk --case 128
   --record out/fuzz/recover-$(date +%H%M%S)`; verify with `--dry-run --only ALL --case 128` first. Payload `0x02`
   (`--case 129`) strands the pad in firmware-update mode — avoid it.

## Replaying a case exactly

A transmitting run writes `case-NNN.bin` (20-byte framing `>d4s4sI`: ts, src, dst, length — as `out/evidence/truth/*.bin`),
`case-NNN.txt` (hexdump + sha256), `case-NNN.json` (`dport`, `plane`, `sha256`, `verdict`, oracle deltas) and
`verdicts.jsonl`; `NNN` is the `--list` index, so `--case 128` == `case-128.bin`.

```bash
jq . out/fuzz/091200/case-042.json                    # what it sent / what came back
sudo python3 run/fuzz-pad.py --live --record /tmp/replay-042 \
     --replay out/fuzz/091200/case-042.bin            # byte-for-byte resend
sudo python3 run/fuzz-pad.py --live --record /tmp/replay-042 \
     --replay out/fuzz/091200/case-042.bin --replay-port 50123 \
     --replay-plane cmd --replay-speed 4.0            # overrides, gaps 4x tighter
```

`replay()` recomputes the stream sha256 and **refuses to transmit on mismatch** (exit 3), prints per-datagram
ack/reply/latency and a post-replay oracle sample; `--record` stays mandatory, and the brick gate still applies.

## Selftest: proof it works (loopback, no pad, no root, exit 0) — 9 stages, 38 assertions, trimmed verbatim

```text
== fuzz-pad.py 1.0 selftest (loopback only, no pad, no root)
   15 console messages, 69 video frames, 400 video datagrams, 8 audio, 8 format messages
   [PASS] cmd header encode(decode(real)) == real        9/9 console messages byte-identical
   [PASS] cmd generic header fields decoded              svc=0 method=0x11 txid=0x10b flags=0x42 final=False gen_size=1028
   [PASS] vstrm/astrm header encode(decode(real)) == real 400/400 video + 8/8 audio datagrams byte-identical
[2/9] mutation-engine determinism
   [PASS] same seed -> identical byte stream             264 cases, sha256 cd50e1414f1c8d48
   [PASS] different seed -> different stream             seed 1235 -> sha256 aeb6664ee9e57afa
   [PASS] every BRICK_CMD method appears as a BRICK case 16 brick cases cover 13 gated methods
   [PASS] every soup yields a parseable BOOTREPLY        control=302B/7opts, duplicate-options=311B/9opts, long-option=452B/3opts
[5/9] full pipeline against the loopback mock pad
   catalogue: 264 cases (248 SAFE, 16 BRICK gated)
[  4/264] cmd  SAFE  cmd/control.brightness   tx1 rx1 ack1 lat 220.2 in  55 st=4->4   LATENCY     reply in 220.2 ms (> 150)
[  8/264] cmd  SAFE  cmd/control.frag_group   tx4 rx1 ack1 lat   0.2 in  70 st=4->5   STATECHANGE state index 4 -> 5
[ 20/264] cmd  SAFE  cmd/outer.qtype=0x3      tx2 rx1 ack1 lat   0.1 in 180 st=11->11 NOREPLY     no reply
== selftest result
   assertions: 38, passed: 38, failed: 0
   mock pipeline: 248 cases, verdicts {'LATENCY': 1, 'NOACK': 1, 'NOREPLY': 3, 'OK': 238, 'STATECHANGE': 5}, 3197 cmd + 297 media datagrams received, 1413 input blobs emitted
SELFTEST PASS
```

Stage 6 replays `record/case-000.bin` and demands a sha256 MATCH; stage 7 silences the mock and requires a deadman abort
within 2 consecutive `GONE`; stages 3 and 8-9 cover the exclusive-bind guard, hex-only dry run and the ap-log tail.

## SAFE catalogue — 248 cases (16 more are BRICK-gated and never in SAFE)

| Plane | Cases | Families (count) |
|---|---|---|
| `cmd` → `50123` | 124 | control 10, fragmentation 6, `outer.*` 19, `gen.*` 32 (magic/version/txid/fragid/flags/final/error/svc/size), `payload.*` 49 (trunc 11, extend 5, intra 33), random 8 |
| `vstrm` → `50120` | 62 | control 3, `header.*` 28, `ext.*` 12, `size.*` 11, `chunk.*` 5, timestamp 3 |
| `astrm` → `50121` | 54 | control 2, `format.*` 22, `header.*` 23 (flags/fmt/seq/size/ts/type, incl. mono & vibrate), `pcm.*` 7 |
| `dhcp` → UDP/68 | 8 | option soups: control, duplicate-options, long-option, oversized43, weird55, truncated, no-end, unknown-codes |
| BRICK (gated) | 16 | svc0 `0x02-0x05`/`0x0b-0x0f`, svc4 `0x01` (payload 0 and 2) and `0x1a`+`0x42`, svc5 `0x0c`/`0x19`, UVC `f3=1`/`f3=3` |
| Total | 264 | 450 SAFE datagrams; `--seed` drives the 8 `cmd/random.*` cases |
