# 01 — Parser code notes: every parser that runs on data the fake console (DRH) sends to the GamePad

Author: offensive-security review, offline source-only. Lab: `/home/kali/Wiiu` (owner's own GamePad, authorised).
Date: 2026-11-04. Nothing in this file was obtained by transmitting to hardware; every "measured" row comes
from the already-decrypted console↔pad capture in `out/evidence/truth/` (parsed read-only with `python3`
one-liners, commands reproduced inline).

## 0. Method, evidence tiers, and one important caveat

**Evidence tiers used throughout**

* `[SRC]` — read directly from source in this repo. Citation is `path:line`.
* `[MEASURED]` — computed by me from `out/evidence/truth/port*.bin` / `console-messages/*.bin`
  (the decrypted real-console session; see `research/GROUND-TRUTH-SESSION.md:1-6`). The parse format is
  `>d 4s 4s I payload` per record (`run/replay-console-session.py:52-56`). Commands are inline below.
* `[DOC]` — a documented claim in a repo doc, cited. Not independently re-verified unless marked.
* `[UNVERIFIED]` — could not be established from this corpus.
* `[SPECULATIVE]` — my inference, labelled as such.

**The central caveat.** Nothing in this repo contains pad-side source. Every statement about *what the
GamePad's parser does* is therefore either (a) a documented reverse-engineering claim (`research/libdrc/web/docs/re/*`),
(b) a behaviour observed on the wire (`out/evidence/truth/`, `research/barista-ref/docs/*`), or
(c) an inference from what our implementation had to do to be accepted. The **pad's parsers are named but not
shipped**: `research/libdrc/web/docs/re/overview.rst:110-123` lists the LVC firmware *services* —
`astrm`, `cmd`, `hiddat`, `msg`, `vstrm`, `wii` — and `overview.rst:130` gives the `cmd` **manager**
("takes requests from the cmd service and sends replies"). That is the entire visibility we have into the
dispatch layer.

**Repo doc corrections found while doing this** (details in §9): the VSTRM sequence packing claim in
`research/GROUND-TRUTH-SESSION.md:81-86` and `:163` is wrong — the real console packs the sequence exactly
as libdrc does. And the "1048-byte UIC state blob is one message" reading is wrong: it is 4 fragments per
message (§1.4).

---

## 1. `cmd` service (UDP 50023 console → 50123 pad, bidirectional)

### 1.1 Where the parser actually lives in libdrc

There is **no** `src/command-service.cpp` / `src/command-manager.cpp` in this repo. The cmd plane is:

| file | role |
|---|---|
| `research/libdrc/include/drc/internal/cmd-packet.h` | on-wire structs + fixed buffers |
| `research/libdrc/src/cmd-packet.cpp` | field getters/setters (the only bit-level parsing we have) |
| `research/libdrc/include/drc/internal/cmd-protocol.h` | `CmdClient` (we are always the **client**) |
| `research/libdrc/src/cmd-protocol.cpp` | receive path, retransmit, ack |

`CmdServer` is a **stub**: `research/libdrc/include/drc/internal/cmd-protocol.h:93-95`

```c
class CmdServer {
  // TODO(delroth): should probably reuse some of CmdClient.
};
```

So **our stack never parses a (service, method) request and never dispatches a handler.** The per-service
handler table is entirely pad-side; §1.6 lists the only documented shape of it.

### 1.2 Outer `CmdHeader` — 8 bytes, little-endian

Declared struct: `research/libdrc/web/docs/re/sc-cmd.rst:32-37`

```c
struct CmdHeader { le16 packet_type; le16 query_type; le16 payload_size; le16 seq_id; };
```

Field offsets as implemented (`research/libdrc/src/cmd-packet.cpp`):

| field | code | line |
|---|---|---|
| `packet_type` | `(pkt_[1] << 8) | pkt_[0]` | `cmd-packet.cpp:48-50` |
| `query_type` | `(pkt_[3] << 8) | pkt_[2]` | `cmd-packet.cpp:52-54` |
| `seq_id` | `(pkt_[7] << 8) | pkt_[6]` | `cmd-packet.cpp:56-58` |
| `payload_size` | `(pkt_[5] << 8) | pkt_[4]` | `cmd-packet.cpp:64-66` |
| payload start | `pkt_.data() + 8` | `cmd-packet.cpp:60-62` |

Types: `kQuery=0, kQueryAck=1, kReply=2, kReplyAck=3` (`cmd-packet.h:36-41`); query types
`kGenericCommand=0, kUvcUacCommand=1, kTimeCommand=2` (`cmd-packet.h:43-47`).

**Documented contract:** "Payload size — Should be `packet_size - sizeof (CmdHeader)`"
(`sc-cmd.rst:50-51`).

### 1.3 Is `payload_size` validated against the datagram length? — **NO, not anywhere in libdrc**

This is the single most important code fact in the cmd plane.

* **Receive buffer:** `research/libdrc/src/udp.cpp:154-158` — a fixed 2000-byte stack/vector buffer:
  ```c
  int msg_max_size = 2000;
  std::vector<byte> msg(msg_max_size);
  int size = recvfrom(sock_fd_, msg.data(), msg_max_size, 0, ...);
  if (size >= 0) { msg.resize(size); recv_cb_(msg); }
  ```
  (the fork carries an untouched twin with a comment `//hmmmmmmmmmmmmmmmmmm` —
  `pc2drc/libdrc-vnc/libdrc-thefloppydriver/src/udp.cpp:191`.) Barista uses **4096**:
  `research/barista-ref/core/drh/runtime_transport.cpp:799`.

* **Copy into a fixed packet object, no length check:**
  `research/libdrc/src/cmd-packet.cpp:37-39`
  ```c
  CmdPacket::CmdPacket(const std::vector<byte>& packet) {
    memcpy(pkt_.data(), packet.data(), packet.size());     // <-- packet.size() unchecked
  }
  ```
  with `std::array<byte, kCmdHeaderSize + kMaxCmdPayloadSize> pkt_;` = **8 + 1400 = 1408 bytes**
  (`cmd-packet.h:73`, `cmd-packet.h:33-34`). A received datagram of 1409…2000 bytes overflows the object by
  up to 592 bytes. Same defect, same shape, in `GenericCmdPacket` (`cmd-packet.cpp:98-100` against
  `cmd-packet.h:116` = `std::array<byte, 12 + 1388>`), `UvcUacCmdPacket` (`cmd-packet.cpp:204-206` against
  `cmd-packet.h:153`, 48 bytes) and `TimeCmdPacket` (`cmd-packet.cpp:292-294` against `cmd-packet.h:177`,
  8 bytes).
  *This is a defect in the direction pad → console* (our parser on pad data) — but it is a direct model of what
  the pad's own LVC implementation plausibly does with console data, and it fixes the number to look for: a
  1400-byte payload ceiling plus a 2000-byte receive buffer.

* **The declared size is then trusted verbatim as a read length.**
  `research/libdrc/src/cmd-protocol.cpp:160-164`
  ```c
  } else if (pkt.PacketType() == CmdPacketType::kReply) {
    if (st->reply_callback != nullptr) {
      std::vector<byte> repl(pkt.Payload(), pkt.Payload() + pkt.PayloadSize());
      st->reply_callback(true, repl);
  ```
  `PayloadSize()` is the raw u16 at bytes 4-5 (`cmd-packet.cpp:64-66`) — **not clamped to 1400, not compared
  with the datagram length, not compared with the 2000-byte receive buffer**. A reply declaring
  `payload_size = 0xFFFF` makes this read 65 535 bytes starting at `pkt_+8`, i.e. an out-of-bounds read of the
  `CmdPacket` object (which lives on the stack of `PacketReceived`). Bounded only by the process's mapped
  memory. `[SRC]`

* **Only the caller of the callback re-checks sizes**, and only where someone remembered:
  `research/libdrc/src/streamer.cpp:202-218` guards the UIC blob with `if (reply.size() == 0x310)`
  before `LoadFromBlob(reply.data() + 0x10, 0x300)`. `research/libdrc/src/uvcuac-synchronizer.cpp:55-70`
  does **not** guard: it dereferences `d[0] … d[14]` on whatever came back (`state_.SetMicVolume(d[0] | (d[1] << 8))`
  etc.). `[SRC]`

* Barista, the second implementation, *does* validate (and therefore shows the check the pad must also do):
  `research/barista-ref/core/drh/runtime_transport.cpp:865-874`
  ```c
  if (packet.size() < kCommandHeaderSize) return false;
  const uint16_t payload_size = ReadLe16(packet.data() + 4);
  if (type > 3 || query_type > 2 || packet.size() != kCommandHeaderSize + payload_size) return false;
  ```
  with `kCommandHeaderSize = 8` (`runtime_transport.cpp:46`). Note it also range-checks
  `type > 3 || query_type > 2`.

### 1.4 `GenericCmdHeader` — 12 bytes, mixed endianness, bit-packed

Declared struct: `sc-cmd.rst:69-79` — `u8 magic_0x7E; u8 version; be12 transaction_id; be12 fragment_id;
u8 flags; u8 service_id; u8 method_id; be16 error_code; be16 payload_size;`

Implemented getters (`research/libdrc/src/cmd-packet.cpp`):

| field | code | line |
|---|---|---|
| magic/version | *never checked on receive*; set to `0x7E,0x01` on reset | `cmd-packet.cpp:109-110` |
| `transaction_id` (10 bits used) | `(pkt_[2] << 8) | (pkt_[3] >> 4)` | `cmd-packet.cpp:119-121` |
| `final_fragment` | `(pkt_[3] & 0x8) != 0` | `cmd-packet.cpp:123-125` |
| `fragment_id` (11 bits) | `((pkt_[3] & 0x7) << 8) | pkt_[4]` | `cmd-packet.cpp:127-129` |
| `flags` | `pkt_[5]` | `cmd-packet.cpp:131-133` |
| `service_id` | `pkt_[6]` | `cmd-packet.cpp:135-137` |
| `method_id` | `pkt_[7]` | `cmd-packet.cpp:139-141` |
| `error_code` | `(pkt_[8] << 8) | pkt_[9]` (**big-endian**) | `cmd-packet.cpp:143-145` |
| `payload_size` | `(pkt_[10] << 8) | pkt_[11]` (**big-endian**) | `cmd-packet.cpp:151-153` |
| payload start | `pkt_.data() + 12` | `cmd-packet.cpp:147-149` |

Writer-side asserts exist but are inert in release builds (`NDEBUG`): `assert(tid < 0x400)`
(`cmd-packet.cpp:156`), `assert(fid < 0x800)` (`cmd-packet.cpp:170`),
`assert(size <= kMaxGenericCmdPayloadSize)` (`cmd-packet.cpp:193`), `assert(size <= kMaxCmdPayloadSize)`
(`cmd-packet.cpp:86`). `GenericCmdPacket::ResetPacket` sets magic `7E 01`, final-fragment, and
service/method `0xFF` (`cmd-packet.cpp:105-117`).

Note the **endianness asymmetry**: outer header little-endian, generic header's two `u16` fields big-endian.
`run/pad-state.py:16-20` documents the same ("all little-endian outside the generic header, which is mixed").

**Size constants (the numbers that matter):**

| constant | value | citation |
|---|---|---|
| `kCmdHeaderSize` | **8** | `research/libdrc/include/drc/internal/cmd-packet.h:33` |
| `kMaxCmdPayloadSize` | **1400** (`0x578`) | `cmd-packet.h:34` |
| `kGenericCmdHeaderSize` | **12** | `cmd-packet.h:76` |
| `kMaxGenericCmdPayloadSize` | **1388** = 1400 − 12 | `cmd-packet.h:77-78` |
| `kUvcUacCmdPacketSize` | **48** | `cmd-packet.h:119` |
| `kTimeCmdPacketSize` | **8** | `cmd-packet.h:156` |
| `CmdPacket` object | `std::array<byte, 8+1400>` = **1408** | `cmd-packet.h:73` |
| `GenericCmdPacket` object | `std::array<byte, 12+1388>` = **1400** | `cmd-packet.h:116` |
| UDP receive buffer (libdrc) | **2000** | `research/libdrc/src/udp.cpp:154-158` |
| UDP receive buffer (barista) | **4096** | `barista-ref/core/drh/runtime_transport.cpp:799` |
| documented max service payload | **1028** (`0x404`) for svc 0 / method `0x03` | `sc-cmd.rst:121` |

Note the mismatch that defines the attack surface: the *documented maximum method payload* is 1028 and the
*largest real message fragment* is 1028 (§1.5), while our stack will happily send and accept up to 1388/1400.
`run/pad-state.py:61-62` independently caps itself at 1016 bytes ("generic payload exceeds
kMaxGenericCmdPayloadSize").

### 1.5 Multi-fragment reassembly — what the shape actually is `[MEASURED]`

**libdrc has no reassembly code at all.** It only *writes* fragment fields
(`cmd-packet.cpp:161-173`) and always sends `final_fragment = true` with `fragment_id = 0`
(`cmd-packet.cpp:114`, used by `run/streamer.cpp:44-54` and `pc2drc/.../src/streamer.cpp:45-66`).
There is no per-fragment index array, no offset accumulator and no max-total-size constant anywhere in
`research/libdrc/`, `research/wozt-libdrc/` or `pc2drc/.../libdrc-thefloppydriver/`. The only description of
the pad-side shape is prose:

* `sc-cmd.rst:85-88` — "Transaction and Fragment ID — Used for commands that require payloads larger than the
  size of a 802.11n packet. Currently only seen in use for firmware upgrades. Set to 0 for most commands."
* `sc-cmd.rst:91-93` — "Flags — Usually set to `0x40` in queries and set to `((query.flags>>3)&0xFC|1)` in
  replies. **If `flags & 0x3`, this is a multi-fragment query.**"
* `sc-cmd.rst:101-103` — "Payload size — Size of the query payload. Should be `packet_size - sizeof
  (GenericCmdHeader) - sizeof (CmdHeader)`."

Decoding the real session settles the shape. Reproduce:

```sh
cd /home/kali/Wiiu && python3 - <<'PY'
import struct, collections
d=open('out/evidence/truth/port50123.bin','rb').read(); o=0; r=[]
while o+20<=len(d):
    ts,si,di,ln=struct.unpack(">d4s4sI",d[o:o+20]); o+=20; r.append(d[o:o+ln]); o+=ln
big=[p for p in r if len(p)==1048]
print(len(big)); print([(p[6]|(p[7]<<8),p[10],p[11],p[12],p[13]) for p in big[:12]])
PY
```

Results (1475 datagrams total, sizes `1048×778, 8×445, 56×228, 20×13, 16×4, 52×3, 25×2, 332×1, 122×1`,
max datagram **1048**):

```
seq=15 b2=01 b3=b0 b4=00 flags=42 svc=00 meth=11 inner=0404
seq=16 b2=01 b3=b0 b4=01 flags=42 svc=00 meth=11 inner=0404
seq=17 b2=01 b3=b0 b4=02 flags=42 svc=00 meth=11 inner=0404
seq=18 b2=01 b3=b8 b4=03 flags=40 svc=00 meth=11 inner=0404
seq=19 b2=01 b3=c0 b4=00 flags=42 svc=00 meth=11 inner=0404   ...
```

**Therefore, for the 1048-byte UIC state message:**

* `transaction_id` = `(b2 << 8) | (b3 >> 4)` and it **increments once per logical message** (0x10b, 0x10c,
  0x10d, …); all four fragments of one message share it. `[MEASURED]`
* `fragment_id` = `((b3 & 7) << 8) | b4` and takes the values **0,1,2,3** — a plain per-fragment index.
  `[MEASURED]`
* `final_fragment` (bit `b3 & 0x08`) is set **only on fragment 3**. `[MEASURED]` Cross-tab over all 778:
  `(b3 bit3=0, flags&3=2) → 584`, `(b3 bit3=1, flags&3=0) → 194`. 584/3 = 194.67 → **194 complete
  4-fragment messages + 2 fragments of a message that started before the capture**, 194×4 = 776 (+2 = 778). `[MEASURED]`
* `flags`: `0x42` for fragments 0-2, `0x40` for fragment 3. So `flags & 0x3 == 2` ⇒ "more fragments follow",
  `== 0` ⇒ "this is the last one" — consistent with `sc-cmd.rst:91-92` but note the doc's "usually `0x40` in
  queries" describes only the *final* fragment. `[MEASURED]` + `[SRC]` (doc)
* **The declared generic `payload_size = 0x0404` (1028) is the length of *that fragment*, not of the message.**
  Per fragment: datagram 1048 = 8 (CmdHeader) + 12 (GenericCmdHeader) + 1028. Four fragments ⇒ **4112 bytes of
  logical payload**. So the pad must hold ≥ 4 × 1028 (or ≥ 4112) bytes for this message class. `[MEASURED]`
* The *outer* declared `payload_size` for the same datagram is `0x0410` = 1040 = 1048 − 8 ✓ — i.e. the outer
  length is consistent, and the generic length is per-fragment. `[MEASURED]`
* Answers arrive in **one** 792-byte reply (`payload_size=784`, inner 772 = 4 + 768), so the pad is definitely
  reassembling the four fragments into one logical message before replying. `[MEASURED]`: 5 datagrams of
  792 B in `port50023.bin`, all `type=2, query=0, payload_size=784` — the same 5 that
  `research/GROUND-TRUTH-SESSION.md:115-116` lists.
* One 332-byte query carries `fid=2, final=1` (`b3=0xd8, b4=0x02`) — a *last* fragment of a 3-fragment message
  whose fragments 0 and 1 are absent from the capture. `[MEASURED]`, semantics `[UNVERIFIED]`.

**Maximum single fragment:** both the field width (11-bit fid, 16-bit declared length) and the measured corpus
allow up to 1028 bytes of generic payload ⇒ 1048 bytes on the wire. Our own writer allows 1388 ⇒ 1408 on the
wire (`cmd-packet.h:77-78`), i.e. **380 bytes beyond anything the real console ever sent.** `[SRC]`+`[MEASURED]`

**What happens if the declared `payload_size` disagrees with the bytes delivered (last fragment or any
fragment):** `[UNVERIFIED]` — no source states it and no capture contains a mismatch: of the 1475 console→pad
datagrams, and of the 1475 pad→console replies in `port50023.bin`, **every** one satisfies
`len == 8 + payload_size` (`(t,q,ps,ok)` all `ok=True`). The pad's own writer is length-consistent
(1030 query-acks with `payload_size=0`, 228 replies of 16, 196 of 16, 5 of 784, etc.). Whether its *parser*
would clamp, reject, or over-read is not observable offline — flag as the primary blind spot for the
memory-corruption document.

### 1.6 Dispatch: how are (service, method) handled?

* **Our side: no table.** `CmdServer` is empty (`cmd-protocol.h:93-95`). Send helpers are hand-rolled per
  call site, e.g. `research/libdrc/src/streamer.cpp:44-54` (`RunGenericCmd`) which sets
  `flags = kQueryFlag (0x40)`, service, method and payload.
* **Pad side: a documented service/method namespace, not a table dump.** `sc-cmd.rst:105-262` enumerates
  services 0-5 with per-method payload/reply sizes. The potentially memory-unsafe ones for an attacker
  document (all `[DOC]`):

  | service/method | declared payload | declared reply | note | line |
  |---|---|---|---|---|
  | 0/0x03 (start product update data) | **Max 1028** | 4 | `struct { u32 block_idx; u8 data[]; }` — variable length array into an update buffer | `sc-cmd.rst:121` |
  | 0/0x0b, 0x0d, 0x0f | 9, 4, 4 | ? | writes EEPROM fields | `:132-141` |
  | 1/0x05 | 0 | 113 | returns SSID (32) + **PSK (64)** + lengths from the pad's own EEPROM | `:151-153` |
  | 2/0x0c | 0 | 272 | device ID + certificate | `:165` |
  | 3/0x03…0x06 | 1 | 13 / 152 / 448 / 2 | Wi-Fi driver stats blobs | `:176-183` |
  | 4/0x01, 0x0e | 1 | – | "Shuts down or reboots to a different mode", payload 4 or 6 = shutdown | `:191-193` |
  | 5/0x02 | **102** | ? | forwarded to UIC command `0x0c`, format `u16,u16,{u8,u8,u8}[32],u16` | `:227` |
  | 5/0x06 | 0 | **772** | UIC fw version + first 768 B of EEPROM | `:229` |
  | 5/0x0c | **258** | ? | "Updates data from the UIC EEPROM", `u8 index, u8 length, u8 data_and_crc[]` — index/length pair from the peer | `:237` |
  | 5/0x10 | **531** | ? | ICTAG/NFC | `:243` |
  | 5/0x11 | **Max 520** | **Max 520** | IRCOM: byte0 = 0 connect / 1 send / 2 receive / 3 disconnect | `:245-247` |
  | 5/0x19 / 0x1a | 13 | 13 | LCD parameters straight to the LCD controller over I2C | `:258-260` |
* **Unknown service/method:** `[UNVERIFIED]`. `sc-cmd.rst` has no error table beyond `sc-cmd.rst:98-99`
  ("Error code — Set in replies with an error code if the query failed"), and `0xFF/0xFF` is the
  "invalid" value libdrc initialises to in order to *avoid* sending a valid command
  (`cmd-packet.cpp:112-116`, comment: "Set service and method to invalid values to avoid sending a valid
  command with an uninitialized packet"). Service 2/method 0 is documented to be a no-op that "simply returns
  with error code 0" (`sc-cmd.rst:163`), which shows a graceful path exists for at least one entry.
* The strongest hint that the dispatch is a table with a per-entry length contract is
  `sc-cmd.rst:304-305`: "This command is issued every second. **Recent versions of the GamePad firmware will
  only show the video stream after receiving one such command.**" (UVC/UAC), and
  `sc-cmd.rst:307-308`: "Setting f3 to 1 switches the GamePad to vWii mode, setting it to 3 shuts it down"
  — a byte in the 48-byte UVC/UAC payload selecting radically different firmware behaviour.

### 1.7 Retransmit / ack path (the only timed state machine we own)

`research/libdrc/src/cmd-protocol.cpp`:

| item | value / code | line |
|---|---|---|
| timeout | `kTimeoutMs = 1000` | `:38` |
| max attempts | `kMaxRetries = 10` (so "up to 10s") | `:39`, documented at `cmd-protocol.h:71` |
| timer armed on send | `NewTimerEvent(kTimeoutMs * 1000000, RetryOperation)` | `:176-179` |
| state on send | `kQueryAck` | `:181` |
| ack handler | `kQueryAck → kReply` | `:158-159` |
| reply handler | cancels timer, invokes callback with `Payload()..Payload()+PayloadSize()`, `RemoveState` | `:153-166` |
| "reply ack regardless" | every `kReply` triggers `SendReplyAck(seq, qtype)` *before* any state lookup | `:138-141` |
| retry | `retries_count++`; at `kMaxRetries` → `reply_callback(false)` + `RemoveState`; else resend | `:193-208` |
| seq allocation | `seqid = seqid_++` into `std::map<u16, CmdState>`; `assert` no duplicate | `:77-92` |
| u16 seq wrap | not handled — `seqid_` is a `u16` and wraps to 0 after 65535 | `cmd-protocol.h:89` |

`RetryOperation` does `assert(state != NULL)` (`:195`) on a map lookup by seqid — in a release build a timeout
firing after the state was removed dereferences NULL. `[SRC]`

Observed timing/semantics on the wire `[MEASURED]`: the console increments `seq_id` per message (8…1044 over
the session), the pad acks with type 1 (`payload_size=0`, 1030 of them), replies with type 2, and the console
sends type-3 acks with the same sequence (`445 × 8 B`; `console-messages/cmd_t3_q*_len0.bin` are `03 00 00 00
00 00 09 00` etc.). Reply `flags = 0x09` for a query with `flags = 0x42`/`0x40`, i.e. exactly
`((query.flags>>3)&0xFC|1)` from `sc-cmd.rst:91`.

---

## 2. `vstrm` video (UDP 50020 console → 50120 pad)

### 2.1 Exact 16-byte header construction (libdrc)

`research/libdrc/include/drc/internal/vstrm-packet.h:33` `kVstrmHeaderSize = 16`;
`:35-37` payload cap:

```c
// Limit our payload size to around 1400 bytes (DRC MTU is about 1800 bytes, so
// increasing this could help performance in the future).
const size_t kMaxVstrmPayloadSize = 1400;
```

Documented bit layout `[DOC]` (`research/libdrc/web/docs/re/sc-vstrm.rst:23-36`):

```c
struct VstrmHeader {
  u32 magic : 4; u32 packet_type : 2; u32 seq_id : 10;
  u32 init : 1; u32 frame_begin : 1; u32 chunk_end : 1; u32 frame_end : 1;
  u32 has_timestamp : 1; u32 payload_size : 11;
  u32 timestamp : 32;                 // if has_timestamp
};
```

As implemented (`research/libdrc/src/vstrm-packet.cpp`):

| byte | content | line |
|---|---|---|
| 0 | `0xF0` = magic `F` (bits7-4) ‖ packet_type=0 (bits3-2) ‖ seq[9:8] (bits1-0) | `:48`, `:83-86` |
| 1 | `seq[7:0]` | `:85` |
| 2 | bit7 `init`, bit6 `frame_begin`, bit5 `chunk_end`, bit4 `frame_end`, bit3 `has_timestamp` (`0x08`), bits2-0 `len[10:8]` | `:49`, `:116`, `:129-132` |
| 3 | `len[7:0]` | `:117` |
| 4-7 | timestamp, **big-endian** u32 µs | `:88-93`, `:59-61` |
| 8-15 | ext/option bytes | `:50-52`, `:134-177` |

The four flag accessors are macro-generated (`vstrm-packet.cpp:120-132`):
`VSTRM_FLAG_FUNCS(Init, 2, 7)`, `(FrameBegin, 2, 6)`, `(ChunkEnd, 2, 5)`, `(FrameEnd, 2, 4)`, using
`InsertBits`/`ExtractBits` (`research/libdrc/include/drc/internal/utils.h:31-42`).

### 2.2 The ext-header options writer (and its assert)

`research/libdrc/src/vstrm-packet.cpp:150-166`

```c
void VstrmPacket::SetExtOption(u8 opt, u8* val) {
  int i;
  for (i = 0; i < 8 && pkt_[8 + i] != 0x00; ++i) {
    if (pkt_[8 + i] == opt) { if (val) pkt_[8 + i + 1] = *val; return; }
  }
  int required_space = (val == NULL ? 1 : 2);
  assert((i + required_space <= 8) || "out of space in vstrm ext header");   // NDEBUG → check vanishes
  pkt_[8 + i] = opt;
  if (val) { pkt_[8 + i + 1] = *val; }
}
```

With `i == 7` and a value (`required_space = 2`) the write `pkt_[8 + 7 + 1] = pkt_[16]` is **outside** the
16-byte *header* but still inside the 1416-byte `pkt_` array (`vstrm-packet.h:86`), so it silently corrupts the
first payload byte instead of overflowing the object. `[SRC]`

Reader: `GetExtOption` scans `pkt_[8..15]` and explicitly refuses to read the value at `i == 7`
(`vstrm-packet.cpp:134-148`) — the encoding is "option byte followed by optional argument byte", terminated by
`0x00` (`sc-vstrm.rst:45-48`: "options are read linearly from the extended header until either 8 bytes were read
or a `0x00` byte was read").

`ClearExtOption` (`vstrm-packet.cpp:168-177`) has a suspicious loop whose index `i` is advanced with `j`:

```c
for (int j = i + 1 + has_val; j < 8; ++i, ++j) { pkt_[8 + i] = pkt_[8 + j]; pkt_[8 + j] = 0; }
```

Both `i` and `j` stay ≤ 7 so it remains inside the header, but it collapses the run and leaves the tail
uncleared in some orders. `[SRC]`

Default ext bytes written by `ResetPacket` (`vstrm-packet.cpp:46-53`):

```c
pkt_[0] = 0xF0;  // 4 bit magic (F), 2 bit packet type (0), 2 bit seqid (0)
pkt_[2] = 0x08;  // Has timestamp = 1
pkt_[8] = 0x83;  // "Force decoding" option, enabled on DRH vstrm messages
pkt_[9] = 0x85;  // Macro blocks per row option, value set below
pkt_[10] = 6;    // 6 macroblock row per chunk (6 * 5 = 480 / 16)
```

**Option semantics `[DOC]`** (`sc-vstrm.rst:50-70`) — this is the closest thing to a pad-side parser spec:

| opt | name | arg | documented effect | line |
|---|---|---|---|---|
| `0x00` | End | N | end of options | `:53` |
| `0x80` | IDR | N | "Indicated that the frame is an IDR" | `:55` |
| `0x81` | Unimplemented | Y | "Takes one byte of argument but does nothing" | `:57-58` |
| `0x82` | Frame Rate | Y | 0=59.94 Hz, 1=50, 2=29.97, 3=25 | `:60-61` |
| `0x83` | **Force Decoding** | N | **"Forces decoding even if buffer is too small."** | `:63-64` |
| `0x84` | Unset Force Flag | N | "Unsets the force decoding flag" | `:66-67` |
| `0x85` | **NumMbRowsInChunk** | Y | "Usually 6 (6 * 16px * 5 chunks = 480px)" | `:68-69` |

`0x83` is the single most interesting option for a corruption document: it is by-name a switch that makes the
decoder proceed with a buffer it considers too small, and it is on in **every** packet — libdrc unconditionally
(`vstrm-packet.cpp:50`), Barista unconditionally (`barista-ref/core/drh/encoder/media_streamer.cpp:173`), and
measured on the real console in **all 73,500** datagrams (`[MEASURED]`, top ext values
`8200838506000000` × 73,454 and `8082008385060000` × 46). Barista's datasheet says its "exact hardware effect
remains unknown" (`barista-ref/docs/drc-media-packet-datasheet.md:71`).

### 2.3 Payload split logic and cap

`research/libdrc/src/video-streamer.cpp:56-96`:

```c
bool first_packet = true;
do {
  const byte* pkt_data = chunk_data;
  size_t pkt_size = std::min(kMaxVstrmPayloadSize, chunk_size);
  chunk_data += pkt_size; chunk_size -= pkt_size;
  bool last_packet = (chunk_size == 0);
  ...
  pkt->SetPayload(pkt_data, pkt_size);
  pkt->SetInitFlag(init_flag);
  pkt->SetFrameBeginFlag(first_chunk && first_packet);
  pkt->SetChunkEndFlag(last_packet);
  pkt->SetFrameEndFlag(last_chunk && last_packet);
  pkt->SetIdrFlag(idr);
  pkt->SetFrameRate(VstrmFrameRate::k59_94Hz);
```

* seq is a `u16` wrapped at 1024 (`video-streamer.cpp:77-80`); the packet only stores 10 bits
  (`vstrm-packet.cpp:83-86`).
* `init` is set on the first frame ever sent (`video-streamer.cpp:51-54`) — the pc2drc fork documents why it
  must never be re-asserted (`pc2drc/.../src/video-streamer.cpp:90-99`).
* `SetPayload` asserts `size <= kMaxVstrmPayloadSize` then writes `pkt_[2]`/`pkt_[3]` from the size and
  **memcpy's into `pkt_.data() + 16`** (`vstrm-packet.cpp:112-118`) — the assert is the only bound.

**Cap constants across the corpus:**

| implementation | cap | citation |
|---|---|---|
| libdrc (upstream) | **1400** | `research/libdrc/include/drc/internal/vstrm-packet.h:37` |
| wozt fork | **1400**, with a measured note | `research/wozt-libdrc/include/drc/internal/vstrm-packet.h:38-42` |
| pc2drc fork | **1694** (`//1586; //set to 1600 if this doesn't work pls thx <3 -thefloppydriver`) | `pc2drc/libdrc-vnc/libdrc-thefloppydriver/include/drc/internal/vstrm-packet.h:39` |
| Barista | **1694** | `barista-ref/core/drh/encoder/media_streamer.cpp:53-56` |
| real console | **1694** max, most common 1694 (UDP 1710) | `[MEASURED]` + `research/GROUND-TRUTH-SESSION.md:76` |

### 2.4 What the pad tolerates — every comment in the corpus that describes pad-side behaviour

1. **`research/wozt-libdrc/include/drc/internal/vstrm-packet.h:36-42`** — the single clearest pad-side
   failure-mode statement anywhere in the repo:
   > "Measured: at 1700 the GamePad stops decoding outright and asks for a keyframe on every frame, so its
   > **reassembly gives out somewhere below that**. The ~1793-byte frames a real console sends must be its
   > audio rather than its video. At 1400 the packet rate lands within a few of the console's own."
   (The second sentence is wrong — the console's 1710-byte datagrams *are* video, `[MEASURED]` — but the
   first is the empirical bound.)
2. **`sc-vstrm.rst:73-89`** — the pad expects the picture split into **5 chunks of 6 macroblock rows**;
   "the last packet of a chunk needs to have the `chunk_end` flag set"; `frame_begin` only on the very first
   packet; `frame_end` only on the last packet of chunk 5.
3. **`barista-ref/docs/drc-media-packet-datasheet.md:57`** — "H.264 payload byte count. **Must equal UDP
   payload length minus 16.**"
4. **`barista-ref/docs/drc-media-packet-datasheet.md:100-103`** — "The `chunk-end` flag ends one logical
   chunk, not necessarily one UDP datagram."
5. **`barista-ref/docs/drc-media-packet-datasheet.md:120-130`** — the payload is *not* a self-contained H.264
   stream (no Annex-B start codes, no SPS/PPS/slice header), and "The GamePad has a fixed decoder configuration
   for the 864x480 surface."
6. **`barista-ref/docs/drc-media-packet-datasheet.md:52`** — for `init`: "Confirmed wire position; **receiver
   semantics partly inferred**."
7. **`research/GROUND-TRUTH-SESSION.md:58, 78-79`** — first frame = 25 datagrams all carrying `init` **and**
   the IDR option; `init` on **25 packets only**, never re-asserted; `[MEASURED]` I confirm 46 IDR-option
   packets and that `init` appears only in the first frame.
8. **`research/GROUND-TRUTH-SESSION.md:65-66`** — "The pad tolerates ~14 s of video it cannot use before it
   asks [for a resync]."
9. **`research/CODEC-SPEC.md:302-304`** — "payload ≤ **1694** B … 5 chunk-ends and exactly one frame-end per
   frame, 10-bit sequence, per-frame timestamp shared by all its packets."

### 2.5 Barista's construction vs libdrc's — the ext-option ordering bug

Barista `reference_options=false` (first build path, `barista-ref/core/drh/encoder/media_streamer.cpp:173-180`)
writes `83 85 06 [80] 82 00` — force-decode first. `reference_options=true` (`:181-193`) rewrites bytes 8-15 in
the **console order**: `[80] 82 00 83 85 06` then zeros, with the comment "Same options, in the order observed
in authenticated console traffic."

pc2drc discovered that the libdrc order was fatal, in
`pc2drc/libdrc-vnc/libdrc-thefloppydriver/src/vstrm-packet.cpp:52-90`:

```
//   IDR : 80 82 00 83 85 06 00 00
//   P   : 82 00 83 85 06 00 00 00
// Upstream libdrc pre-filled pkt_[8..10] with 83 85 06 and appended 80/82 after
// them, emitting "83 85 06 [80] 82 00" - force-decode first and the IDR marker
// in the middle. Measured live on 2026-11-04: the pad then never starts
// decoding (zero resync requests, pad falls back to its "cannot connect"
// screen) even though the slice data itself is conformant.
```

and `NormalizeExtOptions()` (`vstrm-packet.cpp:65-90`) rebuilds `80 82 00 83 85 06 00 00` /
`82 00 83 85 06 00 00 00`, called from `SetIdrFlag`, `SetFrameRate` and `SetPayload`
(`:137`, `:147`, `:156`). This is the strongest available evidence that **the pad's vstrm parser is a strict,
position-sensitive option walker**: the same option bytes in a different order change whether decoding starts
at all. `[SRC]` + the fork's own measured claim.

I confirm the console's order on the wire `[MEASURED]` — exactly two distinct ext-option byte strings in
73,500 datagrams:
`82 00 83 85 06 00 00 00` (73,454, P) and `80 82 00 83 85 06 00 00` (46, IDR).

### 2.6 Sequence packing: the repo doc is wrong, the console matches libdrc

`research/GROUND-TRUTH-SESSION.md:81` claims: "`b0 = 0xF0 | seq[9:6]`, **`b1 = seq[5:0]`**" and `:163` builds
a whole "differs, tolerated by pad" verdict on it. **This is measurably wrong.** Reproduce:

```sh
cd /home/kali/Wiiu && python3 - <<'PY'
import struct, collections
d=open('out/evidence/truth/port50120.bin','rb').read(); o=0; pk=[]
while o+20<=len(d):
    ts,si,di,ln=struct.unpack(">d4s4sI",d[o:o+20]); o+=20; pk.append(d[o:o+ln]); o+=ln
print(collections.Counter("%02x"%p[0] for p in pk))
A=[((p[0]&3)<<8)|p[1] for p in pk]; B=[((p[0]&0xf)<<6)|(p[1]&0x3f) for p in pk]
f=lambda s: sum(1 for a,b in zip(s,s[1:]) if (a+1)%1024==b)
print("libdrc/barista packing contiguous:", f(A), "/", len(A)-1)
print("doc's 4+6 packing contiguous:   ", f(B), "/", len(B)-1)
PY
```

* byte 0 takes **only** `f0, f1, f2, f3` (18,426 / 18,430 / 18,430 / 18,214) ⇒ the low 2 bits are `seq[9:8]`,
  exactly as `sc-vstrm.rst:26` (`u32 seq_id : 10` after 4-bit magic and 2-bit type) and
  `vstrm-packet.cpp:55-57, 83-86` implement it.
* libdrc/Barista packing is contiguous for **73,490 / 73,499** transitions; the doc's 4+6 packing only for
  **72,558 / 73,499**. The 9 real discontinuities are `(804→938), (45→48), (415→417), (662→664), (374→376),
  (201→203), (714→716), (31→33), (73→75)` — i.e. dropped packets.
* Also verified: **`len` field == UDP length − 16 in all 73,500 datagrams** (0 mismatches), so the console's
  length field is self-consistent; and byte 2's top flags on the first packet are `0xce` =
  `init|frame_begin|ts-present|len[10:8]=6` with `b3=0x9e` ⇒ payload 1694 (`console-messages/video_first_frame.bin`).

### 2.7 Barista's packets compared field by field

`barista-ref/core/drh/encoder/media_streamer.cpp:159-196` builds the header in 9 straight assignments:
`packet[0] = 0xf0 | ((sequence >> 8) & 3)`, `packet[1] = sequence`,
`packet[2] = 0x08 | init?0x80 | frame_begin?0x40 | chunk_end?0x20 | frame_end?0x10 | ((len>>8)&7)`,
`packet[3] = len`, `4..7` big-endian timestamp, `8..` options. It also self-tests the maximum layout
(`barista-ref/core/drh/encoder/media_streamer.cpp:521-528`: `maximum_packet.size() != 16 + kMaxVideoPayload ||
(maximum_packet[2] & 7) != (kMaxVideoPayload >> 8) || maximum_packet[3] != (kMaxVideoPayload & 0xff)` → error
"maximum VSTRM payload layout validation failed"). Notable: Barista's self-test asserts the 11-bit length split
survives at 1694 (`0x69e` → `len[10:8] = 6`), i.e. the cap is close to the field's own 2047 limit but the
*receiver's* tolerance is lower (§2.4 item 1).

---

## 3. `astrm` audio + the 32-byte video-format message (UDP 50021 → 50121)

### 3.1 Header field packing

Declared struct `[DOC]` (`research/libdrc/web/docs/re/sc-astrm.rst:27-35`):

```c
struct AstrmHeader {
  u16 format : 3; u16 mono : 1; u16 vibrate : 1; u16 type : 1;
  u16 seq_id : 10; u16 payload_size : 16; u32 timestamp : 32;
};
```

Implemented bits (`research/libdrc/src/astrm-packet.cpp`, header size 8 + payload 1700 in
`research/libdrc/include/drc/internal/astrm-packet.h:33-34`):

| byte | content | line |
|---|---|---|
| 0 bits 7-5 | `format` (`pkt_[0] >> 5`) | `astrm-packet.cpp:49-51` |
| 0 bit 4 | `mono` | `astrm-packet.cpp:110` |
| 0 bit 3 | `vibrate` | `astrm-packet.cpp:111` |
| 0 bits 2-3 | `type` (0 audio, 1 video-format) | `astrm-packet.cpp:53-55`, `astrm-packet.h:45-48` |
| 0 bits 1-0 ‖ 1 | 10-bit `seq_id` | `astrm-packet.cpp:57-59` |
| 2-3 | `payload_size`, **big-endian 16-bit** | `astrm-packet.cpp:69-71`, `:97-98` |
| 4-7 | timestamp, **little-endian** | `astrm-packet.cpp:61-63`, `:86-91` |

Formats: 0 PCM24k, 1 PCM48k, 2 A-law 24k, 3 A-law 48k, 4 µ-law 24k, 5 µ-law 48k
(`astrm-packet.h:36-43`, doc `sc-astrm.rst:39-46`).

Measured `[MEASURED]`: 41,715 records in `port50121.bin`, of which 27,573 are 1672 B and 14,142 are 32 B.
Byte 0 of the PCM packets takes `0x20, 0x21, 0x23, 0x22` ⇒ format `0x20>>5 = 1` = PCM 48 kHz, mono bit
`0x10` clear, vibrate `0x08` clear, type `0x04` clear, seq low bits varying ✓. `payload_size` = `0x0680` in
all 27,573 and equals `udp_len − 8` in all of them.

### 3.2 The 32-byte video-format message

libdrc's version (`research/libdrc/src/video-streamer.cpp:99-117`) is a **24-byte body inside the normal Astrm
8-byte header**, timestamp forced to `0x00100000`, and a payload of:

```c
byte payload[24] = {
  0x00,0x00,0x00,0x00, 0x80,0x3e,0x00,0x00, 0x80,0x3e,0x00,0x00,
  0x80,0x3e,0x00,0x00, 0x80,0x3e,0x00,0x00, 0x00,0x00,0x00,0x00 };
payload[0..3] = ts little-endian;
```

i.e. libdrc's bytes 4-7 of the body are the timestamp, then **four** `16000` (0x3e80) fields. It sets
`SetPacketType(kVideoFormat)` = type bit `0x04` and `SetTimestamp(0x00100000)`, so byte 0 is `0x04`
(`astrm-packet.cpp:77-79`; `0x04 >> 2 & 1 = 1`).

pc2drc rebuilt it correctly as a real 32-byte datagram, with the layout and constants spelled out
(`pc2drc/libdrc-vnc/libdrc-thefloppydriver/src/video-streamer.cpp:141-198`):

```
//   04 00 00 00  11 11 81 08  <ts LE>  80 3e 00 00 80 3e 00 00
//   08 52 00 00  08 52 00 00  00 00 00 00
// The outer length field is deliberately zero even though a 24-byte body
// follows - the real console does the same. The clock fields are 16000,
// 16000, 21000, 21000 microseconds.
```

Offsets: `pkt[0]=0x04` type; `pkt[4..7]` = outer bytes, env-overridable via `DRC_FORMAT_OUTER`
(`:169-181`); `pkt[8..11]` = LE timestamp; `pkt[12..15] = 80 3e` (16000); `pkt[16..19] = 80 3e`;
`pkt[20..23] = 08 52` (21000); `pkt[24..27] = 08 52`; `pkt[28..31] = 0` (`:182-192`).

**`11 11 81 08` vs `00 00 00 00` — every comment in the corpus:**

* `pc2drc/.../video-streamer.cpp:170-176`: "Bytes 4..7: a decrypted real console session sends `00 00 00 00`
  in *every* one of 14,142 format messages (2026-11-04, research/GROUND-TRUTH-SESSION.md sec.4). The datasheet
  value `11 11 81 08` is what Barista sends - and Barista works - so this is **tolerated**, but the console is
  zeroes, so default to zeroes. `DRC_FORMAT_OUTER=11118108` restores the old bytes."
* `barista-ref/docs/drc-media-packet-datasheet.md:170-171`: "Declared outer payload length. **The real console
  deliberately leaves it zero despite the following 24-byte body. Do not flag this alone as malformed.**" and
  "4..7 … The historical authenticated reference used `11 11 81 08`; local Vanilla controls use `11 11 81 88`;
  the fresh authenticated capture uses `10 10 81 08`. **Their meaning is not established.**"
* `research/GROUND-TRUTH-SESSION.md:91-102`: the decrypted console sends `00 00 00 00` in all 14,142.
* `research/CODEC-SPEC.md:138-145`: our stack's mismatch (outer `00 00 10 00`, four `16000` fields) and the
  judgement "this is probably tolerated".
* `sc-astrm.rst:52-54`: "If the packet type flag indicates that the packet is video format information, **all
  the other header fields are ignored** and the payload is interpreted as a video format header." — that is the
  pad-side parsing rule for this packet class.
* `sc-astrm.rst:63-71`: `struct AstrmVideoFormat { u32 timestamp; u32 unknown_freq_0[2]; u32 unknown_freq_1[2];
  u32 video_format; }` and "The timestamp should match the timestamp sent in the `vstrm` packets for that frame."

`[MEASURED]` I confirm: exactly 14,142 format datagrams, **one** distinct 28-byte body after masking the
4-byte timestamp (`04 00 00 00 | 00 00 00 00 | ts | 80 3e 00 00 | 80 3e 00 00 | 08 52 00 00 | 08 52 00 00 |
00 00 00 00`), i.e. outer bytes really are all-zero for the whole session, and the *only* place in the entire
protocol where declared length ≠ actual length (0x0000 declared vs 24 bytes present). Useful for the
memory-corruption doc: **this is the packet class that trains a lenient parser.**

### 3.3 The 1664-byte PCM framing

| implementation | samples/packet | payload | period | citation |
|---|---|---|---|---|
| libdrc | 384 (768 `s16`) | **1536** | 8 ms | `research/libdrc/src/audio-streamer.cpp:40-48` ("must be < 1600 bytes", `384 samples == one 1536b packet every 8ms`), `:83-100` |
| pc2drc | **416** | **1664** | 8.666 ms | `pc2drc/.../src/audio-streamer.cpp:47-52` |
| Barista | **416** | **1664** | 8,666,666 ns (static_assert) | `barista-ref/core/drh/encoder/media_streamer.cpp:57-62`, buffer at `:456` |
| real console | **416** | **1664** (payload_size `0x0680`) | 8.666 ms | `[MEASURED]` (27,573 packets, all `0x0680`) |

pc2drc's comment is the only one that frames this as a validation gate:
`pc2drc/.../src/audio-streamer.cpp:47-50` — "The console sends 416 stereo frames (1664 B of PCM) every 8.666…
ms; Barista reproduces that byte-for-byte. libdrc used 384 frames / 8 ms / 1536 B, which is not what the pad
sees from a real console and is **the obvious thing for a media service to validate** before it starts an
audio/video session."

Barista datasheet numbers: `barista-ref/docs/drc-media-packet-datasheet.md:132-152` (8-byte header + 1664 B,
`0x0680` length, LE timestamp, "a non-vibrating packet starts with `23 21 06 80 78 56 34 12`").
libdrc's own rate math: `research/libdrc/src/audio-streamer.cpp:40-48`. Buffer cap on the producer side:
`samples_.size() < kSamplesPerSecond * 32` i.e. 32 s of samples (`audio-streamer.cpp:110`).
`PopSamples` can also return a **zero-filled** buffer of the requested length when starved
(`audio-streamer.cpp:115-125`), which is what makes the fixed 1664/1536 size hold.

`research/CODEC-SPEC.md:155-160` gives the bandwidth consequence: PCM = 1664 B payload + 8 B header at
115.4 pkt/s = 1.54 Mbps, total ~786 pkt/s for the whole session.

---

## 4. Port 50025 → 50125 (the 96-byte table)

### 4.1 What the docs say

* `research/libdrc/web/docs/re/services.rst:23` — the port table row: console `50025` → pad `50125`,
  "To Console: **N**, To Pad: Y", description literally `:doc:`???``. It is listed under "GamePad 1" and is
  **absent** from the GamePad 2 table (`services.rst:26-37`), suggesting it is tied to the pad's own UI/panel
  rather than to a per-pad service id.
* `port 50023`/cmd, `50022`/input, `50020`/video, `50021`/audio, `50010`/msg are the other rows
  (`services.rst:15-24`, DRH-only broadcast row at `:43`).
* `research/libdrc/web/docs/re/sc-msg.rst:1-3` is `TODO` — the msg protocol on 50010/50110 is undocumented in
  libdrc.

### 4.2 What libdrc implements: nothing

`research/libdrc/include/drc/streamer.h:47-52` lists only `50010, 50022, 50023` binds and `50120, 50121, 50123`
destinations. No `50125`. The word 50025 does not appear anywhere in `research/libdrc/src/` or `include/`.

### 4.3 What Barista implements: a bound but unparsed channel

`research/barista-ref/core/drh/runtime_transport.cpp:41,45`

```c
constexpr uint16_t kConsoleUnknownPort = 50025;
constexpr uint16_t kGamepadUnknownPort = 50125;
```

bound as a receive socket at `:484` (`m_unknown_fd = MakeSocket(config, kConsoleUnknownPort, false, error)`),
mapped in the poll loop at `:756`, and every datagram that arrives on it falls into the else branch at
`:835-853` where it is only counted (`m_unknown_packets_received`) and reported once with its size. **No struct
definition, no field parsing anywhere in Barista.** Its send path exists (`:602` sends `Unknown` channel to
`kGamepadUnknownPort`) but nothing calls it. `research/GROUND-TRUTH-SESSION.md:118-122` says exactly this:
"Barista binds 50025 as a receive port and leaves it 'unknown'."

### 4.4 The 96-byte table — measured content

`out/evidence/truth/console-messages/cmd_50025_table.bin` (96 B) and `port50125.bin` (**220 datagrams, all
exactly 96 B, all 220 distinct** after the counter/ramp advance):

```
00 00 00 00 | 58 00 00 00 | 5a a5 | 58 00 | 00 03 | 00 00 | ff 00 00 00 | 01 00 00 00 | 00 00 00 00
10 00 10 00 10 00 18 00 20 00 28 00 30 00 38 00 40 00 48 00 50 00 58 00
60 00 68 00 70 00 78 00 80 00 88 00 90 00 98 00 a0 00 a8 00 b0 00 b8 00
c0 00 c8 00 d0 00 d8 00 e0 00 e8 00 eb 00 eb 00 eb 00 00 00
```

* magic `5a a5` at offset 8, `58 00` at offset 4 and offset 10, `00 03` at 14, `ff 00 00 00` at 16,
  `01 00 00 00` at 20 (`[MEASURED]`).
* **A u16 counter at offset 6** increments 0,4,5,6,… (`research/GROUND-TRUTH-SESSION.md:120-122`;
  `pc2drc/.../src/streamer.cpp:162-164` writes `pkt[6] = counter & 0xFF; pkt[7] = counter >> 8`).
* Then a monotonic 16-bit **ramp of byte offsets**, step 8, `0x0010 … 0x00e8`, then three copies of `0x00eb`
  and a zero terminator. 55 non-zero bytes total (`GROUND-TRUTH-SESSION.md:214`). This looks like a
  per-row/per-tile address or offset table for the panel. `[SPECULATIVE]`
* Timing: starts the same instant as the console's UVC/UAC polling and the video, ~0.96-1/s
  (`GROUND-TRUTH-SESSION.md:59, 118`). Why: unknown (`GROUND-TRUTH-SESSION.md:214`).

### 4.5 pc2drc is the only implementation that sends it

* Constant table, 96 bytes, verbatim from the capture:
  `pc2drc/libdrc-vnc/libdrc-thefloppydriver/src/streamer.cpp:67-78` (`const byte kPanelTable[96] = {...}`,
  comment: "The console's 96-byte 50025 table, captured verbatim (only the u16 counter at offset 6 changes per
  message)").
* Socket is created with source port 50025 and SO_PRIORITY 5: `streamer.cpp:94`
  (`panel_client_(new UdpClient(HostPart(vid_dst) + ":50125"))`) and `streamer.cpp:124`
  (`panel_client_->Start(50025, 5)`); a bind failure is non-fatal by design (`streamer.cpp:122-126`).
* `Streamer::SendPanelTable()` copies the template, stamps the counter, sends 96 bytes
  (`streamer.cpp:159-166`). Public API documented at `include/drc/streamer.h:140-146`: "A real console sends a
  fixed 96-byte table to the pad on UDP 50025 -> 50125 about once a second, starting at the moment video
  begins … Returns false if the socket is not up. Call it ~1 Hz."
* The replayer treats it as a first-class stream: `run/replay-console-session.py:44`
  (`50125: (50025, "port50125.bin", "panel table")`) and excludes it from timestamp rewriting at `:197`.

---

## 5. DHCP (what our AP hands the pad)

### 5.1 What runs on our side

* `run/drc-up.sh:180-187` starts a purpose-built DHCP server, **not** dnsmasq/udhcpd:
  ```sh
  setsid nohup "$ROOT/pc2drc/drc-hostap/netboot/netboot" \
    192.168.1.255 192.168.1.10 192.168.1.11 "$PAD" > /var/log/drc-dhcp.log 2>&1 &
  ```
  i.e. `<broadcast> <server ip> <lease ip> <client mac>` with `PAD=40:d2:8a:17:e2:09` (`drc-up.sh:40`),
  server `192.168.1.10/24` (`drc-up.sh:157`). MTU is forced to 1800 on the AP (`drc-up.sh:158`)
  — the same 1800-byte session MTU Barista uses (`barista-ref/core/drh/server/backend_linux.cpp:624`
  option 26).
* The DHCP server is `pc2drc/drc-hostap/netboot/netboot.c` (brokestream `netboot`, header comment
  `netboot.c:1-28`). Its behaviour:
  * binds `0.0.0.0:67` and additionally the server address, plus TFTP 69 (`netboot.c:164-184`);
  * drops `p[0] == 2` (replies) and any packet whose **chaddr does not match the configured MAC pattern**
    (`netboot.c:214`, `:233` `if(memcmp(p+28+macskip,macpat,(6-macskip))) continue;`);
  * parses options from fixed offset 240 walking `i += p[i+1] + 2` until `0xff` (`netboot.c:217-226`) — no
    bounds check against the received length (the 1500-byte buffer is zero-initialised, so the walk terminates
    on the zero padding);
  * **options it sends** (`netboot.c:237-295`): `97` (client UUID, echoed back from the request),
    `53` (OFFER=2 / ACK=5), `51` lease time `0xffffffff`, `54` server identifier = console IP,
    `60` vendor class `"PXEclient"`, `43` vendor-specific (`6,1,0` then `8,7,0,0,1,<server ip>` then `255`),
    and for ACK only also `1` subnet mask `255.0.0.0`, `12` hostname `"pxeclient"`, `67` boot file
    `"pxelinux.0"`;
  * `yiaddr = cc` (the pad's IP), `siaddr = sc` (`netboot.c:242-243`), reply sent to broadcast:68
    (`netboot.c:292-294`). **No option 3 (router), no option 28 (broadcast), no DNS options** — the pad gets
    an address and a server id only.
* Barista's own DHCP server is the sanitised reference implementation of the same thing:
  `barista-ref/core/drh/server/backend_linux.cpp:599-628` (`BuildDhcpReply`) sends `53`, `54`
  (console IP), `51` (`kDhcpLeaseSeconds`), `1` = `255.255.255.0`, `3` router, `28` broadcast, `26` MTU
  (`kSessionMtu`), `255`. Option parsing with bounds checks at `:580-597` (`if (i + option_length > length) break;`).
* `run/05-diagnose.sh:34-36` treats "has 192.168.1.11" as the layer-3 gate (`ip neigh`, `ping`).
* The captured pad DHCP traffic is only **6 packets** for the whole 300 s session
  (`research/GROUND-TRUTH-SESSION.md:125`; `[MEASURED]` `out/evidence/truth/port67.bin` = 6 × 300 B).

### 5.2 What the docs say the pad needs

* `research/libdrc/web/docs/re/wifi.rst:56-57` — "After that, the GamePad sends a DHCP request and the console
  answers it with an IP (default: `console=192.168.1.10 gamepad=192.168.1.11`)." That is the whole documented
  requirement: no option negotiation described, fixed addressing.
* `run/05-diagnose.sh:36` — "ICMP: no reply (DHCP may not be serving yet)".
* Nothing anywhere states that the pad validates options 1/3/26/28, and our `netboot` does not send 3/28 at
  all while the pad still came up at `192.168.1.11` (`run/drc-up.sh:4-6`, "Verified working 2026-11-04 …
  DHCP 192.168.1.11"). `[MEASURED]` by the operator, documented.
* Whether the pad's DHCP client is vulnerable (option-length walking, option 43/97 echo) is
  `[UNVERIFIED]` — the pad's DHCP client lives in the BCM4319 firmware or the LVC `nwk` manager
  (`research/libdrc/web/docs/re/overview.rst:139` "nwk - handles high-level network (IP/UDP layer)") and we
  have no code for either.

---

## 6. The 802.11 layer

### 6.1 Which processor runs which code — the documented split

`research/libdrc/web/docs/re/overview.rst:43-54` `[DOC]`, verbatim:

> **BCM4319XKUBG** — A Broadcom Wi-Fi chip that is not so custom - it was actually used in a few other
> products, including the Boxee TV box. The firmware running on it is a fairly standard Broadcom SDIO chip
> firmware with very slight alterations from Nintendo. … It is capable of 802.11n on 5GHz frequency bands,
> which is the requirement to communicate with a Wii U console.
> **The firmware on this Broadcom chip runs on a Cortex-M3 CPU**, which is amusingly more recent than the
> ARM926EJ-S running the main firmware.

and `overview.rst:25-34`: the main SoC is "based on an ARM926EJ-S CPU" and runs the `LVC` firmware
(`overview.rst:74-77`, eForce/µITRON 4.0). `research/libdrc/web/docs/re/boot.rst:53` names the image:
"`WIFI` - code for the Wi-Fi dongle (Cortex-M3)".

**Therefore the split is:**

| layer | owner | evidence |
|---|---|---|
| 802.11 MAC/PHY, rate control, RTS/CTS, BlockAck/ADDBA, CCMP crypto, beacons/probe *transmission* | **BCM4319 Cortex-M3 firmware** | `overview.rst:43-54` |
| WPA2 supplicant / 4-way handshake *logic*, key install, EAPOL frames | firmware + LVC `wifi` driver (`overview.rst:108` "wifi - Wi-Fi networking", `:131` "con - handles low-level network (Wi-Fi layer)") | `overview.rst:108,131` |
| the Nintendo OUI selectors and the 3-byte PTK rotation | Nintendo-modified Broadcom firmware ("very slight alterations", `overview.rst:45-47`) + our hostapd patch | `wifi.rst:44-54` |
| IP/UDP, and every DRC service parser listed in §0 | **LVC (ARM926)** `nwk` manager + service tasks | `overview.rst:110-123,139` |

And on the pad's *own* side of the pass-through, `research/BOOT-AND-MODES.md:47-56` draws the same SoC map
(`DRC-WUP "LVC", the ARM9 … ARM926EJ-S` / `BCM4319 (Cortex-M3)`), whose S2 stage loads the `WIFI` image
(`BOOT-AND-MODES.md:89`).

The consequence for our side: the parts we can configure end-to-end (beacon contents, RSN IE, WPS) are
**host-side** (hostapd builds the IEs, mac80211/firmware transmits them); the parts the pad *parses*
(RSN IE, WPS IEs, EAPOL) are parsed by the Cortex-M3 firmware, and only the resulting key material and IP
traffic reaches the ARM9. `[SPECULATIVE]` for the exact parse boundary inside the Broadcom firmware.

### 6.2 The Nintendo OUI selectors (a4:c0:e1)

The patch is `CONFIG_TENDONIN`, described at `research/drc-hostap/README.DRC:7-12`:

> Added a new compile-time option: `CONFIG_TENDONIN` — Enables Wii U Gamepad specific Wi-Fi modifications:
> WPA PTK rot3 and WPS KDK rot3; Changes the RSN selectors to use the Nintendo selector values (a4-c0-e1);
> Changes the WPS AP detection to detect a Wii U pairing AP as a WPS compatible AP.

Exact constants (`research/drc-hostap/src/common/wpa_common.h`):

```c
#ifdef CONFIG_TENDONIN                                            // :50
#define RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0xa4, 0xc0, 0xe1, 2)   // :51
#else
#define RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#endif
...
#ifdef CONFIG_TENDONIN                                            // :76
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0xa4, 0xc0, 0xe1, 4)               // :77
#define RSN_CIPHER_SUITE_CCMP_256 RSN_SELECTOR(0xa4, 0xc0, 0xe1, 10)          // :78
#else
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
```

`RSN_SELECTOR` is 4 bytes big-endian (`wpa_common.h:36-38`). So the RSN IE we emit carries
**group = `a4:c0:e1:04`, pairwise = `a4:c0:e1:04`, AKM = `a4:c0:e1:02`**, matching the documented pad
requirement (`research/libdrc/web/docs/re/wifi.rst:44-46`) and the failure mode when absent:
"it needs to advertise the support for these algorithms or the Wii U will refuse your connection with **error
code 0x000c**" (`wifi.rst:48-51`).

WPS device OUI: `research/drc-hostap/src/wps/wps_defs.h:283`
`#define WPS_DEV_OUI_NIN ((0x00a4c0e1 << 8) | 0xf4)` and `device_type=6-a4c0e1f4-1`
(`research/drc-hostap/conf/wiiu_ap_pairing.conf:77`, `barista-ref/core/drh/server/backend_linux.cpp:466`),
asserted in Barista's test `barista-ref/core/tests/hostapd_wps_tests.c:25`
(`WPA_GET_BE32(bytes + 2) == 0xa4c0e1f4`).

### 6.3 PTK 3-byte rotation and GTK/KDE

* **PTK:** `research/drc-hostap/src/common/wpa_common.c:187-192` — after PRF, rotate the whole PTK **3 bytes
  left**:
  ```c
  #ifdef CONFIG_TENDONIN
      u8 rotate_data[3];
      memcpy(rotate_data, tmp, 3);
      memmove(tmp, tmp + 3, ptk_len - 3);
      memcpy(tmp + ptk_len - 3, rotate_data, 3);
  #endif
  ```
  (`tmp` is the freshly computed PTK from `sha1_prf`, `wpa_common.c:185`.) Documented at `wifi.rst:53-54`
  ("The only difference between the Nintendo Pairwise CCM and the standard pairwise CCM is a 3 bytes rotation
  of the `PTK` to the left after it's computed") and confirmed independently in
  `research/GROUND-TRUTH-SESSION.md:18` ("stock PRF-512, then Nintendo's **3-byte left rotation of the whole
  PTK** (`rot3`)").
* **WPS KDK:** the same rotation on the 32-byte KDK before `wps_kdf` —
  `research/drc-hostap/src/wps/wps_common.c:115-122` (debug print "WPS: KDK_ROT3"); rationale `wifi.rst:18-22`
  ("a normal WPS implementation will not compute the same *AuthKey* and fail at stage M2").
* **GTK / KDE:** `[MEASURED]` in the repo's own decryption work — `research/GROUND-TRUTH-SESSION.md:127-137`:
  msg3's key data AES-unwraps with the rotated KEK yielding "RSN IE + `dd 16 00 0f ac 01` KDE", GTKs
  `2ee6bbaac7a9012effa840f6aed71afdbd` (session 0) and `00e6bbaac7a9012effa840f6aed71afdbd` (sessions 1-2),
  with "No group-addressed data frame exists in the capture (0 multicast data frames), so the GTK is unused in
  practice — media is pairwise." The `dd 16 00 0f ac 01` is the Microsoft/Nintendo KDE wrapper
  (`00 0f ac 01` = `RSN_KEY_DATA_GROUPKEY`, `research/drc-hostap/src/common/wpa_common.h:95`), length `0x16`
  = 22 = 4-byte selector + 6-byte reserved + 8-byte GTK + 4-byte (2-byte key-id + 2-byte reserved tail).
  Our hostapd does not customise the KDE — it is stock `wpa_auth` emitting the standard vendor wrapper with the
  Nintendo group cipher id.
* **EAPOL key frame construction:** entirely stock hostapd/wpa_supplicant 2.12 with only the selector macros
  and the two rotations patched (`README.DRC:7-12`); `eapol_version=1` in the pairing config
  (`research/drc-hostap/conf/wiiu_ap_pairing.conf:66`). `[SRC]`; the exact frame bytes of a real 4-way
  handshake are in the capture but no plaintext EAPOL dump is checked in — `[UNVERIFIED]` for byte layout.

### 6.4 Beacons / probe responses / IEs — and the one unusually long configurable IE

`run/wiiu_ap_normal.conf.template` (the config we actually run; rendered by `run/drc-up.sh:160-167`) vs
`research/drc-hostap/conf/wiiu_ap_normal.conf` (the upstream sample). Relevant lines:

| item | our runtime config | upstream sample |
|---|---|---|
| `hw_mode=a`, `channel=__CHANNEL__` (default 149, `drc-up.sh:43`) | `template:10-11` | `conf:13-14` (`channel=36`) |
| `beacon_int=100`, `dtim_period=3` | `template:12-13` | `conf:15-16` |
| `auth_algs=3`, `wmm_enabled=1` | `template:15-16` | `conf:23-24` |
| `uapsd_advertisement_enabled=0` (deliberately **off**: pad leaves the BSS with reason 8 about once a
  minute otherwise) | `template:17-20` | `conf:27` (=1) |
| WMM AC parameters (BE/VI/VO txop 47/94/47, AIFS 2/3/3) | `template:22-44` | `conf:29-51` |
| **`rts_threshold=256`** — "every frame over 256 B (i.e. all video/audio) gets RTS/CTS" | `template:46-50` | absent |
| **`vendor_elements=dd09001018020000040000`** (Broadcom vendor IE `00:10:18` type 2, data `00 00 04 00 00`) | `template:52-55` | absent |
| `ieee80211n=1`; `#ht_capab=[GF]` commented ("wiiu uses greenfield, my driver doesn't support it / gamepad doesn't support it anyways") | `template:57-58` | `conf:53-56` |
| `ssid=__SSID__` (`WiiU<mac>`), **`ignore_broadcast_ssid=2`** | `template:60-63` | `conf:64-72` |
| `wpa=2`, `wpa_psk=`, `wpa_key_mgmt=WPA-PSK`, `wpa_pairwise=CCMP` (+ comment that CONFIG_TENDONIN rewrites them to the Nintendo OUI and applies the PTK rotation) | `template:65-70` | `conf:74-80` |

The **vendor_elements** line is the only genuinely long/configurable IE in our beacons: 9 bytes
(`dd 09 00 10 18 02 00 00 04 00 00` = 11 bytes with tag+len) added to match the console, with the rationale
"the last tag-level difference between our AP and the real one, measured 2026-11-04 from the decrypted
capture" (`template:52-54`). Barista adds a **19-byte** one instead, in the console's *ordering*, with a
comment that documents the intended tag sequence
(`barista-ref/core/drh/server/backend_linux.cpp:470-473`):

```
// Match the real Wii U pairing beacon ordering: Broadcom's vendor HT
// compatibility IE, Nintendo-OUI WPS IE, Broadcom compatibility IE,
// then WMM (the latter two are placed by the Tendonin hostapd patch).
"vendor_elements=dd0800904c0700513206dd09001018020100040000\n"
```

i.e. `dd 08 00 90 4c 07 00 51 32 06` + `dd 09 00 10 18 02 01 00 04 00 00`.
Note the two bytes that differ from ours: `02 01` vs `02 00` (Barista, pairing mode) — a mode selector inside
the vendor IE. Whether the pad's firmware parses this IE or only hashes/skips it is `[UNVERIFIED]`; note that
the pad **accepted our AP for a long time before the IE was added** (per `run/drc-up.sh:4-6`, live evidence is
post-fix), so it is not a hard requirement for association.

`run/drc-up.sh:154-156` also pins the AP's MAC to the console's BSSID ("The AP must advertise the console's own
MAC or the pad ignores it": `BSSID=cc:fb:65:b6:81:69`, `drc-up.sh:41`), and `drc-up.sh:166` injects
`ap_max_inactivity=86400`, `disassoc_low_ack=0`, `bssid=$BSSID`.

Pairing-mode config (`research/drc-hostap/conf/wiiu_ap_pairing.conf:62-81`): `ssid=WiiU…_STA1`, `ieee8021x=1`,
`eapol_version=1`, `eap_server=1`, `wps_pin_requests=/etc/hostapd/pinreq`, `wps_state=2`,
**`#ap_setup_locked=1` is commented out** (i.e. setup *not* locked), a fixed `uuid=22210203-0405-0607-0809-
0a0b0c0d0e0f`, `manufacturer=Broadcom`, `model_name=SoftAP`, `device_type=6-a4c0e1f4-1`,
`config_methods=label push_button`, `os_version=80000000`. The PIN scheme (first half on the TV as
♠♥♦♣ = 0/1/2/3, second half hardcoded `5678`) is documented at `wifi.rst:26-32`. Barista's version adds
`skip_cred_build=1`, `extra_cred=<file>`, `wps_cred_processing=1`
(`barista-ref/core/drh/server/backend_linux.cpp:457-461`) — i.e. Barista drives the registrar with a
pre-built credential blob rather than the `wps_pin` path. Our live scripts set the PIN through hostapd's
control interface instead: `run/pi-pair-wps.sh:1-8` and `barista-ref/.../backend_linux.cpp:2680-2689`
(`build_wps_pin_command(pin, timeout)` with a "corrected pin" fallback).

### 6.5 ADDBA / BlockAck, CTS-to-self, RTS thresholds

* **There is no ADDBA or BlockAck code in any of our stacks.** Grep over `research/libdrc`,
  `research/barista-ref`, `research/wozt-libdrc`, `pc2drc/libdrc-vnc`, `run/` finds no `ADDBA`/`addba` builder;
  Barista's `block_ack.py` only *parses* BlockAck frames out of a capture
  (`research/barista-ref/scripts/capture-analysis/block_ack.py:11` `class BlockAckIndex`).
  `[MEASURED]` on air: 16,894 GamePad→AP BlockAcks vs 17,166 AP→pad QoS data frames
  (`research/barista-ref/docs/drc-media-packet-datasheet.md:253`, `research/CODEC-SPEC.md:175`),
  so BlockAck aggregation is established by the *radio firmware* (Cortex-M3 on the pad,
  mac80211+device firmware on our AP). Our only influence is the aggregation/txop knobs and the MCS pinning.
* **RTS:** the console's real link is RTS/CTS protected on ~99 % of media frames — 16,936 RTS → 16,889 CTS on
  17,051 AP TID-5 frames (`drc-media-packet-datasheet.md:248-252`, `CODEC-SPEC.md:174`). We reproduce it two
  ways:
  * our template forces it globally by size: `rts_threshold=256` (`run/wiiu_ap_normal.conf.template:50`);
  * Barista pins it per-TID via `iw` and falls back to a global `iw phy … set rts 0`:
    `barista-ref/core/drh/server/backend_linux.cpp:1338-1343`
    (`RunIw({"dev", m_ap_interface, "set", "tidconf", "tids", "0x20", "rtscts", "on"})` — `0x20` = TID 5),
    restore path at `:1390-1410`. Barista also pins the rate: `iw dev … set bitrates ht-mcs-5 6 lgi-5`
    (`:1377-1382`, "fixed runtime TX rate to HT20 MCS 6 long GI"), matching the measured 99.93 % MCS-6/LGI
    (`drc-media-packet-datasheet.md:249`).
* **CTS-to-self:** not used anywhere in our configs. `[SRC]` (absent). RTS/CTS is our protection mechanism;
  no `cts`/`cts_protect`/`erp_protection` line exists in `run/wiiu_ap_normal.conf.template` or in
  `research/drc-hostap/conf/*.conf`.
* **QoS/TID:** media must land in **TID 5**, 99.33 % of the console's frames (`drc-media-packet-datasheet.md:248`).
  Our stack gets that from `SO_PRIORITY 5` on the media sockets — `pc2drc/.../src/udp.cpp:86-89`
  (`setsockopt(..., SO_PRIORITY, ...)`, comment "5 = voice, the category the console uses for media",
  `pc2drc/libdrc-vnc/libdrc-thefloppydriver/include/drc/internal/udp.h:42-49`), `barista-ref/core/drh/runtime_transport.cpp:53` (`kMediaSocketPriority
  = 5`) and `:54` (`kMediaIpTos = 0xa0`, i.e. DSCP 40) with `:421-433` applying both, and
  `run/replay-console-session.py:144` (`SO_PRIORITY, 5`).
* **HT capability IE:** `ieee80211n=1` only; `[GF]` deliberately not requested
  (`run/wiiu_ap_normal.conf.template:57-58`). Barista additionally ships a hostapd patch "0007 HT-advertisement
  patch (HT capabilities, A-MPDU, RIFS, and omission of Extended Capabilities and Supported Operating Classes)"
  (`research/barista-ref/COMPILING.md:33-39`) — i.e. Barista *removes* Extended Capabilities and Supported
  Operating Classes from the beacon, which is a pad-facing IE-set difference our stack does not implement.
  `[SRC]`+`[DOC]`.

---

## 7. Input path (pad → console): 50122 → 50022, plus 50010/50110 and 50125

### 7.1 Ports

`research/libdrc/web/docs/re/services.rst:19` — input is Console `50022` ← Pad `50122`, "To Console: Y, To Pad:
**N**" (a pad-only uplink). Message/DRH port: Console `50010` ← pad `255.255.255.255:50110` broadcast
(`services.rst:43`). `run/05-diagnose.sh:5-13` restates the whole table and is the authoritative map for our
deployment.

### 7.2 What we send on it: nothing (we only bind 50022)

* libdrc binds `192.168.1.10:50022` (`research/libdrc/include/drc/streamer.h:48`) with a `UdpServer`, and only
  receives (`research/libdrc/src/streamer.cpp:79`, `research/libdrc/src/input-receiver.cpp:64-80`). No send
  path exists to 50122 anywhere in `research/libdrc/`.
* The pad sends from its own `50122`; the source-port check on our side is only "whatever the kernel reports" —
  `research/libdrc/src/udp.cpp:152-161` captures `sender` and **discards it**. Barista at least checks the
  source *address*: `research/barista-ref/core/drh/runtime_transport.cpp:806-807`
  (`if (source.sin_addr.s_addr != m_gamepad_address.sin_addr.s_addr) return false;`).

### 7.3 What we parse (128 bytes, fixed)

* libdrc: `research/libdrc/src/input-receiver.cpp:141-145` — `if (msg.size() != 128) return;`
  (comment: "HID packets should always be 128 bytes"), then fixed offsets:
  `buttons = (msg[80] << 16) | (msg[2] << 8) | msg[3]` (`:149`), four sticks as `s16` at `6+2i` (`:156`),
  10 touch points at `36 + 4*i` (`:176-184`), pressure nibbles at `37/39/41/43` (`:193-196`),
  `battery_charge = msg[5]` (`:202`), `audio_volume = msg[14]` (`:203`), `power_status = msg[4]` (`:204`).
  Highest byte touched = `80`; buffer is 128 ⇒ safe. Sticks are clamped to `[900, 3200]` (`:159-170`).
* Barista: `research/barista-ref/core/drh/runtime_transport.cpp:816-822` (`if (payload.size() != 128) return
  false;`) and `DecodeInput` at `:137-150` reading the same offsets **plus** two extra fields:
  `sequence = ReadBe16(packet)` (`:140`) and **`waiting_for_streaming = (packet[83] & 1u) != 0`** (`:148`).
  That last one is the pad's "ready for media" bit and Barista gates its media on it
  (`run/drc-up.sh:214` — "Barista gates media on the same condition (input seen on 50022 plus a validated
  UVC/UAC reply)"; `research/barista-ref/core/drh/runtime_transport.cpp:1115,1118-1125` logs
  "GamePad streaming state: waiting/active").
* Documented layout and masks: `sc-input.rst:25-62` (buttons mask, power status bits
  `AC_PLUGGED_IN 0x01 / POWER_BUTTON_PRESSED 0x02 / CHARGING 0x40`), `:87-97` (10 touch points, `pad:1 /
  extra:3 / value:12`), `:105-117` (pressure in the `extra` field of points 1-2, **UIC firmware version in the
  `extra` of points 6-8**), `:15-16` ("The 128 bytes blob is generated on the UIC and received unmodified by
  IOSu"), `:11-13` ("sent by each GamePad **180 times per second**").
* Measured `[MEASURED]`: `out/evidence/truth/port50022.bin` is 7,216,480 bytes = 48,760 records × (20 B record
  header + 128 B payload) = **48,760 × 128 B**, matching `research/GROUND-TRUTH-SESSION.md:124`
  ("Pad input: 48,760 × 128 B on 50122 → 50022 (≈163/s)"). So every input datagram in the session is exactly
  128 B — the pad never sends a short or long one.

### 7.4 Our timing/liveness machinery driven by the pad's stream

* `research/libdrc/src/input-receiver.cpp:64-74` — the pad's cadence **is** our clock:
  `server_->SetTimeout(1000000L / 60)` with the comment "Packets are usually received at 180Hz. If nothing was
  received after 1/60s (3 packets missed), timeout", and the timeout handler zeroes the input state
  (`:215-217`).
* `run/_wait-for-pad.sh:13-15,27-40` and `run/drc-up.sh:217-237` gate the *start of media* on the pad's own
  uplink rate: `rx_packets` delta ≥ 40/s on the AP interface ⇒ "pad is up and sending input". This is the
  inverse dependency the task asks about: **the pad's send path is what we treat as evidence of readiness**,
  and (per `drc-up.sh:210-216`) starting media before that first frame discards the only `init`-flagged frame.
* `research/libdrc/src/streamer.cpp:88-94` — the 4-byte `01 00 00 00` message on `50010` is the *only* thing
  the msg service does on our side:
  ```c
  if (msg.size() == 4 && !memcmp(msg.data(), "\1\0\0\0", 4)) { vid_streamer_->ResyncStream(); }
  ```
  Barista identical (`research/barista-ref/core/drh/runtime_transport.cpp:823-834`), documented as the pad's
  keyframe request from source port **50110** to **50010** (`research/CODEC-SPEC.md:310-313`), rate 3 in 300 s
  in a healthy session (`research/GROUND-TRUTH-SESSION.md:61-63`; `[MEASURED]` `port50010.bin` = exactly 3 ×
  `01000000`), answered by one IDR (`GROUND-TRUTH-SESSION.md:62`). The pad tolerates ~14 s of un-decodable
  video before asking (`GROUND-TRUTH-SESSION.md:65-66`) — `[UNVERIFIED]` whether that is a firmware counter.
* 50025/50125 as *input* to the pad: see §4. It is the only console→pad stream whose content we still cannot
  explain, and it starts exactly when the console believes the pad's AV side is alive
  (`GROUND-TRUTH-SESSION.md:186-189`).

---

## 8. Consolidated memory-corruption surface table

| parser | buffer / bound | whose code | missing check | citation |
|---|---|---|---|---|
| cmd outer `CmdPacket` | 1408 fixed (`8+1400`) | ours (and, by shape, the pad's) | `memcpy(pkt_.data(), packet.data(), packet.size())` with no comparison against 1408; receive buffer is 2000 | `cmd-packet.cpp:37-39`, `cmd-packet.h:73`, `udp.cpp:154-158` |
| cmd `GenericCmdPacket` | 1400 fixed (`12+1388`) | ours | same memcpy pattern | `cmd-packet.cpp:98-100`, `cmd-packet.h:116` |
| cmd declared `payload_size` | u16, up to 65535 | ours | used verbatim as a read length into a `std::vector` | `cmd-protocol.cpp:162`, `cmd-packet.cpp:64-66` |
| cmd reply consumers | – | ours | `uvcuac-synchronizer.cpp:55-70` reads `d[0..14]` unguarded (only `streamer.cpp:205` guards its blob) | as cited |
| cmd retransmit | `std::map<u16, CmdState>` | ours | `assert(state != NULL)` then deref; `u16` seq wraps; `GetSize()`/`SetPayload` bounds are asserts only | `cmd-protocol.cpp:193-208`, `cmd-packet.cpp:86,193` |
| cmd fragmentation (pad side) | ≥ 4 × 1028 = 4112 B for the UIC class; field width allows fid ≤ 0x7FF, len ≤ 0xFFFF | pad | unknown; declared length is per-fragment and was always consistent in the capture | §1.5, `[UNVERIFIED]` on mismatch behaviour |
| vstrm header | 16 B header + payload; object = `16 + 1400` | ours | `SetExtOption` assert `i + required_space <= 8` disappears under `NDEBUG` → writes `pkt_[16]` (first payload byte) | `vstrm-packet.cpp:150-166`, `vstrm-packet.h:86` |
| vstrm payload | 11-bit length field (`≤ 2047`), documented receiver limit **< 1700** | pad | length vs datagram is checked on the wire by the console (0/73,500 mismatches) but the *receiver* bound is only empirical | `sc-vstrm.rst:32`, `wozt-libdrc/…/vstrm-packet.h:38-42` |
| vstrm ext options | 8-byte area, linear walk to `0x00` | pad | order-sensitive: wrong order ⇒ decoder never starts | `pc2drc/.../vstrm-packet.cpp:52-90` |
| astrm header | 8 B + payload; object = `8 + 1700` | ours | `SetPayload` assert-only bound | `astrm-packet.cpp:93-99`, `astrm-packet.h:80` |
| astrm format message | 32 B total, **declared body length 0x0000** | pad | the one place the length field lies; parser must ignore it | `barista-ref/docs/drc-media-packet-datasheet.md:170`, `[MEASURED]` |
| input (hiddat) | exactly 128 B both sides | ours | both stacks hard-reject `!= 128` before touching offsets | `input-receiver.cpp:143`, `runtime_transport.cpp:818` |
| cfg blob (`LoadFromBlob`) | exactly 0x300, three page CRCs | ours | length checked, then ~40 offset reads all inside | `device-config.cpp:99-113` |
| UIC EEPROM write (svc 5/0x0c) | 258 B, `u8 index, u8 length, u8 data_and_crc[]` | **pad** | index/length pair from the peer — prime EEPROM-write candidate | `sc-cmd.rst:237` |
| product update (svc 0/0x03) | "Max. 1028", `u32 block_idx; u8 data[]` | **pad** | block index from the peer into an update buffer | `sc-cmd.rst:121` |
| IRCOM (svc 5/0x11) | Max 520 in / 520 out | **pad** | 520-byte fixed pair | `sc-cmd.rst:245-247` |
| NFC/ICTAG (svc 5/0x10) | 531 B in | **pad** | largest single documented console→pad method payload | `sc-cmd.rst:243` |

**Constants worth memorising:** cmd header 8 · generic header 12 · largest real generic payload 1028
(`0x404`) · largest real cmd datagram 1048 · our cmd object 1400/1408 · our UDP read buffer 2000 (barista
4096) · vstrm header 16 · vstrm payload cap 1400 (libdrc/wozt) / 1694 (pc2drc, barista, console) · console
max datagram 1710 · seq 10 bits mod 1024 in `b0[1:0]+b1` · astrm header 8 · PCM payload 1664
(libdrc 1536) · format message 32 (outer length 0) · 50025 table 96 · input 128 · WPS device OUI
`a4:c0:e1:f4` · AKM `a4:c0:e1:02` · cipher `a4:c0:e1:04` · PTK/KDK rotate 3 left.

---

## 9. Corrections to existing repo docs (found by measurement)

1. **VSTRM sequence packing.** `research/GROUND-TRUTH-SESSION.md:81` ("`b0 = 0xF0 | seq[9:6]`,
   `b1 = seq[5:0]`") and `:163` ("Header layout … differs, tolerated by pad") and
   `research/BOOT-AND-MODES.md`'s echo of the same are **wrong**. Measured: byte 0 ∈ {f0,f1,f2,f3} only, and
   `((b0&3)<<8)|b1` is contiguous for 73,490/73,499 transitions vs 72,558 for the 4+6 reading. The console
   packs the sequence **exactly as libdrc, Barista and pc2drc do**. §2.6 above has the reproduction.
2. **"778 × 1048-byte UIC state blobs"** (`GROUND-TRUTH-SESSION.md:55`, `:108`) — they are 778 *fragments*
   = 194 complete 4-fragment messages (+2 stray), each fragment declaring 1028 bytes, `transaction_id`
   incrementing per message, `fragment_id` 0…3, `final_fragment` only on 3, `flags` 0x42 → 0x40. §1.5.
3. **"`payload_size` 0x0404"** — correct as a *per-fragment* length, not a message length
   (`research/BOOT-AND-MODES.md:244` reads it as one message's size).
4. **`GROUND-TRUTH-SESSION.md:115-116`** counts the UIC reply as "5 × 792 B" by *datagram* size; the declared
   payload class is `payload_size = 784` (inner 772), 5 occurrences — consistent, just measured differently.
5. **`research/GROUND-TRUTH-SESSION.md:118`** says the 50025 table is "~0.96/s" — `[MEASURED]` 220 datagrams,
   all 96 B, consistent.

## 10. Explicit UNVERIFIED list

* Pad-side reassembly bounds for `cmd` fragments: max fragments, max total, and behaviour when the declared
  per-fragment `payload_size` disagrees with the bytes delivered (no capture contains a mismatch).
* What the pad's dispatch does for an unknown service, unknown method, or `magic != 0x7E` / `version != 0x01`
  (libdrc never checks magic on receive either — `cmd-packet.cpp:105-117` only writes it).
* Whether the pad's vstrm parser validates `len == udp_len − 16`, the 5-chunk/frame-end structure, or the
  ext-option ordering beyond "it stops decoding".
* The buffer that `0x83` ("forces decoding even if buffer is too small", `sc-vstrm.rst:63-64`) bypasses, its
  size, and whether `0x85`/NumMbRowsInChunk can move the pointer past it.
* What the 96-byte 50025/50125 table means and whether the pad validates any of its bytes
  (`GROUND-TRUTH-SESSION.md:214`).
* The pad's DHCP client option handling (owner: BCM4319 firmware / LVC `nwk`).
* Byte-level layout of the real EAPOL key frames (only counts and verified-PTK results are in the repo:
  `barista-ref/docs/drc-media-packet-datasheet.md:270-275`).
* The exact parse boundary inside the BCM4319 firmware (beacon/RSN/WPS/EAPOL) versus the ARM9 — we only have
  the SoC split (`overview.rst:43-54`), not a function-level map.
* Whether ADDBA is initiated by the pad or by our AP, and with what parameters: we have no ADDBA code, only the
  on-air counts.
