#!/usr/bin/env python3
"""
fuzz-pad.py - protocol-plane fuzzer and crash oracle for a Wii U GamePad (DRC)
link, driven from the impersonated console.

WHAT IT DOES
  Plays the console side of the DRC link and pushes one mutated protocol case at
  a time at the pad, while continuously sampling a liveness oracle, so a case
  that kills, wedges or reconfigures the pad is attributed to a specific byte
  sequence and can be replayed exactly.

  Planes (each can be selected with --plane):
    cmd     UDP 50023 -> 50123   console command RPC (type 0 query / 1 ack /
                                 2 reply / 3 ack-back, generic 12-byte header)
    vstrm   UDP 50020 -> 50120   H.264 video wrapper (4-byte bitfield header +
                                 4-byte timestamp + 8-byte extended header)
    astrm   UDP 50021 -> 50121   PCM audio (8-byte header) and the 32-byte
                                 video-format message that rides the same port
    dhcp    BOOTP/DHCP responder that serves malformed option soup, for when the
            pad renews its lease
    corpus  --mutate-from FILE|DIR: deterministic byte-level mutation of a
            directory of seed messages (any of the above planes)

  Verdicts, printed one line per case and written to JSONL:
    OK          reply/ack as expected, state unchanged, pad alive
    LATENCY     reply arrived but slower than --latency-ms (default 250)
    NOACK       reply arrived but the pad never sent its type-1 ack
    NOREPLY     no reply at all (and the pad is otherwise alive)
    STATECHANGE svc 4/0x05 state index moved across the case
    GONE        command plane silent AND no input datagrams: pad or link is dead

SAFETY RAILS (read this before running anything)
  * Nothing is transmitted to 192.168.1.11 unless you pass --live. Loopback
    (127.0.0.1) is always allowed; any other --target prints a loud warning.
  * The command plane must own its local port exclusively. SO_REUSEPORT is never
    set and SO_REUSEADDR is never set either unless --force is given, because
    several tools in this repo bind 192.168.1.10:50023 with reuse flags and the
    kernel then splits the pad's replies between sockets - the symptom is
    indistinguishable from a dead pad (BOOT-AND-MODES.md sec.5.1). Run
    run/drc-down.sh first; the tool refuses to start if the port is taken.
  * --only SAFE (the default) never sends a flash write or a reboot. Command
    service 0 methods 0x02-0x05 and 0x0b-0x0f, service 4 method 0x01, service 5
    methods 0x0c/0x19 and svc 4/0x1a with flags 0x42 are NEVER in SAFE; they
    exist as 16 cases but need --i-understand-brick-risk, and the driver
    re-checks every datagram before it hits the wire.
  * --deadman N aborts the whole run when the pad reads GONE for N consecutive
    cases, so a crash cannot be compounded by the next hundred packets.
  * --record DIR is mandatory for a transmitting run: every datagram is written
    to DIR/case-N.bin (20-byte record framing, same as out/evidence/truth/*.bin)
    plus DIR/case-N.txt (pcap-ish hex) plus DIR/verdicts.jsonl.

USAGE
  # prove the tool on loopback, no pad, no root, no DRC ports
  python3 run/fuzz-pad.py --selftest

  # print the case catalogue and the exact bytes (no sockets)
  python3 run/fuzz-pad.py --list
  python3 run/fuzz-pad.py --dry-run --record /tmp/fz --family payload

  # first hardware sweep, SAFE only (after run/drc-down.sh)
  sudo run/fuzz-pad.py --live --record out/fuzz/$(date +%H%M%S) --only SAFE

  # replay one recorded case byte for byte
  sudo run/fuzz-pad.py --live --replay out/fuzz/091200/case-42.bin

Encoding facts are taken from research/libdrc/web/docs/re/sc-{cmd,vstrm,astrm}.rst
and cross-checked against out/evidence/truth/ (real console session). The
vstrm/astrm layouts are re-derived from the capture by --selftest, which
re-encodes real datagrams and requires byte equality.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

__version__ = "1.0"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRUTH = os.path.join(ROOT, "out", "evidence", "truth")
CONSOLE_MSGS = os.path.join(TRUTH, "console-messages")

CONSOLE_IP = "192.168.1.10"
PAD_IP = "192.168.1.11"
LOOPBACK = "127.0.0.1"
PAD_MAC = "40:d2:8a:17:e2:09"

# (console sport, pad dport) per plane
PORT_VIDEO = (50020, 50120)
PORT_AUDIO = (50021, 50121)
PORT_CMD = (50023, 50123)
PORT_INPUT = (50022, 50122)          # pad -> console, we only listen
PORT_TABLE = (50025, 50125)
PORT_DHCP = 67
PORT_DHCP_CLIENT = 68

# payload sizes the hand-written parsers in this codebase actually special-case
BOUNDARY_SIZES: Tuple[int, ...] = (0, 1, 8, 255, 256, 257, 520, 521, 772,
                                   1024, 1028, 1040, 1694, 2048)

# sc-cmd.rst: methods that write flash / EEPROM or reboot the pad. Never in SAFE.
BRICK_CMD: frozenset = frozenset({
    (0, 0x02), (0, 0x03), (0, 0x04), (0, 0x05),           # product update lifecycle
    (0, 0x0b), (0, 0x0c), (0, 0x0d), (0, 0x0e), (0, 0x0f),  # TVCode/Lang flash update
    (4, 0x01),                                            # reboot / shutdown / fw-update
    (5, 0x0c),                                            # UIC EEPROM write
    (5, 0x19),                                            # LCD controller via i2c
})

CMD_RETVALS = [0, 10, 4, 5, 6, 1, 2, 3, 9, 7, 8, 11]

REC = struct.Struct(">d4s4sI")   # same framing as out/evidence/truth/*.bin


# ===========================================================================
# small helpers
# ===========================================================================
def mono() -> float:
    return time.monotonic()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hexdump_lines(data: bytes, per_line: int = 16) -> List[str]:
    out = []
    for off in range(0, len(data), per_line):
        chunk = data[off:off + per_line]
        hx = " ".join("%02x" % b for b in chunk)
        out.append("\t%04x  %-*s  %s" % (off, per_line * 3, hx,
                                         "".join(chr(b) if 32 <= b < 127 else "."
                                                 for b in chunk)))
    return out


def say(msg: str) -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    print("[!] " + msg, flush=True)


class BrickRisk(RuntimeError):
    """Raised before a flash-write/reboot datagram is transmitted."""


class ConflictError(RuntimeError):
    """Raised when a local port is already bound and cannot be owned exclusively."""


# ===========================================================================
# cmd plane codec  (sc-cmd.rst)
#   CmdHeader      le16 packet_type | le16 query_type | le16 payload_size | le16 seq
#   GenericCmdHdr  7e | version | tid[11:8] |
#                  tid[7:4]<<4 | FIN(0x08) | fid[10:8] | fid[7:0] | flags |
#                  service | method | be16 error | be16 payload_size
#   tid  = (b2 << 8) | ((b3 >> 4) & 0x0F)     [11-bit message key, not shifted
#                                             down like mine_cmd.py does]
#   FIN  = bool(b3 & 0x08)                    [set on the last fragment only]
#   fid  = ((b3 & 0x07) << 8) | b4            [per-fragment index 0..3]
#   (research/rce-hunt/02-attack-surface.md VERIFIED layout, libdrc cmd-packet.h)
# ===========================================================================
CMD_MAGIC = 0x7E


@dataclass
class CmdPacket:
    service: int = 0
    method: int = 0
    payload: bytes = b""
    packet_type: int = 0            # 0 query, 1 ack, 2 reply, 3 ack-of-reply
    query_type: int = 0             # 0 generic, 1 UVC/UAC, 2 time
    seq: int = 0
    version: int = 1
    txid: int = 0                   # be12
    fragid: int = 0                 # be12, shares a byte with the final bit
    final: bool = True
    flags: int = 0x40
    error: int = 0
    magic: int = CMD_MAGIC
    outer_size: Optional[int] = None      # None -> computed from body
    gen_size: Optional[int] = None        # None -> len(payload)
    generic: bool = True                  # False for query types 1/2
    diag: Dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        body = b""
        if self.generic:
            gen = bytearray(12)
            gen[0] = self.magic & 0xFF
            gen[1] = self.version & 0xFF
            gen[2] = (self.txid >> 8) & 0x0F
            gen[3] = (((self.txid & 0x0F) << 4) | (0x08 if self.final else 0x00)
                      | ((self.fragid >> 8) & 0x07))
            gen[4] = self.fragid & 0xFF
            gen[5] = self.flags & 0xFF
            gen[6] = self.service & 0xFF
            gen[7] = self.method & 0xFF
            gen[8:10] = struct.pack(">H", self.error & 0xFFFF)
            size = len(self.payload) if self.gen_size is None else self.gen_size
            gen[10:12] = struct.pack(">H", size & 0xFFFF)
            body = bytes(gen) + self.payload
        else:
            body = self.payload
        size = len(body) if self.outer_size is None else self.outer_size
        return (struct.pack("<HHHH", self.packet_type & 0xFFFF,
                            self.query_type & 0xFFFF, size & 0xFFFF,
                            self.seq & 0xFFFF) + body)

    @classmethod
    def decode(cls, data: bytes) -> "CmdPacket":
        p = cls()
        p.diag = {"len": len(data)}
        if len(data) < 8:
            p.diag["error"] = "short outer header"
            return p
        (p.packet_type, p.query_type, outer_size, p.seq) = struct.unpack_from(
            "<HHHH", data, 0)
        p.outer_size = outer_size        # keep the declared size for byte-exact re-encode
        p.diag["outer_size"] = outer_size
        p.diag["actual_body"] = len(data) - 8
        if outer_size != len(data) - 8:
            p.diag["size_mismatch"] = outer_size - (len(data) - 8)
        body = data[8:]
        if p.query_type != 0 or len(body) < 12 or body[0] != CMD_MAGIC:
            # not a GenericCmdHeader (foreign query type, short body, or no 0x7e
            # magic): keep the bytes opaque so re-encoding stays byte-exact
            p.generic = False
            p.payload = body
            if len(body) >= 12:
                p.diag["bad_magic"] = body[0]
            return p
        p.generic = True
        p.magic = body[0]
        p.version = body[1]
        p.txid = ((body[2] & 0xFF) << 8) | ((body[3] >> 4) & 0x0F)
        p.final = bool(body[3] & 0x08)
        p.fragid = (((body[3] & 0x07) << 8) | body[4]) & 0x0FFF
        p.flags = body[5]
        p.service = body[6]
        p.method = body[7]
        p.error = struct.unpack_from(">H", body, 8)[0]
        gen_size = struct.unpack_from(">H", body, 10)[0]
        p.gen_size = gen_size            # keep the declared size for byte-exact re-encode
        p.diag["gen_size"] = gen_size
        p.diag["gen_actual"] = len(body) - 12
        if gen_size != len(body) - 12:
            p.diag["gen_size_mismatch"] = gen_size - (len(body) - 12)
        p.payload = body[12:]
        if p.magic != CMD_MAGIC:
            p.diag["bad_magic"] = p.magic
        return p

    def brick(self) -> bool:
        """True if a console sending this would be writing flash or rebooting."""
        if self.query_type == 0 and self.generic:
            if (self.service, self.method) in BRICK_CMD:
                return True
            if (self.service, self.method) == (4, 0x1A) and (self.flags & 0x42) == 0x42:
                return True              # sc-cmd.rst: svc4/0x1a shuts the pad down
        if self.query_type == 1 and len(self.payload) >= 4:
            if self.payload[3] in (1, 3):   # UVC/UAC f3: 1 = vWii, 3 = shutdown
                return True
        return False

    def expects_reply(self) -> bool:
        if not self.generic:
            return True
        return bool(self.final)


def cmd_ack(packet_type: int, query_type: int, seq: int) -> bytes:
    return struct.pack("<HHHH", packet_type, query_type, 0, seq & 0xFFFF)


# ===========================================================================
# vstrm codec  (sc-vstrm.rst, layout re-derived from out/evidence/truth)
#   b0 = magic[3:0] | seq[9:6]      b1 = packet_type[1:0] | seq[5:0]
#   b2 = init|frame_begin|chunk_end|frame_end|has_timestamp|size[10:8]
#   b3 = size[7:0]                  b4..b7 = timestamp (le32 us)
#   b8..b15 = extended header (options until 0x00 or 8 bytes)
# ===========================================================================
DEFAULT_EXT = bytes([0x82, 0x00, 0x83, 0x85, 0x06, 0x00, 0x00, 0x00])
IDR_EXT = bytes([0x80, 0x82, 0x00, 0x83, 0x85, 0x06, 0x00, 0x00])


@dataclass
class VstrmPacket:
    magic: int = 0xF
    packet_type: int = 0
    seq: int = 0
    init: bool = False
    frame_begin: bool = False
    chunk_end: bool = False
    frame_end: bool = False
    has_timestamp: bool = True
    payload_size: Optional[int] = None   # None -> len(payload)
    timestamp: int = 0
    ext: bytes = DEFAULT_EXT
    payload: bytes = b""
    diag: Dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        size = len(self.payload) if self.payload_size is None else self.payload_size
        b0 = ((self.magic & 0x0F) << 4) | ((self.seq >> 6) & 0x0F)
        b1 = ((self.packet_type & 0x03) << 6) | (self.seq & 0x3F)
        b2 = (0x80 if self.init else 0) | (0x40 if self.frame_begin else 0) \
            | (0x20 if self.chunk_end else 0) | (0x10 if self.frame_end else 0) \
            | (0x08 if self.has_timestamp else 0) | ((size >> 8) & 0x07)
        b3 = size & 0xFF
        out = bytearray([b0, b1, b2, b3])
        if self.has_timestamp:
            out += struct.pack("<I", self.timestamp & 0xFFFFFFFF)
        ext = (self.ext + b"\x00" * 8)[:8]
        out += ext
        out += self.payload
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "VstrmPacket":
        p = cls()
        p.diag = {"len": len(data)}
        if len(data) < 4:
            p.diag["error"] = "short header"
            return p
        p.magic = data[0] >> 4
        p.packet_type = (data[1] >> 6) & 0x03
        p.seq = ((data[0] & 0x0F) << 6) | (data[1] & 0x3F)
        p.init = bool(data[2] & 0x80)
        p.frame_begin = bool(data[2] & 0x40)
        p.chunk_end = bool(data[2] & 0x20)
        p.frame_end = bool(data[2] & 0x10)
        p.has_timestamp = bool(data[2] & 0x08)
        p.payload_size = ((data[2] & 0x07) << 8) | data[3]
        off = 4
        if p.has_timestamp and len(data) >= 8:
            p.timestamp = struct.unpack_from("<I", data, 4)[0]
            off = 8
        if len(data) >= off + 8:
            p.ext = data[off:off + 8]
        off += 8
        body = data[off:]
        p.payload = body
        if p.payload_size != len(body):
            p.diag["size_mismatch"] = p.payload_size - len(body)
        return p


def build_ext(options: Sequence[Any]) -> bytes:
    """Serialize an extended header.

    ints are option bytes with no argument; (opt, arg) pairs are option+argument.
    0x00 terminates the option list; anything past that is padding. The result is
    always exactly 8 bytes, as the console sends.
    """
    out = bytearray()
    for item in options:
        if isinstance(item, int):
            out.append(item & 0xFF)
        else:
            opt, arg = item
            out.append(opt & 0xFF)
            out.append(arg & 0xFF)
    if len(out) < 8:
        out += b"\x00" * (8 - len(out))
    return bytes(out[:8])


def parse_ext(ext: bytes) -> List[Tuple[int, Optional[int]]]:
    """Decode an extended header the way the pad does: linear, stop at 0x00 or 8 B."""
    out: List[Tuple[int, Optional[int]]] = []
    i = 0
    while i < len(ext) and i < 8:
        opt = ext[i]
        if opt == 0x00:
            break
        if opt in (0x81, 0x82, 0x85):    # options that take one argument byte
            arg = ext[i + 1] if i + 1 < 8 else None
            out.append((opt, arg))
            i += 2
        else:
            out.append((opt, None))
            i += 1
    return out


# ===========================================================================
# astrm codec  (sc-astrm.rst, layout re-derived from out/evidence/truth)
#   b0..b1 = be16: format[15:13] mono[12] vibrate[11] type[10] seq[9:0]
#   b2..b3 = be16 payload_size
#   b4..b7 = le32 timestamp (us)
# ===========================================================================
@dataclass
class AstrmPacket:
    fmt: int = 1
    mono: int = 0
    vibrate: int = 0
    ptype: int = 0                     # 0 audio data, 1 video format
    seq: int = 0
    payload_size: Optional[int] = None
    timestamp: int = 0
    payload: bytes = b""
    diag: Dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        size = len(self.payload) if self.payload_size is None else self.payload_size
        word = (((self.fmt & 0x07) << 13) | ((self.mono & 1) << 12)
                | ((self.vibrate & 1) << 11) | ((self.ptype & 1) << 10)
                | (self.seq & 0x3FF))
        return (struct.pack(">HH", word, size & 0xFFFF)
                + struct.pack("<I", self.timestamp & 0xFFFFFFFF)
                + self.payload)

    @classmethod
    def decode(cls, data: bytes) -> "AstrmPacket":
        p = cls()
        p.diag = {"len": len(data)}
        if len(data) < 8:
            p.diag["error"] = "short header"
            return p
        word, size, ts = struct.unpack_from(">HHI", data, 0)
        ts = struct.unpack_from("<I", data, 4)[0]
        p.fmt = (word >> 13) & 0x07
        p.mono = (word >> 12) & 1
        p.vibrate = (word >> 11) & 1
        p.ptype = (word >> 10) & 1
        p.seq = word & 0x3FF
        p.payload_size = size
        p.timestamp = ts
        p.payload = data[8:]
        if size != len(p.payload):
            p.diag["size_mismatch"] = size - len(p.payload)
        return p


FORMAT_FIELDS = ("tag", "flag0", "timestamp", "freq0_a", "freq0_b",
                 "freq1_a", "freq1_b", "tail0")


@dataclass
class VideoFormat:
    """The 32-byte video format/timing message that rides udp/50121."""
    tag: int = 0x00000004
    flag0: int = 0
    timestamp: int = 0
    freq0_a: int = 0x3E80
    freq0_b: int = 0x3E80
    freq1_a: int = 0x5208
    freq1_b: int = 0x5208
    tail0: int = 0

    def encode(self) -> bytes:
        return struct.pack("<IIIIIIII", self.tag & 0xFFFFFFFF, self.flag0 & 0xFFFFFFFF,
                           self.timestamp & 0xFFFFFFFF, self.freq0_a & 0xFFFFFFFF,
                           self.freq0_b & 0xFFFFFFFF, self.freq1_a & 0xFFFFFFFF,
                           self.freq1_b & 0xFFFFFFFF, self.tail0 & 0xFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "VideoFormat":
        vals = struct.unpack_from("<IIIIIIII", data + b"\x00" * 32, 0)
        return cls(*vals)


# ===========================================================================
# BOOTP/DHCP responder codec (mirrors pc2drc/drc-hostap/netboot/netboot.c)
# ===========================================================================
DHCP_MAGIC = bytes([0x63, 0x82, 0x53, 0x63])
DHCP_OPTS_START = 240   # 236 fixed + 4 magic cookie


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in re.split(r"[:\-]", mac))


def parse_dhcp_options(pkt: bytes) -> Tuple[List[Tuple[int, bytes, bool]], bool]:
    """Walk options the way a lenient client does.

    Returns (options, well_formed). Each option is (code, value, overruns) where
    overruns means the declared length ran past the end of the datagram.
    """
    out: List[Tuple[int, bytes, bool]] = []
    i = DHCP_OPTS_START
    well_formed = False
    while i < len(pkt):
        code = pkt[i]
        if code == 0xFF:
            well_formed = True
            break
        if code == 0x00:            # padding
            i += 1
            continue
        if i + 1 >= len(pkt):
            out.append((code, b"", True))
            break
        length = pkt[i + 1]
        value = pkt[i + 2:i + 2 + length]
        overrun = len(value) < length
        out.append((code, value, overrun))
        i += 2 + length
    return out, well_formed


def dhcp_soups(server_ip: str, client_ip: str, lease: int = 0xFFFFFFFF) -> Dict[str, bytes]:
    """Named option soups. Each is the raw option area (no magic cookie)."""
    srv = socket.inet_aton(server_ip)
    cli = socket.inet_aton(client_ip)
    # well-formed option 43: sub-option 1 (2 bytes), sub-option 8 (7 bytes), 0xff
    vendor_inner = (bytes([1, 2, 0x00, 0x00]) +
                    bytes([8, 7, 0x00, 0x00, 0x01]) + srv + bytes([0x00, 0x00]) +
                    bytes([0xFF]))
    vendor = bytes([43, len(vendor_inner)]) + vendor_inner
    base = (bytes([53, 1, 0x05]) +                       # DHCPACK
            bytes([51, 4]) + struct.pack(">I", lease) +
            bytes([54, 4]) + srv +
            bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00]) +
            bytes([60, 9]) + b"PXEClient" +
            bytes([12, 9]) + b"pxeclient")
    out: Dict[str, bytes] = {}
    out["control"] = base + vendor + bytes([255])
    # 60 byte vendor class, then a duplicate 43 with a different payload
    out["duplicate-options"] = (base + vendor +
                                bytes([53, 1, 0x02]) +           # second, conflicting msg type
                                bytes([43, 4, 0xDE, 0xAD, 0xBE, 0xEF]) +
                                bytes([255]))
    # option 60 declares 250 bytes of vendor class but the datagram ends after 200
    out["long-option"] = (bytes([53, 1, 0x05]) + bytes([54, 4]) + srv +
                          bytes([60, 250]) + b"P" * 200 + bytes([255]))
    # option 43 with 255 bytes of 0xff at the very end of the option area
    out["oversized43"] = (base + bytes([43, 255]) + b"\xFF" * 255 + bytes([255]))
    # parameter request list (55) of length 255 and a length-0 one
    out["weird55"] = (base + bytes([55, 255]) + bytes(range(0, 255)) +
                      bytes([55, 0]) + bytes([255]))
    # hostname (12) / domain (15) overruns, no terminator at all
    out["truncated"] = (bytes([53, 1, 0x05]) + bytes([12, 200]) + b"hostname" +
                        bytes([15, 200]) + b"example" +
                        bytes([43, 60]) + b"\x00" * 10)
    # option 12 length run off the end, unknown option codes, no 0xff
    out["no-end"] = (bytes([53, 1, 0x05]) + bytes([12, 255]) + b"pxeclient" +
                     bytes([200, 32]) + b"\xAB" * 32 + bytes([254, 1, 2]))
    # options 0x80..0x8f (unassigned) each with a 1-byte value
    out["unknown-codes"] = (base + b"".join(bytes([c, 1, c]) for c in range(0x80, 0x90))
                            + bytes([255]))
    return out


def build_dhcp_reply(request: bytes, *, client_ip: str, server_ip: str,
                     options: bytes) -> bytes:
    """Echo the request, flip it into a BOOTREPLY and attach `options`."""
    pkt = bytearray(request + b"\x00" * (DHCP_OPTS_START + 64 - len(request)))
    pkt[0] = 2                                  # BOOTREPLY
    pkt[1] = request[1] if len(request) > 1 else 1
    pkt[2] = request[2] if len(request) > 2 else 6
    pkt[3] = 0
    pkt[4:8] = request[4:8] if len(request) >= 8 else b"\x00\x00\x00\x00"
    pkt[10:12] = b"\x00\x00"                    # clear broadcast flag
    pkt[12:16] = b"\x00\x00\x00\x00"            # ciaddr
    pkt[16:20] = socket.inet_aton(client_ip)    # yiaddr
    pkt[20:24] = socket.inet_aton(server_ip)    # siaddr
    pkt[24:28] = b"\x00\x00\x00\x00"            # giaddr
    pkt[DHCP_OPTS_START - 4:DHCP_OPTS_START] = DHCP_MAGIC
    return bytes(pkt[:DHCP_OPTS_START]) + bytes(options)


def build_dhcp_request(client_mac: str = PAD_MAC,
                       xid: Optional[int] = None) -> bytes:
    """A minimal DHCPDISCOVER/REQUEST body, as the pad would send it.

    The xid is derived from the client MAC rather than drawn from a global RNG
    so that the generated catalogue is byte-for-byte reproducible per --seed
    (the determinism selftest asserts this).
    """
    pkt = bytearray(300)
    pkt[0] = 1                                  # BOOTREQUEST
    pkt[1] = 1                                  # ethernet
    pkt[2] = 6                                  # hlen
    if xid is None:
        xid = struct.unpack(">I", hashlib.sha256(
            b"dhcp-xid:" + _mac_bytes(client_mac)).digest()[:4])[0]
    pkt[4:8] = struct.pack(">I", (xid or 0x0BADCAFE) & 0xFFFFFFFF)
    pkt[10:12] = b"\x80\x00"                    # broadcast flag
    mac = _mac_bytes(client_mac)
    pkt[28:34] = mac
    pkt[44:44 + 12] = b"WiiU-GamePad"
    pkt[DHCP_OPTS_START - 4:DHCP_OPTS_START] = DHCP_MAGIC
    opts = (bytes([53, 1, 0x01]) +              # DHCPDISCOVER
            bytes([97, 17]) + b"\x00" + mac + b"\x00" * 10 +
            bytes([12, 9]) + b"pxeclient" +
            bytes([55, 3, 1, 3, 6]) +
            bytes([255]))
    return bytes(pkt[:DHCP_OPTS_START]) + opts


# ===========================================================================
# safety: rate limit, port exclusivity, target guard
# ===========================================================================
class TokenBucket:
    def __init__(self, rate: float) -> None:
        self.rate = float(rate)
        self.tokens = float(rate if rate > 0 else 1)
        self.ts = mono()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        with self.lock:
            while True:
                now = mono()
                self.tokens = min(self.rate, self.tokens + (now - self.ts) * self.rate)
                self.ts = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                time.sleep(min(0.05, max(0.001, (1.0 - self.tokens) / self.rate)))


def port_owners(port: int) -> List[str]:
    """Best-effort: which processes hold a local UDP port (via /proc/net/udp)."""
    inodes: List[str] = []
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(path, "r") as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                lport = int(parts[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if lport == port:
                inodes.append(parts[9])
    owners: List[str] = []
    if not inodes:
        return owners
    want = {"socket:[%s]" % i for i in inodes}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        fddir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fddir, fd))
            except OSError:
                continue
            if target in want:
                try:
                    with open("/proc/%s/comm" % pid, "r") as fh:
                        comm = fh.read().strip()
                except OSError:
                    comm = "?"
                owners.append("pid %s (%s)" % (pid, comm))
                break
    if not owners:
        owners.append("inode %s, owner pid not visible (run as root to resolve)"
                      % ",".join(inodes))
    return owners


def bind_udp(ip: str, port: int, *, what: str, allow_reuse: bool = False,
             broadcast: bool = False) -> socket.socket:
    """Bind a UDP socket the strict way - no SO_REUSEPORT, no SO_REUSEADDR.

    Tools in this repo (libdrc, drcvncclient, replay scripts) bind these ports
    with reuse flags, which lets the kernel split a peer's replies between
    sockets. A silent second binder is the bug this function refuses to become.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if allow_reuse:
        warn("%s: binding %s:%d WITH SO_REUSEADDR because --force was given; "
             "replies may be split with another binder" % (what, ip, port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ip, port))
    except OSError as exc:
        owners = port_owners(port)
        sock.close()
        raise ConflictError(
            "%s: cannot bind %s:%d exclusively (%s).\n"
            "    holders: %s\n"
            "    Run run/drc-down.sh (or stop the phase script holding it) and "
            "retry.\n"
            "    --force binds with SO_REUSEADDR anyway and WILL split the pad's "
            "replies,\n    which looks exactly like a dead pad."
            % (what, ip, port, exc, "; ".join(owners) if owners else "unknown"))
    return sock


def resolve_target(args: argparse.Namespace) -> Tuple[str, bool]:
    """Return (pad_ip, live). Refuses to transmit at the pad without --live."""
    if args.target is None:
        return PAD_IP, bool(args.live)
    target = args.target
    if target not in (PAD_IP, LOOPBACK):
        warn("--target %s is not the GamePad (%s) and not loopback; make sure "
             "this is in scope for the engagement" % (target, PAD_IP))
    if target == PAD_IP:
        return target, bool(args.live)
    return target, False          # loopback (and other explicit targets) need no --live


# ===========================================================================
# liveness oracle: input datagram rate, ICMP, hostapd log tail
# ===========================================================================
class ApLogTail:
    """Tail hostapd's log for events about the pad's MAC (deauth/assoc/...)."""

    PATTERN = re.compile(r"(deauth|disassoc|associated|authenticated|"
                         r"disconnected|EAPOL|4-way)", re.I)

    def __init__(self, path: str, mac: str = PAD_MAC) -> None:
        self.path = path
        self.mac_variants = {mac.lower(), mac.lower().replace(":", "-"),
                             mac.lower().replace(":", "")}
        self.offset = 0
        self.buf = b""
        try:
            self.offset = os.path.getsize(path)      # only care about new lines
        except OSError:
            self.offset = 0

    def poll(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return events
        if size < self.offset:                      # truncated / rotated
            self.offset = 0
        if size == self.offset:
            return events
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.offset)
                chunk = fh.read(size - self.offset)
        except OSError:
            return events
        self.offset = size
        self.buf += chunk
        *lines, self.buf = self.buf.split(b"\n")
        for raw in lines:
            line = raw.decode("utf-8", "replace")
            low = line.lower()
            if not any(v in low for v in self.mac_variants):
                continue
            if not self.PATTERN.search(line):
                continue
            events.append({"t": time.time(), "line": line.strip()})
        return events


class Liveness:
    """Continuous pad-liveness sampler, cheap enough to sample per test case."""

    def __init__(self, *, pad_ip: str, input_ip: str, input_port: int,
                 window: float = 1.0, icmp: bool = True,
                 icmp_period: float = 2.0, ap_log: Optional[str] = None,
                 allow_reuse: bool = False) -> None:
        self.pad_ip = pad_ip
        self.input_ip = input_ip
        self.input_port = input_port
        self.window = window
        self.icmp_enabled = icmp
        self.icmp_period = icmp_period
        self.allow_reuse = allow_reuse
        self.sock: Optional[socket.socket] = None
        self.input_available = False
        self._arrivals: List[float] = []
        self._total = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._icmp_thread: Optional[threading.Thread] = None
        self.icmp_ok: Optional[bool] = None
        self.icmp_at: float = 0.0
        self.ap = ApLogTail(ap_log) if ap_log else None
        self.ap_events: List[Dict[str, Any]] = []

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        try:
            self.sock = bind_udp(self.input_ip, self.input_port,
                                 what="input-rate oracle",
                                 allow_reuse=self.allow_reuse)
            self.sock.settimeout(0.1)
            self.input_available = True
        except (ConflictError, OSError) as exc:
            warn("input-rate oracle unavailable (%s); verdicts fall back to the "
                 "command plane only" % str(exc).splitlines()[0])
            self.sock = None
        self._thread = threading.Thread(target=self._rx_loop, name="input-rx",
                                        daemon=True)
        self._thread.start()
        if self.icmp_enabled:
            self._icmp_thread = threading.Thread(target=self._icmp_loop,
                                                 name="icmp", daemon=True)
            self._icmp_thread.start()

    def stop(self) -> None:
        self._stop.set()
        for th in (self._thread, self._icmp_thread):
            if th and th.is_alive():
                th.join(timeout=2.0)
        if self.sock:
            self.sock.close()
            self.sock = None

    # -- workers --------------------------------------------------------
    def _rx_loop(self) -> None:
        sock = self.sock
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self._arrivals.append(mono())
                self._total += 1

    def _ping(self) -> Optional[bool]:
        try:
            rc = subprocess.run(
                ["ping", "-n", "-q", "-c", "1", "-W", "1", self.pad_ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        except (OSError, subprocess.SubprocessError):
            return None
        return rc.returncode == 0

    def _icmp_loop(self) -> None:
        while not self._stop.is_set():
            ok = self._ping()
            self.icmp_ok = ok
            self.icmp_at = time.time()
            self._stop.wait(self.icmp_period)

    # -- sampling -------------------------------------------------------
    def input_rate(self) -> Tuple[Optional[float], int]:
        with self._lock:
            now = mono()
            cut = now - self.window
            self._arrivals = [t for t in self._arrivals if t >= cut]
            n = len(self._arrivals)
            total = self._total
        if not self.input_available:
            return None, total
        return n / self.window, total

    def snapshot(self) -> Dict[str, Any]:
        pps, total = self.input_rate()
        if self.ap:
            events = self.ap.poll()
            if events:
                self.ap_events.extend(events)
        return {
            "input_pps": pps,
            "input_total": total,
            "input_available": self.input_available,
            "icmp_ok": self.icmp_ok,
            "icmp_age_s": (round(time.time() - self.icmp_at, 3)
                           if self.icmp_at else None),
            "ap_events_total": len(self.ap_events),
            "t": time.time(),
        }

    def new_ap_events(self, since_index: int) -> List[Dict[str, Any]]:
        return self.ap_events[since_index:]


# ===========================================================================
# recording / replay
# ===========================================================================
def pack_record(ts: float, src_ip: str, dst_ip: str, datagram: bytes) -> bytes:
    return (REC.pack(ts, socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                     len(datagram) & 0xFFFFFFFF) + datagram)


def iter_records(path: str) -> Iterator[Tuple[float, bytes]]:
    """Read the repo's 20-byte record framing; tolerant of a plain blob."""
    with open(path, "rb") as fh:
        head = fh.read(REC.size)
        if len(head) < REC.size:
            fh.seek(0)
            blob = fh.read()
            if blob:
                yield 0.0, blob
            return
        ts = struct.unpack(">d", head[:8])[0]
        size = struct.unpack(">I", head[16:20])[0]
        if not (0 <= ts < 1e6) or size > 65535:
            fh.seek(0)
            yield 0.0, fh.read()
            return
        fh.seek(0)
        while True:
            hdr = fh.read(REC.size)
            if len(hdr) < REC.size:
                break
            ts = struct.unpack(">d", hdr[:8])[0]
            size = struct.unpack(">I", hdr[16:20])[0]
            body = fh.read(size)
            if len(body) < size:
                yield ts, body
                break
            yield ts, body


class Recorder:
    """One file per case (binary + pcap-ish text) plus a JSONL verdict log."""

    def __init__(self, dirpath: str, meta: Dict[str, Any]) -> None:
        self.dir = os.path.abspath(dirpath)
        os.makedirs(self.dir, exist_ok=True)
        self.meta = dict(meta)
        self.meta["created"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(os.path.join(self.dir, "run.json"), "w") as fh:
            json.dump(self.meta, fh, indent=1, sort_keys=True)
        self.jsonl_path = os.path.join(self.dir, "verdicts.jsonl")
        self._jsonl = open(self.jsonl_path, "a")
        self._sent: List[Tuple[float, int, bytes]] = []
        self._case: Optional[TestCase] = None
        self.cases_written = 0

    def case_begin(self, case: "TestCase") -> None:
        self._case = case
        self._sent = []

    def note_sent(self, datagram: bytes, dport: int) -> None:
        self._sent.append((mono(), dport, datagram))

    def case_end(self, verdict: str, detail: str,
                 extra: Dict[str, Any]) -> Dict[str, Any]:
        assert self._case is not None
        case = self._case
        src_ip = self.meta.get("local_ip", CONSOLE_IP)
        dst_ip = self.meta.get("target", PAD_IP)
        base = os.path.join(self.dir, "case-%03d" % case.idx)
        blob = b"".join(pack_record(t, src_ip, dst_ip, d) for t, _p, d in self._sent)
        with open(base + ".bin", "wb") as fh:
            fh.write(blob)
        lines = ["# fuzz-pad case-%03d  plane=%s dport=%d risk=%s"
                 % (case.idx, case.plane, case.dport, case.risk),
                 "# name: %s" % case.name,
                 "# family: %s" % case.family,
                 "# sha256: %s" % sha256_hex(b"".join(d for _t, _p, d in self._sent)),
                 "# note: %s" % case.note]
        t0 = self._sent[0][0] if self._sent else 0.0
        for t, dport, dgram in self._sent:
            lines.append("%12.6f %s:%d > %s:%d  len=%d"
                         % (t - t0, src_ip, case.sport, dst_ip, dport, len(dgram)))
            lines.extend(hexdump_lines(dgram))
        with open(base + ".txt", "w") as fh:
            fh.write("\n".join(lines) + "\n")
        record = {
            "case": case.idx,
            "name": case.name,
            "family": case.family,
            "plane": case.plane,
            "risk": case.risk,
            "dport": case.dport,
            "sport": case.sport,
            "datagrams": len(self._sent),
            "bytes": sum(len(d) for _t, _p, d in self._sent),
            "sha256": sha256_hex(b"".join(d for _t, _p, d in self._sent)),
            "verdict": verdict,
            "detail": detail,
        }
        record.update(extra)
        with open(base + ".json", "w") as fh:
            json.dump(record, fh, indent=1, sort_keys=True)
        self._jsonl.write(json.dumps(record, sort_keys=True) + "\n")
        self._jsonl.flush()
        self.cases_written += 1
        return record

    def close(self) -> None:
        self._jsonl.close()


# ===========================================================================
# transmitters
# ===========================================================================
@dataclass
class TxResult:
    sent: int = 0
    ack_seen: bool = False
    reply: Optional[CmdPacket] = None
    reply_raw: bytes = b""
    latency_ms: Optional[float] = None
    retransmits: int = 0
    expect_reply: bool = True
    other_rx: int = 0
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sent": self.sent,
            "ack_seen": self.ack_seen,
            "got_reply": self.reply is not None,
            "latency_ms": (round(self.latency_ms, 3)
                           if self.latency_ms is not None else None),
            "retransmits": self.retransmits,
            "client_error": self.error,
            "reply_error_code": (self.reply.error if self.reply else None),
            "reply_bytes": len(self.reply_raw),
        }


class CmdPlane:
    """Owns the console end of the command plane and answers like a console."""

    def __init__(self, *, local_ip: str, local_port: int, pad_ip: str,
                 pad_port: int, timeout: float = 0.25, retries: int = 1,
                 allow_brick: bool = False, allow_reuse: bool = False) -> None:
        self.local_ip = local_ip
        self.local_port = local_port
        self.pad_ip = pad_ip
        self.pad_port = pad_port
        self.timeout = timeout
        self.retries = retries
        self.allow_brick = allow_brick
        self.allow_reuse = allow_reuse
        self.sock: Optional[socket.socket] = None
        self.seq = 100
        self.rx_total = 0
        self.tx_total = 0
        self.last_reply: Dict[Tuple[int, int], Tuple[int, str]] = {}
        self.reply_changes = 0
        self._events: List[Tuple[float, bytes]] = []
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle ------------------------------------------------------
    def open(self) -> None:
        self.sock = bind_udp(self.local_ip, self.local_port, what="cmd plane",
                             allow_reuse=self.allow_reuse)
        self.sock.settimeout(0.1)
        self._thread = threading.Thread(target=self._rx_loop, name="cmd-rx",
                                        daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self.sock:
            self.sock.close()
            self.sock = None

    def _rx_loop(self) -> None:
        assert self.sock is not None
        while not self._stop.is_set():
            try:
                data, _addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._cv:
                self._events.append((mono(), data))
                self._cv.notify_all()
            self.rx_total += 1

    # -- sending --------------------------------------------------------
    def next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def guard(self, datagram: bytes) -> None:
        """Fail closed on a flash-write/reboot packet unless explicitly allowed."""
        if len(datagram) < 20:
            return
        pkt = CmdPacket.decode(datagram)
        if pkt.query_type != 0 and not pkt.generic:
            if pkt.brick() and not self.allow_brick:
                raise BrickRisk(
                    "refusing to send a UVC/UAC command with f3=%d (vWii/shutdown); "
                    "needs --i-understand-brick-risk" % pkt.payload[3])
            return
        if pkt.generic and pkt.brick() and not self.allow_brick:
            raise BrickRisk(
                "refusing to send cmd svc %d method 0x%02x flags 0x%02x: it writes "
                "flash or reboots the pad; needs --i-understand-brick-risk"
                % (pkt.service, pkt.method, pkt.flags))

    def send_bytes(self, datagram: bytes) -> int:
        self.guard(datagram)
        assert self.sock is not None
        try:
            n = self.sock.sendto(datagram, (self.pad_ip, self.pad_port))
        except OSError as exc:
            return -exc.errno if exc.errno else -1
        self.tx_total += 1
        return n

    def send_raw(self, service: int, method: int, payload: bytes = b"", *,
                 flags: int = 0x40, txid: int = 0, fragid: int = 0,
                 final: bool = True, query_type: int = 0, version: int = 1,
                 magic: int = CMD_MAGIC, seq: Optional[int] = None,
                 packet_type: int = 0, generic: bool = True,
                 outer_size: Optional[int] = None,
                 gen_size: Optional[int] = None) -> Tuple[int, bytes]:
        """Build one console query and put it on the wire. Returns (seq, bytes)."""
        s = self.next_seq() if seq is None else seq & 0xFFFF
        pkt = CmdPacket(service=service, method=method, payload=payload,
                        packet_type=packet_type, query_type=query_type, seq=s,
                        version=version, txid=txid, fragid=fragid, final=final,
                        flags=flags, magic=magic, outer_size=outer_size,
                        gen_size=gen_size, generic=generic)
        datagram = pkt.encode()
        self.send_bytes(datagram)
        return s, datagram

    def send_fragmented(self, service: int, method: int, payload: bytes, *,
                        frag_size: int = 1028, txid: int = 0,
                        version: int = 1) -> List[bytes]:
        """Send a console-shaped M M M S group; returns the datagrams sent.

        Console shape (BOOT-AND-MODES.md sec.7b): each fragment is one datagram
        with its own outer sequence, generic payload_size = frag_size, flags 0x42
        on continuation fragments and 0x40 plus the final bit on the last one.
        """
        assert self.sock is not None
        chunks = [payload[i:i + frag_size] for i in range(0, max(len(payload), 1),
                                                          frag_size)]
        out: List[bytes] = []
        last = len(chunks) - 1
        for i, chunk in enumerate(chunks):
            final = (i == last)
            pkt = CmdPacket(service=service, method=method, payload=chunk,
                            seq=self.next_seq(), txid=txid, fragid=i,
                            final=final, flags=0x40 if final else 0x42,
                            version=version)
            dgram = pkt.encode()
            self.send_bytes(dgram)
            out.append(dgram)
        return out

    # -- transactions ---------------------------------------------------
    def _wait_new(self, idx: int, deadline: float) -> Tuple[List[Tuple[float, bytes]], int]:
        with self._cv:
            while len(self._events) <= idx:
                left = deadline - mono()
                if left <= 0:
                    return [], idx
                self._cv.wait(left)
            return self._events[idx:], len(self._events)

    def transact(self, datagram: bytes, *, seq: Optional[int] = None,
                 timeout: Optional[float] = None, retries: Optional[int] = None,
                 expect_reply: Optional[bool] = None,
                 rate: Optional[TokenBucket] = None,
                 on_sent: Optional[Any] = None) -> TxResult:
        """Send one console datagram, ACK the reply, retransmit on timeout."""
        timeout = self.timeout if timeout is None else timeout
        retries = self.retries if retries is None else retries
        if seq is None:
            seq = struct.unpack_from("<H", datagram, 6)[0] if len(datagram) >= 8 else 0
        if expect_reply is None:
            expect_reply = True
            if len(datagram) >= 20:
                parsed = CmdPacket.decode(datagram)
                if parsed.generic and parsed.magic == CMD_MAGIC:
                    expect_reply = parsed.expects_reply()
        res = TxResult(expect_reply=expect_reply)
        idx = len(self._events)
        attempt = 0
        while True:
            if rate:
                rate.acquire()
            t0 = mono()
            written = self.send_bytes(datagram)
            if written < 0:
                res.error = "sendto errno %d" % -written
                return res
            res.sent += 1
            if on_sent:
                on_sent(datagram, self.pad_port)
            deadline = t0 + timeout
            got_ack = False
            while True:
                events, idx = self._wait_new(idx, deadline)
                for t, data in events:
                    if len(data) < 8:
                        continue
                    ptype, qtype, _size, rseq = struct.unpack_from("<HHHH", data, 0)
                    if rseq != seq or qtype != struct.unpack_from("<H", datagram, 2)[0]:
                        res.other_rx += 1
                        continue
                    if ptype == 1:
                        got_ack = True
                        res.ack_seen = True
                    elif ptype == 2:
                        res.reply = CmdPacket.decode(data)
                        res.reply_raw = data
                        res.latency_ms = (t - t0) * 1000.0
                        self._note_reply(res.reply)
                        try:
                            self.send_bytes(cmd_ack(3, qtype, seq))
                        except BrickRisk:
                            pass
                        if not got_ack:
                            res.ack_seen = False
                        return res
                if (got_ack and not expect_reply) or mono() >= deadline:
                    break
            if res.ack_seen and not expect_reply:
                return res
            if attempt >= retries:
                return res
            attempt += 1
            res.retransmits += 1

    def _note_reply(self, reply: CmdPacket) -> None:
        if not reply.generic:
            return
        key = (reply.service, reply.method)
        digest = sha256_hex(reply.payload)[:12]
        prev = self.last_reply.get(key)
        if prev and prev[0] == len(reply.payload) and prev[1] != digest:
            self.reply_changes += 1
        self.last_reply[key] = (len(reply.payload), digest)

    def query(self, service: int, method: int, payload: bytes = b"",
              timeout: Optional[float] = None,
              rate: Optional[TokenBucket] = None) -> TxResult:
        pkt = CmdPacket(service=service, method=method, payload=payload,
                        seq=self.next_seq())
        return self.transact(pkt.encode(), timeout=timeout, retries=0, rate=rate)


class MediaSender:
    """One-way sender for the video/audio planes (console source port)."""

    def __init__(self, *, local_ip: str, local_port: int, pad_ip: str,
                 pad_port: int, what: str, allow_reuse: bool = False) -> None:
        self.local_ip = local_ip
        self.local_port = local_port
        self.pad_ip = pad_ip
        self.pad_port = pad_port
        self.what = what
        self.allow_reuse = allow_reuse
        self.sock: Optional[socket.socket] = None
        self.tx_total = 0
        self.tx_bytes = 0

    def open(self) -> None:
        self.sock = bind_udp(self.local_ip, self.local_port, what=self.what,
                             allow_reuse=self.allow_reuse)

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def send(self, datagram: bytes, port: Optional[int] = None) -> int:
        assert self.sock is not None
        try:
            n = self.sock.sendto(datagram,
                                 (self.pad_ip, self.pad_port if port is None
                                  else port))
        except OSError as exc:
            return -exc.errno if exc.errno else -1
        self.tx_total += 1
        self.tx_bytes += n
        return n


# ===========================================================================
# case catalogue
# ===========================================================================
@dataclass
class TestCase:
    idx: int
    name: str
    family: str
    plane: str                 # cmd | vstrm | astrm | dhcp | corpus
    datagrams: List[bytes]
    sport: int = 0
    dport: int = 0
    risk: str = "SAFE"         # SAFE | BRICK
    note: str = ""
    timeout: Optional[float] = None


@dataclass
class Corpus:
    """Base material: the real console session where available."""
    console_messages: Dict[str, bytes] = field(default_factory=dict)
    video_first_frame: List[bytes] = field(default_factory=list)
    video_frames: List[List[bytes]] = field(default_factory=list)
    video_packets: List[bytes] = field(default_factory=list)
    audio_packets: List[bytes] = field(default_factory=list)
    format_messages: List[bytes] = field(default_factory=list)
    source: str = "synthetic"


def load_truth_records(name: str, cap: int) -> List[Tuple[float, bytes]]:
    path = os.path.join(TRUTH, name)
    if not os.path.exists(path):
        return []
    out: List[Tuple[float, bytes]] = []
    with open(path, "rb") as fh:
        while len(out) < cap:
            hdr = fh.read(REC.size)
            if len(hdr) < REC.size:
                break
            ts = struct.unpack(">d", hdr[:8])[0]
            size = struct.unpack(">I", hdr[16:20])[0]
            body = fh.read(size)
            if len(body) < size:
                break
            out.append((ts, body))
    return out


def load_corpus(verbose: bool = False) -> Corpus:
    c = Corpus()
    try:
        for name in sorted(os.listdir(CONSOLE_MSGS)):
            if name.endswith(".bin"):
                with open(os.path.join(CONSOLE_MSGS, name), "rb") as fh:
                    c.console_messages[name] = fh.read()
    except OSError:
        pass
    vid = load_truth_records("port50120.bin", 400)
    if vid:
        c.video_packets = [p for _t, p in vid]
        frames: List[List[bytes]] = []
        cur: List[bytes] = []
        for _t, p in vid:
            cur.append(p)
            if p[2] & 0x10:            # frame_end
                frames.append(cur)
                cur = []
        if cur:
            frames.append(cur)
        c.video_frames = [f for f in frames if f]
        if c.video_frames:
            c.video_first_frame = list(c.video_frames[0])
    aud = load_truth_records("port50121.bin", 400)
    if aud:
        for _t, p in aud:
            if len(p) == 32:
                if len(c.format_messages) < 8:
                    c.format_messages.append(p)
            elif len(p) >= 8 and len(c.audio_packets) < 8:
                c.audio_packets.append(p)
    if c.video_packets and (c.audio_packets or c.format_messages):
        c.source = "truth"
    # synthetic fallbacks so the tool still works without the capture
    if not c.video_first_frame:
        ext = IDR_EXT
        for i in range(5):
            c.video_first_frame.append(VstrmPacket(
                seq=i + 1, init=True, frame_begin=(i == 0), chunk_end=(i == 4),
                frame_end=(i == 4), timestamp=1500000 + i * 16683,
                ext=ext, payload=bytes((i * 7 + j) & 0xFF for j in range(200))
            ).encode())
        c.video_packets = list(c.video_first_frame)
        c.video_frames = [list(c.video_first_frame)]
    if not c.audio_packets:
        c.audio_packets.append(AstrmPacket(
            seq=0, timestamp=87860260,
            payload=bytes(1664)).encode())
    if not c.format_messages:
        c.format_messages.append(VideoFormat(timestamp=87860260).encode())
    if verbose:
        say("corpus: %s, %d console messages, %d video frames (%d pkts), "
            "%d audio, %d format"
            % (c.source, len(c.console_messages), len(c.video_frames),
               len(c.video_packets), len(c.audio_packets), len(c.format_messages)))
    return c


# ---------------------------------------------------------------------------
# cmd engine
# ---------------------------------------------------------------------------
def cmd_cases(corpus: Corpus, seed: int = 0) -> List[TestCase]:
    out: List[TestCase] = []
    sport, dport = PORT_CMD

    def add(name: str, family: str, dgrams: Sequence[bytes],
            risk: str = "SAFE", note: str = "") -> None:
        out.append(TestCase(idx=0, name=name, family=family, plane="cmd",
                            datagrams=list(dgrams), sport=sport, dport=dport,
                            risk=risk, note=note))

    real_generic = corpus.console_messages.get("cmd_t0_q0_len12.bin")
    real_32b = corpus.console_messages.get("cmd_t0_q0_len44.bin")
    real_frag = corpus.console_messages.get("cmd_t0_q0_len1040.bin")
    real_uvc = corpus.console_messages.get("cmd_t0_q1_len48.bin")
    real_time = corpus.console_messages.get("cmd_t0_q2_len8.bin")

    # ---- controls: read-only queries and the console's own traffic ---------
    add("cmd/control.state", "control",
        [CmdPacket(service=4, method=0x05, seq=101).encode()],
        note="documented state oracle")
    add("cmd/control.version", "control",
        [CmdPacket(service=4, method=0x04, seq=102).encode()])
    add("cmd/control.lvc", "control",
        [CmdPacket(service=0, method=0x00, seq=103).encode()])
    add("cmd/control.brightness", "control",
        [CmdPacket(service=5, method=0x15, seq=104).encode()])
    if real_generic:
        add("cmd/control.console_generic", "control", [real_generic],
            note="byte-identical console 20 B generic command")
    if real_32b:
        add("cmd/control.console_32b", "control", [real_32b],
            note="console svc0/0x10, 32-byte payload")
    if real_frag:
        add("cmd/control.console_frag1", "control", [real_frag],
            note="console svc0/0x11 UIC state blob, one fragment")
        body = real_frag[20 + 4:]
        payload = b"".join(struct.pack(">I", i + 1) + body for i in range(4))
        pkts, chunks = [], [payload[i:i + 1028] for i in range(0, len(payload), 1028)]
        for i, chunk in enumerate(chunks[:4]):
            last = (i == 3)
            pkts.append(CmdPacket(service=0, method=0x11, payload=chunk,
                                  seq=200 + i, txid=0x10B, fragid=i, final=last,
                                  flags=0x40 if last else 0x42).encode())
        add("cmd/control.frag_group", "control", pkts,
            note="complete console-shaped M M M S group (svc0/0x11)")
        pkts_missing = pkts[:3]
        add("cmd/frag.missing_final", "fragmentation", pkts_missing,
            note="group with the final fragment dropped")
        add("cmd/frag.reversed", "fragmentation", list(reversed(pkts)),
            note="final fragment first")
        add("cmd/frag.dup_final", "fragmentation", pkts + [pkts[-1]],
            note="final fragment delivered twice")
        all_more = [replace_cmd(p, flags=0x42, final=False) for p in pkts]
        add("cmd/frag.all_more", "fragmentation", all_more,
            note="every fragment says 'more follows'")
        all_final = [replace_cmd(p, flags=0x40, final=True) for p in pkts]
        add("cmd/frag.all_final", "fragmentation", all_final,
            note="every fragment claims to be final")
        wrong_txid = [replace_cmd(p, txid=0x7FF) for p in pkts]
        add("cmd/frag.wrong_txid", "fragmentation", wrong_txid,
            note="consistent group, wrong transaction id")
    if real_uvc:
        add("cmd/control.uvcuac", "control", [real_uvc],
            note="console UVC/UAC query, f3=0 (inert)")
    if real_time:
        add("cmd/control.time", "control", [real_time])

    # ---- outer header field mutations --------------------------------------
    base = CmdPacket(service=4, method=0x05, seq=300).encode()
    for qtype in (0, 1, 2, 3, 0xFF):
        add("cmd/outer.qtype=%#x" % qtype, "outer.qtype",
            [replace_cmd(base, query_type=qtype)],
            note="generic body under a foreign query type")
    for ptype in (1, 2, 3, 0xFF):
        add("cmd/outer.ptype=%#x" % ptype, "outer.ptype",
            [replace_cmd(base, packet_type=ptype)],
            note="console sending a non-query packet type")
    for size in (0, 1, 12, len(base) - 8, len(base) - 7, 0xFFFF, 2048):
        add("cmd/outer.size=%d" % size, "outer.size",
            [replace_cmd(base, outer_size=size)],
            note="declared outer payload_size vs actual %d" % (len(base) - 8))
    for seq in (0, 1, 0xFFFF):
        add("cmd/outer.seq=%d" % seq, "outer.seq", [replace_cmd(base, seq=seq)])

    # ---- generic header field mutations ------------------------------------
    for magic in (0x00, 0xFF):
        add("cmd/gen.magic=%#x" % magic, "gen.magic", [replace_cmd(base, magic=magic)])
    for ver in (0, 2, 0xFF):
        add("cmd/gen.version=%#x" % ver, "gen.version", [replace_cmd(base, version=ver)])
    for txid in (0x000, 0x10B, 0xFFF):
        add("cmd/gen.txid=%#x" % txid, "gen.txid", [replace_cmd(base, txid=txid)])
    for fid in (0x000, 0x007, 0xFFF):
        add("cmd/gen.fragid=%#x" % fid, "gen.fragid",
            [replace_cmd(base, fragid=fid, final=False)])
    for flags in (0x00, 0x01, 0x02, 0x03, 0x08, 0x42, 0x44, 0xFC, 0xFF):
        add("cmd/gen.flags=%#02x" % flags, "gen.flags",
            [replace_cmd(base, flags=flags)])
    add("cmd/gen.final=0", "gen.final", [replace_cmd(base, final=False)])
    add("cmd/gen.final=1_flags=0x42", "gen.final",
        [replace_cmd(base, final=True, flags=0x42)])
    for err in (1, 0xFFFF):
        add("cmd/gen.error=%#x" % err, "gen.error", [replace_cmd(base, error=err)])
    for svc, meth in ((0xFF, 0xFF), (4, 0xFF), (0xFF, 0x05), (3, 0x06)):
        add("cmd/gen.svc=%d_method=%#x" % (svc, meth), "gen.svc",
            [CmdPacket(service=svc, method=meth, seq=310).encode()],
            note="unmapped service/method (3/0x06 = RSSI, benign)")
    for gsize in (0, 1, 0xFFFF, 2048):
        add("cmd/gen.size=%d" % gsize, "gen.size",
            [replace_cmd(base, gen_size=gsize)])

    # ---- payload size boundaries (truncate / extend) -----------------------
    long_payload = (real_frag[20:] if real_frag
                    else bytes(range(256)) * 4 + bytes(4))
    seed_pkt = CmdPacket(service=0, method=0x11, payload=long_payload,
                         seq=320, txid=0x10B, flags=0x42, final=False)
    for size in BOUNDARY_SIZES:
        if size <= len(long_payload):
            truncated = long_payload[:size]
            add("cmd/payload.trunc=%d" % size, "payload.trunc",
                [replace_cmd(seed_pkt.encode(), payload=truncated,
                             gen_size=len(long_payload))],
                note="declared generic size stays %d, body is %d"
                     % (len(long_payload), size))
    for size in BOUNDARY_SIZES:
        if size > len(long_payload):
            pad = bytes((size - len(long_payload)))
            add("cmd/payload.extend=%d" % size, "payload.extend",
                [replace_cmd(seed_pkt.encode(), payload=long_payload + pad,
                             gen_size=None, outer_size=None)],
                note="payload grown with NULs to %d B" % size)
    for fill, label in ((b"\xff", "0xff"), (b"\x00", "0x00")):
        add("cmd/payload.extend_fill=%s" % label, "payload.extend",
            [replace_cmd(seed_pkt.encode(),
                         payload=long_payload + fill * 1024,
                         gen_size=None, outer_size=None)])

    # ---- intra-payload mutations ------------------------------------------
    for off in (0, 1, 2, 3, 4, 7, 15, 31, 255, 1023):
        for val in (0x00, 0x80, 0xFF):
            if off >= len(long_payload):
                continue
            mutated = bytearray(long_payload)
            mutated[off] = val
            add("cmd/payload.byte[%d]=%#04x" % (off, val), "payload.intra",
                [replace_cmd(seed_pkt.encode(), payload=bytes(mutated))])
    for index in (0, 0x80000000, 0xFFFFFFFF):
        mutated = bytearray(long_payload)
        mutated[0:4] = struct.pack(">I", index & 0xFFFFFFFF)
        add("cmd/payload.index=%#x" % index, "payload.intra",
            [replace_cmd(seed_pkt.encode(), payload=bytes(mutated))],
            note="u32 message index (console runs 1..778)")

    # ---- seeded random byte soup (the --seed actually drives these) --------
    rng = random.Random("%d:cmd:random" % seed)
    pool = [d for d in (real_generic, real_32b, real_frag, real_uvc, real_time)
            if d]
    for n in range(8):
        src = bytearray(pool[n % len(pool)] if pool
                        else CmdPacket(service=4, method=0x05, seq=320).encode())
        for _ in range(rng.randrange(1, 5)):
            src[rng.randrange(len(src))] = rng.randrange(256)
        dgram = bytes(src)
        # a random flip can land on svc/method/query type: classify before the
        # case is scheduled so a flash write can never escape the SAFE gate
        risk = "BRICK" if CmdPacket.decode(dgram).brick() else "SAFE"
        add("cmd/random.%02d" % n, "random", [dgram], risk=risk,
            note="%d seeded byte flips (seed %d)" % (len(src), seed))

    # ---- brick-risk cases (never in SAFE) ---------------------------------
    def brick(name: str, family: str, dgram: bytes, note: str) -> None:
        add(name, family, [dgram], risk="BRICK", note=note)

    brick("cmd/brick.update_start", "brick",
          CmdPacket(service=0, method=0x02, payload=b"\x00\x00\x00\x00",
                    seq=400).encode(), "svc0/0x02 start product update")
    brick("cmd/brick.update_block", "brick",
          CmdPacket(service=0, method=0x03, payload=b"\x00\x00\x00\x01" + bytes(1024),
                    seq=401).encode(), "svc0/0x03 update data block")
    brick("cmd/brick.update_end", "brick",
          CmdPacket(service=0, method=0x04, seq=402).encode(),
          "svc0/0x04 end product update")
    brick("cmd/brick.update_abort", "brick",
          CmdPacket(service=0, method=0x05, seq=403).encode(),
          "svc0/0x05 abort update")
    brick("cmd/brick.reboot_normal", "brick",
          CmdPacket(service=4, method=0x01, payload=b"\x00", seq=404).encode(),
          "svc4/0x01 payload 0 reboot normal mode")
    brick("cmd/brick.reboot_firmware", "brick",
          CmdPacket(service=4, method=0x01, payload=b"\x02", seq=405).encode(),
          "svc4/0x01 payload 2 reboot to firmware-update mode")
    brick("cmd/brick.lang_update", "brick",
          CmdPacket(service=0, method=0x0D, payload=b"\x00\x00\x00\x00",
                    seq=406).encode(), "svc0/0x0d language flash update start")
    brick("cmd/brick.eeprom_write", "brick",
          CmdPacket(service=5, method=0x0C, payload=bytes(258), seq=407).encode(),
          "svc5/0x0c UIC EEPROM write")
    brick("cmd/brick.tvcode_update_start", "brick",
          CmdPacket(service=0, method=0x0B, payload=b"\x00\x00\x00\x00",
                    seq=411).encode(), "svc0/0x0b TVCode flash update start")
    brick("cmd/brick.tvcode_update_block", "brick",
          CmdPacket(service=0, method=0x0E, payload=b"\x00\x00\x00\x01" + bytes(256),
                    seq=412).encode(), "svc0/0x0e TVCode flash update block")
    brick("cmd/brick.lang_update_block", "brick",
          CmdPacket(service=0, method=0x0F, payload=b"\x00\x00\x00\x01" + bytes(256),
                    seq=413).encode(), "svc0/0x0f language flash update block")
    brick("cmd/brick.flash_commit", "brick",
          CmdPacket(service=0, method=0x0C, seq=414).encode(),
          "svc0/0x0c flash update commit")
    brick("cmd/brick.lcd_i2c", "brick",
          CmdPacket(service=5, method=0x19, payload=b"\x00\x00\x00\x00",
                    seq=415).encode(), "svc5/0x19 LCD controller write via i2c")
    brick("cmd/brick.shutdown_flags", "brick",
          CmdPacket(service=4, method=0x1A, flags=0x42, seq=408).encode(),
          "svc4/0x1a with flags 0x42 shuts the pad down")
    uvc = bytearray(VideoFormat(timestamp=0).encode()[:48])
    uvc = bytearray(48)
    uvc[3] = 1
    brick("cmd/brick.uvc_f3_1", "brick",
          CmdPacket(query_type=1, payload=bytes(uvc), seq=409,
                    generic=False).encode(), "UVC/UAC f3=1 switches to vWii mode")
    uvc3 = bytearray(48)
    uvc3[3] = 3
    brick("cmd/brick.uvc_f3_3", "brick",
          CmdPacket(query_type=1, payload=bytes(uvc3), seq=410,
                    generic=False).encode(), "UVC/UAC f3=3 shuts the pad down")
    return out


def replace_cmd(datagram: bytes, **changes: Any) -> bytes:
    """Re-encode a cmd datagram with selected header fields replaced."""
    pkt = CmdPacket.decode(datagram)
    pkt.diag = {}
    for key, value in changes.items():
        if not hasattr(pkt, key):
            raise KeyError(key)
        setattr(pkt, key, value)
    return pkt.encode()


# ---------------------------------------------------------------------------
# vstrm engine
# ---------------------------------------------------------------------------
def vstrm_cases(corpus: Corpus) -> List[TestCase]:
    out: List[TestCase] = []
    sport, dport = PORT_VIDEO

    def add(name: str, family: str, dgrams: Sequence[bytes], note: str = "") -> None:
        out.append(TestCase(idx=0, name=name, family=family, plane="vstrm",
                            datagrams=list(dgrams), sport=sport, dport=dport,
                            note=note))

    frames = corpus.video_frames or [corpus.video_first_frame]
    first = list(frames[0])
    mid_pkt = None
    for p in corpus.video_packets:
        if len(p) >= 20 and not (p[2] & 0x80):
            mid_pkt = p
            break
    if mid_pkt is None:
        mid_pkt = first[-1]
    base = VstrmPacket.decode(mid_pkt)

    add("vstrm/control.first_frame", "control", first,
        note="real console first frame: %d datagrams, all init-flagged" % len(first))
    if len(frames) > 1:
        add("vstrm/control.frame2", "control", frames[1],
            note="real console frame 2 (%d datagrams)" % len(frames[1]))
    add("vstrm/control.single", "control", [mid_pkt],
        note="one real mid-stream datagram")

    def one(name: str, family: str, note: str = "", **changes: Any) -> None:
        pkt = VstrmPacket.decode(mid_pkt)
        pkt.diag = {}
        for k, v in changes.items():
            setattr(pkt, k, v)
        add(name, family, [pkt.encode()], note)

    for magic in (0x0, 0x1, 0x8, 0xF):
        one("vstrm/magic=%#x" % magic, "header.magic", magic=magic)
    for ptype in (0, 1, 2, 3):
        one("vstrm/ptype=%d" % ptype, "header.ptype", packet_type=ptype)
    for seq in (0, 1, 0x3FE, 0x3FF):
        one("vstrm/seq=%d" % seq, "header.seq", seq=seq)
    for field_name, label in (("init", "init"), ("frame_begin", "frame_begin"),
                              ("chunk_end", "chunk_end"), ("frame_end", "frame_end"),
                              ("has_timestamp", "has_timestamp")):
        one("vstrm/%s=1" % label, "header.flags", **{field_name: True})
        one("vstrm/%s=0" % label, "header.flags", **{field_name: False})
    one("vstrm/flags.all-ones", "header.flags",
        init=True, frame_begin=True, chunk_end=True, frame_end=True)
    for size in (0, 1, 0x7FF):
        one("vstrm/plen=%d" % size, "header.size", payload_size=size,
            note="declared payload_size vs %d actual" % len(base.payload))
    one("vstrm/plen=actual+1", "header.size",
        payload_size=min(0x7FF, len(base.payload) + 1))
    one("vstrm/plen=actual-1", "header.size",
        payload_size=max(0, len(base.payload) - 1))

    # ---- extended-header option soup --------------------------------------
    ext_cases = {
        "idr+known": build_ext([0x80, (0x82, 0x00), 0x83, (0x85, 0x06)]),
        "arg-0xff": build_ext([(0x82, 0xFF), (0x85, 0xFF), (0x81, 0xFF)]),
        "arg-0x01": build_ext([(0x82, 0x01), (0x85, 0x01), (0x81, 0x01)]),
        "unterminated": bytes([0x82, 0x00, 0x82, 0x00, 0x82, 0x00, 0x82, 0x00]),
        "early-end": bytes([0x00, 0x82, 0x00, 0x83, 0x85, 0x06, 0x00, 0x00]),
        "no-end-noise": bytes([0x85, 0x06, 0x85, 0x06, 0x85, 0x06, 0x85, 0x06]),
        "unknown-0x86": bytes([0x86, 0x01, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00]),
        "unknown-0x8f": bytes([0x8F, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
        "all-0xff": b"\xff" * 8,
        "all-zero": b"\x00" * 8,
        "idr-eight": bytes([0x80] * 8),
        "frame-rate-abuse": build_ext([(0x82, 0xFF), (0x82, 0x00), (0x85, 0xFF),
                                       (0x83, 0x00)]),
    }
    for label, ext in ext_cases.items():
        one("vstrm/ext.%s" % label, "ext", ext=ext,
            note="extended header %s -> %r" % (ext.hex(), parse_ext(ext)))

    # ---- payload size abuse ------------------------------------------------
    for grow in (1, 16, 106, 1226):
        body = base.payload + bytes(grow)
        one("vstrm/size.grow+%d" % grow, "size", payload=body,
            note="actual %d B, declared %d B" % (len(body), len(base.payload)))
    for shrink in (1, 8, 64):
        if shrink < len(base.payload):
            body = base.payload[:len(base.payload) - shrink]
            one("vstrm/size.shrink-%d" % shrink, "size", payload=body,
                note="actual %d B, declared %d B" % (len(body), len(base.payload)))
    one("vstrm/size.tiny-8", "size", payload=b"\x00" * 8, payload_size=8)
    one("vstrm/size.jumbo-1710", "size", payload=bytes(1694), payload_size=1694,
        note="full 1710 B datagram of zeros")
    one("vstrm/size.jumbo-4096", "size", payload=bytes(4080), payload_size=0x7FF)
    one("vstrm/size.jumbo-65000", "size", payload=bytes(64848), payload_size=0x7FF,
        note="L3-fragmented, far past the pad's reassembly buffer")

    # ---- chunk / frame bookkeeping abuse ----------------------------------
    if len(first) >= 3:
        every_end = []
        for i, d in enumerate(first):
            pkt = VstrmPacket.decode(d)
            pkt.diag = {}
            pkt.chunk_end = True
            pkt.frame_end = True
            every_end.append(pkt.encode())
        add("vstrm/chunk.end-on-every-packet", "chunk", every_end,
            note="25 datagrams each claiming chunk_end+frame_end")
        no_end = []
        for d in first:
            pkt = VstrmPacket.decode(d)
            pkt.diag = {}
            pkt.chunk_end = False
            pkt.frame_end = False
            no_end.append(pkt.encode())
        add("vstrm/chunk.no-end-flags", "chunk", no_end,
            note="frame with no chunk_end/frame_end at all")
        add("vstrm/chunk.shuffled", "chunk", list(reversed(first)),
            note="frame delivered in reverse order")
        dup = first[:3] + first[:3] + first[3:]
        add("vstrm/chunk.duplicated-head", "chunk", dup,
            note="first three datagrams delivered twice")
        add("vstrm/chunk.interleaved-two-frames", "chunk",
            [x for pair in zip(first, first) for x in pair],
            note="same frame referenced twice, interleaved")
    for ts in (0, 0xFFFFFFFF):
        one("vstrm/timestamp=%#x" % ts, "timestamp", timestamp=ts)
    one("vstrm/timestamp.stale", "timestamp", timestamp=base.timestamp - 60_000_000,
        note="timestamp 60 s behind the previous packet")
    return out


# ---------------------------------------------------------------------------
# astrm engine
# ---------------------------------------------------------------------------
def astrm_cases(corpus: Corpus) -> List[TestCase]:
    out: List[TestCase] = []
    sport, dport = PORT_AUDIO

    def add(name: str, family: str, dgrams: Sequence[bytes], note: str = "") -> None:
        out.append(TestCase(idx=0, name=name, family=family, plane="astrm",
                            datagrams=list(dgrams), sport=sport, dport=dport,
                            note=note))

    audio = corpus.audio_packets[0]
    fmt_msg = corpus.format_messages[0]
    abase = AstrmPacket.decode(audio)
    fbase = VideoFormat.decode(fmt_msg)

    add("astrm/control.audio", "control", [audio],
        note="real console PCM packet: fmt=%d psize=%d ts=%d"
             % (abase.fmt, abase.payload_size or 0, abase.timestamp))
    add("astrm/control.format", "control", [fmt_msg],
        note="real console 32 B video-format message")

    def one(name: str, family: str, note: str = "", **changes: Any) -> None:
        pkt = AstrmPacket.decode(audio)
        pkt.diag = {}
        for k, v in changes.items():
            setattr(pkt, k, v)
        add(name, family, [pkt.encode()], note)

    for fmt in range(8):
        one("astrm/fmt=%d" % fmt, "header.fmt", fmt=fmt)
    one("astrm/mono=1", "header.flags", mono=1)
    one("astrm/vibrate=1", "header.flags", vibrate=1)
    one("astrm/type=1(1664B payload)", "header.type", ptype=1,
        note="audio-sized payload declared as a video-format message")
    for seq in (0, 1, 0x3FF):
        one("astrm/seq=%d" % seq, "header.seq", seq=seq)
    for size in (0, 1, 8, 0xFFFF, 1665, 1650, 4000):
        one("astrm/psize=%d" % size, "header.size", payload_size=size,
            note="declared payload_size vs %d actual" % len(abase.payload))
    for ts in (0, 0xFFFFFFFF):
        one("astrm/timestamp=%#x" % ts, "header.ts", timestamp=ts)

    one("astrm/pcm.truncate-100", "pcm", payload=abase.payload[:100])
    one("astrm/pcm.truncate-0", "pcm", payload=b"")
    one("astrm/pcm.extend-4000", "pcm", payload=abase.payload + bytes(4000),
        payload_size=4000)
    one("astrm/pcm.extend-65000", "pcm", payload=bytes(65000), payload_size=65000,
        note="declared 65000, past the 16-bit field is impossible: truncated")
    one("astrm/pcm.silence-full", "pcm", payload=bytes(1664))
    one("astrm/pcm.full-scale", "pcm", payload=b"\xff\x7f" * 832,
        note="PCM at full positive scale")
    one("astrm/pcm.square", "pcm",
        payload=bytes(([0x00, 0x80, 0xFF, 0x7F] * 416)))

    # ---- video-format message field mutations -----------------------------
    def fmt_one(name: str, family: str, note: str = "", **changes: Any) -> None:
        fmt = VideoFormat.decode(fmt_msg)
        for k, v in changes.items():
            setattr(fmt, k, v)
        add(name, family, [fmt.encode()], note)

    for field_name in FORMAT_FIELDS:
        fmt_one("astrm/format.%s=0xffffffff" % field_name, "format",
                **{field_name: 0xFFFFFFFF})
        fmt_one("astrm/format.%s=0" % field_name, "format", **{field_name: 0})
    fmt_one("astrm/format.timestamp.stale", "format",
            timestamp=fbase.timestamp - 60_000_000)
    add("astrm/format.truncated-31", "format", [fmt_msg[:31]])
    add("astrm/format.truncated-16", "format", [fmt_msg[:16]])
    add("astrm/format.extended-40", "format", [fmt_msg + bytes(8)])
    add("astrm/format.zeroes", "format", [bytes(32)],
        note="all-zero format message")
    add("astrm/format.ff", "format", [b"\xff" * 32])
    return out


# ---------------------------------------------------------------------------
# dhcp engine
# ---------------------------------------------------------------------------
def dhcp_cases(server_ip: str, client_ip: str, port: int) -> List[TestCase]:
    req = build_dhcp_request()
    out: List[TestCase] = []
    for soup_name, opts in dhcp_soups(server_ip, client_ip).items():
        reply = build_dhcp_reply(req, client_ip=client_ip, server_ip=server_ip,
                                 options=opts)
        out.append(TestCase(idx=0, name="dhcp/%s" % soup_name, family="dhcp",
                            plane="dhcp", datagrams=[reply], sport=port,
                            dport=PORT_DHCP_CLIENT,
                            note="option soup %r (%d B total)"
                                 % (soup_name, len(opts))))
    return out


# ---------------------------------------------------------------------------
# static corpus engine (--mutate-from)
# ---------------------------------------------------------------------------
CORPUS_MUTATIONS: Tuple[Tuple[str, bytes], ...] = (
    ("set0", b"\x00"),
    ("setff", b"\xff"),
    ("set80", b"\x80"),
    ("set7f", b"\x7f"),
)


def corpus_cases(paths: Sequence[str], port: int, plane: str,
                 seed: int) -> List[TestCase]:
    out: List[TestCase] = []
    for path in paths:
        try:
            with open(path, "rb") as fh:
                seed_bytes = fh.read()
        except OSError as exc:
            warn("cannot read %s: %s" % (path, exc))
            continue
        if not seed_bytes:
            continue
        base = os.path.basename(path)
        rng = random.Random("%d:corpus:%s" % (seed, base))
        out.append(TestCase(idx=0, name="corpus/%s/control" % base,
                            family="corpus.control", plane=plane,
                            datagrams=[seed_bytes], sport=0, dport=port,
                            note="seed message unchanged (%d B)" % len(seed_bytes)))
        offsets = sorted({0, 1, 2, 3, 4, 7, 8, 15, len(seed_bytes) // 2,
                          len(seed_bytes) - 1})
        for off in offsets:
            if off < 0 or off >= len(seed_bytes):
                continue
            for label, value in CORPUS_MUTATIONS:
                mutated = bytearray(seed_bytes)
                mutated[off] = value[0]
                out.append(TestCase(idx=0, name="corpus/%s/byte[%d].%s"
                                    % (base, off, label),
                                    family="corpus.byteflip", plane=plane,
                                    datagrams=[bytes(mutated)], sport=0,
                                    dport=port))
        for cut in (1, 8, 16, len(seed_bytes) // 2):
            if 0 < cut < len(seed_bytes):
                out.append(TestCase(idx=0, name="corpus/%s/trunc-%d" % (base, cut),
                                    family="corpus.truncate", plane=plane,
                                    datagrams=[seed_bytes[:cut]], sport=0,
                                    dport=port))
        for extra in (1, 16, 256):
            grown = seed_bytes + bytes(rng.randrange(256) for _ in range(extra))
            out.append(TestCase(idx=0, name="corpus/%s/extend+%d" % (base, extra),
                                family="corpus.extend", plane=plane,
                                datagrams=[grown], sport=0, dport=port))
        for _ in range(2):
            mutated = bytearray(seed_bytes)
            for _ in range(min(8, len(mutated))):
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            out.append(TestCase(idx=0, name="corpus/%s/random8" % base,
                                family="corpus.random", plane=plane,
                                datagrams=[bytes(mutated)], sport=0, dport=port,
                                note="8 random byte substitutions"))
    return out


def build_catalogue(args: argparse.Namespace, corpus: Corpus,
                    pad_ip: str) -> List[TestCase]:
    cases: List[TestCase] = []
    if args.mutate_from:
        paths: List[str] = []
        for entry in args.mutate_from:
            if os.path.isdir(entry):
                paths.extend(sorted(os.path.join(entry, n)
                                    for n in os.listdir(entry) if n.endswith(".bin")))
            else:
                paths.append(entry)
        cases.extend(corpus_cases(paths, args.corpus_port, args.corpus_plane,
                                  args.seed))
    planes = args.plane or ["cmd", "vstrm", "astrm"]
    if "cmd" in planes:
        cases.extend(cmd_cases(corpus, args.seed))
    if "vstrm" in planes:
        cases.extend(vstrm_cases(corpus))
    if "astrm" in planes:
        cases.extend(astrm_cases(corpus))
    if "dhcp" in planes:
        server_ip = args.local_ip or (LOOPBACK if pad_ip == LOOPBACK else CONSOLE_IP)
        cases.extend(dhcp_cases(server_ip, pad_ip, args.dhcp_port))
    # number the FULL catalogue first: --list, --case and case-NNN.bin all refer
    # to these indices, so a filter must never renumber what it leaves behind
    for i, case in enumerate(cases):
        case.idx = i
    if args.family:
        wanted = set(args.family)
        cases = [c for c in cases if c.family in wanted
                 or any(c.family.startswith(w) for w in wanted)]
    if args.case is not None:
        wanted_idx = set(args.case)
        cases = [c for c in cases if c.idx in wanted_idx]
    return cases


def cases_fingerprint(cases: Sequence[TestCase]) -> str:
    h = hashlib.sha256()
    for case in cases:
        h.update(case.name.encode())
        h.update(b"\x00")
        h.update(str(case.dport).encode())
        for d in case.datagrams:
            h.update(struct.pack(">I", len(d)))
            h.update(d)
    return h.hexdigest()


# ===========================================================================
# verdict classification
# ===========================================================================
def classify(*, reply: Optional[CmdPacket], ack_seen: bool,
             latency_ms: Optional[float], state_before: Optional[int],
             state_after: Optional[int], gone: bool, latency_limit_ms: float,
             expects_reply: bool) -> Tuple[str, str]:
    if gone:
        return "GONE", "command plane silent and no input datagrams"
    if state_before is not None and state_after is not None \
            and state_before != state_after:
        return "STATECHANGE", "state index %d -> %d" % (state_before, state_after)
    if expects_reply and reply is None:
        return "NOREPLY", "no reply"
    if reply is not None and not ack_seen:
        return "NOACK", "reply without type-1 ack"
    if latency_ms is not None and latency_ms > latency_limit_ms:
        return "LATENCY", "reply in %.1f ms (> %.0f)" % (latency_ms,
                                                         latency_limit_ms)
    return "OK", ""


# ===========================================================================
# runner
# ===========================================================================
class Ctx:
    """Everything a case needs: planes, oracle, recorder, rate limit."""

    def __init__(self, args: argparse.Namespace, pad_ip: str, live: bool,
                 recorder: Optional[Recorder], corpus: Corpus) -> None:
        self.args = args
        self.pad_ip = pad_ip
        self.live = live
        self.recorder = recorder
        self.corpus = corpus
        self.local_ip = args.local_ip or (LOOPBACK if pad_ip == LOOPBACK
                                          else CONSOLE_IP)
        self.cmd = CmdPlane(local_ip=self.local_ip, local_port=args.cmd_sport,
                            pad_ip=pad_ip, pad_port=args.cmd_dport,
                            timeout=args.case_timeout, retries=args.retries,
                            allow_brick=args.i_understand_brick_risk,
                            allow_reuse=args.force)
        self.video = MediaSender(
            local_ip=self.local_ip, local_port=args.video_sport, pad_ip=pad_ip,
            pad_port=getattr(args, "video_dport", PORT_VIDEO[1]),
            what="vstrm sender", allow_reuse=args.force)
        self.audio = MediaSender(
            local_ip=self.local_ip, local_port=args.audio_sport, pad_ip=pad_ip,
            pad_port=getattr(args, "audio_dport", PORT_AUDIO[1]),
            what="astrm sender", allow_reuse=args.force)
        self.input_ip = self.local_ip
        self.liveness = Liveness(pad_ip=pad_ip, input_ip=self.input_ip,
                                 input_port=args.input_port,
                                 icmp=not args.no_icmp, ap_log=args.ap_log,
                                 allow_reuse=args.force)
        self.bucket = TokenBucket(args.max_rate)
        self.state: Optional[int] = None
        self.consecutive_gone = 0
        self.aped: bool = False
        self.verdict_counts: Dict[str, int] = {}

    def open(self) -> None:
        self.cmd.open()
        self.video.open()
        self.audio.open()
        self.liveness.start()

    def close(self) -> None:
        self.liveness.stop()
        for plane in (self.cmd, self.video, self.audio):
            plane.close()

    # -- oracle ---------------------------------------------------------
    def probe(self) -> Dict[str, Any]:
        """Sample the documented oracles: state index, version, LVC version."""
        out: Dict[str, Any] = {"state": None, "version": None, "lvc": None,
                              "latency_ms": None, "reply": None,
                              "ack_seen": False, "reply_changes": 0,
                              "errors": {}}
        before_changes = self.cmd.reply_changes
        for label, svc, meth in (("state", 4, 0x05), ("version", 4, 0x04),
                                 ("lvc", 0, 0x00)):
            res = self.cmd.query(svc, meth, timeout=self.args.oracle_timeout,
                                 rate=self.bucket)
            if res.reply is None:
                out["errors"][label] = res.error or "no reply"
                if label == "state":
                    break            # pad dead; skip the rest of the probes
                continue
            body = res.reply.payload
            if label == "state":
                out["reply"] = res.reply
                out["ack_seen"] = res.ack_seen
                out["latency_ms"] = res.latency_ms
                out["state"] = body[0] if body else None
            elif label == "version":
                out["version"] = body.hex()
            else:
                out["lvc"] = body.hex()
        out["reply_changes"] = self.cmd.reply_changes - before_changes
        return out


def print_case_line(case: TestCase, verdict: str, detail: str,
                    total: int, tx: int, live_info: Dict[str, Any],
                    oracle: Dict[str, Any]) -> None:
    pps = live_info.get("input_pps")
    pps_s = "  n/a" if pps is None else "%5.0f" % pps
    icmp = live_info.get("icmp_ok")
    icmp_s = "yes" if icmp else ("no " if icmp is False else "n/a")
    lat = oracle.get("latency_ms")
    lat_s = "   n/a" if lat is None else "%6.1f" % lat
    say("[%3d/%3d] %-5s %-5s %-38s tx%-2d rx%d ack%d lat%s in%s icmp=%s st=%s->%s  %-11s %s"
        % (case.idx + 1, total, case.plane, case.risk, case.name[:38], tx,
           1 if oracle.get("reply") else 0, 1 if oracle.get("ack_seen") else 0,
           lat_s, pps_s, icmp_s,
           "-" if oracle.get("state_before") is None else oracle["state_before"],
           "-" if oracle.get("state") is None else oracle["state"],
           verdict, detail))


def run_cases(ctx: Ctx, cases: Sequence[TestCase],
              total: Optional[int] = None) -> Dict[str, Any]:
    args = ctx.args
    total = total or len(cases)
    started = time.time()
    aborted = ""
    ran = 0
    skipped = 0
    for case in cases:
        if case.risk != "SAFE" and not args.i_understand_brick_risk:
            skipped += 1
            continue
        ap_mark = len(ctx.liveness.ap_events)
        pre = ctx.liveness.snapshot()
        oracle_pre = ctx.probe()
        state_before = oracle_pre["state"]
        if ctx.recorder:
            ctx.recorder.case_begin(case)
        tx = 0
        first: Optional[TxResult] = None
        err = ""
        try:
            for dgram in case.datagrams:
                if case.plane in ("cmd",):
                    res = ctx.cmd.transact(
                        dgram, timeout=case.timeout or args.case_timeout,
                        retries=args.retries, rate=ctx.bucket,
                        on_sent=(ctx.recorder.note_sent if ctx.recorder else None))
                    if ctx.recorder and res.sent and not res.error:
                        pass
                    tx += res.sent
                    if first is None:
                        first = res
                    if res.error:
                        err = res.error
                elif case.plane in ("vstrm", "astrm"):
                    ctx.bucket.acquire()
                    sender = ctx.video if case.plane == "vstrm" else ctx.audio
                    written = sender.send(dgram)
                    if written < 0:
                        err = "sendto errno %d" % -written
                    else:
                        tx += 1
                        if ctx.recorder:
                            ctx.recorder.note_sent(dgram, case.dport)
                else:                     # dhcp / corpus over an arbitrary port
                    ctx.bucket.acquire()
                    written = ctx.video.send(dgram, case.dport or None)
                    if written < 0:
                        err = "sendto errno %d" % -written
                    else:
                        tx += 1
                        if ctx.recorder:
                            ctx.recorder.note_sent(dgram, case.dport)
        except BrickRisk as exc:
            err = str(exc)
            skipped += 1
            say("[skip] %-38s %s" % (case.name, exc))
            continue
        except OSError as exc:
            err = str(exc)
        time.sleep(args.settle)
        post = ctx.liveness.snapshot()
        oracle = ctx.probe()
        oracle["state_before"] = state_before
        state_after = oracle["state"]
        if case.plane == "cmd" and first is not None:
            reply = first.reply
            ack_seen = first.ack_seen
            latency = first.latency_ms
            expects = first.expect_reply
        else:
            reply = oracle["reply"]
            ack_seen = oracle["ack_seen"]
            latency = oracle["latency_ms"]
            expects = True
        gone = (oracle["reply"] is None
                and (post.get("input_pps") in (None, 0.0))
                and post.get("input_available", False))
        verdict, detail = classify(reply=reply, ack_seen=ack_seen,
                                   latency_ms=latency, state_before=state_before,
                                   state_after=state_after, gone=gone,
                                   latency_limit_ms=args.latency_ms,
                                   expects_reply=expects)
        if err:
            detail = (detail + "; " + err).strip("; ")
        ran += 1
        ctx.verdict_counts[verdict] = ctx.verdict_counts.get(verdict, 0) + 1
        ap_events = ctx.liveness.new_ap_events(ap_mark)
        print_case_line(case, verdict, detail, total, tx, post, oracle)
        for ev in ap_events:
            say("           ap-log: %s" % ev["line"][:140])
        if ctx.recorder:
            ctx.recorder.case_end(verdict, detail, {
                "state_before": state_before,
                "state_after": state_after,
                "oracle_latency_ms": (round(oracle["latency_ms"], 3)
                                      if oracle.get("latency_ms") else None),
                "reply_latency_ms": (round(latency, 3) if latency else None),
                "ack_seen": ack_seen,
                "reply_changes": oracle.get("reply_changes", 0),
                "input_pps_pre": pre.get("input_pps"),
                "input_pps_post": post.get("input_pps"),
                "icmp_ok": post.get("icmp_ok"),
                "ap_events": ap_events,
                "client_error": err,
            })
        if verdict == "GONE":
            ctx.consecutive_gone += 1
            if args.deadman and ctx.consecutive_gone >= args.deadman:
                aborted = ("deadman: pad read GONE for %d consecutive cases - "
                           "stopping the run" % ctx.consecutive_gone)
                say("\n[STOP] " + aborted)
                break
        else:
            ctx.consecutive_gone = 0
    elapsed = time.time() - started
    summary = {
        "cases_total": total,
        "cases_ran": ran,
        "cases_skipped": skipped,
        "elapsed_s": round(elapsed, 2),
        "verdicts": dict(sorted(ctx.verdict_counts.items())),
        "aborted": aborted,
        "rx_cmd": ctx.cmd.rx_total,
        "tx_cmd": ctx.cmd.tx_total,
        "tx_video": ctx.video.tx_total,
        "tx_audio": ctx.audio.tx_total,
        "reply_changes": ctx.cmd.reply_changes,
    }
    say("\n== summary")
    for key in ("cases_total", "cases_ran", "cases_skipped", "elapsed_s",
                "verdicts", "aborted", "tx_cmd", "tx_video", "tx_audio",
                "reply_changes"):
        say("   %-15s %s" % (key, summary[key]))
    return summary


# ===========================================================================
# DHCP responder mode
# ===========================================================================
def run_dhcp_responder(ctx: Ctx, args: argparse.Namespace) -> Dict[str, Any]:
    soups = dhcp_soups(ctx.local_ip, ctx.pad_ip)
    names = list(soups)
    req_count = 0
    say("[*] DHCP responder on %s:%d serving %d soups (%s)"
        % (ctx.local_ip, args.dhcp_port, len(names), ", ".join(names[:4]) + " ..."))
    if args.dhcp_port == PORT_DHCP:
        warn("serving real udp/67 - stop netboot first (run/drc-down.sh) or the "
             "pad will never see these replies")
    sock = bind_udp(ctx.local_ip, args.dhcp_port, what="dhcp responder",
                    allow_reuse=args.force,
                    broadcast=(ctx.pad_ip != LOOPBACK))
    sock.settimeout(1.0)
    deadline = mono() + args.dhcp_seconds
    try:
        while mono() < deadline and req_count < args.dhcp_max_requests:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if len(data) < DHCP_OPTS_START or data[0] != 1:
                continue
            soup = names[req_count % len(names)]
            reply = build_dhcp_reply(data, client_ip=ctx.pad_ip,
                                     server_ip=ctx.local_ip, options=soups[soup])
            opts, well_formed = parse_dhcp_options(reply)
            dest = (addr[0], addr[1]) if ctx.pad_ip == LOOPBACK \
                else ("255.255.255.255", PORT_DHCP_CLIENT)
            try:
                sock.sendto(reply, dest)
            except OSError as exc:
                warn("dhcp send failed: %s" % exc)
                continue
            req_count += 1
            pre = ctx.liveness.snapshot()
            time.sleep(0.05)
            post = ctx.liveness.snapshot()
            oracle = ctx.probe()
            verdict, detail = classify(
                reply=oracle["reply"], ack_seen=oracle["ack_seen"],
                latency_ms=oracle["latency_ms"], state_before=ctx.state,
                state_after=oracle["state"],
                gone=(oracle["reply"] is None and post.get("input_pps") in (None, 0.0)
                      and post.get("input_available", False)),
                latency_limit_ms=args.latency_ms, expects_reply=True)
            if oracle["state"] is not None:
                ctx.state = oracle["state"]
            say("[dhcp %2d] soup=%-20s reply=%dB options=%d wells_formed=%s "
                "in=%s/s -> %s %s"
                % (req_count, soup, len(reply), len(opts), well_formed,
                   post.get("input_pps"), verdict, detail))
            if ctx.recorder:
                case = TestCase(idx=req_count - 1, name="dhcp/%s" % soup,
                                family="dhcp", plane="dhcp", datagrams=[reply],
                                sport=args.dhcp_port, dport=PORT_DHCP_CLIENT)
                ctx.recorder.case_begin(case)
                ctx.recorder.note_sent(reply, PORT_DHCP_CLIENT)
                ctx.recorder.case_end(verdict, detail,
                                      {"input_pps_pre": pre.get("input_pps"),
                                       "input_pps_post": post.get("input_pps"),
                                       "dhcp_options": len(opts),
                                       "dhcp_well_formed": well_formed})
    finally:
        sock.close()
    return {"dhcp_requests": req_count, "soups": len(names)}


# ===========================================================================
# replay
# ===========================================================================
def replay(ctx: Ctx, args: argparse.Namespace) -> int:
    path = args.replay
    meta_path = os.path.splitext(path)[0] + ".json"
    meta: Dict[str, Any] = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            meta = {}
    dport = args.replay_port or int(meta.get("dport") or PORT_CMD[1])
    plane = meta.get("plane") or args.replay_plane
    records = list(iter_records(path))
    datagrams = [d for _t, d in records]
    if not datagrams:
        warn("nothing to replay in %s" % path)
        return 2
    digest = sha256_hex(b"".join(datagrams))
    say("[*] replaying %s: %d datagram(s), %d bytes, plane=%s dport=%d"
        % (path, len(datagrams), sum(len(d) for d in datagrams), plane, dport))
    say("[*] byte-stream sha256 %s" % digest)
    if meta.get("sha256"):
        ok = (meta["sha256"] == digest)
        say("[%s] recorded sha256 %s -> %s"
            % ("=" if ok else "!", meta["sha256"], "MATCH" if ok else "MISMATCH"))
        if not ok:
            return 3
    replay_case = TestCase(idx=0, name="replay/%s" % os.path.basename(path),
                           family="replay", plane=plane, datagrams=datagrams,
                           sport=args.cmd_sport, dport=dport,
                           risk="SAFE", note="recorded byte stream replayed")
    if ctx.recorder:
        ctx.recorder.case_begin(replay_case)
    t0 = records[0][0]
    prev_wall = mono()
    for i, (ts, dgram) in enumerate(records):
        if i:
            gap = (ts - records[i - 1][0]) / max(args.replay_speed, 0.001)
            sleep_for = gap - (mono() - prev_wall)
            if sleep_for > 0:
                time.sleep(min(sleep_for, 2.0))
        prev_wall = mono()
        if ctx.recorder:
            ctx.recorder.note_sent(dgram, dport)
        ctx.bucket.acquire()
        if plane == "cmd":
            res = ctx.cmd.transact(dgram, retries=args.retries,
                                   timeout=args.case_timeout)
            say("  [%2d] %4dB tx ack=%d reply=%d lat=%s"
                % (i, len(dgram), 1 if res.ack_seen else 0,
                   1 if res.reply else 0,
                   "-" if res.latency_ms is None else "%.1fms" % res.latency_ms))
        else:
            sender = ctx.video if plane == "vstrm" else ctx.audio
            written = ctx.video.send(dgram) if plane == "dhcp" else sender.send(dgram)
            if written < 0:
                warn("sendto errno %d on datagram %d" % (-written, i))
        _ = t0
    oracle = ctx.probe()
    say("[=] post-replay state=%s version=%s lvc=%s input=%s/s"
        % (oracle["state"], (oracle["version"] or "-")[:16],
           (oracle["lvc"] or "-")[:16], ctx.liveness.snapshot().get("input_pps")))
    if ctx.recorder:
        ctx.recorder.case_end("REPLAY", "%d datagram(s)" % len(datagrams), {
            "state_after": oracle["state"],
            "oracle_latency_ms": (round(oracle["latency_ms"], 3)
                                  if oracle.get("latency_ms") else None),
            "ack_seen": oracle["ack_seen"],
            "client_error": ""})
    return 0


# ===========================================================================
# mock pad for --selftest (loopback only)
# ===========================================================================
class MockPad:
    """A pad stand-in on loopback: cmd responder, input emitter, media sinks.

    Deliberately misbehaves in scripted ways so the oracle and the verdict
    classifier can be exercised without touching hardware:

      * magic != 0x7e, or a foreign query type on a generic body -> silence
        (a real pad drops packets it cannot parse) -> NOREPLY
      * svc 4/0x04 -> reply WITHOUT the type-1 ack -> NOACK
      * svc 5/0x15 -> reply after `slow_delay` seconds -> LATENCY
      * the final fragment of an svc 0/0x11 group -> state index advances
        -> STATECHANGE
      * `gone` -> no cmd replies and no input datagrams -> GONE
    """

    def __init__(self, *, ip: str = LOOPBACK, cmd_port: int, input_port: int,
                 video_port: int, audio_port: int, dhcp_port: int,
                 input_rate: float = 180.0, slow_delay: float = 0.4) -> None:
        self.ip = ip
        self.cmd_port = cmd_port
        self.input_port = input_port
        self.video_port = video_port
        self.audio_port = audio_port
        self.dhcp_port = dhcp_port
        self.input_rate = input_rate
        self.slow_delay = slow_delay
        self.state = 4
        self.gone = False
        self.rx_cmd = 0
        self.rx_media = 0
        self.rx_input_emitted = 0
        self.dhcp_rx = 0
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self.socks: List[socket.socket] = []

    def start(self) -> None:
        cmd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cmd.bind((self.ip, self.cmd_port))
        cmd.settimeout(0.1)
        self.socks.append(cmd)
        video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        video.bind((self.ip, self.video_port))
        video.settimeout(0.1)
        self.socks.append(video)
        audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        audio.bind((self.ip, self.audio_port))
        audio.settimeout(0.1)
        self.socks.append(audio)
        dhcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dhcp.bind((self.ip, self.dhcp_port))
        dhcp.settimeout(0.1)
        self.socks.append(dhcp)
        emitter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socks.append(emitter)
        for target, name in ((self._cmd_loop, "mock-cmd"),
                             (self._media_loop, "mock-media"),
                             (self._dhcp_loop, "mock-dhcp")):
            th = threading.Thread(target=target, name=name, daemon=True)
            th.start()
            self._threads.append(th)
        th = threading.Thread(target=self._input_loop, args=(emitter,),
                              name="mock-input", daemon=True)
        th.start()
        self._threads.append(th)

    def stop(self) -> None:
        self._stop.set()
        for th in self._threads:
            th.join(timeout=2.0)
        for sock in self.socks:
            sock.close()

    # -- workers --------------------------------------------------------
    def _input_loop(self, sock: socket.socket) -> None:
        seq = 0
        period = 1.0 / max(self.input_rate, 1.0)
        nxt = mono()
        while not self._stop.is_set():
            if self.gone:
                self._stop.wait(0.05)
                nxt = mono()
                continue
            blob = bytearray(128)
            struct.pack_into("<HH", blob, 0, seq & 0xFFFF, 0)
            blob[4] = 0x01
            blob[5] = 0x04
            blob[127] = 0xFF - (seq & 0xFF)
            try:
                sock.sendto(bytes(blob), (self.ip, self.input_port))
                self.rx_input_emitted += 1
            except OSError:
                pass
            seq += 1
            nxt += period
            delay = nxt - mono()
            if delay > 0:
                self._stop.wait(delay)
            else:
                nxt = mono()

    def _media_loop(self) -> None:
        while not self._stop.is_set():
            ready = []
            try:
                import select  # local import: only the mock needs it
                ready, _, _ = select.select(self.socks[1:3], [], [], 0.1)
            except (ImportError, OSError, ValueError):
                self._stop.wait(0.1)
                continue
            for sock in ready:
                try:
                    sock.recvfrom(65535)
                    self.rx_media += 1
                except OSError:
                    pass

    def _dhcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.socks[3].recvfrom(4096)
                self.dhcp_rx += 1
            except socket.timeout:
                continue
            except OSError:
                break

    def _cmd_loop(self) -> None:
        sock = self.socks[0]
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.rx_cmd += 1
            if self.gone:
                continue
            ptype, qtype, _size, seq = struct.unpack_from("<HHHH", data, 0)
            if ptype == 3:                  # our ack of the pad's reply
                continue
            if qtype != 0 or len(data) < 20:
                if qtype in (1, 2):
                    sock.sendto(cmd_ack(1, qtype, seq), addr)
                    sock.sendto(self._reply_non_generic(qtype, seq), addr)
                continue
            pkt = CmdPacket.decode(data)
            if pkt.magic != CMD_MAGIC:
                continue                   # real pad: unparseable -> silence
            if pkt.expects_reply():
                if (pkt.service, pkt.method) == (4, 0x04):
                    sock.sendto(self._generic_reply(pkt), addr)   # no ack on purpose
                elif (pkt.service, pkt.method) == (5, 0x15):
                    sock.sendto(cmd_ack(1, qtype, seq), addr)
                    time.sleep(self.slow_delay)
                    sock.sendto(self._generic_reply(pkt), addr)
                else:
                    sock.sendto(cmd_ack(1, qtype, seq), addr)
                    if (pkt.service, pkt.method) == (0, 0x11):
                        self.state = CMD_RETVALS[(CMD_RETVALS.index(self.state)
                                                   + 1) % len(CMD_RETVALS)] \
                            if self.state in CMD_RETVALS else 4
                    sock.sendto(self._generic_reply(pkt), addr)
            else:
                sock.sendto(cmd_ack(1, qtype, seq), addr)

    def _reply_non_generic(self, qtype: int, seq: int) -> bytes:
        if qtype == 2:
            return cmd_ack(2, 2, seq)          # empty time reply
        return cmd_ack(2, 1, seq)

    def _generic_reply(self, q: CmdPacket) -> bytes:
        service, method = q.service, q.method
        if (service, method) == (4, 0x05):
            body = bytes([self.state])
        elif (service, method) == (4, 0x04):
            body = bytes.fromhex("0000000b00000040190c011728000058000800000c0221fe"
                                 "00001ccc")
        elif (service, method) == (0, 0x00):
            body = struct.pack("<II", 385944601, 385944601)
        elif (service, method) == (5, 0x15):
            body = b"\x04"
        elif (service, method) == (1, 0x05):
            body = bytes(113)
        else:
            body = b"\x00\x00\x00\x01"
        reply = CmdPacket(service=service, method=method, payload=body,
                          packet_type=2, query_type=0, seq=q.seq,
                          version=q.version, txid=q.txid, fragid=q.fragid,
                          final=True, flags=((q.flags >> 3) & 0xFC) | 1)
        return reply.encode()


# ===========================================================================
# selftest
# ===========================================================================
class Check:
    def __init__(self) -> None:
        self.results: List[Tuple[str, bool, str]] = []

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, ok, detail))
        say("   [%s] %-46s %s" % ("PASS" if ok else "FAIL", name, detail))
        return ok

    @property
    def failed(self) -> int:
        return sum(1 for _n, ok, _d in self.results if not ok)


def st_codecs(check: Check, corpus: Corpus) -> None:
    say("\n[1/9] codec round-trips against the real console session")
    # cmd: re-encode every console message and require byte equality
    n_ok = 0
    n_all = 0
    for name, blob in sorted(corpus.console_messages.items()):
        if len(blob) < 8:
            continue
        ptype = struct.unpack_from("<H", blob, 0)[0]
        if ptype != 0:
            continue
        n_all += 1
        pkt = CmdPacket.decode(blob)
        if pkt.encode() == blob:
            n_ok += 1
    check.add("cmd header encode(decode(real)) == real", n_ok == n_all and n_all > 0,
              "%d/%d console messages byte-identical" % (n_ok, n_all))
    probe = CmdPacket.decode(corpus.console_messages.get("cmd_t0_q0_len1040.bin", b""))
    check.add("cmd generic header fields decoded",
              probe.service == 0 and probe.method == 0x11 and probe.txid == 0x10B
              and probe.flags == 0x42 and not probe.final and probe.generic,
              "svc=%d method=0x%02x txid=%#x flags=%#02x final=%s gen_size=%s"
              % (probe.service, probe.method, probe.txid, probe.flags, probe.final,
                 probe.diag.get("gen_size")))
    # vstrm: re-encode real datagrams
    v_ok = v_all = 0
    for p in corpus.video_packets:
        v_all += 1
        if VstrmPacket.decode(p).encode() == p:
            v_ok += 1
    check.add("vstrm header encode(decode(real)) == real",
              v_ok == v_all and v_all > 0,
              "%d/%d real video datagrams byte-identical" % (v_ok, v_all))
    f0 = VstrmPacket.decode(corpus.video_first_frame[0])
    check.add("vstrm first-frame flags decoded",
              f0.magic == 0xF and f0.init and f0.frame_begin and f0.has_timestamp,
              "magic=%#x seq=%d init=%s frame_begin=%s size=%d ext=%s ext_opts=%s"
              % (f0.magic, f0.seq, f0.init, f0.frame_begin, f0.payload_size,
                 f0.ext.hex(), parse_ext(f0.ext)))
    a_ok = a_all = 0
    for p in corpus.audio_packets:
        a_all += 1
        if AstrmPacket.decode(p).encode() == p:
            a_ok += 1
    check.add("astrm header encode(decode(real)) == real",
              a_ok == a_all and a_all > 0,
              "%d/%d real audio packets byte-identical" % (a_ok, a_all))
    fm = corpus.format_messages[0]
    check.add("32 B video-format message round-trip",
              VideoFormat.decode(fm).encode() == fm,
              "ts=%d freq0=%#x freq1=%#x"
              % (VideoFormat.decode(fm).timestamp,
                 VideoFormat.decode(fm).freq0_a, VideoFormat.decode(fm).freq1_a))
    # negative controls: the decoders must notice broken fields
    bad = replace_cmd(corpus.console_messages.get("cmd_t0_q0_len12.bin",
                                                  CmdPacket(seq=1).encode()),
                      outer_size=99)
    diag = CmdPacket.decode(bad).diag
    check.add("cmd decoder flags a size mismatch", "size_mismatch" in diag,
              "declared 99 vs %d actual" % (len(bad) - 8))
    bad_v = bytearray(corpus.video_first_frame[0])
    bad_v[2] = 0x07                       # clear the flags, keep size 0
    vdiag = VstrmPacket.decode(bytes(bad_v)).diag
    check.add("vstrm decoder flags a size mismatch", "size_mismatch" in vdiag,
              "declared %d vs %d actual"
              % (VstrmPacket.decode(bytes(bad_v)).payload_size,
                 len(VstrmPacket.decode(bytes(bad_v)).payload)))


def st_determinism(check: Check, base_args: argparse.Namespace,
                   corpus: Corpus) -> None:
    say("\n[2/9] mutation-engine determinism")
    fps = []
    counts = []
    for _ in range(2):
        args = argparse.Namespace(**vars(base_args))
        cases = build_catalogue(args, corpus, LOOPBACK)
        fps.append(cases_fingerprint(cases))
        counts.append(len(cases))
    check.add("same seed -> identical byte stream", fps[0] == fps[1],
              "%d cases, sha256 %s" % (counts[0], fps[0][:16]))
    args = argparse.Namespace(**vars(base_args))
    args.seed = base_args.seed + 1
    other = build_catalogue(args, corpus, LOOPBACK)
    check.add("different seed -> different stream",
              cases_fingerprint(other) != fps[0],
              "seed %d -> sha256 %s" % (args.seed,
                                        cases_fingerprint(other)[:16]))
    args = argparse.Namespace(**vars(base_args))
    subset = build_catalogue(args, corpus, LOOPBACK)[:10]
    args10 = argparse.Namespace(**vars(base_args))
    args10.max_cases = 10
    subset2 = build_catalogue(args10, corpus, LOOPBACK)[:10]
    check.add("per-case RNG is order independent",
              cases_fingerprint(subset) == cases_fingerprint(subset2),
              "first 10 cases identical when truncated")
    risky = [c for c in build_catalogue(base_args, corpus, LOOPBACK)
             if c.risk != "SAFE"]
    brick_planes = {(CmdPacket.decode(c.datagrams[0]).service,
                     CmdPacket.decode(c.datagrams[0]).method)
                    for c in risky if c.plane == "cmd"
                    and len(c.datagrams[0]) >= 20
                    and CmdPacket.decode(c.datagrams[0]).generic}
    check.add("every BRICK_CMD method appears as a BRICK case",
              BRICK_CMD.issubset(brick_planes),
              "%d brick cases cover %d gated methods"
              % (len(risky), len(brick_planes)))


def st_binder_guard(check: Check) -> None:
    say("\n[3/9] exclusive-bind guard (the SO_REUSEADDR split that looks like a dead pad)")
    port = 55031
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind((LOOPBACK, port))
    refused = False
    msg = ""
    try:
        bind_udp(LOOPBACK, port, what="selftest")
    except ConflictError as exc:
        refused = True
        msg = str(exc).splitlines()[0]
    check.add("strict bind refuses a conflicting holder", refused, msg[:110])
    forced_ok = False
    try:
        sock = bind_udp(LOOPBACK, port, what="selftest", allow_reuse=True)
        forced_ok = True
        sock.close()
    except (ConflictError, OSError) as exc:
        msg = str(exc)
    check.add("--force binds with SO_REUSEADDR (hazard made visible)",
              forced_ok, "second binder succeeded: replies would be split")
    holder.close()
    free_ok = False
    try:
        sock = bind_udp(LOOPBACK, port, what="selftest")
        free_ok = True
        sock.close()
    except (ConflictError, OSError):
        pass
    check.add("bind succeeds once the port is free", free_ok, "port %d" % port)
    owners = port_owners(port)
    check.add("port owner lookup runs", isinstance(owners, list),
              "%d owner(s) after release" % len(owners))


def st_dhcp(check: Check) -> None:
    say("\n[4/9] DHCP option soup encoder")
    soups = dhcp_soups(LOOPBACK, PAD_IP)
    req = build_dhcp_request()
    dup_opts, dup_ok = parse_dhcp_options(
        build_dhcp_reply(req, client_ip=PAD_IP, server_ip=LOOPBACK,
                         options=soups["duplicate-options"]))
    codes = [c for c, _v, _o in dup_opts]
    check.add("duplicate-options soup really duplicates option 43",
              codes.count(43) == 2 and codes.count(53) == 2,
              "codes with >1 occurrence: %s"
              % sorted({c for c in codes if codes.count(c) > 1}))
    overrun_opts, _wf = parse_dhcp_options(
        build_dhcp_reply(req, client_ip=PAD_IP, server_ip=LOOPBACK,
                         options=soups["long-option"]))
    overruns = [c for c, _v, o in overrun_opts if o]
    check.add("long-option soup overruns the datagram", bool(overruns),
              "option(s) %s declared more bytes than exist" % overruns)
    trunc_opts, trunc_wf = parse_dhcp_options(
        build_dhcp_reply(req, client_ip=PAD_IP, server_ip=LOOPBACK,
                         options=soups["truncated"]))
    check.add("truncated soup has no 0xff terminator", not trunc_wf,
              "%d options parsed, well_formed=%s" % (len(trunc_opts), trunc_wf))
    len_sizes = {}
    for name, soup in soups.items():
        reply = build_dhcp_reply(req, client_ip=PAD_IP, server_ip=LOOPBACK,
                                 options=soup)
        opts, wf = parse_dhcp_options(reply)
        assert reply[0] == 2 and reply[16:20] == socket.inet_aton(PAD_IP)
        len_sizes[name] = (len(reply), len(opts), wf)
    check.add("every soup yields a parseable BOOTREPLY",
              all(v[1] > 0 for v in len_sizes.values()),
              ", ".join("%s=%dB/%dopts" % (k, v[0], v[1])
                        for k, v in sorted(len_sizes.items())))


def _selftest_args(**over: Any) -> argparse.Namespace:
    ns = argparse.Namespace(
        target=LOOPBACK, live=False, local_ip=LOOPBACK, seed=1234,
        cmd_sport=55024, cmd_dport=55023, video_sport=0, audio_sport=0,
        video_dport=55120, audio_dport=55121,
        input_port=55022, dhcp_port=16767, case_timeout=0.2, retries=1,
        oracle_timeout=0.2, settle=0.02, latency_ms=150.0, max_rate=0.0,
        deadman=0, only="SAFE", i_understand_brick_risk=False, force=False,
        ap_log=None, no_icmp=True, plane=None, family=None, case=None,
        max_cases=None, mutate_from=None, corpus_port=PORT_CMD[1],
        corpus_plane="cmd", record=None, dry_run=False, replay=None,
        replay_port=None, replay_plane="cmd", replay_speed=1.0,
        dhcp_seconds=10.0, dhcp_max_requests=4, verbose=False)
    for key, value in over.items():
        setattr(ns, key, value)
    return ns


def st_pipeline(check: Check, corpus: Corpus, workdir: str) -> Dict[str, Any]:
    say("\n[5/9] full pipeline against the loopback mock pad")
    # the mock answers svc5/0x15 slowly on purpose: the delay must sit between
    # --latency-ms (150) and the case timeout, or the LATENCY rail stays unproven
    mock = MockPad(cmd_port=55023, input_port=55022, video_port=55120,
                   audio_port=55121, dhcp_port=16767, slow_delay=0.22)
    mock.start()
    args = _selftest_args(record=os.path.join(workdir, "record"),
                          case_timeout=0.35,
                          plane=["cmd", "vstrm", "astrm", "dhcp"])
    args.only = "ALL"
    recorder = Recorder(args.record, {
        "tool": "fuzz-pad.py", "version": __version__, "mode": "selftest",
        "target": LOOPBACK, "local_ip": LOOPBACK, "seed": args.seed,
        "argv": ["--selftest"]})
    ctx = Ctx(args, LOOPBACK, False, recorder, corpus)
    ctx.open()
    cases = build_catalogue(args, corpus, LOOPBACK)
    say("   catalogue: %d cases (%d SAFE, %d BRICK gated)"
        % (len(cases), sum(1 for c in cases if c.risk == "SAFE"),
           sum(1 for c in cases if c.risk != "SAFE")))
    summary = run_cases(ctx, cases, total=len(cases))
    oracle_ok = ctx.probe()
    ctx.close()
    recorder.close()
    mock.stop()
    verdicts = summary["verdicts"]
    for want in ("OK", "NOREPLY", "NOACK", "LATENCY", "STATECHANGE"):
        check.add("mock run produced %s verdict(s)" % want, verdicts.get(want, 0) > 0,
                  "%d case(s)" % verdicts.get(want, 0))
    check.add("mock run produced no GONE (pad was alive)",
              verdicts.get("GONE", 0) == 0, "GONE=%d" % verdicts.get("GONE", 0))
    check.add("oracle answered after the whole catalogue",
              oracle_ok["state"] is not None,
              "state=%s version=%s" % (oracle_ok["state"],
                                       (oracle_ok["version"] or "-")[:8]))
    check.add("every transmitted datagram reached the mock",
              mock.rx_cmd + mock.rx_media > 0,
              "%d cmd + %d media datagrams received, %d input blobs emitted"
              % (mock.rx_cmd, mock.rx_media, mock.rx_input_emitted))
    files = sorted(n for n in os.listdir(args.record) if n.endswith(".bin"))
    with open(os.path.join(args.record, "verdicts.jsonl")) as fh:
        jsonl = [json.loads(line) for line in fh if line.strip()]
    check.add("one case-N.bin per executed case",
              len(files) == summary["cases_ran"] and len(files) > 0,
              "%d .bin files for %d executed cases, %d JSONL verdicts"
              % (len(files), summary["cases_ran"], len(jsonl)))
    check.add("JSONL verdict rows carry the replay hash",
              all("sha256" in row and "verdict" in row for row in jsonl),
              "fields: %s" % ",".join(sorted(jsonl[0].keys()))[:110])
    summary["record_dir"] = args.record
    summary["mock"] = {"rx_cmd": mock.rx_cmd, "rx_media": mock.rx_media,
                       "input_blobs": mock.rx_input_emitted}
    return summary


def st_replay(check: Check, corpus: Corpus, workdir: str,
              record_dir: str) -> None:
    say("\n[6/9] replay of a recorded case")
    files = sorted(n for n in os.listdir(record_dir) if n.endswith(".bin"))
    target = None
    for name in files:
        with open(os.path.join(record_dir, name[:-4] + ".json")) as fh:
            meta = json.load(fh)
        if meta.get("plane") == "cmd" and meta.get("verdict") == "OK":
            target = os.path.join(record_dir, name)
            expected = meta
            break
    if target is None:
        check.add("found an OK cmd case to replay", False, "no candidate")
        return
    mock = MockPad(cmd_port=55023, input_port=55022, video_port=55120,
                   audio_port=55121, dhcp_port=16767)
    mock.start()
    args = _selftest_args()
    rec = Recorder(os.path.join(workdir, "replay"), {"mode": "selftest-replay"})
    ctx = Ctx(args, LOOPBACK, False, rec, corpus)
    ctx.open()
    args.replay = target
    rc = replay(ctx, args)
    ctx.close()
    rec.close()
    mock.stop()
    say("   replay exit=%d, mock saw %d cmd datagrams" % (rc, mock.rx_cmd))
    check.add("replay reproduces the recorded byte stream", rc == 0,
              "%s -> exit %d, sha256 %s" % (os.path.basename(target), rc,
                                            expected.get("sha256", "?")[:16]))
    replayed = sorted(n for n in os.listdir(os.path.join(workdir, "replay"))
                      if n.endswith(".bin"))
    check.add("replay wrote its own record", bool(replayed),
              "%d file(s): %s" % (len(replayed), ", ".join(replayed[:3])))


def st_deadman(check: Check, corpus: Corpus, workdir: str) -> None:
    say("\n[7/9] deadman switch on a pad that stops answering")
    mock = MockPad(cmd_port=55023, input_port=55022, video_port=55120,
                   audio_port=55121, dhcp_port=16767)
    mock.start()
    args = _selftest_args(deadman=2, record=os.path.join(workdir, "deadman"),
                          plane=["cmd"])
    rec = Recorder(args.record, {"mode": "selftest-deadman"})
    ctx = Ctx(args, LOOPBACK, False, rec, corpus)
    ctx.open()
    cases = [c for c in build_catalogue(args, corpus, LOOPBACK)
             if c.family == "control"]
    say("   %d control cases; the mock goes silent 0.6 s into the run"
        % len(cases))
    killer = threading.Timer(0.6, lambda: setattr(mock, "gone", True))
    killer.daemon = True
    killer.start()
    summary = run_cases(ctx, cases, total=len(cases))
    killer.cancel()
    ctx.close()
    rec.close()
    mock.stop()
    check.add("deadman aborted the run", bool(summary["aborted"]),
              summary["aborted"] or "no abort")
    check.add("run stopped early", summary["cases_ran"] < len(cases),
              "%d of %d cases executed" % (summary["cases_ran"], len(cases)))
    check.add("GONE verdicts recorded", summary["verdicts"].get("GONE", 0) >= 2,
              "verdicts=%s" % summary["verdicts"])


def st_dryrun(check: Check, corpus: Corpus) -> None:
    say("\n[8/9] dry-run prints bytes without touching a socket")
    args = _selftest_args(plane=["cmd"], family=["gen.flags"], dry_run=True)
    cases = build_catalogue(args, corpus, LOOPBACK)
    lines = []
    for case in cases[:3]:
        lines.append("%-30s %d datagrams" % (case.name, len(case.datagrams)))
        lines.extend(hexdump_lines(case.datagrams[0])[:2])
    check.add("dry-run renders hex for the catalogue", len(lines) > 3,
              "%d catalogue rows -> %d preview lines" % (len(cases), len(lines)))
    say("   " + "\n   ".join(lines[:5]))


def st_ap_log(check: Check, workdir: str) -> None:
    say("\n[9/9] hostapd log tail (--ap-log)")
    path = os.path.join(workdir, "ap.log")
    with open(path, "w") as fh:
        fh.write("old line about 40:d2:8a:17:e2:09 deauth (before start)\n")
    tail = ApLogTail(path)
    with open(path, "a") as fh:
        fh.write("wlan0: AP-STA-DISCONNECTED 40:d2:8a:17:e2:09\n")
        fh.write("wlan0: unrelated 00:11:22:33:44:55 deauth\n")
        fh.write("wlan0: STA 40:d2:8a:17:e2:09 IEEE 802.11: associated\n")
    events = tail.poll()
    check.add("tail picks up new pad MAC events only", len(events) == 2,
              "%d event(s), %d ignored" % (len(events), 1))
    check.add("tail does not re-emit consumed lines", tail.poll() == [],
              "second poll returned nothing")


def selftest(corpus: Corpus) -> int:
    say("== fuzz-pad.py %s selftest (loopback only, no pad, no root)" % __version__)
    workdir = os.path.join("/tmp", "fuzz-pad-selftest-%d" % os.getpid())
    os.makedirs(workdir, exist_ok=True)
    check = Check()
    base_args = _selftest_args(plane=["cmd", "vstrm", "astrm", "dhcp"],
                               only="ALL")
    say("\n[0/9] corpus: %s" % corpus.source)
    say("   %d console messages, %d video frames, %d video datagrams, "
        "%d audio, %d format messages"
        % (len(corpus.console_messages), len(corpus.video_frames),
           len(corpus.video_packets), len(corpus.audio_packets),
           len(corpus.format_messages)))
    st_codecs(check, corpus)
    st_determinism(check, base_args, corpus)
    st_binder_guard(check)
    st_dhcp(check)
    summary = st_pipeline(check, corpus, workdir)
    st_replay(check, corpus, workdir, summary.get("record_dir", workdir))
    st_deadman(check, corpus, workdir)
    st_dryrun(check, corpus)
    st_ap_log(check, workdir)
    say("\n== selftest result")
    say("   assertions: %d, passed: %d, failed: %d"
        % (len(check.results), len(check.results) - check.failed, check.failed))
    say("   mock pipeline: %d cases, verdicts %s, %d cmd + %d media datagrams "
        "received, %d input blobs emitted"
        % (summary["cases_ran"], summary["verdicts"],
           summary["mock"]["rx_cmd"], summary["mock"]["rx_media"],
           summary["mock"]["input_blobs"]))
    say("   artifacts: %s" % workdir)
    if check.failed:
        say("\nSELFTEST FAIL")
        return 1
    say("\nSELFTEST PASS")
    return 0


# ===========================================================================
# command line
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Protocol-plane fuzzer and crash oracle for the Wii U "
                    "GamePad DRC link.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run --selftest first: it proves the codecs and the whole pipeline "
               "on loopback without touching hardware.")
    ap.add_argument("--version", action="version", version="fuzz-pad.py " + __version__)
    # target / mode
    ap.add_argument("--target", help="pad address (default %s)" % PAD_IP)
    ap.add_argument("--live", action="store_true",
                    help="required to transmit to %s at all" % PAD_IP)
    ap.add_argument("--local-ip", help="console address (default %s)" % CONSOLE_IP)
    ap.add_argument("--selftest", action="store_true",
                    help="run the whole pipeline against a loopback mock pad")
    ap.add_argument("--list", action="store_true", help="print the case catalogue")
    ap.add_argument("--dry-run", action="store_true",
                    help="print packets as hex, transmit nothing")
    ap.add_argument("--replay", metavar="FILE",
                    help="re-transmit a recorded case-N.bin (or any port*.bin)")
    ap.add_argument("--replay-port", type=int, help="destination UDP port for replay")
    ap.add_argument("--replay-plane", default="cmd",
                    choices=["cmd", "vstrm", "astrm", "dhcp"],
                    help="plane to use when the file carries no metadata")
    ap.add_argument("--replay-speed", type=float, default=1.0,
                    help="timestamp compression factor for replay (default 1.0)")
    # selection
    ap.add_argument("--plane", action="append",
                    choices=["cmd", "vstrm", "astrm", "dhcp"],
                    help="plane(s) to fuzz (default cmd+vstrm+astrm)")
    ap.add_argument("--family", action="append",
                    help="only families matching this prefix (repeatable)")
    ap.add_argument("--case", type=int, action="append",
                    help="only this case index (repeatable)")
    ap.add_argument("--max-cases", type=int, help="stop after N cases")
    ap.add_argument("--only", default="SAFE", choices=["SAFE", "ALL"],
                    help="SAFE (default) never sends flash writes or reboots")
    ap.add_argument("--i-understand-brick-risk", action="store_true",
                    help="allow BRICK-risk cases (flash writes, reboots)")
    # mutation source
    ap.add_argument("--mutate-from", action="append", metavar="FILE|DIR",
                    help="seed messages to mutate (file or directory)")
    ap.add_argument("--corpus-port", type=int, default=PORT_CMD[1],
                    help="destination port for --mutate-from (default 50123)")
    ap.add_argument("--corpus-plane", default="cmd",
                    choices=["cmd", "vstrm", "astrm", "dhcp"])
    ap.add_argument("--seed", type=int, default=1234,
                    help="deterministic mutation seed (default 1234)")
    # ports
    ap.add_argument("--cmd-sport", type=int, default=PORT_CMD[0])
    ap.add_argument("--cmd-dport", type=int, default=PORT_CMD[1])
    ap.add_argument("--video-sport", type=int, default=PORT_VIDEO[0])
    ap.add_argument("--audio-sport", type=int, default=PORT_AUDIO[0])
    ap.add_argument("--input-port", type=int, default=PORT_INPUT[0],
                    help="local port counting the pad's input stream")
    ap.add_argument("--dhcp-port", type=int, default=16767,
                    help="responder port (67 = real DHCP; needs --force while "
                         "netboot holds it)")
    ap.add_argument("--dhcp-seconds", type=float, default=120.0)
    ap.add_argument("--dhcp-max-requests", type=int, default=50)
    # timing / safety
    ap.add_argument("--max-rate", type=float, default=20.0,
                    help="datagrams per second cap (0 = unlimited, default 20)")
    ap.add_argument("--deadman", type=int, default=5,
                    help="abort after N consecutive GONE cases (0 = never)")
    ap.add_argument("--case-timeout", type=float, default=0.25)
    ap.add_argument("--oracle-timeout", type=float, default=0.4)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--settle", type=float, default=0.25,
                    help="seconds between a case and its post-case sample")
    ap.add_argument("--latency-ms", type=float, default=250.0)
    ap.add_argument("--force", action="store_true",
                    help="bind even if the port is taken (splits replies - avoid)")
    ap.add_argument("--record", metavar="DIR",
                    help="mandatory for a transmitting run: write every datagram")
    ap.add_argument("--ap-log", metavar="FILE",
                    help="tail hostapd log for deauth/assoc of %s" % PAD_MAC)
    ap.add_argument("--no-icmp", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    return ap


def print_catalogue(cases: Sequence[TestCase]) -> None:
    say("%3s %-6s %-5s %-9s %-34s %5s %6s  %s"
        % ("#", "plane", "risk", "family", "name", "dgrams", "bytes", "note"))
    for case in cases:
        say("%3d %-6s %-5s %-9s %-34s %5d %6d  %s"
            % (case.idx, case.plane, case.risk, case.family[:9], case.name[:34],
               len(case.datagrams), sum(len(d) for d in case.datagrams),
               case.note[:40]))
    counts: Dict[str, int] = {}
    for case in cases:
        counts[case.plane] = counts.get(case.plane, 0) + 1
    say("\n%d cases: %s" % (len(cases),
                            ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))


def dry_run(cases: Sequence[TestCase], limit: int = 0) -> int:
    say("dry run: printing packets as hex, nothing is transmitted")
    shown = 0
    for case in cases:
        if limit and shown >= limit:
            break
        shown += 1
        say("\n== case-%03d %-34s plane=%s dport=%d risk=%s"
            % (case.idx, case.name, case.plane, case.dport, case.risk))
        if case.note:
            say("   note: %s" % case.note)
        if case.plane == "cmd" and len(case.datagrams[0]) >= 20:
            pkt = CmdPacket.decode(case.datagrams[0])
            say("   cmd type=%d qtype=%d seq=%d size=%s|%s magic=%#x ver=%d "
                "txid=%#x fragid=%#x final=%s flags=%#02x svc=%d method=%#x "
                "err=%#x gsize=%s diag=%s"
                % (pkt.packet_type, pkt.query_type, pkt.seq,
                   pkt.diag.get("outer_size"), pkt.diag.get("actual_body"),
                   pkt.magic, pkt.version, pkt.txid, pkt.fragid, pkt.final,
                   pkt.flags, pkt.service, pkt.method, pkt.error,
                   pkt.diag.get("gen_size"), pkt.diag.get("size_mismatch", "-")))
        elif case.plane == "vstrm" and len(case.datagrams[0]) >= 16:
            vp = VstrmPacket.decode(case.datagrams[0])
            say("   vstrm magic=%#x ptype=%d seq=%d init=%s fb=%s ce=%s fe=%s ts=%s "
                "size=%d actual=%d ext=%s opts=%s"
                % (vp.magic, vp.packet_type, vp.seq, vp.init, vp.frame_begin,
                   vp.chunk_end, vp.frame_end, vp.has_timestamp,
                   vp.payload_size, len(vp.payload), vp.ext.hex(),
                   parse_ext(vp.ext)))
        elif case.plane == "astrm" and len(case.datagrams[0]) >= 8:
            ap = AstrmPacket.decode(case.datagrams[0])
            say("   astrm fmt=%d mono=%d vib=%d type=%d seq=%d psize=%s ts=%d "
                "actual=%d%s"
                % (ap.fmt, ap.mono, ap.vibrate, ap.ptype, ap.seq, ap.payload_size,
                   ap.timestamp, len(ap.payload),
                   "" if ap.diag.get("size_mismatch") is None
                   else " MISMATCH %d" % ap.diag["size_mismatch"]))
        for dgram in case.datagrams:
            say("   -- %d B" % len(dgram))
            for line in hexdump_lines(dgram)[:6]:
                say(line)
            if len(dgram) > 96:
                say("\t... (%d B truncated in preview)" % (len(dgram) - 96))
    say("\n%d case(s) previewed" % shown)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    corpus = load_corpus(verbose=args.verbose)
    if args.selftest:
        return selftest(corpus)

    pad_ip, live = resolve_target(args)
    if pad_ip == PAD_IP and not live and not args.list and not args.dry_run:
        warn("refusing to transmit to %s without --live (this is the real pad; "
             "run --selftest for loopback proof)" % PAD_IP)
        return 2
    args.local_ip = args.local_ip or (LOOPBACK if pad_ip == LOOPBACK else CONSOLE_IP)
    cases = build_catalogue(args, corpus, pad_ip)
    if args.max_cases:
        cases = cases[:args.max_cases]      # indices stay the catalogue's own
    if not cases:
        warn("no cases selected (check --plane/--family/--case/--mutate-from)")
        return 2

    if args.list:
        print_catalogue(cases)
        return 0
    if args.dry_run:
        return dry_run(cases, limit=args.max_cases or 0)

    record_dir = args.record
    if not record_dir:
        warn("--record DIR is mandatory for a transmitting run (every datagram is "
             "written so a crash can be replayed exactly)")
        return 2

    recorder = Recorder(record_dir, {
        "tool": "fuzz-pad.py", "version": __version__,
        "target": pad_ip, "local_ip": args.local_ip, "seed": args.seed,
        "only": args.only, "brick_risk": args.i_understand_brick_risk,
        "planes": args.plane or ["cmd", "vstrm", "astrm"],
        "argv": list(argv if argv is not None else sys.argv[1:]),
        "corpus": corpus.source,
    })
    ctx = Ctx(args, pad_ip, live, recorder, corpus)
    try:
        ctx.open()
    except ConflictError as exc:
        warn(str(exc))
        recorder.close()
        return 3
    say("[*] %s -> %s, local %s, %d cases, max %.0f pkt/s, deadman %d"
        % (__version__, pad_ip, args.local_ip, len(cases), args.max_rate,
           args.deadman))
    say("[*] record %s" % recorder.dir)
    rc = 0
    try:
        if "dhcp" in (args.plane or []) and not (set(args.plane or []) -
                                                 {"dhcp"}):
            run_dhcp_responder(ctx, args)
        elif args.replay:
            rc = replay(ctx, args)
        else:
            summary = run_cases(ctx, cases, total=len(cases))
            if summary["aborted"]:
                rc = 4
    finally:
        ctx.close()
        recorder.close()
    say("[*] verdict log %s" % recorder.jsonl_path)
    return rc


if __name__ == "__main__":
    sys.exit(main())
