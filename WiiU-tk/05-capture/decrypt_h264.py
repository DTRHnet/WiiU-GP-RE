#!/usr/bin/env python3
"""
Decrypt the captured Wii-U console <-> GamePad (DRC) session ourselves.

Why: tshark in this build hides the EAPOL-Key nonce fields, airdecap-ng refuses
the hidden-SSID handshake, and we need ground truth for the console's H.264
SPS/PPS (libdrc sends b_repeat_headers=0, so our own stream carries none).

We have:  PMK  (= the raw 64-hex PSK, no PBKDF2 in Nintendo's KDF chain)
          ANonce (console, EAPOL msg1)  SNonce (pad, EAPOL msg2)
          AA = console MAC (authenticator), SPA = pad MAC (supplicant)

PTK = PRF-512(PMK, "Pairwise key expansion",
              min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
TK  = PTK[32:48]

Decryption is validated by structure: a correct AAD variant yields a plaintext
starting with the LLC/SNAP header aa:aa:03:00:00:00. We search the small space
of AAD masking conventions rather than trusting one memory of the spec.
"""
import struct, sys, hmac, hashlib, collections

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

PSK_HEX   = "<redacted-psk>"
CONSOLE   = bytes.fromhex("ccfb65b68169")   # authenticator (AP)
PAD       = bytes.fromhex("40d28a17e209")   # supplicant

SNAP = b"\xaa\xaa\x03\x00\x00\x00"


# ---------------------------------------------------------------- pcap reader
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
        if endian is None:
            raise SystemExit("not a pcap: magic=%r" % magic)
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            _, _, caplen, origlen = struct.unpack(endian + "IIII", hdr)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            yield origlen, data
    # linktype is reported through the exception-free path above


def iter_frames(path):
    """Yield (origlen, 802.11 bytes) with the radiotap header removed."""
    for origlen, data in read_pcap(path):
        if len(data) < 4:
            continue
        rt_len = struct.unpack("<H", data[2:4])[0]
        yield origlen, data[rt_len:]


# ---------------------------------------------------------------- 802.11 parse
def dot11_fields(fr):
    """Return dict of header info, or None if not a data frame."""
    if len(fr) < 24:
        return None
    fc0, fc1 = fr[0], fr[1]
    ftype = (fc0 >> 2) & 0x3
    subtype = (fc0 >> 4) & 0xF
    if ftype != 2:                       # management(0) / control(1) / data(2)
        return None
    tods = bool(fc1 & 0x01)
    fromds = bool(fc1 & 0x02)
    protected = bool(fc1 & 0x40)
    a1 = fr[4:10]
    a2 = fr[10:16]
    a3 = fr[16:22]
    sc = fr[22:24]
    off = 24
    a4 = None
    if tods and fromds:
        a4 = fr[24:30]
        off = 30
    qos = bool(subtype & 0x8)
    qc = None
    if qos:
        qc = fr[off:off + 2]
        off += 2
    hdr_len = off
    return dict(fc0=fc0, fc1=fc1, subtype=subtype, tods=tods, fromds=fromds,
                protected=protected, a1=a1, a2=a2, a3=a3, sc=sc, a4=a4,
                qc=qc, hdr_len=hdr_len)


# ---------------------------------------------------------------- key schedule
def prf(key, data, nbytes):
    out = b""
    i = 0
    while len(out) < nbytes:
        out += hmac.new(key, b"Pairwise key expansion\x00" + data + bytes([i]),
                        hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def derive_ptk(pmk, aa, spa, anonce, snonce, ptk_len=48, rotate=True):
    """802.11i PRF-48, then Nintendo's CONFIG_TENDONIN rotation:
       rotate_data = ptk[0:3]; ptk = ptk[3:] || rotate_data   (see wpa_common.c)"""
    data = b"".join([min(aa, spa), max(aa, spa),
                     min(anonce, snonce), max(anonce, snonce)])
    ptk = prf(pmk, data, ptk_len)
    if rotate:
        ptk = ptk[3:] + ptk[:3]
    return ptk


def eapol_nonces(path):
    eapol_nonces.last_msg2 = None
    """msg1 nonce from console (ACK, no MIC), msg2 nonce from pad (MIC, no ACK)."""
    console_nonce = pad_nonce = None
    for origlen, fr in iter_frames(path):
        d = dot11_fields(fr)
        if d is None or d["protected"]:
            continue
        body = fr[d["hdr_len"]:]
        if len(body) < 8 + 95:
            continue
        # LLC/SNAP: aa aa 03 00 00 00 | ethertype
        if body[:6] != SNAP or body[6:8] != b"\x88\x8e":
            continue
        eap = body[8:]
        if len(eap) < 5 + 95 or eap[1] != 3:          # 3 = EAPOL-Key
            continue
        # the 802.11 frame carries a trailing 4-byte FCS; the EAPOL length
        # field tells us exactly where the EAPOL body ends.
        eap_len = 4 + struct.unpack(">H", eap[2:4])[0]
        if len(eap) < eap_len:
            continue
        eap = eap[:eap_len]
        keyinfo = struct.unpack(">H", eap[5:7])[0]
        ack = bool(keyinfo & 0x0080)
        mic = bool(keyinfo & 0x0100)
        nonce = eap[17:49]
        sa = d["a2"]
        if ack and not mic and sa == CONSOLE and console_nonce is None:
            console_nonce = nonce
        if mic and not ack and sa == PAD and pad_nonce is None:
            pad_nonce = nonce
            eapol_nonces.last_msg2 = bytes(eap)
        if console_nonce and pad_nonce:
            return console_nonce, pad_nonce
    return console_nonce, pad_nonce


# ---------------------------------------------------------------- CCMP
FC1_MASK_VARIANTS = [
    ("raw", 0x00),
    ("no-retry", 0x08),
    ("no-pwr", 0x10),
    ("no-moredata", 0x20),
    ("no-prot", 0x40),
    ("no-order", 0x80),
    ("spec-like", 0x08 | 0x10 | 0x20 | 0x40 | 0x80),
    ("flags-zero", 0xFF),
]


def build_aad(d, mask, zero_frag):
    hdr = bytearray()
    hdr += bytes([d["fc0"], d["fc1"] & ~mask & 0xFF])
    hdr += d["a1"] + d["a2"] + d["a3"]
    sc = bytearray(d["sc"])
    if zero_frag:
        sc[0] &= 0xF0            # fragment number is the low nibble of octet 0
    hdr += sc
    if d["a4"]:
        hdr += d["a4"]
    if d["qc"]:
        hdr += d["qc"]
    return bytes(hdr)


def ccmp_decrypt(fr, d, tk, mask, zero_frag, fcs):
    body = fr[:-fcs] if fcs else fr
    if len(body) < d["hdr_len"] + 8 + 8:
        return None
    ch = body[d["hdr_len"]:d["hdr_len"] + 8]
    pn = bytes([ch[7], ch[6], ch[5], ch[4], ch[1], ch[0]])
    nonce = b"\x00" + d["a2"] + pn
    aad = build_aad(d, mask, zero_frag)
    ct = body[d["hdr_len"] + 8:-8]
    tag = body[-8:]
    try:
        return AESCCM(tk, tag_length=8).decrypt(nonce, ct + tag, aad)
    except Exception:
        return None


def find_variant(path, tk, limit=3000):
    """Score (fcs, mask, zero_frag) by how many protected frames decrypt with a
    valid CCMP tag. A wrong AAD fails the tag check outright, so a non-zero
    success rate identifies the convention; the winner should be ~100%."""
    frames = []
    for origlen, fr in iter_frames(path):
        d = dot11_fields(fr)
        if d is None or not d["protected"]:
            continue
        frames.append((fr, d))
        if len(frames) >= limit:
            break
    if not frames:
        return None
    print("[*] %d protected frames available for the probe" % len(frames))
    best = None
    for fcs in (4, 0):
        for name, mask in FC1_MASK_VARIANTS:
            for zf in (False, True):
                ok = 0
                for fr, d in frames:
                    if ccmp_decrypt(fr, d, tk, mask, zf, fcs) is not None:
                        ok += 1
                if ok:
                    print("    fcs=%d mask=%-11s zero_frag=%-5s -> %d/%d"
                          % (fcs, name, zf, ok, len(frames)))
                if best is None or ok > best[0]:
                    best = (ok, fcs, mask, zf, name)
    if not best or best[0] == 0:
        return None
    print("[+] best AAD: fcs=%d mask=%s zero_frag=%s (%d frames)"
          % (best[1], best[4], best[3], best[0]))
    return best[1], best[2], best[3]


# ---------------------------------------------------------------- main
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "real-session.pcap"
    out_payload = sys.argv[2] if len(sys.argv) > 2 else "video-payload.bin"

    print("[*] scanning for EAPOL handshake ...")
    anonce, snonce = eapol_nonces(path)
    if not anonce or not snonce:
        raise SystemExit("[-] could not find both nonces (anonce=%s snonce=%s)"
                         % (bool(anonce), bool(snonce)))
    print("[+] ANonce (console): %s" % anonce.hex())
    print("[+] SNonce (pad)    : %s" % snonce.hex())

    pmk = bytes.fromhex(PSK_HEX)
    ptk = derive_ptk(pmk, CONSOLE, PAD, anonce, snonce)
    kck, kek, tk = ptk[0:16], ptk[16:32], ptk[32:48]
    print("[+] PTK  : %s" % ptk.hex())
    print("[+] KCK  : %s" % kck.hex())
    print("[+] KEK  : %s" % kek.hex())
    print("[+] TK   : %s" % tk.hex())

    # ---- hard verification: does our rotated KCK reproduce EAPOL msg2's MIC?
    import hmac as _hmac
    msg2 = eapol_nonces.last_msg2
    if msg2:
        body = bytearray(msg2)
        mic_on_wire = bytes(body[81:97])
        body[81:97] = b"\x00" * 16
        calc = _hmac.new(kck, bytes(body), hashlib.sha1).digest()[:16]
        print("[%s] KCK MIC check on EAPOL msg2: wire=%s calc=%s"
              % ("+" if calc == mic_on_wire else "!",
                 mic_on_wire.hex()[:32], calc.hex()[:32]))

    print("[*] probing AAD conventions ...")
    got = find_variant(path, tk)
    if not got:
        raise SystemExit("[-] no AAD variant validated - PTK is probably wrong")
    fcs, mask, zf = got

    # ---- full pass: decrypt, reassemble IP, collect UDP
    frags = collections.defaultdict(dict)     # ip_id -> {offset: payload}
    frag_meta = {}
    udp = []                                   # (srcip, dstip, sport, dport, payload)
    stats = collections.Counter()

    for origlen, fr in iter_frames(path):
        d = dot11_fields(fr)
        if d is None:
            continue
        if d["protected"]:
            pt = ccmp_decrypt(fr, d, tk, mask, zf, fcs)
            if pt is None:
                stats["fail"] += 1
                continue
            stats["ok"] += 1
            if pt[:6] != SNAP:
                stats["non_snap"] += 1
                continue
            ethertype = pt[6:8]
            ip = pt[8:]
        else:
            body = fr[:-fcs] if fcs else fr
            body = body[d["hdr_len"]:]
            if len(body) < 8 or body[6:8] != b"\xaa\xaa" or body[8:10] != b"\x03\x00":
                continue
            ethertype = body[10:12]
            ip = body[12:]
        if ethertype != b"\x08\x00" or len(ip) < 20:
            stats["non_ip"] += 1
            continue
        if ip[0] >> 4 != 4:
            stats["non_ip4"] += 1
            continue
        ihl = (ip[0] & 0xF) * 4
        tot = struct.unpack(">H", ip[2:4])[0]
        ident = struct.unpack(">H", ip[4:6])[0]
        flags_frag = struct.unpack(">H", ip[6:8])[0]
        mf = flags_frag & 0x2000
        foff = (flags_frag & 0x1FFF) * 8
        proto = ip[9]
        frag_meta[ident] = proto
        frags[ident][foff] = ip[ihl:tot]
        if mf:
            continue
        # complete datagram?
        parts = frags.pop(ident, None)
        if parts is None:
            continue
        buf = b""
        ok = True
        for off in sorted(parts):
            if off != len(buf):
                ok = False
                break
            buf += parts[off]
        if not ok:
            stats["frag_gap"] += 1
            continue
        stats["datagrams"] += 1
        if proto == 17 and len(buf) >= 8:
            sport, dport, ulen = struct.unpack(">HHH", buf[0:6])
            udp.append((sport, dport, buf[8:ulen if 8 <= ulen <= len(buf) else len(buf)]))
            stats["udp_%d" % dport] += 1

    print("[*] stats: %s" % dict(stats))
    if not udp:
        raise SystemExit("[-] no UDP recovered")

    with open(out_payload, "wb") as f:
        for sport, dport, pl in udp:
            f.write(struct.pack(">HHH", sport, dport, len(pl)))
            f.write(pl)
    print("[+] wrote %d UDP payloads to %s" % (len(udp), out_payload))

    # ---- inspect the video port for H.264 parameter sets
    for want in (50120, 50121, 50122, 50123, 50010, 50022, 50023):
        sel = [p for s, dp, p in udp if dp == want or s == want]
        if not sel:
            continue
        print("\n=== port %d: %d payloads, sizes %s ===" %
              (want, len(sel), sorted({len(p) for p in sel})[:8]))
        sps, pps = None, None
        for p in sel:
            for i in range(len(p) - 3):
                if p[i] == 0 and p[i + 1] == 0 and p[i + 2] == 1:
                    t = p[i + 3] & 0x1F
                    if t == 7 and sps is None:
                        sps = p[i:]
                    if t == 8 and pps is None:
                        pps = p[i:]
        if sps:
            print("  [!] SPS found: %s" % sps[:64].hex())
        if pps:
            print("  [!] PPS found: %s" % pps[:32].hex())
        print("  first payload: %s" % sel[0][:48].hex())


if __name__ == "__main__":
    main()
