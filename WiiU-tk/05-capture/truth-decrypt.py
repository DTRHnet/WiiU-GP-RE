#!/usr/bin/env python3
"""
Ground-truth decryptor for a monitor capture of a real Wii U console <-> GamePad
DRC session.

Built after round 11n claimed the console's media was "group-key encrypted and
therefore invisible".  Every protected frame in capture/console-truth.pcap uses
CCMP key id 0 (pairwise), so media must be decryptable with the PTK.  This tool
establishes that empirically instead of assuming it:

  * finds every EAPOL-Key message (msg1..msg4), so multiple handshakes in one
    capture are visible instead of silently mixed;
  * derives the PTK under both conventions -- stock 802.11i and Nintendo's
    CONFIG_TENDONIN 3-byte left rotation -- and *proves* which one is right by
    reproducing msg2's MIC with the KCK;
  * pulls the GTK out of msg3's key data (KDE 0xdd 0x14) using the KEK, so a
    group-key run can be decrypted too if one ever shows up;
  * decrypts every protected frame, choosing the AAD convention by scoring, and
    reports success broken down by direction / TID / time bucket so a partial
    key epoch (e.g. a re-handshake mid-capture) cannot hide as "media missing";
  * reassembles IPv4 and writes per-port UDP payloads, plus a summary table.

Usage:
  python3 truth-decrypt.py capture/console-truth.pcap [--outdir out/evidence/truth]

Read-only with respect to the capture; writes only under --outdir.
"""
import argparse
import collections
import hashlib
import hmac
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

SNAP = b"\xaa\xaa\x03\x00\x00\x00"


# ------------------------------------------------------------------ pcap I/O
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise SystemExit("short pcap header")
        magic = gh[:4]
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
        if endian is None:
            raise SystemExit("not a classic pcap: magic=%r" % magic)
        ts_scale = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        if linktype not in (105, 127):
            raise SystemExit("expected 802.11/radiotap linktype, got %d" % linktype)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            sec, frac, caplen, origlen = struct.unpack(endian + "IIII", hdr)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            if linktype == 127:
                if len(data) < 4:
                    continue
                rt = struct.unpack("<H", data[2:4])[0]
                yield sec + frac / ts_scale, origlen, data[rt:]
            else:
                yield sec + frac / ts_scale, origlen, data


# ------------------------------------------------------------ 802.11 parsing
def parse_dot11(fr):
    if len(fr) < 24:
        return None
    fc0, fc1 = fr[0], fr[1]
    if (fc0 >> 2) & 3 != 2:                      # data frames only
        return None
    subtype = (fc0 >> 4) & 0xF
    tods, fromds = fc1 & 1, fc1 & 2
    prot = bool(fc1 & 0x40)
    a1, a2, a3 = fr[4:10], fr[10:16], fr[16:22]
    sc = fr[22:24]
    off = 24
    a4 = None
    if tods and fromds:
        a4 = fr[24:30]
        off = 30
    qos = bool(subtype & 0x8)
    qc = None
    tid = None
    if qos:
        qc = fr[off:off + 2]
        tid = qc[0] & 0x0F
        off += 2
    if subtype & 0x8 and (subtype & 0x7) == 0x4:  # Order bit / HT control
        if fc1 & 0x80:
            off += 4
    return dict(fc0=fc0, fc1=fc1, subtype=subtype, tods=bool(tods),
                fromds=bool(fromds), prot=prot, a1=a1, a2=a2, a3=a3, sc=sc,
                a4=a4, qc=qc, tid=tid, hdr=off)


# ------------------------------------------------------------------ key math
def prf(key, data, nbytes):
    out = b""
    i = 0
    while len(out) < nbytes:
        out += hmac.new(key, b"Pairwise key expansion\x00" + data + bytes([i]),
                        hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def derive_ptk(pmk, aa, spa, anonce, snonce, rotate):
    data = b"".join([min(aa, spa), max(aa, spa),
                     min(anonce, snonce), max(anonce, snonce)])
    ptk = prf(pmk, data, 48)
    if rotate:
        ptk = ptk[3:] + ptk[:3]
    return ptk


def eapol_mic(eapol_key, kck):
    body = bytearray(eapol_key)
    mic = bytes(body[81:97])
    body[81:97] = b"\x00" * 16
    return mic, hmac.new(kck, bytes(body), hashlib.sha1).digest()[:16]


def aead_decrypt(kek, keydata, nonce_hint=None):
    """AES-Key-Wrap-Unwrap with the 802.11 default IV / RFC 3394 style used by
    hostapd-wpad (also used for msg3 key data)."""
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
    try:
        return aes_key_unwrap(kek, keydata)
    except InvalidUnwrap:
        return None


# ------------------------------------------------------------------ find keys
def find_eapol(frames):
    """frames: iterable of (ts, origlen, dot11) -> list of handshake dicts."""
    msgs = []
    for ts, origlen, fr in frames:
        d = parse_dot11(fr)
        if d is None or d["prot"]:
            continue
        body = fr[d["hdr"]:]
        if body[:6] != SNAP or body[6:8] != b"\x88\x8e":
            continue
        eap = body[8:]
        if len(eap) < 99 or eap[1] != 3:
            continue
        eap_len = 4 + struct.unpack(">H", eap[2:4])[0]
        if len(eap) < eap_len:
            continue
        eap = eap[:eap_len]
        keyinfo = struct.unpack(">H", eap[5:7])[0]
        kd_len = struct.unpack(">H", eap[97:99])[0]
        msgs.append(dict(
            ts=ts, ta=d["a2"], ra=d["a1"],
            ack=bool(keyinfo & 0x0080), mic=bool(keyinfo & 0x0100),
            install=bool(keyinfo & 0x0040), secure=bool(keyinfo & 0x0200),
            akm=keyinfo & 0x0007, keyver=(keyinfo >> 3) & 7,
            nonce=eap[17:49], mic_bytes=eap[81:97], eapol=bytes(eap),
            keydata=eap[99:99 + kd_len]))
    return msgs


def handshakes(msgs):
    """Group consecutive msg1..msg4 into sessions with their own PTK."""
    sessions = []
    cur = {}
    for m in msgs:
        n = len(cur)
        if m["ack"] and not m["mic"]:
            cur = {"msg1": m}
        elif m["mic"] and not m["ack"] and not m["secure"]:
            if "msg1" in cur:
                cur["msg2"] = m
        elif m["mic"] and m["ack"]:
            if cur:
                cur.setdefault("msg3", m)
        elif m["mic"] and not m["ack"] and m["secure"]:
            if cur:
                cur.setdefault("msg4", m)
                sessions.append(cur)
                cur = {}
    if cur:
        sessions.append(cur)
    return sessions


# ------------------------------------------------------------------ CCMP
AAD_MASKS = [("raw", 0x00), ("spec", 0xF8), ("no-retry", 0x08),
             ("no-pwr", 0x10), ("no-more", 0x20), ("no-prot", 0x40),
             ("flags-zero", 0xFF)]


def build_aad(d, mask, zero_frag, qos_in_aad=True, sc_mode="raw"):
    hdr = bytes([d["fc0"], d["fc1"] & ~mask & 0xFF])
    hdr += d["a1"] + d["a2"] + d["a3"]
    sc = bytearray(d["sc"])
    if zero_frag:
        sc[0] &= 0xF0
    if sc_mode == "zero":
        # Nintendo's implementation does not feed the Sequence Control field into
        # the CCMP AAD (measured: frames only verify when it is zeroed).
        sc = bytearray(2)
    hdr += bytes(sc)
    if d["a4"]:
        hdr += d["a4"]
    if d["qc"] is not None and qos_in_aad:
        hdr += d["qc"]
    return hdr


def ccmp_decrypt(fr, d, tk, mask, zero_frag, fcs, qos_in_aad=True,
                 nonce_order="std", sc_mode="raw", prio_mode="zero"):
    body = fr[:-fcs] if fcs else fr
    if len(body) < d["hdr"] + 16:
        return None
    ch = body[d["hdr"]:d["hdr"] + 8]
    if nonce_order == "std":
        pn = bytes([ch[7], ch[6], ch[5], ch[4], ch[1], ch[0]])
    else:                                   # drc-wireshark rotation variant
        pn = bytes([ch[7], ch[6], ch[5], ch[4], ch[0], ch[1]])
    # 802.11 CCMP "Priority" octet: the TID for QoS data frames.  Using zero here
    # decrypts only TID 0 traffic, which is exactly the trap this capture set.
    prio = (d["tid"] or 0) & 0xF if prio_mode == "tid" else 0
    nonce = bytes([prio]) + d["a2"] + pn
    aad = build_aad(d, mask, zero_frag, qos_in_aad, sc_mode)
    ct = body[d["hdr"] + 8:-8]
    tag = body[-8:]
    try:
        return AESCCM(tk, tag_length=8).decrypt(nonce, ct + tag, aad)
    except Exception:
        return None


SC_MODES = ("zero", "raw")
PRIO_MODES = ("tid", "zero")


def score_config(sample, tk, cfg):
    fcs, mask, zf, qos_in_aad, nonce_order, sc_mode, prio_mode = cfg
    ok = 0
    for fr, d in sample:
        if ccmp_decrypt(fr, d, tk, mask, zf, fcs, qos_in_aad, nonce_order,
                        sc_mode, prio_mode) is not None:
            ok += 1
    return ok


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--outdir", default="out/evidence/truth")
    ap.add_argument("--psk", help="64-hex PSK (default: run/pairing.env)")
    ap.add_argument("--max-frames", type=int, default=0)
    args = ap.parse_args()

    psk_hex = args.psk
    if not psk_hex:
        env = {}
        for line in open("run/pairing.env"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
        psk_hex = env.get("PSK") or env.get("psk")
    if not psk_hex or len(psk_hex.replace(":", "")) != 64:
        raise SystemExit("need a 64-hex PSK (pass --psk or fill run/pairing.env)")
    pmk = bytes.fromhex(psk_hex.replace(":", ""))

    print("[*] reading %s ..." % args.pcap)
    frames = []
    for ts, origlen, fr in read_pcap(args.pcap):
        frames.append((ts, origlen, fr))
        if args.max_frames and len(frames) >= args.max_frames:
            break
    print("[*] %d frames" % len(frames))

    msgs = find_eapol(frames)
    print("[*] %d EAPOL-Key messages" % len(msgs))
    for m in msgs:
        print("    t=%8.2fs %s->%s ack=%d mic=%d inst=%d secure=%d kv=%d kd=%dB"
              % (m["ts"] - frames[0][0], m["ta"].hex(), m["ra"].hex(),
                 m["ack"], m["mic"], m["install"], m["secure"], m["keyver"],
                 len(m["keydata"])))
    sessions = handshakes(msgs)
    print("[*] %d handshake session(s)" % len(sessions))
    for i, s in enumerate(sessions):
        have = ",".join(sorted(k for k in ("msg1", "msg2", "msg3", "msg4") if k in s))
        print("    session %d: t=%.2fs msgs=%s" % (i, s["msg1"]["ts"] - frames[0][0], have))

    if not sessions:
        raise SystemExit("no handshake in capture")

    results = []
    for i, s in enumerate(sessions):
        if "msg1" not in s or "msg2" not in s:
            print("[-] session %d incomplete (no nonces)" % i)
            continue
        aa, spa = s["msg1"]["ta"], s["msg2"]["ta"]
        anonce, snonce = s["msg1"]["nonce"], s["msg2"]["nonce"]
        print("\n[*] session %d  AA=%s SPA=%s" % (i, aa.hex(), spa.hex()))
        print("    ANonce %s" % anonce.hex())
        print("    SNonce %s" % snonce.hex())
        chosen = None
        for rotate in (True, False):
            ptk = derive_ptk(pmk, aa, spa, anonce, snonce, rotate)
            mic_wire, mic_calc = eapol_mic(s["msg2"]["eapol"], ptk[0:16])
            ok = mic_wire == mic_calc
            print("    rotate=%-5s PTK=%s  KCK-MIC %s"
                  % (rotate, ptk.hex(), "MATCH" if ok else "mismatch (%s/%s)"
                     % (mic_wire.hex()[:16], mic_calc.hex()[:16])))
            if ok and chosen is None:
                chosen = (rotate, ptk)
        if chosen is None:
            print("[-] session %d: no PTK reproduces the msg2 MIC -- PSK wrong?" % i)
            continue
        rotate, ptk = chosen
        kck, kek, tk = ptk[0:16], ptk[16:32], ptk[32:48]
        gtk = None
        if "msg3" in s and s["msg3"]["keydata"]:
            kd = s["msg3"]["keydata"]
            # parse KDEs: dd <len> <oui 00:0f:ac> <dataid> <gtk...>
            off = 0
            while off + 2 <= len(kd):
                if kd[off] == 0xDD and off + 2 <= len(kd):
                    ln = kd[off + 1]
                    body = kd[off + 2:off + 2 + ln]
                    print("    KDE 0xdd len=%d %s" % (ln, body.hex()[:48]))
                    if len(body) >= 6 and body[:4] == b"\x00\x0f\xac":
                        kidx = body[4]
                        unwrapped = None
                        if ln > 6:
                            unwrapped = aead_decrypt(kek, body[5:])
                        if unwrapped:
                            gtk = unwrapped
                            print("    [+] GTK keyidx=%d = %s"
                                  % (kidx & 3, gtk.hex()))
                    off += 2 + ln
                else:
                    off += 1
        if gtk is None:
            print("    (no GTK recovered from msg3 key data)")

        results.append(dict(session=i, ts0=s["msg1"]["ts"], rotate=rotate,
                            ptk=ptk, tk=tk, kek=kek, kck=kck, gtk=gtk,
                            aa=aa, spa=spa))

    if not results:
        raise SystemExit("no usable session")

    # ---- per-epoch, per-class convention selection
    #
    # The capture can hold several handshakes (this one holds three), each with
    # its own PTK, and a frame only decrypts under the key in force.  So every
    # frame is attributed to the epoch = the last handshake at or before it, and
    # the AAD convention is solved per epoch *per traffic class* (direction/TID),
    # because a capture whose headers are rewritten for one class can still be
    # perfectly decryptable for another.
    total = collections.Counter()
    for ts, origlen, fr in frames:
        d = parse_dot11(fr)
        if d and d["prot"]:
            total["prot"] += 1
    print("\n[*] %d protected data frames total" % total["prot"])

    results.sort(key=lambda r: r["ts0"])
    starts = [r["ts0"] for r in results] + [float("inf")]

    def epoch_of(ts):
        idx = -1
        for i, s in enumerate(starts[:-1]):
            if ts >= s:
                idx = i
        return idx

    def klass_of(d):
        tods, fromds = d["fc1"] & 1, d["fc1"] & 2
        dirn = "toDS" if tods and not fromds else ("fromDS" if fromds and not tods
                                                   else "ibss")
        return (dirn, d["tid"] if d["tid"] is not None else -1)

    # stratified sample: up to PER_CLASS frames of each class inside the epoch
    PER_CLASS = 30
    for i, r in enumerate(results):
        per = collections.defaultdict(list)
        for ts, origlen, fr in frames:
            if ts < starts[i] or ts >= starts[i + 1]:
                continue
            d = parse_dot11(fr)
            if not d or not d["prot"]:
                continue
            k = klass_of(d)
            if len(per[k]) < PER_CLASS:
                per[k].append((fr, d))
        r["cfg"] = {}
        print("[*] epoch %d (t=%.2fs): classes %s"
              % (i, r["ts0"] - frames[0][0],
                 ", ".join("%s/tid%d(%d)" % (k[0], k[1], len(v))
                           for k, v in sorted(per.items()))))
        for k, sample in sorted(per.items()):
            best = None
            for fcs in (4, 0):
                for mask_name, mask in AAD_MASKS:
                    for zf in (False, True):
                        for qos_in_aad in (True, False):
                            for no in ("std", "swap"):
                                for sc_mode in SC_MODES:
                                    for prio_mode in PRIO_MODES:
                                        cfg = (fcs, mask, zf, qos_in_aad, no,
                                               sc_mode, prio_mode)
                                        ok = score_config(sample, r["tk"], cfg)
                                        if ok and (best is None or ok > best[0]):
                                            best = (ok, cfg, mask_name)
            if not best:
                print("      %-12s tid%-2d : no convention decrypts (n=%d)"
                      % (k[0], k[1], len(sample)))
                continue
            ok, cfg, mask_name = best
            r["cfg"][k] = cfg
            fcs, mask, zf, qos_in_aad, no, sc_mode, prio_mode = cfg
            print("      %-12s tid%-2d : fcs=%d mask=%s(%#04x) zero_frag=%s "
                  "qos_in_aad=%s nonce=%s seqctl=%s prio=%s -> %d/%d"
                  % (k[0], k[1], fcs, mask_name, mask, zf, qos_in_aad, no,
                     sc_mode, prio_mode, ok, len(sample)))

    if not any(r["cfg"] for r in results):
        raise SystemExit("[-] no epoch/class decrypts with any tested convention")

    # ---- full decrypt pass
    frags = collections.defaultdict(dict)
    udp = []
    stats = collections.Counter()
    klass_stats = collections.Counter()
    timeline = collections.Counter()
    t0 = frames[0][0]
    for ts, origlen, fr in frames:
        d = parse_dot11(fr)
        if d is None:
            continue
        if d["prot"]:
            pt = None
            used = None
            ep = epoch_of(ts)
            order = ([results[ep]] if ep >= 0 else []) + [
                r for r in results if not (ep >= 0 and r is results[ep])]
            for r in order:
                cfg = r["cfg"].get(klass_of(d))
                if not cfg:
                    continue
                fcs, mask, zf, qos_in_aad, no, sc_mode, prio_mode = cfg
                pt = ccmp_decrypt(fr, d, r["tk"], mask, zf, fcs, qos_in_aad, no,
                                  sc_mode, prio_mode)
                if pt is not None:
                    used = r["session"]
                    break
            k = klass_of(d)
            klass_stats[(k, "total")] += 1
            if pt is None:
                stats["fail"] += 1
                continue
            stats["ok"] += 1
            stats["ok_s%d" % used] += 1
            klass_stats[(k, "ok")] += 1
            if pt[:6] != SNAP:
                stats["non_snap"] += 1
                continue
            ethertype = pt[6:8]
            ip = pt[8:]
        else:
            body = fr[:-4]
            body = body[d["hdr"]:]
            if len(body) < 8 or body[:6] != SNAP:
                continue
            ethertype = body[6:8]
            ip = body[8:]
        if ethertype != b"\x08\x00" or len(ip) < 20 or ip[0] >> 4 != 4:
            stats["non_ip"] += 1
            continue
        ihl = (ip[0] & 0xF) * 4
        totlen = struct.unpack(">H", ip[2:4])[0]
        ident = struct.unpack(">H", ip[4:6])[0]
        ff = struct.unpack(">H", ip[6:8])[0]
        mf = ff & 0x2000
        foff = (ff & 0x1FFF) * 8
        proto = ip[9]
        frags[(ident, proto)][foff] = ip[ihl:totlen]
        if mf:
            stats["frag"] += 1
            continue
        parts = frags.pop((ident, proto), None)
        if parts is None:
            continue
        buf, good = b"", True
        for o in sorted(parts):
            if o != len(buf):
                good = False
                break
            buf += parts[o]
        if not good:
            stats["frag_gap"] += 1
            continue
        if proto == 17 and len(buf) >= 8:
            sport, dport, ulen = struct.unpack(">HHH", buf[0:6])
            pay = buf[8:ulen] if 8 <= ulen <= len(buf) else buf[8:]
            udp.append((ts - t0, buf[12:16], buf[16:20], sport, dport, pay))
            stats["udp_dst%d" % dport] += 1

    print("\n[*] decrypt stats: %s"
          % json.dumps({k: v for k, v in sorted(stats.items())}, indent=None))
    print("[*] per-class decrypt success:")
    for k in sorted({k for (k, _) in klass_stats}):
        tot_n = klass_stats[(k, "total")]
        ok_n = klass_stats[(k, "ok")]
        print("    %-12s tid%-2d  %7d/%-7d  %5.1f%%"
              % (k[0], k[1], ok_n, tot_n, 100.0 * ok_n / max(tot_n, 1)))

    print("\n[*] %d UDP datagrams recovered" % len(udp))
    flows = collections.Counter((s, dpp) for ts, si, di, s, dpp, p in udp)
    print("    %-28s %s" % ("flow (sport -> dport)", "count"))
    for (s, dpp), c in flows.most_common(25):
        sizes = sorted({len(p) for ts, si, di, s2, d2, p in udp
                        if s2 == s and d2 == dpp})
        print("    %5d -> %-5d  %7d   sizes=%s" %
              (s, dpp, c, sizes[:6] + (["..."] if len(sizes) > 6 else [])))

    os.makedirs(args.outdir, exist_ok=True)
    with open(os.path.join(args.outdir, "udp-payloads.bin"), "wb") as f:
        for ts, si, di, s, dpp, p in udp:
            f.write(struct.pack(">d4s4sHH", ts, si, di, s, dpp))
            f.write(p)
    with open(os.path.join(args.outdir, "flows.json"), "w") as f:
        json.dump({"%d->%d" % k: v for k, v in flows.items()}, f, indent=1)
    with open(os.path.join(args.outdir, "classes.json"), "w") as f:
        json.dump({"%s/tid%d" % k: v for k, v in
                   sorted((k, (klass_stats[(k, "ok")], klass_stats[(k, "total")]))
                          for k in {k for (k, _) in klass_stats})}, f, indent=1)
    print("[+] wrote %s/udp-payloads.bin, flows.json, classes.json" % args.outdir)

    for port in sorted({dpp for *_, dpp, _ in
                        [(u[0], u[1], u[2], u[3], u[4], u[5]) for u in udp]}):
        sel = [(ts, si, di, p) for ts, si, di, s, dpp, p in udp if dpp == port]
        if not sel:
            continue
        path = os.path.join(args.outdir, "port%d.bin" % port)
        with open(path, "wb") as f:
            for ts, si, di, p in sel:
                f.write(struct.pack(">d4s4sI", ts, si, di, len(p)))
                f.write(p)
        print("    %s : %d payloads" % (path, len(sel)))


if __name__ == "__main__":
    main()
