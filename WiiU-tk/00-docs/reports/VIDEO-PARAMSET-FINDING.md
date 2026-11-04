# GamePad video rejection: root cause and fix (2026-11-03)

## Symptom
Our DRC video stream reaches the pad (854x480, ~210 pkt/s, 1710 B payloads on
UDP 50120) but the pad rejects it and emits ~27 resync requests/s to 50010.
Input from the pad works, so the link, addressing, DRC protocol and the
Nintendo OUI / PTK-rotation patches are all fine. Only the bitstream fails.

## Ground truth: the pad uses a HARDCODED parameter set
libdrc ships the pad's own SPS/PPS (`src/h264-encoder.cpp`, DumpH264Headers),
which libdrc encodes with `b_repeat_headers = 0` precisely because the pad does
not need them in-band. Decoded bit-exactly (see /tmp/h264params.py logic):

    SPS 67 64 00 20 ac 2b 40 6c 1e f3 68
      profile High(100), level 3.2(32), sps_id 0, chroma 4:2:0
      log2_max_frame_num_minus4 = 4        -> frame_num is 8 bits
      pic_order_cnt_type = 2               -> no POC LSB in slice headers
      max_num_ref_frames = 1
      pic_width_in_mbs_minus1 = 53 (864 px), height 30 MB (480),
      crop right = 5 (=10 px)              -> display 854x480
      frame_mbs_only = 1, no VUI

    PPS 68 ee 06 0c e8
      CABAC on, no slice groups, 1 ref idx default
      weighted_pred 0, weighted_bipred_idc 0
      pic_init_qp_minus26 = 6 (init QP 32 - matches libdrc CQP 32)
      deblocking_filter_control_present = 1
      constrained_intra_pred = 1
      transform_8x8_mode absent (off)

## What actually differed
libdrc's encoder already matched the PPS on every field, and matched
`pic_order_cnt_type = 2` for free (the bundled drc-x264 forces poc_type 2 when
there are no B-frames and no interlacing, `encoder/set.c:169`).

The single critical mismatch was **log2_max_frame_num**:

    pad : log2_max_frame_num_minus4 = 4   -> 8-bit frame_num
    ours: log2_max_frame_num_minus4 = 1   -> 5-bit frame_num

x264 sizes that field from max_frame_num (encoder/set.c:165-167), which with
keyint_max=30 lands on 5 bits. The pad always reads 8 bits, so every slice
header desynchronises 3 bits in and the frame is undecodable.

## Fix
`pc2drc/drc-x264/encoder/set.c`: force `sps->i_log2_max_frame_num = 8;`
(see the comment added there). libx264 rebuilt; deployed to
`out/x264/lib/libx264.so.140` (libdrc loads it dynamically, so no libdrc
relink is needed).

## Offline proof (no pad required)
Because the pad ignores in-band parameter sets, the pad's effective input is
pad-SPS + pad-PPS + our slice NALs. That is directly testable:

    encode_dump <preset> out.h264 90        # same settings as libdrc, drh off
    prepend 00000001 67640020ac2b406c1ef368 00000001 68ee060ce8
    ffmpeg -v error -i out_pad.h264 -f rawvideo -pix_fmt yuv420p out.yuv

Results (90 frames, one frame = 854*480*1.5 = 614,880 B):

    pre-fix : decode errors ("reference count overflow", "number of reference
              frames (1+1) exceeds max (1; probably corrupt input)",
              "no frame!") -> only 614,880 B = 1 frame decoded
    fixed   : zero errors -> 55,339,200 B = 90/90 frames decoded

This reproduces the pad's behaviour exactly (decode one frame, then resync
forever) and shows the fixed stream is fully conformant with the pad's
hardcoded parameter sets.

## Still to confirm on real hardware
On-pad verification needs a 5 GHz AP. The AX210 (wlan0) cannot do 5 GHz AP in
this regdomain: iwlwifi LAR marks all 5 GHz channels `no IR` and only clears
that while associated to a 5 GHz AP, so hostapd refuses with
"Could not select hw_mode and channel (-3)". There is no `lar_disable` module
parameter on this kernel. Needs either the Pi's brcmfmac (5 GHz AP capable) or
a 5 GHz AP-capable dongle.

## Capture/decryption note
`capture/real-session.pcap` could NOT be decrypted: the pad associated on a
different channel, so the PTK actually in force predates the capture. The two
handshakes present in the file were verified genuine (our derived rotated KCK
reproduces the pad's EAPOL msg2 MIC exactly), but PN runs continuously (1..795,
no reset) across them, so the data key never changed to either. scapy's
independent CCMP implementation also fails, confirming it is the key, not the
code. Capture a session from before association if the console's own bitstream
is ever needed.

---

# Follow-up: live encoder sweep against the real GamePad (2026-11-04)

## Setup that finally worked end-to-end
- `wlan1` (RTL8188FU) = uplink, `wlan0` (AX210) = dedicated DRC AP.
- `wlan0` must be taken out of NetworkManager (`nmcli dev set wlan0 managed no`),
  otherwise NM's background scans hold the radio and hostapd fails with
  `nl80211: Frame command failed: ret=-16 (Device or resource busy)`.
- ch149 becomes IR-capable in this regdomain; hostapd needs
  `country_code=CA` + `ieee80211d=1` AND `bssid=cc:fb:65:b6:81:69` (the vif
  otherwise advertises a random MAC and the pad will not join).
- Result: pad authenticates, completes the 4-way handshake, DHCPs
  192.168.1.11, and its input drives the Kali cursor. Video still rejected.

## Metric
The pad sends 4-byte `\1\0\0\0` to console:50010 per frame it fails to decode
(libdrc streamer.cpp treats exactly that as a resync request). Normalised as
"resync per frame" = resync/s / (video packets/s / ~14 packets per frame).

## Sweep results (all via DRC_* env hooks, no rebuilds)
| config | resync/frame |
|---|---|
| baseline (drh=1, in-band params) | 8.2 |
| transform8x8=on | 7.8 (and one run 0.0 with video flowing) |
| drh_mode=0 | 1.0 - 6.0 (highly variable) |
| t8x8+drh0 | 3.6 |
| keyint=1, fps=60, qp=26, deblock, refs=2, profile=main | 5.7 - 10.0 |

Nothing converges: the same config can score 1.0 and 8.2 on consecutive runs.
The variance exceeds the effect size, so the resync rate is not a usable
objective function - the pad's screen is the only judge.

## What is ruled out
- Parameter-set mismatch: our stream decodes 90/90 frames under the pad's own
  hardcoded SPS/PPS (see above), and the fix is confirmed loaded at runtime
  (/proc/<pid>/maps shows out/x264/lib/libx264.so.140).
- vstrm framing: verified on the wire - magic F, Init/FrameBegin/ChunkEnd/
  FrameEnd, 5 chunks x 6 MB rows, 1694-byte payloads, Idr ext-option present,
  frame-rate option 0 (59.94Hz), MB-rows=6.
- Crypto/link/DHCP/ports: all confirmed working (video 50120, audio 50121,
  input 50122, command 50123, messages 50010).

## Conclusion
Blind iteration over encoder parameters has hit its limit. The remaining defect
is in the live payload path (DRH macroblock-row chunking) or a session/init
detail that is not observable without a reference stream captured from a real
console with the handshake in force.

## Next: capture ground truth
Use .250's ath9k (5 GHz monitor works; only AP mode is blocked) to monitor the
console's channel BEFORE the pad reconnects, so the 4-way handshake in force is
in the capture. Then decrypt (decrypt_h264.py) and diff the console's real
frame payloads against ours.
