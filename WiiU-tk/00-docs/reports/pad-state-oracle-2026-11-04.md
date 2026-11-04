# pad-state oracle — raw runs and interpretation

Evidence for `research/BOOT-AND-MODES.md` §5.1. Tool: `run/pad-state.py`.
Environment: our own AP `WiiUAP` (ssid `WiiUccfb65b68169`, BSSID `cc:fb:65:b6:81:69`,
host `192.168.1.10`), pad `192.168.1.11` associated and reachable by ICMP.

## Run 1 — clean (2026-11-04 09:13 local), nothing else bound to 50023

```
from 192.168.1.10:50023 -> 192.168.1.11:50123
  bright   svc 5/0x15 error=0 1B  LCD brightness level 4 (1-5)
  lvc      svc 0/0x00 error=0 8B  LVC running=385944601 installed=385944601
  state    svc 4/0x05 error=0 1B  state index 0
  version  svc 4/0x04 error=0 28B  0000000b00000040190c011728000058000800000c0221fe00001ccc
  wifi     svc 1/0x05 error=0 113B ssid=b'WiiUccfb65b68169' (16) auth=2 enc=0
                                  psk=<64 hex bytes, withheld here>
```

Interpretation:

* **state index 0** — recorded while the pad was showing its own notice screen under an
  active session. First calibration point for the "which screen is it on" oracle.
* **brightness 4** — set by our own once-per-second `SetLcdBacklight` (svc 5/`0x14`,
  level 4). Independent proof that our command plane reaches panel control, not just the
  pad's protocol layer.
* **LVC running == installed (385944601)** — the pad is not mid-update.
* **ssid/PSK match** — the returned SSID and 64-hex PSK are byte-identical to
  `run/pairing.env` (PSK sha256 prefix `36ef436c8412`). This is the first *positive*
  demonstration that the pad is paired to us rather than to the console; test T2 passes.
  auth=2, enc=0 as libdrc documents.

## Run 2 — collided (2026-11-04 09:14 local), reproduced in `pad-state-091401.log`

```
  bright   NO REPLY ...
  lvc      NO REPLY ...
  state    NO REPLY ...
  version  svc 4/0x04 error=0 28B  ...
  wifi     svc 1/0x05 error=9004 0B
```

A `sudo ./run/phase5-full-session.sh 120` had started in another session and bound the
console's service ports, including `192.168.1.10:50023`, with `SO_REUSEADDR`/
`SO_REUSEPORT`. A second binder on that port **succeeds silently**, and the kernel then
splits the pad's replies between the sockets:

* queries whose replies landed on the other socket report `NO REPLY` (indistinguishable
  from a sleeping pad);
* one reply came back as `error=9004` with an empty body — the only trace of the split.

Conclusion, now in `BOOT-AND-MODES.md` §11: `run/pad-state.py --send` must own port 50023
(stop the stack with `run/drc-down.sh` first) and must never run during another session's
phase test. The pad answers on `…:50023` regardless of the query's source port, which is
why the ephemeral-port fallback appears to work intermittently.
