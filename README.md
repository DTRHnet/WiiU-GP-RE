# WiiU-GP-RE

Reverse-engineering notes, tooling and harnesses for the **Nintendo Wii U
GamePad** wireless link — the 5 GHz console↔pad protocol, its pairing, the
video/audio/command planes, and how far the link can be driven from a PC or a
Raspberry Pi.

This repository contains **original work only**. Third-party projects it builds
on (`libdrc`, `pc2drc`, hostapd, x264) are *not* vendored here — see
[`THIRD-PARTY.md`](THIRD-PARTY.md) for provenance and per-patch licensing.

## What's here

```
WiiU-tk/
  00-docs/          findings: link internals, codec spec, boot modes, reports
  01-radio-kernel/  mac80211 TSF/cipher patches + the kernel build wrapper
  02-bringup/       load patch module, pair, raise AP, stream
  03-pi/            Raspberry Pi variants (be-the-console, WPS pairing, capture)
  04-stack/         userspace stack notes and drivers
  05-capture/       capture methodology and decode helpers
  06-experiments/   one-off probes and falsified hypotheses
  07-protocol/      wire-format analysis of the command/video planes
  08-tests/         hardware-free test harnesses (C/C++ + python)
  09-rce-hunt/      command-plane fuzzing tables and probes
  10-build/         container and native build recipes
  11-patches/       our diffs against upstream, with per-target licensing
  _meta/            source map (provenance), inventory generator, publish audit
```

## Verified findings

The documents under `WiiU-tk/00-docs/` were written from captured traffic and
source reading, not inference. Where a hypothesis was falsified it is recorded as
falsified. Highlights:

- **`00-docs/RESEARCH.md`** — how the link actually works: no cable path exists,
  the pad's only data port is an internal UART, and the radio is 5 GHz-only.
- **`00-docs/research/CODEC-SPEC.md`** — the pad's H.264 path: a *hardcoded*
  SPS/PPS, 5 macroblock-row DRH chunking, and the two streamer defects found
  (no in-frame pacing; every heartbeat forced an IDR).
- **`00-docs/reports/VIDEO-PARAMSET-FINDING.md`** — the pad ignores in-band
  parameter sets and decodes only against its built-in ones.

## Before you push

This repo uses a **default-deny** `.gitignore`: everything is ignored, and only
`WiiU-tk/` plus the root docs are re-included. New directories, downloaded
tarballs and fresh `git clone`s therefore cannot be committed by accident.

Always run the audit before pushing:

```sh
bash WiiU-tk/_meta/prepublish-audit.sh
```

It blocks: paths outside the allowlist, vendored third-party trees, binary blobs,
`GIT binary patch` hunks inside patches, and credential material (WPA PSK,
private keys). It warns on device identifiers and large files.

## License

Original work in this repository is released under the license in `LICENSE`.
**Patch files are licensed under the license of the upstream they apply to**
(GPLv2 for Linux mac80211 / hostapd / x264, GPLv3 for drcvncclient, BSD-2 for
libdrc) and are not covered by the repository license. See
[`THIRD-PARTY.md`](THIRD-PARTY.md).

## Scope and intent

This is interoperability research on hardware the author owns, for personal and
educational use, in the spirit of existing projects such as `libdrc` and
`pc2drc`. Nintendo's GamePad firmware and the console's firmware are proprietary;
nothing here circumvents copy protection or enables piracy. Console and pad
identifiers in this repo are the author's own devices.
