> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# iBoot decoder-integrity findings — publication package (Reports 1–6)

**Authorship & purpose notice (applies to every document in this folder).**
All content here was produced **100% by autonomous AI agents** for **security
research and coordinated vendor disclosure only** (Apple Product Security /
Security Bounty). No document received a human authorship pass — expect terse
jargon, campaign shorthand, and the occasional slop sentence. Every factual claim
is anchored to a checkable artifact: a raw firmware offset, a printed receipt in a
`.log`, or an exact reproduction command. Treat anything you cannot re-verify as
provisional. The PoC binaries are minimal reproducers for triage, not weapons;
there is no persistence, exfil, or evasion tooling in this package.

## What is in the folder

| Artifact | Role |
|---|---|
| `Report1_DEFLATE/` … `Report6_NVRAM/` | One folder per vulnerability: `README.md` (report), harness source, PoC blobs, retest logs on BOTH shipping 26.6 builds |
| `iBoot-Reports-1-6-2026-09-12.zip` | Everything (reports + companions + DeviceRunKit scripts) |
| `ReportN_*.zip` | Per-report single submission archives |
| `RECHECK_24A435_mBoot-20457.2.37.md` | Status of all six bugs on the iOS 27.0 seed (still-present verdicts + relocated offsets) |
| `DELIVERY_PATHS_24A435.md` | How attacker bytes reach each vulnerable function (closed reachable set; four experiments, all resolved) |
| `IBEC_IBSS_24A435.md` | iBoot ≡ iBEC ≡ iBSS proof + the recovery-shell memboot chain (incl. the retail-device verdict) |
| `DeviceRunKit/` | On-device execution: enumeration, zero-risk control, PoC send/bootx sequences, NVRAM demo, safe-exit. `results/RUN1_finding_console_live.md` = current device state |
| `DELIVERY.md` | Completeness checklist + known-open list |

## Submission reading order (for the vendor triager)

1. Each `ReportN_*/README.md` — Summary → Root cause (instruction-level citations) →
   Affected-software offset tables → Reproduction. The harnesses execute REAL firmware
   code from the shipped images (LEVEL-B hybrid; transcribed glue is cited).
2. `RECHECK_24A435_...` — confirms all six survive the 26.6→27.0 toolchain rebuild
   (the memory-safe-iBoot toolchain question, pre-answered).
3. `DELIVERY_PATHS_24A435.md` — the honest delivery boundary: four reachable decode
   entries, the signed-image path verified as auth-before-decode (no storage-swap
   claim is made), staging-class paths carry unkeyed CRC-32 / unsealed integrity.
4. `DeviceRunKit/results/RUN1_finding_console_live.md` — retail-device status:
   recovery console executes commands; the memboot PoC runs are the remaining step.

## Evidence levels used (defined once)

- **LIVE** — real firmware code executed against real extracted images, deterministic
  receipt in a shipped `.log` (multi-rep).
- **STATIC** — disassembly/decompilation fact with a cited offset (BN/Ghidra; BN VA =
  raw file offset + 0x1000 on the 24A435 artifacts).
- **DEVICE** — observed on the physical iPhone17,5 (only one such finding so far:
  console liveness; the PoC device runs are pending and will be labeled the same way).

## Contact/handling note

This package targets coordinated disclosure. If you are not the vendor security
team: these decoder defects are fixed-by-Apple-when-Apple-chooses; nothing here
should be run against a device you do not own and have authorization to test.
