> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# DeviceRunKit run 1 (09-12) — RETAIL A18 RECOVERY CONSOLE IS ALIVE (executes commands; output silent over USB)

Device: iPhone17,5 (v59ap, t8140/A18), ECID 0x55cca0a78801c, **iOS 27.0 24A435**
(the exact audited build), entered Recovery Mode by buttons.

## Evidence (chronological)

| t | action | observation |
|---|---|---|
| 21:41:30 | `step1_enum.sh` | recovery enumerated: CPID 0x8140 CPRV 0x10 BDID 0x04 IBFL 0x3d, NONC/SNON readable, MODE: Recovery (`step1_20260912_214130.log`) |
| 21:41:3x | 27× `getenv <var>` + `peek 0x300730024 8` | **every response empty** — including `build-version` (must return a value if the shell echoed at all) |
| 21:44 | `irecovery -c this_is_not_a_command` | rc=0, empty — and libirecovery prints "Command completed successfully" **unconditionally**: that string is the USB control-transfer ACK, NOT shell confirmation. Empty output is therefore NOT a verdict. |
| 21:46 | 11 command-name probes (help/?/banner/printenv/…) | all empty (same non-verdict) |
| 21:48 | `irecovery -c "reboot"` | **device LEFT the recovery bus at t=2s** (25 s of prior polls had shown stable Recovery Mode), and now enumerates in NORMAL mode: `idevice_id -l` = 00008140-00055CCA0A78801C, `ideviceinfo` ProductVersion **27.0** / BuildVersion **24A435**. |

## Verdict

**The recovery-mode command console EXECUTES commands on a retail, non-checkm8,
production-signed A18 running the shipping 27.0.** The earlier "empty responses"
were an observability gap (shell stdout is not returned on the USB bulk-IN endpoint
in retail recovery — it routes to the internal debug UART, which is silent by
default), not gating. The liveness proof is the state change caused by `reboot`
(n=1 so far; a second confirm costs one recovery re-entry).

This **resolves the open question** `../../IBEC_IBSS_24A435.md` §4.3 in the
affirmative, and makes §4.2 (is the memboot window whitelisted on retail?) the ONE
remaining gate before the memboot chain (IBEC_IBSS §2: `filesize` -> receive ->
`sub_2aa34('krnl')` -> decode -> dispatcher -> Reports 1/2/3/5 decoders) becomes a
**USB-physical, no-exploit delivery on retail silicon** — precisely the
"user-physically-present" class `../../DELIVERY_PATHS_24A435.md` §3 ranked, upgraded
from staging-host to direct-USB.

## What has NOT been shown (do not overclaim in the reports yet)

1. That `send` (bulk-OUT file upload, step 2/3) is accepted — the file path is a
   different endpoint than the control ACKs; only `reboot`'s effect is proven.
2. That the §2.aa435 permission window (`0x3bc8a0/8a8`) admits the receive target
   on retail (`sub_82434`), nor that locked-USB (passcode-protected) units answer
   control commands at all (this unit was usable in recovery; note state honestly).
3. `reboot` evidence is n=1 (one observation); repeat on re-entry.

## Next run (needs the device back in Recovery)

1. `step1_enum.sh` (re-collect with the new understanding: empty != dead)
2. liveness confirm: `irecovery -c "setenv auto-boot NO"` — if NO persists, the
   NEXT boot from recovery should NOT auto-boot; reboot and observe (read-only-ish,
   undo with `setenv auto-boot YES`... prefer `reboot` re-test first: cheapest, safe)
3. `step2_memboot_control.sh` — the zero-risk control (real iBoot bvx2 stream):
   READING: after `bootx`, does the device stay put, hang (decoder ate the payload),
   or reboot? Pair with `step0_pullcrash.sh after` + next-boot crash pull.
4. If the control shows memboot live -> `step3_poc_seq.sh` per the README legend.

## Artifacts

- `step1_20260912_214130.log` — the enumeration (empty getenvs; keep as the BEFORE picture)
- `crash_before/` — full pre-run crash inventory (16 MB incl DiagnosticLogs) for
  diffing after any PoC run
- this file = the run verdict
