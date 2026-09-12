> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# DeviceRunKit — turning the six iBoot reports on the REAL device (iPhone17,5 / t8140)

Everything in `Report*/` so far is LEVEL-B: real firmware code executed on the host.
This kit answers the two questions the static+host work CANNOT (flagged in
`../IBEC_IBSS_24A435.md` §4 and `../DELIVERY_PATHS_24A435.md` §4a):

1. **Does the iBEC/iBSS recovery shell run on a retail non-checkm8 A18 unit?**
   (iBEC is byte-identical to iBoot — the vulnerable decoders AND the shell live in
   the same image; `send`+`bootx` = the memboot chain = decode-before-verify.)
2. **What does the staging mode-bit / NVRAM surface return on THIS unit?**

## Safety contract (read before running anything)

- memboot `send`/`bootx` is **RAM-only (memz)** — nothing persists; a misfire resets
  the SoC, the device re-enters recovery on its own or via buttons.
- Exit ramp at ANY point: hold **Vol- + Side 10s** = forced reboot; then `irecovery -n`
  or just let it boot. Full recovery path (worst case): restore with the existing
  `iPhone17,5_27.0_24A435_Restore.ipsw` (TSS window permitting) — standard procedure.
- step1 is **read-only**. step2 sends a benign control blob. step3 sends the PoC
  streams (device may panic/reset — that IS the receipt). step5 writes one NVRAM
  variable (`auto-boot-once`, the name the protected list does NOT cover) then clears it.
- Battery ≥ 40% before starting. Do steps with the screen UNLOCKED (modern iOS gates
  USB in recovery behind prior unlock — if the device asks for passcode, enter it).

## Protocol (each step logs to `results/`)

| # | script | question answered | expected healthy receipt |
|---|---|---|---|
| 0 | `step0_pullcrash.sh` | baseline crash/panic inventory (normal mode) | folder snapshot |
| 1 | `step1_enum.sh` | shell whitelist VALUES (read-only; **empty ≠ dead** — see RUN 1) | state-change test = the verdict |
| 2 | `step2_memboot_control.sh` | decode-before-verify ordering + latency vocabulary | "Kernelcache image not valid" AFTER decode |
| 3 | `step3_poc_seq.sh [payloads...]` | THE device-side PoC: R1/R2/R3 streams via memboot krnl | reset/panic = decoder consumed attacker bytes on retail silicon |
| 5 | `step5_nvram.sh` | Report 6 live: write `auto-boot-once`, reboot, readback | value persists = no keyed seal, device-proven |
| 6 | `payloads/step6_wrap_complzss.sh` | builds `complzss`-FRAMED PoC IM4Ps (force the dispatcher route when the container attribute, not the stream magic, picks the decoder) | frame_* variants for step3 |
| 9 | `step9_recover.sh` | always-safe exit: reboot to normal | device back up |

**Payload wrapping: two families.** `make_payloads.sh` wraps each stream with
`--compress none` (payload verbatim; works IF iBoot sniffs the stream magic — R2/R3
streams carry `bv41`/`bvx1` magic, R1's raw DEFLATE does not). `step6_wrap_complzss.sh`
emits the real iBoot compression frame (`complzss|algo4cc|out_size|comp_size|stream`,
structure recovered from ipsw's DER dump) so the container attribute routes the payload
into the dispatcher. Run step2 first: its behavior tells you which family the memboot
path respects (if the CONTROL "not valid" verdict arrives WITHOUT a decode-side fault
the ordering is honest-but-post-decode; if it arrives instantly the parser rejected on
attribute and you must use the frame_* payloads in step3).


## RUN 1 RESULT (09-12, iOS 27.0 24A435 unit) — **RETAIL CONSOLE IS ALIVE**

`getenv`/`peek` all returned empty — and that is EXPECTED, not gating: retail recovery
sends shell stdout to the internal debug UART (silent by default), and libirecovery's
"Command completed successfully" is only the USB control-transfer ACK (it prints for
garbage commands too). The decisive probe was `irecovery -c reboot`: the device left
Recovery and booted to normal 27.0. **Commands execute on this retail, non-checkm8 A18.**
Evidence + what is still NOT shown (send/bootx acceptance, the §4.2 whitelist window,
locked-USB behavior): `results/RUN1_finding_console_live.md`. The unit is currently
back in normal mode — re-enter Recovery (vol+, vol−, hold Side) to continue with
step2 (zero-risk control) → step3.

Run order 0→1→2→(3)→5, then 9.

## What each outcome changes in the reports

- **step1 executes commands (RUN 1: CONFIRMED via `reboot`)** → shell reachability is
  settled in the affirmative; the remaining gate is step2/3: if `send`+`bootx` runs the
  memboot chain and the PoC streams fault/reset the device, Reports 1–3/5 get a
  *USB-physically-present, no-exploit, no-pairing* delivery sentence on retail 27.0
  silicon — a material upgrade over the staging-host framing.
- **step2/3 accepted but behavior unchanged** → memboot window (`sub_82434`, §4.2) or the
  container parse rejected our bytes at the boundary; document which (pair with crash pull).
- **locked-USB variation**: repeat step1 on a passcode-locked unit (enter recovery, do NOT
  unlock) — if `reboot` still executes, no unlock precondition exists; if not, delivery
  requires an unlocked device in recovery (still physical-presence, one more precondition).
- **step5 write/readback works** → Report 6 becomes device-proven persistence, no
  jailbreak, USB-physical position only.

## Payloads

`payloads/make_payloads.sh` wraps the report `.bin` streams into `krnl`-typed IM4Ps
(payloads sent uncompressed so the decoder runs on the exact PoC bytes; `sh_memboot`
parses the container then hands the payload to the compression dispatcher).

## Artifacts to paste back

Everything lands in `results/*.log` + the crash folder from step0/step3 aftermath.
The device-side verdicts then get folded into the READMEs' delivery sections and the
zips get rebuilt.
