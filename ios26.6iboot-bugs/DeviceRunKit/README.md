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
| 1 | `step1_enum.sh` | shell alive? getenv whitelist? security-mode reads? | values OR uniform silence = documented negative |
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


Run order 0→1→2→(3)→5, then 9. If step1 shows total silence, stop — write the
outcome into `../DELIVERY_PATHS_24A435.md` §4 as the device answer (shell does not
run on retail A18; Reports 1–3/5 stay staging-position claims — that IS a result).

## What each outcome changes in the reports

- **step1 responds + step3 panics** → Reports 1–3 get a *physically-present* delivery
  sentence (USB recovery, no pairing, no exploit needed) and Report 4's gate claim
  gains the iBEC memboot arm as a live entry point. Biggest upgrade available.
- **step1 responds, commands PERMISSION DENIED** → the `sub_82434` range-whitelist is
  active on retail: document exactly which commands answer (that's the §4.2 answer).
- **step1 silent** → retail iBEC never runs the command prompt outside restore/FUD
  states: reports keep the staging-only framing (already their current wording);
  `§4a` mode-bit question remains open pending an Apple-diag unit.
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
