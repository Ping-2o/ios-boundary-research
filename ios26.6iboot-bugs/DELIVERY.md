# DELIVERY MANIFEST — iBoot bug set (Reports 1–6) — 100% state

Date: 09-12 (v175 session). Device reference: iPhone17,5 (t8140). Builds audited:
iOS 26.6 `mBoot-18000.162.8`, 26.6.1 `mBoot-18000.162.10`, 27.0 `mBoot-20457.2.37`
(24A435). Companion analyses: `RECHECK_24A435_mBoot-20457.2.37.md` (27.0 re-verify),
`DELIVERY_PATHS_24A435.md` (reachable-set + experiment verdicts),
`IBEC_IBSS_24A435.md` (iBEC/iBSS = iBoot, memboot chain).

| # | Report | Folder | Live PoC (26.6 / 26.6.1) | 27.0 status | Delivery story |
|---|---|---|---|---|---|
| 1 | DEFLATE stored-block copy ignores dst capacity | `Report1_DEFLATE/` | 3×3 runs, `OOBbytes=16368` | STILL PRESENT (`0x2026F0` dispatcher) | 'splt' CRC-only staging (P2/P4); escalation: `Report4_SPLT/rce_run*.log` control-transfer 3/3 |
| 2 | LZVN write past caller capacity | `Report2_LZVN/` | 3×3, `capSpanOOB=65536` | STILL PRESENT (`0x21914C` core) | same P2/P4 |
| 3 | LZFSE bvx1 match copier, no lower bound | `Report3_LZFSE/` | 3×3 leak + fault | STILL PRESENT (`0x201080`, fault `0x2010F4`) | same P2/P4 |
| 4 | 'splt' unkeyed CRC gate / attacker-chosen decoder | `Report4_SPLT/` | forged containers ACCEPT + same-CRC tamper decodes + RCE demo | STILL PRESENT (`0x14F3B0` gate) | THE boundary finding — feeds 1/2/3/5 |
| 5 | record-homing `LEN >u E-DELTA` negative-DELTA wrap | `Report5_HOMING/` | 3×3 matrix; N1 write lands below window | **STILL PRESENT — rechecked NEW 09-12** (`0x1a39bc` guard) | P4 kernelcache-map arm incl. 'splt' CRC-failure fallback |
| 6 | NVRAM banks sealed only by unkeyed sums | `Report6_NVRAM/` | forge + re-seal + accept (162.x nvram.c) | PRESENT (static) | persistence amplifier for 1–5; dead-gate claim RETRACTED (§4c) — core survives |

## Completeness checklist

- [x] All six report folders present in this delivery dir, each with README.md,
  harness source, .bin PoC artifacts, and retest logs on both shipping builds.
- [x] 27.0 (24A435) re-verification table for every report (was: 1,2,3,4,6; now: +5).
- [x] Every delivery-path experiment closed: #1 (§4a mode-bit), #2 (§4e P1 honest,
  NEGATIVE for swap-claim — deliberately NOT overclaimed), #3 (§4e wchf = family
  member + log-only 4cc gate), #4 (§4b traced NVRAM→'splt' chain, §4c corrected).
- [x] Table-dispatch method lesson applied everywhere a "zero xrefs" claim exists.
- [x] **DeviceRunKit/**: on-device execution kit (recovery-shell enumeration,
  zero-risk real-bvx2 control, PoC send/bootx sequence with framed + raw IM4P wrap
  families, live NVRAM demo, safe-exit + crash-collection scripts). Pending the
  physical run — every retail-device unknown in these reports is now a script.
- [x] Novelty screen (SearxNG, 09-12): no public CVE/writeup maps to any of the six
  defects on these builds; public iBoot research covers bootrom (checkm8/usbliter8),
  source-leak analyses, and SMMU — not decoder/record arithmetic. Apple's
  "Memory safe iBoot implementation" (iOS 14+, toolchain hardening) is the expected
  pushback: all six are **arithmetic/bounds-logic** defects — negative-offset wraps,
  capacity-blind copies, unkeyed seals — precisely the class a memory-safety
  toolchain does not catch; the persistence of Reports 1–5 across the 18000→20457
  toolchain generation (still-present receipts) is the evidence.

## Known-open (documented, not blocking delivery)

- Live-device questions (retail recovery-prompt reachability, `sub_16a4` mode-bit
  value on retail, staging-region population) need a boot + UART/panic-log read —
  flagged in `IBEC_IBSS_24A435.md` §4 and `DELIVERY_PATHS_24A435.md` §4a.
- Report 5 24A435 live matrix: harness retarget (`set_offs(2)`) — static table done,
  receipts pending the (identical) recompiled guard arithmetic's execution.
- Report 6 dynamic demo replay on 24A435: Adler helper args widened (2→5 regs).
