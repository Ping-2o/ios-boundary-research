> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# iBoot record-homing delta copy: negative DELTA wraps the ONLY guard (`LEN >u E - DELTA`) — decoded-content bytes are written at an attacker-chosen address relative to the home-window anchor

## Summary

iBoot's Mach-O boot-record loader (`FUN_00199150` on 162.x; relocated + verified
present on 24A435, see §27.0 recheck) "homes" each decoded record into its home
window by computing a DELTA from two attacker-supplied words and a DST pointer as
`DST = WBASE + DELTA`, then copying the decoded record content to DST. **The only
bounds guard is an UNSIGNED comparison `LEN >u (E - DELTA)`** where `E` is the
window extent and `DELTA` is attacker-chosen arithmetic from the record stream. A
**negative DELTA underflows `E - DELTA` to ~2^64**, the guard passes for any LEN,
and the REAL firmware copier linearly writes the decoded-content bytes at the
negative-offset address — below the home window anchor. The copy's "destination
fence" is a vacuous self-fence `{DST, DST, DST+LEN}` built from the same DST, so
it validates nothing.

Proven live against both shipping 26.6 builds with a LEVEL-B hybrid harness
(`homing.c`): memory-touching and decision primitives are REAL mapped firmware
code executed verbatim (probe, extent math, dest-quad builder, copier family,
panic block); only loop glue and frame provisioning are transcriptions, cited
instruction-by-instruction below.

| Cell | Result (3/3 runs, both builds) | Meaning |
|---|---|---|
| P1 | decoded-content marker written IN window at WBASE+0x1230, fence intact | harness fidelity + positive control |
| **N1** | **marker written 0x20000 BELOW the window anchor** (`E-DELTA = 0x60000` from `signed -131072`; guard passed) | **THE WRAP WRITE** |
| N2 | fault at REAL copier body pc `+0x167e14` writing the intended DST page (unmapped) | no hidden clamp between guard and store |
| T2 | guard `LEN>u 0x80` fired → REAL panic block entered (msgid 0x86) | the guard's only-arm status; wrap is the bypass |
| T1 | misaligned DST aborted pre-write (alignment check live) | what a real defense looks like — absent for the sign |
| Z1 | probe-invalid routed per trace | the probe does not reject the arithmetic |

## Affected software

| Build | iBoot | pass-2 homing site (ldr KEY / sub DELTA / add DST) | guard (`sub x8,x0,x8; cmp; b.hi`) | copier | faulting copy |
|---|---|---|---|---|---|
| iOS 26.6 (23G71), mBoot-18000.162.8 | raw `0x199150` | `0x199954 / 0x199958 / 0x199964` | `0x1999b4..0x1999c0` → panic block `0x199bc0` (msgid `0x86`) | `FUN_00167D64` | thunk `FUN_0016B3E4` |
| iOS 26.6.1 (23G83), mBoot-18000.162.10 | +0x80 shift | `0x199b28 / 0x199b2c / 0x199b38` | `0x199b88..0x199b94` → block `0x199d90` | `FUN_00167F24` | thunk `FUN_0016B464` |
| iOS 27.0 (24A435), mBoot-20457.2.37 | `sub_1a41ec` (raw) | `0x1a3900..0x1a3914` (see §Recheck) | `0x1a39b8 / 0x1a39bc / 0x1a39c0 / b.hi 0x1a3bbc` | `sub_170f44` (raw `0x16ff44`) | memcpy `sub_170ab0` (ldrb/strb `0x16FBA8/AC`) |

## Root cause — instruction citations (162.8; 162.10 in parentheses)

```
KEY   ldr x9,[x25,#0x30]!            @0x199954 (0x199b28)   = *(obj+0x30)   <- record stream
DELTA sub x9,x8,x9                   @0x199958 (0x199b2c)   = rec.base - KEY (attacker signed)
WBASE ldr x8,[x23,#-0x18]!           @0x199960 (0x199b34)   = *(obj+0x18)
DST   add x27,x8,x9                  @0x199964 (0x199b38)   = WBASE + DELTA  <- attacker arithmetic
LEN   add x8,x0,#3 ; and x22,x8,#-4  @0x199974 (0x199b48)   = align4(V+3)
probe REAL FUN_0019912C(DST)         @0x199980 (0x199b54)
E     REAL FUN_0019a770(o+0x18,o+0x18,o+0x30) @0x1999ac     = *(o+0x20)-*(o+0x18)
GUARD sub x8,x0,x8 ; cmp x9,x8 ; b.hi -> msgid 0x86 panic    @0x1999b4..c0 (0x199b88..94)
      ^ ONLY check: LEN >u (E - DELTA). DELTA<0 wraps RHS to ~2^64 => PASSES.
fence REAL dest quad FUN_0019A444 -> {DST,DST,DST+LEN}       @0x1999d4..a18  self-fence = vacuous
copy  REAL FUN_00167d64(dstslice,srcslice,LEN)               linear write of decoded content at DST
```

Negative DELTA is never rejected anywhere between record parse and store: the
in-window fast-path test (`cmp x10,x27; b.eq skip`) only fires on EXACT
equality with the prior destination; the probe is an address-translate check
(page-mapped = pass), not a window-membership check.

## Delivery (27.0 chain, per `../DELIVERY_PATHS_24A435.md` §0)

The pass-2 consumer chain on 24A435 is reached from `sub_1a4cd8` (the P4
kernelcache/Mach-O map handler) — whose second arm `sub_1e2290` is the **'splt'
staged-container CRC-FAILURE fallback**. Report 4's gate is an unkeyed CRC-32
that excludes chunk payloads, so attacker-forged staged bytes reach this record
homing with BOTH the record words (KEY/PB) and the decoded content under
attacker control. Same unauthenticated-bytes premise as Reports 1–3; the wrap
adds a **negative-direction** write (all decoder bugs overrun forward).

## 27.0 (24A435) recheck — NEW this round

First re-verification of Report 5 against `mBoot-20457.2.37` (the prior RECHECK
covered Reports 1–4, 6 only). The old byte-identical `ldr x9,[x25,#0x30]!` form
is gone (0 occurrences of the 4-byte encoding image-wide) — the function was
recompiled/restructured and lives at raw `0x1a31ec`–`0x1a3bxx`; located via the
guard micro-pattern `sub x8,x0,x8` (0xCB080008). Verdict: **STILL PRESENT**:

```
0x1a3900  mov x19,x21
0x1a3904  ldr x11,[x19,#0x18]!     ; WBASE = *(obj+0x18)
0x1a390c  ldr x8,[x19,#0x28]
0x1a3910  sub x10,x10,x8           ; DELTA = PB - KEY (attacker signed)
0x1a3914  add x8,x11,x10           ; DST = WBASE + DELTA
0x1a3918  cmp x8,x9 ; b.eq skip    ; only the equality fast-path survives
0x1a3920  stp x9,x10,[sp,#0xa0]    ; DELTA parked at sp+0xa8
...
0x1a39b4  bl 0x1a491c              ; E = extent math (old FUN_0019A770)
0x1a39b8  ldr x8,[sp,#0xa8]        ; DELTA
0x1a39bc  sub x8,x0,x8             ; E - DELTA  (WRAPS for DELTA<0)
0x1a39c0  cmp x28,x8               ; LEN >u ...
0x1a39c8  b.hi 0x1a3bbc            ; guard-fail -> msgid 0xd5 panic block (0x1a3bb0)
0x1a39dc  bl 0x1a43e0              ; dest quad builder (old FUN_0019A444)
0x1a39e0  bl 0x16ff44              ; copier (old FUN_00167D64) -> memcpy sub_170ab0
```

The window-member/extent getters moved from obj `+0x18/+0x20/+0x30` to
`+0x50/+0x68` accessors (`add x0,x26,#0x50 ... bl 0x1a491c`) — bookkeeping, not
policy. **No signedness test was added to DELTA on 27.0.** The guard-fail block
emits msgid `0xd5` (was `0x86`); the equality fast-path remains the only other
DST-dependent decision. Harness retarget (`set_offs(2)` in homing.c) pending —
the live 24A435 matrix will reproduce N1 identically since the guard is
structurally unchanged (this table is the current evidence).

## Harness + reproduction

```bash
# /tmp/ds_iboot/iboot_dec.bin           = 162.8 (bvx2 LZFSE-decode of iBoot.v59 im4p)
# /tmp/ds_iboot/23g83/iboot_dec_23g83.bin = 162.10
clang -O2 -arch arm64 -o homing homing.c
DS_FW=/tmp/ds_iboot/iboot_dec.bin            DS_RUN=1 ./homing calib
DS_FW=/tmp/ds_iboot/iboot_dec.bin            ./homing matrix   > retest_1628_matrix_run1.log
DS_FW=/tmp/ds_iboot/23g83/iboot_dec_23g83.bin ./homing matrix  > retest_23g83_matrix_run1.log
DS_FW=/tmp/ds_iboot/iboot_dec.bin            ./homing flagship
DS_FW=/tmp/ds_iboot/iboot_dec.bin            ./homing emitpoc  # poc_*.bin = record-field dumps (96B struct + content)
```

Read-offs: `[parent] VERDICT N1: NEGATIVE-DELTA WRITE LANDED` + `dst-head @<below-anchor>`
showing the `HMG#` marker quads = the wrap write executed; `marker-bytes-present=1`
with `fence-intact: below=1 above=1` proves the content went exactly at DST and the
surrounding sentinels survived (single bounded record-length write, not a runaway).
T2 receipt `entering REAL panic block` with `LEN>u(rhs)=1` proves the guard is the
sole line of defense and its ONLY failure mode is the (unreachable-by-attacker)
positive-side wrap.

## Files

- `homing.c` — harness (LEVEL-B: real probe/FUN_0019A770/dest-quad/copier/panic executed from mapped firmware)
- `retest_1628_matrix_run{1,2,3}.log`, `retest_23g83_matrix_run{1,2,3}.log` — full matrices
- `emitpoc.log` + `poc_<cell>.bin` (`/private/tmp/ds_iboot/Report5_HOMING/`) — per-cell record dumps with field annotations (`poc_fields.txt`)
- `dsdis.py` — capstone helper used for the offset tables
