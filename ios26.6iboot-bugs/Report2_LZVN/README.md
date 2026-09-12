> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# iBoot LZVN decoder writes far beyond the caller's output capacity on attacker-crafted input (heap buffer overflow)

## Summary

iBoot's LZVN decompressor (dispatcher algorithm ids `0x101` raw and `0x100`
`bv4`-container) bounds its match/literal copies against an output-limit value
that does not track the caller-provided destination capacity. A 2-byte crafted
input (`0F 41`) decoded into a 4 KB output buffer makes firmware code dirty
65,536 bytes past the end of every tested capacity (64 B / 256 B / 1 KB / 4 KB —
span is always exactly `capacity + 0x10000`), continuing until an unmapped page
stops it. The raw id-`0x101` path faults with SIGBUS (READ side of the copy
loop); the container path (id `0x100`, 18-byte file) faults with SIGSEGV at the
same instruction. Reproduced live against both shipping builds with identical
firmware-side receipts, including replay of the on-disk PoC container from disk.

## Affected software

| Build | Firmware image | Dispatcher entry | LZVN frame driver `bl` (LR site) | LZVN core entry | Match-copy `memcpy` call (return addr) | Thunk faulting instr |
|---|---|---|---|---|---|---|
| iOS 26.6 (23G71), mBoot-18000.162.8 | `/tmp/ds_iboot/iboot_dec.bin` | `+0x1EB3C8` | `+0x1E8DBC` → LR `+0x1E8DC0` | `+0x200F6C` | `+0x20101C` → LR `+0x201020` | `ldrb` `+0x16B3E4` |
| iOS 26.6.1 (23G83), mBoot-18000.162.10 | `/tmp/ds_iboot/23g83/iboot_dec_23g83.bin` | `+0x1EB448` | `+0x1E8E3C` → LR `+0x1E8E40` | `+0x200FEC` | `+0x20109C` → LR `+0x2010A0` | `ldrb` `+0x16B5A4` |

## Root cause

The frame driver that invokes the LZVN core computes the output-end argument
from its own length state, and no comparison against the caller's actual
destination capacity appears anywhere on this path. The core then trusts it.

Build 162.8 (old), frame driver → LZVN core:

```
+0x1e8d34:  cmp   x1, #0x81             ; arg1 = output LENGTH (from caller above)
+0x1e8db0:  mov   x0, sp                ; &dst cursor
+0x1e8db8:  mov   x1, x19               ; dst base
+0x1e8dbc:  bl    +0x200f6c             ; LZVN core; x2 = x19+x22 = OUTPUT END
                                        ; LR = +0x1e8dc0 (logged backtrace bt[1])
```

LZVN core (both builds; new at `+0x80`):

```
+0x200fd0:  mov   x24, x4               ; src end
+0x200fd4:  mov   x23, x2               ; OUTPUT END = arg2, trusted
+0x200ff4..:     sub/cmp/b.lo          ; in-loop copies bounded only by x23
```

Match copies go through the shared `memcpy` thunk:

```
+0x201018:  mov   x2, x26               ; match length            (162.8)
+0x20101c:  bl    +0x16b2f0             ; memcpy; LR = +0x201020 (logged bt[0])
...thunk byte tail:
+0x16b3e4:  ldrb  w6, [x1], #1          ; FAULTING LOAD (PC logged here)
+0x16b3e8:  strb  w6, [x3], #1
```

Build 162.10 (new): identical instructions at `+0x80` — driver `bl +0x200fec`
@ `+0x1E8E3C`, match-copy `bl` @ `+0x20109C`, thunk `ldrb` @ `+0x16B5A4`.

The wrong check, precisely: the bound threaded into the LZVN core (`arg2`,
held in `x23`) is *not* derived from the caller's destination capacity.
Behavioral proof: observed write span = `capacity + 0x10000` bytes for every
capacity tested (64 B → 4 KB), i.e. the effective granted window exceeds the
caller's buffer by at least 64 KB in all configurations; the copy never stops
on its own — only the first unmapped page ends it.

## Reproduction

1. Build the harness: `clang -O2 -arch arm64 -o qsweep qsweep.c -lcompression`
2. OOB-write battery vs OLD build (default env): `./qsweep b0w > retest_1628_b0w_run1.log 2>&1`
   — four cells (`dcap=64/256/1024/4096`, raw LZVN via id `0x101`) plus the
   container cell; each decisive case repeated in 3 separate log files.
3. Same battery vs NEW build:
   `DS_FW=/tmp/ds_iboot/23g83/iboot_dec_23g83.bin ./qsweep b0w > retest_23g83_b0w_run1.log 2>&1`
4. On-disk PoC replay through id `0x100` (3 runs per build):
   `./qsweep pocv0 poc_v0.bin`
   Expected observable: `field check ... -> MATCH` then a fault at
   `pc_off=16b3e4` (old) / `16b5a4` (new), **sig=11 (SIGSEGV)**,
   `dirty-span=[0..69632)`, `OOBpast4K=65536`.
5. Signal precision to expect: direct/raw cells (id `0x101`, the `b0w dcap=`
   lines) fault with **SIGBUS (sig=10)**; the container path (id `0x100`,
   `poc-v0`/`pocv0-from-file` lines) faults with **SIGSEGV (sig=11)** — same
   faulting instruction, different fault classification by address context.
6. Control: the zlib-wrapped stored-block control cell (`poc-v1`, id `0x505`)
   completes cleanly (`faulted=0`), isolating the defect to the LZVN path.

## Evidence

Quotes from this round's fresh logs. Old build, `retest_1628_b0w_run1.log`:

- L5: `b0w dcap=64 faulted=1 sig=10 pc_off=16b3e4 addr-vs-dst=-1212416 dirty-span=[0..65600) capSpanOOB=65536 hiApronDirty=1`
- L17: `b0w dcap=4096 faulted=1 sig=10 pc_off=16b3e4 ... dirty-span=[0..69632) capSpanOOB=65536 hiApronDirty=1`
- L25: `poc-v0 id=0x100 sn=18 faulted=1 sig=11 pc_off=16b3e4 ... dirty-span=[0..69632) OOBpast4K=65536 hiApronDirty=1`
- L26: `poc-v1 id=0x505 sn=23 faulted=0` (control)

New build, `retest_23g83_b0w_run1.log`: L5/L17/L25 identical except
`pc_off=16b5a4` (the `+0x80` shift). On-disk replay,
`retest_23g83_pocv0_x3.log`: L8 `[pocv0] field check: magic=bv41 end=bv4$ out=64 paylen=2 payload=0f 41 -> MATCH`,
L12 `pocv0-from-file id=0x100 sn=18 faulted=1 sig=11 pc_off=16b5a4 ... dirty-span=[0..69632) OOBpast4K=65536 hiApronDirty=1`.

Determinism: across 3 runs per build, signal class, `pc_off`, dirty-span,
`capSpanOOB=65536` / `OOBpast4K=65536`, and `hiApronDirty=1` are identical.
The `addr-vs-dst` field varies between processes because the runaway copy stops
at whichever unmapped host page it reaches first — a host-layout artifact,
excluded from the determinism claim. The regenerated `poc_v0.bin` (harness dump)
is sha256-identical to the shipped artifact
(`a0c057ce...55d8d30`), proving the on-disk PoC is exactly what the decoder consumed.

## Exploitability analysis

Primitive: a linear heap buffer overflow whose **length is effectively unbounded
by the destination** (writes continue ≥64 KB past any tested capacity until an
unmapped page). Contents are decompressor-derived: literal bytes come from the
input stream (attacker-chosen), match copies duplicate previously-written
output, so an attacker controls content over large stretches while the tail of
the runaway run repeats structure — sufficient for corrupting adjacent objects
with chosen data patterns, not for a single-shot arbitrary-pointer overwrite by
itself.

Constraints: strictly forward linear overwrite starting at the output buffer;
no offset addressing; termination is by unmapped-page fault (so in-process
survivability depends on heap layout, but corruption of everything between
buffer end and the next unmapped region happens regardless).

Attacker positioning and delivery context, honestly stated: these decoders are
selected by parsed algorithm ids on iBoot's staged-container (`splt`) path whose
input arrives during manufacturing/upgrade ("combo") staging handoff;
standard-boot image loads verify signatures before decompression, so no remote
attacker path is demonstrated (27.0 audit: entry set CLOSED at four paths,
decode-before-verify tested NEGATIVE on P1 — `../DELIVERY_PATHS_24A435.md` §4e). An attacker positioned to influence staged or
upgrade-time content gains a large linear overflow in privileged boot code:
adjacent boot-state objects can be corrupted deterministically during staging,
yielding persistence/trust-anchor tampering or a reliable boot DoS from a
tiny (18-byte) input. Severity reasoning: memory-safety violation in the
highest-privilege firmware stage, gated behind the staging attack position
rather than remote reachability.

## Target Flag note

The bounty guidelines define Target Flags for Commpage compromise
(userspace→kernel escalation primitives) and TCC database compromise; neither
concept exists in boot-loader research, and iBoot has no commpage surface. As
the guidelines direct for research areas without applicable Target Flags, the
detailed exploitability analysis above accompanies this report instead.

## Validation method disclosure

All evidence comes from executing the genuine shipped iBoot images mapped from
the official IPSW payloads under instrumentation — guard pages, marker aprons,
and SIGSEGV/SIGBUS handlers logging firmware-relative PC/backtrace offsets.
Not emulation, not fuzzing claims: each cited cell was executed ≥3 times against
each build with identical firmware-side receipts, and the on-disk PoC container
was verified hash-identical to the in-memory stream the decoder consumed.
Cross-checked statically by disassembling both shipping builds at the cited
offsets; the inter-build delta is exactly the documented `+0x80` cluster shift.

## File manifest

| File | Purpose |
|---|---|
| `poc_v0.bin` | 18-byte `bv41` container wrapping the 2-byte LZVN trigger `0F 41`; sha256 `a0c057ce90245b185da459a0a2af3aa5c2689a063ef6791fe2bf46dfe55d8d30`; regenerated by the harness during retest and hash-identical |
| `qsweep.c` | Harness source used for this round (modes `b0w`, `pocv0`; `DS_FW` selects build, unset = 162.8) |
| `retest_1628_b0w_run{1,2,3}.log` | Fresh OOB-write battery vs 162.8 |
| `retest_23g83_b0w_run{1,2,3}.log` | Fresh OOB-write battery vs 162.10 |
| `retest_1628_pocv0_x3.log` | On-disk PoC replay ×3 vs 162.8 |
| `retest_23g83_pocv0_x3.log` | On-disk PoC replay ×3 vs 162.10 |
| `run_23g83_b0w.log` | Earlier-session capture (context only; claims above cite fresh `retest_*` logs) |

Rebuild: `clang -O2 -arch arm64 -o qsweep qsweep.c -lcompression`.
