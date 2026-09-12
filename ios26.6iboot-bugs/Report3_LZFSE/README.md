# iBoot LZFSE (bvx1) match copier reads below the output buffer start without a lower-bound check (out-of-bounds read / information disclosure into decoded content)

## Summary

iBoot's LZFSE `bvx1` block decoder resolves LZ77 match sources as
`dst_begin + produced_count - distance` and never validates the result against
the start of the output buffer. A crafted two-block stream — one warm block to
advance the produced counter, then a hostile block whose match distance exceeds
the bytes actually produced — makes the match copier read attacker-selected
memory *below* the destination buffer and emit it verbatim into the trusted
decoded output. Within mapped memory this is completely silent (adjacent-memory
disclosure); at an unmapped page it faults deterministically inside the copier's
word-load instruction (`+0x1EA188` old build / `+0x1EA208` new build). Distances
are attacker-chosen up to 262,139 (the firmware distance table maximum), giving
byte-granular positional selection of what gets disclosed. Reproduced live
against both shipping builds, through both the direct decode core and the
staged dispatcher path, including replay of on-disk PoC files.

## Affected software

| Build | Firmware image | Dispatcher entry | Match-copier function | Faulting word load | Decode core |
|---|---|---|---|---|---|
| iOS 26.6 (23G71), mBoot-18000.162.8 | `/tmp/ds_iboot/iboot_dec.bin` | `+0x1EB3C8` | `FUN_+0x1EA100` (`bti c`) | `ldr w8,[x10]` @ `+0x1EA188` | `FUN_+0x1E908C` |
| iOS 26.6.1 (23G83), mBoot-18000.162.10 | `/tmp/ds_iboot/23g83/iboot_dec_23g83.bin` | `+0x1EB448` | `FUN_+0x1EA180` (`bti c`) | `ldr w8,[x10]` @ `+0x1EA208` | `FUN_+0x1E910C` |

## Root cause

The match copier computes the source address for each copied byte from the
attacker-controlled distance and loads it with an aligned 32-bit load; there is
no comparison of that address against `dst_begin`. Build 162.8:

```
+0x1ea140:  ldr   x11, [x20, #0x10]     ; window bound from copier context
+0x1ea144:  ldr   x12, [x20]            ; dst_begin (output base)
+0x1ea150:  sub   x9,  x11, x9          ; produced-count bookkeeping
+0x1ea154:  add   x10, x9,  x8          ; x10 = byte offset of source (can go NEGATIVE)
+0x1ea15c:  and   x13, x10, #~3         ; word-align: floor4(offset)
+0x1ea160:  add   x10, x12, x13         ; candidate src word address = base + floor4(off)
+0x1ea174:  cmp   x10, x11              ; compare against upper/window bound...
+0x1ea178:  b.lo  +0x1ea188             ; ...and branch INTO the load — no lower bound
+0x1ea188:  ldr   w8, [x10]             ; FAULTING WORD LOAD (PC logged here)
+0x1ea18c:  lsl   w9, w9, #3            ; sub-word rotate/shift extraction follows:
+0x1ea190:  lsr   w8, w8, w9            ; reads are word-granular u32 loads
```

Build 162.10 is instruction-identical at `+0x80`: offset math at
`+0x1EA1D0..+0x1EA1E0`, `cmp/b.lo` @ `+0x1EA1F4/+0x1EA1F8`, faulting
`ldr w8,[x10]` @ `+0x1EA208`.

Missing check: `dst_begin + produced - distance >= dst_begin`, i.e. clamp
`distance <= produced`. When `distance > produced` the source lies below the
buffer; within mapped memory the load succeeds silently and the fetched bytes
are shifted/masked into the output stream (information disclosure); only an
unmapped page turns it into a visible fault. The aligned-u32 addressing also
means the effective granularity is words: a logical read at delta −5 touches
address `begin−8` (floor4(−5)·4).

## Reproduction

1. Build the harness: `clang -O2 -arch arm64 -o qsweep qsweep.c -lcompression`
2. Evidence battery vs OLD build (default env):
   `./qsweep leakpoc > retest_1628_leakpoc_run1.log 2>&1`
   Runs: (A) silent-leak cells at distances `D=P+L+1 .. P+L+9` (=48..56, where
   P=32 warm-block output and L=15 literals precede the first match) through
   both the direct core and staging id `0x8A1`; (B) the large-D fault cell
   (`D=262139`); (C) writes the PoC files into this folder.
3. Same battery vs NEW build:
   `DS_FW=/tmp/ds_iboot/23g83/iboot_dec_23g83.bin ./qsweep leakpoc > retest_23g83_leakpoc_run1.log 2>&1`
4. Replay the on-disk PoCs like Reports 1–2 (3 runs per build per file):
   - `./qsweep poclf poc_lzfse_oobread.bin` → decodes cleanly,
     `FOREIGN-A5-BYTES=2 first@47` (silent adjacent-memory disclosure).
   - `./qsweep poclf poc_lzfse_fault.bin` → `sig=10 pc_off=1ea188` (old) /
     `pc_off=1ea208` (new), `addr-vs-dstbegin=-262092`.
5. Expected observables: leak cells report `FOREIGN-A5-BYTES=N first@47` with N
   deterministic per distance; the large-D cell reports SIGBUS at exactly the
   copier word-load offset with delta −262092 relative to buffer start.
6. Repeat ≥3 times per build; all firmware-side receipts identical.

## Evidence

All quotes from this round's fresh logs.
`retest_1628_leakpoc_run1.log` (old build):

- L4–L12: `D= 48: ret=124 faulted=0 FOREIGN-A5-BYTES=2 first@47` … `D= 56: ... FOREIGN-A5-BYTES=8 first@47` (direct core)
- L14–L22: same nine distances via staging id `0x8A1` — identical counts
- L26: `D=262139 direct     ret=-9999 faulted=1 sig=10 pc_off=1ea188 FAULTSITE=copier-load(0x1ea188) delta-vs-begin=-262092`
- L29: `D=262139 disp-0x8A1 ret=-9999 faulted=1 sig=10 pc_off=1ea188 ... delta-vs-begin=-262092`
- L31/L34: `[poc_lzfse_oobread.bin] wrote 1612 bytes` / `distance D=48 -> dist-symbol=14 base(TB_D_BASE[sym])=44 extra=4 extra-bits(W)=3`
- L40/L43: `[poc_lzfse_fault.bin] wrote 1612 bytes` / `distance D=262139 -> dist-symbol=63 base=229372 extra=32767 extra-bits(W)=15`

New build, `retest_23g83_leakpoc_run1.log`: L4–L29 byte-identical except the
fault site shifts `1ea188 → 1ea208` (the documented `+0x80`). On-disk replay ×3:
`retest_1628_poclf_fault_x3.log` and `retest_23g83_poclf_fault_x3.log` show
`sig=10 pc_off=1ea188/1ea208 addr-vs-dstbegin=-262092` in all six runs;
`retest_*_poclf_leak_x3.log` show `FOREIGN-A5-BYTES=2 first@47` in all runs,
direct and id-`0x8A1` alike.

Determinism: signal class, `pc_off`, `delta-vs-begin=-262092`, per-distance
leak-byte counts {48→2, 49→4, 50→6, 51→7, 52→7, 53→7, 54→7, 55→8, 56→8}, and
`first@47` are identical across ≥3 runs per build and across both decode paths.
No host-dependent values are used in any claim above.

## Exploitability analysis

Primitive: an **out-of-bounds READ** with full positional control — the
attacker picks the distance symbol/base/extra-bits (up to D_max=262139) and the
copier emits the addressed bytes into the decoded output stream, which iBoot
then treats as trusted decompressed content. Reads below the buffer can walk
arbitrary earlier heap memory (any offset reachable by repeated blocks: the
positional sweep construction extracts chosen windows from multiple deltas in a
single stream). Content control: none over the leaked bytes themselves; the
attacker chooses *where* to read, not *what* is there. No write primitive is
involved.

Constraints: strictly backward reads from the output buffer; disclosure lands
in decoded content, so it must survive whatever parsing/consumption follows
(iBoot does not transmit decoded staging content off-device, which limits
practical exfiltration); word-granular alignment (floor4) truncates low 2 bits
of positioning; silent operation requires the target page to be mapped —
otherwise the run faults instead of disclosing.

Attacker positioning and delivery context, honestly stated: these decoders are
selected by parsed algorithm ids on iBoot's staged-container (`splt`) path whose
input arrives during manufacturing/upgrade ("combo") staging handoff;
standard-boot image loads verify signatures before decompression, so no remote
trigger is demonstrated (27.0 audit: entry set CLOSED at four paths,
decode-before-verify tested NEGATIVE on P1 — `../DELIVERY_PATHS_24A435.md` §4e). Within the staging position, the defect discloses
adjacent privileged boot heap into decoded content — a confusion/
info-disclosure primitive inside the trust boundary rather than a code-execution
path. Severity reasoning: a deterministic, attacker-positioned OOB read in
privileged boot code; realistic impact is corruption of the confidentiality of
boot-time memory during staging (and reliable fault/DoS when the read crosses
into unmapped pages), not direct privilege escalation by itself.

## Target Flag note

Apple's Target Flags cover Commpage compromise (userspace/kernel escalation
primitives) and TCC database compromise; neither mechanism applies to iBoot
research — iBoot exposes no commpage and has no TCC subsystem. Following the
guidelines' requirement for research areas without applicable Target Flags, the
detailed exploitability analysis above is provided in place of a Target Flag
claim.

## Validation method disclosure

All evidence comes from executing the genuine shipped iBoot binaries from the
official IPSW payloads under instrumentation: PROT_NONE guard pages below/above
marker-filled aprons (lower apron pre-filled with a known marker byte so
disclosed foreign bytes are countable and attributable), and SIGSEGV/SIGBUS
handlers logging firmware-relative PC/backtrace offsets. Live execution of real
decoder instructions — not emulation, not fuzzing claims. Every cited cell was
run ≥3 times per build with identical receipts, and static disassembly of both
shipping builds confirms the missing lower-bound check at the exact offsets the
dynamic PC evidence names.

## File manifest

| File | Purpose |
|---|---|
| `poc_lzfse_oobread.bin` | 1612-byte replayable stream: `[bvx1 warm blk 804B | bvx1 hostile blk 804B (dist sym 14, base 44, extra 4, W 3 → D=48) | 'bv4$']` — silent adjacent-memory disclosure |
| `poc_lzfse_fault.bin` | Same structure with dist sym 63 (base 229372, extra 32767, W 15 → D=262139) — guard-page fault witness at the copier load |
| `qsweep.c`, `build_qsweep.sh` | Harness source + build script for this round (modes `leakpoc`, `poclf`; `DS_FW` selects build, unset = 162.8) |
| `retest_1628_leakpoc_run{1,2,3}.log` | Fresh battery vs 162.8 (leak cells + fault receipt + PoC dumps/annotations) |
| `retest_23g83_leakpoc_run{1,2,3}.log` | Fresh battery vs 162.10 |
| `retest_1628_poclf_leak_x3.log`, `retest_1628_poclf_fault_x3.log` | On-disk PoC replays ×3 vs 162.8 |
| `retest_23g83_poclf_leak_x3.log`, `retest_23g83_poclf_fault_x3.log` | On-disk PoC replays ×3 vs 162.10 |
| `run_23g83_val_leak_q1.log` | Earlier-session capture (context only; claims above cite fresh `retest_*` logs) |

Rebuild: `clang -O2 -arch arm64 -o qsweep qsweep.c -lcompression`.
Replay: `./qsweep poclf poc_lzfse_oobread.bin` (leak) ·
`DS_FW=/tmp/ds_iboot/23g83/iboot_dec_23g83.bin ./qsweep poclf poc_lzfse_fault.bin` (fault, new build).
