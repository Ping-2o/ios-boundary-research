> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# iBoot NVRAM persisted-state integrity: bank images are guarded only by forgeable checksums (no keyed MAC in the store path) — mBoot-18000.162.8 / 18000.162.10

> **Vendor disposition — Apple Product Security, OE1107324358640 (submitted 31 Aug 2026, closed 01 Sep 2026).**
> **Closed as not actionable.** Apple did not dispute the checksum analysis; it rejected the
> report for lacking a demonstrated user-visible consequence:
> *"This is not an actionable security report without evidence of it reproducing a security or
> privacy impact to a user on-device."* — and, on the bar for this class:
> *"An actionable report is clear, concise and outlines and demonstrates a security or privacy
> issue that causes an impact to a user. It should be demonstrated on-device, and on the latest
> version of iOS or macOS."*
>
> Read this report as a **design/integrity observation with no demonstrated on-device impact**.
> The core claim below — no keyed seal exists at any hop of the persisted bank path, proven with
> real firmware code — stands; what is missing is a path from "a writable session can re-seal a
> bank" to an actual security or privacy effect on a device.

## Summary

iBoot's persistent NVRAM variables (`boot-command`, `auto-boot`, `one-time-boot-command`,
`bootdelay`, `boot-args`, `security-mode-change-enable`, … — consumed on every cold boot at
the highest boot privilege) are persisted as *bank images* whose entire integrity protection
is two unkeyed checksums:

* a per-record **8-bit additive fold** (`FUN_001709E8` / `FUN_00170BA8`) over each TLV
  entry's first 16 bytes, and
* an image-wide **Adler-32 mod 0xFFF1** (`FUN_00158FEC` / `FUN_001591A4`) over the record
  area `[hdr+0x14, size)` stored at `hdr+0x10`.

There is no MAC, no signature, and no key derivation anywhere between the serializer that
produces a bank image and the load-side verifier that accepts it. This PoC demonstrates, by
executing the REAL shipped firmware code (not reimplementations), that any attacker-writable
session can (a) author policy content into the real format, (b) tamper a policy byte of an
existing valid-looking image, (c) re-seal it with the REAL checksum functions so that every
integrity check iBoot performs on the next cold boot PASSES. The monotonic sequence counter
defends only against naive replay: it is a plain integer inside the (forgeable) Adler
coverage; re-sealing any chosen sequence value is proven to pass. **Retraction/correction
(09-12, per `../DELIVERY_PATHS_24A435.md` §4c):** the earlier claim that the protected-name
enforcement wrapper "has zero references (dead code)" is a **table-dispatch tooling
artifact**, not a finding: `setenv` command surfaces live in **iBEC**, whose handler tables
are data-dispatched (`sh_memboot` itself has zero code callers by the same method), and on
27.0 the name-materializer `sub_15cd34` has four callers chaining to the `boot-command`
consumer. The live `setenv boot-command` refusal was therefore the gate working as
designed. The durable claim of this report is unaffected and stands alone: **no keyed
seal exists at any hop of the persisted bank path** — forge, re-seal, and cold-boot
acceptance are proven with REAL firmware code; the targeted names should be ones the
design list does not protect (e.g. `auto-boot-once`).

## Affected software

| Item | mBoot-18000.162.8 (`iboot_dec.bin`) | mBoot-18000.162.10 (`iboot_dec_23g83.bin`) | delta |
|---|---|---|---|
| Bank-image serializer | `FUN_0016FB78` @0x16fb78 | `FUN_0016FD38` | +0x1C0 |
| Commit entry (mutex magic 0x3C4E5653) | `FUN_0016FA4C` @0x16fa4c | `FUN_0016FC0C` | +0x1C0 |
| Commit-with-explicit-store helper | `FUN_00170CC0` @0x170cc0 | `FUN_00170CC8` | +0x8 |
| Adler-32 mod 0xFFF1 | `FUN_00158FEC` @0x158fec | `FUN_001591A4` | +0x2B8 |
| 8-bit record fold | `FUN_001709E8` @0x1709e8 | `FUN_00170BA8` | +0x1C0 |
| Load-side bank verifier | `FUN_0016FFA0` @0x16ffa0 | `FUN_00170160` | +0x1C0 |
| Per-bank pre-read/header check | `FUN_00170438` @0x170438 | `FUN_001705F8` | +0x1C0 |
| DT-prop consumption (nvram-bank-size/count/current-bank/proxy-data/raw/nor) | `FUN_001725C4` @0x1725c4 | `FUN_00172798` | +0x1D4 |
| Bank selector | `FUN_00173700` @0x173700 | — | n/a (same chain) |
| Storage READ (svc 0x62) | `FUN_001C2948` @0x1c2948 (svc @0x1c2978) | same address | 0 |
| Storage WRITE (svc 0x62 / svc 0xC5) | `FUN_001C3154` @0x1c3154 (svc @0x1c3174) | same address | 0 |
| Protected-name table | 0x2038C0 | 0x203950 | +0x90 |
| Protected-name consumer | `FUN_00003A28` @0x3a28 | same address | 0 |
| Dead-gate caller | `FUN_0015E05C` @0x15e05c — **ZERO xrefs** | `FUN_0015E21C` — **ZERO xrefs** | +0x1C0 |

Zero-xref status verified via Ghidra `get_xrefs_to(FUN_00003a28)` (→ exactly one caller,
the dead-gate wrapper) plus `get_xrefs_to(FUN_0015e05c)` / `get_xrefs_to(FUN_0015e21c)`
→ `count=0` in both programs.

## Root cause

Integrity of persisted boot policy rests entirely on unkeyed sums:

* Record fold — decompilation of `FUN_001709E8`/`FUN_00170BA8`: seeds with the tag byte,
  adds bytes `[entry+2, entry+F]` (14 bytes), folds >0xFFFF down to a byte:
  `uVar1 = uVar1 + *pbVar2; … for (; 0xff < (uVar1 & 0xffff); uVar1 = (uVar1>>8&0xff)+(uVar1&0xff))`.
  Called four times per image by the serializer (header / `/common` / `/system` /
  filler) and re-computed per record by the verifier.
* Image Adler-32 — `FUN_00158FEC`/`FUN_001591A4`: classic `a|b<<16`, both reduced
  mod 0xFFF1; serializer stores the result at header+0x10
  (`stur w8,[x20,#0x10]`), verifier re-derives it and compares
  (`cmp w0,w8; b.ne 0x17045c` → log err 0x263, new build).
* Verifier record walk (new build receipts): fold compare
  `ldrb w8,[x21,#1]; cmp w8,w0,UXTB; b.ne 0x1704b8` → err 0x26c; filler break
  `cmp w8,#0x7f`; stride `len16<<4`.
* Neither function reads key material, device UID, or nonce state — they are pure
  functions of the image bytes (proven empirically: identical outputs from both builds'
  binaries for identical input).

Rollback defense is likewise unauthenticated: the monotonic sequence counter lives at
header+0x14, inside the (forgeable) Adler coverage, and its only loader-side consumer is
a plain comparison against a running best (`ldr w9,[x19,#0x14]; cmp w8,w9; b.cc skip`
at new-build 0x17020c–0x170214).

Protection-gate dead code: the protected-name table (5 PAC-signed pointer-pair entries)
is read solely by `FUN_00003A28`, whose only caller `FUN_0015E05C`/`FUN_0015E21C` has
zero references in both builds — no reachable code path enforces the name policy in this
binary.

## Reproduction

Prereqs: macOS arm64 host, clang, the extracted firmwares at
`/tmp/ds_iboot/iboot_dec.bin` (162.8) and `/tmp/ds_iboot/23g83/iboot_dec_23g83.bin`
(162.10).

1. Build:
   ```
   cd Report6_NVRAM
   clang -O2 -arch arm64 -o nvram nvram.c
   ```
2. Run the decisive set three times per build (DS_FW selects the target):
   ```
   for i in 1 2 3; do ./nvram . > retest_1628_run$i.log 2>&1; done
   export DS_FW=/tmp/ds_iboot/23g83/iboot_dec_23g83.bin
   for i in 1 2 3; do ./nvram . > retest_23g83_run$i.log 2>&1; done
   ```
   Cells: S1 authorship → V1 forged accepted by REAL checks → T1 tamper+reseal with REAL
   fns → V2 tampered-resealed ACCEPTED → X1 negative controls → Q1 sequence study.
3. The flow serialize→tamper→reseal→load-accept, as executed by the harness:
   * the session attempts to drive the REAL serializer end-to-end (receipt shows where
     execution stops outside boot context),
   * authors a format-exact 4096-byte bank image containing
     `boot-command=persistpoc;` at policy offset +0x30 of the `/common` partition with
     seq=42, seals every record including the 0x5A header with the REAL fold fn and the
     whole image with the REAL Adler fn → `poc_nvram_forged.bin`,
   * flips ONE payload byte deep inside `/common` (`0x40: 73->8c`) and re-seals using
     ONLY the REAL fns → `poc_nvram_tampered_resealed.bin`,
   * hands both back through the exact checks the load-side verifier performs
     (`Adler(img+0x14,size-0x14)==*(u32*)(img+0x10)` and `rec[1]==fold(rec)`) — both PASS.

## Evidence

Fresh receipt lines (abridged; full logs shipped):

```
== V1 validate FORGED image with REAL load-path checks ==
[V1] ADLER-check : real FUN_158FEC(img+0x14, size-0x14) = 8fe60d6c ; stored@hdr+0x10 = 8fe60d6c -> PASS
[V1] REC-check  : rec@0x20 tag=0x71 len16=192 stored_sum=0x32 real_FUN_1709E8=0x32 -> OK
[V1] REC-check  : rec@0xc20 tag=0x70 len16=48 stored_sum=0xa0 real_FUN_170BA8=0xa0 -> OK      [new-build line]

== T1 tamper ONE policy byte ... ==
[T1] flipped byte @0x40: 73 -> 8c (payload region of record tag 0x71)
[T1] RESEAL: recsum(FUN_1709E8)=(0x32) adler(FUN_158FEC)=19c40d85 patched rec[1]/hdr+0x10
[T1] determinism(x64 recompute): recsum STABLE adler STABLE

== V2 validate TAMPERED+RESEALED image with REAL load-path checks ==
[V2] ADLER-check : real FUN_158FEC(img+0x14, size-0x14) = 19c40d85 ; stored@hdr+0x10 = 19c40d85 -> PASS
[V2] REC-check  : ... -> OK  (all records)

== X1 negatives ==
[X1-noreseal] ADLER-check : ... -> FAIL          (unsealed flip rejected => checks not vacuous)
[X1] name-window flip @0x24: FOLD-CAUGHT ; ADLER-CAUGHT
[X1] deep-flip @0x41 (no reseal): shallow fold blind (window [rec+2,rec+F]); adler catches (deep-guard, unkeyed)

== Q1 sequence-counter study ==
[Q1] seq=42 (+0) PASS | seq=41 (-1) PASS | seq=43 (+1) PASS | seq=1073741823 PASS
```

Determinism: 3 independent invocations per build produce byte-identical checksums across
invocations AND across builds (`poc_nvram_forged.bin` sha256 identical after either
build's run); plus x64 intra-run recomputation receipts.

PoC hexdump head (`xxd poc_nvram_forged.bin | head -8`):
```
00000000: 5a5c 0200 0000 0000 0000 6cd60d8f 2a00 0000   Z\......l...*..
00000010: ................                             <- adler@+0x10, seq=42(0x2a)@+0x14
00000020: 7132 c000 ..                                  <- '/common' rec, sum=0x32
00000030: 'boot-command=persistpoc;'...
```
Full annotated parse in `poc_layout_annotated.txt`.

Live receipts for the supervisor boundary that fences in-process serialization:
```
[S1] FAULTED sig=SIGSYS pc_off=0x36f74 addr=0x104efaf74 (strategy A)     [162.8]
[S1] FAULTED sig=SIGSYS pc_off=0x36f9c addr=0x109ac6f9c (strategy A)     [162.10]
[S1] dependency-split receipt: ... FUN_1DC428 -> FUN_1DC3D4 -> early svc gate ...
     prefilled-arena re-entry reaches the REAL assert chain ending in halt `b .` @fw+0x43c
```

## Exploitability analysis

**Proven (live, real-code):**
1. Persisted policy consumed every cold boot (`boot-command`, `auto-boot`,
   `one-time-boot-command`, `bootdelay`, `boot-args`,
   `security-mode-change-enable`) has NO cryptographic authentication anywhere in
   iBoot's store path. Both integrity primitives are pure unkeyed byte functions,
   executed and verified live from this harness against BOTH shipping builds.
2. Any code able to write the backing storage can therefore mint or re-author fully
   valid-looking bank images — arbitrary chosen policy values (here
   `boot-command=persistpoc;` as a benign-but-nondefault one-time marker), arbitrary
   sequence numbers — such that iBoot's own cold-boot validation accepts them.
   Tamper-then-reseal is proven deterministic (3 runs/build, cross-build identical).
3. The attacker-facing write primitive itself sits behind the supervisor boundary
   (`FUN_001C3154`, `svc 0x62`/`svc 0xC5`); reaching it requires a privileged session
   context per sibling reports' delivery model (combo/SPTM-context research thread).
4. The name-protection layer is dead code in these builds (zero-xref wrapper) — within
   THIS binary nothing blocks authoring any variable name, while acknowledging caveat 6.

**Unproven / explicitly NOT claimed:**
5. Bypassing whatever enforcement caused the observed refusal of live `setenv
   boot-command` on a real device. That incident suggests enforcement may exist in the
   supervisor, storage layer, or another non-extracted component; we do not claim any
   bypass of it. The finding stands regardless: even when writes are granted through
   legitimate-but-buggy privileged channels (e.g., partial-erase/window bugs), the store
   layer provides no second wall because there is none to meet.
6. Physical NOR delivery is the single un-exercised hop here (Level-B split, see below);
   the commit call chain is documented functionally (serialize → `FUN_001C3154` → svc)
   but was not executed beyond the boundary.

**Delivery & impact framing:** requires an attacker-writable session at privileged-boundary
level (combo/firmware-research contexts consistent with sibling reports). Impact =
persistence of attacker-chosen boot policy/state across cold boots at the highest boot
privilege — a durable foothold amplifier rather than a standalone sandbox escape.

## Target Flag note

The Commpage/TCC flags target userspace/kernel escalation and TCC-database compromise
respectively; neither applies to bootloader persistent-state research. A detailed
exploitability analysis is provided above per reporting guidelines.

## Validation method disclosure

Standalone arm64 host harness (`nvram.c`) maps the shipped firmware images with the
proven MAP_PRIVATE pattern from Reports 1–4 (`[0,TEXT_SPLIT)` RX, rest RW + anon tail)
and executes selected REAL firmware functions directly (`FUN_158FEC`/`1591A4`,
`FUN_1709E8`/`170BA8`, serializer probe) inside guard windows (SIGSEGV/BUS/ILL/TRAP/
ABRT/SYS + 5 s watchdog). No reimplementation of any check occurs: every PASS/FAIL
verdict comes from the firmware's own instructions, fed faithful fences spanning each
checked buffer (these leaves assert buffer containment and divert violations into
iBoot's panic-halt loop `b .` @fw+0x43c — reproduced and cited during development).
Static claims are anchored to Ghidra disassembly/decompilation of both programs in a
read-only shared session; no mutating tool was used. Level-A/B split: the serializer's
full in-process execution stops at (a) its own heap-wrapper supervisor dependency
(SIGSYS at fw+0x36f74 / fw+0x36f9c) and (b) a prefilled-arena re-entry into the real
assert/halt chain — receipts quoted in logs; physical NOR write (`FUN_001C3154`)
was never exercised. Determinism: ≥3 independent runs per build shipped, plus x64
intra-run recomputation receipts, plus cross-build identity of all produced images.

## File manifest

| File | Purpose |
|---|---|
| `nvram.c` | Standalone PoC driver (cells S1/V1/T1/V2/X1/Q1) — single file, builds with clang |
| `nvram` (arm64 binary) | Built driver used for all shipped logs |
| `re_probe_min.c`, `re_probe_min` | Minimal isolated-execution probe (dev evidence: leaf calls need containment fences; determinism x1000) |
| `poc_nvram_forged.bin` | Authored valid-authority-looking bank image (seq=42, `boot-command=persistpoc;`, sealed with REAL fns) |
| `poc_nvram_tampered_resealed.bin` | Same image after ONE policy flip + reseal with REAL fns (accepted) |
| `poc_nvram_seq_minus1_resealed.bin` | Lower-sequence replay variant sealed with REAL fns (accepted by integrity layer) |
| `poc_nvram_seq_plus1.bin` | Higher-sequence variant sealed with REAL fns (accepted) |
| `poc_layout_annotated.txt` | Byte-by-byte annotated layout (TLV tags, sums, seq position, adler location, var markers) |
| `re_disasm_citations.txt` | Quoted disassembly/decompile citations incl. dead-gate xref counts (both builds) |
| `retest_1628_run{1,2,3}.log` | Decisive-set receipts, 162.8, 3 independent runs |
| `retest_23g83_run{1,2,3}.log` | Decisive-set receipts, 162.10, 3 independent runs |
| `re_devprobe_{1628,23g83}_run{1,2}.log` | Isolated leaf-function probes (stability x1000, both builds) |
