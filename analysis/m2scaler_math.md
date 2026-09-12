> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# M2ScalerCSC — size & geometry arithmetic audit (iOS 27.0 RC, 24A435)

**Target**: `com.apple.driver.AppleM2ScalerCSCDriver`, mac-aarch64, image `0xfffffff0075511d0`.
**Tool**: Binary Ninja (MCP) only. String/const references located with `scripts/ds_locate_strrefs.py`;
all instruction-level analysis and verdicts are from Binary Ninja.
**Build context**: `__TEXT_EXEC.__text` grew `0x13bbe0 → 0x1407e8` (+19,464) with zero new functions
and byte-identical `__const`/`__cstring`. No 23G71/23G83 kext is present on disk, so no byte-diff
baseline was available — this audit is single-build static re-verification.

## 0. Coverage & method limits (read first)

* 10,218 functions, fully stripped (only `mod_init_func_*` symbols survive). Data/string xrefs return
  empty, so every function below was located by **ADRP+ADD materialisation of a source-tagged log
  string** (`__func__` / `__FILE__` / format string) and then confirmed in Binary Ninja.
* A global "top-N functions by basic-block count" sort was **not** performed — it needs 11 pages of
  `bn_function_list` at 1,000 rows each. Large functions were instead enumerated from the
  `validate*` / `AppleM2ScalerCSCHal*` source tags. Coverage is therefore **namespace-complete for
  the geometry validators, not exhaustive for the whole kext**.
* Headless BN (`scripts/bn_query.py`) is unusable here: `RuntimeError: License is not valid`.
* Decompiler output was treated as untrusted for widths; **every width below was re-read in
  `bn_function_disassembly`.** This mattered — see §1.

Functions characterised (sorted by basic blocks):

| Function | BB | Identified as | Size math? |
|---|---|---|---|
| `sub_fffffff0090d3ec0` | 160 | capabilities publisher (`IOSurfaceAcceleratorCapabilities*`) | none |
| `sub_fffffff0090f0dc8` | 124 | `dumpSrcOrDstTransform` (`AppleM2ScalerCSCDriver.cpp:0x1aa7`) | none (pure logging) |
| `sub_fffffff009090ec8` | 69 | `IosaTiledCompressedMemMSR8.cpp` `validateCompressedTileBuffers` | **yes, 64-bit** |
| `sub_fffffff0090a5788` | 41 | `validateBorderFill`-adjacent | not audited |
| `sub_fffffff0090ac3e8` | 41 | `IosaColorManagerMSR23.cpp` histogram path | **yes, 32-bit** |
| `sub_fffffff0090cd7c8` | 39 | `AppleM2ScalerCSCHalMSR25.cpp` `validateDimensions` | index shifts only |
| `sub_fffffff0091321c4` | 31 | `AppleM2ScalerCSCHalMSR15.cpp` `validateXYOffsets` | **yes, 32-bit** |
| `sub_fffffff00909a87c` | 28 | `IosaColorManagerMSR4.cpp` `validateHistogram` | **yes, 32-bit** |
| `sub_fffffff0090d4fb0` | 25 | `AppleM2ScalerCSCHal.cpp` `validateDimensions` | none (min/max compares) |
| `sub_fffffff009106160` | — | transfer geometry gate (Apple "can corrupt memory" check) | none |

---

## 1. Every size-producing multiplication

### 1a. Confirmed 64-bit (`mul x`) — safe

`sub_fffffff009090ec8` — `IosaTiledCompressedMemMSR8.cpp::validateCompressedTileBuffers`

| Addr | Instruction | Width | Produces | Destination | Verdict |
|---|---|---|---|---|---|
| `0xfffffff0090911ec` | `add x9, x19, w20, uxtw` | x (32-bit operand **zero-extended**) | `mbW + W` | addend for ceil-div | SAFE — `uxtw`, no 32-bit wrap |
| `0xfffffff0090911fc` | `mul x21, x9, x20` | **x (64)** | `expectedMinStride = reqStride * ceil((mbW+W-1)/mbW)` | bound, compared `cmp x21, x28` / `b.ls` | SAFE |
| `0xfffffff009091248` | `add x9, x10, w9, uxtw` | x (uxtw) | `mbH + H` | addend for ceil-div | SAFE |
| `0xfffffff009091254` | `mul x9, x19, x28` | **x (64)** | `tilesH * stride` | intermediate | SAFE |
| `0xfffffff00909125c` | `mul x9, x9, x10` | **x (64)** | `* height` = required plane bytes | bound, `cmp x9, x25` / `b.lo` → reject | SAFE |
| `0xfffffff009091224` | `msub x9, x10, x9, x28` | x (64) | `stride % mbW` | alignment check | SAFE (`udiv` by 0 yields 0 on AArch64, no trap) |

All three `mul` are 64-bit and every 32-bit source operand is widened with `uxtw` **before** the
arithmetic. There is no `mul w`, `umull`, `smull` or `madd w` anywhere in this function's size path.
The stride itself is a 32-bit load (`0xfffffff00909114c  ldr w28, [x24, #0x18]`) zero-extended into
`x28`, so it cannot sign-extend into the 64-bit product.

`sub_fffffff0090cd7c8` — `AppleM2ScalerCSCHalMSR25.cpp::validateDimensions`
* `(arg2 << 5) + (i << 3)` → plane-descriptor index. 64-bit shifts, `i < planeCount`. SAFE (index).
* `*(x0_1 + 0x68) << x21_2` → stride alignment, 64-bit. SAFE.

### 1b. Confirmed 32-bit — the one real hit

`sub_fffffff0091321c4` — `AppleM2ScalerCSCHalMSR15.cpp::validateXYOffsets` (log line `0xb8`,
`"Stride: %u is less than: %u bytes for plane: %d, iDS: %d\n"`)

```asm
0xfffffff0091322bc  ldr   w28, [x20, #0x28]      ; width            (32-bit load, zext)
0xfffffff009132318  udiv  w28, w28, w9           ; width /= hSubFactor  (guarded: cbz at 0x...2310/2314)
0xfffffff0091322fc  ldrb  w21, [x25, x8]         ; macroblock/align granularity (BYTE capability)
0xfffffff009132340  bl    sub_fffffff009193218   ; w24 = per-plane byte factor
0xfffffff009132374  fcvtzs w9, d8                ; <-- SIGNED double -> int32 : the X offset
0xfffffff009132378  add   w9, w9, w21            ; + granularity    (32-bit)
0xfffffff00913237c  add   w9, w9, w28            ; + width          (32-bit)
0xfffffff009132380  sub   w9, w9, #0x1
0xfffffff009132384  udiv  w9, w9, w21            ; UNSIGNED divide
0xfffffff009132388  mul   w23, w9, w24           ; <-- 32-BIT MULTIPLY, WRAPS
0xfffffff00913238c  ldr   w27, [x8]              ; actual stride
0xfffffff009132390  cmp   w27, w23
0xfffffff009132394  b.lo  0xfffffff009132424      ; reject if stride < required  (UNSIGNED)
```

| Addr | Instruction | Width | Produces | Destination | Verdict |
|---|---|---|---|---|---|
| `0xfffffff009132388` | `mul w23, w9, w24` | **w (32)** | `requiredBytes = ceil((X + gran + W - 1)/gran) * planeFactor` | **bound** (stride floor) | **STRONG** |

Why this is the top candidate:

1. **Width**: `mul w` truncates mod 2^32. Unlike §1a there is no `uxtw` widening and no 64-bit form.
2. **Signedness mix**: the X offset arrives as a `double` (`ldr d8, [x8, x22, lsl #0x3]`), is converted
   with **`fcvtzs` (signed)**, then immediately consumed by **`udiv` (unsigned)** and compared with
   **`b.lo` (unsigned)**. A negative offset therefore becomes a huge unsigned dividend, `udiv`
   produces a large quotient, and `mul w` wraps — potentially to a *small* `requiredBytes` that the
   real stride comfortably exceeds, so the check passes for a geometry it should reject.
3. It is an **allocation/access bound**, not just a diagnostic: this is the function that decides
   whether the plane stride can hold `X + W`.

Not proven: that `d8` is client-reachable **and** can be driven negative in this build. The kext
publishes `IOSurfaceAcceleratorCapabilitiesFractionalXYOffsetsSupported = 0`
(`sub_fffffff0090d3ec0`), which argues the offsets are integral, and the prior campaign's border-fill
offsets are `%u`. Reachability must be settled by the harness, not statically. **Confidence: STRONG
(not PROVEN BUG).**

**32-bit multiply count: 1** (`0xfffffff009132388`). Every other size-producing multiply audited is
64-bit `mul x` with explicit `uxtw` widening. The more common 32-bit defect in this kext is the
**wrapping add** in the rect gates (§3), not a wrapping multiply.

---

## 2. Allocation vs bound consistency

**Not isolatable in this pass — INCONCLUSIVE, and this is stated rather than guessed.**

* `buf:allocSize=%llu` (`0xfffffff00762e26d`) and `buf:allocOffset=%u` (`0xfffffff00762e281`) are
  referenced **only** from `sub_fffffff009189d44` / its neighbour, whose sole caller is
  `sub_fffffff0090f0dc8` = `dumpSrcOrDstTransform` — a pure logging function. The allocator that
  *writes* `allocSize` was not located (no writable-field xrefs).
* `Failed to allocate IOBufferMemoryDescriptor size %zu` (`0xfffffff007625526`) and
  `allocateTileArrayBuffer` (`0xfffffff007625213`) similarly only appear in 1-basic-block outlined
  log blocks (`sub_fffffff0091801a4`, `sub_fffffff00918023c`, `sub_fffffff0090c7c14`); the callers of
  those blocks were not chased to completion within budget.

**What *can* be said (AppleAVD-style consistency question):**

* Where a size/bound relationship *is* enforced — `validateCompressedTileBuffers` — the required
  size and the actual size come from the **same expression chain evaluated in 64-bit**:
  `x19_3 = (mbH + H - 1)/mbH` → `mul x9, x19, x28` (×stride) → `mul x9, x9, x10` (×height) →
  `cmp x9, x25` against `x25_2` (actual plane size). Allocation input and write bound are the same
  64-bit pipeline; no 32/64 split exists that an input could pry apart.
* M2Scaler does **not** share AppleAVD's property of both terms deriving from one constant
  (AVD's `0xb8950`). Here every bound is derived at runtime from plane geometry. That is a weaker
  structural guarantee on paper, but the arithmetic that computes it is uniformly 64-bit.

**Verdict: no alloc-vs-bound mismatch observed. INCONCLUSIVE pending location of the allocator —
the AppleAVD-style "single shared constant" proof does not apply to this kext.**

---

## 3. Rectangle / rect validation

### 3a. Histogram rect — **32-bit wrapping add, no carry guard** (both generations)

`sub_fffffff00909a87c` — `IosaColorManagerMSR4.cpp::validateHistogram` (log line `0x246`)

```asm
0xfffffff00909a8a8  ldr  w23, [x1, #0x770]     ; Bw  (real surface width)
0xfffffff00909a8ac  ldr  w24, [x1, #0x774]     ; Bh
0xfffffff00909a8b0  ldr  w25, [x1, #0xc80]     ; Hw  (client HistogramWidth)
0xfffffff00909a8b4  ldr  w26, [x1, #0xc84]     ; Hh
0xfffffff00909a8e0  ldr  w21, [x19, #0xc78]    ; Hx  (client OffsetX)
0xfffffff00909a8e4  ldr  w22, [x19, #0xc7c]    ; Hy
0xfffffff00909a8e8  add  w8,  w21, w25         ; Hx + Hw   32-bit, WRAPS
0xfffffff00909a8ec  add  w9,  w22, w26         ; Hy + Hh   32-bit, WRAPS
0xfffffff00909a8f0  cmp  w8,  w23
0xfffffff00909a8f4  ccmp w9,  w24, #0x2, ls
0xfffffff00909a8f8  b.ls 0xfffffff00909a958    ; ACCEPT
```

`sub_fffffff0090ac3e8` — `IosaColorManagerMSR23.cpp` (log line `0x872`) is **instruction-identical**:

```asm
0xfffffff0090ac788  ldp  w25, w26, [x0, #0x20] ; Bw, Bh from the descriptor (real dims)
0xfffffff0090ac78c  ldr  w27, [x19, #0xc80]    ; Hw
0xfffffff0090ac790  ldr  w28, [x19, #0xc84]    ; Hh
0xfffffff0090ac794  ldr  w23, [x19, #0xc78]    ; Hx
0xfffffff0090ac798  ldr  w24, [x19, #0xc7c]    ; Hy
0xfffffff0090ac7b4  add  w8,  w23, w27         ; Hx + Hw   32-bit, WRAPS
0xfffffff0090ac7b8  add  w9,  w24, w28         ; Hy + Hh   32-bit, WRAPS
0xfffffff0090ac7bc  cmp  w8,  w25
0xfffffff0090ac7c0  ccmp w9,  w26, #0x2, ls
0xfffffff0090ac7c4  b.ls 0xfffffff0090ac824    ; ACCEPT
```

Analysis: `b.ls` is taken (accept) iff `(Hx+Hw) <= Bw` **and** `(Hy+Hh) <= Bh`, all **unsigned
32-bit**. The adds are plain `add w` — **not** `adds`, so no carry flag is produced and there is no
`b.hs` overflow guard. A negative client offset stored as `int32` loads as e.g. `0xFFFFFFF0`;
`0xFFFFFFF0 + 1920 = 0x770 = 1904 <= 1920` → **accept**. This is exactly the hole
`REPORT_M2SCALER.md` §5 documented, and it is **unchanged in 24A435** — both generations, same
encoding.

Mode gate also unchanged and still unsigned-correct:
`0xfffffff0090ac824-30` → `sub w9, w8, #1; cmp w9, #2; b.hs` ⇒ rejects unless `(mode-1U) < 2`.

### 3b. `validateDimensions` — no rect add at all

`sub_fffffff0090d4fb0` (`AppleM2ScalerCSCHal.cpp:0x28c0-0x28e1`) compares `*(x0_1+0x28)` / `*(x0_1+0x2c)`
against min (`x23_1`) and max (`x25`/`x26`) with no offset term, then divides
`*(x0_1+0x20) / *(x0_1+0x74)` for plane-height sufficiency. No `x + w` arithmetic ⇒ no overflow site.

`sub_fffffff0090cd7c8` (`AppleM2ScalerCSCHalMSR25.cpp`) checks alignment (`(x28_1 - 1) & *(x0_1+0x28)`),
`> max`, `<= 7`, `< 8`, and stride modulo — all on already-bounded scalars. No wrapping add.

**Verdict: the only rect-validation overflow sites in the audited set are the two histogram gates
above. There is no `adds` + `b.hs` carry guard anywhere in either.**

---

## 4. Signedness

| Site | Instruction | Issue | Confidence |
|---|---|---|---|
| `0xfffffff009132374` | `fcvtzs w9, d8` then `0xfffffff009132384 udiv w9, w9, w21` | signed→int32 immediately reinterpreted as unsigned by `udiv` | STRONG |
| `0xfffffff009132388` | `mul w23, w9, w24` | 32-bit bound, wraps | STRONG |
| `0xfffffff00909a8e8/ec` | `add w` | signed client offsets read as unsigned, wrap | PROVEN (matches prior live result) |
| `0xfffffff0090ac7b4/b8` | `add w` | same, MSR23 | PROVEN |
| `0xfffffff00909114c` | `ldr w28, [x24, #0x18]` | 32-bit load, **zero**-extended into 64-bit math — correct | SAFE |

All bounds compares in §1a use `b.lo` / `b.ls` (unsigned) on operands that are zero-extended from
32-bit — correct, because the operands are genuinely unsigned dimensions. The defect is not the
branch condition; it is that a **signed** value is fed into unsigned 32-bit arithmetic upstream.

---

## 5. Re-verification checklist vs `REPORT_M2SCALER.md`

| Gate (report §) | Still holds in 24A435? | Evidence |
|---|---|---|
| Transfer geometry gate — Apple corrupt-memory config `destH<=32 && srcW>128 && planes>1` (§4) | **YES — still present** | `sub_fffffff009106160`: `if (*(x26+0x126) && *(x0_1+0x2c) <= 0x20 && *(x0_3+0x28) >= 0x81 && *(arg2+0x75c) >= 2) → 0xe00002c2` + log `0xfffffff007630560` via `sub_fffffff00918b3bc`. Note it is conditional on device bit `*(x26+0x126)`; on unaffected silicon the branch is never taken. |
| Histogram signed-offset wrap, MSR4 (§5) | **YES — NOT fixed** | `sub_fffffff00909a87c` @ `0xfffffff00909a8e8`/`ec`, `cmp`/`ccmp`/`b.ls` @ `0xfffffff00909a8f0-f8`. No carry guard. |
| Histogram signed-offset wrap, MSR23 (§5) | **YES — NOT fixed** | `sub_fffffff0090ac3e8` @ `0xfffffff0090ac7b4`/`b8`, `b.ls` @ `0xfffffff0090ac7c4`. Log line moved `0x870 → 0x872` vs the prior build's `:874` note — the surrounding code was edited, but the gate itself is byte-for-byte the same shape. |
| Histogram mode gate `(mode-1U)<2` (§5) | **YES** | `sub_fffffff0090ac3e8` `0xfffffff0090ac828-30`; `sub_fffffff00909a87c` decompile `x9_2 - 1 >= 2` → reject. |
| Filter coefficients (sel4) taps/phases consistency (§7) | **NOT RE-VERIFIED** | String present at `0xfffffff00761f1ee` ("inconsistent sizes given: … vTaps/vPhase…"), referenced from `0xfffffff0090a79bc`. Instruction-level check not re-run this pass. |
| Sel map 0–11 (§3) | **NOT RE-VERIFIED** | Requires the user-client external-method table; no symbols and no string xrefs available. |
| Alloc-vs-patch-bound size consistency | **INCONCLUSIVE** | See §2. `allocSize` writer not located. |
| BorderFill rect = fill geometry only (§4) | **NOT RE-VERIFIED** | `validateBorderFill` (`0xfffffff007616e47`) referenced from `0xfffffff00915ab1c`, `0xfffffff0091722c8`, `0xfffffff0091769b0`, `0xfffffff00918e264`, `0xfffffff00918ff9c`, `0xfffffff00919164c` — not decompiled this pass. |
| Post-create surface mutation immutable / WithSwap refcounting / flags sweep (§4) | **N/A (dynamic)** | Not reachable statically. |

**No previously-verified gate was found missing or weakened.** The one change detected (MSR23
histogram line `0x870→0x872`) is a line-number shift, not a gate change.

---

## 6. Ranked candidates

| # | Finding | Confidence |
|---|---|---|
| 1 | `validateXYOffsets` (`AppleM2ScalerCSCHalMSR15.cpp:0xb8`): 32-bit `mul w23, w9, w24` computing the required-stride bound, fed by `fcvtzs w9, d8` (signed X offset) then `udiv` (unsigned) and compared `b.lo` (unsigned). Negative/large X offset ⇒ wrap ⇒ stride floor under-enforced. `0xfffffff009132374-0xfffffff009132394`. | **STRONG** |
| 2 | Histogram rect wrap, MSR4 `0xfffffff00909a8e8`/`0xfffffff00909a8ec` + `b.ls 0xfffffff00909a8f8`. | **PROVEN BUG** (validator hole; prior campaign showed HW contains it) |
| 3 | Histogram rect wrap, MSR23 `0xfffffff0090ac7b4`/`0xfffffff0090ac7b8` + `b.ls 0xfffffff0090ac7c4`. | **PROVEN BUG** (same, second generation) |
| 4 | `sub_fffffff0091321c4` tail: `udiv w9, w8, w24` / `msub` alignment checks where `w24 = ldrb [x25,#0x1f8]` is a *byte* capability — if 0, `udiv` yields 0 and the alignment check silently passes. | **SPECULATIVE** (capability byte, likely non-zero constant) |
| 5 | `sub_fffffff0090cd7c8` `x0_14 % x8_12` where `x8_12 = *(x0_1+0x68) << (1|2)`; a zero would make the modulo vacuous. | **SPECULATIVE / likely REFUTED** (format-table field) |
| — | 32-bit `w*h` or `stride*h` used as an allocation size or copy length | **REFUTED** for every site audited — all are `mul x` with `uxtw` widening |
| — | Allocation-vs-bound expression mismatch (the AppleAVD question) | **INCONCLUSIVE** — allocator not located |

## 7. Bottom line

The +19,464-byte in-place rewrite did **not** regress any gate the prior audit verified: the transfer
geometry gate, both histogram gates and the histogram mode gate are all present and structurally
identical. The rewrite also did not introduce 32-bit size arithmetic into the compressed-tile size
path, which remains uniformly 64-bit and internally consistent.

The one *new* item relative to the prior report is #1: a genuine 32-bit bound multiply with a
signed→unsigned conversion upstream, in `AppleM2ScalerCSCHalMSR15::validateXYOffsets`. It is the only
32-bit size-producing multiply among the geometry validators and is where a follow-up dynamic probe
should go first — the question to answer is whether the `d8` X offset can be driven negative or large
enough to make `mul w23` wrap below the real stride.
