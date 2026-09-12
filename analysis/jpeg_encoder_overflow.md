> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleJPEGDriver (iOS 27.0 RC, 24A435) — `req+0x464` MCU-count overflow trace

Binary: `com.apple.driver.AppleJPEGDriver`, mac-aarch64, `__text` 0xfffffff00900ebb0..0xfffffff00903c538
Tooling: Binary Ninja (read-only; `bn_data_xrefs_*` empty, no symbols/imports in the BV — everything below
is from direct disassembly or call-graph traversal).

**VERDICT: REFUTED** (the 32-bit `mul` is real and unchecked, but it is *unreachable* and its only
consumer is a hardware-descriptor field, not an allocation size). No undersized allocation, no OOB write.

---

## 0. Recap of the anchor (re-confirmed, do not re-derive)

`AppleJPEGDriver::getMCUSize` — `sub_fffffff009018680`

```
0xfffffff009018730  ldr     w9, [x21]              ; w9  = *arg5          (rows candidate = in+0x54)
0xfffffff009018734  add     w11, w22, w10          ; w22 = Vert (arg4), w10 = v-divisor (tbl2)
0xfffffff009018738  sub     w11, w11, #0x1
0xfffffff00901873c  rbit    w10, w10
0xfffffff009018740  clz     w10, w10               ; log2(v-divisor)
0xfffffff009018744  lsr     w10, w11, w10          ; w10 = (Vert + h - 1) >> log2(h)
0xfffffff009018748  cmp     w9, w10
0xfffffff00901874c  b.ls    0xfffffff009018758
0xfffffff009018750  mov     w9, #0                 ; out-of-range -> rows = 0
0xfffffff009018754  str     wzr, [x21]
0xfffffff009018758  add     w10, w20, w8           ; w20 = Horz (arg3), w8 = h-divisor (tbl1)
0xfffffff00901875c  sub     w10, w10, #0x1
0xfffffff009018760  rbit    w8, w8
0xfffffff009018764  clz     w8, w8
0xfffffff009018768  lsr     w8, w10, w8            ; w8 = (Horz + w - 1) >> log2(w)
0xfffffff00901876c  mul     w8, w9, w8             ; <<< 32-bit multiply, NO overflow check
0xfffffff009018770  str     w8, [x19]              ; *arg6 = req+0x464
```

Both `add` ops (`Horz + w`, `Vert + h`) are also 32-bit and also unchecked, but with the reachable
input ranges (see §4) they cannot wrap.

### Divisor tables (read from `bn_memory_read 0xfffffff007548a58`, 48 bytes)

`10000000 10000000 08000000 20000000 08000000 | 10000000 08000000 08000000 08000000 98000000 ...`

| addr | role | mode 0 | 1 | 2 | 3 | 4 | default (mode ≥ 5) |
|---|---|---|---|---|---|---|---|
| `0xfffffff007548a58` | **w** (Horz divisor, → cols) | 0x10 | 0x10 | 0x08 | 0x20 | 0x08 | **0x20** (`mov w8,#0x20` @ 0x90672c) |
| `0xfffffff007548a6c` | **h** (Vert divisor, → rows bound) | 0x10 | 0x08 | 0x08 | 0x08 | 0x98→/8 | **0x08** (`mov w10,#0x8` @ 0x906728) |

Shift amount is `clz(rbit(x))` = index of lowest set bit, so 0x98 (0b10011000) divides by 8.

Call site in `startEncoder` (`sub_fffffff009019ad0`):

```
0xfffffff009019c44  ldp   w2, w3, [x19, #0x14]     ; w2 = Horz (32-bit), w3 = Vert (32-bit)
0xfffffff009019c48  str   w2, [x22, #0x428]
0xfffffff009019c4c  str   w3, [x22, #0x42c]
0xfffffff009019c70  ldr   w1, [x19, #0x2c]         ; subsampling
0xfffffff009019c74  add   x4, sp, #0x1c            ; &copy of in+0x54
0xfffffff009019c78  add   x5, x22, #0x464          ; &req+0x464
0xfffffff009019c7c  bl    sub_fffffff009018680
```

NOTE: although `startEncoder`'s *logging* path uses `ldrh w9,[x19,#0x18]` (0x9019b3c / 0x9019ea8),
the value actually **passed** to `getMCUSize` is the full 32-bit `ldp w2,w3,[x19,#0x14]`.

---

## 1. Every reader of `req+0x464`

Found by walking the complete call graph from `startEncoder` (data xrefs are unavailable, so this is
call-graph enumeration, not an xref query).

| # | Address | Function | Role |
|---|---|---|---|
| 1 | `0xfffffff00903bf4c` | `RequestHandling::encodeHWRequestSetup` (`sub_fffffff00903bcd8`) | **only reader**: `ldr w8,[x19,#0x464]` → `str w8,[x19,#0x224]` @ `0xfffffff00903bf50`. Copies the MCU count into the hardware command descriptor at `req+0x78`. |

```
0xfffffff00903bf4c  ldr   w8, [x19, #0x464]
0xfffffff00903bf50  str   w8, [x19, #0x224]
```

Functions examined and confirmed **not** to read `0x464`:

* `startEncoder` `sub_fffffff009019ad0` — writes it only.
* `AppleJPEGDriver::queue_io_gated` `sub_fffffff009018c0c` — reads 0x428/0x42c/0x468/0x46c/0x470/0x538, not 0x464.
* `setupBuffersForCoding_gated` `sub_fffffff009017b78`, `doRestOfBufferSetupForEncode_gated`
  `sub_fffffff009017844`, `doRestOfBufferSetupForDecode_gated` `sub_fffffff0090171fc` — none.
* `sub_fffffff00902af00`, `sub_fffffff00902c554`, `sub_fffffff00902c72c` — indexed by core index
  (`req+0x46c`), never receive `req`.
* `sub_fffffff00902b684`, `sub_fffffff00902b1cc`, `sub_fffffff009017194` — receive surface /
  memory-descriptor / interior pointers only.
* `sub_fffffff009013228` — ring-buffer enqueue of `req+0x78`; no allocation, no length arithmetic.

**No reader treats `req+0x464` as an allocation size, a copy length, or a loop trip count.**

---

## 2. Allocation site

**There is none derived from `req+0x464`.** The complete encode path performs exactly one kernel
allocation, and it is fixed-size:

```
0xfffffff009019bc0  adrp  x0, 0xfffffff00807b000
0xfffffff009019bc4  add   x0, x0, #0x938          ; static type descriptor
0xfffffff009019bc8  bl    sub_fffffff00903c588    ; (stub) -> JpegRequest allocation
0xfffffff009019bcc  cbz   x0, 0xfffffff009019cb0
0xfffffff009019bd0  mov   x22, x0
```

The encode **source and destination buffers are client-supplied IOSurfaces**, mapped (not allocated) in
`doRestOfBufferSetupForEncode_gated`:

```
sub_fffffff00902b1cc(codec, destMemDesc, coreIdx, req+0x308, &len, &log)   ; dest
sub_fffffff00902b1cc(codec, srcMemDesc,  coreIdx, req+0x300, &len, &log)   ; src
```
followed only by alignment checks (`& 3`, `& 0xfff`, `& 0x1f`) at 0x9018fbc-0x9018fd8 region.

So there is no `IOMalloc`/`IOBufferMemoryDescriptor`/`IOSurface` whose size expression contains
`req+0x464` (or `req+0x224`).

---

## 3. Write site

There is no kernel write bounded by `req+0x464`. The JPEG output is produced by the hardware engine
into the mapped destination IOSurface; `req+0x224` (the copy of `req+0x464`) is simply a field of the
command blob `req+0x78` that `sub_fffffff009013228` pushes onto a 0x1ff9-entry ring queue.

---

## 4. Arithmetic widths at every step (disassembly-confirmed)

| Site | Instruction | Width | Wraps? |
|---|---|---|---|
| `0xfffffff00901876c` | `mul w8, w9, w8` | **32-bit** | **yes, unchecked** — the vulnerability-*shaped* bug |
| `0xfffffff009018734` | `add w11, w22, w10` (`Vert + h`) | 32-bit | unchecked, but unreachable |
| `0xfffffff009018758` | `add w10, w20, w8` (`Horz + w`) | 32-bit | unchecked, but unreachable |
| `0xfffffff009018f00` | `umull x8, w26, w25` then `mul x8, x8, x27` → `req+0x470` | **64-bit** | no (correct workload estimate) |
| `0xfffffff00903bf70` | `mul w8, w0, w22` (stride × yOffset) | 32-bit | in address arithmetic, post-validation |
| `0xfffffff00903b3d4` | `sub w9, w9, #0x10, lsl #0xc` (`Vert - 0x10000`) | 32-bit | intentional range test |

No `smull`/`umaddl`/`madd` is involved in the MCU-count path.

---

## 5. Rule out the counter-hypothesis — the wrapped value IS rejected (twice)

### 5a. `getMCUSize` zeroes an over-large row count

`getMCUSize` itself clamps: if `in+0x54 > (Vert + h - 1) >> log2(h)` then `w9 = 0` and the product is 0.
So the row multiplicand is already bounded by the *Vert*-derived bound.

### 5b. `RequestHandling::encodeRequestValidation` bounds Horz/Vert **before** any consumer

`queue_io_gated` runs, in order:

```
0xfffffff009018fd8  bl  sub_fffffff009017b78   ; setupBuffersForCoding_gated
0xfffffff00901904c  bl  sub_fffffff00903acd8   ; dispatch on req+0x2a8 -> sub_fffffff00903b24c
0xfffffff009019050  cbz w0, 0xfffffff009019158 ; 0 == pass -> continue
0xfffffff009019158  bl  sub_fffffff00903b6b4   ; -> sub_fffffff00903bcd8 (encodeHWRequestSetup)
```

`sub_fffffff00903acd8` → for encoder (`req+0x2a8 != 0`, set to 1 at `0xfffffff009019c10`) →
`sub_fffffff00903b24c` = `RequestHandling::encodeRequestValidation`. Raw disassembly:

```
0xfffffff00903b294  ldr   w20, [x19, #0x428]        ; Horz
0xfffffff00903b2a4  cmp   w20, w0                   ; vs IOSurface plane width
0xfffffff00903b2a8  b.hi  0xfffffff00903b2e4        ; Horz > width  -> FAIL
0xfffffff00903b28c  lsr   w8, w0, #0x10 ; cbnz w8   ; surface w >= 0x10000 -> FAIL
0xfffffff00903b2cc  ldr   w20, [x19, #0x42c]        ; Vert
0xfffffff00903b2dc  cmp   w20, w0                   ; vs IOSurface plane height
0xfffffff00903b2e0  b.ls  0xfffffff00903b35c        ; Vert > height -> FAIL
...
0xfffffff00903b3b4  ldr   w8,  [x19, #0x428]
0xfffffff00903b3c0  lsr   w9,  w8, #0x10
0xfffffff00903b3c4  cbnz  w9,  0xfffffff00903b370   ; Horz >> 16      -> FAIL   (Horz < 0x10000)
0xfffffff00903b3c8  cmp   w8,  #0x4
0xfffffff00903b3cc  b.lo  0xfffffff00903b370        ; Horz < 4        -> FAIL
0xfffffff00903b3d0  ldr   w9,  [x19, #0x42c]
0xfffffff00903b3d4  sub   w9,  w9, #0x10, lsl #0xc  ; w9 = Vert - 0x10000 (32-bit)
0xfffffff00903b3d8  mov   w10, #0xffff0001
0xfffffff00903b3dc  cmp   w9,  w10
0xfffffff00903b3e0  b.ls  0xfffffff00903b370        ; (Vert-0x10000) u<= 0xFFFF0001 -> FAIL
```
→ enforced: **Horz ∈ [4, 0xFFFF]**, **Vert ∈ [2, 0xFFFF]** (identical to the `startEncoderExt` /
`startEncoder2024` in-caller checks quoted in the brief).

### 5c. Therefore the multiply cannot wrap

Worst reachable case (mode 2: w = 8, h = 8):

* rows ≤ ceil(0xFFFF / 8) = 0x2000 = 8192
* cols  = ceil(0xFFFF / 8) = 0x2000 = 8192
* max `req+0x464` = 8192 × 8192 = **0x4000000 (67,108,864) ≪ 2^32**

Even the theoretical worst case with 1-pixel MCUs (0xFFFF × 0xFFFF = 0xFFFE0001) is below 2^32.

### 5d. (Horz, Vert) pairs that *would* wrap — all rejected

Given the real widths (`Horz` = 32-bit `ldr`, `Vert` = 32-bit `ldp w3`; the `ldrh` is only in the
log path), wrapping needs rows × cols ≥ 2^32, e.g.:

| Horz | Vert | mode | cols | rows | product (mod 2^32) | outcome |
|---|---|---|---|---|---|---|
| 0x200000 | 0x80000 | ≥5 (w=32,h=8) | 0x10000 | 0x10000 | **0** | rejected: `Horz>>16` ≠ 0 |
| 0x10000 | 0x10000 | 2 (w=8,h=8) | 0x2000 | 0x2000 | 0x4000000 (no wrap) | rejected: `Horz>>16` ≠ 0 |
| 0x8000 | 0xFFFF | 2 | 0x1000 | 0x2000 | 0x2000000 | **accepted, no wrap** |
| 0xFFFF | 0xFFFF | 2 | 0x2000 | 0x2000 | 0x4000000 | **accepted, no wrap (max)** |

The prompt's suggested "Horz = 0x8000, Vert = 0x20000" cannot even be expressed as a wrap:
`Vert` is a 32-bit load, and 0x20000 is rejected by the `Vert - 0x10000 ≤ 0xFFFF0001` test.
**No reachable (Horz, Vert) pair makes `mul w8, w9, w8` wrap.**

### 5e. Decoder asymmetry

`bn_function_callers(0xfffffff009018680)` returns exactly three callers, **all encoders**:

| Callsite | Caller |
|---|---|
| `0xfffffff009019c7c` | `sub_fffffff009019ad0` — `startEncoder` (**no** in-caller bounds check) |
| `0xfffffff00901a194` | `sub_fffffff009019ee4` — `startEncoderExt` (checks `x9_3 < 7 \|\| x10_1 < 4 \|\| x10_1>>0x10 \|\| arg2[6]-0x10000 <= 0xffff0001` **before** the call) |
| `0xfffffff00901acb4` | `sub_fffffff00901a9e8` — `startEncoder2024` (same checks, before the call) |

**The decoders never call `getMCUSize` at all.** The asymmetry is between the three *encoder* entry
points — and it is fully compensated downstream by `encodeRequestValidation`, which runs on the single
shared `queue_io_gated` path before the only consumer of `req+0x464`.

---

## 6. Honest primitive statement

* The primitive hypothesized (undersized kernel allocation + OOB write) **does not exist**.
* What exists: an unchecked 32-bit `mul` at `0xfffffff00901876c` whose result lands in a hardware
  command-descriptor field (`req+0x224`, set at `0xfffffff00903bf50`) via `req+0x464`. It is a
  **latent / defence-in-depth integer overflow with no memory-safety consequence on 24A435**.
* Attacker-controlled content: `Horz` (in+0x14), `Vert` (in+0x18), `in+0x54` (row count) and
  `in+0x2c` (subsampling). All are 32-bit from the `IOConnectCallMethod` struct, but all are
  range-checked to Horz ≤ 0xFFFF, Vert ≤ 0xFFFF before use.
* Residual weaknesses worth reporting as hardening, not as a CVE:
  1. `startEncoder` omits the input validation its siblings perform (relies solely on the downstream
     `RequestHandling::encodeRequestValidation`).
  2. `getMCUSize` uses 32-bit `mul`/`add` where the sibling workload computation at
     `0xfffffff009018f00` correctly uses `umull` (64-bit). Any future consumer of `req+0x464` placed
     *before* `encodeRequestValidation`, or any relaxation of that validator, would immediately revive
     a real overflow.

---

## Verdict

**REFUTED** — downgraded from STRONG.
Overflow site confirmed at `0xfffffff00901876c` (`mul w8, w9, w8`, 32-bit, unchecked), but:
(a) its only reader (`0xfffffff00903bf4c`) copies it to a HW descriptor field, not to an allocation size
or a length; and (b) `RequestHandling::encodeRequestValidation` (`sub_fffffff00903b24c`) enforces
Horz ∈ [4,0xFFFF] / Vert ∈ [2,0xFFFF] before that reader executes, capping the product at 0x4000000.
No allocation sized from the wrapped value exists, so there is no undersized buffer and no OOB write.
