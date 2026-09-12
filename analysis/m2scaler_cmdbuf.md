> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# M2ScalerCSC — command-buffer / patch-engine, surface & plane, dispatch, gate re-verification

**Target**: `com.apple.driver.AppleM2ScalerCSCDriver`, iOS 27.0 RC (24A435), iPhone17,5 (t8140).
**Tool**: Binary Ninja only (read-only; no `set_active`, no `open_item`). Active view image start
`0xfffffff0075511d0`.
**Note on VAs**: this carve's `__TEXT_EXEC.__text` lives at `0xfffffff0090521f0..0xfffffff0091929d8`
(kernelcache places all kext `__TEXT_EXEC` in a separate region from `__TEXT`), which is why `__const`
(`0xfffffff0075518f0` / `0xfffffff00807f338`) and code are ~29 MB apart. All addresses below are
Binary-Ninja view VAs.

Sections (from the Mach-O, for reference):

```
__TEXT       __const         va=0xfffffff0075518f0 size=0xc3090
__TEXT       __cstring       va=0xfffffff007614980 size=0x2515b
__TEXT_EXEC  __text          va=0xfffffff0090521f0 size=0x1407e8
__DATA_CONST __const         va=0xfffffff00807f338 size=0x2abf0
```

Symbols are **fully stripped** (`bn_symbol_list` for `Iosa` → 0; `bn_function_search` for
`cmdbuf` → 0). String xrefs return empty, so all code location was done with
`scripts/ds_locate_strrefs.py` (locator only) + `bn_function_callers` on the outlined log thunks.

---

## 1. Does a cmdBuf / patch-engine primitive exist?

### Verdict: **NO AppleAVD-style "cmdBuf + patch engine" exists in this kext.** REFUTED (for the
patch engine), and the prior note in `REPORT_M2SCALER.md` was **speculative**.

Evidence (all negative, all reproducible):

| Probe | Result |
|---|---|
| `bn_string_list` query `cmdBuf` | **0 strings** |
| `bn_string_list` query `patch` | **0 strings** |
| `bn_function_search` `cmdbuf` | **0 functions** |
| raw binary scan for `patch` | 0 byte matches |
| `bn_symbol_list` (any query) | 0 — fully stripped |

There is no "apply a patch descriptor at client-supplied offset into a firmware command buffer"
engine, no patch-descriptor table, and nothing structurally equivalent to AppleAVD's
`0xb8950`-sized command buffer + bounded-offset patch applier.

### What *does* exist (bounded-write machinery, 4 distinct mechanisms)

1. **FDR — Frame Descriptor Ring** (driver → firmware).
   `sub_fffffff009088e54` allocates 4 rings:
   ```c
   for (i = 0; i != 4; i++)
       *(arg1 + 0x48 + (i<<3)) = sub_fffffff00910f930(i, 0x1000, provider);   // size = 0x1000
   ```
   So **FDR allocation = 0x1000 (4096) bytes each**, 4 instances.
   Strings: `Failed to allocate FDR!\n` `0xfffffff00761b56c`, `Allocated FDR: %p\n`
   `0xfffffff00761b585`, `"[MSRCPU] Invalid FDR size: %zu"` `0xfffffff007629314`,
   `fdrStoreWritePointer` / `fdrGetReadPointer` / `fdrResetPointers` / `fdr_0..fdr_4_wr_ptr`.

2. **SDR — Status Descriptor Ring** (firmware → driver). Source file
   `StatusDescriptorRingMSR23.cpp`. Bounds check in `sub_fffffff0090da2cc` (§2).

3. **APIODMA register stream / "Arena"** — `MsrApiodmaRegisterStream.cpp`. An "Arena" of
   `ArenaPageDescriptor` + `PacketSequence` objects wrapping `IODMACommand`s (`getDmaCommandDva`,
   `initCommandPools`, `getCommand`, `arenaAllocate`, `commandRingAdvanceTail`,
   `releaseApiodmaPackets`, `writeIterate`). This is IOKit `IODMACommand` scatter-gather, not a
   patchable command buffer.

4. **`writeBlock` — generic bounded 32-bit write into a range**: `sub_fffffff009096204` (§2.2).

---

## 2. Bounded write sites: base / bound / offset validation

### 2.1 SDR offset+size check — `sub_fffffff0090da2cc` @ `0xfffffff0090da2cc`
*(closest structural analog to the AppleAVD patch bound — and it is NOT client-driven)*

Decompiled:
```c
uint64_t sub_fffffff0090da2cc(int64_t* arg1) {
    int64_t off  = (*(*arg1 + 0xe0))(arg1, 0x30);   // vtable dispatch — HW/SW reg read
    int32_t size = (*(*arg1 + 0xe0))(arg1, 0x34);
    if (!(off >> 0x10) && off + (size << 2) <= 0x10000)
        return off;
    log("SDR offset/size out of bounds (off=%08X, size=%08x).  Is firmware loaded?");
    return &data_fffffff0075c0820;   // + w1 = 0x4592
}
```

**Confirmed in disassembly (widths as executed):**
```asm
0xfffffff0090da330  lsl     w1, w0, #0x2            ; size<<2   -- 32-bit
0xfffffff0090da334  lsr     w8, w19, #0x10          ; off>>16   -- 32-bit view of a 64-bit reg
0xfffffff0090da338  cbnz    w8, fail                ; if low32(off) > 0xFFFF -> fail
0xfffffff0090da33c  add     w8, w19, w0, lsl #0x2   ; 32-bit add -- NO carry guard
0xfffffff0090da340  cmp     w8, #0x10, lsl #0xc     ; cmp w8, #0x10000
0xfffffff0090da344  b.hi    fail
0xfffffff0090da348  mov     w0, w19                 ; return offset (32-bit)
```

| Property | Value |
|---|---|
| base pointer | not in this function — returns the **offset** only |
| bound | **0x10000** (65536) |
| offset source | `(*vtable[0xe0])(this, 0x30)` — a **firmware/HW register read**, not client input |
| size source | `(*vtable[0xe0])(this, 0x34)` — same |
| carry/overflow guard | **NONE.** `add w` + `cmp w` + `b.hi`. No `adds` + `b.hs`. |
| AppleAVD comparison | AppleAVD had `adds`/`b.hs` **and** `cmp`/`b.hi`; M2Scaler has only the `cmp`/`b.hi`. |

**32-bit wrap is reachable in principle**: `size = 0x40000000` ⇒ `size << 2 == 0` (32-bit) ⇒ the
check reduces to `off <= 0x10000`, which passes for any `off <= 0xFFFF`. So the bound can be
defeated by an oversized `size` field.

**Alloc-vs-bound verdict: NOT ESTABLISHED (and the wrap is moot anyway).**
- The SDR allocation size could not be traced. `sub_fffffff009088c34` (`IosaFirmwareControlMSR23::…`)
  creates it via `sub_fffffff00913c48c(0, provider)` — the size is internal to that constructor, not a
  literal argument, and I did not resolve it. The **FDR** size is `0x1000`, and the SDR bound is
  `0x10000` — different rings, not comparable.
- Decisive point: **neither `off` nor `size` is client-supplied.** They come from vtable-dispatched
  register reads at indices `0x30`/`0x34`. Even if the bound is defeatable, there is no client
  primitive behind it.

**Confidence: SPECULATIVE** (arithmetic weakness proven at instruction level, attacker-controlled
input **not** proven — most likely not present).

### 2.2 `writeBlock` — `sub_fffffff009096204` @ `0xfffffff009096204` — **BOUNDS-SAFE**

The only *generic* "write N words at offset O into buffer B" loop found. Disassembly of the loop:

```asm
0xfffffff00909627c  ldr     x8, [x19, #0x18]        ; x8  = base pointer
0xfffffff009096280  sub     w24, w26, w21           ; w24 = offset = arg4 - result_1   (32-bit)
0xfffffff009096284  add     x27, x8, x24            ; dest = base + zext(offset)
0xfffffff00909628c  ldur    x8, [x19, #0x10]        ; x8  = range length (64-bit)
0xfffffff009096290  cmp     x8, w24, uxtw           ; 64-bit compare: length vs zext32(offset)
0xfffffff009096294  b.ls    fail                    ; if length <= offset -> ERROR, break
0xfffffff0090962a8  ldr     w8, [x23], #0x4         ; load  32-bit
0xfffffff0090962ac  str     w8, [x27], #0x4         ; STORE 32-bit
0xfffffff0090962b4  add     w24, w24, #0x4          ; offset += 4 (32-bit, no carry guard)
0xfffffff0090962b8  sub     w22, w22, #0x1
0xfffffff0090962bc  cbnz    w22, loop
```
Failure path logs `writeBlock [ID: %u] offset %x exceeds range length %#llx`
(`0xfffffff00761d7f5`).

- Store width: **`str w`** = 4 bytes; the offset advances by exactly 4. ✓ consistent.
- Bound compare is **64-bit** (`cmp x8, w24, uxtw`) against the **zero-extended** 32-bit offset, so
  no 32-bit wraparound can smuggle a large offset past it.
- Carry guard: absent (`add w24` only), but **not needed**: the increment is 4 and the store is 4
  bytes, so the last passing offset is `length-4` → write covers `[length-4, length)`.
- Underflow of the initial `sub w24, w26, w21` (offset < 0) yields a large 32-bit value,
  zero-extended → large 64-bit → `b.ls` taken → **caught**.
- A 2^32 wrap of `add w24` would require ~4·10^9 iterations (count is `int32`) and, if reached,
  wraps to a **low** offset (in-bounds), not past the end.

**Confidence: REFUTED as a bug — bounds-safe, same conclusion as AppleAVD, via a different
mechanism (64-bit compare on a zero-extended offset rather than `adds`/`b.hs`).**

---

## 3. Surface / IOSurface handling

Two validators found.

### 3.1 Stride + alignment — `sub_fffffff0091321c4` @ `0xfffffff0091321c4`
(`AppleM2ScalerCSCHalMSR15.cpp`, log label `validateXYOffsets`)

```c
for (plane = 0; plane != 3; plane++) {                     // x22_1 ∈ {0,1,2}
    if (*(desc + 0x1f4 + (plane << 2)) == 5) {             // plane in use
        ...                                                 // x9_2 = desc + 0x200 + (…<<2)  [PAC-checked]
        min_stride = (vcvtd_s32_f64(v8_1) + x21_1 + x28_1 - 1) / x21_1 * x0_13;
        actual     = *x8_11;                                // desc+0x18 or desc+0x1c / +0x2b0 / +0x1c
        if (actual < min_stride) {                          // <<< THE COMPARE
            log("Stride: %u is less than: %u bytes for plane: %d, iDS: %d\n");
            return 0xe00002c2;
        }
    }
}
if (*(desc + 0x18) % x24) { log("Luma Stride: %u is improperly aligned to: %u bytes, iDS: %d");
                            return 0xe00002c2; }
if (*(desc + 0x1c) % x24) { log("Chroma Stride: %u is improperly aligned to: %u bytes, iDS: %d");
                            return 0xe00002c2; }
return 0;
```
Strings: `Luma Stride: %u is improperly aligned to: %u bytes, iDS: %d\n` `0xfffffff00761eb92`;
`Chroma Stride: …` `0xfffffff00761ebcf`.

**Stride is validated against the geometry the scaler is asked to process** (`min_stride` derived
from the transform dimension) **and** against an alignment modulus — per plane.

### 3.2 Region-vs-plane dimension — `sub_fffffff00910513c` @ `0xfffffff00910513c`
(`AppleM2ScalerCSCHalMSR.cpp`, `miscDimensionAdjustments`)

```c
v0_4 = v8 - (v9 + v10);            // transformDim − (offset + planeDim)
if (v0_4 >= 0.0 || !(x26 & 1)) {   // <<< THE COMPARE
    /* proceed */
} else {
    result = 0xe00002c2;
    log("%s %s transform dimension %s%d.%s%u plus offset %s%d.%s%u exceeds plane dimension "
        "%s%d.%s%u and will not be clipped\n");   // 0xfffffff00762ffd8
}
```
so the region is rejected when `(offset + transformDim) > planeDim`.

⚠️ **The check is gated by `!(x26 & 1)`**: if that flag bit is clear the *whole* region-vs-plane
comparison is skipped and the oversized region proceeds. `x26 = *(arg4 + 0x3d)` — a byte field of
the transform descriptor. Whether that bit is client-reachable was **not** established.

**Confidence: SPECULATIVE.** ("STRONG" would require proving `arg4+0x3d` bit0 is client-settable.)

### Surface verdict
The scaler does compare requested geometry against real surface dimensions and per-plane strides.
The stride path (§3.1) is unconditional; the *dimension* path (§3.2) is conditional on a flag bit.
**No unconditional missing-compare was found.**

---

## 4. Plane handling

- **Plane index**: in `sub_fffffff0091321c4` the plane index is a **loop counter** `{0,1,2}` with
  `if (x22_1 != 3) continue;`. It is *not* taken from the client. `plane_count` is implied by the
  in-use marker `*(desc + 0x1f4 + (plane << 2)) == 5`.
- **Plane count vs array size**: the loop is hard-bounded at 3, and the in-use array at
  `desc+0x1f4` and the pointer array at `desc+0x200` are indexed with `<<2` / `<<3` from the same
  counter. No client-supplied plane index was observed.
- **Per-plane stride/size arithmetic width**: mixed. `sub_fffffff0090cfa18(plane) << 2` and
  `desc + 0x200 + x8_6` are 64-bit pointer arithmetic; the in-use test is a 32-bit load
  (`*(x0_1 + 0x1f4 + (x22_1 << 2)) == 5`); strides are carried as `uint32_t` (`x28_1`, `x27`) and
  converted with `vcvtd_s32_f64`. The minimum-stride expression
  `(vcvtd_s32_f64(v8_1) + x21_1 + x28_1 - 1) / x21_1 * x0_13` is computed in **double** and
  truncated — a rounding hazard, but the result is only used as a *lower bound* on the stride, and
  a too-small `min_stride` is the safe direction.
- Multi-plane formats are further handled by dedicated classes (`MSR23ChromaDownsampleFilter.cpp`,
  `M2ScalerSrcDestCfgControlMSR23.cpp`, `M2ScalerScalingASEControlMSR20.cpp`).

**No plane-index OOB found. Confidence: STRONG (negative).**

---

## 5. User-client surface

### 5.1 Class
`IOSurfaceAcceleratorClient` — string `0xfffffff00761ec0e`, file `IOSurfaceAcceleratorClient.cpp`
`0xfffffff00761f0bd`. A second, kernel-side class `IOSurfaceAcceleratorKernelClient`
(`0xfffffff00761ed62`) exists for K2K (kernel-to-kernel) callers.

**`AppleM2ScalerCSCDriverUserClient` does NOT appear in this carve** — the binary scan for
`UserClient` yields exactly one hit, `asynchronousUserClientCompletionCallback`. The UC class here
is `IOSurfaceAcceleratorClient`. (`AppleM2ScalerCSCDriver` itself is present at
`0xfffffff00761f1b2`.)

### 5.2 Dispatch table — **NOT LOCATED (honest negative)**

- I scanned `__TEXT.__const` (`0xfffffff0075518f0`, 0xc3090 B) and `__DATA_CONST.__const`
  (`0xfffffff00807f338`, 0x2abf0 B) for `0x18`-strided runs of
  `IOExternalMethodDispatch {fn, sIn, stIn, sOut, stOut}` (8 + 4×4) with plausible small counts.
  **Zero** runs of ≥6 entries matched.
- Root cause established: the on-disk `__const` contains **no resolvable pointers into
  `__TEXT_EXEC`**. A raw scan of the whole file found **0** occurrences (as full 8-byte VAs *or* as
  low-32-bit values) of `0xfffffff0090da2cc`, `0xfffffff009088c34`, or `0xfffffff00906c084` — i.e.
  the chained fixups have **not** been applied to this carve and I did not determine the encoding.
  The `VA = 0xfffffff007000000 + (raw & 0xFFFFFFFF)` rule from `REPORT_M2SCALER.md` does not reach
  `0xfffffff00905xxxx`, so it does not apply to this build's layout.
- Consequence: I **cannot** report the numeric selector→handler table or per-selector declared
  struct sizes from the table itself.

### 5.3 Handlers recovered (via callers of the outlined log thunks)

| Handler | Evidence | Declared / checked sizes |
|---|---|---|
| `sub_fffffff0090a74f8` | caller of the thunk logging `user_transform_surface` (`0xfffffff00761f10c`) and `"given size (%llu) doesn't match TransformSurfaceData's (%lu)\n"` (`0xfffffff00761f123`) | **input struct size validated == `sizeof(TransformSurfaceData)`** (prior report: `0x1b0`) |
| `sub_fffffff0090a7724` | caller of thunk logging `setCustomFilter` (`0xfffffff00761f1c9`) | see §6.1 |
| `sub_fffffff0090a7ab8` | contains log sites for `user_set_filter` (`0xfffffff00761f33d`) **and** `user_get_histogram` (`0xfffffff00761f34d`), incl. `Protected surface - cannot get histogram` (`0xfffffff00761f360`) and `Prepare failed to wire down histogram data` (`0xfffffff00761f38a`) | not established |
| `sub_fffffff0090a7c94` | **KernelTests**: `if (!x1_1 \|\| x2_2 != 0xfa8 \|\| *x1_1 > 0x3e8) return 0xe00002c2;` then `if (!*(*(x0_4+0x288)+0x18)) return 0xe00002e2;` | **0xfa8 struct-in, exact; stubbed (`0xe00002e2`)** — matches prior report §3 sel6 |
| (estimation) | `"given size (%llu) doesn't match TransformEstimationData's (%lu)\n"` `0xfffffff00761f469` | **input size validated** |

**Handler writing an output struct without validating caller size: none proven.** Every struct-sized
entry point I could resolve performs an explicit `given size (…) doesn't match <Type>Data's (…)`
equality check. The one unvalidated writer I saw is the **K2K** branch at the top of
`sub_fffffff0090a7c94`, which writes `arg2[0]`, `arg2+0x608`, `+0x610`, `+0x618` with no size
parameter — but that branch is entered only when `*(arg1 + 0x15c)` (kernel-client flag) is set, and
it is guarded by the `user client call to K2K method!` assertion (`0xfffffff00761f07e`,
`0xfffffff00761f3b6`). **K2K is kernel-internal; not a user-reachable path.**

### 5.4 Entitlement gate — **programmatic, not plist-string, and not entitlement-based**

- Raw binary scan: `"entitlement"` → **0**, `"com.apple.private"` → **0**,
  `"copyClientEntitlement"` → **0**, `"IOUserClient"` → **0**, `"uthoriz"` → **0**.
- The gate that *is* present is a **task/user-vs-kernel** check on the client object:
  - `*(client + 0x15c)` / `*(client + 0x158)` — kernel-client flag
  - `"[%s] " "user client call to K2K method!" @%s:%d` → `0xfffffff00761f07e`, `0xfffffff00761f3b6`
  - `"[%s] " "K2K call to user client!\n" @%s:%d` → `0xfffffff00761f161`
  - `"[%s] " "must called from user space!\n" @%s:%d` → `0xfffffff00761f0dc`
  - `"[%s] " "must only be called from user space!\n" @%s:%d` → `0xfffffff00761f3e9`
- Quoted (from `sub_fffffff0090a7c94`): `if (*(arg1 + 0x15c)) { …K2K path… }` else fall through to
  the user-space checks.
- **No entitlement string is consulted in this kext.** Any entitlement gating therefore lives in the
  personality plist in the kernelcache (not in this carve) or in the client library — consistent with
  `REPORT_M2SCALER.md` §2, which empirically opened the connection from a sandboxed app with no
  entitlements.

---

## 6. Re-verification of the prior gates

### 6.1 Filter coefficients (sel 4) — **STILL HOLDS. STRONG.**

`sub_fffffff0090a7724` @ `0xfffffff0090a7724` (log label `setCustomFilter`,
`IOSurfaceAcceleratorClient.cpp:0x365`):

```c
if (!arg2) return 0xe00002c2;
x23   = *(sub_fffffff0090e3d7c(*(arg1 + 0x100), 8) + 0xc0);      // HAL capability object
x0_3  = (*(*x23 + 0xe8))(x23, 0);    x0_5 = (*(*x23 + 0xf0))(x23, 0);
x0_7  = (*(*x23 + 0xe8))(x23, 1);    x0_9 = (*(*x23 + 0xf0))(x23, 1);
z_1   = (*(… + 0x4c) >= 0x17) ? !data_fffffff00b8e2040 : false;  // MSR >= 23
x25_2 = !z_1 ? x0_9 : 0x20;   x24_2 = !z_1 ? x0_7 : 9;
x22_2 = !z_1 ? x0_5 : 0x20;   x21_2 = !z_1 ? x0_3 : 9;

if (arg2[1] != x21_2 || arg2[2] != x22_2 || arg2[4] != x24_2 || arg2[5] != x25_2) {
    log("inconsistent sizes given: given(expected): vTaps: %d(%d), vPhases: %d(%d), "
        "hTaps: %d(%d), hPhases: %d(%d)\n");                       // 0xfffffff00761f1ee
    return 0xe00002c2;
}
else if (!*arg2 || !arg2[3]) {                                    // ratios must be > 0
    log("given ratios are must be > 0");                           // 0xfffffff00761f259
    return 0xe00002c2;
}
x21_3 = (x24_2 * x25_2 + x21_2 * x22_2) << 1;                      // int32 coefficient count
x0_13 = sub_fffffff0090a6c88(arg1, *(arg2 + 0x18), x21_3);         // allocate
…
sub_fffffff0091929e8(x0_13, x21_3 << 2);                           // zero x21_3*4 bytes
```

This is an **exact-equality** gate: client taps/phases must equal the values the HAL reports
(falling back to hard-coded `9` taps / `0x20` phases on MSR ≥ 23 when `data_fffffff00b8e2040` is
clear). A mismatch cannot be constructed, so the coefficient-count arithmetic feeding
`sub_fffffff0090a6c88` and the `<< 2` byte count is bounded by HAL constants.

**Verdict: gate holds in 24A435.** (The `int32` `x21_3 = (a*b + c*d) << 1` and `x21_3 << 2`
would be a 32-bit overflow hazard *if* taps/phases were client-controlled — they are not.)

### 6.2 sel map — **PARTIALLY RE-VERIFIED (cannot confirm indices)**

Confirmed in this build:

| sel | handler / evidence | status |
|---|---|---|
| 1 | `sub_fffffff0090a74f8` — `user_transform_surface`, struct size == `sizeof(TransformSurfaceData)` | ✅ struct size check confirmed |
| 4 | `sub_fffffff0090a7724` — `setCustomFilter`, taps/phases exact equality | ✅ confirmed |
| 6 | `sub_fffffff0090a7c94` — `0xfa8` struct, `*x1_1 <= 0x3e8`, returns `0xe00002e2` | ✅ stubbed, as prior report |
| 7 | log site `user_get_histogram` `0xfffffff00761f34d` (+ `Protected surface - cannot get histogram`) | ✅ exists |
| 9 | `"given size (%llu) doesn't match TransformEstimationData's (%lu)\n"` `0xfffffff00761f469` | ✅ size check confirmed |

**Not confirmed**: sel 0, 2, 3, 5, 8, 10, 11 — the numeric selector→handler table was not located
(§5.2), so I cannot re-derive the index assignment in 24A435. The *existence* of the handlers and
their struct-size checks is confirmed; their *indices* are carried over from the prior report and
are **not** re-verified here.

---

## 7. Ranked candidates

| # | Candidate | Confidence |
|---|---|---|
| 1 | **`sub_fffffff00910513c` region-vs-plane dimension check is conditional on `*(arg4+0x3d) & 1`** — when the bit is clear, an `(offset + transformDim) > planeDim` region is not rejected. `AppleM2ScalerCSCHalMSR.cpp`, `miscDimensionAdjustments`. Needs: is `arg4+0x3d` bit0 client-reachable? | **SPECULATIVE** |
| 2 | **`sub_fffffff0090da2cc` SDR bound is 32-bit and defeats itself** — `add w` + `cmp w` + `b.hi`, no `adds`/`b.hs`; `size = 0x40000000` ⇒ `size<<2 == 0` ⇒ bound bypassed. Bound `0x10000`; SDR alloc size unresolved. **offset/size are firmware register reads, not client input.** | **SPECULATIVE** (arithmetic PROVEN, reachability REFUTED-leaning) |
| 3 | Dispatch table / numeric sel map | **NOT ESTABLISHED** — honest negative, `__const` pointers still chained-fixup encoded |
| 4 | `writeBlock` `sub_fffffff009096204` | **REFUTED** — bounds-safe at instruction level |
| 5 | cmdBuf / patch-engine primitive | **REFUTED** — does not exist in this kext |
| 6 | Filter-coefficient (sel 4) gate | **HOLDS — STRONG** |
| 7 | Plane index / plane-count OOB | **REFUTED** — plane index is a 0..2 loop counter |
| 8 | Entitlement gate | **None in kext**; programmatic kernel-vs-user flag (`+0x15c`) only |

## 8. Bottom line

The prior note's "bounded kernel write into cmdBuf / alloc-vs-patch-bound" mechanism **does not
exist** in this kext. M2Scaler has FDR/SDR descriptor rings and an `IODMACommand`-based
APIODMA register stream, not a patchable firmware command buffer. The two real bounded-write sites
were both resolved at instruction level: `writeBlock` is **safe** (64-bit compare on a
zero-extended 32-bit offset, 4-byte store, 4-byte increment), and the SDR check has a
self-defeating 32-bit `add` but reads its offset/size from firmware registers, not from the client.
The surface path validates stride unconditionally and validates region-vs-plane dimension only
conditionally — that conditional is the one lead worth a follow-up. The filter-coefficient gate is
intact (exact equality against HAL values). The dispatch table could not be located because this
carve's `__const` pointers are still chained-fixup encoded; that is a tooling gap, not a finding.
