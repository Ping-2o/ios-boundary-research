> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleAVD kext — FW patch applier / patch-list translator (deep audit)

**Target**: `com.apple.driver.AppleAVD` (Mach-O kext, mac-aarch64), iOS 27.0 RC (24A435), image start `0xfffffff007181580`.
**Tooling**: Binary Ninja GUI + MCP, read-only. No `bn_binary_view_set_active`, no `bn_open_item_open`. Every address/quote below comes from a `bn_function_decompile` / `bn_function_disassembly` query in this session. String xrefs (`bn_data_xrefs_*`) are known-empty in this view and were not used.
**Scope**: the firmware-command patch engine flagged in `REPORT_AVD.md` §2c / `analysis/avd_patch_descriptors.md` §2.

---

## 0. Verdict summary

| # | Question | Verdict | Reason |
|---|---|---|---|
| 1 | Is the offset bounds check wrap-safe? | **CORRECT (PROVEN)** | It is the safe form: `adds w9,w21,w24` + `b.hs` carry guard, then `cmp w9,w10` + `b.hi`. No 32-bit wrap bypass. |
| 2 | Is the check applied before/after offset arithmetic? | **CORRECT (PROVEN)** | The offset (`x21`) is loaded once (`0x…5468`) and never modified; the addend arithmetic only changes the *value*, not the offset. |
| 3 | Is there a second path to the same write? | **REFUTED** | `sub_fffffff0086b5400` has exactly one caller (`0xfffffff0086b4fd0`). `sub_fffffff0086b0978` is `removeNalTrailingZerosAndEPB`, not an applier. |
| 4 | Is the record loop / record array bounded? | **CORRECT (PROVEN)** | Loop = `numRequests`; the list was validated as `48*numRequests ≤ user-mapping size` by `translateToKVA`. |
| 5 | Is the written value a user-memory read (OOB read)? | **REFUTED** | `translateToDVA` (`0x…b5694`) **never dereferences** the record pointer; it returns a mapping base. No OOB user read. |
| 6 | Does `cmdBufSize` equal the `cmdBuf` allocation size? | **UNVERIFIED** | The bound is client-supplied `*(arg2+8)`, gated to `≤ var_130` (the FW-declared frame-param region size) by `copyUserspaceToKernel`. The base is the frame-param base. Whether that size field equals the real per-slot allocation is not resolvable in-view. See §5. |

**No PROVEN OOB kernel write was found.** The engine's own checks are correct. The single residual lead is an allocation-vs-size-field divergence on the *frame-param region* (§5, UNVERIFIED).

---

## 1. The applier — `sub_fffffff0086b5400` @ `0xfffffff0086b5400`

Signature (BN): `uint64_t(uint64_t arg1, int64_t arg2, int32_t arg3, int64_t arg4, int32_t arg5, int32_t arg6)`
Roles: `arg1` = device/patcher object · `arg2` = kernel KVA of the patch list · `arg3` = `numRequests` · **`arg4` = `cmdBuf` (write base)** · **`arg5` = `cmdBufSize` (bound)** · `arg6` = frame number.

### 1.1 Essential decompilation

```c
uint64_t sub_fffffff0086b5400(uint64_t arg1, int64_t arg2, int32_t arg3,
                              int64_t arg4, int32_t arg5, int32_t arg6)
{
    int32_t var_8c = 0xe00002bc;
    if (arg3) {
        int64_t  x19_1 = 0;              // record index
        uint64_t x20_1 = arg3;           // remaining count
        while (true) {
            int64_t* x8_1 = arg2 + x19_1 * 0x30;      // 48-byte record
            /* chained-fixup / pointer-tag re-tag of x8_1 */
            uint64_t x21_1 = x8_1[3];                  // +0x18 offset
            uint64_t x24_1 = x8_1[5];                  // +0x28 fieldSize (byte)
            if (x21_1 + x24_1 < x21_1 || x21_1 + x24_1 > arg5) {   // BOUND CHECK
                log("AppleAVD: INFO: %s(): Invalid offset\n");
                break;
            }
            uint64_t x26_1 = *(x8_1 + 0x1c);           // +0x1c addend
            uint64_t x23_1 = x8_1[4];                  // +0x20 truncate
            uint64_t x25_1 = *(x8_1 + 0x24);           // +0x24 bitfieldMask
            int64_t  x27_1 = *x8_1;                    // +0x00 pointer/key
            int64_t  x22_1 = x8_1[1];                  // +0x08 mask
            uint64_t x28_1 = x8_1[2];                  // +0x10 iosid (u64 slot, low dword used)
            uint64_t x3    = *(x8_1 + 0x14);           // +0x14 type/id
            int64_t  var_68 = 0;
            int32_t  x0_1 = sub_fffffff0086b5694(arg1, x28_1, x27_1, x3, x26_1, &var_68, arg6);
            if (x0_1 == 0xe00002bc) { log("...Invalid offset into userspace pointer..."); break; }
            if (x0_1 == 0xe00002f0) { log("...not mapped\n"); var_8c = 0xe00002f0; break; }
            int64_t x8_3 = var_68;                     // resolved mapping base
            if (x26_1 + x8_3 < x26_1 || !x22_1 || x23_1 > 0x40 || !x25_1) {
                log("...Invalid patch request - addend=%d, mask=0x%llx, truncate=%d, bitfieldMask=0x%x\n");
                break;
            }
            uint32_t x8_7 = ((x8_3 + x26_1) & x22_1) >> x23_1
                            << (sub_fffffff0086c21d4(x25_1) - 1);   // bit-count-1
            if (x24_1 == 4)
                *(arg4 + x21_1) = (*(arg4 + x21_1) & ~x25_1) | (x25_1 & x8_7);   // 32-bit WRITE
            else if (x24_1 == 2)
                *(arg4 + x21_1) = (*(arg4 + x21_1) & ~x25_1) | (x25_1 & x8_7);   // 16-bit WRITE
            else { log("...Field size (%d) not supported\n"); break; }
            x19_1 += 1; if (--x20_1 == 0) { var_8c = 0; break; }
        }
    }
    return var_8c;
}
```

### 1.2 The bound comparison — quoted disassembly (decisive)

```asm
0xfffffff0086b5468  ldr   w21, [x8, #0x18]      ; offset      (u32, zero-extended)
0xfffffff0086b546c  ldrb  w24, [x8, #0x28]      ; fieldSize   (u8)
0xfffffff0086b5470  adds  w9, w21, w24          ; w9 = offset + fieldSize   <-- 32-bit ADD, flags
0xfffffff0086b5474  b.hs  0xfffffff0086b5564    ; reject if CARRY (unsigned overflow)
0xfffffff0086b5478  ldr   w10, [sp, #0x4c]      ; w10 = arg5 = cmdBufSize   (u32)
0xfffffff0086b547c  cmp   w9, w10
0xfffffff0086b5480  b.hi  0xfffffff0086b5564    ; reject if (offset+fieldSize) > cmdBufSize
```

This is the **safe** form (`CARRY32(offset,fieldSize) || offset+fieldSize > cmdBufSize`), not the wrapping `cmdBufSize < offset + fieldSize` form. The `adds`/`b.hs` pair kills the classic 32-bit wrap. `b.hi` is unsigned. **Verdict: CORRECT.**

### 1.3 Record layout (derived from the loads at `0x…5484`–`0x…5490`)

```asm
0xfffffff0086b5484  ldp   w26, w23, [x8, #0x1c]   ; +0x1c addend(u32), +0x20 truncate(u32)
0xfffffff0086b5488  ldr   w25,      [x8, #0x24]   ; +0x24 bitfieldMask(u32)
0xfffffff0086b548c  ldp   x27, x22, [x8]          ; +0x00 key(u64), +0x08 mask(u64)
0xfffffff0086b5490  ldp   w28, w3,  [x8, #0x10]   ; +0x10 iosid(u32), +0x14 type(u32)
```

| Off | Width | Field | Meaning / use | Validation |
|---|---|---|---|---|
| +0x00 | u64 | `userPointer` / key | matched against mapping `*i` | must match a live mapping (else `0xe00002f0`) |
| +0x08 | u64 | `mask` | AND-mask on `(value+addend)` | `!= 0` (`0x…54e0 cbz x22`) |
| +0x10 | u32 | `iosid` | matched against mapping `[+0x98]` | must match |
| +0x14 | u32 | `type`/id | matched against mapping `[+0x9c]` | must match |
| +0x18 | u32 | `offset` | write offset into `cmdBuf` | `offset+fieldSize` no-carry && `≤ cmdBufSize` |
| +0x1c | u32 | `addend` | added to resolved base; **also** the length checked `≤ mapping size` | 64-bit carry guard (`cmn x26,x8; b.hs`); `≤ mapping[+0x2c]` |
| +0x20 | u32 | `truncate` | right-shift amount | `≤ 0x40` (`0x…54e4 cmp w23,#0x40; b.hi`) |
| +0x24 | u32 | `bitfieldMask` | read-modify-write mask | `!= 0` (`0x…54ec cbz w25`) |
| +0x28 | u8 | `fieldSize` | write width | `== 2` or `== 4` (`0x…550c`/`0x…5514`) |
| +0x29..0x2f | — | pad | | |

This matches the plugin-side builder layout in `analysis/avd_patch_descriptors.md` §2.1 exactly (`+0x10` is a u64 there, split into the two u32 matchers `+0x10`/`+0x14` here).

### 1.4 Value computation (fully in-bounds)

```asm
0xfffffff0086b54d8  cmn   x26, x8        ; addend + resolvedBase  (64-bit)
0xfffffff0086b54dc  b.hs  reject         ; reject on 64-bit carry
0xfffffff0086b54f0  add   x8, x8, x26    ; value = base + addend
0xfffffff0086b54f4  and   x8, x8, x22    ; & mask
0xfffffff0086b54f8  lsr   x22, x8, x23   ; >> truncate
0xfffffff0086b5508  lsl   x8, x22, x8    ; << (bitcount(bitfieldMask)-1)
0xfffffff0086b5520  ldrh  w9, [x10, x21] ; 2-byte RMW  (fieldSize==2)
0xfffffff0086b553c  ldr   w9, [x10, x21] ; 4-byte RMW  (fieldSize==4)
```

The store address is `x10 (arg4, 64-bit base) + x21 (zero-extended 32-bit offset)`, width 2 or 4. All arithmetic that feeds the *offset* is done before the check; the addend/truncate only affect the *value*. The read-modify-write is masked by `bitfieldMask` and the store width is 2/4. **No OOB.**

**Minor, non-memory-safety**: `truncate == 0x40` is allowed (`b.hi` rejects `> 0x40`), but `lsr x22, x8, x23` with `x23 == 64` shifts by `64 mod 64 == 0` on AArch64, i.e. **no shift** instead of shifting everything out. This changes only the written *value* (still masked and width-bounded) — a correctness quirk, not an OOB. Label: SPECULATIVE (low).

---

## 2. The translator — `sub_fffffff0086b4e2c` @ `0xfffffff0086b4e2c`

Signature: `int64_t(uint64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int32_t* arg6, int64_t arg7, int64_t arg8, int32_t arg9)`

```c
result = arg3;                                   // arg3 = cmdBuf (write base)
lock(*(arg1+0x20));
x0_2 = sub_fffffff0086b5030(arg1, arg2, arg4, &var_58);   // translateToKVA(user buf id, len=arg4)
if (x0_2) { log("...Translation/check of decode buffer (%llu) failed..."); result = 0; }
else if (arg8 < 0x5555556) {                     // arg8 = numRequests  (0x…4ecc)
    x0_4 = sub_fffffff0086b5030(arg1, arg7, arg8 * 0x30, &var_60);  // patch list
    if (!x0_4) {
        x0_6 = sub_fffffff0086b511c(arg1, var_58, result, arg4, arg5, arg6);  // copyUserspaceToKernel
        if (!x0_6) {
            if (sub_fffffff0086b5400(arg1, var_60, arg8, result, arg4, arg9))   // APPLIER
                log("...failed to patch firmware command\n");
        }
        else log("...Copy from userspace decode buffer to kernel decode buffer failed...");
    }
    else log("...Translation/check of patch list (0x%llx) failed...");
}
else log("...numRequests=%u overflow\n");
```

Argument plumbing at the applier call (`0xfffffff0086b4fb8`–`0xfffffff0086b4fd0`):

```asm
0xfffffff0086b4fc0  mov  x1, x24     ; arg2 = var_60  (patch-list KVA)
0xfffffff0086b4fc4  mov  x2, x21     ; arg3 = arg8    (numRequests)
0xfffffff0086b4fc8  mov  x3, x20     ; arg4 = translator arg3 = cmdBuf
0xfffffff0086b4fcc  mov  x4, x22     ; arg5 = translator arg4 = cmdBufSize
0xfffffff0086b4fd0  bl   sub_fffffff0086b5400
```

So **`cmdBuf` = translator `arg3`** and **`cmdBufSize` = translator `arg4`**. Both are passed unchanged into the copy function as its dest (`arg3`) and dest-size limit (`arg4`):

```asm
0xfffffff0086b4f6c  mov  x2, x20     ; copy arg3 = translator arg3 = cmdBuf  (dest)
0xfffffff0086b4f70  mov  x3, x22     ; copy arg4 = translator arg4 = cmdBufSize (limit)
0xfffffff0086b4f74  mov  x4, x25     ; copy arg5 = translator arg5 = var_130
0xfffffff0086b4f7c  bl   sub_fffffff0086b511c
```

**Count bound** (`0xfffffff0086b4ecc`): `cmp w21, 0x5555556; b.lo` → `numRequests ≤ 0x5555555`, so `48*numRequests ≤ 0xFFFFFFF0 < 2^32`; the length is built 32-bit (`add w8,w21,w21,lsl#1; lsl w2,w8,#4`) and passed to `translateToKVA`, which validates it `≤` the mapping size. The loop in the applier runs the same `numRequests`. **Consistent — no record over-read.**

---

## 3. `cmdBufSize` provenance chain (with addresses)

| Step | Address | Value |
|---|---|---|
| Caller `sub_fffffff0086affac` loads the bound | `0xfffffff0086b061c` `ldr w3, [x20, #0x8]` | `*(arg2+8)` — client/userspace decode-buffer size (u32) |
| Caller loads the base | `0xfffffff0086b0618` `ldr x2, [sp,#0x38]` | `var_128` |
| Caller calls translator | `0xfffffff0086b0638` `bl sub_fffffff0086b4e2c` | `arg3=var_128`, `arg4=*(arg2+8)` |
| Translator passes to copy | `0xfffffff0086b4f7c` | copy dest=`var_128`, limit=`*(arg2+8)`, cap=`var_130` |
| Translator passes to applier | `0xfffffff0086b4fd0` | applier base=`var_128`, bound=`*(arg2+8)` |
| `var_128` / `var_130` produced | `0xfffffff0086b0464` `bl sub_fffffff0086afc2c` | see below |

`sub_fffffff0086afc2c` (named `decodeFrameFigHelper_GetDecodeBufInFrameParamQ` by its own log string):

```asm
0xfffffff0086afc80  str   x0,  [sp, #0x30]        ; data struct base
0xfffffff0086afc84  ldr   w9,  [x0, #0x200]
0xfffffff0086afc88  str   w9,  [sp, #0x38]
0xfffffff0086afc8c  str   w4,  [sp, #0x50]        ; frameNumber
0xfffffff0086afcb8  bl    sub_fffffff00868697c   ; sendCommandToCommandGate(dev, &data, cmd=0xc)
0xfffffff0086afd7c  ldr   x8,  [sp, #0x40]        ; var_128 = data+0x10  -> *arg2 (BASE)
0xfffffff0086afd84  ldp   w9, w8, [sp, #0x48]     ; w9 = data+0x18, w8 = data+0x1c
0xfffffff0086afd88  str   w8,  [x23]              ; *arg3 = var_12c
0xfffffff0086afd8c  str   w9,  [x21]              ; *arg4 = var_130 (SIZE)
```

The command-gate dispatch chain: `sub_fffffff00868697c` (`sendCommandToCommandGate`) → `sub_fffffff008682a48` (`runCommand`, case for cmd `0xc`) → `sub_fffffff00868317c` → `sub_fffffff008685640` → `sub_fffffff008663db8` (`getAvailableSlotInFrameParamQ`) → **`sub_fffffff00867c424` (`getFrameParamAddr`)**:

```c
x9_1 = (slot * 0xb0) | 8;
x10_1 = arg1 + 0x138 + x9_1;
x8_1 = *x10_1;                 // BASE  -> data+0x10 -> var_128
x9_2 = *(arg1 + 0x6c0);        // SIZE  -> data+0x18 -> var_130
if (x9_2 && x8_1) { *arg3 = x8_1; *arg4 = x9_2; }
else log("Frame params not yet allocated\n");
```

**So**: `cmdBuf` (`var_128`) = the per-slot frame-param region base `*(obj + 0x138 + (slot*0xb0|8))`; `cmdBufSize` (`*(arg2+8)`) is the **client-declared** userspace decode-buffer size. They are **not** the same computation. Two independent checks constrain `cmdBufSize` before any write:

1. `translateToKVA` (`sub_fffffff0086b5030`, `0xfffffff0086b50a4` `cmp w2, w9; b.ls`): `*(arg2+8) ≤ user-mapping size`.
2. `copyUserspaceToKernel` (`sub_fffffff0086b511c`, `0xfffffff0086b5144` `cmp w3, w4; b.ls` else "decodeBufferSize too large! (%u > %u)"): **`*(arg2+8) ≤ var_130`**.

Since check (2) gates the applier (the applier is only reached if the copy returns 0), the write bound is `min(*(arg2+8), var_130) = *(arg2+8) ≤ var_130`. **Whether `var_130 == *(obj+0x6c0)` equals the real allocation of the per-slot buffer at `var_128` is UNVERIFIED in this view** — `var_128` and `var_130` come from two different struct fields (per-slot pointer vs a single global size). This is the one residual link.

---

## 4. Source of the written value

`sub_fffffff0086b5694` (`translateToDVA`) is called with `(arg1, iosid, userPointer, type, addend, &value, frameNumber)`:

```asm
0xfffffff0086b56c4  ldr   x8, [x22]         ; mapping key
0xfffffff0086b56c8  cmp   x8, x2            ; == userPointer (rec+0x00)
0xfffffff0086b56d0  ldr   w8, [x22, #0x98]
0xfffffff0086b56d4  cmp   w8, w1            ; == iosid (rec+0x10)
0xfffffff0086b56dc  ldr   w8, [x22, #0x9c]
0xfffffff0086b56e0  cmp   w8, w3            ; == type (rec+0x14)
0xfffffff0086b56e4  b.eq  match
0xfffffff0086b5784  ldr   w9, [x8, #0x2c]   ; mapping size
0xfffffff0086b5788  cmp   w19, w9           ; addend <= mapping size ?
0xfffffff0086b578c  b.ls  ok
0xfffffff0086b57c8  ldr   x8, [x8, #0x10]   ; *arg6 = mapping base  (no dereference of x2!)
0xfffffff0086b57cc  str   x8, [x21]
0xfffffff0086b57f8  b     sub_fffffff0086b5834   ; addFrameRefToMemory(...)
```

The record's `+0x00` pointer is only ever **compared** to a mapping key; the returned value is the mapping's field `[+0x10]` (its DVA/base). The addend is separately required `≤` the mapping size. Therefore the written value is `(mapping_base + addend) & mask` — an **address computation**, not a read of user memory. **The prior report's "kernel READS user memory / IOSurface" hypothesis is REFUTED**: there is no `ldr`/`ldrb`/`copyin` through the record pointer anywhere in the applier or its resolver.

---

## 5. Ranked candidates

| Rank | Candidate | Confidence | Detail |
|---|---|---|---|
| 1 | **Frame-param region size field `*(obj+0x6c0)` may not equal the per-slot buffer allocation at `*(obj+0x138+slot*0xb0+8)`.** The applier bound is client `*(arg2+8)`, gated only by `≤ var_130 = *(obj+0x6c0)`. If the per-slot buffers are allocated with a size different from the global `0x6c0` field, the write can exceed the allocation. | **UNVERIFIED / SPECULATIVE** | `getFrameParamAddr` `0xfffffff00867c424` returns base from a per-slot pointer and size from a global field. Needs the allocation site for `obj+0x138+…` and the writer of `obj+0x6c0`. |
| 2 | `truncate == 0x40` executes as shift-by-0 (`lsr x, x, #64`) due to AArch64 6-bit shift masking. | **SPECULATIVE (not memory-safety)** | Value-integrity only; store stays within the masked 2/4-byte window. |
| 3 | 32-bit wrap in the offset bounds check. | **REFUTED** | `adds w9,w21,w24; b.hs` + `cmp w9,w10; b.hi` is the safe form (`0x…5470`–`0x…5480`). |
| 4 | OOB kernel read of user memory via the patch source. | **REFUTED** | `translateToDVA` never dereferences the record pointer (§4). |
| 5 | Second write path bypassing the bound. | **REFUTED** | Applier has one caller (`0xfffffff0086b4fd0`); `sub_fffffff0086b0978` is EPB removal. |
| 6 | Record count exceeding the array. | **REFUTED** | Same `numRequests` used for `48*numRequests` validation and the loop; `translateToKVA` enforces `≤` mapping size. |

### Next step to close candidate #1

Resolve `obj` in `getFrameParamAddr` (`0xfffffff00867c424`): find the writer of `*(obj+0x6c0)` and the allocation that produces the pointers at `obj+0x138+slot*0xb0+8`. If the allocation size argument differs from `*(obj+0x6c0)`, candidate #1 becomes a real OOB kernel write; otherwise the engine is airtight and this is a clean negative.
