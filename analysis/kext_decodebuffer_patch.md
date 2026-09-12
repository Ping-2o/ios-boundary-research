> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleAVD `com.apple.driver.AppleAVD` (iOS 27.0 RC, 24A435) — "patch into kernel decode buffer" path

Binary: Mach-O kext, `mac-aarch64`, image start `0xfffffff007181580`,
`__text` = `0xfffffff008659160..0xfffffff0086c1b74`, 2393 functions, stripped.
Method: Binary Ninja only (MCP), read-only. No `bn_binary_view_set_active`, no `bn_open_item_open`.

---

## 0. Attribution correction (PROVEN)

The task statement attributes the string
`"AppleAVD: ERROR: %s(): Patch into kernel decode buffer (from userspace decode buffer) failed"`
(`@0xfffffff007199df9`, verified by `bn_memory_read`) to `sub_fffffff0086b0978`. **This is wrong.**

Full decompile + full disassembly (320 insns, `0xfffffff0086b0978..0xfffffff0086b0d34`) of
`sub_fffffff0086b0978` contain **no reference** to `0xfffffff007199df9`. Its only string literals are:

* `"removeNalTrailingZerosAndEPB"` (`@0xfffffff0071a70b7`)
* `"AppleAVD: INFO: %s(): sliceNum > max encrypted slices allowed:%d\n"` (`@0xfffffff00719a676`)
* `"AppleAVD: INFO: %s(): pSrc poitners OOB!\n"` (`@0xfffffff00719a6b8`)

The string `0xfffffff007199df9` is referenced by **`sub_fffffff0086affac`** (`createAndSubmitDecodeCMD`),
at callsite `0xfffffff0086b0638`, immediately after the call to `sub_fffffff0086b4e2c`
(`patchIntoDecodeBuffer`):

```
x0_35 = sub_fffffff0086b4e2c(arg1[0x73], *arg2, var_128, arg2[1], var_130,
                             &arg2[0x130], arg2[0x12f], *(arg2 + 0x99c), var_160);
if (!x0_35)
    log("AppleAVD: ERROR: %s(): Patch into kernel decode buffer (from userspace decode buffer) failed\n");
```

So the real "patch into kernel decode buffer" engine is:

```
createAndSubmitDecodeCMD (sub_fffffff0086affac)
        └─> patchIntoDecodeBuffer  (sub_fffffff0086b4e2c)     [0xfffffff0086b0638]
                ├─> translateToKVA       (sub_fffffff0086b5030)  (x2)
                ├─> copyUserspaceToKernel(sub_fffffff0086b511c)
                └─> patchCommand         (sub_fffffff0086b5400)  [0xfffffff0086b4fd0]
```

`sub_fffffff0086b5400` and `sub_fffffff0086b4e2c` are the applier/translator the task said another
agent covers. This report covers both the misattributed function and the real bound question.

---

## 1. What `sub_fffffff0086b0978` actually is

Signature: `int64_t sub_fffffff0086b0978(int64_t arg1, int64_t arg2, int64_t arg3, int32_t arg4, int32_t arg5, int64_t arg6, int64_t arg7, int32_t arg8)`

Essential body (from decompile):

```c
uint64_t x9_4 = arg8 % 9 * 0x808;                       // per-frame slot (frameNumber % 9)
int32_t* x23_1 = arg1 + 0x10a8 + x9_4;                  // session+0x10a8 + slot*0x808
int64_t result = sub_fffffff0086c2184(x23_1, 0x808);    // memset(slot, 0, 0x808)

if (arg5) {                                             // arg5 = slice count
    int64_t x8_1 = 0;
    int64_t x9_5 = arg3 + arg4;                         // arg3 = src ptr, arg4 = src len -> end
    int64_t x10_1 = x9_5 - arg3;                        // == arg4
    while (true) {
        if (x8_1 == 0x100) {                            // HARD CAP 256 slices
            log("... sliceNum > max encrypted slices allowed:%d\n");
            return ...;
        }
        uint64_t x1 = *(arg7 + (x8_1 << 2));            // arg7: per-slice size array
        uint64_t x2 = *(arg6 + (x8_1 << 2));            // arg6: per-slice offset array
        if (x1 ? x2 == arg4 : true) break;
        ...
        int64_t x3_1 = arg3 + x2;
        int64_t x4_2 = x3_1 + x1;
        if (x4_2 > x9_5) {                              // READ BOUND: src + off + len > end
            log("... pSrc poitners OOB!\n");
            return ...;
        }
        ...
        if (x2 & 0x80000000 || x2 >= x10_1) { ... /* abort */ }   // x2 < arg4
        ...
        x23_1[0x201] = 1;                               // byte 0x804, inside 0x808
        x2_9  = &x23_1[0x101] + (x8_1<<2);              // byte 0x404 + 4*i
        *x2_9 = x4_5;                                   // store slice length
        x2_11 = &x23_1[1] + (x8_1<<2);                  // byte 0x4 + 4*i
        *x2_11 = *(arg7 + (x8_1<<2));                   // store slice size
        x8_1 += 1;
        *x23_1 = x8_1;                                  // slot[0] = count
        if (x8_1 == arg5) break;
    }
}
```

**It does not patch anything.** It is the `removeNalTrailingZerosAndEPB` slice-info parser: it walks
per-slice `{size,offset}` arrays for the current frame, strips trailing zeros/EPB, and writes the
per-slice `{length,size}` table plus a "modified" flag into a **session-owned, fixed 0x808-byte
per-frame slot** at `arg1 + 0x10a8 + (arg8 % 9) * 0x808`.

**Bounds on this function — all present and sufficient:**

| Access | Check (disasm) | Verdict |
|---|---|---|
| slot writes `x23_1[1+i]`, `x23_1[0x101+i]`, `x23_1[0x201]` | `cmp x8,#0x100; b.eq` cap; `i < arg5`; max index `0x201`→byte `0x804` < `0x808` | bounded |
| src reads `*(arg3+x2)`, `*(arg3+x2+1)` | `cmp w2,w10; b.hs` (`x2 < arg4`); `adds x4,x3,x1; cmp x4,x9; b.hi` (`end`) | bounded |
| loop iteration | `x8_1 == 0x100` → log+return; `x8_1 == arg5` → break | bounded (≤256) |

No unbounded write. Verdict for this function: **clean (REFUTED as a bug)**.

---

## 2. The real patch path and its bound

### 2.1 `patchIntoDecodeBuffer` (`sub_fffffff0086b4e2c`) — argument mapping

Called from `createAndSubmitDecodeCMD` as
`sub_fffffff0086b4e2c(patcher, *arg2, var_128, arg2[1], var_130, &arg2[0x130], arg2[0x12f], *(arg2+0x99c), frame)`:

| param | value | meaning |
|---|---|---|
| arg1 | `arg1[0x73]` | `m_commandPatcher` |
| arg2 | `*arg2` | **userspace** decode-buffer pointer |
| arg3 | `var_128` | **kernel** decode-buffer destination |
| arg4 | `arg2[1]` | userspace-requested decode-buffer size |
| arg5 | `var_130` | kernel decode-buffer size |
| arg6 | `&arg2[0x130]` | size-descriptor struct |
| arg7 | `arg2[0x12f]` | **userspace** patch-list pointer |
| arg8 | `*(arg2+0x99c)` | number of patch requests |
| arg9 | frame number | |

`var_128` and `var_130` are two adjacent fields of one gate response (see §5).

Body:

```c
int64_t result = arg3;                                  // dest
if (sub_fffffff0086b5030(arg1, arg2, arg4, &var_58))    // translateToKVA(userspace buf, arg4)
    { log("Translation/check of decode buffer (%llu) failed"); result = 0; }
else if (arg8 < 0x5555556) {                            // numRequests overflow guard
    if (sub_fffffff0086b5030(arg1, arg7, arg8*0x30, &var_60))
        { log("Translation/check of patch list (0x%llx) failed"); result = 0; }
    else if (sub_fffffff0086b511c(arg1, var_58, result, arg4, arg5, arg6))
        { log("Copy from userspace decode buffer to kernel decode buffer failed"); result = 0; }
    else if (sub_fffffff0086b5400(arg1, var_60, arg8, result, arg4, arg9))
        { log("failed to patch firmware command"); result = 0; }
} else { log("numRequests=%u overflow"); result = 0; }
```

### 2.2 `translateToKVA` (`sub_fffffff0086b5030`) — length validated against the mapping

```c
for (i = *(arg1 + 0x10); i; i = i[0x34])
    if (*i == arg2 && !i[0x13] && !*(i + 0x9c)) {
        if (i[0x15] != 6)              log("Invalid mapType=%d");
        else if (arg3 <= *(i + 0x2c))  { result = 0; *arg4 = i[1]; }   // arg3 <= mapping size
        else                           log("OOB (length=%u) for returned mapping");
        return result;
    }
return 0xe00002f0;
```

Both the userspace decode buffer (`arg4` bytes) and the patch list (`arg8*0x30` bytes) are checked
`<= mapping->size` before any copy/write. The patch list is a **mapped userspace buffer**, not a raw
pointer dereference.

### 2.3 `copyUserspaceToKernel` (`sub_fffffff0086b511c`) — the "from user" copy is bounded

```c
if (arg4 <= arg5) {                                     // user size <= kernel buffer size
    ...
    if (!x8_1 || x8_1 > arg4 || !x9_2 || x8_1 + x23_1 > arg4 ||
        x13_1 + x11_2 > arg4 || x13_2 + x12_2 > arg4)
        log("Invalid decodeBuffer sizes ...");          // every sub-size checked vs arg4
    else {
        memset(arg3, arg4);                             // arg3 = dest
        memcpy(arg3, arg2, *arg6);                      // <= arg4
        memcpy(arg3 + x8_2, arg2 + x8_2, x23_1);        // x8_2 + x23_1 <= arg4
        ... work-unit loop: if (x9_6 + x11_4 > arg4) break; ...
    }
} else log("decodeBufferSize too large! (%u > %u)\n\n");
```

**Copy length is validated** against `arg5` (kernel buffer size) and against the userspace mapping
size (via `translateToKVA`). No unchecked copy length.

### 2.4 `patchCommand` (`sub_fffffff0086b5400`) — the actual bounded write, quoted

Disassembly (dest = `x10` = `[sp,#0x38]` = `arg4`; bound = `w10` = `[sp,#0x4c]` = `arg5`):

```
0xfffffff0086b5468  ldr     w21, [x8, #0x18]          ; offset  (patch record +0x18, 32-bit)
0xfffffff0086b546c  ldrb    w24, [x8, #0x28]          ; size    (patch record +0x28, 8-bit)
0xfffffff0086b5470  adds    w9, w21, w24              ; offset + size
0xfffffff0086b5474  b.hs    0xfffffff0086b5564        ; carry  -> "Invalid offset"
0xfffffff0086b5478  ldr     w10, [sp, #0x4c {var_74}] ; bound = arg5 (decode-buffer size)
0xfffffff0086b547c  cmp     w9, w10
0xfffffff0086b5480  b.hi    0xfffffff0086b5564        ; offset+size > bound -> "Invalid offset"
...
0xfffffff0086b5514  cmp     w24, #0x2                 ; size == 2
0xfffffff0086b5518  b.ne    0xfffffff0086b5644        ; else "Field size (%d) not supported"
0xfffffff0086b5520  ldrh    w9,  [x10, x21]           ; 2-byte read
0xfffffff0086b5530  strh    w8,  [x10, x21]           ; 2-byte write  (width == checked size)
...
0xfffffff0086b5538  ...     w24 == 4
0xfffffff0086b553c  ldr     w9,  [x10, x21]           ; 4-byte read
0xfffffff0086b554c  str     w8,  [x10, x21]           ; 4-byte write  (width == checked size)
```

The comparison that establishes the bound is `cmp w9, w10` / `b.hi` at
`0xfffffff0086b547c..0xfffffff0086b5480`, where `w9 = offset+size` and
`w10 = arg5 = the kernel decode-buffer size (var_130)`.

The store width matches the size field (`strh` for size 2, `str` for size 4), so there is **no**
size/width mismatch.

---

## 3. Input provenance

* **Patch list**: `arg7 = arg2[0x12f]` (`frame_struct + 0x978`), a **userspace** pointer, count
  `arg8 = *(arg2 + 0x99c)`, each record 0x30 bytes. Both are validated by `translateToKVA`
  (`sub_fffffff0086b5030`) against the mapping length `arg8*0x30` before use. The records are read
  by the kernel from the translated KVA (`var_60`).
* **Userspace decode buffer**: `arg2 = *arg2`, a **userspace** pointer, length `arg2[1]`; validated
  by `translateToKVA` and copied to the kernel decode buffer with `copyUserspaceToKernel`.
* **Destination kernel decode buffer**: `var_128`, returned by the firmware gate query
  `decodeFrameFigHelper_GetDecodeBufInFrameParamQ` (`sub_fffffff0086afc2c`, gate cmd `0x2b680144`).
* Interface: `frame_struct` (`arg2` in `createAndSubmitDecodeCMD`) is the per-frame decode command
  populated from the userspace decode request. So the patch contents are **userspace-supplied**
  through the mapped decode/patch buffers of the decode command.

---

## 4. Size / geometry mismatch check (hypothesis 5) — REFUTED

`var_128` (dest) and `var_130` (bound) both come from the **same gate response struct**
(`sub_fffffff0086afc2c`, disassembly):

```
0xfffffff0086afc80  str   x0, [sp, #0x30 {var_90}]       ; request: session
0xfffffff0086afc84  ldr   w9, [x0, #0x200]
0xfffffff0086afc88  str   w9, [sp, #0x38 {var_88}]       ; request: session+0x200
0xfffffff0086afc8c  str   w4, [sp, #0x50]                ; request: frame
0xfffffff0086afcb8  bl    sub_fffffff00868697c          ; gate cmd 0xc into sp+0x30
... success (w0==0) at 0xfffffff0086afd5c:
0xfffffff0086afd7c  ldr   x8, [sp, #0x40 {var_88+0x8}] ; buffer KVA   -> *arg2 (var_128)
0xfffffff0086afd84  ldp   w9, w8, [sp, #0x48]           ; sp+0x48 size -> *arg4 (var_130)
0xfffffff0086afd88  str   w8, [x23]                      ; sp+0x4c     -> *arg3 (var_12c)
0xfffffff0086afd8c  str   w9, [x21]
```

`var_128 = [sp+0x40]` (buffer pointer) and `var_130 = [sp+0x48]` (its size) are adjacent fields of
one gate descriptor `{ptr@0x40, size@0x48, extra@0x4c}`. The bound is therefore derived from the
**same** geometry as the destination — there is no "old buffer / new SPS size" split on this path.
The applier additionally uses the *smaller* value `arg4 = arg2[1]` (user size), with
`arg4 <= var_130` enforced in `copyUserspaceToKernel`, so the effective bound is
`min(user size, kernel buffer size)`. **No mismatch found.**

---

## 5. Reachability

* `createAndSubmitDecodeCMD` (`sub_fffffff0086affac`) has exactly one caller:
  `sub_fffffff0086abae0` (`@0xfffffff0086abaec`), which is a 3-instruction thunk:
  `return sub_fffffff0086affac(arg1, *(arg3 + 0x30), *(arg3 + 0x58));`
* `sub_fffffff0086abae0` has **no direct callers** (`bn_function_callers` → 0). It sits in a cluster
  of 1-BB vtable-style thunks (`0xfffffff0086abac8..0xfffffff0086abb74`), i.e. it is dispatched
  indirectly through a session object method table — consistent with `IOUserClient` method dispatch.
* The user client's `externalMethod` override is `sub_fffffff0086abb74`
  (string `"externalMethod"` @`0xfffffff0071a6c65`, `"dispatchExternalMethod error! %d\n"`
  @`0xfffffff007198399`). It dispatches through a table of **10 entries** at
  `0xfffffff007f0a0e8` (`adrp x3,0xfffffff007f0a000; add x3,x3,#0xe8; mov w4,#0xa; bl
  sub_fffffff0086c1e34`). Table entries are encoded (arm64e chained-fixup/PAC form, e.g.
  `0x8050bcad016a7ac8`); the specific selector index reaching `createAndSubmitDecodeCMD` could not be
  resolved statically with the read-only MCP (no byte-search, data xrefs return empty).
* Entitlement gating confirmed by adjacent strings in `__const`:
  `"IOUserClientEntitlements"` @`0xfffffff0071a6cec` and
  `"com.apple.videotoolbox.hardwarevideodecoder"` @`0xfffffff0071a6d05`; also
  `"IOUserClientDefaultLockingSingleThreadExternalMethod"` @`0xfffffff0071a6cb7`.
  This corroborates the prior audit: the only reachable path for a third-party app is via the
  `videocodecd` daemon (which holds the entitlement). `"videocodecd"` itself is not a string in this
  kext.

---

## 6. Ranked candidate list

| # | Candidate | Confidence | Basis |
|---|---|---|---|
| 1 | `sub_fffffff0086b0978` is the "patch into kernel decode buffer" path | **REFUTED** | Full decompile/disasm: no reference to `0xfffffff007199df9`; it is `removeNalTrailingZerosAndEPB`, writes only within a 0x808 session slot. |
| 2 | Unbounded patch write into the kernel decode buffer | **REFUTED** | `patchCommand` checks `offset+size > bound` (`0xfffffff0086b547c`/`b.hi`) and store width matches size; `copyUserspaceToKernel` checks every sub-size vs `arg4` and `arg4 <= arg5`. |
| 3 | Unchecked copy length from userspace | **REFUTED** | `sub_fffffff0086b511c` validates length vs `arg5` and vs the userspace mapping (`translateToKVA`, `arg3 <= i[0x2c]`). |
| 4 | Geometry mismatch (bound from new SPS, buffer old size) | **REFUTED** | `var_128`/`var_130` are adjacent fields of one gate descriptor; bound = `min(user size, kernel buffer size)`. |
| 5 | 2-byte store overflow in `patchCommand` (decompiler showed same 4-byte RMW for size 2/4) | **REFUTED** | Disassembly shows `strh` for size==2, `str` for size==4 — widths match. |
| 6 | Destination buffer `var_128` allocation not independently size-asserted at the applier; relies on firmware gate reporting a size (`var_130`) consistent with `var_128` | **SPECULATIVE** | If the gate ever returns `{ptr, size}` where `size` exceeds the real allocation of `ptr`, both the copy and the patches overflow. No such inconsistency is visible in `sub_fffffff0086afc2c`; low priority. |
| 7 | Selector index in the 10-entry dispatch table (`0xfffffff007f0a0e8`) that reaches `createAndSubmitDecodeCMD` | **UNRESOLVED** | Table entries are fixup/PAC-encoded; no byte-search available; data xrefs empty. Chain `externalMethod → (indirect) → createAndSubmitDecodeCMD` is established. |

**Overall:** the "patch into kernel decode buffer (from userspace)" path is bounded and appears
sound. The most valuable negative result is the attribution correction: `sub_fffffff0086b0978` is a
bounded slice/NAL parser, not the patch engine, and no out-of-bounds primitive was found on the
actual patch path.
