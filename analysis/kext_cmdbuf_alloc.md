> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleAVD `AppleAVDCommandPatcher` — allocation vs. bound audit

**Target:** `com.apple.driver.AppleAVD`, iOS 27.0 RC (24A435), Mach-O kext, mac-aarch64, stripped.
**Tooling:** Binary Ninja MCP only (read-only). Active view = the kext; `__text` = `0xfffffff008659160..0xfffffff0086c1b74`.
**Question under test:** can the allocation size of `cmdBuf` / the patch-record array diverge from the bound the applier uses, turning the FW-command patch engine into an OOB kernel write?

**Bottom line:** **REFUTED for this engine.** The patch engine performs **no size-parameterised allocation at all** — every allocation in the subsystem is a fixed-size `kalloc_type` site. `cmdBuf` is not allocated here; it is a kernel decode buffer fetched per frame from the FW gate, and the applier's bound (a client-supplied decode-buffer size) is clamped against the gate-returned size *before* any write. The residual risk is a single trust assumption on the gate (SPECULATIVE), not an arithmetic/rounding divergence.

---

## 1. Object model — `AppleAVDCommandPatcher`

### 1.1 Allocation

`sub_fffffff0086ace8c` = `createDecoder` (state machine: requires `state==1`, ends at `state=3`). It allocates the patcher at **`0xfffffff0086ad474`**:

```asm
0xfffffff0086ad46c  adrp  x0, 0xfffffff007f0e000
0xfffffff0086ad470  add   x0, x0, #0x50          ; x0 = 0xfffffff007f0e050  (kalloc_type site)
0xfffffff0086ad474  bl    sub_fffffff0086c1c14   ; alloc(type)
0xfffffff0086ad478  ldr   w2, [x25, #0x178]      ; devType
0xfffffff0086ad47c  ldrb  w3, [x25]              ; codecType
0xfffffff0086ad480  mov   x1, x19                ; AppleAVD state
0xfffffff0086ad484  bl    sub_fffffff0086b4104   ; init(patcher, state, devType, codecType)
0xfffffff0086ad488  str   x0, [x19, #0x398]      ; session->m_commandPatcher
```

`sub_fffffff0086c1c14` is an external stub (`__auth_stubs`); its single argument is a **`kalloc_type` site descriptor** in section `__kalloc_type` (`0xfffffff007f0ae50..0xfffffff007f0e950`, confirmed by `bn_section_list`). There is **no size argument** — the size is a compile-time constant encoded in the descriptor.

### 1.2 Descriptor decode (size evidence)

Descriptor bytes (read via `bn_memory_read`):

| descriptor | `+0x10` | `+0x20` | `+0x28` | **`+0x2c` = size** |
|---|---|---|---|---|
| `0xfffffff007f0e050` CommandPatcher | `d4301a00 00002000` | `f0301a00 00006000` | `64000000` | **`0x28`** |
| `0xfffffff007f0e010` framesInFlight | `931b1a00 00002000` | `ad1b1a00 00006000` | `64000000` | **`0x18`** |
| `0xfffffff007f0e310` mapping entry | `2b321a00 00002000` | `46321a00 00006000` | `64000000` | **`0x1a8`** |
| `0xfffffff007f0e350` mapping entry (alloc) | same as `…310` | same | `64000000` | **`0x1a8`** |
| `0xfffffff007f0e390` mapping entry (free) | same as `…310` | same | `64000000` | **`0x1a8`** |

The size field is at `+0x2c` (`+0x28` is the constant `0x64` in every descriptor). Cross-check: the mapping entry's observed linked-list stride is `0x1a8` (`next` at `+0x1a0`, `prev` at `+0x198`), matching the decoded size exactly — so the decode is reliable.

⇒ **`sizeof(AppleAVDCommandPatcher) == 0x28` (40 bytes), fixed at compile time.** No client input participates.

### 1.3 Field layout

| offset | size | meaning | evidence |
|---|---|---|---|
| `+0x00` | u32 | devType / coreID | `sub_fffffff0086b4104`: `*arg1 = arg3`; caller passes `[x25+0x178]` |
| `+0x04` | u32 | codecType | `sub_fffffff0086b4104`: `arg1[1] = arg4`; caller passes `[x25]` |
| `+0x08` | ptr | AppleAVD session state | `sub_fffffff0086b4104`: `*(arg1+8) = arg2` (=`x19`) |
| `+0x10` | ptr | mapping-list **head** | `sub_fffffff0086b5030/5694` iterate `*(arg1+0x10)`; `addSharedMemToMappingList` writes it |
| `+0x18` | ptr | mapping-list **tail** | `sub_fffffff0086b60ec` writes `*(arg1+0x18)` |
| `+0x20` | ptr | `IOLock*` (`m_patcherLock`) | `sub_fffffff0086b4318`: `*(arg1+0x20)=IOLockAlloc()`; free in `sub_fffffff0086b42dc` |

**There is no cmdBuf pointer, no patch-record array pointer, no record capacity, and no record count inside this object.** That part of the prior model (`REPORT_AVD.md` §2c) is **REFUTED**. The patch records are a *userspace* buffer translated per frame; `cmdBuf` is fetched per frame from the gate.

---

## 2. Every allocation in the engine

| # | object | site descriptor | size | alloc site | free |
|---|---|---|---|---|---|
| 1 | `AppleAVDCommandPatcher` | `0xfffffff007f0e050` | `0x28` fixed | `createDecoder` @ `0xfffffff0086ad474` | `0xfffffff007f0e090`, @ `0xfffffff0086ad4a4` / `0xfffffff0086ac20c` |
| 2 | mapping-list entry (`addSharedMemToMappingList`) | `0xfffffff007f0e350` | `0x1a8` fixed | `sub_fffffff0086b60ec` | `0xfffffff007f0e390` in `sub_fffffff0086b61e0` |

- **No `kalloc_var`, no `IOMalloc(size)`, no size expression anywhere in the engine.** Consequently there is no `madd w` vs `madd x` question on the *allocation* path: the sizes are constants.
- `createDecoder` also allocates `m_framesInFlight` / `m_showExistingFrames` (`0x18`, descriptor `0xfffffff007f0e010`) and shared buffers via `createSharedBuffer` with fixed lengths `0x120` and `0x3c` (`sub_fffffff0086ad848` in `createDecoderHelper_UserParser`). None is client-sized.

### 2.1 Where `cmdBuf` actually comes from

`sub_fffffff0086afc2c` = `decodeFrameFigHelper_GetDecodeBufInFrameParamQ`. It sends FW gate command `0xc` (`bl sub_fffffff00868697c(..., &var_90, 0xc)`) and returns three values:

```c
*arg2 = *(&var_88 + 8);   // var_128  = kernel decode buffer pointer
*arg3 = *(&var_78 + 4);   // var_12c  = slot / resource id
*arg4 = var_78;           // var_130  = size (32-bit)
```

(Disassembly `0xfffffff0086afd7c`: `ldr x8,[sp,#0x40] / str x8,[x24]` → pointer; `ldp w9,w8,[sp,#0x48] / str w8,[x23] / str w9,[x21]` → two u32.) So the buffer **and its size** are both produced by the gate. The kext does not allocate it.

---

## 3. Capacity vs. count (patch records)

`sub_fffffff0086b4e2c` = `patchIntoDecodeBuffer`. The patch list is a **userspace** buffer; the record count `numRequests` (`arg8`) is checked and used as the *mapping length*:

```asm
0xfffffff0086b4ecc  mov   w8, #0x5556
0xfffffff0086b4ed0  movk  w8, #0x555, lsl #0x10   ; w8 = 0x5555556
0xfffffff0086b4ed4  cmp   w21, w8                  ; w21 = numRequests, 32-bit
0xfffffff0086b4ed8  b.lo  0xfffffff0086b4f10       ; unsigned <
...
0xfffffff0086b4f10  add   w8, w21, w21, lsl #0x1   ; w8  = numRequests*3
0xfffffff0086b4f14  lsl   w2, w8, #0x4              ; w2  = numRequests*0x30   (32-bit)
0xfffffff0086b4f1c  mov   x0, x19
0xfffffff0086b4f20  mov   x1, x24
0xfffffff0086b4f24  bl    sub_fffffff0086b5030      ; translateToKVA(patchList, numRequests*0x30)
```

`translateToKVA` (`sub_fffffff0086b5030`) rejects unless `arg3 <= *(entry+0x2c)` (the mapping's own length):

```c
else if (arg3 <= *(i + 0x2c)) { result = 0; *arg4 = i[1]; }   // KVA returned
else { ... "OOB (length=%u) for returned mapping" ... }
```

The applier (`sub_fffffff0086b5400`, = `patchCommand`) is the **only** consumer of the list and loops exactly `arg3 = numRequests` times:

```c
while (true) {
    int64_t* x8_1 = arg2 + x19_1 * 0x30;      // record i, 48 bytes
    uint64_t x21_1 = x8_1[3];                 // offset
    uint64_t x24_1 = x8_1[5];                 // field size (2 or 4)
    if (x21_1 + x24_1 < x21_1 || x21_1 + x24_1 > arg5) { ... break; }  // carry + bound
    ...
    x19_1 += 1; x20_1 -= 1; if (temp0_1 != 1) continue; break;
}
```

- **Capacity:** the list mapping must be ≥ `numRequests*0x30`; the loop reads exactly `numRequests` × `0x30`. Consistent.
- **Count:** there is no kernel-side `count++`/capacity pair — the count is the request field and is simultaneously the length divisor. No append-without-capacity-check exists.
- `bn_function_callers`: `sub_fffffff0086b5400` ← only `sub_fffffff0086b4e2c`; `sub_fffffff0086b4e2c` ← only `sub_fffffff0086affac` (`createAndSubmitDecodeCMD`). No alternate path to the applier.

**⇒ REFUTED: no capacity/count divergence.**

---

## 4. Integer overflow

- `numRequests * 0x30` is computed **32-bit** (`add w8,w21,w21,lsl#1 ; lsl w2,w8,#4`), but the guard `numRequests < 0x5555556` (unsigned) bounds it at `0x5555555*0x30 = 0xFFFFFFF0 < 2^32`. **Exact, no truncation.**
- `copyUserspaceToKernel` (`sub_fffffff0086b511c`) is explicitly overflow-hardened:
  - `x23_1 = arg6[1]*x9_1; if (x23_1 & 0xffffffff00000000 || x8_1 + x23_1 < x8_1) reject;`
  - `if (x13_1 + x11_2 < x13_1) reject;` and `if (x13_2 + x12_2 < x13_2) reject;` for the 2×/4× scaled arrays
  - per work unit: `x11_4 = x10_6*x8_7; if (x11_4 & 0xffffffff00000000) break; if (x9_6+x11_4 < x9_6) break; if (x9_6+x11_4 > arg4) break;`
- The applier re-checks the offset carry (`x21_1 + x24_1 < x21_1`) before the bound.

**⇒ REFUTED: no 32-bit product is used as an allocation size or a bound.**

---

## 5. The bound chain — the one real question

`patchIntoDecodeBuffer(patcher, userDecodeBuf, kernelDecodeBuf, size, gateSize, layoutDesc, patchList, numRequests, frameNum)`:

```c
int64_t result = arg3;                                              // kernel decode buffer (var_128)
int64_t x0_2 = sub_fffffff0086b5030(arg1, arg2, arg4, &var_58);     // translate user decode buf, len=arg4
if (arg8 < 0x5555556) {
    int64_t x0_4 = sub_fffffff0086b5030(arg1, arg7, arg8*0x30, &var_60);   // translate patch list
    int64_t x0_6 = sub_fffffff0086b511c(arg1, var_58, result, arg4, arg5, arg6);  // copy user->kernel
    if (!x0_6)
        if (sub_fffffff0086b5400(arg1, x24_1, arg8, result, arg4, arg9)) { ... }  // APPLY, bound = arg4
}
```

- `arg4` = `arg2[1]` of the submit request (client-supplied decode-buffer size).
- `arg5` = `var_130` (gate-returned size).
- The applier is reachable **only** if `copyUserspaceToKernel` returned 0, and its first check is:

```c
if (arg4 <= arg5) { ...all size checks relative to arg4... }
else { result = 0xe00002bc; /* "decodeBufferSize too large! (%u > %u)" */ }
```

So `arg2[1] <= var_130` is enforced **before** the `bzero(kernelBuf, arg4)`/`memcpy`, and the same clamped `arg4` bounds the patch writes. The engine's write window is `[0, arg2[1]) ⊆ [0, var_130)`.

**⇒ The engine is bounds-consistent, given that `var_130` is the true capacity of `var_128`.** That equality is a property of the gate (FW/PQ shared response), not of the kext's arithmetic, and cannot be proven or disproven from this kext alone.

---

## 6. Lifecycle / reconfiguration

- `createDecoder` (`sub_fffffff0086ace8c`) ← `sub_fffffff0086abac8` (a `tailcall` thunk with **no direct callers** → reached via the UC dispatch table). One patcher per session; state machine prevents re-entry (`state==1` → `3`).
- Destroy: `sub_fffffff0086ac048` (`DeallocateUserClientKernelMemory`) → `sub_fffffff0086b42dc(patcher)` then `kfree(desc 0xfffffff007f0e090)`; sets `session+0x398 = 0`.
- **`setResolutionInfo` (`sub_fffffff008689240`) has exactly one caller: `createDecoder` (callsite `0xfffffff0086ad5a8`).** There is no standalone resolution-change selector that re-runs it.
- The kernel decode buffer + size are re-fetched **every frame** from the gate (`sub_fffffff0086afc2c`, command `0xc`), so no stale geometry can survive a resolution change.

**⇒ REFUTED: the "buffer sized for old geometry, bound updated for new geometry" reconfiguration race does not exist in the direct call graph. A resolution change requires destroy + create, which allocates a fresh 0x28 patcher and re-fetches the buffer with its size.**

---

## 7. Ranked candidates

| # | candidate | confidence | basis |
|---|---|---|---|
| 1 | Allocation-size vs. bound divergence (rounding/truncation/recompute) in the patch engine | **REFUTED** | no size-parameterised allocation exists; all sizes are `kalloc_type` constants (`0x28`, `0x1a8`); `cmdBuf` is gate-provided |
| 2 | Patch-record capacity vs. count overflow | **REFUTED** | count == length divisor; `numRequests*0x30` 32-bit but guarded `< 2^32`; applier loops exactly the validated count |
| 3 | 32-bit size product used as alloc/bound | **REFUTED** | explicit `>>32` and carry checks in `copyUserspaceToKernel`; applier carry check |
| 4 | Resolution-change stale-size race | **REFUTED** | `setResolutionInfo` only from `createDecoder`; buffer+size re-fetched per frame from gate |
| 5 | Kept trust: `var_130` (gate-returned size) assumed == capacity of `var_128`; the applier write bound is clamped only by this FW value | **SPECULATIVE** | `if (arg4 <= arg5)` is the sole clamp; if a gate/PQ response can be made inconsistent with the buffer it describes, the clamp is void. Requires the PQ/gate + `AVD.videodecoder` plugin RE; not decidable in this kext |
| 6 | Mapping-entry `length` at `+0x2c` copied from `memInfo` (`m_vpInstrFifoSharedMem`) and trusted by `translateToKVA` as the mapping length | **SPECULATIVE** | `addSharedMemToMappingList` (`sub_fffffff0086b60ec`) copies `memInfo[0..0xa]` verbatim; if `memInfo.length > actual mapping`, `copyUserspaceToKernel` and the patch value resolver read/write OOB. Source is FW shared memory, not directly client-controlled |
| 7 | Record field `fieldSize` used as a write width | **REFUTED** | applier enforces `x24_1 == 4 || x24_1 == 2`, else logs "Field size (%d) not supported" and aborts |

### Negative result is a real result

The prior `REPORT_AVD.md` §2c model ("per-frame bounded kernel writes into a firmware command buffer, validating offset against `cmdBufSize`") is **structurally correct but mis-attributed**: the buffer is the *kernel decode buffer* (gate-provided per frame), the bound is the *client decode-buffer size* (clamped by the gate size), and the patch-record array is a *userspace mapping*, not a kernel allocation. The interesting residual is item 5 — a trust assumption on a FW/PQ response — which is outside this kext's audit boundary.

---

*Method note: `bn_data_xrefs_*` and string xrefs return empty on this view; all reachability above uses `bn_function_callers`/`bn_function_callees` and direct decompilation/disassembly. Descriptor sizes decoded from raw `bn_memory_read` of `__kalloc_type` sites and cross-validated against an independently observed linked-list stride. All addresses are quoted from the disassembly/decompiler output; none are fabricated.*
