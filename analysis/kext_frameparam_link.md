> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleAVD — FrameParam slot buffer size vs. `obj+0x6c0` (patch-applier bound)

Target: `com.apple.driver.AppleAVD`, iOS 27.0 RC (24A435), mac-aarch64, Binary Ninja MCP (read-only).
Question: can the firmware-command applier (`patchCommand`, `sub_fffffff0086b5400`) write out of
bounds because its base is a **per-slot** pointer while its bound is validated against a **global**
size field `*(obj+0x6c0)`?

## TL;DR

**REFUTED.** The per-slot buffers at `obj+0x138 + slot*0xb0` are allocated with exactly the same
32-bit constant that is written to `obj+0x6c0` (e.g. `0xb8950`), for all 8 slots, by every frame-param
allocator. `obj+0x6c0` is not a "global max" that can exceed a slot allocation — it *is* the slot
allocation size, set by the allocator. Additionally the client-declared size is explicitly clamped to
`obj+0x6c0` by `copyUserspaceToKernel` before the applier ever runs. Bound == allocation.

## 1. Write sites for `obj+0x6c0` (the value's provenance)

`obj+0x6c0` is written in the frame-param allocators, immediately after allocating the 8 slot buffers,
with the **same constant** used as the allocation size:

`allocateAPCommFrameParams` = **`sub_fffffff00867933c`** (0xfffffff00867933c):
```c
do {
    result = sub_fffffff00868ad94(*(arg1 + 0x6c8), 0xb8950, 2, arg1 + 0x138 + i*0xb0, x20);
    i += 1;
} while (i != 8);
*(arg1 + 0x6c0) = 0xb8950;                 // <-- write
```
Disassembly of the write (confirms 32-bit width, constant `0xb8950`):
```
0xfffffff0086793e4  mov     w8, #0x8950
0xfffffff0086793e8  movk    w8, #0xb, lsl #0x10      ; w8 = 0xb8950
0xfffffff0086793ec  str     w8, [x19, #0x6c0]       ; 32-bit store
```

Second variant, **`sub_fffffff0086a2c6c`** (0xfffffff0086a2c6c) — identical:
```c
result = sub_fffffff00868ad94(*(arg1 + 0x6c8), 0xb8950, 2, arg1 + 0x138 + i*0xb0, x20);  // i=0..7
*(arg1 + 0x6c0) = 0xb8950;
```

Third variant, **`sub_fffffff0086b15fc`** (0xfffffff0086b15fc) — different object class, still matched:
```c
result = sub_fffffff00868ad94(*(arg1 + 0x6c8), 0x113148, 2, arg1 + 0x138 + x21*0xb0, x20); // 8x
*(arg1 + 0x6c0) = 0x113148;
```

These are reached from the `initAvdWrap` wrappers, e.g. `sub_fffffff00867a27c`:
```c
"AppleAVD: INFO: %s(): allocate FrameP\n"   // %s = "allocateAPCommFrameParams"
sub_fffffff00867933c(arg1);
```
The only other "size"-looking string, `m_maxFrameParamsInFlight changed from %d to %d`, names a
*different* (count) field, not `+0x6c0`: `+0x6c0` is consumed as a byte buffer size (see §3) and is
compared for equality against `m_decodeCmdSize` (see below), which a small count could not satisfy.

## 2. Allocation site for the per-slot buffer, with size expression

`sub_fffffff00868ad94` is the alloc/map wrapper (`AllocKernelMem`-equivalent):
```c
x0 = sub_fffffff0086c1c14(-0xfffffff007f0c9d0);   // kern_mem_info
arg4[4] = x0;                                      // descriptor+0x20 = kern_mem_info
result = sub_fffffff008689500(arg1, 0, arg2, arg3, 1, 0, arg4, 0, 0, 0, arg5);
```
`sub_fffffff008689500` is **`allocateKernelMemoryInternal`** (its own string is in the body) and treats
`arg3` as the byte size:
```c
int64_t x27 = arg3;                       // size
if (arg3 < 0xcc00001) {
    x28_1 = (x27 + align - 1) & -align;   // round up
    if (x28_1 >> 0x20) { "actualAllocSize > 32 bits!"; return 0xe00002bc; }
    ...
```
So the per-slot buffer size is the constant passed to `sub_fffffff00868ad94`, i.e. `0xb8950`
(or `0x113148`), **the same constant stored to `obj+0x6c0`**. The descriptor's `+8` pointer
(the KVA read by `getFrameParamAddr`) is filled by this allocator; `~CAvdApComm`
(`sub_fffffff00867c300`) frees the same slots by reading descriptor `+0x20`.

Array geometry: `0x138 + 8*0xb0 = 0x6b8`; the 8-slot array is `0x580` bytes and `+0x6c0` sits just past
its end. All loops are hard-limited to 8 (`i != 8`, and `getAvailableSlotInFrameParamQ` stops at 8).

## 3. Direct size comparison, with arithmetic widths

Reader (the size that becomes the applier's bound-side limit) — `getFrameParamAddr`
**`sub_fffffff00867c424`**:
```
0xfffffff00867c428  add  x8, x0, #0x138
0xfffffff00867c42c  mov  w9, #0xb0
0xfffffff00867c430  umull x9, w1, w9         ; slot(w1,32) * 0xb0 -> 64-bit
0xfffffff00867c434  orr  x9, x9, #0x8
0xfffffff00867c44c  ldr  x8, [x10]           ; base = *(obj+0x138+slot*0xb0+8)   (8-byte)
0xfffffff00867c450  ldr  w9, [x0, #0x6c0]    ; size = *(obj+0x6c0)              (32-bit)
```
So `size = obj+0x6c0` (32-bit) and `base = obj+0x138+slot*0xb0+8` (8-byte pointer), same object.

`allocDecodeCmd` (`sub_fffffff008663024`) independently enforces equality of the slot buffer size with
the caller's decode-cmd size:
```c
*(arg1 + 0x18) = arg2;                                   // m_decodeCmdSize = arg2
sub_fffffff008663128(arg1, arg1+0x10, arg1+0x1c, &var_24);   // -> base, bufIdx, var_24 = obj+0x6c0
if (var_24 == *(arg1 + 0x18) || *(arg1 + 0x1c) == 0xffffffff) return 0;
else  "frameParQbufSize(%u) != m_decodeCmdSize(%u)";     // hard reject
```

The decisive clamp is in `copyUserspaceToKernel` **`sub_fffffff0086b511c`**:
```c
if (arg4 <= arg5) { ... }            // arg4 = client-declared size, arg5 = obj+0x6c0
else { "decodeBufferSize too large! (%u > %u)"; return 0xe00002bc; }
```
Caller chain (verified against disassembly):
- `createAndSubmitDecodeCMD` (`sub_fffffff0086affac`), call site `0xfffffff0086b0610`:
  ```
  ldr  x0, [x19, #0x398]      ; commandPatcher
  ldr  x1, [x20]              ; frame param record +0
  ldr  x2, [sp, #0x38]        ; arg3 = var_128 (base)   <- getFrameParamAddr per-slot ptr
  ldr  w3, [x20, #0x8]        ; arg4 = client-declared size (32-bit!)
  ldr  w4, [sp, #0x30]        ; arg5 = var_130 = obj+0x6c0 (32-bit)
  ...
  bl   sub_fffffff0086b4e2c
  ```
- `patchIntoDecodeBuffer` (`sub_fffffff0086b4e2c`) copies via `sub_fffffff0086b511c(arg1, var_58,
  result, arg4, arg5, arg6)` (clamped), and only on success calls
  `sub_fffffff0086b5400(arg1, x24_1, arg8, result, arg4, arg9)` — i.e. applier base = `result` (=arg3),
  applier bound = `arg4` = the same client size that was just proven `<= obj+0x6c0`.

Widths: bound/size arithmetic is uniformly **32-bit** — client size `ldr w3`, `obj+0x6c0` `ldr w`,
allocation constant `mov w/movk w`, and in the applier `ldr w21,[x8,#0x18]`, `adds w9,w21,w24`,
`cmp w9,w10; b.hi` with the zero-extended `x21` used only as the final index. No 64-bit widening
mismatch; no path where `bound > allocation`.

## 4. Slot-index bounds

- Applier's slot comes from `getAvailableSlotInFrameParamQ` (`sub_fffffff008663db8`): it scans for the
  first free index and returns failure at 8:
  ```c
  while (*(arg1 + 0x18 + (slot << 2))) { slot += 1; if (slot == 8) return 0; }
  sub_fffffff00867c424(*(arg1 + 0x10), slot, arg3, arg4);   // slot in [0,7]
  ```
  So the applier's base index is bounded `0..7`.
- `getSpecifiedFrameParamQ` (`sub_fffffff0086635a4`) takes `arg2` (bufIdx) **without** an explicit
  bounds check; it indexes `manager+0x38+arg2*4`, `manager+0x18+arg2*4`, then
  `getFrameParamAddr(*(manager+0x10), arg2, ...)` → `obj+0x138+arg2*0xb0`. Its only argument
  validation is the clientID compare (`*(manager+0x38+arg2*4) == arg5`). Its caller is
  `avdOutbox0ISR` (`sub_fffffff008683fe4`) using a **firmware-queue-supplied** bufIdx
  (`*(&var_120 + 0xc)`), and the resulting base/size are handed to `sub_fffffff00867e454`
  (error/report path), **not** to the patch applier. This is a distinct, firmware-controlled
  OOB-read question and does not affect the applier write bound.
- All 8 slots are allocated with one identical constant inside the allocator loop, so **no two slots
  can have differently-sized buffers**.

## 5. Verdict

**REFUTED.** For every frame-param allocator found (`sub_fffffff00867933c`,
`sub_fffffff0086a2c6c`, `sub_fffffff0086b15fc`), the 8 per-slot buffers at `obj+0x138+slot*0xb0` are
allocated with size `S` and `obj+0x6c0` is set to the *same* `S` (0xb8950 / 0xb8950 / 0x113148). The
applier's bound is the client-declared size, which `copyUserspaceToKernel` rejects unless
`clientSize <= obj+0x6c0 = S`. Therefore `bound <= allocation` always; the earlier hypothesis that a
per-slot buffer can be smaller than `obj+0x6c0` does not hold. The prior trace was correct about the
chain but wrong about the conclusion: the "global" `obj+0x6c0` and the per-slot allocation size are the
same value by construction, not independent.

No out-of-bounds kernel write is demonstrated on this path.

### Addresses used (all from live Binary Ninja queries)
| Role | Function |
| --- | --- |
| Patch applier (`patchCommand`) | `sub_fffffff0086b5400` |
| Translator (`patchIntoDecodeBuffer`) | `sub_fffffff0086b4e2c` |
| Copy + size clamp (`copyUserspaceToKernel`) | `sub_fffffff0086b511c` |
| Caller (`createAndSubmitDecodeCMD`) | `sub_fffffff0086affac` (call @ 0xfffffff0086b0610) |
| Gate get-decode-buf (cmd 0xc) | `sub_fffffff00868697c` → `sub_fffffff008682a48` → `sub_fffffff00868317c` → `sub_fffffff008685640` |
| Slot picker (`getAvailableSlotInFrameParamQ`) | `sub_fffffff008663db8` |
| `getFrameParamAddr` | `sub_fffffff00867c424` |
| `allocDecodeCmd` | `sub_fffffff008663024` |
| Frame-param allocators | `sub_fffffff00867933c`, `sub_fffffff0086a2c6c`, `sub_fffffff0086b15fc` |
| Alloc wrapper → `allocateKernelMemoryInternal` | `sub_fffffff00868ad94` → `sub_fffffff008689500` |
| `~CAvdApComm` (frees slots) | `sub_fffffff00867c300` |
| `initAvdWrap` | `sub_fffffff00867a27c` |
