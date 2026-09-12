> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AVD.videodecoder — SPS work-buffer overflow & FW patch-descriptor builder

Target: `AVD.videodecoder` (Mach-O, ios-aarch64), iOS 27.0 RC (24A435), image base `0x22a341000`, 4373 functions.
Tooling: Binary Ninja MCP only, read-only (no `bn_binary_view_set_active`, no `bn_open_item_open`). Every address/quote below comes from a `bn_function_decompile` / `bn_function_disassembly` query in this session.

---

## 0. Verdicts

| Lead | Verdict | One-line reason |
|---|---|---|
| 1 — 32-bit wrap in `CAHDecSalviaAvc::allocWorkBuf_SPS` @ `0x22a42cef0` | **REFUTED** (as reachable) | The `madd w` wrap is real, but the operands are clamped by `parseSPS` to ≤ 0x4000 and the only dims that wrap exceed the kext `setResolutionInfo` gate (maxDim 0x10000 → mbs ≤ 4095 → max product 2^30). Latent, not reachable. |
| 2 — FW patch descriptor builder `CAHDec::addToPatcherList` @ `0x22a35c2b0` | **SPECULATIVE** (no plugin-side bug proven) | Record layout fully mapped. `offset` is plugin-chosen and kext-validated against `cmdBufSize`; the only real defect is a 64→32 truncation of the `size/addend` field, which is **not** the kext's write bound. A bug would require a kext-side `cmdBufSize ≠ allocation` mismatch (not visible in this view). |

No fabricated code. Two clean negatives are reported.

---

## 1. Lead 1 — the 32-bit `madd` in `allocWorkBuf_SPS`

### 1.1 Quoted expression (decompiler, `0x22a42cef0`)

```c
*(this + 0x3e18) = (x9 << 6) + 0x40;
*(this + 0x3e14) = (x9 << 6) + 0x40 + ((x9 << 6) + 0x40) * x21;
```

with `x9 = *(arg2 + 0x616)` and `x21 = *(arg2 + 0x618)`.

### 1.2 Disassembly — the arithmetic is 32-bit (this is the decisive quote)

```asm
0x22a42cf10  ldrb    w10, [x1, #0x4]
0x22a42cf14  ldrh    w9,  [x1, #0x616]      ; x9 = SPS+0x616, 16-bit load
0x22a42cf18  lsl     w20, w9, #0x4
0x22a42cf1c  ldrh    w21, [x1, #0x618]      ; x21 = SPS+0x618, 16-bit load
...
0x22a42d044  lsl     w9, w9, #0x6           ; 32-bit
0x22a42d048  add     w9, w9, #0x40          ; 32-bit
0x22a42d04c  str     w9, [x19, #0x3e18]
0x22a42d050  madd    w9, w9, w21, w9        ; *** madd W ***  w9 = w9*w21 + w9, 32-bit
0x22a42d054  str     w9, [x19, #0x3e14]
```

`madd w9, w9, w21, w9` is the **32-bit** form (a 64-bit multiply would be `madd x`). The product wraps mod 2^32. Algebraically the stored value is `64·(x9+1)·(x21+1) mod 2^32`.

### 1.3 What the value is used for: an **allocation size** (not a bound, not an index)

`+0x3e14` is consumed exactly once in the function, as the size argument of the plugin allocator:

```asm
0x22a42d0e8  ldr     w2, [x19, #0x3e14]     ; size (32-bit, zero-extended)
0x22a42d0f0  ldr     x0, [x19, #0x1b8]
0x22a42d0f8  add     x1, x23, x8
0x22a42d108  bl      CAVDDecoder::allocAVDMem
```

The same pattern allocates `+0x3e00` and `+0x3e04` (into `this+0x230+…` and `this+0x12b0+…`); `+0x3e14` allocates 24 buffers at `this+0x28b0+i*0xb0`. So the wrapped value is a **heap allocation size**, i.e. a wrapped small value would under-allocate the work buffers that later firmware/plugin code writes. `+0x3e18` (the row size) is *not* passed to `allocAVDMem` in this function.

### 1.4 Can x9/x21 reach wrap-inducing values? — parser clamp vs kext gate

**The parser clamps both fields.** `AVC_RBSP::parseSPS` @ `0x22a47370c` reads each as `ue(v)` and rejects `> 0x4000`:

```asm
0x22a473fe8  bl      AVC_RBSP::ue_v
0x22a473ff4  cmp     w0, #0x4, lsl #0xc      ; 0x4000
0x22a473ff8  b.ls    0x22a47401c
0x22a473ffc  ...     AVC_RBSP::parseSPS .cold.7  (reject)
0x22a47401c  strh    w21, [x23, #0x616]      ; store width field (16-bit)
0x22a474020  bl      AVC_RBSP::ue_v
0x22a47402c  cmp     w0, #0x4, lsl #0xc      ; 0x4000
0x22a474030  b.ls    0x22a47406c
0x22a474034  ...     AVC_RBSP::parseSPS .cold.6  (reject)
0x22a47406c  strh    w21, [x23, #0x618]      ; store height field (16-bit)
```

So `x9, x21 ∈ [0, 0x4000]` (16384). The maximum unwrapped product is `64·16385² = 17,181,966,400` → mod 2^32 = `2,097,216`; the wrap **is** arithmetically reachable from parser output. Example: `x9 = 16383, x21 = 4095` → `64·16384·4096 = 2^32 ≡ 0` (zero-byte allocation).

**But the kext resolution gate caps the dims far below that.** Per `REPORT_AVD.md` §2b the create/`setResolutionInfo` handler enforces `max(w,h) ≤ maxDim`, with `maxDim = 0x10000` (65536) in the `kVASetUnlimitedResolution` arm and `0x41f8` (16888) otherwise. The plugin builds the request from the raw SPS: in `CAVDAvcDecoder::processParserOut` @ `0x22a42ec00`, `*arg6 = (*(sps+0x616) << 4) + 0x10` and `*(arg6+4) = (*(sps+0x618) << 4) + 0x10`. Hence `x9 ≤ (65536-16)/16 = 4095`. At that ceiling the SPS product is `64·4096·4096 = 2^30 < 2^32` — **no wrap**. Reaching the wrap needs `(x9+1)(x21+1) ≥ 2^26`, i.e. pixels of order 262144×65520, which the gate rejects.

A secondary, *conditional* plugin-side check exists in `CAVDAvcDecoder::VAStartDecode` @ `0x22a42e2f0`:

```c
uint32_t x8_7 = *(x21_2 + 0x616);            // width mbs
*(this + 0xb9c) = (x8_7 << 4) + 0x10;
uint32_t x9_6 = *(x23_1 + x20_1*0x8b0 + 0x618);  // height mbs
*(this + 0xba0) = (x9_6 << 4) + 0x10;
if (*(this + 0xa) == 1 && !(*(this + 0x1d36) & 1) && (x8_7 > 0xff || x9_6 >= 0x100)) {
    CAVDAvcDecoder::VAStartDecode .cold.6(x20_1, x21_3, (x9_6 << 4) + 0x10);  // error
    return 0x136;
}
```

Its cold block `.cold.6` @ `0x22a4c1204` is called with `(sps index, width px, height px)`, matching the format string `"AppleAVD: ERROR: %{public}s(): AVC sps[%d] width %d height %d over size\n"` @ `0x22a4e56f9`. **This check is only active when `*(this+0xa) == 1`** (settable via `VASetParams` case `0x14`); the default leaves it off, so it is *not* the barrier. The kext gate is.

### 1.5 Verdict — REFUTED (latent only)

The 32-bit `madd` is a genuine integer-overflow defect and the wrapped result **is** used directly as a heap allocation size. However it is **not reachable**: the operands are clamped to ≤ 0x4000 by `parseSPS`, and every dimension that would wrap is larger than the kext's `maxDim` (65536 even in the unlimited arm), so `setResolutionInfo` rejects the session before the work buffer is used. Residual risk: if any future/alternate path calls `allocWorkBuf_SPS` (vtable slot +0x90, reached from `processParserOut`) **before** the resolution gate, the zero/small allocation would become a real under-allocation. No such path was found. Confidence: **REFUTED**, with the ordering caveat noted.

---

## 2. Lead 2 — the FW patch descriptor builder

### 2.1 Exact record layout (from the stores in `addToPatcherList` @ `0x22a35c2b0`)

Record stride is `0x30` (48 B), base `x8 = *(this+0x48)`, index `w10 = *(this+0x40)`:

```asm
0x22a35c424  ldr     x9,  [x27]              ; x9 = arg2[0]
0x22a35c434  ldr     d0,  [x27, #0x98]       ; arg2[0x98] (8 bytes)
0x22a35c438  str     d0,  [x12, #0x10]       ; rec+0x10 = arg2[0x98]
0x22a35c43c  stp     w26, w25, [x12, #0x18]  ; rec+0x18 = arg3, rec+0x1c = arg4
0x22a35c440  stp     x9,  x24, [x12]         ; rec+0x00 = arg2[0], rec+0x08 = arg5
0x22a35c444  stp     w23, w6,  [x12, #0x20]  ; rec+0x20 = arg6, rec+0x24 = arg7
0x22a35c448  strb    w7,  [x12, #0x28]       ; rec+0x28 = arg8
0x22a35c44c  add     w8, w10, #0x1
0x22a35c450  str     w8, [x20]               ; *(this+0x40) = count+1
```

| Off | Width | Source | Role (cross-referenced to `REPORT_AVD.md` §2c kext model) |
|---|---|---|---|
| +0x00 | u64 | `arg2[0]` (first qword of `_avd_client_mem_info`) | **value source** — base pointer of the client memory region |
| +0x08 | u64 | `arg5` | **mask** (callers pass `0xffffffff` / `0x3ffffffffff`) |
| +0x10 | u64 | `arg2[0x98]` | second half of value source (descriptor / IOSurface-id field) |
| +0x18 | u32 | `arg3` | **offset** into the firmware command buffer |
| +0x1c | u32 | `arg4` | **size / addend** (truncated from 64-bit, see §2.3) |
| +0x20 | u32 | `arg6` | **truncate** shift (callers pass 0, 8, or 0x20 — all ≤ 0x40) |
| +0x24 | u32 | `arg7` | **bitfield mask** (callers pass `0xffffff00`, `0x3ff`, …) |
| +0x28 | u8 | `arg8` | **field size** — always 4 or 2, matching the kext's "2 or 4 only" rule |

Semantic mapping to the kext names in `REPORT_AVD.md` §2c: `offset = arg3`, `mask = arg5`, `addend = arg4`, `truncate = arg6`, `bitfieldMask = arg7`, `fieldSize = arg8`, value source = `arg2`. (The prior report's raw `rec[i]` indices are a different struct view; the roles line up one-to-one.)

### 2.2 Caller trace — what controls each field

`addToPatcherList` is called from ~40 decoder generations. Representative sites:

- **`CAHDecSalviaAvc::populateAvdWork` @ `0x22a42ccfc`**
  ```c
  CAVDAvcDecoder::GetSDataMemInfo(*(this+0x1b8), i, &var_68, &var_70);
  ...
  result = CAHDec::addToPatcherList(this, x26_1, x22_1, x27_1, 0xffffffff, 0, 0xffffffff, 4);
  ```
  `arg3 = x22_1 = 0x8aadc + i*0x28` — a **constant base plus slice index** (loop `i < arg2`); `arg4 = var_70` — a **64-bit size from `GetSDataMemInfo`**; `arg5/6/7 = 0xffffffff/0/0xffffffff`; `arg8 = 4`.

- **`CAHDecTansyAvx::populateAvdWork` @ `0x22a37c4c4`**
  ```c
  result = CAHDec::addToPatcherList(this, x25_2, x22_1 + 0xc614, x26_1, 0xffffffff, 0, 0xffffffff, 4);
  ...
  result = CAHDec::addToPatcherList(this, x25_2, x22_1 + 0xc612, x26_2, 0x3ffffffffff, 0x20, 0xffffffff, 2);
  ```
  `arg3` is **tile-derived**: `x22_1 = x25_1*0x24`, `x25_1` computed from the tile loop, base `0xc600`; `arg4 = var_78` from `GetTileMemInfo`; `arg8 = 2` in the second call.

- **`CAHDecTansyAvc::populatePictureRegisters` @ `0x22a35fad8`** — `arg3` is a **fixed command-buffer offset** (`0x5c`, `0x94`, `0x98`, `0x9c`, `0xa0`, `0x238`, `0x23c`, `0x240`, looping `0x5c…0x238`); `arg4` is `0` or `(*(x9_35+0x10) & 0xf) << 9` (a register field, ≤ 0x1e00); `arg5/6/7` are masks; `arg8 = 4`.

So: **offset (`arg3`) is always plugin-computed** — either a hard-coded base + index (bounded by the slice/tile count, itself bounded by `AVC_MAX_SLICES = 0x384` per `processParserOut .cold.10`) or a small fixed constant. It is not a raw attacker bitstream value; it is a function of bitstream-derived counts, and the kext re-validates `offset + fieldSize ≤ cmdBufSize`.

### 2.3 The one concrete defect: 64→32 truncation of the size field

Every caller that supplies a real region size (`arg4`) first checks the high word and **logs a warning but proceeds**:

```c
uint64_t x27_1 = var_70;                     // from GetSDataMemInfo / GetTileMemInfo (u64)
if (x27_1 >> 0x20 && os_log_enabled(...)) {
    log("AppleAVD: WARNING: %{public}s(): %s %d 64->32 conversion problem!\n", "populateAvdWork", 0x820, 0x615);
    x27_1 = var_70;
}
result = CAHDec::addToPatcherList(this, x26_1, x22_1, x27_1, ...);   // arg4 truncated to 32-bit
```

`arg4` is declared `uint32_t`, so a >4 GiB region size is silently truncated at `rec+0x1c`. **This is not the kext's write bound** — the kext bounds the write by `fieldSize` (`arg8 ∈ {2,4}`) against `cmdBufSize`, and uses `arg4` only as an addend in `(value + addend)`. So the truncation alters a computed *value*, not an extent; no memory-safety consequence follows from it alone. (This is the same "64→32 conversion problem" warning class the prior PPS audit logged at `avd_pps_workbuf.md` §3.)

### 2.4 Record count

`*(this+0x40)` is the count; `*(this+0x44)` is the capacity. When `count < capacity` the record is appended; otherwise the list is reallocated to `(capacity+0x100)*0x30` and `capacity += 0x100`:

```asm
0x22a35c310  cmp     w10, w9
0x22a35c314  b.lo    0x22a35c420           ; count < capacity -> append
...
0x22a35c364  add     w8, w9, #0x100
0x22a35c370  umull   x2, w8, w9            ; (capacity+0x100)*0x30 in 64-bit -> no overflow
```

There is **no plugin-side hard cap**; growth is by 0x100 entries and the multiplication is 64-bit. The kext independently caps `numRequests < 0x5555556`. The count the kext receives is the same `*(this+0x40)` the plugin increments, so count and records are consistent.

### 2.5 Verdict — SPECULATIVE (clean negative)

The plugin builds well-formed 48-byte records; `offset` is plugin-chosen and kext-validated, `fieldSize` is always 2 or 4, and the count is consistent. The only defect proven in the plugin is the 64→32 truncation of the size/addend field, which the kext does not use as the write extent. The open question — **"can a plugin-computed offset pass the kext's `offset + fieldSize ≤ cmdBufSize` check while the write lands outside the intended region?"** — reduces entirely to whether `cmdBufSize` equals the real `cmdBuf` allocation. That is a **kext-side** question (the patch applier `FUN_fffffff0084c6bd4`) and cannot be answered from the `AVD.videodecoder` view. No plugin-side primitive was found. Confidence: **SPECULATIVE**, leaning REFUTED on the plugin side.

---

## 3. Suggested next step (needs the kext view)

The single decisive check left for Lead 2 is the kext side: verify that the `cmdBufSize` handed to the patch applier is derived from the *same* allocation that produced `cmdBuf`, and that the patch-list buffer (plugin `this+0x48`, sized `(capacity)*0x30`, initial `0x3000`) and the command buffer are not confusable. That is not observable from `AVD.videodecoder`.
