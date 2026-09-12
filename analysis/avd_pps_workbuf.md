> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AVD.videodecoder — PPS work-buffer allocation path audit

Target: `AVD.videodecoder` (Mach-O, ios-aarch64), iOS 27.0 RC (24A435), image base `0x22a341000`, 4373 functions.
Tooling: Binary Ninja MCP only (read-only queries; no `bn_binary_view_set_active`, no `bn_open_item_open`).
Date: 2026-09-11

---

## 0. Executive summary (honest result)

**The specific hypothesis under investigation — "`getPPSWorkBufSize` does not write offsets 0x10 / 0x1c / 0x24, so `ppsWorkBufSizeIncrease`'s 13-field predicate misses three fields and a stale, too-small buffer is reused" — is FALSE.**

Disassembly proves all 13 size fields (0x00..0x30) are written on every path, including the three named fields, via 8-byte and 16-byte SIMD stores that the decompiler rendered as scalar u32 stores. The predicate compares the same 13 fields, and `allocWorkBuf_PPS` / `freeWorkBuf_PPS` use the identical field→buffer mapping and the identical `new > cached` predicate. The alloc/reuse/free/compare quartet is internally consistent.

No PROVEN memory-safety bug was found in this path. Three SPECULATIVE leads and one OPEN question are recorded below. A negative result is reported rather than a fabricated one.

---

## 1. Implementation inventory

Base-class stubs (no-op) — these are *not* the real implementation:
| class | function | address | shape |
|---|---|---|---|
| `CAHDec` | `getPPSWorkBufSize` | `0x22a3728e8` | 1 BB, `{ return; }` (writes nothing) |
| `CAHDec` | `ppsWorkBufSizeIncrease` | `0x22a3728ec` | 1 BB, `{ return 0; }` |

Real Avx implementations (all 44-BB `getPPSWorkBufSize` + 14-BB `ppsWorkBufSizeIncrease` — identical shape):
| generation | getPPSWorkBufSize | ppsWorkBufSizeIncrease | allocWorkBuf_PPS | freeWorkBuf_PPS | matches Tansy shape |
|---|---|---|---|---|---|
| TansyAvx | `0x22a37ce24` | `0x22a37daec` | `0x22a37dbc8` | `0x22a37e390` | reference |
| CatnipAvx | `0x22a3a2648` | `0x22a3a2f28` | `0x22a3a3004` | `0x22a3a37cc` | yes |
| IxoraAvx | `0x22a3d6ea4` | `0x22a3d7850` | `0x22a3d792c` | `0x22a3d8148` | yes |
| DaisyAvx | `0x22a407658` | `0x22a407f38` | `0x22a408014` | `0x22a408830` | yes |
| HibiscusAvx | `0x22a4224b0` | `0x22a422d90` | `0x22a422e6c` | `0x22a42378c` | yes (different buffer offsets, see §5) |
| **BorageAvx (new in 27.0 RC)** | `0x22a441f94` | `0x22a442874` | `0x22a442950` | `0x22a443118` | yes |
| **KopsiaAvx (new in 27.0 RC)** | `0x22a4863b4` | `0x22a486c94` | `0x22a486d70` | `0x22a48758c` | yes |
| ThymeAvx | `0x22a4a7420` | `0x22a4a7d00` | `0x22a4a7ddc` | `0x22a4a85a4` | yes |

Supporting objects:
- vtable `__ZTV14CAHDecTansyAvx` @ `0x273fda9e8` (chained-fixup encoded). vptr-relative slots used by the driver: `+0x120` = `getPPSWorkBufSize`, `+0x128` = `ppsWorkBufSizeIncrease`, `+0xa0` = `allocWorkBuf_PPS`, `+0xa8` = `freeWorkBuf_PPS` (these are symbol-relative `0x130`/`0x138`/`0xB0`/`0xB8`; the vptr sits 0x10 bytes past the symbol start, accounting for the earlier 0x10 discrepancy).
- driver: `CAVDAvxDecoder::initPicture` @ `0x22a3b84b0` (739 lines). It owns the `CAHDec*` at `this+0x830`, the decoder-state object at `*(this+0x3b48)`, and the "workbuf allocated" flag at `this+0x946c`.
- instantiation: `createTansyAvxDecoder` @ `0x22a378014`, sole caller `CAVDAvxDecoder::allocateHwDecoder` @ `0x22a3b7a1c`.
- cached sizes live at `decoderState + 0x13584 + 4*i` (13 × u32, cleared with `memset(..., 0, 0x34)`).

---

## 2. Hunt priority #1 — missing-field reuse — DISPROVED (PROVEN negative)

### 2.1 The predicate (`CAHDecTansyAvx::ppsWorkBufSizeIncrease` @ `0x22a37daec`, full asm)

```asm
0x22a37daec  ldr  w8, [x2]        ; new[0x00]
0x22a37daf0  ldr  w9, [x1]        ; cached[0x00]
0x22a37daf4  cmp  w8, w9
0x22a37daf8  b.gt 0x22a37dbac     ; -> return 1 (must grow)
...
0x22a37dba0  ldr  w9, [x1, #0x2c]
0x22a37dba4  cmp  w8, w9
0x22a37dba8  b.le 0x22a37dbb4
0x22a37dbac  mov  w0, #0x1
0x22a37dbb0  ret
0x22a37dbb4  ldr  w8, [x2, #0x30] ; new[0x30]
0x22a37dbb8  ldr  w9, [x1, #0x30] ; cached[0x30]
0x22a37dbbc  cmp  w8, w9
0x22a37dbc0  cset w0, gt
0x22a37dbc4  ret
```
Fields compared: `0x00,0x04,0x08,0x0c,0x10,0x14,0x18,0x1c,0x20,0x24,0x28,0x2c,0x30` — **all 13**. Predicate: `return 1` if any `new[i] > cached[i]` (signed `b.gt`), else `new[0x30] > cached[0x30]`.

### 2.2 The writer — all 13 fields ARE written (TansyAvx tail, asm @ `0x22a37d644`..`0x22a37d6dc`)

```asm
0x22a37d644  stp  w25, w23, [x22, #0x4]   ; 0x04, 0x08
0x22a37d650  stur d0, [x22, #0xc]         ; 0x0c AND 0x10   (8-byte store)
0x22a37d6c8  str  w24, [x22, #0x14]       ; 0x14
0x22a37d6d4  stp  d1, d0, [x22, #0x18]    ; 0x18,0x1c,0x20,0x24 (16-byte store)
0x22a37d6d8  stp  w21, w19, [x22, #0x28]  ; 0x28, 0x2c
0x22a37d6dc  str  w20, [x22, #0x30]       ; 0x30
```
`0x10`, `0x1c`, `0x24` are written as the high halves of `stur d0,[x22,#0xc]` and `stp d1,d0,[x22,#0x18]`. The decompiler showed these as scalar `*(arg3 + 0xc) = var_f0; *(arg3 + 0x18) = var_160; *(arg3 + 0x20) = var_c0;`, which is what created the false premise.

### 2.3 Confirmed on the NEW 27.0 RC class (`CAHDecBorageAvx::getPPSWorkBufSize` @ `0x22a441f94`, asm tail)

```asm
0x22a442738  str  w16, [x22]              ; 0x00
0x22a4427b4  stp  w25, w23, [x22, #0x4]   ; 0x04, 0x08
0x22a4427c0  stur d0, [x22, #0xc]         ; 0x0c AND 0x10
0x22a442838  str  w24, [x22, #0x14]       ; 0x14
0x22a442844  stp  d1, d0, [x22, #0x18]    ; 0x18,0x1c,0x20,0x24
0x22a442848  stp  w21, w19, [x22, #0x28]  ; 0x28, 0x2c
0x22a44284c  str  w20, [x22, #0x30]       ; 0x30
```
Identical shape, identical 64→32 warnings at lines `0x81d`/`0x821`. The output struct is exactly `0x34` bytes (13 × u32); there is no 14th field.

### 2.4 Conclusion
- No field is written-but-uncompared, and none is compared-but-unwritten.
- There is no "missing-field reuse" primitive in this path. Confidence: **PROVEN (negative)**.

---

## 3. Hunt priorities #2 & #3 — truncation and signed arithmetic (SPECULATIVE)

`getPPSWorkBufSize` computes sizes in 64-bit registers, checks the high word, and **logs a WARNING but does not reject**:
```asm
0x22a442744  adrp x0, 0x2681b5000
0x22a442750  bl   0x2300c6ff0        ; os_log_enabled?
0x22a4427a0  add  x3, x3, #0x608     ; "AppleAVD: WARNING: %{public}s(): %s %d 64->32 conversion problem!\n"
0x22a4427a8  mov  w2, #0
0x22a4427ac  mov  w5, #0x1c
0x22a4427b0  bl   0x2300c6c60        ; log
0x22a4427b4  stp  w25, w23, [x22,#4] ; <-- truncated store, execution continues
```
Two such paths exist (fields `0x04` and `0x14`; Tansy lines `0x825`/`0x829`, Borage lines `0x81d`/`0x821`), guarded by `lsr x8, x24, #0x20` / `cbz`.

Every consumer is signed:
- `ppsWorkBufSizeIncrease`: `b.gt` on `w` registers (signed).
- `allocWorkBuf_PPS`: `ldrsw x2, [arg4+off]` (sign-extended) then `if (x2 <= cached)`.
- `freeWorkBuf_PPS`: same signed `<=` checks.

**Consequence if reachable:** a required size that truncates to `>= 0x80000000` becomes negative, so all three functions classify it as "no growth" and the buffer is *not* reallocated, while the real requirement is ~4 GiB. That would be an under-allocation.
**Why it is only SPECULATIVE:** the size inputs are AV1 tile widths/heights and bit-depth factors, all bounded by the AV1 tile syntax (`tile_width_minus_1` is 12 bits → tile width ≤ 4096; tile counts ≤ 64×64). Reaching 2^32 requires an out-of-spec tile width that the RBSP parser must reject upstream. Not demonstrated. Confidence: **SPECULATIVE**.

---

## 4. Hunt priority #4 — alloc/free/compare consistency — NO divergence found (PROVEN negative)

`allocWorkBuf_PPS` field→descriptor mapping (verified against `freeWorkBuf_PPS`, which uses the *same* mapping in a permuted order):

| size field | alloc descriptor | cached size | free check field |
|---|---|---|---|
| 0x00 | `this+0x698` | `ds+0x13584` | 0x00 |
| 0x04 | `this+0x748` | `ds+0x13588` | 0x04 |
| 0x08 | `this+0x7f8` | `ds+0x1358c` | 0x08 |
| 0x0c | `this+0x8a8` | `ds+0x13590` | 0x0c |
| 0x10 | `this+0xb68` | `ds+0x13594` | 0x10 |
| 0x14 | `this+0xf88` | `ds+0x13598` | 0x14 |
| 0x18 | `this+0x958` | `ds+0x1359c` | 0x18 |
| 0x1c | `this+0xa08` | `ds+0x135a0` | 0x1c |
| 0x20 | `this+0xab8` | `ds+0x135a4` | 0x20 |
| 0x24 | `this+0xc18` | `ds+0x135a8` | 0x24 |
| 0x28 | `this+0xcc8` | `ds+0x135ac` | 0x28 |
| 0x2c | `this+0xed8` | `ds+0x135b0` | 0x2c |
| 0x30 | `this+0xe28` | `ds+0x135b4` | 0x30 |

All three functions use the same predicate `new[i] > cached[i]`, so `freeWorkBuf_PPS` frees exactly the descriptors that `allocWorkBuf_PPS` then reallocates. `freeWorkBuf_PPS` clears the descriptor (0xb0 bytes) but not the cached size; that is harmless because the cached size stays equal to the value that triggered the free, and alloc re-tests the same predicate. The driver calls them in the correct order:
```
if (this+0x946c) { if (ppsWorkBufSizeIncrease(ds+0x13584, &sizes)) need_grow = 1; }
if (need_grow) freeWorkBuf_PPS(decHdr, &sizes);
if (!allocWorkBuf_PPS(decHdr, ds+0x18, 0, &sizes)) this+0x946c = 1; else { freeWorkBuf_PPS(decHdr, 0); memset(ds+0x13584,0,0x34); this+0x946c = 0; return -1; }
```
Confidence: **PROVEN (negative)** for the Tansy/Catnip/Ixora/Daisy/Borage/Kopsia/Thyme family.

---

## 5. Hunt priority #5 — alloc-vs-patch-bound — OPEN (cannot resolve in this binary)

The work buffers are handed to the firmware patch engine through `CAHDecTansyAvx::populateAvdWork` @ `0x22a37c4c4`:
```c
result = CAHDec::addToPatcherList(this, x25_2, x22_1 + 0xc614, x26_1, 0xffffffff, 0, 0xffffffff, 4);
...
result = CAHDec::addToPatcherList(this, x25_2, x22_1 + 0xc612, x26_2, 0x3ffffffffff, 0x20, 0xffffffff, 2);
```
`CAHDec::addToPatcherList` @ `0x22a35c2b0` only *records* a 0x30-byte descriptor; it performs no bounds check against the destination buffer:
```c
int64_t* x12_1 = x8_1 + x10_1 * 0x30;
x12_1[2] = *(arg2 + 0x98);
x12_1[3] = arg3;              // destination offset/address
*(x12_1 + 0x1c) = arg4;       // size, 32-bit, from GetTileMemInfo
...
*(this + 0x40) = x10_1 + 1;   // count++
```
The size (`arg4`) is `var_78` from `CAVDAvxDecoder::GetTileMemInfo` and is itself truncated to 32 bits under a "64->32 conversion problem!" warning (populateAvdWork lines `0x6a2`, `0x6a3`, `0x6a5`). Whether the kext patch engine's `cmdBufSize` bound (REPORT_AVD.md §2c) equals the real allocation cannot be determined from `AVD.videodecoder` alone — the bound check lives in the `com.apple.driver.AppleAVD` kext. **This remains the highest-value open lead** and requires the kext binary.

---

## 6. Other observations (not bugs)

- **`CAHDecHibiscusAvx::allocWorkBuf_PPS` @ `0x22a422e6c`** (133 BB vs 107 BB) is the only structural outlier: it uses a different descriptor layout (`this+0x1508, 0x15b8, 0x13a8, 0x12f8, 0x1198, 0x10e8, 0x1038, …`) and calls `0x2300c6c80(oldptr, size)` to clear the old buffer before reallocating. It still covers exactly the same 13 fields with the same predicate. No divergence in the size contract.
- **Assert-broken, no enforcement** — `getPPSWorkBufSize` @ `0x22a37ce24` line `0x7cb`:
  ```c
  if (x22_1 > 0x1000) { if (os_log_enabled) log("ASSERT @ ... Line 0x7cb Assert Broken"); }
  int32_t x24_2 = x22_1 < 0xfffffff1 ? x22_1 + 0x1e : x22_1 + 0xf;
  ```
  The "tile width ≤ 0x1000" assertion is logged but never enforced. However the subsequent size math (`x25_1 * ((x25 * x9_3) >> 3)`) scales with `x22_1`, so the allocation grows with it — this is not by itself an under-allocation. Worth a follow-up only if a parser-side path can deliver an out-of-spec tile width. Confidence: **SPECULATIVE**.
- `allocWorkBuf_SPS` @ `0x22a37ca3c` / `freeWorkBuf_SPS` @ `0x22a37e1dc` were not audited in depth (out of the assigned PPS scope).

---

## 7. Ranked candidate list

| # | candidate | location | confidence | consequence |
|---|---|---|---|---|
| 1 | `getPPSWorkBufSize` truncates two 64-bit sizes to 32-bit after a warning; all consumers compare signed, so a truncated size ≥ 0x80000000 is read as "no growth" → buffer not reallocated | writer: `0x22a441f94` (Borage) / `0x22a37ce24` (Tansy), asm `0x22a442744`–`0x22a4427b4` / `0x22a37d648`–`0x22a37d6c8`; consumers: `0x22a37daec`, `0x22a37dbc8`, `0x22a37e390` | SPECULATIVE | under-allocation → heap overflow *if* a >2^32 size is reachable (not demonstrated) |
| 2 | Assert-broken, no enforcement of tile-width ≤ 0x1000 | `0x22a37ce24` line `0x7cb` (Borage `0x22a441f94` analogous) | SPECULATIVE | feeds out-of-spec widths into size math; allocation still scales → not an overflow by itself |
| 3 | Patch-descriptor size stored unbounded (32-bit, truncated) and never checked against the destination allocation | `0x22a37c4c4` (populateAvdWork) → `0x22a35c2b0` (addToPatcherList) | OPEN — needs kext | potential under-bound patch write; unresolvable from this binary |
| — | missing-field reuse (the original hypothesis) | `0x22a37ce24` vs `0x22a37daec` | **DISPROVED (PROVEN negative)** | none |

---

## 8. Queries run (Binary Ninja MCP, read-only)

1. `bn_function_search("PPS", limit=200)` — enumerate PPS-named functions; 520 total.
2. `bn_function_search("createTansyAvx", limit=50)` — located `createTansyAvxDecoder` @ `0x22a378014`.
3. `bn_function_search("processParserOut", limit=100)` — enumerate parser-output handlers.
4. `bn_function_search("AvxDecoder", limit=100)` — located `CAVDAvxDecoder` methods incl. `initPicture`, `VADecodeFrame`, `allocateHwDecoder`.
5. `bn_function_callers(0x22a378014)` — `createTansyAvxDecoder` ← `CAVDAvxDecoder::allocateHwDecoder` @ `0x22a3b7ae4`.
6. `bn_function_callers(0x22a37c4c4)` — 0 callers (virtual / no direct refs).
7. `bn_function_decompile(0x22a3b84b0, offset 0, limit 400)` and `(offset 400, limit 400)` — full `CAVDAvxDecoder::initPicture` (739 lines); located the work-buffer reuse/realloc decision.
8. `bn_function_disassembly(0x22a37daec, limit 200)` — full `ppsWorkBufSizeIncrease` (72 instr).
9. `bn_function_decompile(0x22a37dbc8, limit 500)` — full `allocWorkBuf_PPS` (448 lines).
10. `bn_function_disassembly(0x22a37ce24, offset 555, limit 70)` — Tansy `getPPSWorkBufSize` epilogue (store sequence + 64→32 warnings).
11. `bn_function_decompile(0x22a37e390, limit 500)` — full `freeWorkBuf_PPS` (201 lines).
12. `bn_function_decompile(0x22a37ce24, limit 280)` — `getPPSWorkBufSize` first half (tile size math).
13. `bn_function_decompile(0x22a37c4c4, limit 400)` — full `populateAvdWork` (216 lines); located `addToPatcherList` call sites.
14. `bn_function_search("addToPatcherList", limit=50)` — 4 hits; `CAHDec::addToPatcherList` @ `0x22a35c2b0`.
15. `bn_function_decompile(0x22a35c2b0, limit 300)` — full `addToPatcherList` (180 lines).
16. `bn_function_decompile(0x22a422e6c, limit 320)` — `CAHDecHibiscusAvx::allocWorkBuf_PPS` first 320 lines.
17. `bn_function_disassembly(0x22a441f94, offset 520, limit 90)` — Borage `getPPSWorkBufSize` epilogue; confirmed all 13 stores.
