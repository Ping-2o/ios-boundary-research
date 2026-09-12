> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AVD.videodecoder (iOS 27.0 RC, 24A435) — tile geometry & tile-array population audit

Binary: `AVD.videodecoder` (Mach-O, ios-aarch64, image base `0x22a341000`, 4,373 functions,
analysis complete).
Tooling: **Binary Ninja MCP only** (read-only). No Ghidra, no IDA, no otool.
Rules honoured: never called `bn_binary_view_set_active`, never called `bn_open_item_open`.

Diff context: `REPORT_27_0_RC_DIFF.md` §2.1 — `__TEXT.__text` +150,612 B, 4,124 → 4,380
functions, 8 new decoder classes `CAHDec{Borage,Kopsia}{Avc,Avx,Hevc,Lgh}`. The tile/geometry
symbol families were listed there as "new, never-audited size/geometry math".

---

## 1. Verdict

**Negative result. No PROVEN or STRONG memory-safety bug was found in the tile-geometry /
tile-array-population path.**

The tile index helpers (`getTileStartCTU` / `getTileEndCTU` / `getTileIdxAbove`) genuinely have
**no bounds check on the tile index** — this is real and confirmed in decompilation and
disassembly. However, three independent facts neutralise it:

1. `HEVC_RBSP::parsePPS` (@ `0x22a468944`) enforces the HEVC limits
   `num_tile_columns_minus1 <= 19` and `num_tile_rows_minus1 <= 21` and rejects out-of-range
   values with a logged error. So tile columns <= 20 and tile rows <= 22.
2. The tile-boundary arrays are sized exactly for those maxima: in every Hevc class the column
   boundary array (base `+0x2b8`, `+0x318`, or `+0xb28`) and the row boundary array
   (base `+0x2e2`, `+0x342`, or `+0xb52`) are separated by exactly `0x2a` = 42 bytes =
   **21 `uint16` entries**, i.e. 20 tile columns + 1 boundary. `getTileStartCTU` indexes
   `0..cols-1` and `getTileEndCTU` indexes `1..cols`; both fit inside 0..20.
3. The containing tile-register struct is allocated far larger than the arrays:
   `CAHDecBorageHevc` ctor sets `*(this + 0x1b0) = 0x66a5c` (420,444 B) and
   `CAHDecBorageAvx` sets `*(this + 0x1b0) = 0x30640` (198,208 B); the row array ends near
   `+0x310`. There is ~400 KB of headroom.

The `+1` indexing in `getTileEndCTU` is **intentional boundary-array semantics** (n columns need
n+1 cumulative positions), not an off-by-one bug.

All tile functions in the new Borage/Kopsia classes are **structural copies** of the
pre-existing Tansy/Daisy implementations (identical offsets, identical arithmetic, only the
struct base offset and the `populateTileRegisters` target differ). This is inheritance, not new
logic — so even if a latent bug existed it would be pre-existing, not a 27.0-RC regression.

The one *new* behaviour worth recording is a functional divergence, not a memory-safety one:
`getTileIdxAbove` is a **stub returning 0** in the new Avx/Lgh classes.

---

## 2. Audited functions

Legend — Guard: `none` = raw index, no clamp; `upstream` = bounded only by parsePPS limits;
`stub` = constant return; `n/a` = not applicable.

| Function | Address | Index/size expression | Guard | Notes |
|---|---|---|---|---|
| `CAHDecRoseHevc::getTileStartCTU` | `0x22a37124c` | `col[arg2%cols] + arg3*row[arg2/cols]` | none | cols `+0xb24`, col arr `+0xb28`, row arr `+0xb52`; `udiv`+`msub` |
| `CAHDecRoseHevc::getTileEndCTU` | `0x22a371278` | `col[(arg2%cols)+1] + (row[(arg2/cols)+1]-1)*arg3` | none | `+1` boundary index; returns `x8_3-1` |
| `CAHDecRoseHevc::getTileIdxAbove` | `0x22a3712b4` | `arg2%cols ? ... : 0xffffffff` | n/a | returns `-1` on top row |
| `CAHDecTansyHevc::getTileStartCTU` | `0x22a37417c` | as Rose | none | cols `+0x2b4`, arr `+0x2b8`/`+0x2e2` |
| `CAHDecTansyHevc::getTileEndCTU` | `0x22a359b4c` | as Rose | none | `+0x2b4/0x2b8/0x2e2` |
| `CAHDecDaisyHevc::getTileStartCTU` | `0x22a3e7a44` | as Rose | none | cols `+0x314`, arr `+0x318`/`+0x342` |
| `CAHDecBorageHevc::getTileStartCTU` | `0x22a447f94` | `*(x8+0x2b8+((a2%cols)<<1)) + a3**(x8+0x2e2+((a2/cols)<<1))` | none | **byte-identical to Tansy** |
| `CAHDecBorageHevc::getTileEndCTU` | `0x22a447fc0` | `...((a2%cols+1)<<1)...` | none | `+1` index, same as Tansy |
| `CAHDecBorageHevc::getTileIdxAbove` | `0x22a447ffc` | — | — | (not a stub here) |
| `CAHDecKopsiaHevc::getTileStartCTU` | `0x22a48ffc0` | cols `+0x314` | none | **identical to Daisy** |
| `CAHDecKopsiaHevc::getTileEndCTU` | `0x22a48ffec` | `+1` index | none | identical to Daisy |
| `CAHDecKopsiaHevc::getTileIdxAbove` | `0x22a490028` | — | — | |
| `CAHDecBorageAvx::getTileStartCTU` | `0x22a4415d4` | cols `+0x3e4`, arr `+0x3e8`/`+0x46a` | none | col→row gap `0x82` = 65 entries |
| `CAHDecBorageAvx::getTileEndCTU` | `0x22a441600` | `+1` index | none | returns `x8_3-1` |
| `CAHDecBorageAvx::getTileIdxAbove` | `0x22a443600` | `return 0` | **stub** | **divergence** |
| `CAHDecKopsiaAvx::getTileStartCTU` | `0x22a485964` | as Borage Avx | none | |
| `CAHDecKopsiaAvx::getTileEndCTU` | `0x22a485990` | `+1` index | none | |
| `CAHDecKopsiaAvx::getTileIdxAbove` | `0x22a487ac8` | `return 0` | **stub** | **divergence** |
| `CAHDecKopsiaLgh::getTileStartCTU` | `0x22a4833e8` | — | none | |
| `CAHDecKopsiaLgh::getTileEndCTU` | `0x22a483414` | `+1` index | none | |
| `CAHDecKopsiaLgh::getTileIdxAbove` | `0x22a483fd4` | `return 0` | **stub** | **divergence** |
| `CAHDecBorageLgh::getTileIdxAbove` | `0x22a451c70` | `return 0` | **stub** | **divergence** |
| `CAHDecBorageAvc::getTileStartCTU` | `0x22a44d800` | — | none | AVC |
| `CAHDecBorageAvc::getTileEndCTU` | `0x22a44d82c` | — | none | AVC |
| `CAHDecBorageAvc::getTileIdxAbove` | `0x22a44d868` | — | — | AVC |
| `CAHDecKopsiaAvc::getTileStartCTU` | `0x22a48b744` | — | none | AVC |
| `CAHDecKopsiaAvc::getTileEndCTU` | `0x22a48b770` | — | none | AVC |
| `CAHDecKopsiaAvc::getTileIdxAbove` | `0x22a48b7ac` | — | — | AVC |
| `CAHDecTansyHevc::getTileHdrMemInfo` | `0x22a35dfe0` | `this+0x210+arg2*0xb0` | none | reachability unproven (see §4) |
| `CAHDecBorageHevc::getTileHdrMemInfo` | `0x22a4447e0` | `this+0x210+arg2*0xb0`, `this+0xd10+arg2*0xb0` | none | identical to Tansy |
| `CAHDecKopsiaHevc::getTileHdrMemInfo` | `0x22a48c810` | identical | none | |
| `CAHDecBorageHevc::populatePictureRegisters` | `0x22a444858` | copies PPS tile arrays | upstream | 520 BB |
| `CAHDecKopsiaHevc::populatePictureRegisters` | `0x22a48c888` | copies PPS tile arrays | upstream | 520 BB |
| `CAHDecTansyAvx::populateTiles` | `0x22a37ad84` | `for n < cols*rows: regs[0x600+n*0xc]` | upstream | reference |
| `CAHDecKopsiaAvx::populateTiles` | `0x22a420644` | `for n < cols*rows: regs[0x674+n*0xc]` | upstream | **same count source as Tansy** |
| `CAHDecTansyLgh::populateTiles` | `0x22a37493c` | `for n < rows*cols: regs[0x3ac+n*0xc]` | upstream | reference |
| `CAHDecKopsiaLgh::populateTiles` | `0x22a3f5c9c` | `for n < rows*cols: regs[0x40c+n*0xc]` | upstream | same as Tansy |
| `CAHDecLotusLgh::populateTiles` | `0x22a3f2ed8` | nested `rows × cols` | upstream | 8 BB variant |
| `CAHDecBorageAvx::populateAvdWork` | `0x22a44163c` | `rows*cols` × `0x24` at `+0xc5f8` | none in fn | **no** `workUnitOffsetInvalid` call |
| `CAHDecBorageHevc::populateAvdWork` | `0x22a448024` | — | calls `workUnitOffsetInvalid` @ `0x22a448234` | 154 BB |
| `CAHDecKopsiaHevc::populateAvdWork` | `0x22a490050` | — | calls `workUnitOffsetInvalid` @ `0x22a490264` | 154 BB |
| `CAHDec::workUnitOffsetInvalid` | `0x22a4345bc` | sums slice work units, compares to `0x1000` | yes | 16 callers, all Hevc |
| `CAHDecBorageAvx::getPPSWorkBufSize` | `0x22a441f94` | 32-bit size math | assert-only | see C5 |
| `CAHDecKopsiaAvx::getPPSWorkBufSize` | `0x22a4863b4` | 32-bit size math | assert-only | see C5 |
| `CAHDecBorageAvx::ppsWorkBufSizeIncrease` | `0x22a442874` | 13× `<=` compare | yes | correct |
| `CAHDecKopsiaAvx::ppsWorkBufSizeIncrease` | `0x22a486c94` | 13× `<=` compare | yes | correct |
| `CAHDecBorageAvx::allocWorkBuf_PPS` | `0x22a442950` | cached-size compare per field | yes | reallocs only if larger |
| `CAHDecKopsiaAvx::allocWorkBuf_PPS` | `0x22a486d70` | cached-size compare per field | yes | |

### Tile boundary array geometry (measured from decompiled offsets)

| Class | cols field | col array | row array | gap | entries |
|---|---|---|---|---|---|
| Rose Hevc | `+0xb24` | `+0xb28` | `+0xb52` | `0x2a` | 21 |
| Tansy Hevc | `+0x2b4` | `+0x2b8` | `+0x2e2` | `0x2a` | 21 |
| Borage Hevc | `+0x2b4` | `+0x2b8` | `+0x2e2` | `0x2a` | 21 |
| Daisy Hevc | `+0x314` | `+0x318` | `+0x342` | `0x2a` | 21 |
| Kopsia Hevc | `+0x314` | `+0x318` | `+0x342` | `0x2a` | 21 |
| Borage Avx | `+0x3e4` | `+0x3e8` | `+0x46a` | `0x82` | 65 |

21 entries = max 20 tile columns + 1 boundary → exactly the `parsePPS` limit.

---

## 3. Candidate findings

### C1 — `getTileStartCTU` / `getTileEndCTU`: tile index used with no bounds check
**Addresses:** `0x22a37124c`, `0x22a371278`, `0x22a37417c`, `0x22a359b4c`, `0x22a3e7a44`,
`0x22a447f94`, `0x22a447fc0`, `0x22a48ffc0`, `0x22a48ffec`, `0x22a4415d4`, `0x22a441600`,
`0x22a485964`, `0x22a485990`, `0x22a4833e8`, `0x22a483414`.

**Quoted decompilation** (`CAHDecBorageAvx::getTileStartCTU`):
```c
void* x8_2 = *(this + 0x1c0);
uint32_t x9_1 = *(x8_2 + 0x3e4);                 // tile column count
return *(x8_2 + 0x3e8 + ((arg2 % x9_1) << 1))    // col boundary array
     + arg3 * *(x8_2 + 0x46a + ((arg2 / x9_1) << 1));  // row boundary array
```
Disassembly confirms a raw `ldrh w9,[x11,w9,uxtw #1]` after `udiv`/`msub`, with no compare
against `x9_1` or any capacity. `arg2` (tile index) is used modulo/divide only.

**Why it is not exploitable as found:**
- `HEVC_RBSP::parsePPS` @ `0x22a468944` rejects `num_tile_columns_minus1 > 19` /
  `num_tile_rows_minus1 > 21` with
  `"AppleAVD: INFO: %{public}s(): value out of range: num_tile_columns_minus1 %d num_tile_rows_minus1 %d\n"`.
- The arrays hold exactly 21 / 23 entries and the index range is 0..20 / 0..22.
- The containing struct is `0x66a5c` (Hevc) / `0x30640` (Avx) bytes — ~400 KB headroom.

**Bitstream field that would control it:** PPS `num_tile_columns_minus1` / `num_tile_rows_minus1`
(and the derived tile index `arg2`). **Consequence if the parsePPS limits were bypassed:**
16-bit OOB read of adjacent struct fields (tile geometry corruption), not a controllable write.

**Confidence: SPECULATIVE (leaning refuted).** The missing check is real; the OOB is blocked by
the upstream limit and by array/struct sizing.

### C2 — `getTileEndCTU` indexes one past the boundary array
**Addresses:** same set, `...EndCTU` entries.
**Quoted** (`CAHDecBorageHevc::getTileEndCTU`):
```c
int32_t x8_3 = *(x8_4 + 0x2b8 + ((arg2 % x9_1 + 1) << 1))
             + (*(x8_4 + 0x2e2 + ((arg2 / x9_1 + 1) << 1)) - 1) * arg3;
return x8_3 - 1;
```
**Verdict:** intentional. `n` tile columns require `n+1` cumulative boundary positions. Max index
`cols` = 20 fits in the 21-entry array. **Confidence: REFUTED.**

### C3 — `getTileHdrMemInfo`: pointer computed from unchecked tile index
**Addresses:** `0x22a35dfe0`, `0x22a4447e0`, `0x22a48c810`.
**Quoted:**
```c
int64_t x9 = arg2 * 0xb0;
*arg3 = this + 0x210 + x9;
*(arg3 + 8) = this + 0xd10 + x9;
```
`arg2` (tile index) is multiplied by `0xb0` with no clamp; both pointers are handed to the caller
as buffer descriptors. With max tiles 440, `0x210 + 440*0xb0 = 0x13090` — well inside the
`0x66a5c` struct.
**Reachability correction:** an earlier working note claimed this is reached from
`_AppleAVDWrapperHEVCDecoderDecodeFrameWithOptions` @ `0x22a35dc2c`. That is a **false positive**:
the reported callsite `0x22a35dfdc` is `bl 0x2300c6c50`, an external stub (it follows a stack-canary
`ldr x9,[...]; cmp x9,x8; b.ne`), and `getTileHdrMemInfo` merely begins at `0x22a35dfe0` by address
adjacency. `bn_function_xrefs_to` / `bn_data_xrefs_to` recover **no real caller**.
**Confidence: SPECULATIVE**, reachability unproven.

### C4 — `populateTiles`: unbounded `rows*cols` loop at stride `0xc`
**Addresses:** `0x22a37ad84`, `0x22a37493c`, `0x22a420644`, `0x22a3f5c9c`, `0x22a3f2ed8`,
`0x22a405484`, `0x22a406b2c` (+ others).
**Quoted** (`CAHDecKopsiaAvx::populateTiles`):
```c
int64_t x22 = *(this + 0x1c0);
void* x8_1 = *(*(this + 0x1b8) + 0x3b48);
uint64_t x21 = *(x8_1 + 0x8c) * *(x8_1 + 0x88);   // rows * cols
CAHDecDaisyAvx::populateClearTiles(this);
do {
    CAHDecTansyAvx::populateTileRegisters(this, x22 + 0x674 + x20_1 * 0xc, x20_1);
    x20_1 += 1;
} while (x21 != x20_1);
```
The count is a product of two struct fields and there is no comparison against the array
capacity. **However** the reference `CAHDecTansyAvx::populateTiles` (`0x22a37ad84`) is
**structurally identical** (`x22 + 0x600 + x20_1*0xc`, same `*(x8_1+0x8c) * *(x8_1+0x88)` count).
New == old, so this is **pre-existing, not a 27.0-RC regression**.
**Confidence: SPECULATIVE (pre-existing pattern).**

### C5 — `getPPSWorkBufSize`: assert-only validation, 32-bit size arithmetic
**Addresses:** `0x22a441f94` (Borage Avx), `0x22a4863b4` (Kopsia Avx).
**Quoted:**
```c
if (x22_1 > 0x1000) {
    ... 0x2300c6c60(..., "AppleAVD: INFO: %{public}s(): ASSERT @ %s() :: Line %d Assert Broken \n\n", ...);
    // no return, no clamp — execution continues with x22_1 unchanged
}
int32_t x24_2 = x22_1 < 0xfffffff1 ? x22_1 + 0x1e : x22_1 + 0xf;
...
int32_t x8_22 = x25_1 * ((x25 * x9_3) >> 3);
```
and later:
```c
if (x25_5 >> 0x20) { ... "AppleAVD: WARNING: %{public}s(): %s %d 64->32 conversion problem!\n" ... }
```
Both diagnostics are **non-enforcing**: they log and continue. The `>> 0x20` 64→32 truncation is
detected but not corrected. All arithmetic is 32-bit; with the observed bounds
(`x25 <= 0x1fe`, `x9_3 <= 0x30`, tile dimension in CTUs) the products stay below 2^31, so no
overflow is demonstrable. The `0x1000` assert can legitimately fire for a wide single-column tile
(tile width in CTUs << 6), which shows it is a sanity check rather than a hard bound.
**Confidence: SPECULATIVE.** A genuine missing-enforcement pattern; no proven overflow.

### C6 — `populateAvdWork`: Avx/Avc/Lgh variants omit `workUnitOffsetInvalid`
**Evidence:** `bn_function_callers(0x22a4345bc)` returns 16 callers — all `*Hevc::populateAvdWork`
(Tansy, Rose, Clover, Clary, Catnip, Lotus, Ixora, Radish, Daisy, Viola, Dahlia, Salvia, **Borage**,
Hibiscus, **Kopsia**, Thyme). No `*Avx`, `*Avc`, or `*Lgh` variant calls it.
`CAHDecBorageAvx::populateAvdWork` (`0x22a44163c`) writes `rows*cols` entries of `0x24` bytes at
`*(this+0x1c0) + 0xc5f8` with no in-function bound:
```c
void* x28_1 = x10 + 0xc5f8 + x10_3;
...
do { ... x24_1 += 0x24; x28_1 = x24_1; } while (x23_1 < x8_2);
```
The buffer is sized for ~4096 units (`x15_1 = 0x1002 / (x14_2 & 0xffff) * 0x24`), and the write
count is bounded by tile counts (`cols <= 20`, `rows <= 22` ⇒ 440), so it fits.
**Confidence: SPECULATIVE (by-design codec difference; no proven overflow).**

### C7 — `getTileIdxAbove` stubs in the new Avx/Lgh classes
**Addresses:** `0x22a443600`, `0x22a487ac8`, `0x22a483fd4`, `0x22a451c70`.
**Quoted:**
```c
int64_t CAHDecBorageAvx::getTileIdxAbove(struct CAHDecBorageAvx* this, uint32_t arg2) __pure
{
    return 0;
}
```
The Rose/Tansy implementations compute a real "tile above" index (returning `0xffffffff` on the
top row). The new classes hard-return `0`. **This is a functional divergence, not a memory-safety
bug** (0 is a valid tile index, so it is memory-safe). Worth flagging because it means the new
Avx/Lgh classes never take the tile-above path.
**Confidence: INFORMATIONAL.**

---

## 4. Reachability analysis (why confidence is capped at SPECULATIVE)

- `bn_function_xrefs_to` returns **0** for `getTileStartCTU`, `getTileEndCTU`, `getTileIdxAbove`
  (Rose, Borage Hevc, Borage Avx, Kopsia Hevc, Kopsia Avx, Kopsia Lgh).
- `bn_data_xrefs_to` returns **0** for the same function ranges — i.e. Binary Ninja recovered **no
  vtable entry** pointing at them either.
- Therefore these are reached only through indirect `(*(*this + 0xNN))(...)` virtual dispatch whose
  vtable BN did not resolve (vtables live in `__AUTH_CONST.__const`, which grew `0x4e40 → 0x5940`
  in the RC). With read-only BN queries I cannot enumerate the vtable slot or prove the caller.
- Consequently the tile index `arg2` provenance is **unproven**. The `parsePPS` limit argument in
  §1 is the strongest available bound, and it is indirect (it bounds the stored counts, not the
  index at the call site).

## 5. Divergence summary vs. older generations

| Aspect | Old (Rose/Tansy/Daisy) | New (Borage/Kopsia) | Change |
|---|---|---|---|
| tile index bounds check | absent | absent | none |
| boundary array sizing | 21 entries | 21 entries | none |
| `getTileIdxAbove` | real computation | `return 0` (Avx/Lgh) | **functional** |
| `populateTiles` loop | `rows*cols`, stride `0xc` | same | none |
| `workUnitOffsetInvalid` | Hevc only | Hevc only | none |
| `ppsWorkBufSizeIncrease` | element-wise | element-wise | none |
| tile struct allocation | — | `0x66a5c` / `0x30640` | new class sizes |

No security-relevant divergence found. The new classes are inheritance-based copies with
generation-specific struct bases and a stubbed `getTileIdxAbove`.

## 6. Refuted hypotheses

- **`getTileEndCTU` off-by-one OOB read** — refuted; `+1` is boundary semantics, array holds 21.
- **Divide-by-zero in `getTileStartCTU`** (`udiv` by tile column count) — refuted; HEVC guarantees
  `tileColumns >= 1`, `parsePPS` enforces it, and AArch64 `udiv` by zero returns 0 without trapping.
- **Row boundary array overflow at max rows** — refuted; 23 entries needed, struct headroom
  ~400 KB, arrays laid out contiguously and sized to the limit.
- **`getTileHdrMemInfo` reached from `DecodeFrameWithOptions`** — refuted; false-positive caller
  from function adjacency (`bl 0x2300c6c50` external stub at `0x22a35dfdc`, next function begins
  at `0x22a35dfe0`).

---

## 7. Queries run (reproducibility)

All via the Binary Ninja MCP server, read-only. Active view: `AVD.videodecoder` (ios-aarch64).

```
bn_function_search  "Borage"                    -> 181 functions
bn_function_search  "Kopsia"                    -> 141 functions
bn_function_search  "populateTiles"             -> 12 functions
bn_function_search  "populateClearTiles"        -> 4 functions
bn_function_search  "parse"                     -> located HEVC_RBSP::parsePPS @ 0x22a468944

bn_function_info       0x22a35dc2c
bn_function_decompile  0x22a35dc2c (400)        -> DecodeFrameWithOptions
bn_function_disassembly 0x22a35dc2c (200..290)  -> tail: bl 0x2300c6c50 (external stub)
bn_function_callers    0x22a35dfe0              -> 1 (FALSE POSITIVE: adjacency @0x22a35dfdc)
bn_function_xrefs_to   0x22a35dfe0              -> same false positive
bn_symbol_list_at      0x2300c6c50              -> no symbol (external)
bn_symbol_list_at      0x22a35dfe0              -> getTileHdrMemInfo
bn_import_list         0x2300c6c40 len 0x40     -> empty

bn_function_callers    0x22a4345bc              -> 16 callers, all *Hevc::populateAvdWork
bn_function_decompile  0x22a4345bc              -> workUnitOffsetInvalid (0x1000 limit)

bn_function_xrefs_to   0x22a37124c              -> 0
bn_function_xrefs_to   0x22a371278              -> 0
bn_function_xrefs_to   0x22a3712b4              -> 0
bn_data_xrefs_to       0x22a37124c len 0x90     -> 0
bn_data_xrefs_to       0x22a4415d4 len 0x2c     -> 0
bn_data_xrefs_to       0x22a447f94 len 0x2c     -> 0

bn_function_decompile  0x22a37124c / 0x22a371278 / 0x22a3712b4   (Rose Hevc tile idx)
bn_function_decompile  0x22a37417c / 0x22a359b4c                (Tansy Hevc)
bn_function_decompile  0x22a3e7a44                              (Daisy Hevc)
bn_function_decompile  0x22a4415d4 / 0x22a441600 / 0x22a443600   (Borage Avx)
bn_function_decompile  0x22a447f94 / 0x22a447fc0 / 0x22a447ffc   (Borage Hevc)
bn_function_decompile  0x22a48ffc0 / 0x22a48ffec / 0x22a490028   (Kopsia Hevc)
bn_function_decompile  0x22a485964 / 0x22a485990 / 0x22a487ac8   (Kopsia Avx)
bn_function_decompile  0x22a4833e8 / 0x22a483414 / 0x22a483fd4   (Kopsia Lgh)
bn_function_decompile  0x22a4447e0 / 0x22a48c810                (getTileHdrMemInfo)
bn_function_decompile  0x22a3712dc                              (Rose Hevc populateAvdWork)

bn_function_decompile  0x22a44163c                              (Borage Avx populateAvdWork)
bn_function_decompile  0x22a441f94                              (Borage Avx getPPSWorkBufSize)
bn_function_decompile  0x22a442874                              (Borage Avx ppsWorkBufSizeIncrease)
bn_function_decompile  0x22a442950                              (Borage Avx allocWorkBuf_PPS)

bn_function_decompile  0x22a37ad84                              (Tansy Avx populateTiles)
bn_function_decompile  0x22a37493c                              (Tansy Lgh populateTiles)
bn_function_decompile  0x22a420644                              (Kopsia Avx populateTiles)
bn_function_decompile  0x22a3f5c9c                              (Kopsia Lgh populateTiles)
bn_function_decompile  0x22a3f2ed8                              (Lotus Lgh populateTiles)

bn_function_decompile  0x22a43d3e4                              (Borage Avx ctor: size 0x30640)
bn_function_decompile  0x22a443698                              (createBorageHevcDecoder: size 0x66a5c)
bn_function_decompile  0x22a443754                              (Borage Hevc init)
bn_function_decompile  0x22a43d60c                              (Borage Avx init)

bn_function_decompile  0x22a468944 (parsePPS, via earlier session) -> tile count limits 19/21
bn_function_decompile  0x22a418e5c (LGH_Syntax::get_tile_info)     -> max 0x100 tiles
```

## 8. Limitations

1. **No vtable resolution.** The decisive gap. All tile functions are unreferenced in BN's
   recovered call graph, so index provenance and reachability are unproven. Resolving
   `__AUTH_CONST.__const` vtables (possibly pointer-authenticated / relative) would be required to
   move C1–C3 off SPECULATIVE.
2. **No dynamic confirmation.** Read-only static analysis only; no execution, no coverage.
3. **Struct field semantics inferred.** `*(x8_1+0x88)` / `*(x8_1+0x8c)` are treated as tile
   row/column counts from their use as loop bounds; the defining parser was not located.
4. **`parsePPS` limits assumed load-bearing.** If a second, less strict tile-count path exists
   (e.g. the LGH parser, which caps at `0x100` tiles = 256, not 20×22), the bounds argument in §1
   weakens. `LGH_Syntax::get_tile_info` @ `0x22a418e5c` allows up to 256 tiles, which is larger
   than the 21-entry Hevc boundary arrays — **this is the most promising follow-up**: confirm
   whether any path can populate a Hevc-class boundary array from LGH-style counts.

## 9. Recommended next step

The single highest-value follow-up is **not** in the tile-index helpers (blocked by array sizing)
but at the intersection of C3/C7 and the LGH parser:

> Trace `LGH_Syntax::get_tile_info` (@ `0x22a418e5c`, max 256 tiles) and determine whether its
> tile counts can reach a Hevc-class `getTileHdrMemInfo` / `getTileStartCTU` (`this+0x210+arg2*0xb0`,
> `+0x2b8`/`+0x2e2` arrays sized for 20/22). If yes, a 256-tile index against 21-entry arrays is a
> real OOB. If the Hevc and LGH paths are disjoint, the tile-geometry surface is clean.

This requires resolving the vtable dispatch that BN did not recover.
