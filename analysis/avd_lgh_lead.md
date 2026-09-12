> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AVD.videodecoder — LGH tile-count lead: investigation & verdict

Binary: `AVD.videodecoder` (Mach-O, ios-aarch64), iOS 27.0 RC (24A435), image base `0x22a341000`.
Tooling: Binary Ninja MCP only (read-only). All addresses/quotes below come from live BN queries.

**VERDICT: REFUTED.** The LGH tile parser and the HEVC/AVC tile consumers are disjoint decoder
families, and the LGH classes size their tile-boundary arrays for LGH's *per-dimension* tile
limits (64 cols / 4 rows), not for the 21-entry HEVC arrays. The prior agent's "256 tiles vs 21
entries" compares a total-tile bound against a per-dimension array from a different codec.

---

## 1. `LGH_Syntax::get_tile_info` @ `0x22a418e5c` — parsing and bounds

Signature (BN): `int64_t LGH_Syntax::get_tile_info(struct LGH_Syntax* this, uint8_t const* arg2, uint64_t arg3, lgh_header* arg4)`.
Only caller: `LGH_Syntax::Parse_Header` @ `0x22a41a868` (callsite `0x22a41ab18`).

Prologue (disasm `0x22a418e80`–`0x22a418ea8`):

```
0x22a418e88  ldp     w11, w10, [x3, #0x40]   ; w11 = [arg4+0x40], w10 = [arg4+0x44]
0x22a418e8c  lsl     w24, w9, w10            ; w24 = 1 << w10
0x22a418e90  str     w24, [x3, #0x118]       ; header+0x118 = tile rows
0x22a418e94  lsl     w23, w9, w11            ; w23 = 1 << w11
0x22a418e98  str     w23, [x3, #0x11c]       ; header+0x11c = tile cols
0x22a418e9c  lsl     w20, w24, w11           ; w20 = rows << cols_log2 = rows*cols (total tiles)
0x22a418ea0  cmp     w11, #0x6
0x22a418ea4  ccmp    w10, #0x2, #0x2, ls
0x22a418ea8  b.hi    0x22a419114             ; FAIL
0x22a418eac  cmp     w20, #0x100
0x22a418eb0  b.hi    0x22a419114             ; FAIL
```

`ccmp w10,#2,#2,ls` + `b.hi`: on the `ls` path the flags come from `w10-2`; on the `hi` path
(`w11>6`) flags are forced to `C=1,Z=0`, so `b.hi` is taken. Therefore the guard is exactly:

> **proceed iff `cols_log2 (w11) <= 6` AND `rows_log2 (w10) <= 2` AND `rows*cols (w20) <= 0x100`.**

i.e. **at most 64 columns, at most 4 rows, at most 256 total tiles.** The failure log confirms
the field roles and the total cap (disasm `0x22a419138`–`0x22a419198`):

```
str  w9=0x100  -> "max allow tiles %d"
str  w20       -> "got %d"
stur w24       -> "tile rows : %d"
str  w23       -> "tile cols : %d"
"AppleAVD: INFO: %{public}s(): max allow tiles %d got %d, tile rows : %d, tile cols : %d\n\n"
```

Writes into `lgh_header* arg4` (pseudoc, `x26_1` = tile index, `x9_4`/`x9_5` = boundary index):

| offset | stride | index range | content | region size |
|---|---|---|---|---|
| `+0x120` | 4 | `x26_1 < rows*cols <= 256` | tile offset | `0x520-0x120 = 0x400` = **exactly 256** |
| `+0x520` | 4 | `x26_1 < rows*cols <= 256` | tile size | `0x920-0x520 = 0x400` = **exactly 256** |
| `+0x920` | 4 | `rows+1 <= 5` | row boundaries | `0x934-0x920 = 0x14` = **exactly 5** |
| `+0x934` | 4 | `cols+1 <= 65` | col boundaries | `>= 0x104` (65×4) |

Every array is written exactly to its capacity: the total-tile cap (256) matches the two 256-entry
arrays, and the per-dimension caps (rows≤4→5 boundaries, cols≤64→65 boundaries) match the two
boundary arrays. **`get_tile_info` is internally self-consistent and cannot overrun its own
`lgh_header`.** Note the two boundary arrays are 4-byte-strided here (unlike the 2-byte class arrays
in §2); they are header-side staging, not the decoder-class arrays.

---

## 2. Decoder-class tile-array capacities

`getTileStartCTU`/`getTileEndCTU` read the geometry from `*(this+0x1c0)` (a per-picture work
struct) as **uint16** arrays:

```
CAHDecTansyLgh::getTileStartCTU @0x22a377364
0x22a377364  ldr  x8, [x0, #0x1c0]
0x22a377368  ldrh w9, [x8, #0x218]          ; cols
0x22a377370  udiv w10, w1, w9               ; row = tileIdx / cols
0x22a377374  msub w9, w10, w9, w1           ; col = tileIdx % cols
0x22a377378  add  x11, x8, #0x21c
0x22a37737c  ldrh w9, [x11, w9, uxtw #0x1]  ; colBd[col]
0x22a377380  add  x8, x8, #0x29e
0x22a377384  ldrh w8, [x8, w10, uxtw #0x1]  ; rowBd[row]
```

The **column-boundary array capacity = (rowBd_base − colBd_base)** (uint16). Survey:

| class family | class | getTileStartCTU | cols field | colBd base | rowBd base | gap | colBd capacity |
|---|---|---|---|---|---|---|---|
| LGH | `CAHDecTansyLgh` | `0x22a377364` | `+0x218` | `+0x21c` | `+0x29e` | `0x82` | **65** |
| LGH | `CAHDecCloverLgh` | `0x22a386b04` | `+0x160` | `+0x164` | `+0x1e6` | `0x82` | **65** |
| LGH | `CAHDecClaryLgh` | `0x22a392644` | `+0x218` | `+0x21c` | `+0x29e` | `0x82` | **65** |
| LGH | `CAHDecCatnipLgh` | `0x22a3b66e4` | `+0x218` | `+0x21c` | `+0x29e` | `0x82` | **65** |
| LGH | `CAHDecIxoraLgh` | `0x22a3d1400` | `+0x278` | `+0x27c` | `+0x2fe` | `0x82` | **65** |
| LGH | `CAHDecRadishLgh` | `0x22a3ec4f0` | `+0x278` | `+0x27c` | `+0x2fe` | `0x82` | **65** |
| LGH | `CAHDecViolaLgh` | `0x22a3f49d8` | `+0x178` | `+0x17c` | `+0x1fe` | `0x82` | **65** |
| LGH | `CAHDecHibiscusLgh` | `0x22a3f849c` | `+0x278` | `+0x27c` | `+0x2fe` | `0x82` | **65** |
| LGH | `CAHDecSalviaLgh` | `0x22a425a4c` | `+0x178` | `+0x17c` | `+0x1fe` | `0x82` | **65** |
| LGH | `CAHDecBorageLgh` | `0x22a4510a0` | `+0x218` | `+0x21c` | `+0x29e` | `0x82` | **65** |
| LGH | `CAHDecDahliaLgh` | `0x22a45fb1c` | `+0x1b8` | `+0x1bc` | `+0x23e` | `0x82` | **65** |
| LGH | `CAHDecThymeLgh` | `0x22a47edcc` | `+0x218` | `+0x21c` | `+0x29e` | `0x82` | **65** |
| LGH | `CAHDecKopsiaLgh` | `0x22a4833e8` | `+0x278` | `+0x27c` | `+0x2fe` | `0x82` | **65** |
| LGH | `CAHDecDaisyLgh` | `0x22a494b3c` | `+0x278` | `+0x27c` | `+0x2fe` | `0x82` | **65** |
| LGH | `CAHDecLotusLgh` | `0x22a4ab178` | `+0x178` | `+0x17c` | `+0x1fe` | `0x82` | **65** |
| HEVC | `CAHDecRoseHevc` | `0x22a37124c` | `+0xb24` | `+0xb28` | `+0xb52` | `0x2a` | **21** |
| HEVC | `CAHDecTansyHevc` | `0x22a37417c` | `+0x2b4` | `+0x2b8` | `+0x2e2` | `0x2a` | **21** |
| AVC | `CAHDecTansyAvc` | `0x22a3732cc` | `+0x378` | `+0x37c` | `+0x3a6` | `0x2a` | **21** |
| AVX | `CAHDecTansyAvx` | `0x22a37c45c` | `+0x3ec` | `+0x3f0` | `+0x472` | `0x82` | **65** |

Each family's array capacity matches **its own** parser's per-dimension bound:

- **LGH** `get_tile_info` caps cols ≤ 64 → colBd needs indices `0..cols` = 65 entries (`getTileEndCTU`
  indexes `arg2 % cols + 1`, max `cols`). 65 == capacity. ✔
- **HEVC** `HEVC_RBSP::parsePPS` @ `0x22a468944` enforces `num_tile_columns_minus1 <= 0x13` (19) and
  `num_tile_rows_minus1 <= 0x15` (21): `if (x24_14 > 0x13 || x0_60 >= 0x16) { ...goto fail; }` →
  cols ≤ 20 → colBd needs 21 entries. 21 == capacity. ✔
- **AVC/AVX** follow the same pattern (21 / 65).

The prior agent's "21 entries" is the **HEVC/AVC** colBd array; the **LGH** colBd array is 65
entries. There is no LGH array sized to 21.

The LGH work struct is also large: `CAHDecTansyLgh::startPicture` @ `0x22a3747cc` clears `0x24fac`
bytes at `*(this+0x1c0)` (`mov w1,#0x4fac; movk w1,#0x2,lsl#16; bl 0x2300c6c80`), so the rowBd
array at `+0x29e` has ample room beyond its ≤5 used entries.

---

## 3. Dispatch trace — how a stream selects the class

Two independent decoder families, each selecting its own hardware-decoder classes by chip ID:

```
LGH  stream → CAVDLghDecoder::allocateHwDecoder @0x22a426c0c   (switch on *(this+0x930))
              → createTansyLghDecoder  @0x22a374250   (callsite 0x22a426e58)
              → createClaryLghDecoder / createCatnipLghDecoder / createIxoraLghDecoder /
                createRadishLghDecoder / createViolaLghDecoder / createHibiscusLghDecoder /
                createCloverLghDecoder / createSalviaLghDecoder / createBorageLghDecoder /
                createDahliaLghDecoder / createThymeLghDecoder / createKopsiaLghDecoder /
                createDaisyLghDecoder / createLotusLghDecoder / createLilyDLghDecoder /
                createNerineLghDecoder / createDandelionLghDecoder / createNarcissusLghDecoder
              → CAHDec*Lgh

HEVC stream → CAVDHevcDecoder::allocateHwDecoder @0x22a34b008
              → createTansyHevcDecoder @0x22a34b39c  (callsite 0x22a34b15c)
              → CAHDec*Hevc
```

`LGH_Syntax::get_tile_info` has exactly **one** caller (`LGH_Syntax::Parse_Header`), and LGH is a
distinct codec: the binary carries both `LGH_Syntax`/`lgh_header` and `AV1_Syntax`/`av1_header`
(`AV1_Syntax::get_tile_info` @ `0x22a49c650`, `AV1_Syntax::read_tile_info_max_tile`). LGH tile
data is written only into `lgh_header` and consumed by `CAVDLghDecoder` → `CAHDec*Lgh`. **No LGH
data path reaches a HEVC or AVC class.** The `CAVDAvxDecoder::allocateHwDecoder` call inside
`CAVDLghDecoder::allocateHwDecoder` (`label_22a426f58`) is the unrecognized-chip-id error path,
not a class selection.

---

## 4. Tile-index provenance (`arg2` in `getTileStartCTU`/`getTileEndCTU`)

`getTileStartCTU`/`getTileEndCTU` are virtual leaf accessors; BN reports **0 direct callers**
(virtual dispatch is unresolved — a documented limitation), so the index could not be traced
call-site-by-call-site. However the callers that consume the tile geometry enumerate tiles
internally against the validated counts:

- `CAHDecTansyLgh::populateTiles` @ `0x22a37493c`: `i_1 = *(x8_1+0x13c) * *(x8_1+0x138)` tiles,
  `x8_1 = *(*(this+0x1b8)+0x45d8)` — the decoder's tile rows/cols from the validated header.
- `CAHDecTansyLgh::populateAvdWork` @ `0x22a3773cc`: nested loops bounded by `*(x25+0x138)`
  (cols) and `*(x25+0x13c)` (rows), same source object.

So `arg2` is an **internal tile-enumeration counter bounded by `rows*cols`**, not a raw
bitstream tile id. Combined with the validated per-dimension caps, the index satisfies
`arg2 % cols < cols` and `arg2 / cols < rows`, keeping both reads inside the 65/5-entry arrays.
The absent clamp noted by the prior agent is therefore harmless on both the LGH and HEVC paths
(HEVC: cols ≤ 20 fits the 21-entry array; rows ≤ 22 fits its rowBd array).

---

## 5. Verdict

**REFUTED.**

- `LGH_Syntax::get_tile_info` does not "allow up to 256 tiles" in a way that overruns anything:
  it enforces **cols ≤ 64, rows ≤ 4, total ≤ 256**, and its own `lgh_header` arrays are sized
  exactly (256 / 256 / 5 / 65).
- The "21-entry" boundary arrays belong to `CAHDec*Hevc`/`CAHDec*Avc`; the LGH classes
  (`CAHDec*Lgh`) carry **65-entry** colBd arrays, matching LGH's cols ≤ 64 bound.
- LGH tile data cannot reach a HEVC/AVC class: `get_tile_info` is called only by
  `LGH_Syntax::Parse_Header`, and LGH streams instantiate `CAVDLghDecoder` → `CAHDec*Lgh` via
  `allocateHwDecoder` @ `0x22a426c0c`.
- The tile index is an internally enumerated counter bounded by the validated tile count, so the
  missing clamp is not reachable with an out-of-range value.

No array-capacity mismatch, no OOB read/write. Clean negative.

### Caveats / limits
- Virtual callers of `getTileStartCTU`/`getTileEndCTU` are unresolved in BN; provenance is
  inferred from the enumerating callers (`populateTiles`, `populateAvdWork`), not directly traced.
- The prior agent's tile-struct sizes (0x66a5c Hevc / 0x30640 Avx) were not needed and were not
  verified; the LGH work struct measured here is 0x24fac.
