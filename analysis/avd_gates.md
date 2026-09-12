> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AVD.videodecoder — wrapper gates & resolution/dimension flow

Target: `AVD.videodecoder` (Mach-O, ios-aarch64), iOS 27.0 RC build 24A435, image base `0x22a341000`.
Method: Binary Ninja MCP only (`bn_function_decompile`, `bn_function_disassembly`, `bn_function_search`,
`bn_function_list`, `bn_function_xrefs_to`, `bn_data_xrefs_to`, `bn_string_list`). Read-only; no
`bn_binary_view_set_active`, no `bn_open_item_open`.

**Headline result:** the two previously-suspected leads are **dead** —
(a) the AVC SPS/PPS array indexing is fully bounds-checked, and (b) the
`CanAcceptFormatDescription` gate is honest. The live lead is an **asymmetric resolution-cap
bypass** driven by two independent `VASetParams` flags, feeding 32-bit work-buffer size math.

---

## 1. Wrapper gate inventory

| Function | Address | Validates | Does NOT validate |
|---|---|---|---|
| `_AppleAVDWrapperH264DecoderCanAcceptFormatDescription` | `0x22a470c0c` | state `[0x19cc]==6` (unless `CFEqual` fast-path), `CFEqual([0x18], fmt)` early-accept, `CMFormatDescriptionGetDimensions` low32==`[0x1458]` & high32==`[0x145c]`, `CFGetTypeID` vs cached `[0x22e4]`, bit-depth/chroma via `_getBitDepthsAndChromaFormatFromFormatDesc` vs `[0x1980..0x1983]`/`[0x190c]`, DPB consistency (`var_2348==1`) | in-band **SPS** dimensions. Only the *format-description* dims are compared. |
| `_AppleAVDWrapperHEVCDecoderCanAcceptFormatDescription` | `0x22a45cf3c` | state `[0x16c8]==6`, dims vs `[0x145c]/[0x1460]`, typeID `[0x3200]`, VPS compare when `[0x1fdc]==1` | in-band SPS dims |
| `_AppleAVDWrapperH264DecoderStartSession` | `0x22a46fc74` | already-started `[0x44e]`, state `[0x19cc]!=1`, `[0x1981]&~2`==0 and `[0x1981]==[0x1982]` (chroma) | any dimension cross-check; it reads `[0x1458]/[0x145c]` (log + `_isEligibleToUseCompression`) and derives `[0x1460]/[0x1464]` from `[0x1960]/[0x1964]` |
| `_AppleAVDWrapperH264DecoderStartTileSession` | `0x22a470e50` | tile state `[0x2270]==2` downstream; builds pixel-format list / attrs dict with `_setSIntValue(0x4000/0x10000/0x10000/0x3ffc0)` | per-frame SPS dims |
| `_AppleAVDWrapperH264DecoderSetProperty` | `0x22a46ee94` | VRA dims path: rejects unless `0x438`/`0x438` or `&0xf==0`; if tile session, requires new dims == `[0x1460]/[0x1464]` | other dimension entry points |
| `CAVDAvcDecoder::VAStartDecode` | `0x22a42e2f0` | **stores** session dims `[0xb9c]/[0xba0]` from SPS; applies a 4096-px cap | cap is conditional (see §4) |
| `CAVDAvcDecoder::processParserOut` | `0x22a42ec00` | per-frame SPS dims == `[0xb9c]/[0xba0]`, else `0x131`; chroma/bit-depth/DPB consistency | **skipped entirely** when `*(this+0xa)&1` (see §4) |

`CMFormatDescriptionGetDimensions` is inlined/external; `bn_function_search "GetDimensions"` → 0 hits.
String xrefs are unavailable in this view (`bn_data_xrefs_to` on `0x22a4e2555`, `0x22a4e56f9`,
`0x22a4e6690` → 0 refs), so the `"over size"` / `"exceeds limit"` / `kVASetUnlimitedResolution`
string users could not be resolved by xref; they were reached only by reading candidate functions.

---

## 2. Dimension flow (H264), with addresses

1. **Format description → wrapper.** `_AppleAVDWrapperH264DecoderStartSession` (`0x22a46fc74`)
   calls `_CreateHeaderBuffer` → H264 variant at **`0x22a3465e0`** →
   `_getAvcSeqAndPicParamSetFromImageDescExt` **`0x22a36ce94`** →
   `_JVTLibCompDecodeAVCDecoderConfigurationRecord` (external). Outputs written to
   `[0x190c],[0x1470],[0x1480],[0x1478],[0x1500],[0x1900],[0x1904]`.
   StartSession then sets `[0x1460] = [0x1960]`, `[0x1464] = [0x1964]`, `[0x1454] = 1`.
2. **Wrapper dims `[0x1458]/[0x145c]`.** Read in StartSession (`0x22a46fc74`, log + compression
   eligibility) and in `CanAcceptFormatDescription` (`0x22a470c0c`). **Writer not located** within
   budget; ruled out: `CreateInstance` `0x22a46e1a8` (memset 0x22e8 only), all three
   `_CreateHeaderBuffer` (`0x22a346088`/`0x22a346464`/`0x22a3465e0`), `SetProperty` `0x22a46ee94`,
   `getAvcSeqAndPicParamSetFromImageDescExt` `0x22a36ce94`. This is the one **unverified link** for
   candidate 3.
3. **Per-frame SPS → decoder.** `_AppleAVDWrapperH264DecoderDecodeFrame` `0x22a366054` →
   `CAVDAvcDecoder::VADecodeFrame` `0x22a3639d4` →
   `AVC_RBSP::parseNALUs` → `CAVDAvcDecoder::processParserOut` `0x22a42ec00` →
   `CAVDAvcDecoder::VAStartDecode` `0x22a42e2f0`.
4. **SPS dims computed** in `processParserOut` `0x22a42ec00`:
   ```c
   int32_t x19_4 = (*(x8_26 + 0x616) << 4) + 0x10;   // pic_width_in_mbs_minus1
   *arg6 = x19_4;
   int32_t x23_2 = (*(x8_26 + 0x618) << 4) + 0x10;   // pic_height_in_map_units_minus1
   *(arg6 + 4) = x23_2;
   ```
   and stored into the decoder in `VAStartDecode` `0x22a42e2f0`:
   ```c
   uint32_t x8_7 = *(x21_2 + 0x616);
   uint64_t x21_3 = (x8_7 << 4) + 0x10;
   *(this + 0xb9c) = x21_3;                 // stored session width
   uint32_t x9_6 = *(x23_1 + x20_1 * 0x8b0 + 0x618);
   *(this + 0xba0) = (x9_6 << 4) + 0x10;    // stored session height
   ```
5. **Consumers of SPS dims.** `CAHDec*::allocWorkBuf_SPS` (e.g. Salvia AVC `0x22a42cef0`)
   sizes work buffers; `avd_seq_params` (`arg6`) carries dims to the hardware command builder.

---

## 3. Candidates

### Candidate A — asymmetric resolution-cap bypass (STRONG)
**Function:** `CAVDAvcDecoder::VAStartDecode` `0x22a42e2f0` + `CAVDAvcDecoder::processParserOut` `0x22a42ec00`.
**Quoted (`VAStartDecode`, `0x22a42e2f0`):**
```c
if (*(this + 0xa) == 1 && !(*(this + 0x1d36) & 1) && (x8_7 > 0xff || x9_6 >= 0x100))
{
    ... log ...
    return 0x136;          // reject >4096 px
}
```
**Quoted (`processParserOut`, `0x22a42ec00`):**
```c
if (!(*(this_1 + 0xa) & 1))
{
    int32_t x25_5 = *(this_1 + 0xb9c);
    if (x19_4 != x25_5) goto label_22a42f6f0;      // -> "Frame resolution change not supported", 0x131
    if (x23_2 != this_1[0x174]) { x25_5 = x19_4; label_22a42f6f0: ... }
    ...
}
else
{
    x25_4 = *(this_1 + 0x1d2c);
    if (x25_4 < x21_4) goto label_22a42f634;       // DPB check only
}
```
**Why it is a bug (logic asymmetry).** `processParserOut` tests `*(this+0xa) & 1` (any odd value)
while `VAStartDecode` tests `*(this+0xa) == 1` (exact). The same field is written wholesale by
`VASetParams` case `0x14` (`0x22a364de4`):
```c
case 0x14: { *(this + 0xa) = *arg3; return nullptr; }
```
If `*(this+0xa)` is any odd value other than 1 (e.g. 3), then **both** guards are disabled:
the resolution-change check is skipped (`!(3&1)==false`) and the 4096-px cap is skipped
(`3==1` false). Only the parse-time bound remains (`pic_width_in_mbs_minus1 <= 0x4000`,
`pic_height_in_map_units_minus1 <= 0x4000` → up to 262144 px per side). The second flag
`[0x1d36]` (selector `0x2f`, `case 0x2f: *(this + 0x1d36) = *arg3;`) independently disables
the cap even when `*(this+0xa)==1`.
**Input control:** `_AppleAVDSetParameter(ctx, sel, &val)` → `CAVDAvcDecoder::VASetParams`
selectors `0x1f` (0x14) and `0x39` (0x2f). Reachability of a value ≠1 from an untrusted path is
**not proven** — this is the unverified link.
**Consequence:** if reachable, in-band SPS dims diverge from the format-description / surface
dims with no cross-check → hardware programs larger dims than the destination surface →
OOB write by the decode engine / undersized work buffers.

### Candidate B — 32-bit multiply overflow in work-buffer sizing (SPECULATIVE)
**Function:** `CAHDecSalviaAvc::allocWorkBuf_SPS` `0x22a42cef0`.
**Quoted:**
```c
uint32_t x9  = *(arg2 + 0x616);     // pic_width_in_mbs_minus1
uint32_t x21 = *(arg2 + 0x618);     // pic_height_in_map_units_minus1
...
*(this + 0x3e18) = (x9 << 6) + 0x40;
*(this + 0x3e14) = (x9 << 6) + 0x40 + ((x9 << 6) + 0x40) * x21;   // 32-bit multiply
...
uint64_t x2_3 = *(this + 0x3e14);
if (x2_3 && CAVDDecoder::allocAVDMem(*(this + 0x1b8), this + 0x28b0 + x22_2 * 0xb0,
        x2_3, 7, 1, 0))
```
**Why:** `(x9<<6)*x21` overflows `uint32_t` when `x9*x21 > 2^26` (e.g. both ≈8192 MBs =
131072 px). At `x9=x21=0x4000` (parse max) the product wraps to `0x100000` (65536), so the
allocation is far smaller than the buffer the hardware indexes.
**Input control:** SPS dims. **Requires Candidate A's cap bypass to reach** (the 0x4000 MBs
parse bound alone is not reachable under the 4096-px cap). Confidence **SPECULATIVE** pending A.

### Candidate C — format-desc vs SPS dims never cross-checked (STRONG)
The `CanAcceptFormatDescription` gate (`0x22a470c0c`) compares the incoming format description
against wrapper-stored `[0x1458]/[0x145c]`; it never inspects the in-band SPS. The per-frame
SPS dims are compared only against `[0xb9c]/[0xba0]`, which `VAStartDecode` (`0x22a42e2f0`)
*itself* overwrites from the SPS. Therefore the only place a bitstream SPS dimension is tied to
the surface is the `*(this+0xa)&1`-gated check in `processParserOut` (`0x22a42ec00`). Disabling
that check (Candidate A) removes the last tie. Confidence **STRONG** for the absence of a
cross-check; the wrapper-dims writer (§2.2) must still be confirmed to be format-desc-derived.

### Candidate D — `_AppleAVDChangeVTResolutionInternal` (INFORMATIONAL, not a bug)
`0x22a4801b8`, called from `_AppleAVDDecodeFrame` `0x22a34fdf4` (callsites `0x22a350204`,
`0x22a350808`). Rounds `(arg4+0xf)&~0xf`, `(arg5+0xf)&~0xf`, mutates a CFDictionary
(width/height keys) and calls `0x2300e0df0(arg6, arg3)`; `*arg2 = 0`. It does not allocate or
bounds-check itself. Legitimate resolution-change plumbing; no flaw found here.

---

## 4. Negative results (valuable — do not re-chase)

- **`AVC_RBSP::parseSPS` `0x22a47370c`** bounds-checks `seq_parameter_set_id`:
  ```c
  x10_1 = 0xff & ~(x8_6 - x25_1);
  if (x10_1 < 0x20) { x11_1 = x25_1 + ~x8_6; goto label_22a473904; }
  // else log "seq_parameter_set_id(%d) out of range [0..%d]" and return 0xffffffff
  ```
  and clamps dims: `if (x0_72 <= 0x4000) { *(x23_2 + 0x616) = x0_72; ... if (x0_77 <= 0x4000) { *(x23_2 + 0x618) = x0_77; ... return x10_1; } }`.
- **`AVC_RBSP::parsePPS` `0x22a474748`** bounds-checks both IDs before indexing:
  ```c
  if (result < 0x100) { uint32_t x24_1 = x27_1;
      if (x24_1 < 0x20) { int16_t* x21_3 = arg2 + result * 0x25c;
                          void* x9_3 = arg3 + x24_1 * 0x8b0; ... } }
  ```
- **`_parseAvcSps` `0x22a47b5ac`** allocates 32 SPS slots (`0x11600 / 0x8b0`) and 256 PPS slots
  (`0x25c00 / 0x25c`); the only index into them is `parseSPS`/`parsePPS`'s return value, already
  checked (`==0xffffffff` → break). No OOB.
- **`CanAcceptFormatDescription` (H264/HEVC)** — no bypass found; the `CFEqual` fast-path accepts
  only when the stored format pointer is already equal (no free/replace observed in the audit).
- **`_CreateHeaderBuffer` `0x22a346088`** is the AV1/OBU variant (`*x0_16 != 0x81` config-OBU
  check); it writes `[0x1470]/[0x1478]/[0x14e0..0x14e2]`, not the dims.

---

## 5. Single most promising lead

**Candidate A/C combined:** the `*(this+0xa)` (`kVASetUnlimitedResolution`) and `*(this+0x1d36)`
flags in `VAStartDecode` `0x22a42e2f0` / `processParserOut` `0x22a42ec00` disable the *only*
in-band-SPS-to-surface dimension check, after which `allocWorkBuf_SPS` `0x22a42cef0` computes
buffer sizes with a wrapping 32-bit multiply. The decisive next step is to prove the flag values
are settable from an untrusted path (`_AppleAVDSetParameter` selector provenance) and to confirm
the writer of `[0x1458]/[0x145c]` (format-desc-derived vs SPS-derived).

---

## 6. Queries run (reproducibility)

```
bn_function_decompile  0x22a47370c  (AVC_RBSP::parseSPS)  off 0/250
bn_function_decompile  0x22a474748  (AVC_RBSP::parsePPS)  off 0
bn_function_search     "FormatDescription" | "Resolution" | "Sps" | "WorkBuf" | "alloc" |
                       "CAVDAvcDecoder::" | "AppleAVDWrapperH264" | "SeqAndPic" | "GetDimensions"
bn_string_list         "over size" | "Unlimited" | "exceeds" | addr 0x22a4e56f9
bn_function_xrefs_to   0x22a4801b8  (_AppleAVDChangeVTResolutionInternal)
bn_function_decompile  0x22a42ec00  (processParserOut)    off 350
bn_function_decompile  0x22a46e1a8  (H264 CreateInstance)
bn_function_decompile  0x22a4801b8  (_AppleAVDChangeVTResolutionInternal)
bn_function_decompile  0x22a42cef0  (CAHDecSalviaAvc::allocWorkBuf_SPS)
bn_function_decompile  0x22a46ee94  (H264 SetProperty)    off 0/515
bn_function_decompile  0x22a364de4  (CAVDAvcDecoder::VASetParams)
bn_function_decompile  0x22a47b5ac  (_parseAvcSps)
bn_function_decompile  0x22a46fc74  (H264 StartSession)   off 0/295
bn_function_decompile  0x22a346088 / 0x22a346464 / 0x22a3465e0  (_CreateHeaderBuffer variants)
bn_function_decompile  0x22a3639d4  (CAVDAvcDecoder::VADecodeFrame)  off 0/400
bn_function_decompile  0x22a42e2f0  (CAVDAvcDecoder::VAStartDecode)
bn_function_decompile  0x22a36ce94  (_getAvcSeqAndPicParamSetFromImageDescExt)
bn_data_xrefs_to       0x22a4e2555 / 0x22a4e56f9  -> 0 refs (string xrefs unavailable)
```

*No addresses or code in this document were invented; every quoted line is from the decompiler
output of the listed function on this build.*
