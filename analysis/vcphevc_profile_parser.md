> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# VCPHEVC.videocodec — Profile/String + CF Dictionary Parsing Audit

Target: `VCPHEVC.videocodec`, iOS 27.0 RC (24A435), Mach-O dylib, ios-aarch64.
Active Binary Ninja view: image base `0x242599000`, `__text` = `0x242599c98..0x2426e8780`, 2461 functions, stripped.
Method: Binary Ninja MCP only (decompile/disassembly/callers/callees/function-list/memory-read/string-list).

> Caveat that affected method: `bn_data_xrefs_to` / `bn_data_xrefs_from` return **empty** in this view, and
> `bn_memory_read` returns **0 bytes** for the `0x2680fxxxx` `__DATA_CONST`/GOT page. Consequently all
> pointer globals (`0x2680f89a0`, `0x2680f8970`, `0x2680f8f78`, …) could not be dereferenced, and string
> xrefs could not be enumerated. Every conclusion below is from code that *was* read; where a claim depends
> on an unreadable global it is labelled accordingly.

---

## 0. Verdict (short)

The four named targets (`sub_2425a15b4`, `sub_2425a1f1c`, `sub_2425a9434`, `sub_2425a9aa8`) plus the
profile consumers were audited. **No memory-safety bug was proven.** Every type check, array bound and
`CFNumberGetValue` width that the brief asked about is present and consistent on the encoder property
surface. This is a *clean negative* on hypotheses 1–5, with one SPECULATIVE lead (the `0xffffffff`
`hdr_type` sentinel, §6) and one unresolved decoder-side lead (§7).

The single most important structural fact: the safety of the **generic** property setters rests entirely on
an internal, constant descriptor table built once in `sub_24259d838`. That table was enumerated (§4) and is
internally consistent, so the generic path is safe *for the encoder*.

---

## 1. Reachability trace (all addresses are real BN function starts / call sites)

```
[VideoToolbox / app]  VTCompressionSessionSetProperty(key, value)
        │  (indirect: handler pointer, NOT a direct call — bn_function_callers(sub_2425a15b4) == 0)
        ▼
sub_2425a15b4 @ 0x2425a15b4   "SetProperty: %s\n"   ← app-supplied key + value
        │
        ├─ profile branch (key == **0x2680f89a0) ─────────────────────────────┐
        │     0x2425a1804  ldr  x8,[x8,#0x9a0]      ; 0x2680f89a0 (ProfileLevel key)
        │     0x2425a1814  bl   0x24809d490         ; CFEqual(arg2, ProfileLevel)
        │     0x2425a1818  cbz  w0,0x2425a190c
        │     0x2425a181c  cbz  x20,0x2425a19b8     ; value == NULL → profile = 0
        │     0x2425a1824  bl   0x24809a6f0         ; CFGetTypeID(value)
        │     0x2425a182c  bl   0x24809a790         ; CFStringGetTypeID()
        │     0x2425a1834  b.ne 0x2425a19c0         ; → "Profile argument not a string"
        │     0x2425a1854..0x2425a1878              ; 5-iteration table walk (data_2690213f0)
        │     0x2425a1ac8  str  w8,[x19,#0x8]       ; store parsed profile id (32-bit)
        │     0x2425a1ae4  bl   0x24809a780         ; CFRetain(value) → [x19,#0]
        │     ...
        └─ sub_2425a1f1c @ 0x2425a1f1c  (buffer-attribute sibling; also indirect, 0 callers)
               └─ sub_2425cf97c @ 0x2425cf97c (call site 0x2425a1f80)

Consumers of the parsed profile id (x0[1] / [obj+8]):
   0x2425a1bb0  bl sub_2425cf97c   (from sub_2425a15b4)
   0x2425a1af8  bl sub_2425d0120   (from sub_2425a15b4)
   0x2425a3650  bl sub_2425d0120   (from sub_2425a35f0 @ 0x2425a35f0)
       sub_2425cf97c → sub_2425cecf0 (0x2425cecf0) + sub_2425cfea8 (0x2425cfea8)
       sub_2425d0120 → sub_2425cfea8 (0x2425d0258)
   sub_2425cfea8 @ 0x2425cfea8 : profile id → fixed pixel-format string tables (see §3)

Registration / object construction:
   _HEVCVideoEncoder_CreateInstance @ 0x2425a1158
        └─ sub_24259d838 @ 0x24259d838   (object init + descriptor hashmap; 46 sub_2425a9aa8 inserts)
   _VCPHEVCRegisterDecoder @ 0x24259aa3c → sub_24259d76c @ 0x24259d76c
        └─ 0x2480aa100(0x68766331, dict, _HEVCVideoDecoder_CreateInstance)  ; 'hvc1'

Copy path (for completeness):
   sub_2425a139c @ 0x2425a139c  "CopyProperty: %s\n"
        └─ sub_2425a0fdc @ 0x2425a0fdc (CopyCommonProperty)
   CreateProfileLevelDict: sub_2425a9434 @ 0x2425a9434  (0 direct callers → data/vtable reference)
```

**Input class: PROVEN app-supplied.** `sub_2425a15b4` is the VideoToolbox *SetProperty* handler
(its own log string `"SetProperty: %s\n"` at `0x2425a1634`/`0x2425a1688`), reached through the
property-descriptor table populated by `sub_24259d838` from `_HEVCVideoEncoder_CreateInstance`. The
`arg3` value flows unmodified from the session-property call. Severity of any bug here would be **high**.

---

## 2. Profile/level lookup paths

| # | Function / site | Value parsed | Table / array indexed | Size | Guard |
|---|---|---|---|---|---|
| 1 | `sub_2425a15b4` @ `0x2425a1854` (loop head), match at `0x2425a1860`→`0x2425a1ac0` | `arg3` = **CFString** (session value) | `data_2690213f0` (5 × 16 B: `{CFStringRef* key; int32_t value;}`) | **5** (`mov w24,#0x5` @ `0x2425a184c`; `subs x24,x24,#1; b.eq` @ `0x2425a1870`) | `CFGetTypeID(value)==CFStringGetTypeID()` @ `0x2425a1824/0x2425a1834`; loop counter bounded; `cbz w8` on value 0 @ `0x2425a1ac4` |
| 2 | `sub_2425cfea8` @ `0x2425cfea8` | profile id `arg1` (int32) | **branch-selected fixed tables**, not indexed: `"f024v024"` (2), `"800L"` (1), `"010L800L"` (2), `"024x02fx612vv024f024B01Y"` (6), `"024x02fx612vf024v024010L800LB01Y"` (8) | loop counts literal | branch tests `(arg1&0xfffffffd)==1`, `arg1==0x7e4`, `arg1==0x764`, `arg1==2`, else; **no user-controlled index** |
| 3 | `sub_2425a44dc` @ ~`0x2425a4dxx` (profile switch, "Specified profile %d…") | `x0[1]` = profile id (int32) | none — membership test only | — | `x8_91>0x763 / >0xb63 / !=0x764,0x7e4 / >1 / !=2,3 / !=1`; default only logs |
| 4 | `sub_2425a0c74` @ `0x2425a0d30` (generic CFNumber setter) | `arg3` = CFNumber | descriptor hashmap entry `[3]=type [4]=dest [5]=numType [6]=min` | 48 entries built in `sub_24259d838` | `CFGetTypeID(arg3)==entry[3]` @ `0x2425a0ce4/0x2425a0ce8`; `CFNumberGetValue` success @ `0x2425a0d34`; `CFNumberCompare(v,entry[6],0) != -1` @ `0x2425a0d5c` |
| 5 | `sub_2425a75ec` @ ~`0x2425a7xxx` (options dict) | `arg4` = `HEVCEncoderOptions` dict | none — `CFDictionaryGetValue` per key | — | per-key `CFGetTypeID == CFNumberGetTypeID` before every `CFNumberGetValue` |
| 6 | `sub_2425a2034` @ ~`0x2425a2xxx` (options sub-array) | array of option values | CFArray from options | **min(count,5)** | `CFArrayGetTypeID` check; `x8_6 = count<5?count:5` |

Table `data_2690213f0` contents (raw bytes read at `0x2690213f0`, 80 B; value halves little-endian):
`{key0,2}, {key1,1}, {key2,3}, {key3,0x7e4}, {key4,0x764}` → the five
`_kVTProfileLevel_HEVC_{Main10,Main,MainStill,Monochrome,Monochrome10}_AutoLevel` strings.

---

## 3. `CFNumberGetValue` sites (type code vs destination width)

| Function | Call site | Type arg (reg) | Destination | Dest width | Verdict |
|---|---|---|---|---|---|
| `sub_2425a0c74` | `0x2425a0d30` | `x1 = entry[5]` (`ldr x23,[x0,#0x28]` @ `0x2425a0d08`) | `x2 = entry[4]` (`ldr x21,[x0,#0x20]` @ `0x2425a0cd8`) | descriptor-driven: `3`/`5`→4 B, `13`→8 B | **consistent** (verified against all 48 descriptors in `sub_24259d838`) |
| `sub_2425a15b4` (PASP val1) | `0x2425a1d14` | `w1 = #0x9` (SInt32) | `sp+0x10` (`var_70`) | 4 B | **consistent** |
| `sub_2425a15b4` (PASP val2) | `0x2425a1d3c` | `w1 = #0x9` (SInt32) | `sp+0x2c` (`i_6`) | 4 B | **consistent** |
| `sub_2425a75ec` (many, e.g. `arg3+0x51c`, `+0x8c`, `+0x90`, `+0x11c`, `+0x120`, `+0x98`, `+0xa0`, `+0x1dc`, `+0x1e0`, `+0x1e4`, `+0x1e8`, `+0x1ec`, `+0x1f0`, `+0x2b8`, `+0x1c8`, `+0x1cc`, `+0x1d0`, `+0x1d4`, `+0x1c4`, `+0x1ac`, `+0x1b8`, `+0x1bc`, `+0x1c0`) | various | `w1 = #0x3` (SInt32) | 4-byte fields | 4 B | **consistent** |
| `sub_2425a75ec` | ~`arg3+0x1b0` | `w1 = #0xd` (Double) | `arg3+0x1b0` | 8 B | **consistent** |
| `sub_2425a75ec` (array elements) | ~`0x2425a7xxx` | `w1 = #0x9` (SInt32) | `arg3+0x16c+(i<<2)`, `i < min(count,0x10)` | 4 B | **consistent**, bounded |
| `sub_2425a2034` | several | `#0x3` / `#0x9` / `#0xd` | various 4 B / 8 B fields | matching | **consistent** |

No `CFNumberGetValue` was found whose type code is wider than its destination, nor a destination
narrower than the type. **Hypothesis 5 REFUTED for this surface.**

Note on the decompiler width warning: `CFNumberGetValue` at `0x2425a0d30` is genuinely
`mov x1, x23` with `x23` a 64-bit load from the descriptor; the *value* is a `CFNumberType` enum, not a
width. The destination is a raw pointer and its size is implicit in the descriptor — verified by
enumerating the descriptor table.

---

## 4. Descriptor table (encoder) — why the generic setter is safe

`sub_24259d838` registers 48 descriptors via `sub_2425a9aa8`. Entry layout (from `sub_2425a99c0` /
`sub_2425a0c74`): `[0]=next [1]=hash [2]=key [3]=expected CFTypeID [4]=dest [5]=CFNumberType [6]=min`.
Registration records observed:

- **ProfileLevel**: `var_88=**0x2680f89a0`, type `0x24809a790` (CFString), dest `arg1+0`, numType `0x10`.
  Matches the dedicated parser: `[obj+0]` = retained CFString, `[obj+8]` = parsed int (unregistered, internal).
- **PASP**: key `**0x2680f8970`, type `0x24809a6d0` (CFDictionary), dest `arg1+0x38`.
- CFNumber entries: dest `+0x10,0x14,0x18,0x1c,0x20,0x28,0x30,0x80,0x90,0x94,0x98,0xa0,0xa4,0xa8,0xb0,0x4ac,0x4b4,0x4c4,0x4dc`
  with numType `3` (4 B) or `5` (4 B) or `0xd` (8 B, only `+0x28`).
- CFBoolean entries: type `0x24809a660`, 1-byte stores.
- CFString/CFData entries: type `0x24809a790` / `0x24809d460`, 8-byte pointer stores.

No dest overlaps a differently-sized field; no dest is narrower than its declared type. The
ProfileLevel int at `[obj+8]` is not a registered dest, so no generic setter can alias it.

---

## 5. Candidate bugs and confidence

### C1 — CFString/CFNumber type confusion on the profile value — **REFUTED**
The only check that matters is at `0x2425a1834` (`b.ne` on `CFGetTypeID(value) != CFStringGetTypeID()`).
Downstream of that check the value is used **only** in `CFEqual` against the 5 table strings
(`0x2425a185c`) and in `CFRetain` (`0x2425a1ae4`). The *parsed integer* (`str w8,[x19,#0x8]` @
`0x2425a1ac8`) is a constant from `data_2690213f0`, never the CFString. There is no second path that
re-uses `arg3` as an integer. The `arg3 == NULL` path (`0x2425a181c`) stores `0` without a type check,
which is correct for a null value.
Quotes: `0x2425a1824 bl 0x24809a6f0` (CFGetTypeID); `0x2425a1834 b.ne 0x2425a19c0`;
`0x2425a19dc add x0,x0,#0x1e9 {data_24271a1e9, "Profile argument not a string\n"}`.

### C2 — CFArray index vs count — **REFUTED**
Two array walks exist; both clamp the index by the *same* array's count:
- `sub_2425a2034`: `x8_6 = x0_16 < 5 ? x0_16 : 5; x0_1[0x50]=x8_6; do { CFArrayGetValueAtIndex(x0_11,i) … i++ } while (i < x0_1[0x50])`. Index < count.
- `sub_2425a75ec`: `x8_41 = x0_147 < 0x10 ? x0_147 : 0x10; *(arg3+0x168)=x8_41; do { CFNumberGetValue(CFArrayGetValueAtIndex(x0_142,i),9,…) i++ } while (i < *(arg3+0x168))`. Index < count.
Destination strides (`+0x1f4+i*0x1c`, i<5; `+0x16c+i*4`, i<16) stay inside the allocations.
Count and index always come from the same `x0_11` / `x0_142`.

### C3 — Lookup table indexed by a parsed integer — **REFUTED**
The only indexed table is the 5-entry `data_2690213f0`, walked by a hard-coded 5-iteration loop
(`0x2425a184c`, `0x2425a1870`) with the *string* compared, never the index. The parsed int is used
only as a switch discriminant in `sub_2425cfea8` and `sub_2425a44dc`.

### C4 — `strtol`/`atoi`/`sscanf` on the profile string — **REFUTED**
No numeric parsing on the profile string. The parser uses `CFEqual` against 5 exact constant strings
(`0x2425a185c`). No `strtol`/`atoi`/`sscanf`/end-pointer logic exists on this path. (The new
`fscanf`/`fopen` surface belongs to the config/scaling-list files, a different subsystem.)

### C5 — `CFNumberGetValue` width mismatch — **REFUTED** (see §3).

### C6 — `-1` / `0xffffffff` sentinel — **SPECULATIVE**
`sub_24259d838` initialises `hdr_type` to `0xffffffff`:
`*(arg1 + 0x4c4) = 0xffffffff;` (in the init block). In `sub_2425a44dc` the value is overwritten **only**
when a colour-primaries/transfer/matrix triple matches (`(9,0x10,9)→2`, `(9,0x12,9)→3`); otherwise it
remains `0xffffffff`. The downstream consumer at `label_2425a5c78` does
`if (*(x0 + 0x4c4) == 0xffffffff) { … }` and proceeds to read more keys — it does **not** use the value
as an array index in the code read. Confidence SPECULATIVE: no OOB was demonstrated; a consumer outside
the read window could still treat `-1` as a valid `hdr_type`. Recommend a follow-up on every read of
`[obj+0x4c4]`.
The `-1` used in `sub_2425a0c74` (`cmn x0,#0x1; b.eq 0x2425a0f50`) is a correct
`CFNumberCompare(value, min, 0) == kCFCompareLessThan` lower-bound check — **REFUTED** as a bug.

### C7 — `CreateProfileLevelDict` (`sub_2425a9434`) — **REFUTED**
Builds `CFMutableArray` (`0x24809b570`), appends exactly 5 constant strings
(`0x24809b560` ×5, loop count `mov w24`-style literal 5), wraps it in a 1-entry `CFDictionaryCreate`
(`0x2480a9d80`), then merges per-key copies into an outer mutable dict. No indexing, no user input,
no attacker-controlled length. Error paths `CFRelease` correctly (`0x248097e30`).

### C8 — `sub_2425a9aa8` / `sub_2425a99c0` (hashmap) — **REFUTED (not profile-specific)**
Generic open-addressing hashmap insert/lookup; bucket = `hash(key) % n` with power-of-two masking. Used
by 46 descriptor registrations and by every property set/get. Key hashing (`0x2480aa2f0`) and bucket
math are self-consistent. Not a profile parser.

---

## 6. `profile_space_[layer_idx]` and the decoder-side leads — UNRESOLVED

Strings `"profile_space_[layer_idx] == 0 failed!\n"` (`0x24271dfff`, dup `0x2427270b4`),
`"input profile %d is not applicable, suggesting %d\n"` (`0x24271df2f`),
`"Unable to determine a profile\n"` (`0x24271de27`), `"Profile %d not supported\n"` (`0x24271e03c`),
`"SPS change resulted in different profile!\n"` (`0x24271b460`) and
`"------ ProfileTierLevel ------"` (`0x24271e056`) form a contiguous `__cstring` block that belongs to a
**decoder-side ProfileTierLevel / SPS parser**, not to the encoder property cluster audited above.

I could **not** resolve the containing function with the tools available:
- `bn_data_xrefs_to` returns empty for every one of these addresses (documented BN limitation), and
- the `0x24271d000`/`0x24271e000` pages are referenced only by `adrp`+`add` from code I could not locate
  by name (all functions are `sub_*`), and
- `bn_memory_read` could not be used to brute-force the `__text` scan at acceptable cost.

What *is* known: `profile_space_[layer_idx]` is a **per-sub-layer field name** (`profile_space`,
`profile_idc`, `profile_compatibility_flag`, `sub_layer_profile_present_flag` are adjacent strings), i.e.
a `layer_idx` loop over an HEVC `profile_tier_level()` sub-layer array — the exact pattern the brief
flags. Reachability from an **app-supplied CFString is low**: this is bitstream/SPS-driven (decoder),
not a session-property value. It should be treated as a separate decoder-fuzzing target, not part of the
property-parser surface. Confidence that a bug exists there: **SPECULATIVE / unverified**.

---

## 7. Confidence summary

| Candidate | Confidence |
|---|---|
| C1 CFString/CFNumber type confusion (ProfileLevel) | **REFUTED** |
| C2 CFArray index vs count | **REFUTED** |
| C3 lookup table indexed by parsed int | **REFUTED** |
| C4 `strtol`/`atoi`/`sscanf` on profile string | **REFUTED** |
| C5 `CFNumberGetValue` width mismatch | **REFUTED** |
| C6 `0xffffffff` `hdr_type` sentinel | **SPECULATIVE** |
| C7 `CreateProfileLevelDict` array/dict | **REFUTED** |
| C8 hashmap helpers | **REFUTED** |
| Decoder `profile_space_[layer_idx]` lead | **SPECULATIVE / not located** |
| Reachability of `sub_2425a15b4` from app CFString | **PROVEN** (indirect property callback) |
