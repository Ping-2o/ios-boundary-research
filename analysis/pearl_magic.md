> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# ApplePearlSEPDriver — the `0xdead4567` ("Psd2 / v63p1") magic

Target: `com.apple.driver.ApplePearlSEPDriver`, iOS 27.0 RC (24A435), mac-aarch64 kext.
Tooling: Binary Ninja (MCP), read-only. Active binary view = `com.apple.driver.ApplePearlSEPDriver`,
image start `0xfffffff00769bde0`, `__text` = `0xfffffff009352610..0xfffffff009393174`.

All four reference sites named in the task live inside one function:

| | |
|---|---|
| Function | `sub_fffffff00935400c` |
| Range | `0xfffffff00935400c..0xfffffff009358f13` (20232 bytes, 1000 basic blocks, 6152 instrs) |
| Signature | `uint64_t(int64_t* arg1 /*driver*/, void* arg2 /*cmd*/, int32_t* arg3 /*payload*/, int64_t arg4 /*payloadSize*/, int64_t* arg5 /*outData*/, int32_t* arg6 /*outSize*/)` |
| Log tag | `"performSpecificCommandGated"` (`data_fffffff00769ca3a`) |
| Dispatch | `switch (*(int32_t*)(arg2+2) - 1)`, range-checked `<= 0x5d` |

`bn_function_callers(0xfffffff00935400c)` returns **empty** → the function is reached only indirectly
(function pointer / vtable / command-gate), so it is a command handler, not a direct-call helper.

---

## 0. Verdict (headline)

**REFUTED.** The newly-accepted `0xdead4567` magic does **not** select a different structure revision
and does **not** reach any parsing code. At all three sites where it is recognised, the code is
`if (magic != 0x45674567) { if (magic == 0xdead4567) <call>; fail; }` — the call result is
**discarded** and control falls into the same assertion-failure path used for every invalid magic.
There is therefore no v2 field/offset/size divergence to be out of bounds, and no OOB read or write.

The call-result discard is itself a defect (the `&& isV63p1Psd2MagicAllowed()` gate is a no-op),
but it is a *functional* defect, not memory corruption.

---

## 1. The magic checks — exact code

### 1.1 Site A — `psd3` (switch case 0x50, command id 0x51)

Case body starts at `0x3545a0`:

```
0xfffffff0093545a4  ldrh    w8, [x24, #0x4]            ; cmd->version (u16 @ cmd+4)
0xfffffff0093545a8  cmp     w8, #0x1
0xfffffff0093545ac  b.ne    0xfffffff009357668         ; must be 1
0xfffffff0093545b0  cbz     x21, 0xfffffff009357b7c    ; payload != NULL
0xfffffff0093545b4  cmp     x20, #0x5b
0xfffffff0093545b8  b.ls    0xfffffff00935831c         ; payloadSize >= 0x5c  (sizeof(*psd3))
0xfffffff0093545bc  ldr     w8, [x21]                  ; magic = *(u32*)payload
0xfffffff0093545c0  mov     w9, #0x4567
0xfffffff0093545c4  movk    w9, #0x4567, lsl #0x10     ; w9 = 0x45674567
0xfffffff0093545c8  cmp     w8, w9
0xfffffff0093545cc  b.ne    0xfffffff009356998         ; <-- anything != v1 -> block #569
0xfffffff0093545d0  ldr     w8, [x21, #0x4]            ; version = *(u32*)(payload+4)
0xfffffff0093545d4  cmp     w8, #0x6
0xfffffff0093545d8  b.ne    0xfffffff0093587a0
0xfffffff0093545dc  add     x1, x21, #0x8              ; &payload[8]
0xfffffff0093545e0  mov     x0, x19
0xfffffff0093545e4  mov     w2, #0x50                  ; 80 bytes
0xfffffff0093545e8  mov     w3, #0x1
0xfffffff0093545ec  bl      sub_fffffff00935a81c      ; getBrunorUnwrappedKey(...)
```

Block `#569` @ `0x356998` — the only place `0xdead4567` is mentioned in this case:

```
0xfffffff009356998  mov     w9, #0x4567
0xfffffff00935699c  movk    w9, #0xdead, lsl #0x10     ; w9 = 0xdead4567
0xfffffff0093569a0  cmp     w8, w9
0xfffffff0093569a4  b.ne    0xfffffff0093569ac         ; magic != dead4567 -> log
0xfffffff0093569a8  bl      sub_fffffff0093932f4       ; <== RESULT DISCARDED
0xfffffff0093569ac  mov     w8, #0x6e6                 ; source line 1766
0xfffffff0093569b0  adrp    x9, 0xfffffff00769c000
0xfffffff0093569b4  add     x9, x9, #0xaa1             ; .../ApplePearlSEPDriver.cpp
0xfffffff0093569b8  stp     x9, x8, [sp, #0x20]
0xfffffff0093569bc  adrp    x8, 0xfffffff00769c000
0xfffffff0093569c0  add     x8, x8, #0xaa0
0xfffffff0093569c4  adrp    x9, 0xfffffff00769d000
0xfffffff0093569c8  add     x9, x9, #0x894             ; "psd3->hdr.magic == (0x45674567) || (0xdead4567) && isV63p1Psd2MagicAllowed()"
0xfffffff0093569cc  b       0xfffffff009356b28         ; shared failure tail -> result = 0x102
```

Raw bytes at `0x356998` (read via `bn_memory_read`), decoded little-endian:

```
e9 ac 88 52 -> 0x5288ace9  MOVZ  W9, #0x4567
a9 d5 bb 72 -> 0x72bbd5a9  MOVK  W9, #0xdead, LSL#16
1f 01 09 6b -> 0x6b09011f  CMP   W8, W9
41 00 00 54 -> 0x54000041  B.NE  +8            ; -> 0x3569ac
53 f2 00 94 -> 0x9400f253  BL    #0x3c94c      ; -> 0x3932f4
c8 dc 80 52 -> 0x5280dcc8  MOVZ  W8, #0x6e6   ; <-- next instr is the failure logger
```

There is **no** `CBZ`/`TBZ`/`TBNZ` between the `BL` and the failure logger.

### 1.2 Site B — `psdHeader` (switch case 0x1d, command id 0x1e)

Case body starts at `0x3563c0` (`{Case 0x1d}`):

```
0xfffffff0093563fc  ldrh    w8, [x24, #0x4]            ; cmd->version (u16 @ cmd+4)
0xfffffff009356400  cmp     w8, #0x1
0xfffffff009356404  b.ne    0xfffffff009357a6c
0xfffffff009356408  cbz     x21, 0xfffffff0093581c8    ; payload != NULL
0xfffffff00935640c  cmp     x20, #0x7
0xfffffff009356410  b.ls    0xfffffff00935864c         ; payloadSize >= 8  (sizeof(*psdHeader))
0xfffffff009356414  cbz     x23, 0xfffffff009358768    ; outData != NULL
0xfffffff009356418  cbz     x22, 0xfffffff0093588e0    ; outSize != NULL
0xfffffff00935641c  ldr     w8, [x21]                  ; magic
0xfffffff009356420  mov     w9, #0x4567
0xfffffff009356424  movk    w9, #0x4567, lsl #0x10     ; w9 = 0x45674567
0xfffffff009356428  cmp     w8, w9
0xfffffff00935642c  b.ne    0xfffffff009356af4         ; <-- anything != v1 -> block #836
0xfffffff009356430  ldr     w8, [x21, #0x4]            ; version
0xfffffff009356434  cmp     w8, #0x6
0xfffffff009356438  b.eq    0xfffffff009357084         ; version == 6 -> parse
0xfffffff00935643c  cmp     w8, #0x5
0xfffffff009356440  b.ne    0xfffffff0093570a4
0xfffffff009356444  ... "psdHeader->version != (5)" ...  ; version 5 explicitly rejected
```

Version-6 parse (`0x357084`):

```
0xfffffff009357084  cmp     x20, #0x5b
0xfffffff009357088  b.ls    0xfffffff009358d14         ; payloadSize >= 0x5c
0xfffffff00935708c  add     x1, x21, #0x8              ; &payload[8]
0xfffffff009357090  mov     x0, x19
0xfffffff009357094  mov     w2, #0x50                  ; 80 bytes
0xfffffff00935709c  bl      sub_fffffff00935a81c      ; getBrunorUnwrappedKey(...)
```

Block `#836` @ `0x356af4`:

```
0xfffffff009356af4  mov     w9, #0x4567
0xfffffff009356af8  movk    w9, #0xdead, lsl #0x10
0xfffffff009356afc  cmp     w8, w9
0xfffffff009356b00  b.ne    0xfffffff009356b08
0xfffffff009356b04  bl      sub_fffffff0093932f4       ; <== RESULT DISCARDED
0xfffffff009356b08  mov     w8, #0x262                 ; source line 610
0xfffffff009356b0c  ...  file path ...
0xfffffff009356b24  add     x9, x9, #0xef1             ; "psdHeader->magic == (0x45674567) || ..."
0xfffffff009356b28  <failure tail -> result = 0x102>
```

### 1.3 Site C — a second `psdHeader` assert (source line 0x285 = 645)

Block `#686` @ `0x3569d0`, reached from a different command (`#604` @ `0x355114`):

```
0xfffffff0093569d0  mov     w9, #0x4567
0xfffffff0093569d4  movk    w9, #0xdead, lsl #0x10
0xfffffff0093569d8  cmp     w8, w9
0xfffffff0093569dc  b.ne    0xfffffff0093569e4
0xfffffff0093569e0  bl      sub_fffffff0093932f4       ; <== RESULT DISCARDED
0xfffffff0093569e4  mov     w8, #0x285
0xfffffff0093569e8  b       0xfffffff009356b0c         ; -> psdHeader failure tail
```

All three `0xdead4567` sites therefore have the identical shape.

### 1.4 CFG proof that the call result is unused

From `bn_function_basic_blocks`:

```
#453  0x3545bc-0x3545d0   TrueBranch -> #569 (0x356998)      ; magic != 0x45674567
                          FalseBranch -> #570 (0x3545d0)     ; v1 path (version check)
#569  0x356998-0x3569a8   TrueBranch -> #661 (0x3569ac)      ; magic != 0xdead4567 -> log
                          FalseBranch -> #662 (0x3569a8)     ; magic == 0xdead4567 -> call
#662  0x3569a8-0x3569ac   UnconditionalBranch -> #661 (fallthrough)
#661  0x3569ac-0x3569d0   UnconditionalBranch -> #3 (0x356b28)  ; shared failure tail
#3    0x356b28            -> result = 0x102 ; return

#788  0x35641c-0x356430   TrueBranch -> #836 (0x356af4)      ; magic != 0x45674567
                          FalseBranch -> #837 (0x356430)     ; v1 path
#836  0x356af4-0x356b04   ... -> #808 (0x356b0c)             ; failure tail
#686  0x3569d0-0x3569e0   TrueBranch -> #754 (0x3569e4)      ; magic != 0xdead4567 -> fail
                          FalseBranch -> #755 (0x3569e0)     ; call
#755  0x3569e0-0x3569e4   -> #754 (fallthrough)
```

Both the "equal" and "not equal" outcomes of the `0xdead4567` comparison land on the same failure
block. The compiler had no conditional to emit because the source does not use the value.

### 1.5 What is `sub_fffffff0093932f4`? (the "enable condition" question)

```
0xfffffff0093932f4  adrp    x17, 0xfffffff0080ee000
0xfffffff0093932f8  add     x17, x17, #0x418
0xfffffff0093932fc  ldr     x16, [x17]        ; slot = 0x8011000002fc093c  (PAC-signed pointer)
0xfffffff009393300  braa    x16, x17
```

* It is an **external (cross-image) function** reached through a signed pointer slot at
  `data_fffffff0080ee418`. Its body is **not present in this kext**, so a boot-arg / device-tree /
  SEP-firmware enable flag cannot be read out of this binary.
* The *same* stub is used for the `IOBioUtils::isInternal()` predicate: case 0x47 (command 0x48)
  at `0x354608` does `bl sub_fffffff0093932f4` followed by `tbz w0, #0, 0x357678` (i.e. it **does**
  test the result), and its failure block loads `"IOBioUtils::isInternal()"`
  (`data_fffffff00769d355` at `0x35869c`).
* Conclusion: `isV63p1Psd2MagicAllowed()` in the assertion text resolves to this same external
  predicate (most plausibly a macro/inline over `IOBioUtils::isInternal()`, i.e. internal/dev-build
  gated, possibly combined with a chip-revision check). The exact enable condition is
  **not determinable from this kext**.

Crucially, even if an unprivileged caller *could* make the predicate true, the return value is
discarded, so it has no effect on the control flow here.

---

## 2. v1 vs v2 comparison

There is **no v2 path**. Both `psd3` and `psdHeader` accept only `0x45674567`; `0xdead4567` is
funnelled into the failure tail (`result = 0x102`) before any struct field is consumed.

| field | offset | width | v1 (`0x45674567`) | v2 (`0xdead4567`) |
|---|---|---|---|---|
| `magic` | `+0x00` | u32 | must `== 0x45674567` (`0x3545c8`/`0x356428`) | rejected (`0x3545cc`→`0x356998`; `0x35642c`→`0x356af4`) |
| `version` | `+0x04` | u32 | must `== 6` (`0x3545d4`, `0x356434`); 5 explicitly rejected (`0x356444`) | never read |
| `wrappedKeyData` | `+0x08` | 0x50 bytes | passed to `getBrunorUnwrappedKey` (`0x3545dc`, `0x35708c`) | never read |
| `payloadSize` | — | u64 (`arg4`, `x20`) | `>= 0x5c` for `psd3` (`0x3545b4`); `>= 8` then `>= 0x5c` for `psdHeader` (`0x35640c`, `0x357084`) | — |
| `cmd->version` | `+0x04` of `arg2` | u16 (`ldrh`) | must `== 1` (`0x3545a4`, `0x3563fc`) | — |

`payloadSize` is `arg4` (`x20`), **not** a header field. Confirmed by `cmp x20, #0x5b` /
`cmp x20, #0x7` and by the decompiler's `if (arg4 <= 0x5b)`.

`sizeof(*psd3)` = `0x5c` (92) and `sizeof(*psdHeader)` = 8 (header only; the body size `0x5c` is
re-checked in the version-6 path).

---

## 3. Every field read after the magic, and in-bounds verdict

### `psd3` (case 0x50, command 0x51)

| read | address | width | bound | verdict |
|---|---|---|---|---|
| `magic = *(u32*)arg3` | `0x3545bc` | 32-bit `ldr w8,[x21]` | needs `payloadSize >= 4` | **in-bounds** (checked `>= 0x5c`) |
| `version = *(u32*)(arg3+4)` | `0x3545d0` | 32-bit `ldr w8,[x21,#4]` | needs `>= 8` | **in-bounds** |
| `arg3[2..]` = 0x50 bytes → `getBrunorUnwrappedKey` | `0x3545dc` | `add x1,x21,#8` + `w2=0x50` | needs `>= 8+0x50 = 0x58` | **in-bounds** (`payloadSize >= 0x5c`) |

### `psdHeader` (case 0x1d, command 0x1e)

| read | address | width | bound | verdict |
|---|---|---|---|---|
| `magic = *(u32*)arg3` | `0x35641c` | 32-bit `ldr w8,[x21]` | needs `>= 4` | **in-bounds** (checked `>= 8`) |
| `version = *(u32*)(arg3+4)` | `0x356430` | 32-bit `ldr w8,[x21,#4]` | needs `>= 8` | **in-bounds** |
| `arg3[2..]` = 0x50 bytes → `getBrunorUnwrappedKey` | `0x35708c` | `add x1,x21,#8` + `w2=0x50` | needs `>= 0x58` | **in-bounds** (version-6 path re-checks `payloadSize >= 0x5c`) |

The size constant and the field offset are consistent for both structs: the check (`0x5c`) is
strictly larger than the furthest byte touched (`0x58`). The "v1 size check vs v2 larger offset"
bug the hypothesis predicts **does not exist**, because the v2 branch is never taken.

The downstream callee `sub_fffffff00935a81c` (`getBrunorUnwrappedKey`) additionally asserts
`wrappedKeyData != NULL` (line 0x19f4) and `wrappedKeyDataSize == (80)` (line 0x19f5), so the
0x50-byte window is fully validated before use.

---

## 4. Write side

The parser does **not** write a caller-provided buffer using a value derived from the PSD header.
The only value carried from the parsed region into the rest of the driver is the compile-time
constant `0x50` (wrapped-key length) and a pointer to `payload+8`; there is no header-supplied
count / length / index. Output writes use `arg5`/`arg6` (`outData`/`outSize`) with fixed sizes, and
the version-6/`0x50` path never computes a length from the header. No header-derived OOB write
exists on the reachable path.

---

## 5. Reachability

* `bn_function_callers(0xfffffff00935400c)` → **0 callers** (indirect dispatch: function-pointer /
  vtable / command-gate). Log tag `"performSpecificCommandGated"` and the argument shape
  `(driver, cmd, payload, payloadSize, outData, outSize)` match an IOKit command-gate / SEP mailbox
  command handler in `ApplePearlSEPDriver`.
* Command id = `*(int32_t*)(arg2+2) - 1`, bounded `0..0x5d`; the command struct's own version field
  `*(u16*)(arg2+4)` must be `1` for the PSD-parsing commands (`0x3545a4`, `0x3563fc`).
* The PSD bytes are the caller-supplied `payload` (`arg3`), i.e. this is on the driver's command
  ingestion path (ApplePearlSEPDriverUserClient / SEP mailbox). That path is normally gated behind
  the biometrics entitlement and the SEP itself.
* Because `0xdead4567` is rejected before parsing, this change adds **no** new reachable
  memory-safety surface, regardless of who can reach the handler.

---

## 6. Confidence labels

| claim | confidence |
|---|---|
| `0xdead4567` selects no distinct revision and reaches no parsing code (both/three sites) | **REFUTED** (the OOB hypothesis) — PROVEN code-level |
| The `isV63p1Psd2MagicAllowed()` call result is discarded at `0x3569a8`, `0x3569e0`, `0x356b04` | **PROVEN** (raw bytes + CFG edges #569→#661, #662→#661, #686/#755→#754) |
| No OOB read on the v1 paths (`psd3`/`psdHeader`); reads end at `+0x58`, checks require `>= 0x5c` | **PROVEN** |
| No header-derived write to a caller buffer | **STRONG** (output path uses fixed sizes; `getBrunorUnwrappedKey` asserts size `== 0x50`) |
| The stub `0x3932f4` is the `IOBioUtils::isInternal()` predicate and `isV63p1Psd2MagicAllowed()` resolves to it | **STRONG** (same stub is `tbz`-tested at the `IOBioUtils::isInternal()` asserts) |
| The predicate's enable condition (boot-arg / DT / SEP flag) | **SPECULATIVE / not determinable** — external function, body absent from this kext |
| The advertised "second accepted magic" is not actually accepted here | **PROVEN** within `sub_fffffff00935400c`; **SPECULATIVE** that no other function accepts it (only this function was in scope) |

### Severity

**LOW.** The change is inert on the memory-safety front: `0xdead4567` is routed to the generic
`result = 0x102` failure tail before any field is consumed, so there is no OOB read or write. The
only observable defect is functional: the added `&& isV63p1Psd2MagicAllowed()` gate is compiled to
a call whose result is unused, so a caller sending the new magic gets an error instead of the
intended new-revision path. If the release intent really was to accept `0xdead4567`, the acceptance
is implemented elsewhere (out of scope) or the check is miscompiled/miswritten — but within this
function it is dead.

---

## Appendix — reproduction queries (Binary Ninja MCP, read-only)

* `bn_function_info 0xfffffff00935400c` → 1000 BB, `0xfffffff00935400c..0xfffffff009358f13`
* `bn_function_disassembly 0xfffffff00935400c offset=2860 limit=45` → `0x356420..` (psdHeader accept)
* `bn_function_disassembly 0xfffffff00935400c offset=435 limit=55` → `0x3545a0..` (psd3 accept)
* `bn_function_disassembly 0xfffffff00935400c offset=3290 limit=130` → `0x356998..` (psd3 fail block)
* `bn_function_disassembly 0xfffffff00935400c offset=3410 limit=160` → `0x356af4..` (psdHeader fail block)
* `bn_memory_read 0xfffffff009356960 len 0x140` → raw bytes proving no test after the `bl`
* `bn_function_basic_blocks 0xfffffff00935400c` → edges #453/#569/#662/#661, #788/#836, #686/#755/#754
* `bn_function_callees 0xfffffff00935400c` → `0x3569a8 -> 0x3932f4`, `0x3569e0 -> 0x3932f4`, `0x356b04 -> 0x3932f4`
* `bn_function_decompile 0xfffffff00935400c offset=4000 limit=721` → decompiled `case 0x50` magic check
