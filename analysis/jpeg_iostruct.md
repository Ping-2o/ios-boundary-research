> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# `AppleJPEGDriverIOStruct` — layout, six-method validation matrix, and candidate bugs

**Target:** `com.apple.driver.AppleJPEGDriver`, iOS 27.0 RC (24A435), mac-aarch64
**Tool:** Binary Ninja + MCP, active view `com.apple.driver.AppleJPEGDriver` (read-only)
**Image base:** `0xfffffff00753b4d0` · `__text` = `0xfffffff00900ebb0..0xfffffff00903c538`
**Method:** every offset/width below was confirmed in `bn_function_disassembly`, not taken from the
decompiler alone (see §0 for why).

---

## 0. Decompiler rendering conventions (IMPORTANT — verified against disassembly)

BN types the input struct as `int32_t* arg2`. Two different renderings appear and they **do not mean
the same thing**:

| decompiler form | actual meaning | proof |
|---|---|---|
| `arg2[N]` | **element index**, byte offset `4*N` | `arg2[0x12]` ⇔ `ldr w2, [x19, #0x48]` @ `0xfffffff00901a5e4` |
| `*(arg2 + K)` | **byte offset** `K` (NOT scaled) | `*(arg2 + 0x30)` ⇔ `ldr x8, [x19, #0x30]` @ `0xfffffff00901a5e8` |

Other confirmed width corrections (the decompiler widens these to 64-bit; the disassembly is 32-bit):

* `uint64_t x21 = *(arg2 + 0x428)` in `sub_fffffff00903acec` is really
  **`ldr w21, [x1, #0x428]`** @ `0xfffffff00903ad1c` (32-bit). Same for `0x42c` @ `0xfffffff00903ad20`.
  So "pixelsX/pixelsY" arithmetic is **32-bit**, not 64-bit.
* `ldur d0, [x19, #0x14]` / `str d0, [x21, #0x428]` is a genuine 8-byte copy of the *pair*
  `{0x14, 0x18}` into `{req+0x428, req+0x42c}` — semantically two u32s.

## 0.1 The six methods and their reachability

| method | function | signature string |
|---|---|---|
| `startDecoder` | `sub_fffffff009018830` | `0xfffffff00753c417` |
| `startDecoderExt` | `sub_fffffff009019334` | `0xfffffff00753c499` |
| `startEncoder` | `sub_fffffff009019ad0` | `0xfffffff00753c524` |
| `startEncoderExt` | `sub_fffffff009019ee4` | `0xfffffff00753c5a6` |
| `startDecoder2024` | `sub_fffffff00901a348` | `0xfffffff00753c631` |
| `startEncoder2024` | `sub_fffffff00901a9e8` | `0xfffffff00753c6bf` |

Each is reachable from **two** thin trampolines (all confirmed by decompilation), i.e. two distinct
selectors each:

* *Family A* (extracts in/out from a struct at `arg3+0x30` / `arg3+0x58`):
  `0xfffffff009022da4`→Decoder, `0xfffffff009022de4`→Encoder, `0xfffffff009022e18`→EncoderExt,
  `0xfffffff009022e4c`→DecoderExt, `0xfffffff009022e80`→Encoder2024, `0xfffffff009022eb4`→Decoder2024.
* *Family B* (passes `arg2`/`arg3` straight through):
  `0xfffffff009023040`→Decoder, `0xfffffff009023068`→Encoder, `0xfffffff009023090`→EncoderExt,
  `0xfffffff0090230b8`→DecoderExt, `0xfffffff0090230e0`→Encoder2024, `0xfffffff009023108`→Decoder2024.

All six trampolines share: `if (!*(arg1+0xe0)) return 0xe00002bc;` then tail-call.
**All six methods are live.** `bn_function_callers` on the trampolines returns *empty* (they are
reached only through a data-side dispatch table), which is a tool limitation, not proof of dead code.

## 0.2 Where the request goes

Every one of the six ends with the identical gate call:

```
0xfffffff0090197c0  ldr  x0, [x22, #0xb8]
0xfffffff0090197c4  ldr  x16, [x0]      ; ... autda ...
0xfffffff0090197d4  ldr  x9, [x16, #0xe8]!
0xfffffff0090197e0  add  x16, x16, #0xc0c   ; sub_fffffff009018c0c  (queue_io_gated)
0xfffffff009019808  blraa x9, x17
```

`sub_fffffff009018c0c` = `queue_io_gated`, which calls
`sub_fffffff00903acd8(*(arg1+0x160), arg2, …)` = *"pass the request validation"* and
`sub_fffffff00903b6b4` = *"pass the request setup"*. Those dispatch on `*(req+0x2a8)`:

* `0` (decode) → `sub_fffffff00903acec` = `RequestHandling::decodeRequestValidation`
* `1` (encode) → `sub_fffffff00903b24c` = `RequestHandling::encodeRequestValidation`

`*(req+0x2a8)` is set to `1` in the encoders (`str w8, [x22, #0x2a8] {0x1}` @ `0xfffffff009019c10`)
and `0` in the decoders (`str wzr, [x21, #0x2a8]` @ `0xfffffff009019448`).

---

## 1. `AppleJPEGDriverIOStruct` field layout

All offsets are **byte** offsets from the start of the input struct. "req→" names the destination
offset in the `JpegRequest` object (`x21`/`x22`/`x23` in the six methods).

### 1.1 Base block — present in **all six** variants

| off | width | meaning / evidence | req→ |
|---|---|---|---|
| `0x00` | u32 | `ldp w9,w10,[x19]`; `str w9,[x21,#0x2ac]` | `0x2ac` |
| `0x04` | u32 | **inputSize** — named in Ext error string *"inputSize %d"*; `ldr w8,[x19,#0x4]` @ `0xfffffff009019fd8` | `0x420` |
| `0x08` | u32 | `ldp w9,w11,[x19,#0x8]`; `str w9,[x21,#0x2b0]` | `0x2b0` |
| `0x0c` | u32 | **outputSize** — *"req->outputSize %d"*; `ldr w9,[x19,#0xc]` @ `0xfffffff009019fdc` | `0x424` |
| `0x14` | u32 | **Horz resolution / pixelsX** — *"Horz (%d)"*; also `ldrh w8,[x19,#0x18]`-paired in trace | `0x428` |
| `0x18` | u32 | **Vert resolution / pixelsY** — *"Vert (%d)"*; `ldrh w9,[x19,#0x18]` @ `0xfffffff0090195e4` | `0x42c` |
| `0x1c` | u32 | **encoding quality**; `(v & 0xfffe) >= 0xa` → reject @ `0xfffffff009019b58` | `0x44c` |
| `0x20` | u8 | **flags**: bit0→req `0x310`, bit1→`0x312`, bit2→`0x314`, bit3→`0x31c`, bit4→`0x318` (`ldrb w9,[x19,#0x20]` @ `0xfffffff00901942c`) | `0x310/0x312/0x314` |
| `0x24` | 2×u32 | **xOffset/yOffset**; `ldur d0,[x19,#0x24]` @ `0xfffffff00901a478` | `0x450`/`0x454` |
| `0x2c` | u32 | **subsampling mode** (0..4) → `convertToRequestSubSampleMode` / `getMCUSize`; `ldr w8,[x19,#0x2c]` | `0x444` |
| `0x30` | 16 B | `ldr q0,[x19,#0x30]; str q0,[x21,#0x10]`; low 64 bits tested with `ldr x8,[x19,#0x30]; cbz` @ `0xfffffff00901a810` | `0x10` |
| `0x40` | u64 | `ldr x9,[x19,#0x40]; str x9,[x21,#0x20]` @ `0xfffffff009019414` | `0x20` |
| `0x48` | u32 | **request id / trace tag** (`ldr w2,[x19,#0x48]` in every trace call) | `0x538` |
| `0x4c` | 2×u32 | **decodeWidth / decodeHeight**; `ldur d0,[x19,#0x4c]` @ `0xfffffff00901a470` | `0x47c`/`0x480` |
| `0x54` | u32 | `ldr w9,[x19,#0x54]` @ `0xfffffff00901a4b0` | `0x458` and `0x4ac` |

### 1.2 `…IOStructExt` — additional fields (used by `startDecoderExt` / `startEncoderExt`)

| off | width | meaning / evidence | req→ |
|---|---|---|---|
| `0x58` | u32 | `ldr w9,[x19,#0x58]` @ `0xfffffff00901a4b8` | `0x4b0` |
| `0x5c` | u32 | "scale/crop enable" (`cbz w8` @ `0xfffffff00901a19c`) | `0x4b4` |
| `0x60` | u32 | `ldr w8,[x19,#0x60]` | `0x4b8` |
| `0x64` | u32 | `ldr w8,[x19,#0x64]` | `0x4bc` |
| `0x68` | u32 | **cropW** (validated `< 0x10000` in `decodeRequestValidation`) | `0x4c0` |
| `0x6c` | u32 | **cropH** (validated `< 0x10000`) | `0x4c4` |
| `0x70` | u32 | `ldr w9,[x19,#0x70]` @ `0xfffffff00901a488` | `0x498` |
| `0x74` | u32 | `ldr w9,[x19,#0x74]` | `0x49c` |
| `0x78` | u32 | `ldr w9,[x19,#0x78]` | `0x4a8` |
| `0x7c` | **u32** | **`newHeaderSize`** — `ldr w25,[x19,#0x7c]` @ `0xfffffff009019484`; `ldr w26,[x19,#0x7c]` @ `0xfffffff00901a498` | `0x4a0` |
| `0x80` | u32 | `ldr w9,[x19,#0x80]` | `0x4a4` |
| `0x84` | byte[] | **`newHeader` / `partialDecodeFakeHeader` payload** — source pointer built as `add x23, x19, #0x84` @ `0xfffffff009019620` | copied to heap vector |

### 1.3 `…IOStruct2024` — additional fields (used by `startDecoder2024` / `startEncoder2024`)

Same as §1.2 up to `0x84`, plus:

| off | width | evidence | req→ |
|---|---|---|---|
| `0xc84` (`arg2[0x321]`) | u32 | `x21_1[0x8d] = arg2[0x321]` | `0x468` |
| `0xcac` (`arg2[0x32b]`) | u32 | `*(x21_1 + 0xc4) = arg2[0x32b]` | `0x620` |

plus `startEncoder2024` reads `arg2[0x57]` (byte `0x15c`) as a 1-bit flag → `req+0x500`
(`ldrb w8, [x19, #0xdc]` in `startEncoderExt`, i.e. the Ext variant reads the *same semantic flag*
from `0xdc` while 2024 reads it from `0x15c`).

### 1.4 Derived struct sizes (strong, arithmetic — see §4.2)

* **Ext:** capacity constant `0x3df` elements × 4 B = **`0xf7c`**, and `0x84 + 0xf7c = 0x1000` =
  `MARKERRAM_MEM_SIZE`. ⇒ `AppleJPEGDriverIOStructExt` is **exactly 0x1000 bytes**, with
  `newHeader[0xf7c]` at offset `0x84`.
* **2024:** `0x300` × 4 = `0xc00`, `0x84 + 0xc00 = 0xc84`, and the *next* field is at `0xc84`. ⇒
  `AppleJPEGDriverIOStruct2024` has `newHeader[0xc00]` at `0x84`, then trailing fields from
  `0xc84`; total ≥ `0xcb0`.
* **Base (old):** highest field read is `0x54` ⇒ ≥ `0x58`.

---

## 2. Six-method validation matrix

| # | Check (controlling input) | startDecoder | startDecoderExt | startEncoder | startEncoderExt | startDecoder2024 | startEncoder2024 |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|
| 1 | `arg2 != NULL` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| 2 | quality `(0x1c & 0xfffe) >= 0xa` → reject | n/a | n/a | **✔** | **✔** | n/a | **✔** |
| 3 | `inputSize (0x04) > 0xff` | ✘ | ✘ | **✘** | **✔** | ✘ | **✔** |
| 4 | `outputSize (0x0c) >= 7` | ✘ | ✘ | **✘** | **✔** | ✘ | **✔** |
| 5 | `Horz (0x14) >= 4` | ✘ | ✘ | **✘** | **✔** | ✘ | **✔** |
| 6 | `Horz (0x14) < 0x10000` (`lsr #0x10` zero) | ✘ | ✘ | **✘** | **✔** | ✘ | **✔** |
| 7 | `Vert (0x18)` in `[2, 0xffff]` | ✘ | ✘ | **✘** | **✔** | ✘ | **✔** |
| 8 | `newHeaderSize <= 0x1000` | n/a | **✔** | n/a | n/a | **✔** | n/a |
| 9 | `newHeaderSize % 12 == 0` | n/a | **✔** | n/a | n/a | **✔** | n/a |
| 10 | `elementCount <= cap` (`0x3df` / `0x300`) | n/a | **✔** | n/a | n/a | **✔** | n/a |
| 11 | subsampling `0x2c` sane (`>4` → logged + defaults) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| 12 | `inputSize`/`outputSize`/dimensions re-checked vs IOSurface | ✔* | ✔* | ✔* | ✔* | ✔* | ✔* |

\* = not in the method itself but in `RequestHandling::decodeRequestValidation`
(`sub_fffffff00903acec`) / `…encodeRequestValidation` (`sub_fffffff00903b24c`), reached from
`queue_io_gated` for **all** variants (§3.3).

### 2.1 Quoted checks

**Check 2 — encoder-only quality gate (all three encoders, identical):**
```
startEncoder     0xfffffff009019b54  ldr w8, [x19, #0x1c]
                 0xfffffff009019b58  and w9, w8, #0xfffe
                 0xfffffff009019b5c  cmp w9, #0xa
                 0xfffffff009019b60  b.lo   0xfffffff009019bc0      ; <-- straight to alloc

startEncoderExt  0xfffffff009019f74  cmp w9, #0xa
                 0xfffffff009019f78  b.lo   0xfffffff009019fd8      ; <-- falls into size checks

startEncoder2024 0xfffffff00901aa70  ldr w8, [x19, #0x1c]
                 0xfffffff00901aa74  and w9, w8, #0xfffe
                 0xfffffff00901aa78  cmp w9, #0xa
                 0xfffffff00901aa7c  b.lo   0xfffffff00901aadc      ; <-- falls into size checks
```

**Checks 3–7 — the block `startEncoder` does not have.** Verbatim from `startEncoderExt`
(`0xfffffff009019fd8`–`0xfffffff00901a0c0`):
```
0xfffffff009019fd8  ldr  w8, [x19, #0x4]          ; inputSize
0xfffffff009019fdc  ldr  w9, [x19, #0xc]          ; outputSize
0xfffffff009019fe0  cmp  w8, #0xff
0xfffffff009019fe4  b.hi 0xfffffff00901a094       ; require inputSize > 0xff
            ; else -> "i/o sizes are illegal (inputSize %d, req->outputSize %d)! or
            ;          Horz (%d) and Vert (%d) Resolutions are not set"   (0xfffffff0075414b0)
0xfffffff00901a094  ldr  w10, [x19, #0x14]        ; Horz
0xfffffff00901a098  cmp  w9, #0x7
0xfffffff00901a09c  b.lo 0xfffffff009019fec       ; require outputSize >= 7
0xfffffff00901a0a0  cmp  w10, #0x4
0xfffffff00901a0a4  b.lo 0xfffffff009019fec       ; require Horz >= 4
0xfffffff00901a0a8  lsr  w11, w10, #0x10
0xfffffff00901a0ac  cbnz w11, 0xfffffff009019fec  ; require Horz < 0x10000
0xfffffff00901a0b0  ldr  w11, [x19, #0x18]        ; Vert
0xfffffff00901a0b4  sub  w11, w11, #0x10, lsl #0xc      ; w11 -= 0x10000
0xfffffff00901a0b8  mov  w12, #0xffff0001
0xfffffff00901a0bc  cmp  w11, w12
0xfffffff00901a0c0  b.ls 0xfffffff009019fec       ; require (Vert-0x10000) > 0xffff0001
```
`startEncoder2024` contains the **same block** at
`0xfffffff00901aadc`(`ldr w8,[x19,#0x4]`) / `0xfffffff00901aae0`(`ldr w9,[x19,#0xc]`) /
`0xfffffff00901aae4`(`cmp w8,#0xff`) / `0xfffffff00901ab98`(`cmp w9,#0x7`) /
`0xfffffff00901aba0`(`cmp w10,#0x4`), with the same string at `0xfffffff007541797`.

**`startEncoder` has none of these.** After `b.lo 0xfffffff009019bc0` the very next instruction is
`bl sub_fffffff00903c588` (request allocation) and then unconditional field copies
(`0xfffffff009019c18 ldp w8,w9,[x19]`, `0xfffffff009019c44 ldp w2,w3,[x19,#0x14]`).
`0x04`, `0x0c`, `0x14`, `0x18` are copied into the request **with no bounds test of any kind**.

**Checks 8–10 — `newHeaderSize` (decoder Ext/2024 only).**
```
startDecoderExt   0xfffffff009019484  ldr  w25, [x19, #0x7c]
                  0xfffffff009019488  str  w25, [x21, #0x4a0]
                  0xfffffff0090194ac  cmp  w25, #0x1, lsl #0xc      ; 0x1000
                  0xfffffff0090194b0  b.ls 0xfffffff00901951c       ; else "…exceeds MARKERRAM_MEM_SIZE %u"
                  0xfffffff00901951c  and  w9, w25, #0xffff
                  0xfffffff009019528  mul  w9, w9, w10              ; w10 = 0xaaaaaaab
                  0xfffffff00901952c  ror  w9, w9, #0x2
                  0xfffffff009019538  cmp  w9, w10                  ; w10 = 0x15555556
                  0xfffffff00901953c  b.lo 0xfffffff009019568        ; divisibility-by-12 gate
                  0xfffffff009019568  lsr  x1, x25, #0x2             ; elementCount
                  0xfffffff00901956c  cmp  w25, #0xf7f
                  0xfffffff009019570  b.ls 0xfffffff009019620        ; cap 0x3df elements

startDecoder2024  identical shape at
                  0xfffffff00901a498  ldr  w26, [x19, #0x7c]
                  0xfffffff00901a4c0  cmp  w26, #0x1, lsl #0xc
                  0xfffffff00901a530  … mul/ror/cmp (same magic) …
                  0xfffffff00901a57c  lsr  x1, x26, #0x2
                  0xfffffff00901a580  cmp  w26, #0xc03               ; cap 0x300 elements
```

The copy itself (Ext; 2024 identical modulo registers/cap):
```
0xfffffff009019620  add  x23, x19, #0x84      ; src = input struct + 0x84
0xfffffff009019628  add  x0, x21, #0x4d8
0xfffffff00901962c  bl   sub_fffffff009019954 ; std::vector<int32_t>::resize(elementCount)
0xfffffff009019630  ldr  x24, [x21, #0x4d8]   ; begin
0xfffffff009019634  ldr  x26, [x21, #0x4e8]   ; end
0xfffffff009019638  and  w25, w25, #0xffc     ; n = newHeaderSize & 0xffc
0xfffffff009019648  bl   sub_fffffff00903cb08 ; memcpy(begin, src, n)
0xfffffff00901964c  sub  x8, x26, x24
0xfffffff009019650  cmp  x8, x25
0xfffffff009019654  b.ge 0xfffffff009019668
0xfffffff009019658  brk  #0x800               ; hardening trap
```
When the `0x30` low-64 field is zero the copy is skipped and the driver aliases the *caller's struct*
directly: `0xfffffff00901965c str x23, [x21, #0x4c8]` / `0xfffffff009019660 mov w8, #0x3df` /
`0xfffffff009019664 str x8, [x21, #0x4d0]` (2024: `0x300`).

---

## 3. Candidates, ranked

### C1 — `startEncoder` (old) bypasses the entire i/o-size / resolution gate · **STRONG**

* **Function / address:** `sub_fffffff009019ad0` (`startDecoder`'s sibling), decision point
  `0xfffffff009019b60 b.lo 0xfffffff009019bc0`.
* **Exact reads (unvalidated, 32-bit each):**
  `0xfffffff009019c18 ldp w8,w9,[x19]` → `w9` = `[0x04]` inputSize → `str w9,[x22,#0x420]`
  `0xfffffff009019c20 ldp w8,w10,[x19,#0x8]` → `w10` = `[0x0c]` outputSize → `str w10,[x22,#0x424]`
  `0xfffffff009019c44 ldp w2,w3,[x19,#0x14]` → Horz → `0x428`, Vert → `0x42c`
* **Controlling input:** userspace bytes at struct offsets `0x04, 0x0c, 0x14, 0x18`.
* **Consequence:** `startEncoder` is the **only** one of the three encoder variants that reaches
  `queue_io_gated` with fully attacker-controlled `inputSize`/`outputSize`/`Horz`/`Vert`.
  This is exactly the shape the brief predicts ("if one variant validates a field and another does
  not, that is almost certainly the bug the 0x784-byte change relates to"): the two newer siblings
  implement the identical gate byte-for-byte, the oldest does not, and the oldest is still
  reachable through two live trampolines.
* **Why not PROVEN:** I could not finish proving that `req+0x420`/`0x424` (input JPEG size / output
  buffer size) drive an allocation or a DMA length downstream. `encodeRequestValidation`
  (`sub_fffffff00903b24c`) does bound `0x428`/`0x42c` (pixelsX/pixelsY) against the destination
  IOSurface's real width/height (`sub_fffffff00903c938`, `sub_fffffff00903c968`), which mitigates the
  *dimension* half of C1. The `inputSize`/`outputSize` consumer (§"next step") is unresolved.
  Until that consumer is traced the practical impact is unproven.

### C2 — `newHeader` copy: out-of-bounds read past the input struct · **REFUTED (arithmetic)**

* Reads up to `(newHeaderSize & 0xffc)` bytes from `input+0x84`.
* Bounded by three gates (§2.1 checks 8–10): `newHeaderSize ≤ 0x1000`, `≡ 0 (mod 12)`,
  `newHeaderSize ≤ 0xf7f` (Ext) / `≤ 0xc03` (2024). Max copy = `0xf7c` (Ext) / `0xc00` (2024).
* `0x84 + 0xf7c = 0x1000` = `MARKERRAM_MEM_SIZE` = the Ext struct size derived independently in
  §1.4; `0x84 + 0xc00 = 0xc84` = exactly where the 2024 struct's next field begins.
* The caps are *derived from the array extents*, not arbitrary, and the destination vector is
  resized to `size>>2` elements *before* the copy, with a `brk #0x800` hardening check after.
  ⇒ No write overflow, and no read overflow **provided the caller supplied a full-size struct**.
  Marked REFUTED for the "unchecked size field" theory.

### C3 — aliasing the caller's struct as the fake-header array · **SPECULATIVE**

* `0xfffffff00901965c str x23,[x21,#0x4c8]` (ptr = `input+0x84`) with
  `0xfffffff009019664 str x8,[x21,#0x4d0]` (count = `0x3df`, resp. `0x300`), taken when the `0x30`
  field is NULL.
* The count is the **maximum** capacity, not `newHeaderSize>>2`. A caller can set
  `newHeaderSize = 12` and have the driver treat 991 (`0x3df`) marker elements as valid.
* Contained by the struct's real extent (`0x84 + 0xf7c = 0x1000`), and the whole `0x1000` bytes are
  caller-supplied, so this is **not** an info leak. It is a data-integrity issue (stale / attacker
  bytes parsed as JPEG markers) unless a consumer trusts `0x4d0` as a *proven* element count.
  Needs consumer tracing; low severity.

### C4 — integer width on dimension products · **SPECULATIVE (likely benign)**

* `decodeRequestValidation`: `x22 * x21` (pixelsX × pixelsY) — both operands are **32-bit**
  (`ldr w21,[x1,#0x428]` @ `0xfffffff00903ad1c`), and both are pre-clamped (`< 0x10000`), so the
  product is `≤ 0xFFFE0001` — no 32-bit overflow. **Clean negative.**
* `queue_io_gated` (`sub_fffffff009018c0c`): `int64_t x8_8 = x26_1 * x25_1 * x27_1;` stored to
  `arg2[0x8e]` — decompiler types this 64-bit; the instruction width was **not** confirmed in
  disassembly. It feeds workload accounting (`*x8_16 -= x10_14`), not an allocation, so even a
  32-bit truncation is not obviously exploitable. Flagged for width confirmation only.

### C5 — raw userspace pointer used as a kernel pointer · **REFUTED in the six methods**

* No field of the IOStruct is dereferenced as a kernel pointer inside the six methods. Every field
  is a scalar copied into the `JpegRequest`, and the one 16-byte field at `0x30` is only
  *tested* (`cbz`) or copied to `req+0x10`, never dereferenced in these functions.
* The real buffers are **IOSurfaces** held at `req+0x2b8` / `req+0x2c0` and are queried through
  IOSurface accessors (`sub_fffffff00903c938`, `…03c968`, `…03c908`, `…03c8f8`) in
  `encodeRequestValidation` / `decodeRequestValidation`. The driver does not translate a
  userspace virtual address by hand on this path.

### C6 — old-struct handler reachable with a new-sized struct (and vice versa) · **BLOCKED**

* Struct sizes differ: base ≥ `0x58`, 2024 ≈ `0xcb0`, Ext = `0x1000`. The 2024 handler reads
  `0xc84`/`0xcac`, which lie *inside* a 2024 struct but are **outside** the region an Ext struct
  guarantees only if the Ext struct is < `0xcb0` — it is not, so 2024-on-Ext is safe.
  Conversely an Ext handler fed a 2024-sized (`0xcb0`) input would read `0x84 + up to 0xf7c =
  0x1080` — `0x3d0` bytes past the end — *if* `newHeaderSize` were allowed near max.
* **What is missing:** the `IOExternalMethodDispatch` table's `checkStructureInputSize` for each
  selector. I could not read it: `bn_data_xrefs_to` returns empty (documented limitation) and the
  vtable/table pointers in `__const#10` (`0xfffffff0080767c8..0xfffffff00807b5b8`) are
  arm64e chained-fixup / PAC-encoded, so they do not decode to plain addresses by inspection.
  **This is the single open question that decides C2/C6 and should be resolved by finding the
  six-entry table and reading the 4-byte field at `entry+0xc`.**

---

## 4. Summary of confidence

| candidate | confidence |
|---|---|
| C1 — `startEncoder` skips the i/o-size + resolution gate that `startEncoderExt`/`startEncoder2024` both enforce | **STRONG** (divergence proven; impact unproven) |
| C2 — `newHeader` OOB read/write | **REFUTED** (caps derived from array extents; sizes line up exactly) |
| C3 — fake-header aliased with max capacity, not actual size | **SPECULATIVE** (integrity, not memory safety) |
| C4 — dimension product overflow | **SPECULATIVE / likely benign** (32-bit, pre-clamped — clean negative) |
| C5 — raw userspace pointer as kernel pointer | **REFUTED** (IOSurface-backed; no manual translation on this path) |
| C6 — struct-size/version mismatch across variants | **BLOCKED** — needs the `IOExternalMethodDispatch` table |

## 5. Honest negatives

* The `newHeaderSize` parser is **not** vulnerable to an oversized-length copy; the three gates are
  correct and self-consistent with the struct geometry.
* No userspace address in the IOStruct is used directly as a kernel pointer in any of the six
  methods.
* No untrusted-count loop with an unbounded trip count was found in the six methods: the only
  loops are the fixed 0x40-iteration Huffman/quant-table copies in `startEncoderExt` /
  `startEncoder2024` (`0xfffffff00901a240`, `mov w13, #0x40`) and the fixed `0x10`-iteration loop in
  `sub_fffffff0090232d8`.
* The user client's other entry points (`sub_fffffff0090231bc` / `sub_fffffff0090232d8`,
  `jpeg_huffman_set` / `jpeg_qtbl_set`) *do* copy attacker-controlled lengths
  (`while (arg4) { … }`, `while (arg6) { … }`) into fixed regions, bounded only by `0x10` /
  `0xa2` / `0xc` iteration counters — outside the assigned scope but worth a separate look.

## 6. Next step to close C1 / C6

1. Locate the six-entry `IOExternalMethodDispatch` table (24-byte stride:
   `func(8), checkScalarInputCount(4), checkStructureInputSize(4), checkScalarOutputCount(4),
   checkStructureOutputSize(4)`) and read `checkStructureInputSize` per selector. If any selector's
   size is smaller than the struct its handler parses, C6 becomes PROVEN.
2. Find the consumer of `req+0x420` / `req+0x424` (inputSize / outputSize) — grep
   `sub_fffffff00903b6c8` and `sub_fffffff00903bcd8` (the encode/decode *request setup* halves) for
   `[x, #0x420]` / `[x, #0x424]`. That decides whether C1 is a real OOB or merely a
   defense-in-depth gap.
