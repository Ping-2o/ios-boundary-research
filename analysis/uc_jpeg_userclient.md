> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# `AppleJPEGDriverUserClient` — external method table, entitlement gate, struct versioning

**Target:** `com.apple.driver.AppleJPEGDriver`, iOS 27.0 RC (24A435), iPhone17,5
**Tooling:** `otool -v -s __TEXT_EXEC __text` (+ `otool -s __DATA_CONST __const`) only. No Binary Ninja.
**Method discipline:** every width and every size constant below is quoted from disassembly /
raw section bytes, not from pseudo-C.

## 0. Pointer decoding (validated, do not skip)

`__DATA_CONST __const` stores arm64e chained-fixup / PAC-encoded pointers. The decode that
validates against real code is:

```
target = 0xfffffff007004000 + (raw_u64 & 0xFFFFFFFF)
```

Validation: dispatch-table entry 1 at `0xfffffff008078888` is raw `a4ed 0102 adbc 5080`
→ `0x0201eda4` → `0xfffffff009022da4`, which is exactly `bti c` / `mov x4, x0`, a real
function start (`0xfffffff00902eda4` is mid-instruction garbage). Same base reproduces the
vtable written by the constructor (`0xfffffff0080781f0`, installed as `vtable+0x10` at
`0xfffffff009022c38`).

Section bases: `__TEXT_EXEC __text = 0xfffffff00900ebb0`, `__DATA_CONST __const =
0xfffffff0080767c8..0xfffffff00807b5b8`, `__TEXT __cstring = 0xfffffff00753bb98`.

---

## 1. Entitlement gate — **NO GATE on user-client creation; partial gate on 2 of 10 selectors**

### 1.1 `AppleJPEGDriver::newUserClient` = `0xfffffff009015ecc`

The only test before constructing the client is a **client-count** test:

```
fffffff009015f48  ldp  x8, x10, [x23, #0x120]
fffffff009015f4c  sub  x9, x8, x10
fffffff009015f50  cmp  x9, #0x3e9
fffffff009015f54  b.lt 0xfffffff009015f90      ; < 1001 -> create
fffffff009015f58  ... log ...
fffffff009015f88  add  w20, w20, #0x2          ; else kIOReturnBusy-ish
fffffff009015f90  mov  x0, x23 ; mov x1, x19 ; mov x2, x25 ; mov x3, x24 ; mov x4, x22
fffffff009015fa4  bl   0xfffffff009022be0      ; alloc + initWithTask
```

There is **no `IOTaskHasEntitlement` / `copyClientEntitlement` call and no branch to a
failure return based on an entitlement** anywhere between `0xfffffff009015ecc` and
`0xfffffff009016138`. That is the whole function.

### 1.2 `AppleJPEGDriverUserClient::initWithTask` = `0xfffffff009022834`

Evaluates two entitlements — and only *records* them:

```
fffffff00902286c  adrp x1, -6885 ; 0xfffffff00753d000
fffffff009022870  add  x1, x1, #0x8be          ; "com.apple.applejpegdriver.poweron"
fffffff009022874  mov  x0, x2
fffffff009022878  bl   0xfffffff00903c698      ; IOTaskHasEntitlement(task, "…poweron")
fffffff009022884  cbz  x0, 0xfffffff0090228b8
fffffff009022898  strb w8, [x19, #0x108]       ; <-- STORE, no branch
...
fffffff0090228bc  add  x1, x1, #0x8e0          ; "com.apple.applejpegdriver.ajpegtestapp"
fffffff0090228c4  bl   0xfffffff00903c698
fffffff0090228dc  strb w8, [x19, #0x109]       ; <-- STORE, no branch
fffffff009022930  blraa x8, x16                ; super::initWithTask(...)  vt+0x550
```

`0xfffffff00903c698` is an `__auth_stubs` import whose result is compared against a
canonical object and then `release`d through `vtable+0x28` — the `IOTaskHasEntitlement`
shape exactly. Return value of `initWithTask` is super's; **a client with neither
entitlement is still created and attached**.

### 1.3 Where the recorded bits are actually consumed

* `this+0x108` (`poweron`) is read as a **gate** in exactly two dispatch-table handlers:
  `0xfffffff009022ef8` (selector 8) and `0xfffffff009022f28` (selector 9), both
  `ldrb w8, [x1, #0x108]` / `tbz w8, #0x0, <return 0xe00002bc>`.
* `this+0x109` (`ajpegtestapp`) is **not a gate anywhere**. It is copied as a 1-bit feature
  flag: `0xfffffff00901a6b4` (`startDecoder2024`) and `0xfffffff00901ac94`
  (`startEncoder2024`) → `strb w8, [x22, #0xc8]`.
* The `externalMethod` override (§2) does **not** read either bit.

**Verdict: entitlement is NOT a gate on opening the client, nor on selectors 0–7.**
Selectors 8 and 9 are gated on `com.apple.applejpegdriver.poweron`.

---

## 2. External method table — **one table, 10 selectors, all sizes FIXED**

Only one `IOExternalMethodDispatch`-shaped run exists in either const section
(stride `0x28`; the scan over `__DATA_CONST __const` *and* `__TEXT __const` at strides
0x18/0x20/0x28/0x30/0x38/0x40 found exactly one, length 10):

**`0xfffffff008078860` .. `0xfffffff0080789f0`**, all function pointers with diversity
`0x8050bcad`. Layout verified from raw bytes: `fn@+0`, `checkScalarInputCount@+8`,
`checkStructureInputSize@+0xc`, `checkScalarOutputCount@+0x10`,
`checkStructureOutputSize@+0x14`, `flags@+0x18`.

| sel | entry | handler | scalarIn | **structIn** | scalarOut | **structOut** | flags | reaches |
|----:|---|---|---:|---:|---:|---:|---:|---|
| 0 | `0x…80878860` | `0xfffffff009022d98` | 0 | **0** | 0 | **0** | 0 | `0x01717c` (ignores args) |
| 1 | `0x…80878888` | `0xfffffff009022da4` | 0 | **0x58** | 0 | **0x58** | 0 | `startDecoder` `0x018830` |
| 2 | `0x…808788b0` | `0xfffffff009022dd8` | 0 | **0** | 0 | **0** | 0 | `0x017188` (ignores args) |
| 3 | `0x…808788d8` | `0xfffffff009022de4` | 0 | **0x58** | 0 | **0x58** | 0 | `startEncoder` `0x019ad0` |
| 4 | `0x…80878900` | `0xfffffff009022e18` | 0 | **0x1000** | 0 | **0x1000** | 0 | `startEncoderExt` `0x019ee4` |
| 5 | `0x…80878928` | `0xfffffff009022e4c` | 0 | **0x1000** | 0 | **0x1000** | 0 | `startDecoderExt` `0x019334` |
| 6 | `0x…80878950` | `0xfffffff009022e80` | 0 | **0xda0** | 0 | **0xda0** | 1 | `startEncoder2024` `0x01a9e8` |
| 7 | `0x…80878978` | `0xfffffff009022eb4` | 0 | **0xda0** | 0 | **0xda0** | 1 | `startDecoder2024` `0x01a348` |
| 8 | `0x…808789a0` | `0xfffffff009022ee8` | 0 | **0x4** | 0 | **0** | 0 | `0x0165e4` — **poweron-gated** |
| 9 | `0x…808789c8` | `0xfffffff009022f18` | 0 | **0** | 0 | **0** | 0 | `0x01667c` — **poweron-gated** |

Raw bytes for two representative entries (proves the fields):

```
fffffff0080788d8  e4 ed 01 02 ad bc 50 80  00 00 00 00 58 00 00 00   ; sel3: fn, sIn=0, stIn=0x58
fffffff0080788e8  00 00 00 00 58 00 00 00  00 00 00 00 00 00 00 00   ;        sOut=0, stOut=0x58
fffffff008078950  80 ee 01 02 ad bc 50 80  00 00 00 00 a0 0d 00 00   ; sel6: stIn=0xda0
fffffff008078960  00 00 00 00 a0 0d 00 00  01 00 00 00 00 00 00 00   ;        stOut=0xda0, flags=1
```

**IMPORTANT CORRECTION to the earlier note `jpeg_userclient.md`:** `structIn == 0` is
**not** `kIOUCVariableStructureSize`. That constant is `0xFFFFFFFF`. A `0` field is a
*fixed* size of zero — IOKit rejects any call whose `structureInputSize != 0`. This is
internally consistent: the size-0 handlers (`0x022d98`, `0x022dd8`, `0x022f18`) never
dereference `args`. **No selector in this table has `0xFFFFFFFF` in any size field.**

The dispatcher is vtable slot 184 (`vt+0x5d0`) = `0xfffffff009022f40`:

```
fffffff009022f44  adrp x3, -4010 ; 0xfffffff008078000
fffffff009022f48  add  x3, x3, #0x860       ; the 10-entry table
fffffff009022f4c  mov  w4, #0xa             ; count = 10  -> selector bounds check
fffffff009022f50  mov  x5, x0               ; target = this
fffffff009022f54  mov  x6, #0x0             ; reference = NULL
fffffff009022f58  b    0xfffffff00903c768   ; tailcall to IOKit's external-method dispatcher
```

Slot 185 (`vt+0x5d8`) is `initWithTask`; slot 173 (`vt+0x578`) is `registerNotificationPort`.
Slot 170/171 = `clientClose`/`clientDied` (`0x022cf4`/`0x022d64`), which is the ordering
anchor that pins 184 as `externalMethod`.

---

## 3. Struct versioning — **REFUTED: IOKit pins each variant's size; no cross-feeding**

The three generations are sized by the table itself:

| struct | enforced `structureInputSize` | highest field the handler reads | head-room |
|---|---|---|---|
| `…IOStruct` (base) | **0x58** | `0x54` | ok |
| `…IOStruct2024` | **0xda0** | `0xcac` (`0xfffffff00901a6ac`) | ok |
| `…IOStructExt` | **0x1000** | `0x84 + 0xf7c = 0x1000` | ok |

Because `checkStructureInputSize` is an *equality* test against the caller's
`structureInputSize`:

* You **cannot** hand an 88-byte base struct to selector 4/5 (Ext) — IOKit returns
  `kIOReturnBadArgument` before the handler runs.
* You **cannot** hand a 0x1000-byte Ext struct to selector 1/3 (base).
* You **cannot** hand a 0xda0 2024 struct to the Ext handlers.

So the `newHeader` copy is bounded on both ends: `startDecoderExt` caps
`newHeaderSize` at `0x1000`, requires `% 12 == 0`, and caps the element count at
`0x3df` (`0xfffffff00901956c cmp w25, #0xf7f`), then copies `newHeaderSize & 0xffc`
bytes from `input+0x84` (`0xfffffff009019620 add x23, x19, #0x84`) into a vector
pre-resized to `size>>2`. `0x84 + 0xf7c = 0x1000` exactly. `startDecoder2024` is the
same shape with cap `0x300` / `0xc03` (`0xfffffff00901a580 cmp w26, #0xc03`).

### 3.1 The one real divergence: `startEncoder` skips the gate its siblings have

`startEncoderExt` (`0xfffffff009019ee4`) enforces five checks:

```
fffffff009019fd8  ldr  w8,  [x19, #0x4]        ; inputSize
fffffff009019fdc  ldr  w9,  [x19, #0xc]        ; outputSize
fffffff009019fe0  cmp  w8,  #0xff
fffffff009019fe4  b.hi 0xfffffff00901a094      ; require inputSize > 0xff
fffffff00901a094  ldr  w10, [x19, #0x14]       ; Horz
fffffff00901a098  cmp  w9,  #0x7
fffffff00901a09c  b.lo 0xfffffff009019fec      ; require outputSize >= 7
fffffff00901a0a0  cmp  w10, #0x4
fffffff00901a0a4  b.lo 0xfffffff009019fec      ; require Horz >= 4
fffffff00901a0a8  lsr  w11, w10, #16
fffffff00901a0ac  cbnz w11, 0xfffffff009019fec ; require Horz < 0x10000
fffffff00901a0b0  ldr  w11, [x19, #0x18]       ; Vert
fffffff00901a0b4  sub  w11, w11, #0x10, lsl #12
fffffff00901a0b8  mov  w12, #-0xffff
fffffff00901a0bc  cmp  w11, w12
fffffff00901a0c0  b.ls 0xfffffff009019fec      ; require 2 <= Vert <= 0xffff
```

`startEncoder2024` has the identical block (`0xfffffff00901aae4`, `0x01ab9c`, `0x01aba4`,
`0x01abc0`). **`startEncoder` has none of it.** A full listing of every `cmp wN` in
`0xfffffff009019ad0..0x019ee4` yields only `cmp w9, #0xa` (quality, at
`0xfffffff009019b5c`) plus the subsampling switch (`cmp w9, #1/#2/#3/#4`). It then
copies the fields unchecked:

```
fffffff009019b5c  cmp  w9, #0xa
fffffff009019b60  b.lo 0xfffffff009019bc0      ; <-- the ONLY validation branch
fffffff009019bc8  bl   0xfffffff00903c588      ; straight to allocation
fffffff009019c18  ldp  w8, w9,  [x19]
fffffff009019c3c  str  w9,  [x22, #0x420]      ; inputSize   (32-bit)
fffffff009019c20  ldp  w8, w10, [x19, #0x8]
fffffff009019c40  str  w10, [x22, #0x424]      ; outputSize  (32-bit)
fffffff009019c44  ldp  w2, w3,  [x19, #0x14]
fffffff009019c48  str  w2,  [x22, #0x428]      ; Horz        (32-bit)
fffffff009019c4c  str  w3,  [x22, #0x42c]      ; Vert        (32-bit)
```

Widths confirmed: all `w` registers, all `str w`.

### 3.2 …but the downstream validator closes it

`queue_io_gated` dispatches on `req+0x2a8` (`startEncoder` sets it to 1 at
`0xfffffff009019c10`):

```
fffffff00903acd8  ldr  w8, [x1, #0x2a8]
fffffff00903ace0  cbz  w8, 0xfffffff00903ace8
fffffff00903ace4  b    0xfffffff00903b24c      ; encodeRequestValidation
```

and `RequestHandling::encodeRequestValidation` (`0xfffffff00903b24c`) re-imposes exactly
the omitted bounds against the real IOSurface:

```
fffffff00903b294  ldr  w20, [x19, #0x428]      ; Horz
fffffff00903b2a0  bl   0xfffffff00903c938      ; surface width
fffffff00903b2a4  cmp  w20, w0
fffffff00903b2a8  b.hi 0xfffffff00903b2e4      ; Horz <= surfaceWidth  (error)
fffffff00903b2cc  ldr  w20, [x19, #0x42c]      ; Vert
fffffff00903b2d8  bl   0xfffffff00903c968      ; surface height
fffffff00903b2dc  cmp  w20, w0
fffffff00903b2e0  b.ls 0xfffffff00903b35c      ; Vert <= surfaceHeight
fffffff00903b3b4  ldr  w8,  [x19, #0x428]
fffffff00903b3c0  lsr  w9, w8, #16
fffffff00903b3c4  cbnz w9, 0xfffffff00903b370  ; Horz < 0x10000 (error)
fffffff00903b3c8  cmp  w8, #0x4
fffffff00903b3cc  b.lo 0xfffffff00903b370      ; Horz >= 4     (error)
fffffff00903b3d0  ldr  w9,  [x19, #0x42c]
fffffff00903b3d4  sub  w9, w9, #0x10, lsl #12
fffffff00903b3d8  mov  w10, #-0xffff
fffffff00903b3dc  cmp  w9, w10
fffffff00903b3e0  b.ls 0xfffffff00903b370      ; 2 <= Vert <= 0xffff (error)
```

And `req+0x420`/`0x424` (inputSize / outputSize) have **no functional consumer at all** —
the only two reads in the entire kext are `0xfffffff00903afa0` and `0xfffffff00901b208`,
both of which feed an `snprintf`-class call (`bl 0xfffffff00903cb28`) for a log line.

---

## 4. `registerNotificationPort(mach_port_t, UInt32, UInt32)` — **REFUTED**

```
fffffff009022f5c  ldr  x9, [x0, #0xf0]
fffffff009022f64  cbz  x9, 0xfffffff009022fbc   ; only if no port is registered
        ... log "Client active, cannot switch port" ...  return 0xe00002bc
fffffff009022fbc  mov  x8, x0
fffffff009022fc0  mov  w0, #0x0
fffffff009022fc4  str  x1, [x8, #0xf0]          ; port
fffffff009022fc8  str  w3, [x8, #0xf8]          ; refCon
fffffff009022fcc  ret
```

* `w2` (the `type` UInt32) is **never read** — it is discarded.
* `w3` (refCon) is only stored; no consumer uses it as an index anywhere.
* No TOCTOU: re-registration is blocked by the `cbz` on `+0xf0`.
* Port rights are consumed by IOKit before the override runs.

---

## 5. Userspace indices into internal arrays — **none without a bounds compare**

* **subsampling (`struct+0x2c`)** — `getMCUSize` `0xfffffff009018680` bounds it first:
  `cmp w1, #0x5 ; b.hs 0xfffffff0090186fc`, then indexes two 5-entry tables at
  `0xfffffff007548a58` / `0x548a6c` with `ubfiz x9, x1, #2, #32` and a hardened
  `csel x10, x10, x16, eq` (ptrauth'd decoy on mismatch). Out-of-range → log + defaults.
* **`newHeaderSize`** — three gates (§3).
* **2024 trailing fields** — plain scalar copies (`0xfffffff00901a6ac ldr w8, [x19, #0xcac]`),
  all inside the enforced 0xda0 window.
* No `lsl #2/#3` + unchecked base-from-struct pattern was found in any of the six handlers.

### 5.1 `getMCUSize` 32-bit multiply — arithmetic real, impact closed

```
fffffff009018768  lsr  w8, w10, w8
fffffff00901876c  mul  w8, w9, w8      ; *** w-register: genuine 32-bit multiply ***
fffffff009018770  str  w8, [x19]       ; stored 32-bit
```

The multiplication is genuinely 32-bit and unchecked. But it is called only from the three
encoders (`0xfffffff009019c7c`, `0x01a194`, `0x01acb4`), its result (`req+0x464`) is read
exactly once, at `0xfffffff00903bf4c` → `str w8, [x19, #0x224]`, i.e. **after**
`encodeRequestValidation` has already forced `Horz < 0x10000`, `Vert <= 0xffff`. With those
bounds `rows*cols <= 0x2000 * 0x800`, no wrap. Overflowing values are computed only on
requests that validation then rejects.

---

## 6. Dead code: the six "Family B" trampolines

`0xfffffff009023040`, `0x023068`, `0x023090`, `0x0230b8`, `0x0230e0`, `0x023108` call the
six `start*` methods with `(driver, p1, p2, client->port, client, client->task)` — the
`IOExternalTrap` shape. **They are unreachable in this build:**

* no fixup in `__DATA_CONST __const`, `__TEXT __const`, `__DATA __data`, `__kalloc_type`,
  `__mod_init_func` resolves to any address in `0x23040..0x2312c` (scanned for the low-32
  fixup pattern `0x0201f0xx..0x0201f2xx`);
* no `adrp`/`add` pair in `__TEXT_EXEC __text` materialises them;
* none of vtable slots 0–203 (full dump performed) points at them;
* `getExternalTrapForIndex` is not overridden (vtable slots 174–183 are all kernel,
  `0xfffffff00b3…`).

---

## 7. Verdicts

| # | Finding | Verdict |
|---|---|---|
| 1 | `newUserClient` has no entitlement gate — only `cmp x9, #0x3e9` on the client count | **PROVEN (negative)** |
| 2 | `initWithTask` evaluates `com.apple.applejpegdriver.poweron` / `.ajpegtestapp` but only stores them at `+0x108`/`+0x109`; super's result is returned unchanged | **PROVEN** |
| 3 | `externalMethod` (vt+0x5d0, `0x022f40`) performs **no** entitlement check | **PROVEN (negative)** |
| 4 | Selectors 8 and 9 are gated on `+0x108` (poweron); 0–7 are not | **PROVEN** |
| 5 | `startEncoder` omits the inputSize/outputSize/Horz/Vert gate that `startEncoderExt` and `startEncoder2024` both enforce | **PROVEN (divergence)** |
| 6 | …is a memory-safety bug | **REFUTED / CLEAN NEGATIVE** — Horz/Vert are re-bounded by `encodeRequestValidation` (`0x03b294`–`0x03b3e0`); `req+0x420/0x424` reach only a log call |
| 7 | 32-bit `mul w8` in `getMCUSize` overflows | **arithmetic PROVEN / impact REFUTED** — inputs bounded pre-consumption; consumer is `0x03bf4c` |
| 8 | Old/undersized struct can be fed to the Ext (or 2024) handler | **REFUTED** — `checkStructureInputSize` equality (0x58 / 0xda0 / 0x1000) is enforced by IOKit before dispatch |
| 9 | Any selector accepts variable-size input (`0xFFFFFFFF`) | **REFUTED** — no such field in the table; `0` means fixed-zero |
| 10 | `registerNotificationPort` type/refCon validated or used as index | **REFUTED** — `w2` discarded, `w3` only stored, re-registration blocked |
| 11 | `newHeaderSize` copy can over-read the input struct | **REFUTED** — three gates + 0x1000/0xda0 window + pre-resized vector + `brk #0x800` |
| 12 | Userspace index into an internal array without bounds compare | **REFUTED** — only subsampling, and it is `cmp w1, #0x5`-gated with a ptrauth decoy |
| 13 | Six `IOExternalTrap`-shaped trampolines at `0x023040..0x02312c` reachable | **REFUTED (dead code)** — no fixup, no code ref, no vtable slot |
| 14 | Plist-level `IOUserClientEntitlements` on the personality | **SPECULATIVE / UNRESOLVED** — the extracted kext has no `__info_plist` section; `IOUserClientEntitlements` is present in `__cstring` and read at `0xfffffff00902280c` (vtable slot 84, `0x022718`) but its result is discarded |

## 8. What this means for the sandbox change

The WebContent profile flipping `AppleJPEGDriverUserClient` from allow to deny is
consistent with a **live, unentitled** surface: `IOServiceOpen` on
`AppleJPEGDriverUserClient` succeeds for any task the sandbox lets through
(`newUserClient` checks only the client count), and selectors 0–7 — including all six
`startDecoder*` / `startEncoder*` entry points — run with **no entitlement check of any
kind**. I found no exploitable bug on those paths: the struct-version confusion the brief
hypothesises is closed by IOKit's own `checkStructureInputSize` equality check, and the one
genuine validation divergence (`startEncoder`) is closed downstream by
`encodeRequestValidation`. The remaining open question is #14 — a personality-level
`IOUserClientEntitlements` array, which cannot be read from this binary.
