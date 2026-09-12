> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# Face ID bracket-capture & configuration-key audit — `H16ISP.mediacapture` (iOS 27.0 RC, 24A435)

Scope: `H16ISPGraphExclaveAutoExposureNode::runFaceIDAEBracketCapture`, the
`kFigCaptureStreamProperty_CaptureSecureFaceIDBracket` property path, the
`…BracketKey_{NumberOfDoubles,DoubleOrder,ProbePatternIndex,ProbePatternType}` keys, and the
`…SecureFaceIDConfigurationKey_*` configuration keys.

Tooling: Binary Ninja (read-only). Every width/offset claim below is taken from
`bn_function_disassembly`, not from the decompiler — the decompiler demonstrably mis-scales
indices in **both** loops analysed here.

---

## 0. Helper identification (from call shape and argument use)

| stub | identity (inferred, consistent everywhere) |
|---|---|
| `0x250094550` | `CFGetTypeID` |
| `0x2500944f0` | `CFDictionaryGetTypeID` |
| `0x2500c5840` | `CFDictionaryGetValueIfPresent(dict, key, &out)` |
| `0x2500945b0` | `CFNumberGetValue(num, type, dst)` |
| `0x250094520` | `CFBooleanGetValue` |
| `0x250094380` | `CFArrayGetCount` |
| `0x2500943a0` | `CFArrayGetValueAtIndex(arr, idx)` |
| `0x250095300` | `bzero` / `memset(.., 0, ..)` (2 args) |
| `0x250094300` | `memcpy` |
| `0x2500e9af0` | Exclave IDL round-trip (send cmd, fill reply buffer) |

`CFNumberGetValue` type codes used in this dylib: `9` = `kCFNumberIntType` (4 bytes on arm64),
`0xC` = `kCFNumberFloatType` (4 bytes).

---

## 1. `runFaceIDAEBracketCapture` — the headline target

`0x24ebb8b98` … `0x24ebb8eb7`,
`int64_t H16ISP::H16ISPGraphExclaveAutoExposureNode::runFaceIDAEBracketCapture(this, uint32_t requestID)`

### 1.1 Frame layout (from the prologue)

```
0x24ebb8b98  pacibsp
0x24ebb8b9c  stp x24, x23, [sp, #-0x40]!      ; S-0x40
0x24ebb8ba0  stp x22, x21, [sp, #0x10]        ; S-0x30
0x24ebb8ba4  stp x20, x19, [sp, #0x20]        ; S-0x20
0x24ebb8ba8  stp fp, lr, [sp, #0x30]          ; S-0x10  <-- saved FP = S-0x10, LR = S-0x8
0x24ebb8bac  add fp, sp, #0x30
0x24ebb8bc4  sub sp, sp, #0x2, lsl #0xc       ; -0x2000
0x24ebb8bc8  sub sp, sp, #0xa0                ; -0xa0
```

Define `sp_w = S - 0x20A0`. Then saved regs are at:

| item | address |
|---|---|
| saved `x24/x23` | `sp_w + 0x20A0` |
| saved `x22/x21` | `sp_w + 0x20B0` |
| saved `x20/x19` | `sp_w + 0x20C0` |
| saved **FP** | `sp_w + 0x20D0` |
| saved **LR** | `sp_w + 0x20D8` |
| caller frame starts | `sp_w + 0x20E0` |

Frame = `0x20A0` bytes exactly, split into:
* `[sp_w+0x000, sp_w+0x470)` — outgoing `sCIspExclaveSensorAEBracketConfig`
* `[sp_w+0x470, sp_w+0x209C)` — the IDL request/reply block (`0x1C2C` bytes + 4-byte cmd word)

### 1.2 Where the count comes from

```
0x24ebb8c6c  add x8, sp, #0x470        ; var_1c70 = IDL block base
0x24ebb8c70  add x0, x8, #0x4          ; var_1c6c
0x24ebb8c74  mov w1, #0x1c28           ; <-- SIZING: bzero(IDL+4, 0x1C28)
0x24ebb8c78  bl  0x250095300
...
0x24ebb8c8c  str w9, [sp, #0x470]      ; cmd word = 0x3000e
0x24ebb8c90  add x0, sp, #0x470
0x24ebb8c94  bl  0x2500e9af0           ; <-- Exclave IDL round-trip; fills the block
0x24ebb8c98  cbz w0, 0x24ebb8cf4
```

The count is read back out of the Exclave-filled reply:

```
0x24ebb8d30  ldr w8, [sp, #0x788]      ; IDL + 0x318  == "NumberOfDoubles" slot
```

**Provenance: the Exclave** (secure world), via the generated stub `0x2500e9af0`. It is *not* a
literal in this dylib and *not* a direct function argument — the only argument is `requestID`.

### 1.3 Destination array and its capacity — **sizing instruction**

```
0x24ebb8d08  mov x8, sp                 ; var_20e0 = sp_w (config struct base)
0x24ebb8d0c  add x21, x8, #0x10         ; var_20d0 = sp_w + 0x10  <-- ARRAY BASE
0x24ebb8d10  mov x0, x21
0x24ebb8d14  mov w1, #0x460             ; <-- SIZING: bzero(array, 0x460)
0x24ebb8d18  bl  0x250095300
```

Destination = `sp_w + 0x10`, `0x460` bytes.
Stride (from the loop, 64-bit arithmetic):

```
0x24ebb8d54  add x12, x9,  x9,  lsl #0x2     ; 5*i
0x24ebb8d58  add x13, x10, x12, lsl #0x6     ; src  = IDL+0x32C + 320*i   (0x140 stride)
0x24ebb8d5c  lsl x12, x9,  #0x6              ; 64*i
0x24ebb8d60  sub x12, x12, x9, lsl #0x3      ; 64*i - 8*i = 56*i
0x24ebb8d64  add x14, x21, x12               ; dst  = (sp_w+0x10) + 56*i  (0x38 stride)
```

**Capacity = 0x460 / 0x38 = 20 entries, exactly.** (No remainder: 20 × 56 = 1120 = 0x460.)

Independently corroborated by the consumer, `H16ISP::H16ISPDevice::SetExclaveAEBracketConfig`
(`0x24ebd4c24`), which copies the struct with a hard-coded length:

```
0x24ebd4c60  add x0, x8, #0x1c
0x24ebd4c64  add x1, x2, #0x10
0x24ebd4c68  mov w2, #0x460            ; memcpy(dst+0x1c, cfg+0x10, 0x460)
0x24ebd4c6c  bl  0x250094300
0x24ebd4c78  mov w2, #0x47c            ; total struct size = 0x1c + 0x460
```

So `sCIspExclaveSensorAEBracketConfig` = `{u32 numDoubles @0; u16 requestID @4; void* @8;
entry entries[20] @0x10}`, `sizeof = 0x47C`, entries `0x38` bytes. **Capacity 20 is proven.**

The source array is likewise 20 entries: `IDL+0x32C` with `0x140` stride inside a block that ends
at `sp_w+0x209C` → `(0x209C − 0x79C)/0x140 = 0x1900/0x140 = 20`.

### 1.4 The bound check — **ABSENT**

Full pre-loop gate, verbatim:

```
0x24ebb8d2c  ands w9, w19, #0xffff     ; requestID & 0xffff
0x24ebb8d30  ldr  w8, [sp, #0x788]     ; w8 = count (32-bit, zero-extended)
0x24ebb8d34  stp  w8, w9, [sp]         ; cfg->numDoubles = count ; cfg->requestID = requestID
0x24ebb8d38  b.eq 0x24ebb8cd4          ; if (requestID & 0xffff) == 0 -> bail
0x24ebb8d3c  cbz  w8, 0x24ebb8dc8      ; if (count == 0) -> skip loop
   ; <-- no `cmp w8, #0x14`, no `mov wN,#0x14; csel/cmin`, no clamp of any kind
0x24ebb8d40  mov  x9, #0                ; i = 0
...
0x24ebb8dc0  subs x8, x8, #0x1
0x24ebb8dc4  b.ne 0x24ebb8d54           ; do { ... } while (--count)
```

There is **no `cmp wN, #capacity`** anywhere between the load and the loop. The only guards are
`count != 0` and `requestID != 0`. Confirmed 32-bit load, zero-extended to a 64-bit trip counter.

**Confidence: PROVEN BUG** (missing bound). The *exploitability* depends entirely on whether the
Exclave can be made to emit `count > 20` — see §5.

### 1.5 Stride/overflow arithmetic — clean negative

Both the source index (`5*i << 6` → `320*i`) and the destination index (`64*i − 8*i` → `56*i`) are
computed in **64-bit `x` registers**, and the trip counter `x8` is a 64-bit zero-extension of the
32-bit count. `0xFFFFFFFF × 0x38 ≈ 2.4 × 10^11`, far below 2^64.

> **There is no integer overflow in this function.** The defect is purely the absent compare.
> (Confidence: PROVEN — this is a real negative, not a gap.)

### 1.6 Per-iteration write

Per iteration, `x13` = source slot, `x14` = destination slot:

| dst off | insn | width | value |
|---|---|---|---|
| `+0x00` | `str w15, [x14]` | 4 | `src+0x108` (or clamped DoubleOrder) |
| `+0x04` | `stur x11, [x14, #0x4]` | 8 | constant `0x4000000000000001` |
| `+0x0C` | `stur q0, [x14, #0xc]` | 16 | `src+0x114 … +0x123` |
| `+0x1C` | `stur d0, [x14, #0x1c]` | 8 | `src+0x124 … +0x12B` |
| `+0x24` | `str w12, [x14, #0x24]` | 4 | `src+0x12C` |
| `+0x28` | `str d0, [x14, #0x28]` | 8 | `src+0x130 … +0x137` |
| `+0x30` | `str w15, [x14, #0x30]` | 4 | `src+0x138` |
| `+0x34` | `strb w12, [x14, #0x34]` | 1 | `src+0x13D` |
| `+0x35` | `strb w12, [x14, #0x35]` | 1 | `src+0x13C` |
| `+0x36` | `strb w12, [x14, #0x36]` | 1 | `src+0x13E` |

37 bytes written per 56-byte slot; the 8-byte constant at `+0x04` is the only non-source byte.

### 1.7 Overflow distance — what is corrupted at count = N+k

`dst_i = sp_w + 0x10 + 0x38*i`.

| count | first address written | corrupted |
|---|---|---|
| 20 (max safe) | `sp_w+0x438` | last in-bounds slot (ends exactly at `sp_w+0x470`) |
| **21** | `sp_w+0x470` | IDL cmd word `0x3000e` → `IDL+0x0` … (self-inflicted source corruption) |
| 21 … ~147 | `sp_w+0x470` … | the IDL reply block, incl. its own source array from slot ≈35 onward |
| **148** | `sp_w+0x2070` | saved `x24` |
| **149** | `sp_w+0x20A8` | saved `x24/x23`, `x22/x21`, `x20/x19` |
| **150** | `sp_w+0x20E0` | **saved FP (`sp_w+0x20D0`) and saved LR (`sp_w+0x20D8`)** — plus into caller frame |
| ≥151 | — | caller's frame, then the stack guard page (fault → DoS) |

(Entry index `i` covers `[0x10+56i, 0x10+56i+0x38)`. `sp_w+0x20D0` falls in `i=149`
(`0x10+56·149 = 0x20A8`, end `0x20DF`), so `count ≥ 150` clobbers FP/LR.)

**Stack-layout consequence: at `count ≥ 150` the saved FP and LR are overwritten before `retab`
at `0x24ebb8cf0`.** PAC (`retab`) will reject an unauthenticated LR, **but FP is not PAC'd** — a
controlled `x29` in the caller's epilogue is a stack-pivot primitive. All five callee-saved pairs
are already attacker-influenced one iteration earlier (`count ≥ 149`), so there is also a
straight non-PAC'd register-gadget surface. Bytes written are copies of the Exclave/adjacent-stack
source slots, i.e. partially influenced.

Note also the mirror-image bug: for `i ≥ 20` the **source** reads at
`IDL+0x32C + 320*i` run past the zeroed block (`sp_w+0x209C`) into the caller's stack — an OOB
*read* feeding the config that is sent to the Exclave.

---

## 2. `ProbePatternIndex` / `ProbePatternType` / `DoubleOrder` — **REFUTED as OOB indices**

All three are consumed in `SetCaptureSecureFIDBracket` (`0x24eb4a448`).

* **`ProbePatternIndex` (`var_338`) is never used as an index.** It is only *compared*:
  ```
  0x24eb4a654  ldr w8, [sp, #0x78]      ; var_338 = ProbePatternIndex
  0x24eb4a658  cmp x20, x8              ; i == ProbePatternIndex ?
  0x24eb4a65c  b.ne 0x24eb4a678         ; if not, skip the probe assignment
  ```
  **Confidence: REFUTED** — no table indexing, no OOB read.
* **`ProbePatternType` (`var_33c`) is range-clamped to {0,1,2}:**
  ```
  0x24eb4a660  ldr  w8, [sp, #0x74]
  0x24eb4a664  cmp  w8, #0x1
  0x24eb4a668  cinc w9, w22, ne         ; w22 = 1 -> w9 = (w8==1) ? 1 : 2
  0x24eb4a66c  cmp  w8, #0
  0x24eb4a670  csel w8, wzr, w9, eq     ; -> 0 if w8==0, else 1 or 2
  0x24eb4a674  str  w8, [x25, #0x8]
  ```
  **Confidence: REFUTED** — fully clamped; an arbitrary int32 cannot escape {0,1,2}.
* **`DoubleOrder` values are also clamped to {0,1,2}:**
  ```
  0x24eb4a63c  ldr  w8, [sp]            ; raw CFNumber value
  0x24eb4a640  cmp  w8, #0
  0x24eb4a644  cset w9, ne
  0x24eb4a648  cmp  w8, #0x2
  0x24eb4a64c  csel w8, w8, w9, eq      ; v==2 ? 2 : (v ? 1 : 0)
  0x24eb4a650  str  w8, [x25]
  ```
  The array element fetch is `CFArrayGetValueAtIndex(var_330, i)` (`0x24eb4a62c`), and `i` is
  bounded because the code *enforces* `CFArrayGetCount(DoubleOrder) == NumberOfDoubles`:
  ```
  0x24eb4a554  bl   0x250094380         ; CFArrayGetCount
  0x24eb4a55c  ldr  w8, [sp, #0x7c]     ; NumberOfDoubles
  0x24eb4a560  cmp  x0, x8
  0x24eb4a564  b.ne 0x24eb4a858         ; mismatch -> 0xffffce14
  ```
  **Confidence: REFUTED.**

---

## 3. `SetCaptureSecureFIDBracket` — **the client-facing sibling, and a second missing bound**

`0x24eb4a448`, handler for `kFigCaptureStreamProperty_CaptureSecureFaceIDBracket`
(log string: `ISP_EXCLAVEKIT_CMD_CH_FID_BRACKET_CAPTURE`, cmd `0xf0002`).

### 3.1 Input validation that *is* present (credit where due)

```
0x24eb4a4e8  mov  x0, x20
0x24eb4a4ec  bl   0x250094550          ; CFGetTypeID(value)
0x24eb4a4f4  bl   0x2500944f0          ; CFDictionaryGetTypeID()
0x24eb4a4f8  cmp  x21, x0
0x24eb4a4fc  b.ne 0x24eb4a858          ; -> 0xffffce14   [TYPE CHECKED: must be a dictionary]
```
`NumberOfDoubles` is mandatory and must be a CFNumber; each `CFNumberGetValue` uses
type `9` (`kCFNumberIntType`, 4 bytes) into a 4-byte `int32_t` stack slot — **width matches**:
```
0x24eb4a528  add  x2, sp, #0x7c        ; &int32 var_334
0x24eb4a52c  mov  w1, #0x9
0x24eb4a530  bl   0x2500945b0
```
> **No CFNumberGetValue width mismatch anywhere in this function.** (Confidence: PROVEN negative.)

### 3.2 The missing bound

```
0x24eb4a5c8  add  x21, sp, #0x90       ; var_320 = struct base (sp_w+0x90)
0x24eb4a5cc  add  x0, x21, #0x4
0x24eb4a5d0  mov  w1, #0x2b4           ; <-- SIZING: bzero(struct+4, 0x2B4) -> struct = 0x2B8
0x24eb4a5d4  bl   0x250095300
...
0x24eb4a5ec  ldr  w24, [sp, #0x7c]     ; w24 = NumberOfDoubles (int32)
0x24eb4a5f0  strb w24, [sp, #0x2a0]    ; <-- stored to the Exclave struct as a SINGLE BYTE
0x24eb4a5f4  cbz  w24, 0x24eb4a688     ; if (numDoubles == 0) skip
```

Loop:
```
0x24eb4a5f8  mov  x20, #0                   ; i = 0
0x24eb4a5fc  add  x21, x21, #0x214          ; array base = sp_w + 0x2A4
0x24eb4a604  ldr  d8, [x8, #0xfd0]          ; 0xd00000002
0x24eb4a60c  add  x8,  x20, x20, lsl #0x1  ; 3*i
0x24eb4a610  add  x25, x21, x8,  lsl #0x2  ; dst = base + 12*i    <-- STRIDE 0x0C
0x24eb4a614  str  d8,  [x25]                ; 8 bytes
0x24eb4a618  str  wzr, [x25, #0x8]          ; 4 bytes
   ... (optional overwrite of +0 and +8 with clamped {0,1,2} values)
0x24eb4a678  add  x20, x20, #0x1
0x24eb4a67c  ldr  w8, [sp, #0x7c]
0x24eb4a680  cmp  x20, x8
0x24eb4a684  b.lo 0x24eb4a60c               ; while (i < numDoubles)
```

**Decompiler trap:** the pseudo-C renders this as `int64_t* x25_1 = &(&var_10c)[i * 3]`, i.e. a
24-byte stride. The disassembly proves the stride is **12 bytes** (`3*i` then `lsl #2`).

**Capacity:** the array runs from struct offset `0x214` to the end of the `0x2B8` struct
(`sp_w+0x348`) → `0x348 − 0x2A4 = 0xA4 = 164` bytes = **13 complete 12-byte entries** (156 bytes)
plus 8 trailing bytes. Genuinely in-struct capacity is therefore **≤ 13**.

**No `cmp w24, #13` (or any other ceiling) exists.** Only `numDoubles != 0` is checked.

Again, 64-bit index arithmetic — **no integer overflow** (PROVEN negative).

### 3.3 Overflow distance (`SetCaptureSecureFIDBracket`)

Frame: `sub sp, sp, #0x350` after `stp d9,d8,[sp,#-0x60]!`, so saved regs are
`d9/d8 @ sp_w+0x350`, `x26/x25 @ +0x360`, `x24/x23 @ +0x370`, `x22/x21 @ +0x380`,
`x20/x19 @ +0x390`, **FP @ +0x3A0**, **LR @ +0x3A8**, caller frame @ `+0x3B0`.

`dst_i = sp_w + 0x2A4 + 12*i`:

| numDoubles | corrupted |
|---|---|
| ≤ 13 | in bounds |
| 14 | spills past the zeroed region into struct padding |
| 15–16 | saved `d8`/`d9` |
| 17–20 | saved `x26/x25`, `x24/x23`, `x22/x21`, `x20/x19` |
| **22** | **saved FP (full 8 bytes) + LR low 4 bytes** (`i=21` → `sp_w+0x3A0`) |
| **23** | **LR high 4 bytes** (`i=22` → `sp_w+0x3AC`) + caller frame |
| ≫ 23 | caller frames, then stack guard → SIGSEGV |

**Values written are heavily constrained**, which caps exploitability:
FP ← `0x0000000D_00000002` (low word optionally replaced by a clamped DoubleOrder value ∈{0,1,2});
LR low ← `0` (or clamped ProbePatternType ∈{0,1,2}); LR high ← `0x00000002` (or clamped).
Resulting LR is a low non-canonical pointer → `retab` faults. So this is a **deterministic
camera-daemon crash (DoS)** and a proven stack-buffer overflow, but **not** a demonstrated
PC-control primitive. (Confidence: overflow PROVEN; control of PC REFUTED for this function.)

### 3.4 Inconsistency that proves the bound was simply forgotten

`NumberOfDoubles` is used as the full 32-bit loop bound, but the value actually transmitted to the
Exclave is `strb w24` — **truncated to 8 bits** — and the log prints `and w8, w24, #0xff`.
The designer clearly assumed ≤ 255; the loop uses the unvalidated int32. **Confidence: STRONG.**

**Trigger without any array:** the `CFArrayGetCount(DoubleOrder) == numDoubles` consistency check
is only reached `if (x0_14)` — i.e. only when the `DoubleOrder` key is present. Omitting
`DoubleOrder` entirely leaves `numDoubles` completely unvalidated and the loop still runs.

---

## 4. Configuration keys (`…SecureFaceIDConfigurationKey_{Mode,RetryType,…}`)

Parsed in `HandleSecureStreamOutputConfig` (`0x24eb4d8f8`, 170 blocks), reached from
`SetMetadataOutputConfiguration` (`0x24ea6c074`) ← `SetVideoOutputConfigurations` (`0x24ea5c2ec`).

* The container **is** type-checked:
  ```
  x0_1 = CFGetTypeID(cfg); x0_2 = CFDictionaryGetTypeID();
  if (!x0 || x0_1 != x0_2) -> log "Secure Metadata configuration prop invalid"
  ```
* Booleans (`AttentionRequired`, `PeriocularEnabled`, `FrameLogEnabled`, `FrameMetadataEnabled`)
  are read with `CFBooleanGetValue`, not `CFNumberGetValue` — no width issue.
* Numeric values:
  * `CFNumberGetValue(v, 9, stream+0xB78)` — 4-byte int into a 4-byte field. ✔
  * `CFNumberGetValue(v, 0xC, stream+0xB7C)` — `kCFNumberFloatType` (4 bytes) into a float. ✔
  * `CFNumberGetValue(v, 9, stream+0xBE0)` and `stream+0xBE4` — the `Mode` / `RetryType` pair,
    4-byte int into 4-byte fields. ✔
* Neither `Mode` nor `RetryType` is used as an array index here; they are stored as stream flags.

> **The classic `CFNumberGetValue` type-code/destination-width mismatch is REFUTED** for every
> call I could locate on this path. **Confidence: PROVEN negative.**

Caveat: `HandleSecureStreamOutputConfig` is 760 decompiled lines; I audited the first 260, which
contain all numeric extractions and the CFArray loop. A later block could contain a further
`CFNumberGetValue` with a mismatched width — not seen, not excluded.

---

## 5. Reachability

### 5.1 Dispatch path (inside the plugin)

`SetCaptureSecureFIDBracket` is installed in the static stream-property table by
`invocation function for block in getStreamProperties()` (`0x24eb21c20`); confirmed by
`ds_locate_strrefs.py` → `0x24eb26424  ->  0x24eb4a448  (adrp+add)`, immediately followed by
`paciza` / `str x16, [x0, #0x4480]` (the `+0x10` setter slot).

The dispatcher `H16ISPCaptureStreamSetProperty` (`0x24ea5346c`) applies **three** gates:

1. property name → index via a CFDictionary of CFNumbers; **index bounds-checked**
   (`if (x23 < getNumStreamProperties()::numStreamProperties)`);
2. `IsPropertySupportedForStream(entry, stream, device)` — per-device/stream capability gate;
3. a **privilege flag**: `if (stream->byte[1] || !(entry->flags & 2))` → else `0xffffce6f`
   (refused). `stream->byte[1]` is a privileged/internal-client marker on the stream object.

So the plugin does enforce a per-property privilege bit. I could **not** statically resolve the
flag value for the Face ID bracket entry from the 4739-instruction initializer (the flags are
written to a second parallel array via `x12`, whose base relation I did not establish).
**Confidence: SPECULATIVE** on whether bit `0x2` is set for this specific entry.

### 5.2 Third-party reachability verdict

* The dylib contains **no entitlement strings** — the only hit for "ntitle" is
  `_entitlementsCheckedE`, an unrelated `FileInputFactory` static. Any entitlement gate is
  therefore **upstream**, in Fig / CameraServices / `mediacaptured`, not here.
* All 36 `kFig…SecureFaceID*` symbols are **ExternalSymbol / autoDefined** (imported into this
  dylib from the Fig framework). They are private Fig SPI, not public API.
* A sandboxed third-party app reaches the camera through AVFoundation. AVFoundation forwards a
  fixed, curated set of `AVCaptureDevice` properties; there is no public surface that lets an app
  name an arbitrary `kFigCaptureStreamProperty_*` string. CMIOExtension is for *implementing*
  camera extensions, not for setting arbitrary stream properties on the system camera.

**Verdict per property / key:**

| property / key | third-party settable? | confidence |
|---|---|---|
| `kFigCaptureStreamProperty_CaptureSecureFaceIDBracket` | **No** — private Fig SPI; additionally gated inside the plugin by the `entry->flags & 2` / `stream->byte[1]` check | STRONG (gate bit itself: SPECULATIVE) |
| `…BracketKey_NumberOfDoubles` | **No** — sub-key of the above dictionary; only consumed after the property is accepted | STRONG |
| `…BracketKey_DoubleOrder` | No (same) | STRONG |
| `…BracketKey_ProbePatternIndex` / `_ProbePatternType` | No (same) | STRONG |
| `…SecureFaceIDConfigurationKey_*` | **No** — reached only via `SetVideoOutputConfigurations` → `SetMetadataOutputConfiguration`, again a Fig stream property | STRONG |

**Honest bottom line:** I found **no evidence** that any of these is reachable from a sandboxed
third-party app. The realistic attacker is a process that already speaks Fig capture-stream
properties to `mediacaptured` (an entitled Apple client, or an upstream Fig/CameraServices bug that
launders a client-supplied property name). Whoever that is, `SetCaptureSecureFIDBracket` will parse
their `NumberOfDoubles` **without any upper bound** and smash the stack.

---

## 6. Ranked findings

| # | Finding | Confidence | Severity if reachable |
|---|---|---|---|
| **F1** | `SetCaptureSecureFIDBracket` (`0x24eb4a448`): `NumberOfDoubles` (client-dictionary `int32`) used unclamped as a loop bound writing 12 B/iter into a `≤13`-entry, `0x2B8`-byte stack struct. `numDoubles ≥ 23` fully overwrites saved FP + LR. Trigger needs only `{NumberOfDoubles: N}` — the `DoubleOrder` consistency check is skipped when that key is absent. | **PROVEN BUG** (missing bound); PC-control REFUTED (written values ∈ {0,1,2} + constants); DoS PROVEN | High (DoS certain; stack smash certain) |
| **F2** | `runFaceIDAEBracketCapture` (`0x24ebb8b98`): Exclave-supplied count at `IDL+0x318` unclamped against the `0x460`/`0x38` = **20**-entry destination; `count ≥ 150` overwrites saved FP/LR at `sp_w+0x20D0/0x20D8`. Mirrored OOB *read* of the source array past `sp_w+0x209C` for `i ≥ 20`. | **PROVEN BUG** (missing bound); triggerability **SPECULATIVE** (needs Exclave `count > 20`) | Critical if Exclave coerced; defence-in-depth break otherwise |
| **F3** | Loop bound is the full `int32` while the value sent to the Exclave is `strb`-truncated to 8 bits — direct evidence the bound was omitted, not intended. | **STRONG** | Corroborates F1 |
| **F4** | `SetExclaveAEBracketConfig` (`0x24ebd4c24`) forwards a hard-coded `0x460` bytes with no count validation — no second line of defence. | **PROVEN** | Corroborates F2 |
| **F5** | `ProbePatternIndex` / `ProbePatternType` / `DoubleOrder` as unchecked indices into a table | **REFUTED** — clamped to {0,1,2} or only compared, never indexed | — |
| **F6** | `CFNumberGetValue` type-code/destination-width mismatch on the bracket or configuration path | **REFUTED** — every call observed uses 9 (`int`, 4 B) or 0xC (`float`, 4 B) into 4-byte destinations | — |
| **F7** | Integer overflow in `count * stride` | **REFUTED** — all index arithmetic is 64-bit | — |
| **F8** | Third-party app reachability of any of these properties/keys | **REFUTED (no evidence found)**; plugin-internal privilege bit unresolved → **SPECULATIVE** | — |

## 7. Clean negatives (stated explicitly)

* No `cmp wN, #capacity` exists in `runFaceIDAEBracketCapture`, but there is also **no integer
  overflow** — the bug is a missing compare, not a wrapping multiply.
* `ProbePatternIndex` is compared, never dereferenced: it cannot cause an OOB read.
* Every `CFNumberGetValue` I located on these paths has a type code whose width equals its
  destination width.
* No entitlement-related string exists in this dylib; gating lives upstream.
* Despite the "control the return address" framing in the assignment, `SetCaptureSecureFIDBracket`
  **cannot** write a useful return address — the spilled constants yield a non-canonical pointer
  that faults. The real impact there is a guaranteed daemon crash, not code execution.

## 8. Suggested next steps

1. Confirm `entry->flags & 2` for the Face ID bracket property by resolving `x12`'s base in
   `getStreamProperties()` (`0x24eb21c20`) — this decides whether the plugin itself refuses
   unprivileged callers.
2. Determine whether the Exclave (outside this dylib) echoes `NumberOfDoubles` back at
   `IDL+0x318`; if it does, F2 upgrades to a directly reachable stack smash.
3. Audit the remaining ~500 lines of `HandleSecureStreamOutputConfig` for a later
   `CFNumberGetValue` with a mismatched width (F6 caveat).
