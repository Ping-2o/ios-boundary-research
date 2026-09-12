> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# `H16ISPGraphExclaveFaceIDNode` — Exclave FaceID result parsing (H16ISP.mediacapture, iOS 27.0 RC 24A435)

Binary: `H16ISP.mediacapture`, ios-aarch64, image base `0x24ea3e000`, `__TEXT,__text` = `0x24ea3ff90` + `0x1d8594`.
All work done read-only in Binary Ninja (active view `H16ISP.mediacapture`). Widths confirmed in
`bn_function_disassembly`, not from the decompiler.

Functions examined:

| Address | Symbol |
| --- | --- |
| `0x24ead9c14` | `H16ISPGraphExclaveFaceIDNode::H16ISPGraphExclaveFaceIDNode(H16ISPDevice*, uint32_t)` |
| `0x24eae60c0` | `H16ISPGraphExclaveFaceIDNode::onMessageProcessing(H16ISPFilterGraphMessage*)` |
| `0x24eb0a804` | `H16ISPGraphExclaveFaceIDNode::AddFaceIDMetadata(H16ISPFilterGraphMessage*, ISPExclaveCoreChRunKitFidResult const&, uint64_t, bool)` |
| `0x24eb0b398` | `H16ISPGraphExclaveFaceIDNode::GetNodeProcessingState()` |
| `0x24ebfbe88` | `AddFaceIDMetadata .cold.1` |
| `0x24ebb8b98` | `H16ISPGraphExclaveAutoExposureNode::runFaceIDAEBracketCapture(uint32_t)` (adjacent, see §6) |

Note on the signature: in this build `AddFaceIDMetadata` takes **five** args
`(this, H16ISPFilterGraphMessage*, ISPExclaveCoreChRunKitFidResult const&, uint64_t, bool)` —
one more `uint64_t` than the brief states.

---

## 1. Where the result comes from

`onMessageProcessing` (0x24eae60c0) builds the Exclave IDL argument block on the stack:

```
0x24eae62b4  mov     w8, #0x504
0x24eae62b8  ldr     w3, [x19, #0x60]              ; this->channelId (set by ctor from uint32_t arg3)
0x24eae62bc  str     w8, [sp, #0x28]               ; IDL+0x08  = 0x504
0x24eae62c0  str     w3, [sp, #0x22c]              ; IDL+0x20C = channel id
0x24eae62c4  adrp    x8, 0x24ec26000
0x24eae62c8  ldr     d0, [x8, #0xb88]              ; 0x10000000f0004
0x24eae62cc  str     d0, [sp, #0x20]               ; IDL+0x00  = magic/cmd
...
0x24eae62f0  add     x0, sp, #0x20                 ; &IDL
0x24eae62f4  bl      0x2500e9af0                   ; Exclave IDL call (ISP_EXCLAVEKIT_CMD_CH_RUN_FID)
0x24eae62f8  mov     x23, x0                       ; retval
0x24eae6314  cbz     w23, 0x24eae63b8              ; if (ret == 0) -> success
...
0x24eae6444  add     x8, sp, #0x20
0x24eae6448  add     x2, x8, #0x210                ; arg3 = IDL + 0x210
0x24eae644c  mov     x0, x19                       ; this
0x24eae6450  mov     x1, x20                       ; message
0x24eae6454  mov     x3, x21                       ; arg4 = *(msg + 0x58)
0x24eae6458  mov     x4, x22                       ; arg5 = *(msg + 0x183)
0x24eae645c  bl      0x24eb0a804                   ; AddFaceIDMetadata
```

So `ISPExclaveCoreChRunKitFidResult` lives at **IDL+0x210** inside a stack block that starts at
`sp+0x20` (frame `sub sp, sp, #0x530`). The whole block is compiler-sized from the IDL type —
there is no length negotiation with the Exclave at this layer; the generated stub
`0x2500e9af0` owns the copy.

Cross-check on the result size: the highest offset `AddFaceIDMetadata` touches is `+0x2F0`
(one byte) → `sp+0x230+0x2F0 = sp+0x520`, and `onMessageProcessing` itself reads
`ldrb w9, [sp, #0x520]` (0x24eae6400) for the `Attn=%{bool}d` log. Consistent: the observed
result span is `0x210 … 0x2F0` (≥ 0x2F1 bytes; almost certainly a 0x2F8/0x300-byte type).

---

## 2. `ISPExclaveCoreChRunKitFidResult` layout **as the code reads it**

Base = `arg3` (= IDL+0x210). Every access below is an **immediate** offset from `x27` (= arg3);
there is not a single variable index register anywhere in the function.

| Offset | Width (confirmed in disasm) | Consumer / meaning | Validated? |
| --- | --- | --- | --- |
| `+0x110` | `ldr w` → CFNumber type 3 (SInt32) | scalar #1 (`k…948` key) | n/a |
| `+0x114` | `ldr w` → type 3 | scalar #2 (`k…958`) | n/a |
| `+0x118` | `ldr x` (8B, debug log only) | 64-bit value logged as `R:%#llx` | n/a |
| `+0x120` | `ldr x` → type 4 (SInt64) | `R:%#llx` #1 | n/a |
| `+0x128` | `ldr x` → type 4 | `R:%#llx` #2 | n/a |
| `+0x134` | `ldr w` → type 3 | rect-ish int #1 | n/a |
| `+0x138` | `ldr w` → type 3 | int #2 | n/a |
| `+0x13C` | `ldr w` → type 3 | int #3 | n/a |
| `+0x140` | `ldr w` → type 3 | int #4 | n/a |
| `+0x14C` | 8B (`ldr x17,[x17]`, log only) | triple base | n/a |
| `+0x154` | `ldr x` → type 4 (via `x20+0x8`) | `M:%#llx` #1 | n/a |
| `+0x15C` | `ldr x` → type 4 (via `x20+0x10`) | `M:%#llx` #2 | n/a |
| `+0x168` | `ldr w` → type 3 | | n/a |
| `+0x16C` | `ldr w` → type 3 | | n/a |
| `+0x170` | `ldr w` → type 3 | | n/a |
| `+0x174` | `ldr w` → type 3 | | n/a |
| `+0x180` | 8B (log only) | | n/a |
| `+0x188` | `ldr x` → type 4 | | n/a |
| `+0x190` | `ldr x` → type 4 | | n/a |
| `+0x19C` | `ldr w` → type 3 | | n/a |
| `+0x1A0` | `ldr w` → type 3 | | n/a |
| `+0x1A4` | `ldr w` → type 3 | | n/a |
| `+0x1A8` | `ldr w` → type 3 | | n/a |
| `+0x2BC` | **`ldrb`** (1 byte), `tst #1` | AD flag, selected when `isExclaveADRequired()==0` | n/a (boolean) |
| `+0x2C0` | `ldr w` (32-bit) | "E:" status/enum; also compared `== 0x20` / `== 0x800` | see §4 |
| `+0x2C4` | `ldr s` (float32) → `fcvt d` | rect[0] | n/a |
| `+0x2C8` | float32 | rect[1] | n/a |
| `+0x2CC` | float32 | rect[2] | n/a |
| `+0x2D0` | float32 | rect[3] | n/a |
| `+0x2D4` | float32 → `fcvtzs` → CFNumber type 3 | P (pitch) | n/a |
| `+0x2D8` | float32 → `fcvtzs` → type 3 | Y (yaw) | n/a |
| `+0x2DC` | float32 → `fcvtzs` → type 3 | R (roll) | n/a |
| `+0x2E0` | `ldr s`, CFNumber type **0xC** (Float64, 8B read) | G[0] | n/a |
| `+0x2E4` | type 0xC | G[1] | n/a |
| `+0x2E8` | type 0xC | G[2] | n/a |
| `+0x2EC` | type 0xC | G[3] | n/a |
| `+0x2F0` | **`ldrb`** (1 byte) | Attention / "Attn" bool; also `&1` for `k…968` key | n/a (boolean) |

**Width note (the decompiler lies here).** The pseudocode renders `+0x2D4/+0x2D8/+0x2DC` as
`double` (they appear as `double v4_1; v4_1 = *(arg3 + 0x2d4);` in the debug-log block). The
disassembly is unambiguous:

```
0x24eb0a9a0  ldr     s0, [x27, #0x2d4]     ; 32-bit
0x24eb0a9a4  fcvtzs  s0, s0
0x24eb0a9a8  stur    s0, [fp, #-0x6c]      ; 4-byte store
0x24eb0a9b4  mov     w1, #0x3              ; kCFNumberSInt32Type
0x24eb0a9b8  bl      0x250094580           ; CFNumberCreate
```

They are **float32**, converted to int32. The "double" reading in the log block is a vararg
promotion (`fcvt d0, s0`) — same bytes.

## 3. There is **no** size/count/index field in the parsed result

This is the central negative result. `AddFaceIDMetadata` is **763 instructions, 19 basic blocks,
zero backward branches, zero loops, zero `memcpy`/`memmove`/`bcopy`, zero variable-offset
loads/stores**. Full callee list (129 callsites) contains only:

- `0x2500944b0` ×8 — `CFDictionaryCreateMutable(alloc, 0, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)`
- `0x250094360` ×1 — mutable container create (3-arg)
- `0x250094330` ×1 — container append
- `0x250094580` ×39 — `CFNumberCreate`
- `0x250094510` ×38 — `CFDictionarySetValue`
- `0x250094630` ×43 — `CFRelease`
- `0x2500c6660` ×1 — rect→object helper (4 doubles in, object out)
- `0x250095820`/`0x250095830` ×2 — message lock/unlock
- `0x2500957a0`/`0x250095790`/`0x2500952d0` — os_log
- `0x24eadd318` `isExclaveADRequired`, `0x24ead9e50` `enabledExclaveDebug`

Nothing computes `count * stride`, nothing allocates from a result-supplied size, nothing
indexes an array. Therefore **items 2 and 3 of the assignment have no instances to check**:
there is no count field to bound, because the code never uses one.

The only comparisons against result data anywhere in the function:

```
0x24eb0aaf4  ldr     w8, [x27, #0x2c0]
0x24eb0aafc  cmp     w8, #0x20
0x24eb0ab00  b.eq    0x24eb0ab10
0x24eb0ab04  cmp     w8, #0x800
0x24eb0ab08  b.eq    0x24eb0ab10
0x24eb0ab0c  mov     x2, x21                ; else -> kCFBooleanFalse
```
and
```
0x24eb0b0f8  ldrb    w8, [x8]               ; +0x2BC or +0x2F0
0x24eb0b0fc  tst     w8, #0x1
```
Both are value/enum classification, not bounds.

## 4. `AddFaceIDMetadata` — decompiled body

Verbatim pseudocode (BN 5.x, `Pseudo C`), log-init boilerplate elided with `…`.

```c
int64_t H16ISP::H16ISPGraphExclaveFaceIDNode::AddFaceIDMetadata(
        H16ISPGraphExclaveFaceIDNode* this, H16ISPFilterGraphMessage* arg2,
        ISPExclaveCoreChRunKitFidResult const& arg3, uint64_t arg4, bool arg5)
{
    int32_t var_190 = arg5;
    uint64_t var_78  = arg4;
    int64_t x20 = **0x2680d3150;                      /* kCFAllocatorDefault */
    int64_t x22 = *0x2680d3348, x23 = *0x2680d3350;   /* kCFTypeDictionary{Key,Value}CallBacks */

    int64_t x0_1  = CFDictionaryCreateMutable(x20, 0, x22, x23);
    int64_t x0_3  = CFCreate3(x20, 0, *0x2680d3338);
    int64_t x0_5  = CFDictionaryCreateMutable(x20, 0, x22, x23);
    int64_t x0_7  = CFDictionaryCreateMutable(x20, 0, x22, x23);
    int64_t x0_9  = CFDictionaryCreateMutable(x20, 0, x22, x23);
    int64_t x0_11 = CFDictionaryCreateMutable(x20, 0, x22, x23);
    int64_t x0_13 = CFDictionaryCreateMutable(x20, 0, x22, x23);
    int64_t x0_15 = CFDictionaryCreateMutable(x20, 0, x22, x23);

    bool z   = x0_1 ? !x0_3 : true;      /* any NULL -> z chain true -> error path */
    bool z_1 = !z   ? !x0_7 : true;
    bool z_2 = !z_1 ? !x0_5 : true;
    bool z_3 = !z_2 ? !x0_15 : true;
    bool z_4 = !z_3 ? !x0_9 : true;
    bool z_5 = !z_4 ? !x0_11 : true;
    bool z_6 = !z_5 ? !x0_13 : true;

    if (z_6) {                                        /* 0x24eb0a944 : ALLOC-FAILURE PATH */
        … os_log_get("com.apple.isp","exclaves") …
        if (!os_log_type_enabled(log, 0x10)) return result;           /* 0x24eb0a984 cbz -> epilogue */
        return AddFaceIDMetadata .cold.1(this, log, x2_8, x3_7, x4);  /* 0x24eb0a990 */
    }

    /* --- face geometry: three float32 -> int32 CFNumbers --- */
    float var_7c = vcvts_s32_f32(*(arg3 + 0x2d4));
    int64_t x0_19 = CFNumberCreate(x20, 3, &var_7c);
    CFDictionarySetValue(x0_1, **0x268113510, x0_19); CFRelease(x0_19);
    var_7c = vcvts_s32_f32(*(arg3 + 0x2d8));
    int64_t x0_23 = CFNumberCreate(x20, 3, &var_7c);
    CFDictionarySetValue(x0_1, **0x268113520, x0_23); CFRelease(x0_23);
    var_7c = vcvts_s32_f32(*(arg3 + 0x2dc));
    int64_t x0_27 = CFNumberCreate(x20, 3, &var_7c);
    CFDictionarySetValue(x0_1, **0x268113518, x0_27); CFRelease(x0_27);

    /* --- rect: 4 float32 -> double -> object --- */
    int64_t x0_30 = RectHelper(*(arg3+0x2c4), *(arg3+0x2c8), *(arg3+0x2cc), *(arg3+0x2d0));
    if (x0_30) { CFDictionarySetValue(x0_1, **0x268113b00, x0_30); CFRelease(x0_30); }

    int64_t x19_1 = **0x2680d3198;   /* kCFBooleanTrue  */
    int64_t x21_1 = **0x2680d3188;   /* kCFBooleanFalse */
    CFDictionarySetValue(x0_1, **0x268113530, *(arg3 + 0x2f0) ? x19_1 : x21_1);

    if (arg5) {
        int32_t x8_10 = *(arg3 + 0x2c0);
        CFDictionarySetValue(x0_1, **0x268113718,
                             (x8_10 != 0x20 && x8_10 != 0x800) ? x21_1 : x19_1);
    }

    /* --- 4 float64 gaze values --- */
    for (off in {0x2e0, 0x2e4, 0x2e8, 0x2ec}) {
        int64_t n = CFNumberCreate(x20, 0xc, arg3 + off);
        CFDictionarySetValue(x0_1, &cfstr_, n); CFRelease(n);
    }

    /* --- nesting: x0_1 -> x0_3 -> x0_5 -> x0_7 -> msg metadata --- */
    AppendContainer(x0_3, x0_1);
    CFDictionarySetValue(x0_5, **0x268112ed0, x0_3);
    int64_t x0_54 = CFNumberCreate(x20, 0xb, &var_78);       /* arg4 */
    CFDictionarySetValue(x0_5, **0x268113d18, x0_54); CFRelease(x0_54);
    CFDictionarySetValue(x0_7, **0x268112e98, x0_5);
    Lock(msg + 8);
    CFDictionarySetValue(*(arg2 + 0x170), **0x268113348, x0_7);
    Unlock(msg + 8);

    /* --- three 6-field triples at +0x120 / +0x154 / +0x188 --- */
    /*   SInt64 @ +0x120/+0x154/+0x188, SInt64 @ +0x128/+0x15C/+0x190,      */
    /*   SInt32 @ +0x134/+0x168/+0x19C, +0x138/+0x16C/+0x1A0,               */
    /*           +0x13C/+0x170/+0x1A4, +0x140/+0x174/+0x1A8                 */
    … 39 x CFNumberCreate / CFDictionarySetValue / CFRelease …

    CFDictionarySetValue(x0_15, **0x268114960, x0_9);
    CFDictionarySetValue(x0_15, **0x268114950, x0_11);
    CFDictionarySetValue(x0_15, **0x268114970, x0_13);
    CFNumber(x0_15, **0x268114948, arg3+0x110);
    CFNumber(x0_15, **0x268114958, arg3+0x114);

    int64_t x8_28 = H16ISPDevice::isExclaveADRequired(*(this + 0x58)) ? 0x2bc : 0x2f0;
    CFDictionarySetValue(x0_15, **0x268114968, (*(arg3 + x8_28) & 1) ? x19_1 : x21_1);
    CFNumber(x0_15, **0x268114940, arg3+0x2c0);   /* SInt32 */

    Lock(msg + 8);
    CFDictionarySetValue(*(arg2 + 0x170), **0x268113358, x0_15);
    Unlock(msg + 8);

    if (H16ISPDevice::enabledExclaveDebug(*(this + 0x58))) {
        … builds a 0xdc-byte os_log arg buffer on the stack (var_160 … var_8c) and
          logs "@@@ Attn:%d %d E:%#x Rect:[%1.5f,%1.5f][%1.5f,%1.5f] P:%1.5f Y:%1.5f R:%1.5f
                G:[%1.5f,%1.5f] E:%1.5f %1.5f R:%#llx %#llx %#llx M:%#llx %#llx %#llx
                R:%#llx %#llx %#llx\n" (0x24ec68f9d) …
    }

    CFRelease(x0_1); CFRelease(x0_3); CFRelease(x0_5); CFRelease(x0_7);
    CFRelease(x0_9); CFRelease(x0_11); CFRelease(x0_13);
    return CFRelease(x0_15);
}
```

The one "variable" thing in the whole function is `x8_28` (0x2BC vs 0x2F0) — a **two-way
selected constant**, both 1-byte reads, both well inside the struct.

## 5. `onMessageProcessing` — message validation

Reads from `arg2`, all fixed offsets, all width-confirmed:

| Offset | Width | Use |
| --- | --- | --- |
| `+0x008` | — | `lock()` / `unlock()` (0x250095820 / 0x250095830) |
| `+0x048` | `ldr x` (8B) | node-type bitmask; `x25 = (1 << GetType(this)) & mask` |
| `+0x058` | `ldr x` (8B) | forwarded as `arg4` to `AddFaceIDMetadata` |
| `+0x168` | `ldr w` (4B) | request id; always masked `& 0x7ff` before use |
| `+0x170` | `ldr x` (8B) | metadata dictionary, target of `CFDictionarySetValue` |
| `+0x182` | `ldrb` (1B) | **message selector — must `== 1` to process** |
| `+0x183` | `ldrb` (1B) | bool → `arg5` |

```
0x24eae60fc  ldrb    w23, [x20, #0x182]
0x24eae6134  cmp     w23, #0x1
0x24eae6138  ccmp    x25, #0, #0x4, eq
0x24eae613c  b.ne    0x24eae6218          ; process only if (+0x182 == 1) && (type bit set)
```

Selector is **validated by equality to 1**, not by range. No payload length is read, because no
payload is parsed — the handler only forwards a pointer and 3 scalars. `1 << GetType(this)`
is a bitmask shift, not an array index (ARM64 `lsl` masks the shift to 6 bits; no memory
access). **No payload-length vulnerability exists in this handler.**

## 6. `GetNodeProcessingState` / ctor

```
0x24eb0b398  ldrb    w0, [x0, #0x50]      ; returns this->state byte
0x24eb0b39c  ret
```

```
0x24ead9c2c  mov     w1, #0x20
0x24ead9c30  bl      0x24ead86ec              ; base H16ISPFilterGraphNode ctor(this, 0x20)
0x24ead9c50  strb    wzr, [x0, #0x50]         ; state = 0
0x24ead9c54  str     x20, [x0, #0x58]         ; device
0x24ead9c58  str     w19, [x0, #0x60]         ; channel/node id = uint32_t arg3
0x24ead9c64  retab
```

`arg3` (the `uint32_t`) is **stored unvalidated** at `this+0x60`. It is then only ever used as:
an os_log argument (`0x24eae619c`, `0x24eae62fc`, `0x24eae6358`) and as the IDL channel field
(`str w3, [sp, #0x22c]`). **It is never used as an array index or a size anywhere in this
class.** → the "ctor uint32 indexes a node array" hypothesis is REFUTED for this node; the
missing bound is a hardening gap only.

---

## 7. Candidate findings, ranked

### C1 — `runFaceIDAEBracketCapture`: unbounded Exclave count drives a 56-byte-stride write into a fixed 20-entry stack array
**Confidence: PROVEN BUG** (missing bound is a fact of the code); **impact: STRONG**; **attacker control: SPECULATIVE** (depends on the Exclave).

Out of the assigned class, but it is the one real count-driven loop in the Exclave FaceID surface.

Destination:
```
0x24ebb8d08  mov     x8, sp
0x24ebb8d0c  add     x21, x8, #0x10            ; var_20d0 = sp + 0x10
0x24ebb8d10  mov     x0, x21
0x24ebb8d14  mov     w1, #0x460                ; 1120 bytes  == 20 * 0x38
0x24ebb8d18  bl      0x250095300                ; memset(var_20d0, 0, 0x460)
```

Controlling input — a 32-bit field of the Exclave IDL result at **IDL+0x318**:
```
0x24ebb8d2c  ands    w9, w19, #0xffff          ; reqid & 0xffff
0x24ebb8d30  ldr     w8, [sp, #0x788]          ; sp+0x470 = IDL base; +0x318  <-- COUNT
0x24ebb8d34  stp     w8, w9, [sp]              ; {count, reqid}
0x24ebb8d38  b.eq    0x24ebb8cd4               ; if ((reqid & 0xffff) == 0) return
0x24ebb8d3c  cbz     w8, 0x24ebb8dc8           ; if (count == 0) skip loop
```
**There is no `cmp w8, #20` / `b.hi` anywhere.** The only two guards are `reqid != 0` and
`count != 0`.

Loop body (0x24ebb8d54 … 0x24ebb8dc4):
```
0x24ebb8d54  add     x12, x9, x9, lsl #0x2     ; 5*i
0x24ebb8d58  add     x13, x10, x12, lsl #0x6   ; src = (IDL+0x32C) + 0x140*i
0x24ebb8d5c  lsl     x12, x9, #0x6             ; 64*i
0x24ebb8d60  sub     x12, x12, x9, lsl #0x3    ; 64*i - 8*i = 56*i = 0x38*i
0x24ebb8d64  add     x14, x21, x12             ; dst = var_20d0 + 0x38*i
0x24ebb8d68  add     x12, x13, #0x124
0x24ebb8d6c  ldr     d0, [x12]      ;  0x24ebb8d70  stur   d0, [x14, #0x1c]
0x24ebb8d74  ldr     w12, [x13, #0x12c] ; 0x24ebb8d78  str    w12, [x14, #0x24]
0x24ebb8d7c  ldr     d0, [x13, #0x130] ; 0x24ebb8d84  str    d0, [x14, #0x28]
0x24ebb8d88  ldr     w15, [x13, #0x108] ; 0x24ebb8d8c  str    w15, [x14]
0x24ebb8d90  ldr     w15, [x13, #0x138] ; 0x24ebb8d94  str    w15, [x14, #0x30]
0x24ebb8d98  ldr     q0, [x12]        ;  0x24ebb8d9c  stur   q0, [x14, #0xc]
0x24ebb8da0  stur    x11, [x14, #0x4]           ; 0x4000000000000001
0x24ebb8da4  ldrb    w12, [x13, #0x13c] ; 0x24ebb8da8  strb   w12, [x14, #0x35]
0x24ebb8dac  ldrb    w12, [x13, #0x13d] ; 0x24ebb8db0  strb   w12, [x14, #0x34]
0x24ebb8db4  ldrb    w12, [x13, #0x13e] ; 0x24ebb8dbc  strb   w12, [x14, #0x36]
0x24ebb8db8  add     x9, x9, #0x1
0x24ebb8dc0  subs    x8, x8, #0x1
0x24ebb8dc4  b.ne    0x24ebb8d54
```

Arithmetic that pins the intended capacity:
- destination element size = highest write `0x36` + 1 = **0x38 (56)**; `0x460 / 0x38 = 20` exactly.
- destination array `sp+0x10 … sp+0x470`; the IDL block begins immediately at `sp+0x470`.
- source element stride **0x140**, base `IDL+0x32C`; 20 entries end at `IDL+0x32C+0x1900 = IDL+0x1C2C`,
  which is exactly the end of the `memset(IDL+4, 0, 0x1C28)` region (0x24ebb8c6c–0x24ebb8c78).
  Both arrays are therefore 20 entries by construction, and the count field is *expected* ≤ 20
  with **no runtime enforcement**.

Consequences as `count` grows (`dst_i` = `sp+0x10 + 0x38*i`):
- `i = 20 … ~147` — writes land inside the IDL result block (`sp+0x470 … sp+0x209C`). Note the
  destination and the source array share that block, so entries ≥20 also **corrupt their own
  source data** (later iterations read back attacker-influenced bytes).
- `i = 148` → `sp+0x2090`, covering saved `x24/x23` (`sp+0x20A0`), `x22/x21` (`sp+0x20B0`),
  `x20/x19` (`sp+0x20C0`).
- `i = 149` → `sp+0x20A8 … sp+0x20E0`, which includes saved **FP (`sp+0x20D0`) and LR
  (`sp+0x20D8`)** → `retab` at 0x24ebb8cf0. (PAC: `retab` will reject an unsigned LR, but saved
  FP and all five callee-saved pairs are already attacker-influenced at `i=148`.)
- `i ≥ 20` also reads the source out of bounds past `sp+0x209C`.
- `count` is a full 32-bit value, so the loop can run up to 4 294 967 295 iterations.

Controlling input: `IDL+0x318`, written by the Exclave stub `0x2500e9af0` (0x24ebb8c94) —
semantically `kFigCaptureStreamCaptureSecureFaceIDBracketKey_NumberOfDoubles`. Not reachable
from userspace data in this dylib.

### C2 — `AddFaceIDMetadata`: CF object leak on the allocation-failure path
**Confidence: PROVEN BUG** (low severity).

```
0x24eb0a918  cmp     x28, #0
0x24eb0a91c  ccmp    x27, #0, #0x4, ne
0x24eb0a920  ccmp    x23, #0, #0x4, ne
0x24eb0a924  ccmp    x25, #0, #0x4, ne
0x24eb0a928  ccmp    x0,  #0, #0x4, ne
0x24eb0a930  ccmp    x26, #0, #0x4, ne
0x24eb0a934  ccmp    x21, #0, #0x4, ne
0x24eb0a93c  ccmp    x19, #0, #0x4, ne
0x24eb0a940  b.ne    0x24eb0a998            ; all 8 non-NULL -> normal path
                                            ; fall-through = at least one NULL
0x24eb0a978  mov     x0, x19 ; mov w1, #0x10
0x24eb0a980  bl      0x2500957a0            ; os_log_type_enabled
0x24eb0a984  cbz     w0, 0x24eb0b378        ; ----> straight to epilogue
0x24eb0a990  bl      0x24ebfbe88            ; .cold.1 -> only logs
0x24eb0a994  b       0x24eb0b378            ; ----> straight to epilogue
```
The epilogue at `0x24eb0b378` contains **no `CFRelease`** (all eight releases live at
`0x24eb0b338`–`0x24eb0b374`, which is skipped). The successfully created dictionaries are
leaked. `.cold.1` (0x24ebfbe88) confirms the path is the CF-allocation-failure branch — it only
logs `"[Exclaves] H16ISPGraphExclaveFaceIDNode::%s CF Allocation failed! ch=%u\n"`
(0x24ec68f54). Reachable only under allocator pressure; no memory corruption.

### C3 — `H16ISPGraphExclaveFaceIDNode` ctor `uint32_t` parameter stored without a bound
**Confidence: SPECULATIVE** (hardening gap, not a bug I can prove exploitable).
`str w19, [x0, #0x60]` (0x24ead9c58). Downstream uses are os_log args and the IDL channel
field only — **no array indexing observed** → the classic "node id indexes a node array"
pattern is **REFUTED** for this class.

### C4 — Frame-proxy keys (`…SecureFaceIDFrameProxyKey_FrameHeight` / `_FrameIdentifier` / …)
**Confidence: REFUTED as a bug source in this dylib.**

- `bn_symbol_list` reports all six (plus `_FrameWidth`, `_PixelFormat`,
  `_SharedMemoryAreaOffset`, `_Stride`) as **ExternalSymbol / autoDefined**, at synthetic
  addresses `0x2d506f278 … 0x2d506f2a0` — outside every Mach-O section in this file
  (highest real section ends at `0x275eb4a18`).
- `ds_locate_strrefs.py` over the whole `0x2d5060000–0x2d5070000` window: **0 hits** in
  `__TEXT,__text`. Positive control on the same run: `0x275ea98d0` → `0x24eb0ab40` (the real
  CFString use inside `AddFaceIDMetadata`) — so the locator works.
- `AddFaceIDMetadata` touches no frame-height/stride/pixel-format/offset field at all (see §2).

Caveat: the locator scans executable sections only; a pure **data** relocation into
`__DATA_CONST,__const` would not be caught. Even so, no Exclave-parsed code path in this dylib
consumes a proxied frame's dimensions. Wherever the frame proxy is decoded, it is not here.

---

## 8. Honest reachability statement

- The `ISPExclaveCoreChRunKitFidResult` is produced by the Exclave (secure world) through the
  generated stub `0x2500e9af0`; the dylib only supplies a stack buffer, a magic/cmd word
  (`0x10000000f0004`), `0x504`, and a channel id. There is **no userspace-controllable length
  or count** on that path, and the only userspace values that reach `AddFaceIDMetadata` are
  `*(msg+0x58)` (a `uint64_t` turned into a CFNumber) and `*(msg+0x183)` (a bool).
- Consequently **C1 is not attacker-reachable from the camera userspace plugin in this build**
  unless the Exclave itself emits `count > 20` at `IDL+0x318`. What is proven is the *absence
  of the bound*: the compiler-sized destination is exactly 20 entries and the loop is gated
  only on `count != 0`. If the Exclave is trusted to enforce ≤ 20, this is defence-in-depth
  breakage; if the Exclave can ever be induced to return a larger count (Exclave bug, version
  skew between IDL definition and Exclave implementation, or a rollback of the Exclave to an
  older build with a different limit), it becomes a straight stack smash reaching saved LR at
  `count ≥ 150`.
- Even granting a fully trusted Exclave, C1 is a **real defect**: it is a cross-trust-boundary
  structure whose count field is consumed without validation by untrusted userspace. The
  whole point of the Exclave boundary is that the plugin must not assume the peer is
  well-behaved.
- C2 is a genuine, if minor, correctness bug reachable under memory pressure.

## 9. Clean negatives (explicitly)

- `AddFaceIDMetadata` contains **no** size/count/length field usage: no loop, no `memcpy`,
  no variable offset, no `count * stride`, no result-sized allocation. Items 2 and 3 of the
  assignment have zero instances.
- Metadata dictionary construction uses `CFDictionaryCreateMutable(..., 0, ...)` with a
  **constant capacity of 0** in all 8 calls — capacity never derives from result data.
- `onMessageProcessing` validates the message selector by equality (`+0x182 == 1`) and does not
  parse a variable-length payload at all.
- The ctor's `uint32_t` is not used as an index.
- The frame-proxy keys have no code reference in this image.
