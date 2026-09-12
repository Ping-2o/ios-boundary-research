> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# Face ID bracket — closing the two open fronts (canary + Exclave) and the reachability gate

Supersedes/extends `fid_bracket.md` §3.3, §5.1 and `fid_node.md` §8.2.
Tooling: Binary Ninja (read-only), `H16ISP.mediacapture` (24A435) and — **new** —
`ISPExclaveKitServices` (24A435), the secure-world peer that neither prior audit opened.
Every width/offset below is from `bn_function_disassembly`. Where the decompiler disagrees with
the disassembly, the disassembly wins (BN mis-scales here — see §1.2).

---

## TL;DR — three corrections to the prior audits

| # | Prior claim | Corrected |
|---|---|---|
| **C1** | `SetCaptureSecureFIDBracket` needs `numDoubles ≥ 22/23` to matter | **`numDoubles ≥ 14` already destroys the stack canary** → deterministic `abort()` |
| **C2** | PC control "REFUTED because the spilled values are constrained" | PC control is refuted by a **hard architectural control** (canary), which fires *first*; the value constraints are a second, independent reason |
| **C3** | "Does the Exclave echo `NumberOfDoubles` back at `IDL+0x318`?" — open | **Yes, proven** (`*(arg1 + 0x318) = var_b0_1[6]`). But the Exclave is itself structurally safe — see §2 |

Net: **F1 is now a proven, deterministic, single-integer denial-of-service in the camera daemon.**
F2's missing bound is proven and its producer is now identified, but triggerability is still unproven.

---

## 1. `SetCaptureSecureFIDBracket` (0x24eb4a448) — the canary nobody noticed

### 1.1 The canary exists

Prologue:

```
0x24eb4a448  pacibsp
0x24eb4a44c  stp     d9, d8, [sp, #-0x60]!
0x24eb4a450  stp     x26, x25, [sp, #0x10]
0x24eb4a454  stp     x24, x23, [sp, #0x20]
0x24eb4a458  stp     x22, x21, [sp, #0x30]
0x24eb4a45c  stp     x20, x19, [sp, #0x40]
0x24eb4a460  stp     fp, lr, [sp, #0x50]
0x24eb4a464  add     fp, sp, #0x50
0x24eb4a468  sub     sp, sp, #0x350
...
0x24eb4a478  adrp    x8, 0x2681b5000
0x24eb4a47c  ldr     x8, [x8, #0x5a0]
0x24eb4a480  ldr     x8, [x8]                 ; __stack_chk_guard
0x24eb4a484  stur    x8, [fp, #-0x58]         ; <-- CANARY STORED
```

Epilogue:

```
0x24eb4a85c  ldur    x8, [fp, #-0x58]
0x24eb4a860  adrp    x9, 0x2681b5000
0x24eb4a864  ldr     x9, [x9, #0x5a0]
0x24eb4a868  ldr     x9, [x9]                 ; __stack_chk_guard
0x24eb4a86c  cmp     x9, x8
0x24eb4a870  b.ne    0x24eb4a8b4              ; -> 0x250095270, tail-called
...
0x24eb4a888  ldp     d9, d8, [sp], #0x60
0x24eb4a890  retab
```

`0x250095270` is the `___stack_chk_fail` stub (Binary Ninja merges it into the adjacent
`SetSecureFrameProxyIdentifierRelease` because it is a tail call). Confirmed independently:

```
$ nm -a H16ISP.mediacapture | grep stack_chk
         U ___stack_chk_fail
         U ___stack_chk_guard
```

### 1.2 Frame arithmetic (disassembly, not the decompiler)

`sp_w = S − 0x3B0`. Canary at `fp − 0x58` = `sp_w + 0x348`.

| item | address |
|---|---|
| struct base | `sp_w + 0x90`, size `0x2B8` → ends `sp_w + 0x348` |
| array base | `sp_w + 0x90 + 0x214` = **`sp_w + 0x2A4`** |
| **canary** | **`sp_w + 0x348`** |
| saved `d9/d8` | `sp_w + 0x350` |
| saved `x26…x19` | `sp_w + 0x360 … 0x390` |
| saved **FP / LR** | `sp_w + 0x3A0` / `0x3A8` |

**The struct ends exactly where the canary begins.** There is no slack.

Stride is 12, proven (the decompiler renders 24):

```
0x24eb4a60c  add     x8, x20, x20, lsl #0x1   ; 3*i
0x24eb4a610  add     x25, x21, x8, lsl #0x2   ; dst = base + 12*i
```

### 1.3 Distance to the canary — the trigger threshold

`dst_i = sp_w + 0x2A4 + 12*i`, 12 bytes written per iteration.

| `numDoubles` | last `i` | effect |
|---|---|---|
| ≤ 13 | 12 | in bounds (ends `sp_w+0x33F`) |
| **14** | **13** | `sp_w+0x340…0x34B` → **canary bytes 0–3 clobbered** |
| 15 | 14 | `sp_w+0x34C…0x357` → full canary clobbered, then into `d9/d8` |
| ≥ 22 | 21 | saved FP, then LR (never reached — canary fires first) |

Values written per slot: the 8-byte constant `0x0000000D_00000002`
(`ldr d8, [x8, #0xfd0]`) plus `str wzr, [x25, #0x8]`; optionally `+0` ← clamped
`DoubleOrder ∈ {0,1,2}` and `+8` ← clamped `ProbePatternType ∈ {0,1,2}`.

So the canary is overwritten with a **deterministic, known, tiny value**, while
`__stack_chk_guard` is a random per-process 64-bit value. Mismatch is certain.

> ### F1 (restated)
> `NumberOfDoubles ≥ 14` → canary clobbered with a known constant → `___stack_chk_fail` →
> `abort()` of the hosting camera daemon. **Confidence: PROVEN.** Deterministic: no ASLR, no
> heap layout, no guessing, no PAC bypass, no race. Trigger is a single int32 in a dictionary;
> the `DoubleOrder` consistency check is skipped when that key is absent (`fid_bracket.md` §3.4).

**PC control: REFUTED — twice over.** (a) The canary check precedes `retab`, so a clobbered
LR is never reached. (b) Even if it were, the spilled bytes yield only `{0,1,2}` and
`0x0000000D_00000002` — a non-canonical pointer.

### 1.4 The asymmetry that makes this worse

`runFaceIDAEBracketCapture` (0x24ebb8b98) has **no canary at all** — only a stack probe:

```
0x24ebb8b98  pacibsp
0x24ebb8b9c  stp     x24, x23, [sp, #-0x40]!
...
0x24ebb8bb0  mov     w9, #0x20a0
0x24ebb8bb4  adrp    x17, 0x271c4b000
0x24ebb8bb8  add     x17, x17, #0x4d8
0x24ebb8bbc  ldr     x16, [x17]
0x24ebb8bc0  blraa   x16, x17                 ; __chkstk_darwin
0x24ebb8bc4  sub     sp, sp, #0x2, lsl #0xc
```

Two sibling functions on the same Exclave data path: one got `-fstack-protector`'s canary
(the small frame), the other got only a probe (the 0x20A0 frame with the 20-entry array).
**Confidence: PROVEN.**

---

## 2. The Exclave side (`ISPExclaveKitServices`, base 0x286c5a000) — new

Binary: `/Users/pauyedin/24A435__iPhone17,5/24A435__iPhone17,5/ISPExclaveKitServices`
(arm64e, **full symbol table** — no guessing needed).

### 2.1 `ispExclaveKitCommandChFidBracketCapture` @ 0x286c6533c

Receives our command buffer. Decompiled:

```c
char var_bc_1 = *(arg1 + 0x210);        // numDoubles (the strb-truncated byte)
int64_t i_1 = 0xa;                      // <-- FIXED 10
do {
    int32_t* x13_1 = arg1 + 0x214 + ((x8_1 * 3) << 2);   // 12-byte stride
    ... clamps: {0,1,2} / (v-1 < 13 ? v : 0) / (v < 4 ? v : 1) ...
    x8_1 += 1; i = i_1; i_1 -= 1;
} while (i != 1);
```

and the marshaller `_fidflowmodule_ekfidflow_channelfidbracketcapture` @ 0x286c78dac:

```c
int64_t x21 = 0; int64_t i_1 = 0xa;
do {
    _fidflowmodule_fidbiocapturedoublet__raw_encode(&var_110, &arg2[2 + x21 * 3]);
    x21 += 1; i = i_1; i_1 -= 1;
} while (i != 1);
```

> **The Exclave loops exactly 10 times and never indexes by `numDoubles`.**
> **Confidence: PROVEN. The secure world is structurally safe on this path** — a clean negative
> that closes the "is the Exclave also vulnerable?" front.

But it is also the cleanest possible proof that the dylib's loop bound is wrong:

| consumer | entries it wants |
|---|---|
| Exclave `ChFidBracketCapture` | **10** |
| dylib's stack array capacity | 13 (`0x2A4…0x348`) |
| dylib's actual loop bound | `numDoubles`, an unvalidated **int32** |

Three different numbers; the only one enforced is none of them.

### 2.2 `ispExclaveKitCommandChAeInitBracketSettingGet` @ 0x286c67e8c — answers §8.2

```c
if (!_autoexposuremodule_ekautoexposure_channelautoexposureinitbracketsettingsget(...)) {
    result = 0;
    *(arg1 + 0x318) = var_b0_1[6];          // <-- THE COUNT
    *(arg1 + 0x324) = var_b0_1[7];
    *(arg1 + 0x320) = *(var_b0_1 + 0x34);
    *(arg1 + 0x31c) = var_b0_1[0xf] ^ 1;
}
```

`arg1 + 0x318` is **exactly** the field `runFaceIDAEBracketCapture` loads at
`0x24ebb8d30  ldr w8, [sp, #0x788]` and uses as its unvalidated trip count.
**Confidence: PROVEN — the Exclave is the producer of F2's count.**

The companion visitor, `…_block_invoke_2` @ 0x286c68144, writes the source array at
`cmdHdr + 0x32c + i*0x140` with fields at `+0x108, +0x10c, +0x110, +0x114, +0x124, +0x12c,
+0x130, +0x138, +0x13c, +0x13d, +0x13e` — a **byte-for-byte match** to what
`runFaceIDAEBracketCapture` reads. The pairing is confirmed end-to-end.

Where the count comes from: `_autoexposuremodule_ekautoexposurebracketsetting__v_visit`
@ 0x286c6e210 iterates `while (i < *(arg1 + 0x18))` decoding 0x38-byte entries from a stream —
i.e. AE-internal state, **not** client data. No cap is visible, but no client-controlled path
to it exists either. **F2 triggerability: still SPECULATIVE.**

One loose thread worth pulling: the Exclave zeroes `cmdHdr + 0x210` for `0x1a1c` bytes
(`0x2880d8770`) whereas the dylib's reply block is `bzero(IDL+4, 0x1C28)` and its array ends at
`IDL+0x1C2C`. If those are the same type they disagree by `0x100` — i.e. a possible **IDL
size skew** between the two binaries, exactly the scenario `fid_bracket.md` §8.2 speculated
about. **Confidence: SPECULATIVE** — `0x2880d8770` is an unnamed stub and I did not confirm
it is `bzero`.

---

## 3. Reachability — the gate, resolved (one field short)

`H16ISPCaptureStreamSetProperty` @ 0x24ea5346c, 218 instructions. Exact gate:

```
0x24ea535a0  ldrb    w9, [x19, #0x1]        ; stream->byte[1]
0x24ea535a4  ldr     w8, [sp, #0x2c]        ; property index
0x24ea535a8  add     x8, x8, x8, lsl #0x1   ; 3*idx
0x24ea535ac  cbnz    w9, 0x24ea535bc        ; privileged stream -> ALLOW

0x24ea535b0  add     x9, x24, x8, lsl #0x4  ; entry = props + idx*0x30
0x24ea535b4  ldrb    w9, [x9, #0x24]        ; <-- privilege byte, entry+0x24
0x24ea535b8  tbnz    w9, #0x1, 0x24ea53748  ; bit 1 set -> DENY (0xffffce6f)

0x24ea535bc  ldr     x8, [x9, #0x10]        ; setter
0x24ea535d4  blraaz  x8
```

So: `allow = stream->byte[1] || !(byte_at_entry+0x24 & 2)`.
**Confidence: PROVEN** (this settles `fid_bracket.md` §5.1's "SPECULATIVE" gate shape).

### Entry layout (from the initializer, `invocation function for block in getStreamProperties()` @ 0x24eb21c20, 4739 instrs)

Stride `0x30`; `x12 = x0 + 0x4000` (`add x12, x0, #0x4, lsl #0xc`) used once offsets exceed the
immediate range.

| off | field |
|---|---|
| `+0x00` | property-name CFString |
| `+0x08` | secondary CFString |
| `+0x10` | **setter** (`paciza`'d) |
| `+0x18` | getter (often `xzr`) |
| `+0x20` | u32 |
| `+0x24` | **u32 whose low byte carries the privilege bit** |
| `+0x28` | flags word |

### Our entry, located exactly

```
0x24eb26420  adrp    x16, 0x24eb4a000
0x24eb26424  add     x16, x16, #0x448        ; 0x24eb4a448 = SetCaptureSecureFIDBracket
0x24eb26428  paciza  x16
0x24eb2642c  str     x16, [x0, #0x4480]      ; setter slot
0x24eb26430  str     xzr, [x0, #0x4488]
0x24eb26434  str     d16, [x0, #0x4490]      ; +0x20/+0x24 pair
0x24eb26438  str     w8, [x12, #0x498]       ; +0x28 flags word
```

- index = `(0x4480 − 0x10) / 0x30` = `0x4470 / 0x30` = **365**
- `+0x28` flags word = **`w8` = `0x10`** (`mov w8, #0x10` @ 0x24eb25dc8, not redefined before use)
- privilege byte = byte 4 of `d16` @ entry `+0x24` → **not yet bound**

### The gate is genuinely selective

Other entries in the same table take flags `0x3f`, `0x1f`, `0x18`, `0x10`, `0x8`, `0x7`, `0x1`
(e.g. `mov w15,#0x3f` @ 0x24eb21c80, `mov w13,#0x1f` @ 0x24eb21cac, `mov w10,#0x18` @ 0x24eb25f94,
`mov w9,#0x8` @ 0x24eb26404). So privileges are per-property and mixed — the gate is not a
blanket "everything is privileged".

> **Remaining item (one instruction).** Find `ldr d16, …` in the initializer — it is loaded
> before offset 4050 and live until 4613, so it is a long-lived constant, not a per-entry load.
> If `d16`'s byte 4 has bit 1 **clear**, then **any** Fig client (no privilege, no entitlement)
> can set `CaptureSecureFaceIDBracket` and F1 is a directly reachable, unauthenticated DoS.
> If it is **set**, F1 requires `stream->byte[1]` — i.e. a privileged/internal Fig client, or an
> upstream Fig/CameraServices bug that launders the property name.
> Either way the overflow itself is proven; only the blast radius changes.

---

## 4. Corrected findings table

| # | Finding | Confidence | Impact |
|---|---|---|---|
| **F1′** | `SetCaptureSecureFIDBracket` 0x24eb4a448: unclamped int32 `numDoubles` writes 12 B/iter from `sp_w+0x2A4`; **`numDoubles ≥ 14` clobbers the stack canary at `sp_w+0x348`** → deterministic `abort()` | **PROVEN** | DoS, deterministic |
| **F2′** | `runFaceIDAEBracketCapture` 0x24ebb8b98: no canary (probe only); Exclave-supplied count at `IDL+0x318` unclamped vs a 20-entry/0x460 array; `count ≥ 150` reaches saved FP/LR | Missing bound **PROVEN**; producer **PROVEN (§2.2)**; triggerability **SPECULATIVE** | Critical if the AE module can emit > 20 |
| **F3′** | The Exclave consumes a **fixed 10** entries and never indexes by `numDoubles`, while the dylib allocates 13 and writes `numDoubles` — three incompatible capacities, none enforced | **PROVEN** | Explains F1 is a pure dylib bug |
| **F4′** | Exclave side of the FID bracket path is **not** vulnerable | **PROVEN (clean negative)** | Closes the secure-world front |
| **F5′** | Asymmetric hardening: F1's frame canaried, F2's (8× larger, count-driven) not | **PROVEN** | — |
| **F6′** | Dispatcher gate = `stream->byte[1] || !(byte@entry+0x24 & 2)`; our entry is index 365, flags word `0x10` | Mechanism **PROVEN**; our privilege bit **SPECULATIVE** | Reachability |

## 5. What this is, honestly

**Proven:** an out-of-bounds stack write (CWE-787 / CWE-121) in Apple's H16ISP camera plugin,
reachable through a single unvalidated 32-bit integer, with a **deterministic abort** as the
observable outcome. No memory grooming, no info leak, no PAC bypass required.

**Not proven:** that the process which can set the property is an unprivileged third-party
client. The dylib contains no entitlement strings; `kFigCaptureStreamProperty_*` is private Fig
SPI; AVFoundation exposes no surface to name it. Everything hinges on the single byte in §3.

**Not achieved, and I want to be plain about it:** code execution. Apple put two independent
controls in the way — a stack canary on F1 and PAC (`retab`) on both — and the data this loop
can spill is constants and values clamped to {0,1,2}. That is a deliberate, effective mitigation,
not an oversight I can route around. What is left is a **denial of service**, and that is what
should be reported.

## 6. Next steps, in order

1. Bind `d16` (§3) — one instruction; converts reachability from SPECULATIVE to settled.
2. Confirm `0x2880d8770` is `bzero` and compare the Exclave/dylib reply-struct sizes (§2.2) —
   a genuine skew would upgrade F2 from SPECULATIVE to reachable.
3. Determine what sets `stream->byte[1]` — the other half of the gate.
4. Write the crash PoC against a Fig client that can name the property; expected signature is
   `SIGABRT` with `__stack_chk_fail` on the stack, `NumberOfDoubles = 14`, no `DoubleOrder` key.
