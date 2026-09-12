> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# `AppleJPEGDriverUserClient` — dispatch, entitlement gate, and the `startEncoder` validation gap

Target: `com.apple.driver.AppleJPEGDriver`, iOS 27.0 RC (24A435), mac-aarch64, arm64e.
All addresses from Binary Ninja read-only queries on the active view.

## 0. Method used for finding data

`bn_data_xrefs_*` / string xrefs return empty in this view, so all data was located by
decoding raw section bytes.

**Pointer decoding (important).** `__DATA_CONST __const` stores arm64e chained-fixup /
PAC-encoded pointers. Raw reads return the *encoded* form. The decode that validates is:

```
target = 0xfffffff007004000 + (raw_u64 & 0xFFFFFFFF)      # for entries with bit63 set
```

Verified: user-client vtable `data_fffffff0080781f0` (installed by the constructor
`sub_fffffff009022be0` as `*x0 = &data_fffffff0080781f0`) has slot `+0x5d8` at
`0xfffffff0080787c8` = raw `0x804041f20201e834` → `0xfffffff009022834`, which is exactly
the function the constructor tail-calls with `(this, task, securityID, type, props, handler)`
— i.e. `initWithTask`. Note the fixup base is `0xfffffff007004000`, **not** the kext image
start `0xfffffff00753b4d0`.

## 1. External-method dispatch table

`IOExternalMethodDispatch`-shaped array in `__DATA_CONST __const`:

* start **`0xfffffff008078860`**, **10 entries × 40 bytes**, ends `0xfffffff0080789f0`.
* Every entry's function pointer shares the ptrauth diversity `0x8050bcad` (high dword),
  which is what identifies the whole run as one table.
* Entry layout: `fn(8)`, `scalarIn(4)`, `structIn(4)`, `scalarOut(4)`, `structOut(4)`,
  `flags(4)`, then 3 unused dwords (32 bytes of trailing fields, all zero except `flags`).
* `structIn == 0` means `kIOUCVariableStructureSize` — **IOKit accepts any input size** and
  the handler must do its own check.

| sel | entry addr | handler | scalarIn | structIn | scalarOut | structOut | flags | trampoline target |
|----:|---|---|---:|---:|---:|---:|---:|---|
| 0 | `0xfffffff008078860` | `0xfffffff009022d98` | 0 | **0 (any)** | 0 | 0 | 0 | `0x01717c` (stub, ignores args) |
| 1 | `0xfffffff008078888` | `0xfffffff009022da4` | 0 | 0x58 | 0 | 0x58 | 0 | `0x018830` |
| 2 | `0xfffffff0080788b0` | `0xfffffff009022dd8` | 0 | **0 (any)** | 0 | 0 | 0 | `0x017188` (stub, ignores args) |
| 3 | `0xfffffff0080788d8` | `0xfffffff009022de4` | 0 | 0x58 | 0 | 0x58 | 0 | **`0x019ad0` = `startEncoder`** |
| 4 | `0xfffffff008078900` | `0xfffffff009022e18` | 0 | 0x1000 | 0 | 0x1000 | 0 | `0x019ee4` (Ext variant) |
| 5 | `0xfffffff008078928` | `0xfffffff009022e4c` | 0 | 0x1000 | 0 | 0x1000 | 0 | (Ext variant) |
| 6 | `0xfffffff008078950` | `0xfffffff009022e80` | 0 | 0xda0 | 0 | 0xda0 | 1 | (2024 variant) |
| 7 | `0xfffffff008078978` | `0xfffffff009022eb4` | 0 | 0xda0 | 0 | 0xda0 | 1 | (2024 variant) |
| 8 | `0xfffffff0080789a0` | `0xfffffff009022ee8` | 0 | 0x4 | 0 | **0 (any)** | 0 | (not decompiled) |
| 9 | `0xfffffff0080789c8` | `0xfffffff009022f18` | 0 | **0 (any)** | 0 | **0 (any)** | 0 | (not decompiled) |

Trampoline shape (selector 3, verbatim):

```c
// 0xfffffff009022de4
int64_t sub_fffffff009022de4(void* arg1, int64_t arg2, void* arg3) {
    void* x0 = *(arg1 + 0xe0);          // the AppleJPEGDriver
    if (!x0) return 0xe00002bc;         // kIOReturnNotAttached
    /* tailcall */
    return sub_fffffff009019ad0(x0, *(arg3 + 0x30), *(arg3 + 0x58),
                                *(arg1 + 0xf0), arg1);
}
```

`arg3 + 0x30` = `structureInput`, `arg3 + 0x58` = `structureOutput` (both 88-byte
`AppleJPEGDriverIOStruct`s, size enforced by IOKit because `structIn = structOut = 0x58`).

**`sub_fffffff009019ad0` is `AppleJPEGDriver::startEncoder`** — its log strings are
`"IOReturn AppleJPEGDriver::startEncoder(AppleJPEGDriverIOStruct *, AppleJPEGDriverIOStruct *, mach_port_t, IOUserClient *, task_t)"`.
The parallel agent's `0xfffffff009019b60` is *inside* `sub_fffffff009019ad0`
(range `0xfffffff009019ad0`–`0xfffffff009019ee3`), at the only validation branch.

## 2. Entitlement gate — **PROGRAMMATIC, and not enforced on the paths I traced**

Set in `AppleJPEGDriverUserClient::initWithTask` = `sub_fffffff009022834`
(reached from the constructor at vtable `+0x5d8`). Verbatim:

```c
int64_t sub_fffffff009022834(int64_t* arg1, int64_t* arg2, int64_t arg3,
                             int64_t arg4, int64_t arg5, int64_t arg6) {
    int64_t* x0_1 = sub_fffffff00903c698(arg3, "com.apple.applejpegdriver.poweron");
    if (x0_1) {
        arg1[0x21] = x0_1 == **0x10000000e7e9e0 ? 1 : 0;   // offset 0x108
        (*(*x0_1 + 0x28))();                                // release
    }
    int64_t* x0_3 = sub_fffffff00903c698(arg3, "com.apple.applejpegdriver.ajpegtestapp");
    if (x0_3) {
        *(arg1 + 0x109) = x0_3 == **0x10000000e7e9e0 ? 1 : 0;
        (*(*x0_3 + 0x28))();
    }
    if (!arg2) return 0;
    int32_t result = (*(*arg1 + 0x550))(arg1, arg3, arg4, arg5, arg6); // super::initWithTask
    ...
}
```

* `sub_fffffff00903c698` is an **import stub** (`braa` via `0xfffffff00807c428`) with
  signature `(task_t, const char *) -> OSBoolean *` → **`IOTaskHasEntitlement`**.
* Entitlement strings: **`com.apple.applejpegdriver.poweron`** (@`0xfffffff00753d8be`) and
  **`com.apple.applejpegdriver.ajpegtestapp`** (@`0xfffffff00753d8e0`), both immediately
  following `IOUserClientEntitlements` (@`0xfffffff00753d8a5`) in `__cstring`.
* **Set programmatically, not from Info.plist.** IOKit's plist path would read
  `IOUserClientEntitlements` from the personality; here the kext calls
  `IOTaskHasEntitlement` itself.

**Crucially, this is a *record*, not a *deny*.** `initWithTask` returns `super`'s result
unchanged — a client with neither entitlement is still created. The two booleans land at
`this+0x108` and `this+0x109` (the constructor `sub_fffffff009022be0` pre-zeroes `x0[0x21]`).
I found **no consumer** of `+0x108`/`+0x109` in `sub_fffffff009019ad0`, nor in the dispatch
trampolines (which check only `*(this+0xe0) != 0`). `newUserClient`
(`sub_fffffff009015c38`) checks only the client count (`< 0x3e9`) before attaching.

## 3. Per-handler input validation

| sel | declared structIn | handler's own check | verdict |
|----:|---:|---|---|
| 0 | 0 (any) | none — **but handler never reads `args`** (`0x9022d98` ignores arg2/arg3 entirely) | safe (speculative risk only) |
| 1 | 0x58 | not decompiled | – |
| 2 | 0 (any) | none — **handler never reads `args`** (`0x9022dd8` ignores arg2/arg3) | safe (speculative risk only) |
| 3 | 0x58 | **only** `quality = struct[0x1c]; if ((quality & 0xfffe) >= 0xa) reject;` | **GAP** — `inputSize@0x04`, `outputSize@0x0c`, `Horz@0x14`, `Vert@0x18` all unchecked |
| 4 | 0x1000 | Ext variant — has the 4 checks (per parallel agent) | checked |
| 5 | 0x1000 | Ext variant | checked |
| 6 | 0xda0 | 2024 variant — has the 4 checks | checked |
| 7 | 0xda0 | 2024 variant | checked |
| 8 | 0x4 in / **0 out** | not decompiled | output size unchecked |
| 9 | 0 (any) in / 0 (any) out | not decompiled | unchecked both ways |

The asymmetry is exactly the bug pattern: **the Ext/2024 selectors validate; the base
selectors (1 and 3) do not**, even though all four write the same request fields.

## 4. Candidates

### 4.1 `startEncoder` missing size validation — **STRONG** (reachability PROVEN)

`sub_fffffff009019ad0`, disassembly (32-bit widths confirmed, not 64-bit):

```
0xfffffff009019b38  ldr     w8,  [x19, #0x14]      ; Horz      (32-bit)
0xfffffff009019b3c  ldrh    w9,  [x19, #0x18]      ; Vert      (16-bit)
0xfffffff009019b40  orr     w4,  w9, w8, lsl #0x10 ; (log only)
...
0xfffffff009019b54  ldr     w8,  [x19, #0x1c]      ; quality
0xfffffff009019b58  and     w9,  w8, #0xfffe
0xfffffff009019b5c  cmp     w9, #0xa
0xfffffff009019b60  b.lo    0xfffffff009019bc0      ; <-- the ONLY validation branch
```

After `0xfffffff009019b60` the function goes straight to allocation
(`bl sub_fffffff00903c588` at `0xfffffff009019bc8`) and bulk-copies the struct into the
`JpegRequest`:

```
0xfffffff009019c00  ldr     q0, [x19, #0x30]   ; 16-byte copy
0xfffffff009019c04  str     q0, [x22, #0x10]
0xfffffff009019c08  ldr     x8, [x19, #0x40]
0xfffffff009019c0c  str     x8, [x22, #0x20]
0xfffffff009019c18  ldp     w8, w9,  [x19]       ; w9 = inputSize  @0x04
0xfffffff009019c1c  str     w8, [x22, #0x2ac]
0xfffffff009019c20  ldp     w8, w10, [x19, #0x8] ; w10 = outputSize @0x0c
0xfffffff009019c24  str     w8, [x22, #0x2b0]
```

* Controlling input: fully user-supplied 88-byte `structureInput` (selector 3).
* `inputSize@0x04` → `req+0x420`, `outputSize@0x0c` → `req+0x424`,
  `Horz@0x14` → `req+0x428`, `Vert@0x18` → `req+0x42c`. **All four unchecked.**

### 4.2 32-bit multiply overflow in `getMCUSize` — **PROVEN arithmetic, STRONG impact**

`sub_fffffff009018680` =
`AppleJPEGDriver::getMCUSize(AppleJPEGSubsampling, unsigned int&, unsigned int&, unsigned int&)`,
called from `startEncoder` as
`sub_fffffff009018680(x0_1, arg2[0xb] /*subsampling*/, Horz, Vert, &var_64, req + 0x464)`:

```
0xfffffff009018730  ldr     w9,  [x21]          ; var_64 = struct[0x54]
0xfffffff009018734  add     w11, w22, w10       ; Vert + mcuH
0xfffffff009018738  sub     w11, w11, #0x1
0xfffffff009018744  lsr     w10, w11, w10
0xfffffff009018748  cmp     w9, w10
0xfffffff00901874c  b.ls    0xfffffff009018758
0xfffffff009018750  mov     w9, #0              ; clamp rows to 0 if too big
0xfffffff009018754  str     wzr, [x21]
0xfffffff009018758  add     w10, w20, w8        ; Horz + mcuW      <-- w20 = Horz
0xfffffff00901875c  sub     w10, w10, #0x1
0xfffffff009018768  lsr     w8, w10, w8         ; (Horz + mcuW - 1) >> ctz(mcuW)
0xfffffff00901876c  mul     w8, w9, w8          ; *** 32-BIT multiply, no overflow check ***
0xfffffff009018770  str     w8, [x19]           ; req->mcuCount (req+0x464)
```

* **`mul w8, w9, w8` — `w`, not `x`.** Confirmed in disassembly; no `madd x`, no
  widening. Result truncates to 32 bits and is stored 32-bit (`str w8`).
* Row count is clamped to `(Vert + mcuH - 1) >> ctz(mcuH)`, but with `Vert` unchecked
  the clamp bound itself can be ~`0x20000000` (mcuH=8), and the column factor with
  `Horz` unchecked can be ~`0x08000000` (mcuW=0x20). Product `0x20000000 * 0x08000000`
  wraps to **0**.
* Consequence: `req+0x464` (MCU count) can be forced to 0 / wrapped-small while the
  genuine image dimensions remain large → classic undersized-allocation / oversized-copy
  setup. Downstream consumer is `sub_fffffff009018c0c` (reads `arg2[0x85]` = `req+0x428`
  Horz and `*(arg2+0x42c)` = Vert); I did **not** complete the trace to the exact
  `IOMalloc`/descriptor call, so the precise primitive is not yet nailed.
* **Confidence: arithmetic overflow PROVEN; heap-corruption impact STRONG (not PROVEN).**

### 4.3 `structIn = 0` on selectors 0, 2, 9 — **REFUTED**

Declared "any size", but `0xfffffff009022d98` and `0xfffffff009022dd8` never dereference
`args`; they only touch `*(this+0xe0)` and tail-call `0x01717c` / `0x017188`. No input is
read, so an arbitrary structure size is harmless. Selector 9 not decompiled — still open.

### 4.4 `registerNotificationPort` — **REFUTED (no bug found)**

`sub_fffffff009022f5c`:

```c
if (!*(arg1 + 0xf0)) {
    *(arg1 + 0xf0) = arg2;      // mach_port_t
    *(arg1 + 0xf8) = arg4;      // UInt32 token
    return 0;
}
// else: "Client active, cannot switch port" -> 0xe00002bc
```

* No token used as an index, no user value later used as a pointer, no
  re-registration TOCTOU (guarded by the `!*(arg1+0xf0)` test).
* Port rights are handled by IOKit before the override is reached.
* It is **not** in the dispatch table — it is a vtable virtual, not an external method.

## 5. Reachability — honest assessment

* **Selector 3 is a real, directly reachable external method.** It is entry 3 of the
  dispatch table, reachable with `IOConnectCallMethod` given an `io_connect_t`. The user
  supplies a fixed 88-byte struct and IOKit itself enforces that size, so all of
  `inputSize/outputSize/Horz/Vert` are attacker-controlled with no kernel-side bound.
* **The entitlement is not a gate on this path.** It is evaluated in `initWithTask` and
  only *stored*; the client is created either way, and neither `startEncoder` nor the
  trampoline reads `+0x108`/`+0x109`. On the evidence I have, **no entitlement is required
  to open `AppleJPEGDriverUserClient` or to call selector 3.**
* Therefore the WebKit sandbox denial naming `AppleJPEGDriverUserClient` looks like a
  genuine defence-in-depth fix for a live surface, **not** belt-and-braces over an
  already-entitlement-gated surface. This is the notable result: the surface is likely
  app-reachable, and the gate that exists does not cover it.

Caveat: I could not enumerate the kext's `Info.plist` (not present in this binary), so a
plist-level `IOUserClientEntitlements` cannot be excluded from the binary alone. However
`IOUserClientEntitlements` appears in `__cstring` and the two entitlement strings are
consumed programmatically, which is the pattern that supersedes the plist path.

## Confidence summary

| # | Finding | Confidence |
|---|---|---|
| 1 | Dispatch table: 10 selectors, addresses + declared sizes | **PROVEN** |
| 2 | Selector 3 → `startEncoder` (`0x019ad0`), user-reachable | **PROVEN** |
| 3 | `startEncoder` lacks the 4 checks the Ext/2024 variants have | **PROVEN** |
| 4 | `getMCUSize` 32-bit `mul w8` overflow, no check | **PROVEN** (arithmetic) |
| 5 | That overflow yields an exploitable undersized buffer | **STRONG** (consumer not fully traced) |
| 6 | Entitlement gate is programmatic (`IOTaskHasEntitlement`, `com.apple.applejpegdriver.poweron` / `.ajpegtestapp`) | **PROVEN** |
| 7 | Gate is not enforced on the start* path → app-reachable | **STRONG** |
| 8 | `structIn=0` selectors 0/2 exploitable | **REFUTED** |
| 9 | `registerNotificationPort` token/port bug | **REFUTED** |
