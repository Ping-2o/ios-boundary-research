> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# USB XHCI "CommandRing" ring-machinery audit — iOS 27.0 RC (24A435), iPhone17,5

**Target:** `com.apple.driver.usb.AppleSynopsysUSB40XHCI`
(active Binary Ninja view; `__TEXT_EXEC.__text` = `0xfffffff00a6b5e70` + `0x796a4`)

**Tooling:** Binary Ninja MCP only (read-only). No `bn_binary_view_set_active`, no `bn_open_item_open`.
String→code location done with `scripts/ds_locate_strrefs.py` (locator only); all analysis in BN.
Widths confirmed in `bn_function_disassembly` (the HLIL mis-renders 32-bit ops as 64-bit).

---

## 0. Headline result

> **There is no TRB / ring-index / cycle-bit / doorbell / DMA-length code in this kext.**
> The `…USBXHCICommandRing` classes are *host-controller* subclasses (instance size 0x1868 =
> 6248 B) whose only non-boilerplate overrides are `addEndpoint` / `updateEndpoint`
> endpoint-interval quirk workarounds. The XHCI ring engine lives in the **separate**
> `com.apple.driver.usb.AppleUSBXHCI` kext.

Evidence for the negative (all reproducible):

| Probe | This kext | `com.apple.driver.usb.AppleUSBXHCI` |
|---|---|---|
| strings matching `TRB` | **0** (of 1767 strings) | **43** |
| strings matching `doorbell` | **0** | **5** |
| strings matching `equeue` (enqueue/dequeue) | **0** | **8** |
| strings matching `ring` (case-insensitive) | class names only (`…USBXHCICommandRing`) | **66** |
| strings matching `ransfer` | **0** | — |
| `bn_function_search "CommandRing"` | 0 symbols (kext fully stripped) | — |

The `ring`/`TRB`/`doorbell` counts for the sibling kext were obtained with `strings` on
`/Users/pauyedin/24A435__iPhone17,5/kexts/com.apple.driver.usb.AppleUSBXHCI` (locator use only).

**Consequence for the assignment:** items 2–5 (index mask/compare, wrap/cycle bit, DMA
programming, TRB-vs-buffer length) have **no substrate in this binary**. A clean negative is the
correct result; below I give the evidence, then the only real structural divergence I found.

---

## 1. The new class: `AppleT8152USBXHCICommandRing`

Class-name string `0xfffffff007ade3d8`; kalloc-site string `0xfffffff007ade3f5`
(`site.AppleT8152USBXHCICommandRing`). Seven code references (from `ds_locate_strrefs.py`):
`0xa6b5e84, 0xa6b5fc8, 0xa6b633c, 0xa6b63ac, 0xa6b6540, 0xa6b65b0, 0xa6b6664`.

**Translation unit = `0xfffffff00a6b5e70 .. 0xfffffff00a6b66ab`** (the very first 0x83C bytes of
`__TEXT_EXEC.__text`). Bounded on both sides: it starts at the section start, and the next
function `0xfffffff00a6b66ac` is the `AppleT6000USBXHCI` constructor
(`sub_a72f5c4(arg1, "AppleT6000USBXHCI", &data_fffffff00b989ae8, 0x1030)`).

| VA | size | role (from decompilation) |
|---|---|---|
| `0xfffffff00a6b5e70` | 0x4b | ctor A: `sub_a72f5c4(arg1, "AppleT8152USBXHCICommandRing", 0x100000049869d8, 0x1868)`; `*obj = &data_fffffff00837d968` |
| `0xfffffff00a6b5ebc` | 0x08 | `int64_t()` — trivial getter/stub |
| `0xfffffff00a6b5ec4` | 0x38 | alloc + install vtable `0xfffffff00837d818` |
| `0xfffffff00a6b5efc` | 0x38 | alloc + install vtable `0xfffffff00837d818` (duplicate) |
| `0xfffffff00a6b5f34` | 0x08 | trivial |
| `0xfffffff00a6b5f3c` | 0x08 | trivial |
| `0xfffffff00a6b5f44` | 0x48 | `operator new`: tailcall `sub_a72f594(&data_fffffff008383df0, arg1, 0x1868)` |
| `0xfffffff00a6b5f8c` | 0x18 | `int64_t(arg1,arg2)` stub |
| `0xfffffff00a6b5fa4` | 0x10 | `int64_t()` stub |
| `0xfffffff00a6b5fb4` | 0x4b | ctor B — **byte-identical in behaviour to ctor A** |
| `0xfffffff00a6b6000` | 0x6c | `sub_a72f5a4(&data_fffffff008383df0, 0x1868)`; vtable `0x837d818`; `sub_a72f734(&data_fffffff00b9898b8)` |
| `0xfffffff00a6b606c` | 0x14 | `int64_t(arg1)` stub |
| `0xfffffff00a6b6080` | 0x5c | placement-init: `*f(arg1,&data_b9898b8) = &data_837d818`; `sub_a72f734(&data_b9898b8)` |
| `0xfffffff00a6b60dc` | 0x5c | identical to `0xa6b6080` |
| `0xfffffff00a6b6138` | 0x100 | **factory `with…(a,b,c,d)`**: kalloc 0x1868 → vtable `0x837d818` → `(*vt[0x110])(obj,a,b,c,d)`; on failure `(*vt[0x28])(obj)` (release) and return NULL |
| `0xfffffff00a6b6238` | 0x204 | **`addEndpoint` override** |
| `0xfffffff00a6b643c` | 0x204 | **`updateEndpoint` override** |
| `0xfffffff00a6b6640` | 0x08 | trivial |
| `0xfffffff00a6b6648` | 0x54 | `sub_a72f5c4(&data_fffffff00b9898b8, "AppleT8152USBXHCICommandRing", 0x100000049869d8, 0x1868)`; vtable `0x837d968` |
| `0xfffffff00a6b669c` | 0x10 | trivial |

* `0xfffffff008383df0` = start of `__DATA_CONST.__kalloc_type`; `0xfffffff00b9898b8` = a static in
  `__DATA.__common` (`0xfffffff00b9898a8` + 0x268).
* Two vtables appear: `0xfffffff00837d968` (ctor path) and `0xfffffff00837d818` (alloc/factory
  path). I could **not** resolve vtable slot targets: `bn_memory_read` of
  `__DATA_CONST.__const` returns unresolved KC values (e.g. slot 0 reads
  `0x80113771036b1ebc`, which is below `__TEXT_EXEC` start and therefore not the fixup-resolved
  pointer). `bn_data_xrefs_*` are empty in this view. **The method list above is derived from the
  TU code, not from the vtable.** Do not trust any vtable-slot enumeration in this kext.

**Instance size = 0x1868 (6248) bytes.** That is a *controller-sized* object, not a ring struct —
confirming these "CommandRing" classes are host-controller classes (they override
`addEndpoint`/`updateEndpoint`, which are `IOUSBController` virtuals).

---

## 2. Index arithmetic / wrap / cycle bit — **NOT PRESENT**

Requested audit: "for every place a producer/consumer index is advanced: is the index masked…?"

**Result: zero sites.** Every function in the T8152 CommandRing TU is either kalloc/vtable
boilerplate or the interval clamp. There is no enqueue pointer, no dequeue pointer, no `& (n-1)`
mask, no cycle-bit test, no doorbell register write anywhere in the TU.

The only integer arithmetic on a *bounded* field is the interval clamp (§4), and it uses
**32-bit, unsigned, non-truncated** operations throughout:

```
0xfffffff00a6b62bc  ldr   w8, [x19]              ; 32-bit load
0xfffffff00a6b62c0  tst   w8, #0xfc0000
0xfffffff00a6b62c4  b.eq  0xfffffff00a6b63ec
0xfffffff00a6b62c8  ldr   w8, [x19]
0xfffffff00a6b62cc  ubfx  w8, w8, #0x10, #0x8    ; zero-extend 8-bit field — explicit
0xfffffff00a6b62d0  cmp   w8, #0x6
0xfffffff00a6b62d4  b.hi  0xfffffff00a6b63ec     ; UNSIGNED > (b.hi, not b.gt)
...
0xfffffff00a6b63d8  and   w8, w8, #0xff00ffff
0xfffffff00a6b63dc  str   w8, [x19]              ; 32-bit store
0xfffffff00a6b63e4  orr   w8, w8, #0x30000
0xfffffff00a6b63e8  str   w8, [x19]              ; 32-bit store
```

No `uxtw`/`uxth`-truncated 64-bit value is ever used as an offset; no 64→32 truncation hazard
(the decompiler's `int32_t*` types match the disassembly's `w` registers). **Clean negative.**

---

## 3. DMA programming path — **NOT PRESENT**

No ring base physical-address programming, no ring-size/TRB-count register write, no
`IODMACommand`/mapper setup, and no "TRB length vs. buffer length" comparison exists in this
kext. The kalloc site allocates a **single 0x1868-byte object** — there is no separate ring
allocation whose size could disagree with a programmed TRB count.

---

## 4. The one real divergence: the endpoint-interval clamp

`addEndpoint`/`updateEndpoint` take `arg4` (endpoint descriptor–derived word) and
`arg5` → a two-dword XHCI endpoint context: `arg5[0]` bits 23:16 = **Interval**, `arg5[1]`
bits 5:3 = **EP Type** (0x18 = EP-type 3 Interrupt-OUT, 0x38 = 7 Interrupt-IN,
0x8 = 1 Isoch-OUT, 0x28 = 5 Isoch-IN). *(Field naming is my interpretation of the XHCI spec; the
bit patterns and shifts are literal from the disassembly.)*

### 4a. Family 1 — `0xfffffff00a6cb9f4` / `0xa6cbd24` (28 basic blocks), logs `"AppleUSBXHCICommandRing"`

Two clamps. EP-type dispatch uses **runtime-loaded** constants:
```
0xfffffff00a6cba30  ubfx  w9, w8, #0x14, #0x4
0xfffffff00a6cba34  ldr   x8, [x23, #0x1868]     ; table pointer from the object
0xfffffff00a6cba38  ldr   w10, [x8, #0x680]      ; runtime EP-type A
0xfffffff00a6cba3c  cmp   w9, w10
```
Clamp 1 — Interrupt IN/OUT, Interval ≥ 4 → 3 (8 µFrames), **no upper bound**:
```
0xfffffff00a6cba84  ldr   w8, [x19]
0xfffffff00a6cba88  tst   w8, #0xfc0000          ; interval >= 4 ?
0xfffffff00a6cba8c  b.eq  0xfffffff00a6cbb0c     ; no -> fall into clamp 2
```
Clamp 2 — **Isoch IN/OUT with Interval ≥ 6 → 5 (32 µFrames)** (this branch does not exist
anywhere else in the kext):
```
0xfffffff00a6cbb0c  ldr   w8, [x19, #0x4]
0xfffffff00a6cbb10  and   w8, w8, #0x38
0xfffffff00a6cbb14  cmp   w8, #0x28              ; Isoch IN
0xfffffff00a6cbb18  b.eq  0xfffffff00a6cbb2c
0xfffffff00a6cbb1c  ldr   w8, [x19, #0x4]
0xfffffff00a6cbb20  and   w8, w8, #0x38
0xfffffff00a6cbb24  cmp   w8, #0x8               ; Isoch OUT
0xfffffff00a6cbb28  b.ne  0xfffffff00a6cbcd4
0xfffffff00a6cbb2c  ldr   w8, [x19]
0xfffffff00a6cbb30  and   w8, w8, #0xfe0000
0xfffffff00a6cbb34  cmp   w8, #0x50, lsl #0xc    ; 0x50000
0xfffffff00a6cbb38  b.ls  0xfffffff00a6cbcd4     ; <= 5 -> skip   (b.ls = unsigned <=)
...
0xfffffff00a6cbcb8  mov   w8, #0x50000           ; interval := 5
0xfffffff00a6cbcc0  and   w9, w9, #0xff00ffff
0xfffffff00a6cbcc4  str   w9, [x19]
0xfffffff00a6cbccc  orr   w8, w9, w8
0xfffffff00a6cbcd0  str   w8, [x19]
```

### 4b. Family 2 — `0xfffffff00a70abc8` / `0xa70adc4` (18 blocks), also logs `"AppleUSBXHCICommandRing"`

Runtime EP-type dispatch, clamp 1 only, **no `<=6` gate, no isoch clamp**.

### 4c. Family 3 — the T81xx variants, incl. the new T8152 (20 blocks)

Hard-coded EP-type constants; clamp 1 **gated by `interval <= 6`**; **no isoch clamp**:
```
0xfffffff00a6b6270  ldr   w8, [x20]
0xfffffff00a6b6274  and   w8, w8, #0xf00000
0xfffffff00a6b6278  cmp   w8, #0x400, lsl #0xc   ; 0x400000
0xfffffff00a6b627c  b.ne  0xfffffff00a6b6288
...
0xfffffff00a6b6290  and   w8, w8, #0xf00000
0xfffffff00a6b6294  cmp   w8, #0x500, lsl #0xc   ; 0x500000
```

| Variant | addEndpoint | updateEndpoint | blocks | EP-type dispatch | `interval<=6` gate | isoch clamp |
|---|---|---|---|---|---|---|
| "AppleUSBXHCICommandRing" A | `0xfffffff00a6cb9f4` | `0xfffffff00a6cbd24` | 28 | runtime `[+0x680]/[+0x684]` | **no** | **YES** |
| "AppleUSBXHCICommandRing" B | `0xfffffff00a70abc8` | `0xfffffff00a70adc4` | 18 | runtime `[+0x680]/[+0x684]` | **no** | no |
| T8132 | `0xfffffff00a6f6440` | `0xfffffff00a6f6644` | 20 | hard-coded 4/5 | **yes** | no |
| T8142 | `0xfffffff00a6cc488` | `0xfffffff00a6cc68c` | 20 | hard-coded 4/5 | **yes** | no |
| **T8152 (NEW)** | **`0xfffffff00a6b6238`** | **`0xfffffff00a6b643c`** | 20 | hard-coded 4/5 | **yes** | no |

Decompilations of T8132 (`0xa6f6440`) and T8142 (`0xa6cc488`) are **structurally identical** to
T8152 (`0xa6b6238`) — differing only in the class-name string passed to the logger.

---

## 5. Candidate findings, ranked

### C1 — Missing isochronous interval clamp in T8152 `addEndpoint` / `updateEndpoint`
* **Address:** `0xfffffff00a6b6238` / `0xfffffff00a6b643c` (identical logic).
* **Write:** `*arg5 = (*arg5 & 0xff00ffff) | 0x30000` at `0xa6b63d8-0xa6b63e8`.
  The *missing* write is `*arg5 = (*arg5 & 0xff00ffff) | 0x50000` present at
  `0xfffffff00a6cbcb8-0xa6cbcd0` in family 1.
* **Controlling input:** Endpoint Interval field, derived from the USB endpoint descriptor
  `bInterval` supplied by the attached device (malicious/compromised accessory is the threat
  model). Isoch IN/OUT, Interval ≥ 6.
* **Consequence:** A value the base class refuses to program (Interval ≥ 6 on an isochronous
  endpoint) is passed through unmodified on T8152. This changes host-controller scheduling and
  periodic-bandwidth accounting. **No memory-safety impact identified.**
* **Confidence: SPECULATIVE.** The code divergence is *proven* (bit-exact, quoted above), but
  (a) it is **not T8152-specific** — pre-existing T8132/T8142 are identical, so it is not a new
  regression; and (b) no memory-corruption path follows from an unclamped interval.

### C2 — Interrupt clamp gated to `interval <= 6` on the T81xx family
* **Address:** `0xfffffff00a6b62cc-0xa6b62d4` (`ubfx` … `cmp w8,#0x6` … `b.hi`).
* **Effect:** for Interrupt IN/OUT endpoints with Interval 7..255, T81xx does **not** force
  Interval → 3, whereas family 1/2 do. Direction is *more permissive* on the variants.
* **Consequence:** same class as C1 (scheduling/bandwidth), no memory safety.
* **Confidence: SPECULATIVE** — same reasoning; also not T8152-specific.

### C3 — `1 << interval` 32-bit shift by an 8-bit (0..255) value — **REFUTED**
* `0xfffffff00a6b6318-0xa6b6324` and `0xa6b6388-0xa6b6394`:
  `lsr w8,w8,#0x10` → `lsl w8,w9,w8` (w9=1).
* AArch64 `lsl` of a 32-bit register masks the shift to 5 bits, so large intervals wrap rather
  than fault, and the result is **only** stored into the os_log argument frame
  (`stp x8,x9,[sp,#0x18]`). No control flow or allocation depends on it. Not a bug.

### C4 — Family 1/2 dereference `this` without a NULL test — **REFUTED**
* `0xfffffff00a6cba90 ldr w8,[x23,#0x1860]` (no `cbz`), vs T8152 `0xfffffff00a6b62d8 cbz x23`.
  The variants are *safer*. `this` cannot be NULL through a virtual dispatch. Not a bug.

### C5 — Family 1/2 read a pointer at `this + 0x1868`, i.e. 8 bytes past the 0x1868-byte
T81xx allocation — **REFUTED / not reachable**
* `0xfffffff00a6cba34 ldr x8,[x23,#0x1868]`, dereferenced at `+0x680`/`+0x684`.
* This would be an 8-byte over-read **only if** the object were the 0x1868-byte T81xx class. It
  is a different, larger class (it also owns field `+0x1860` used at `0xa6cba90`), and the T81xx
  code never executes this path (hard-coded EP-type constants). Not reachable from T8152.

### C6 — Ring index / wrap / cycle bit / doorbell / TRB-vs-buffer length — **REFUTED (absent)**
* No such code exists in this kext (§0, §2, §3). The ring engine is in
  `com.apple.driver.usb.AppleUSBXHCI`.

---

## 6. Limitations & honest gaps

1. **Vtable contents unresolvable** in this view (unfixed `__DATA_CONST` pointers, empty data
   xrefs). Method enumeration is code-derived; a method reachable only via an unresolved vtable
   slot could have been missed in principle — but the TU is contiguous and fully bounded.
2. **Not audited:** the 84 KB `AppleT8152USBXHCI` TU (`0xfffffff00a6cc910` – `0xfffffff00a6e150c`,
   287 references to the `"AppleT8152USBXHCI"` string). That is the actual new-silicon body and
   contains the power/phy/CIO/tunable code, not the ring. If a second agent has not taken it, it
   is the better place to look for a *new-code* bug.
3. **Unverified lead (not a candidate):** the interval value feeds periodic-bandwidth accounting
   (`getPeriodicBandwidthUsage`, string `0xfffffff007adffda`, and the
   `"floor bandwidth: %u safe bandwidth: %u"` family). Whether an unclamped isoch interval can
   overflow that accounting was **not** checked. That is the only path by which C1/C2 could become
   security-relevant, and it is the recommended next step.
4. `bn_function_search` finds nothing (kext is stripped); `bn_symbol_list` returns 0 symbols.

---

## 7. Verdict

The "new command-ring class is a DMA / ring-index target" hypothesis does **not** survive contact
with the binary: `AppleT8152USBXHCICommandRing` is a 6248-byte host-controller class whose entire
non-boilerplate contribution is 2 × 0x204-byte `addEndpoint`/`updateEndpoint` overrides that
rewrite one 8-bit field of an endpoint context. There are **no index-advance sites, no wrap or
cycle-bit handling, no doorbell write, and no DMA length check** in this kext. The single
structural divergence (missing isochronous interval clamp, C1) is real and bit-exact, but is
shared byte-for-byte with the pre-existing T8132/T8142 variants and has no identified
memory-safety consequence.
