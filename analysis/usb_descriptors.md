> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# USB descriptor / endpoint-state audit — `com.apple.driver.usb.AppleSynopsysUSB40XHCI`
### iOS 27.0 RC (24A435) · Binary Ninja only · image base `0xfffffff007addd10`

Scope assigned: descriptor parsing, endpoint/device state, "rest of the new code",
plus the new `AppleT8152USBXHCI` TU (~`0xfffffff00a6cc910`–`0xfffffff00a6e150c`)
and the isoch interval / periodic-bandwidth lead.

Read-only view. No `bn_binary_view_set_active`, no `bn_open_item_open`.

---

## 0. TL;DR

| Item | Result |
|---|---|
| Descriptor parsing (device/config/interface/endpoint/string/HID/BOS/SS) | **ABSENT from this kext — clean negative.** No `bLength`/`wTotalLength` validation exists because no descriptor is ever parsed here. |
| Count-driven loops from `bNumInterfaces` / `bNumEndpoints` / `bNumConfigurations` | **None exist.** Only loop is a NULL-terminated endpoint linked list. |
| Endpoint array indexing | 3 sites, index = `8 \| (epnum << 4)` off `this + 0x6b0`. **No mask and no bound at the site.** Bound is inherited from an out-of-binary virtual call. SPECULATIVE. |
| String descriptors (UTF-16 → char) | **None in this kext.** |
| HID / report descriptors | **None** (zero `hid`/`report` strings). |
| Interval trace (`1 << interval`) | **REFUTED as an OOB index.** All 32 variable-shift `1<<n` sites in the whole binary are printf arguments inside the 14 interval-clamp functions. Zero elsewhere. |

One genuine (but low-severity) finding: the new SoC `addEndpoint`/`updateEndpoint`
overrides are *narrower* than the base class they replace — they drop the
`interval >= 6 → 5` clamp. See §5.1 (STRONG, semantic; not memory-unsafe here).

---

## 1. Why there is no descriptor parsing here (evidence)

`com.apple.driver.usb.AppleSynopsysUSB40XHCI` is the **host-controller** driver.
USB descriptor parsing lives in `IOUSBHostFamily` (`AppleUSBHostDevice` /
`AppleUSBHostInterface`) and in the class drivers. Confirmed by exhaustive string
search of the active view (1767 strings total):

| Query (`bn_string_list`, case-insensitive) | Hits |
|---|---|
| `descriptor` | **0** |
| `hid` | **0** |
| `hub` | **0** |
| `wTotalLength` / `bLength` / `bNumInterfaces` / `bNumEndpoints` | 0 (covered by `descriptor`+`interface`+`endpoint` queries below) |
| `endpoint` | 19 — all are the interval log `"%s: %s::%s: forcing endpoint interval from %d uFrames to %d uFrames\n"` (17 copies) + `"addEndpoint"` + `"updateEndpoint"` |
| `interface` | 4 — all `IOTBTTunnelClientInterfaceManager` / `DVFM_IF_BWR_AGENT_INTERFACE_AGENT_BWR` (power-management register names) |
| `config` | 6 — all `"creating _configRegistersMap failed\n"` (MMIO map) |
| `speed` | 8 — all `"port %u max link speed %u\n"` |

Also: `bn_symbol_list` query `descriptor` → 0; `bn_function_search` `Descriptor` → 0;
`Endpoint` → 0. The only symbols matching `_mem` are Binary-Ninja-internal
`__builtin_memcpy` / `__builtin_memset`.

**Consequence for the attack surface:** a malicious USB device's descriptors do
**not** reach this kext as bytes. What reaches it is a driver-internal, two-dword
endpoint-parameters block (see §3), already normalised by `IOUSBHostFamily`.
The classic "BadUSB descriptor overflow" surface is therefore **not** in this
binary. Verdict: **CLEAN NEGATIVE (high confidence)**.

### 1.1 Descriptor-parsing site table

| # | Address | Descriptor type | Destination buffer + size | Length validation | Verdict |
|---|---|---|---|---|---|
| — | — | device / config / interface / endpoint / string / HID / BOS / SuperSpeed | — | — | **No such code exists in this kext.** No `bLength`, `wTotalLength`, `bNumInterfaces`, `bNumEndpoints`, `bNumConfigurations`, or UTF-16 string handling anywhere. |

### 1.2 The nearest thing to a descriptor: the endpoint-parameters block

The interval clamps (§5) operate on `arg5`, a caller-owned 2-dword block:

```
arg5[0]  (dword @ +0) : bits 16..23 = interval; bits 20..23 = "family"/speed nibble
arg5[1]  (dword @ +4) : bits 3..5   = endpoint type/direction selector
```

This is **not** a USB endpoint descriptor. In a real `IOUSBEndpointDescriptor`
(7 bytes) `bInterval` is byte **6**, not byte 2; there is no dword at +4. So no
attacker-supplied `bLength` is ever copied into it here.

---

## 2. Count-driven loops

| Address | Loop | Trip-count bound | Verdict |
|---|---|---|---|
| `0xfffffff00a6ca6c0` (T8142 `getPeriodicBandwidthUsage`) | `for (ep = this->f58; ep; ep = *(ep+0x10))` | NULL terminator; **no count, no descriptor field** | SAFE |
| `0xfffffff00a6e06fc` (T8152 `getPeriodicBandwidthUsage`) | same | same | SAFE |
| `0xfffffff00a6f4c28` (3rd variant) | same | same | SAFE |

No loop anywhere in the binary is driven by `bNumInterfaces`, `bNumEndpoints`,
`bNumConfigurations`, `bNumAltSettings`, or any other descriptor count field —
because no descriptor is parsed (§1). Verdict: **CLEAN NEGATIVE**.

---

## 3. Interface / endpoint array indexing

Exactly **three** sites compute an array index from an endpoint number. Found by
scanning all of `__TEXT_EXEC` for the `orr Xd, Xn, Xm, lsl #4` idiom
(`8 | n << 4`); there are only 3 instances in the whole kext.

| Address (function) | Code |
|---|---|
| `0xfffffff00a6ca71c` — `sub_fffffff00a6ca424` (T8142, TU `0xa6b6d40`–`0xa6cb4c4`) | see below |
| `0xfffffff00a6e0758` — `sub_fffffff00a6e0460` (T8152, TU `0xa6cc910`–`0xa6e150c`) | byte-identical |
| `0xfffffff00a6f4c90` — `sub_fffffff00a6f48b4` (3rd variant) | byte-identical |

```asm
; sub_fffffff00a6e0460 @ 0xfffffff00a6e0704  (T8152; T8142 twin at 0xa6ca6c8)
0xfffffff00a6e0704  add     x26, x19, #0x6b0      ; base = this + 0x6b0
0xfffffff00a6e0708  mov     w27, #0x8
0xfffffff00a6e071c  ldr     x8, [x16, #0x80]!
0xfffffff00a6e0728  blraa   x8, x16               ; x22 = (*(*ep + 0x80))(ep)   <- ENDPOINT NUMBER, external vcall
0xfffffff00a6e0740  ldr     x8, [x16, #0x88]!
0xfffffff00a6e074c  blraa   x8, x16               ; x21 = (*(*ep + 0x88))(ep)
0xfffffff00a6e0754  mov     w8, w22
0xfffffff00a6e0758  orr     x8, x27, x8, lsl #0x4 ; index = 8 | (n << 4)
0xfffffff00a6e075c  cmp     x8, w8, sxtw          ; sign-extension guard only
0xfffffff00a6e0760  add     x28, x26, w8, sxtw
0xfffffff00a6e0764  add     x16, x26, x8
0xfffffff00a6e0768  movk    x16, #0x2bad, lsl #0x30
0xfffffff00a6e076c  csel    x28, x28, x16, eq
0xfffffff00a6e0770  ldr     x0, [x28]             ; <-- the read
```

**Analysis**

* Effective byte offset from `this + 0x6b0` is `8 + 16*n` (equivalently element
  `2n+1` of an 8-byte-stride array, or the high half of a 16-byte-stride array).
* **There is no `and`/`uxth`/`cmp` on `n` at this site.** The only guard is
  `cmp x8, w8, sxtw` → poisoned `0x2bad...` pointer, which fires only when
  `n >= 2^28`. It does **not** bound `n` to 15.
* Therefore the safety of this read rests entirely on the contract of the
  out-of-binary virtual `(*(*ep + 0x80))(ep)` (an `AppleUSBHostEndpoint` accessor
  in `IOUSBHostFamily`). If that accessor returns a masked endpoint **number**
  (0–15) the worst-case offset is `0x6b0 + 0xf8 = 0x7a8` — safe. If it can return
  a raw **endpoint address** (`bEndpointAddress`, 0x81 → 129), the offset becomes
  `0x6b0 + 0x818 = 0xec8`, and the `ldr x0,[x28]` + subsequent virtual calls would
  be an OOB pointer dereference.
* The T8152 TU (`0xa6e0758`) is **byte-identical** to the T8142 TU
  (`0xa6ca71c`) — the new silicon introduces no regression here.

**Confidence: SPECULATIVE.** Cannot be closed inside this kext; needs
`IOUSBHostFamily` to resolve the `+0x80` accessor. Not a new-code finding (the
new TU copies the old code exactly).

---

## 4. The interval / periodic-bandwidth trace (the flagged lead)

### 4.1 Where the clamped interval lands

All 14 clamp functions do the same three things with the interval byte:

1. **Log it** — `1 << interval` is computed and passed as a printf vararg:
   ```asm
   0xfffffff00a6b6318  ldr   w8, [x19]        ; interval = (dw0 >> 16) & 0xff
   0xfffffff00a6b631c  lsr   w8, w8, #0x10
   0xfffffff00a6b6320  mov   w9, #0x1
   0xfffffff00a6b6324  lsl   w8, w9, w8       ; 1 << interval   (LSLV)
   0xfffffff00a6b6328  mov   w9, #0x8         ; "to" value = 8 = 1<<3
   0xfffffff00a6b632c  stp   x8, x9, [sp, #0x18]   ; varargs for os_log
   ```
2. **Write it back** in place:
   ```asm
   0xfffffff00a6cbcbc  ldr   w9, [x19]
   0xfffffff00a6cbcc0  and   w9, w9, #0xff00ffff
   0xfffffff00a6cbcc4  str   w9, [x19]
   0xfffffff00a6cbcc8  ldr   w9, [x19]
   0xfffffff00a6cbccc  orr   w8, w9, w8       ; w8 = 0x30000 or 0x50000
   0xfffffff00a6cbcd0  str   w8, [x19]        ; *arg5 = (*arg5 & 0xff00ffff) | (new << 16)
   ```
3. **Forward the struct** to an out-of-binary superclass implementation
   (unresolved external, PAC'd `braa`):
   ```asm
   0xfffffff00a6cbcd4  adrp  x5, 0xfffffff008384000
   0xfffffff00a6cbcd8  ldr   x5, [x5, #0x528]
   0xfffffff00a6cbcdc  ldr   x16, [x5, #0xc8]!   ; 0x10000001383430 (unresolved)
   0xfffffff00a6cbd20  braa  x16, x17             ; tail call
   ```

### 4.2 Does `1 << interval` ever index anything? — **No. PROVEN.**

Scan of every executable section for the variable-shift `LSL` encodings
(`LSLV` 32-bit `0x1AC02000`, 64-bit `0x9AC02000`) returns **32 sites, all 32 of
which are the printf `1 << interval` computations inside the 14 clamp functions**
(addresses listed in §5). **Zero** variable shifts exist anywhere else in the
kext. There is therefore no `1 << interval` table index, no
periodic-schedule slot computation, and no allocation size derived from interval.

The bandwidth accounting itself (`getPeriodicBandwidthUsage`) proves it too: it
sums fixed MMIO reads (`(*(*this + 0x9d0))(this, ..., 0x2c/0x38/0x30/0x3c/0x34/0x40)`
each `<< 0xa`) plus per-endpoint contributions, and never uses interval as a
subscript. `sub_fffffff00a6ca424` (T8142), `sub_fffffff00a6e0460` (T8152),
`sub_fffffff00a6f48b4` are all structurally identical.

**Interval-trace verdict: REFUTED as an out-of-bounds index.** The value is
consumed only by `os_log` and by the in-place write-back, then handed to an
out-of-binary superclass. Any downstream misuse would be in
`AppleUSBXHCICommon`/`IOUSBHostFamily`, not this kext.

---

## 5. Interval-clamp comparison table (base vs. new silicon)

14 functions = **7 addEndpoint/updateEndpoint pairs**. Located by (a) `adrp+add`
scan for the 17 copies of the `"forcing endpoint interval…"` string, (b) scan for
`cmp wN, #6` (8 hits) and (c) scan for `cmp wN, #0x50000` (2 hits).

| Func | Pair | Class literal in log | `cmp w,#6` (upper bound on →3) | `cmp w,#0x50000` (≥6 → 5) | `1<<n` (LSLV) sites |
|---|---|---|---|---|---|
| `0xfffffff00a6cb9f4` | addEndpoint | `AppleUSBXHCICommandRing` (`0xfffffff007ae0528`) — **base** | ✗ **absent** | ✓ `0xfffffff00a6cbb34` | `0xa6cbad8`, `0xa6cbb84`, `0xa6cbbf4`, `0xa6cbc78` |
| `0xfffffff00a6cbd24` | updateEndpoint | `AppleUSBXHCICommandRing` — **base** | ✗ **absent** | ✓ `0xfffffff00a6cbe64` | `0xa6cbe08`, `0xa6cbeb4`, `0xa6cbf24`, `0xa6cbfa8` |
| `0xfffffff00a6b6238` | addEndpoint | `AppleT8152USBXHCICommandRing` (`0xfffffff007ade3d8`) | ✓ `0xfffffff00a6b62d0` | ✗ | `0xa6b6324`, `0xa6b6394` |
| `0xfffffff00a6b643c` | updateEndpoint | `AppleT8152USBXHCICommandRing` | ✓ `0xfffffff00a6b64d4` | ✗ | `0xa6b6528`, `0xa6b6598` |
| `0xfffffff00a6cc488` | addEndpoint | `AppleT8142USBXHCICommandRing` (`0xfffffff007ae0540`) | ✓ `0xfffffff00a6cc520` | ✗ | `0xa6cc574`, `0xa6cc5e4` |
| `0xfffffff00a6cc68c` | updateEndpoint | `AppleT8142USBXHCICommandRing` | ✓ `0xfffffff00a6cc724` | ✗ | `0xa6cc778`, `0xa6cc7e8` |
| `0xfffffff00a6f6440` | addEndpoint | (SoC variant, TU `0xa6e157c`–`0xa6f601c` / `0xa6f68c8`–) | ✓ `0xfffffff00a6f64d8` | ✗ | `0xa6f652c`, `0xa6f659c` |
| `0xfffffff00a6f6644` | updateEndpoint | ″ | ✓ `0xfffffff00a6f66dc` | ✗ | `0xa6f6730`, `0xa6f67a0` |
| `0xfffffff00a70abc8` | addEndpoint | ″ | (TU tail) | ✗ | `0xa70acac`, `0xa70ad1c` |
| `0xfffffff00a70adc4` | updateEndpoint | ″ | (TU tail) | ✗ | `0xa70aea8`, `0xa70af18` |
| ~`0xa70b4xx` | addEndpoint | ″ | ✓ `0xfffffff00a70b48c` | ✗ | `0xa70b4e0`, `0xa70b550` |
| ~`0xa70b6xx` | updateEndpoint | ″ | ✓ `0xfffffff00a70b690` | ✗ | `0xa70b6e4`, `0xa70b754` |
| ~`0xa70bcxx` / ~`0xa70bexx` | add/update | ″ | (TU tail) | ✗ | `0xa70bd0c`, `0xa70bd7c`, `0xa70bf00`, `0xa70bf70` |

*(7 classes = 6 SoC families T8142/T8152/T8132/T8122/T8112/T8103 + base
`AppleUSBXHCI`; TU boundaries established by `adrp+add` scan on the class-name
strings `AppleT8142USBXHCI` `0xfffffff007ade9b5`, `AppleT8152USBXHCI`
`0xfffffff007ae057f`, `AppleT8132USBXHCI` `0xfffffff007ae05ef`,
`AppleT8122USBXHCI` `0xfffffff007ae0966`, `AppleT8112USBXHCI` `0xfffffff007ae1016`,
`AppleT8103USBXHCI` `0xfffffff007ae1055`, `AppleT6000USBXHCI` `0xfffffff007ade785`.)*

### 5.1 The actual semantic difference

**Base** (`sub_fffffff00a6cb9f4`, `0xfffffff00a6cba84`):
```asm
0xfffffff00a6cba84  ldr   w8, [x19]
0xfffffff00a6cba88  tst   w8, #0xfc0000       ; interval >= 4 ?
0xfffffff00a6cba8c  b.eq  0xfffffff00a6cbb0c  ; no  -> try the >=6->5 path
                                              ; yes -> force interval = 3   (NO upper bound)
...
0xfffffff00a6cbb0c  ldr   w8, [x19, #0x4]
0xfffffff00a6cbb10  and   w8, w8, #0x38
0xfffffff00a6cbb14  cmp   w8, #0x28
0xfffffff00a6cbb18  b.eq  0xfffffff00a6cbb2c
0xfffffff00a6cbb1c  ...   cmp   w8, #0x8
0xfffffff00a6cbb28  b.ne  0xfffffff00a6cbcd4
0xfffffff00a6cbb2c  ldr   w8, [x19]
0xfffffff00a6cbb30  and   w8, w8, #0xfe0000
0xfffffff00a6cbb34  cmp   w8, #0x50, lsl #0xc ; interval >= 6 ?
0xfffffff00a6cbb38  b.ls  0xfffffff00a6cbcd4  ; no  -> leave alone
                                              ; yes -> force interval = 5 (w8 = 0x50000 @ 0xa6cbcb8)
```
Base also selects the endpoint family **from data**:
`ubfx w9, w8, #0x14, #0x4` compared against `(*(this + 0x1868))[0x680]` and
`[0x684]` at `0xa6cba3c` / `0xa6cba5c`.

**SoC override** (`sub_fffffff00a6b6238`, `sub_fffffff00a6cc488`, …):
```asm
0xfffffff00a6b6270  ldr   w8, [x20]
0xfffffff00a6b6274  and   w8, w8, #0xf00000
0xfffffff00a6b6278  cmp   w8, #0x400, lsl #0xc   ; 0x400000  (hard-coded, not from data)
...
0xfffffff00a6b629c  ldr   w8, [x19, #0x4]
0xfffffff00a6b62a4  bics  wzr, w9, w8            ; (dw1 & 0x38) == 0 ?
0xfffffff00a6b62b0  and   w8, w8, #0x38
0xfffffff00a6b62b4  cmp   w8, #0x18              ; or == 0x18
0xfffffff00a6b62c0  tst   w8, #0xfc0000          ; interval >= 4
0xfffffff00a6b62cc  ubfx  w8, w8, #0x10, #0x8
0xfffffff00a6b62d0  cmp   w8, #0x6               ; <-- upper bound the BASE does not have
0xfffffff00a6b62d4  b.hi  0xfffffff00a6b63ec     ; interval > 6 -> NO clamp at all
                                                 ; interval 4..6 -> force to 3
```

**Net difference (confirmed, matches the parallel agent's observation, with
corrected attribution):**

* Only the **base** `AppleUSBXHCI` pair has the `interval >= 6 → 5` branch
  (`cmp w8, #0x50000; b.ls` at `0xfffffff00a6cbb34` / `0xfffffff00a6cbe64`).
  All six SoC overrides — including the T8142 and T8152 ones — **lack it**.
* Conversely the SoC overrides add an **upper** bound (`cmp w8, #6; b.hi`) that
  the base's `→3` path does not have, so they clamp only `interval ∈ [4,6] → 3`,
  while the base clamps `interval ∈ [4,255] → 3`.
* Net: for `interval >= 7` the SoC override performs **no** clamp and forwards
  the raw value to the out-of-binary superclass. The base's `→3` path, had it run,
  would have clamped it.
* The SoC overrides also hard-code the family selectors `0x400000`/`0x500000`
  where the base reads them from `(*(this+0x1868))[0x680]/[0x684]`.

**Confidence: STRONG** for the structural difference (direct disassembly, both
directions). **SPECULATIVE** for impact: the value is only forwarded; whether an
unclamped `interval >= 7` is harmful depends on the out-of-binary superclass
`addEndpoint`, which this kext cannot show.

### 5.2 The `0xfffffff00a6b62cc` gate (as flagged)

`0xfffffff00a6b62cc`–`0xa6b62d4` is exactly the `ubfx #0x10,#0x8` / `cmp #6` /
`b.hi` sequence: the clamp is gated to `interval <= 6`, i.e. the clamp is a
narrowing, not a widening. Confirmed at all 8 `cmp w,#6` sites.

---

## 6. Candidate ranking

| Rank | Candidate | Address | Exact op | Controlling input | Consequence | Confidence |
|---|---|---|---|---|---|---|
| 1 | Endpoint array index unmasked | `0xfffffff00a6ca71c` (T8142), `0xfffffff00a6e0758` (**T8152, new TU**), `0xfffffff00a6f4c90` | `orr x8, x27, x8, lsl #0x4` (`8 \| n<<4`) then `ldr x0, [x28]` | `n` from `(*(*ep+0x80))(ep)` — out-of-binary `AppleUSBHostEndpoint` accessor | If `n` is an endpoint *address* (bit 7 = direction, 0x81 → 129) rather than a masked number 0–15, offset `0x6b0 + 0x818 = 0xec8` → OOB pointer load + subsequent virtual call on garbage | **SPECULATIVE** — not closable in this kext; also **not new** (T8152 byte-identical to T8142) |
| 2 | SoC `addEndpoint`/`updateEndpoint` drop the `interval >= 6 → 5` clamp | `0xfffffff00a6b62d4` (`b.hi`), `0xfffffff00a6cc520`, `0xfffffff00a6f64d8`, `0xa70b48c`, `0xa70b690`; missing branch where base has `0xfffffff00a6cbb34` / `0xa6cbe64` | missing `str w8, [x19]` with `w8 = 0x50000` | device-supplied `bInterval` ≥ 7 on an isoch IN/OUT endpoint | Unclamped interval forwarded to out-of-binary superclass; possible schedule/bandwidth mis-accounting. **Not** a memory-safety bug in this kext (§4.2) | **STRONG** (difference) / **SPECULATIVE** (impact) |
| 3 | Base `→3` clamp has no upper bound | `0xfffffff00a6cba88` `tst w8, #0xfc0000` (no `cmp #6`) | `str w8, [x19]` with `w8 = 0x30000` | interval ≥ 4 | Forces interval 3 for **any** declared interval ≥ 4 — over-broad but a *narrowing* clamp; fail-safe direction, not a bug | **REFUTED** (not exploitable) |
| 4 | `1 << interval` as index / periodic-schedule slot | — | — | — | No such use exists; all 32 `LSLV` sites are printf args | **REFUTED (proven)** |
| 5 | Descriptor parsing overflows (`wTotalLength`, `bLength`, string UTF-16, HID report) | — | — | — | No descriptor parsing in this kext | **REFUTED (proven negative)** |
| 6 | Count-driven descriptor-walk loops | — | — | — | None exist; only NULL-terminated endpoint list | **REFUTED (proven negative)** |

---

## 7. Method / reproducibility

* `bn_string_list` (1767 strings), `bn_symbol_list`, `bn_function_search`,
  `bn_function_list` for TU mapping and function extents.
* `ds_locate_strrefs.py` (adrp+add / adrp+ldr scan) to map string→code, run on:
  the 17 `"forcing endpoint interval…"` copies, all 7 `AppleT*USBXHCI` class names,
  the 6 `.cpp` names, `getPeriodicBandwidthUsage` (`0xfffffff007adffda`),
  `"in bandwidth: %u KB/"` (`0xfffffff007adff90`).
* Custom `__TEXT_EXEC` instruction scans (all read-only, same Mach-O parser):
  * `orr Xd, Xn, Xm, lsl #4`  → 3 hits (endpoint index idiom, §3).
  * `add/sub X, X, #0x6b0`    → 3 hits (endpoint array base, §3).
  * `cmp wN, #6` (`SUBS wzr`) → 8 hits (interval upper bound, §5).
  * `cmp wN, #0x50000` (`SUBS wzr, wN, #0x50 lsl #12`) → 2 hits (base-only ≥6→5, §5).
  * `LSLV` 32/64-bit → 32 hits, all in the clamp functions (§4.2).
* Widths for every claim verified in `bn_function_disassembly`, not the
  decompiler (e.g. `*arg5` write-back is `str w8` / 32-bit at `0xa6cbcc4`–`0xa6cbcd0`).

## 8. Caveats

* The kext is fully stripped; all functions are `sub_fffffff00a6xxxxx`. Class
  attribution is inferred from the class-name string literal each function passes
  to the logger and from TU address ranges, not from symbols.
* The log format is `"%s: %s::%s"` and the middle slot is a *ring* class name
  (e.g. `AppleT8142USBXHCICommandRing`) rather than the controller class name.
  I report the literal as it appears; the SoC family attribution (T8142/T8152/…)
  follows from the T8xxx prefix and TU placement.
* Superclass `addEndpoint`/`updateEndpoint` targets are unresolved externals
  (`0x100000013935f8`, `0x10000001393600`, `0x10000001383430`, reached via GOT
  slots `0xfffffff008384520` / `0xfffffff008384528` + `0xc8`, PAC'd `braa`).
  Their behaviour is outside this binary — the end-to-end fate of an unclamped
  interval cannot be determined here.
