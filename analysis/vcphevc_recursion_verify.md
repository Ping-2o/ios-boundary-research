> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# VCPHEVC.videocodec — `HEVCEncoderOptions` recursion: adversarial verification

Target: `VCPHEVC.videocodec`, iOS 27.0 RC (24A435), ios-aarch64, image base `0x242599000`.
Method: Binary Ninja MCP, read-only. No active-view mutation.

**Verdict: the reported guard asymmetry and self-recursion are REAL (PROVEN), but the
"third-party app DoS" framing is OVERSTATED.** The recursion is not reachable from any
`VTCompressionSession` property; it is reachable only through a CFPreferences key in the
system domain `com.apple.VideoProcessing`. Impact is **DoS-only** (no memory corruption),
and even the crash is conditional on a stack-vs-fd-limit race.

---

## 1. Guard asymmetry — CONFIRMED (PROVEN)

### `sub_242615520` (handler registered for option `config`) — HAS the guard

```
0x242615554  mov     x22, x0
0x242615558  ldrb    w8, [x0, #0x24]        ; read per-object recursion flag
0x24261555c  cmp     w8, #0x1
0x242615560  b.ne    0x2426155dc            ; flag==0 -> take normal path
0x242615564  ...                           ; flag==1 -> error path
0x242615580  add     x0, x0, #0xafc  {data_24271dafc, "Config file within a config file not supported!\n"}
0x242615590  bl      0x2480995a0
0x2426155d4  mov     w19, #0xffffcd9a
...
0x2426155dc  mov     w8, #0x1
0x2426155e0  strb    w8, [x22, #0x24]      ; SET the flag
0x2426155e4  add     x0, sp, #0x140
0x2426155e8  mov     x1, x19
0x2426155ec  bl      sub_2425d6a60          ; open the config file
0x24261568c  bl      sub_2426163bc          ; then delegate parsing
```

Registration (in the option-set constructor `sub_2426151d0`):

```
sub_2426151d0:
    *(arg1 + 0x24) = 0;                                             ; flag initialised to 0
    sub_242615464(arg1, 0x78039475c6a50527, "config", sub_242615520, 0, 1);
```

So `+0x24` is a **per-option-set object field**, initialised to 0, set to 1 on first entry.

### `sub_2426163bc` (handler registered for option `HEVCEncoderOptions`) — NO guard

Full function disassembly was reviewed (470 instructions, `0x2426163bc`–`0x2426169e8`).
There is **no `ldrb/ldr`/`str`/`strb` against `[x?, #0x24]` anywhere in the function.**
The only object fields it reads are:

```
0x2426163e0  str     x0, [sp, #0x58 {var_8a8}]   ; save option-set ptr
0x242616534  ldr     x8, [sp, #0x58]
0x242616538  ldr     w26, [x8, #0x20]            ; +0x20 = multi-pass counter, NOT the guard
```

`+0x20` is a pass counter (`subs w26,w26,#1; b.ge`), not a depth/recursion guard.

**Object identity — decisive.** The guard would have caught the recursion *if 163bc checked
it*, because the object is **shared**, not re-created:

```
15520: sub_2426163bc(arg1=x22, hash, filename, ptr)   ; x22 == 15520's own arg1
163bc: sub_242616a3c(arg1, hash, name, value, ...)     ; arg1 == 163bc's own arg1
616a3c: sub_242616bb4(arg1, ...)                       ; arg1 == option set
616bb4: ldr x8,[x24,#0x10]!                            ; tree root at option_set+0x10
```

Every level carries the same option-set pointer, so `+0x24` is shared across the whole
recursion. The asymmetry is a genuine **omitted check**, not an artefact of a fresh object.

## 2. Recursion is real — STRONG

The descriptor table is built in `sub_24259d838`. The `HEVCEncoderOptions` entry:

```
0x24259f70c  add     x2, x2, #0x336   {data_242720336, "HEVCEncoderOptions"}
0x24259f714  add     x16, x16, #0x3bc {sub_2426163bc}
0x24259f720  mov     x1, ...          {-0x229921caa0554059}   ; FNV-1a("HEVCEncoderOptions")
0x24259f73c  bl      sub_242615464                            ; (option_set, hash, name, handler, 0, 0)
```

Handler calling convention confirmed against a sibling registered the same way:

```
sub_24265d5e8(void* arg1, int64_t arg2, int64_t arg3, int64_t arg4)   ; "gop-size"-family
    if (!arg4) { *(arg1+0x6a)=0; return 0; }
    sub_24265f70c(arg4, arg1+0x6a, &var_28)   ; arg4 == the VALUE string
```

i.e. `handler(option_set, hash, name, value)`. This matches 15520's direct call
`sub_2426163bc(arg1, hash, filename, filename_ptr)`.

Parse → dispatch inside 163bc (dash-less `option : argument` form):

```
0x24261675c  strb  wzr, [sp,#0x80]                 ; x9 != '-' branch
0x242616764  bl    0x248099cf0                      ; strtok-ish split on ':'
0x24261679c  ...    FNV-1a over the option name
0x2426167e8  bl    sub_242616a3c                   ; (option_set, hash, name, arg, 0xffffffff, &flag)
```

```
0x242616a60  bl    sub_242616bb4                   ; 616a3c -> 616bb4
0x242616ca4  ldr   x8, [x24,#0x10]!                ; 616bb4: tree root
0x242616cac  ldr   x9, [x8,#0x20]                  ; compare node hash
0x242616ce0  ldr   x0, [x8,#0x30]                  ; node payload
0x242616d1c  blraa x8, x16                         ; indirect call -> vtable thunk -> handler
```

A line `HEVCEncoderOptions : <path>` therefore re-enters `sub_2426163bc` with
`value == <path>`, which 163bc immediately opens:

```
0x2426163fc  mov  x0, x3
0x242616400  bl   0x248099c70    ; fopen(value)
```

If `<path>` is a file whose content contains `HEVCEncoderOptions : <path>`, the recursion
never terminates: each level opens the file again and calls down before its own `fclose`
at `0x242616984` (only reached on unwind). There is **no depth cap**; the
`"Too many options (max 128)"` check (`0x2426168e0`) is a per-file line limit.

Residual uncertainty (why STRONG, not PROVEN): the vtable thunk `data_2754ad6b0[1]` is
PAC-signed and could not be resolved statically, so the exact register shuffle
`(node, value, count, ctx) -> (option_set, hash, name, value)` is inferred from the sibling
handler and from 15520's direct call, not read directly.

## 3. Per-level stack cost

| function | prologue | bytes |
|---|---|---|
| `sub_2426163bc` | `stp x28,x27,[sp,#-0x60]!` + `sub sp,sp,#0x8a0` | 0x900 |
| `sub_242616a3c` | `sub sp,sp,#0x60` | 0x60 |
| `sub_242616bb4` | `sub sp,sp,#0x80` | 0x80 |
| vtable thunk (`data_2754ad6b0[1]`) | unresolved (PAC) | ~0x20–0x40 |

Total **≈ 0xA10 (2 576 bytes) per level**. Depth before stack exhaustion:

* 512 KB secondary thread → **≈ 203 levels**
* 1 MB → ≈ 407
* 8 MB main thread → ≈ 3 256

Additionally each level leaks one file descriptor (fopen at `0x242616400`, fclose deferred).

## 4. Impact — DoS-only

* No memory corruption found. The line buffer copy is bounds-checked
  (`0x2426165e0 cmp x24,#0x3ff; b.hs` → `"option too long"`), and the options array
  (`sp+0x80..sp+0x480`, 128 slots) is written only for indices ≤ 127 — the "max 128" check
  is exact, no off-by-one.
* Failure mode is stack exhaustion → SIGSEGV on the guard page, **or** fd exhaustion →
  `fopen` fails → `0xffffcd98` propagates up and unwinds **gracefully** (no crash).
* The two race: need `stack_bytes / 2576 < RLIMIT_NOFILE`. A 512 KB thread (~203 levels)
  crashes if the fd limit > ~203 (iOS default soft limit is 256). An 8 MB main thread
  (~3 256 levels) likely hits fd exhaustion first and exits cleanly unless the limit is high.

**Verdict: DoS-only, and conditional.**

## 5. Reachability

The only external input that can *name* `HEVCEncoderOptions` is the CFPreferences reader
`sub_242616dd4`:

```
sub_242616dd4:
 0x242616dfc  add  x19, x19, #0x5a8        {cfstr_ = CFString @ 0x2754ae5a8}
 0x242616e30  bl   0x2480aa310             ; CFPreferencesCopyKeyList(domain, user, host)
 0x242616e3c  bl   0x24809a640             ; CFArrayGetCount
   ... for each key: must be CFString, get C string, FNV-1a hash of key
   sub_242616bb4(arg1, hash(key), key, value, 0xffffffff, &flag, &flag2)   ; dispatch key as option
```

The CFString at `0x2754ae5a8` decodes to flags `0x7c8`, length `0x19` (=25), cstring
pointer whose low 32 bits are `0xC271DC85` → **`0x24271dc85` = "com.apple.VideoProcessing"**
(the sibling string `com.apple.videoprocessing` @ `0x24271a862` has low32 `0xC271A862`, so it
is not the one). The second/third arguments are unresolved `kCFPreferences*` globals
(`0x2680d32c8`, `0x2680d32a0`; not readable in this view).

Call chain into the encoder setup (normal, no debug flag):

```
_HEVCVideoEncoder_CreateInstance (0x2425a1158)
  -> sub_24259d838 (builds option set incl. HEVCEncoderOptions @ 0x24259f73c)
  -> sub_2425a3704 / sub_2425a2034
     -> sub_2425a44dc (applies VTCompression properties; hard-coded names only)
        -> sub_24263de04  (0x2425a714c)
             sub_242616dd4(&arg1[0x168])   ; unconditional: read prefs, dispatch every key
```

**Reachability statement**

* It is **NOT** settable through a normal `VTCompressionSession` property. `sub_2425a44dc`
  maps only hard-coded keys (`profile`, `max-cll`, `master-display`, `ambient-viewing`,
  `lossless`, …) and never dispatches `HEVCEncoderOptions` or `config`.
* It **is** settable by writing the preference key `HEVCEncoderOptions` (string value = a
  file path) in domain `com.apple.VideoProcessing`. The same reader also exposes `config`,
  so the config-file route is gated the same way.
* A **sandboxed third-party app is unlikely to be able to write that domain** — cfprefsd /
  the iOS sandbox restrict cross-application-domain writes. If it cannot, the trigger
  requires an entitled/system/root process, or a debug build, and severity drops sharply.
  No `getenv`-based or fixed-path auto-load of a config file was found.

## 6. Stronger version?

Not established. Several other registered handlers also take a file path
(`scaling-list-file` → `sub_24265ea00`, `logfile`, `isp_meta_file`, `face_meta_file`,
`ave_bin_path`) and were not audited here. The recursion is the clearest issue because it is
the only unbounded re-entry; nothing in the `HEVCEncoderOptions` path showed an unbounded
copy or a missing index bound that would turn the DoS into memory corruption.

## Confidence

| claim | confidence |
|---|---|
| Guard in `sub_242615520`; absent in `sub_2426163bc` | **PROVEN** |
| Object (option set) is shared across the recursion, so a per-object flag would have caught it | **PROVEN** |
| `HEVCEncoderOptions` dispatches back into `sub_2426163bc` (self-recursion) | **STRONG** (indirect thunk not statically resolved) |
| Impact is DoS-only, stack/fd exhaustion, conditional | **STRONG** |
| Reachable by a sandboxed third-party app | **SPECULATIVE** (preference-domain write access unproven; no VT property path) |

Overall: **STRONG** as a latent bug; the prior agent's "DoS from a normal app property" is
**not supported** — the trigger is preference-gated, not a `VTCompressionSession` property.
