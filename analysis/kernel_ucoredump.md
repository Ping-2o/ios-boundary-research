> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# iOS 27.0 RC (24A435) kernel — `ucoredump` facility investigation

**Target:** `kernelcache.release.iPhone17,5`, Binary Ninja `KCView`, platform `ios-kernel-aarch64`
**Tooling:** Binary Ninja MCP only (read-only; `bn_binary_view_set_active` and `bn_open_item_open` were never called)
**Date:** 2026-09-12

---

## 0. Headline result

**The investigation could not be performed. The active binary view contains no kernel code.**

The active `KCView` (`view_19`, open item `item_10`) has mapped **exactly 0x5830 bytes** — the
Mach-O header plus its load commands — out of a 78 MB file. It has **0 functions, 0 real symbols,
and 313 strings, all of which are segment/section names and KEXT bundle IDs harvested from the
prelink info.** There is no `__TEXT`, no `__TEXT_EXEC`, no `__PRELINK_TEXT` body, no `__LINKEDIT`,
no symbol table, and no code of any kind in the view.

Therefore **every one of the five questions is UNANSWERABLE** on this view, and I am not going to
invent an answer. Nothing in this report is derived from anything other than observed tool output;
no addresses, function names, or disassembly below are fabricated.

**Confidence on the top-level question ("relocated or removed?"): `UNRESOLVED — NOT TESTABLE`.**
Note carefully: this is *not* `REFUTED`. I did not disprove the premise. I established that this
Binary Ninja view cannot test it either way.

---

## 1. Evidence: the view is empty of code

### 1.1 Triage

```
$ bn_binary_view_triage
{
  "binaryView": { "handle":"view_19", "openItem":"item_10", "viewType":"KCView",
                  "platform":"ios-kernel-aarch64", "start":"0xfffffff007004000",
                  "end":"0xfffffff017004030", "entryPoint":"0x0" },
  "analysis":   { "state":"IdleState", "stateValue":2,
                  "progress":{"count":0,"total":0},
                  "info":{"analysisTime":0,"active":[]} },
  "segmentCount": 2,
  "sectionCount": 2,
  "symbolCount": 322,
  "functionCount": 0,          <-- no functions
  "stringCount": 313,
  "dataVariableCount": 322
}
```

`functionCount = 0`. There is not a single function — named, thunk, or auto-discovered — in the
entire 0x10000030-byte address span.

### 1.2 Only two segments exist, and only one is backed by file data

```
$ bn_segment_list
| 0xfffffff007004000 | 0xfffffff007009830 | 0x5830 | dataOffset 0x0 | dataLength 0x5830 | SegmentReadable |
| 0xfffffff017004000 | 0xfffffff017004030 | 0x30   | dataOffset 0x0 | dataLength 0x0    | (synthetic)     |
```

```
$ bn_section_list
| kernelcache_header  | 0xfffffff007004000 | 0xfffffff007009830 | 0x5830 | ReadOnlyData |
| .synthetic_builtins | 0xfffffff017004000 | 0xfffffff017004030 | 0x30   | External     |
```

Note the absence of `__TEXT`, `__TEXT_EXEC`, `__TEXT_BOOT_EXEC`, `__DATA_CONST`, `__DATA_SPTM`,
`__DATA`, `__PRELINK_TEXT`, `__PRELINK_INFO` and `__LINKEDIT` as *sections*, even though the header's
own load commands name all of them (see §1.5). The KCView created synthetic
`kernelcache_header` / `.synthetic_builtins` sections instead of the real ones.

### 1.3 Memory reads outside the 0x5830-byte header return zero bytes

```
$ bn_memory_read  0xfffffff007004000  0x80   ->  bytesRead 296   (OK: header is mapped)
$ bn_memory_read  0xfffffff007009800  0x10   ->  bytesRead  22   (last mapped page)
$ bn_memory_read  0xfffffff007100000  0x40   ->  bytesRead   0   partial_read
$ bn_memory_read  0xfffffff008000000  0x10   ->  bytesRead   0   partial_read
$ bn_memory_read  0xfffffff00b9fb000  0x10   ->  bytesRead   0   partial_read
```

The kernel body (which the load commands place well above `0xfffffff007009830`) is simply not
present. Any attempt to read, disassemble or decompile it fails.

### 1.4 Searches return nothing — because there is nothing to search

| Query | Tool | Result |
|---|---|---|
| `ucoredump` | `bn_function_search` | `count: 0, total: 0` |
| `ucoredump` | `bn_string_list` | `count: 0, total: 0` |
| `ucoredump` | `bn_symbol_list` | `count: 0, total: 0` |
| `coredump` | `bn_function_search` | `count: 0, total: 0` |
| `coredump` | `bn_symbol_list` | `count: 0, total: 0` |
| `kdp_` | `bn_symbol_list` | `count: 0, total: 0` |
| `panic` | `bn_symbol_list` | `count: 0, total: 0` |
| (no query) | `bn_function_list` | `count: 0, total: 0` |

The `kdp_` and `panic` controls are the important ones. Even in a build where coredump had been
*entirely* deleted, `panic()` and the `kdp_*` KDP machinery would still exist. They return zero.
That is the signature of an **empty view**, not of a removed feature.

`bn_analysis_update_and_wait` was called first and returned `IdleState` before *and* after with
`count: 0, total: 0` — Binary Ninja considers there to be nothing to analyze. This is not a
"wait longer" situation.

### 1.5 Why: only the header + load commands were materialized

```
$ bn_memory_read 0xfffffff007004000 0x80
cffaedfe 0c000001 020000c0 0c000000 39010000 10580000 00000000 00000000
1b000000 18000000 fd9a81e2 c7a92d06 77ef40fe 8be3e7f3 32000000 18000000
```

Decoded `mach_header_64`:

| Field | Bytes | Value |
|---|---|---|
| `magic` | `cf fa ed fe` | `0xfeedfacf` = `MH_MAGIC_64` |
| `cputype` | `0c 00 00 01` | `0x0100000c` = `CPU_TYPE_ARM64` |
| `cpusubtype` | `02 00 00 c0` | `0xc0000002` = `CPU_SUBTYPE_ARM64E` + PTRAUTH/kernel ABI bits |
| `filetype` | `0c 00 00 00` | `0x0c` |
| `ncmds` | `39 01 00 00` | **0x139 = 313** |
| `sizeofcmds` | `10 58 00 00` | **0x5810** |
| `flags` | `00 00 00 00` | 0 |

`0x20 (header) + 0x5810 (sizeofcmds) = 0x5830` — **exactly** the length of the one readable
segment. The KCView mapped the header and the load-command table and stopped. Every segment
described *by* those load commands (file offsets and vmsizes spanning the 78 MB file) was never
mapped. This is why `symbolCount` (322) equals `dataVariableCount` (322): the view contains
nothing but Binary Ninja's own auto-generated `__macho_load_command::kernelcache[N]` /
`__macho_section_64::kernelcache[N]` struct symbols.

### 1.6 The 313 strings are the prelink-info KEXT list, not kernel strings

All 313 strings live in `0xfffffff007004188 … 0xfffffff007009810` (inside the header). They are:

- segment/section names: `__TEXT`, `__PRELINK_TEXT`, `__text`, `__DATA_CONST`, `__DATA_SPTM`,
  `__TEXT_EXEC`, `__TEXT_BOOT_EXEC`, `__PRELINK_INFO`, `__info`, `__DATA`, `__LINKEDIT`
- the KEXT bundle-ID roster: `com.apple.kernel`, `com.apple.kec.Libm`, `com.apple.kec.pthread`,
  `com.apple.driver.AppleT8140*`, `com.apple.iokit.IOUSBHostFamily`, `com.apple.filesystems.apfs`,
  `com.apple.driver.DiskImages.*`, … through `com.apple.filesystems.tmpfs`
  (`0xfffffff007009810`, the last string).

`ncmds = 313` and `stringCount = 313`, consistent with one string per load command.

**No kernel C string — no panic message, no `%llu` format, no entitlement string, no
`coredump*` or `ucoredump*` string — exists anywhere in this view.** The absence of `"ucoredump"`
here is therefore *uninformative*: the entire `__TEXT.__cstring` region of the kernel is unmapped.

---

## 2. The new `ucoredump` facility

**Status: NOT FOUND — but NOT_FOUND ≠ ABSENT (view defect). Confidence: `UNRESOLVED — NOT TESTABLE`.**

- `bn_function_search "ucoredump"` → 0 results.
- `bn_symbol_list "ucoredump"` → 0 results.
- `bn_string_list "ucoredump"` → 0 results.
- No function list to enumerate at all (`bn_function_list` → `total: 0`).

Mapping onto the old API (`kern_coredump_routine`, `kcc_coredump_*`, `coredump_save_*`): cannot be
attempted. The view has no functions, no callers, no callees, no xrefs — `bn_function_callers`,
`bn_function_callees`, `bn_function_xrefs_to`, `bn_data_xrefs_to` all require at least one function
or mapped data address, and none exists outside the 0x5830-byte header.

---

## 3. Check-by-check: removed check → successor

**Every row is `UNKNOWN (NO SUCCESSOR DETERMINABLE)`, not `NO SUCCESSOR`.** I want to be blunt
about this distinction: writing `NO SUCCESSOR` here would be the single most misleading thing this
report could do, because it would read as "I looked and it is gone" when the truth is "I could not
look".

| Removed check (beta 8 string) | Successor in RC | Confidence |
|---|---|---|
| `coredump size limit exceeded: attempted %llu bytes, limit is %llu bytes` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `coredump_save_segment_descriptions() called too many times, %llu segment descriptions already recorded` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `%s(0x%llx, 0x%llx, %p) : coredump_save_segment_descriptions() called too many times, …` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `called with invalid length %llu` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `called with too much data, %llu written, %llu left` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `ran out of space to save threads with %llu of %llu remaining` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `Corefile is not yet initialized. Cannot write a coredump to disk` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `LZ4 stage is not yet initialized. Cannot write a coredump to disk` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `Zlib stage is not initialized. Cannot write a coredump to shared memory / network` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `We were in the middle of initializing LZ4 / the disk stage. …` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `(disk_stage_write) coredump size limit exceeded: …` | unknown — not testable | UNRESOLVED — NOT TESTABLE |
| `(%s) : kcc_coredump_save_note_data returned without all note data written, %llu of %llu remaining` | unknown — not testable | UNRESOLVED — NOT TESTABLE |

There is **no finding** in this table. There is no candidate bug here. There is a tooling failure.

---

## 4. New write-path bound analysis

**Not performed. Confidence: `UNRESOLVED — NOT TESTABLE`.**

Requires: function bodies in the write path, the destination buffer and its capacity, and the
`madd w` / `madd x` / `adds`+`b.hs` width checks in disassembly. `bn_function_disassembly` and
`bn_function_decompile` both resolve a *function start address*; the view resolves zero addresses
to functions (`bn_function_info 0xfffffff0071a0000` → `errorCode: function_not_found`). There is
no code to disassemble.

I did **not** attempt to read "likely" addresses and hand-disassemble raw bytes, because the bytes
are not there (`bytesRead: 0`). Manufacturing a `madd`/`adds` sequence would be fabrication.

---

## 5. Segment-description array analysis

**Not performed. Confidence: `UNRESOLVED — NOT TESTABLE`.**

Requires locating the allocation (`kalloc`/`zalloc` size argument or a static array symbol) and the
incrementing counter. Neither exists in a view with 0 functions and 322 synthetic struct symbols.

---

## 6. Reachability / severity

**Not assessed. Confidence: `UNRESOLVED — NOT TESTABLE`.**

Trigger analysis (boot-arg / sysctl / entitlement / panic path) requires at least one reachable
function and its xrefs. Unavailable.

For what it is worth, and flagged as reasoning *outside* Binary Ninja rather than evidence: the
premise that all sizes flowing into a coredump writer are kernel-derived (segment descriptors come
from the pmap/VM map, thread counts from the task) is plausible and would cap severity even in the
worst case. But that is an argument about the general shape of coredump code, not a finding about
24A435, and it should not be recorded as one.

---

## 7. Ranked candidates

There are **no vulnerability candidates to rank.** The candidate list is empty.

| Rank | Candidate | Confidence |
|---|---|---|
| — | (none — nothing was analyzable) | — |
| — | `ucoredump` facility exists and replaced `coredump_*` | SPECULATIVE (per the diff premise; unverified here) |
| — | Any specific removed check lacks a successor | SPECULATIVE at best; **not supported by any evidence in this view** |

---

## 8. Root cause and remediation

The KCView for `item_10` mapped only `mach_header_64` + load commands (0x5830 bytes). Everything
else in the 78 MB file is unmapped. Probable causes, in order of likelihood:

1. **The kernel collection could not be parsed** — `KCView` needs the file to be a valid
   kernel collection (`LC_FILESET_ENTRY` / `KCView`'s expected layout). `filetype = 0x0c` in the
   header is worth a second look; if this is an IMG4-unwrapped-but-not-rebased or otherwise
   non-canonical kernelcache, the KC parser can bail after the header.
2. **Companion files missing** — if this came from an IPSW, the `.kch`/symbol companion or the
   `kernelcache` + `kernelcache.??.kch` pair may not have traveled with it.
3. **Truncated / sparse source file** — note `item_10`'s sibling `Raw` view (`view_20`) reports
   length `0x4a6c000` (≈78 MB), so the file itself is full-size. The problem is parsing, not
   download integrity.

Suggested next steps (all of which require actions I was instructed not to take, or a fresh load):

1. Reload item_10 explicitly as **Mach-O** rather than relying on `KCView` auto-detection. Note
   that `bn_binary_view_list` shows a `Raw` view (`view_20`) and the `KCView` (`view_19`) for
   `item_10` and **no Mach-O view** — for every other item in the project there *is* a Mach-O view
   alongside the Raw one. The missing Mach-O view for `item_10` is itself suspicious and is the
   most likely thing to fix.
2. Load the kernel's **companion symbol file** so real symbol names are available, then re-run
   `bn_function_search "ucoredump"` and `bn_string_list "ucoredump"`.
3. If a Mach-O view is obtained, sanity-check first: `bn_symbol_list "panic"` and
   `bn_symbol_list "kdp_"` must return non-zero before any coredump conclusion is credible. Only
   then proceed to the check-by-check table in §3.
4. Re-run this entire analysis against that view.

---

## 9. Provenance

Every claim above traces to one of these read-only calls, in order:

```
bn_binary_view_get_active
bn_function_search   {query:"ucoredump"}
bn_string_list       {query:"ucoredump"}
bn_symbol_list       {query:"ucoredump"}
bn_analysis_update_and_wait
bn_symbol_list       {query:"coredump"}
bn_function_search   {query:"coredump"}
bn_symbol_list       {query:"kdp_"}
bn_symbol_list       {query:"panic"}
bn_function_list     {}
bn_string_list       {limit:5}
bn_section_list      {}
bn_function_list     {query:"sub_"}
bn_string_list       {start:"0xfffffff007009830"}
bn_memory_read       0xfffffff007100000 /0x40
bn_segment_list      {}
bn_binary_view_triage
bn_binary_view_list  {}
bn_memory_read       0xfffffff007004000 /0x80
bn_symbol_list       {limit:40}
bn_string_list       {limit:330, previewBytes:80}
bn_memory_read       0xfffffff007004210 /0x50
bn_function_info     0xfffffff0071a0000
bn_memory_read       0xfffffff007009800 /0x10
bn_memory_read       0xfffffff008000000 /0x10
bn_memory_read       0xfffffff00b9fb000 /0x10
```

`bn_binary_view_set_active` — never called. `bn_open_item_open` — never called. No view was
modified (`"modified": false, "analysisModified": false`).
