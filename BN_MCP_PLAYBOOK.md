> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# Binary Ninja MCP playbook — DirtySlide / iOS RE

How to drive Binary Ninja from an agent. Read this before touching the MCP. Everything here was
learned the hard way on iOS 27.0 RC (24A435); the four gotchas in **§2** will each cost you hours
if you skip them.

---

## 1. Prerequisites

Binary Ninja GUI must be **running** — its bundled MCP plugin serves on `http://127.0.0.1:24642/mcp`.
The connection is already registered in `~/.workbuddy-ai/mcp.json`:

```json
"binja-mcp": { "type": "http", "url": "http://127.0.0.1:24642/mcp", "disabled": false }
```

Nothing to install. Verify it is alive (both should return a table, possibly empty):

```
ToolSearch(tool_names=["mcp__binja-mcp__bn_open_item_list","mcp__binja-mcp__bn_binary_view_list"])
DeferExecuteTool(toolName="mcp__binja-mcp__bn_open_item_list", params={"limit":100})
```

### Tool-access pattern — tools are DEFERRED

Direct calls fail with `InputValidationError`. Always load schemas first, then invoke:

```
ToolSearch(tool_names=["mcp__binja-mcp__bn_function_decompile", ...])   # exact names
ToolSearch(queries=["xref", "decompile"])                               # or keyword search
DeferExecuteTool(toolName="mcp__binja-mcp__bn_function_decompile",
                 params={"function":"0x24eb4a448","limit":1000})
```

Core inventory (all `mcp__binja-mcp__bn_`):

| purpose | tool |
|---|---|
| open / switch binary | `bn_open_item_open`, `bn_binary_view_list`, `bn_binary_view_set_active` |
| status / stats | `bn_analysis_status`, `bn_analysis_update_and_wait`, `bn_binary_view_info`, `bn_binary_view_triage` |
| functions | `bn_function_list`, `bn_function_search`, `bn_function_info` |
| code | `bn_function_decompile`, `bn_function_disassembly` |
| calls | `bn_function_callers`, `bn_function_callees`, `bn_function_xrefs_to` |
| data | `bn_string_list`, `bn_symbol_list`, `bn_section_list`, `bn_memory_read`, `bn_data_at` |
| (broken, see §2c) | `bn_data_xrefs_to`, `bn_data_xrefs_from` |

---

## 2. The four gotchas

### a. Personal license = **no headless analysis**. Do not try.

```
bn.load("/path/to/binary")  ->  RuntimeError('License is not valid. Please supply a valid license.')
```

This happens even though a valid license sits at
`~/Library/Application Support/Binary Ninja/license.dat` (product = `Binary Ninja Personal`).
**The free Personal tier does not license the API outside the GUI.** Only the running GUI instance
is licensed.

Consequences:
- All analysis goes through the MCP. No batch scripts.
- `scripts/bnpy`, `scripts/bn_lib.py`, `scripts/bn_query.py`, `scripts/bn_build.py` are headless
  and therefore **dead code** — don't sink time into them.
- Paths: `PYTHONPATH="/Applications/Binary Ninja.app/Contents/Resources/python"`,
  `DYLD_FALLBACK_LIBRARY_PATH="/Applications/Binary Ninja.app/Contents/MacOS"`.

### b. ONE active binary view — parallelise by *phase*, never by *binary*

Every query tool acts on the **active** view. There is no view handle parameter on
`bn_function_decompile` / `bn_string_list` / etc.

Safe recipe for many concurrent agents:
1. Orchestrator opens binary X (`setActive: true`), runs `bn_analysis_update_and_wait`.
2. Launch N agents against X. **Every agent prompt must contain:**
   > do NOT call `bn_binary_view_set_active` and do NOT call `bn_open_item_open`.
   Concurrent *read-only* queries on one view are fine; a stray view switch silently corrupts
   everyone else's results.
3. Wait for all agents. Only then switch the view and start the next wave.

### c. No code→data cross-references. This is the big one.

`bn_data_xrefs_to`, `bn_data_xrefs_from` and `bn_function_xrefs_to` return **empty** for iOS
kernelcache kexts and DSC dylibs (chained-fixup / PAC). `bn_string_list` works, but you cannot ask
"which function uses this string" — which kills the normal workflow on stripped binaries.

**Workaround — `scripts/ds_locate_strrefs.py`** (locator only; all analysis stays in Binary Ninja).
It parses the Mach-O, scans executable sections for `adrp`+`add` / `adrp`+`ldr` pairs, and prints
the code VA that materialises a given string/const address:

```bash
PY=/Users/pauyedin/.workbuddy-ai/binaries/python/versions/3.13.12/bin/python3
cd /Users/pauyedin/DirtySlide/scripts

# by explicit string addresses (get them from bn_string_list first)
$PY ds_locate_strrefs.py <macho> 0x<va> 0x<va> ...

# or: any target inside an address range
$PY ds_locate_strrefs.py <macho> --range 0xSTART 0xEND
```

Then resolve the containing function:

```
DeferExecuteTool(toolName="mcp__binja-mcp__bn_function_list",
                 params={"start":"0x<code_va>","length":4096,"limit":40})
```

Many Apple kexts also keep **C++ signature strings** in `__cstring`
(`"IOReturn AppleJPEGDriver::startDecoder(AppleJPEGDriverIOStruct *)"`) — `bn_string_list` for the
method name, then locate. That is how the stripped JPEG/SAR drivers were mapped.

### d. The decompiler lies about operand widths. Always confirm in disassembly.

Binary Ninja renders some 32-bit loads/stores as 64-bit. Example that nearly produced a false CVE:
`AppleAVD`'s patch applier decompiled as `uint64_t x21_1 = x8_1[3]` (which would fold the adjacent
u32 addend into the high half of a write address = "arbitrary kernel write"), but the real
instruction is `ldr w21, [x8, #0x18]` — a 32-bit, zero-extended load, and the code is bounds-safe.

**Rule: any claim about a size, index or offset must be backed by `bn_function_disassembly`.**
Also watch for stores rendered as int32/int128.

---

## 3. Loading binaries

Open with the Mach-O view (BN usually marks it `recommended: true` and auto-activates it; ignore
the sibling `Raw` view):

```
DeferExecuteTool(toolName="mcp__binja-mcp__bn_open_item_open",
                 params={"kind":"file","path":"<abs path>","setActive":true})
DeferExecuteTool(toolName="mcp__binja-mcp__bn_analysis_update_and_wait", params={})
DeferExecuteTool(toolName="mcp__binja-mcp__bn_binary_view_triage", params={})   # counts
```

| target | how to get it | BN platform | symbols |
|---|---|---|---|
| DSC dylib | `ipsw dyld extract <cache> <dsc-path> -o dylibs` | `ios-aarch64` | **rich demangled C++** (AVD, H16ISP) |
| kext | `ipsw kernel extract -a -o kexts <kernelcache>` | `mac-aarch64` | stripped `sub_*`, some keep signature strings |
| kernel | **use `kexts/com.apple.kernel`** (12.5 MB) | `ios-aarch64` | 212 syms / 5886 fns |
| kernelcache | ⚠ **do not load** | — | loads as `KCView` mapping only the header → **0 functions** |

Extraction recipe (24A435 already done → `/Users/pauyedin/24A435__iPhone17,5/`):

```bash
ipsw extract --kernel -o OUT iPhone17,5_27.0_24A435_Restore.ipsw
ipsw kernel extract -a -o OUT/kexts OUT/24A435__iPhone17,5/kernelcache.release.iPhone17,5
ipsw extract --dyld --dyld-arch arm64e -o OUT iPhone17,5_27.0_24A435_Restore.ipsw
ipsw dyld extract OUT/24A435__iPhone17,5/dyld_shared_cache_arm64e \
    /System/Library/VideoDecoders/AVD.videodecoder -o OUT/dylibs
```

Paging: list tools take `offset`/`limit` (cap 1000). `bn_function_decompile` takes `offset`/`limit`
too — a 1000-block function must be paged.

---

## 4. Copy-paste agent brief

Drop this block into every analysis agent (fill in the brackets):

```
You are reversing <BINARY> with **Binary Ninja only** (no Ghidra, no IDA).

The active Binary Ninja view is <NAME> (<arch>, <base>, <N> functions).
CRITICAL: do NOT call bn_binary_view_set_active and do NOT call bn_open_item_open —
other agents share this view. Read-only queries only.

Tool access (deferred — load schemas first):
  ToolSearch(tool_names=["mcp__binja-mcp__bn_function_decompile",
    "mcp__binja-mcp__bn_function_disassembly","mcp__binja-mcp__bn_function_search",
    "mcp__binja-mcp__bn_function_list","mcp__binja-mcp__bn_function_callers",
    "mcp__binja-mcp__bn_function_callees","mcp__binja-mcp__bn_function_info",
    "mcp__binja-mcp__bn_string_list","mcp__binja-mcp__bn_symbol_list",
    "mcp__binja-mcp__bn_memory_read"])
  DeferExecuteTool(toolName="mcp__binja-mcp__bn_function_decompile",
                   params={"function":"0xADDR","limit":1000})

KNOWN LIMITATIONS OF THIS MCP:
1. bn_data_xrefs_to / bn_data_xrefs_from / bn_function_xrefs_to return EMPTY.
   Never conclude "unreachable" from an empty xref. To find code referencing a string/const,
   run from Bash (locator only; analysis stays in Binary Ninja):
     cd /Users/pauyedin/DirtySlide/scripts && \
     /Users/pauyedin/.workbuddy-ai/binaries/python/versions/3.13.12/bin/python3 \
       ds_locate_strrefs.py <BINARY_PATH> 0x<string_va> ...
   then resolve the containing function with bn_function_list(start/length).
2. The decompiler mis-renders 32-bit loads/stores as 64-bit. ALWAYS confirm widths
   (ldr w vs ldr x, mul w vs mul x, adds+b.hs carry guards) in bn_function_disassembly
   before claiming an overflow, truncation or OOB.

Write findings to /Users/pauyedin/DirtySlide/analysis/<topic>.md. Label every candidate
PROVEN BUG / STRONG / SPECULATIVE / REFUTED. Quote real disassembly; never fabricate
addresses or code. A clean negative is a real result.
```

---

## 5. Judgement rules that paid off

- **A newly-added validation string marks a bug that was already fixed.** In `AppleSARService` and
  `ApplePearlSEPDriver` the added checks were present and correct; siblings already had equivalents.
  Good for finding where a bug *was*, bad for finding a live one.
- **Assert strings are gates or logs — inspect the branch target.** Log-and-continue vs branch to
  an error return are indistinguishable in pseudo-C.
- **Look for validation divergence between sibling/variant implementations** (base vs `Ext` vs
  `2024`, or one SoC generation vs another). That is how the Face ID and JPEG leads were found.
- **Trace the value to a real memory operation before claiming impact.** Twice a wrapped 32-bit
  value turned out to feed only a hardware descriptor, or to be re-clamped downstream.
