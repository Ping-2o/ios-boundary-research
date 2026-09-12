> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# VCPHEVC.videocodec — file / string parser audit (iOS 27.0 RC, 24A435)

Binary: `VCPHEVC.videocodec` (Mach-O dylib, ios-aarch64)
Image base `0x242599000`, `__text` `0x242599c98..0x2426e8780`, 2461 functions, stripped.
All queries via Binary Ninja MCP, read-only. **No `bn_binary_view_set_active` / `bn_open_item_open` was used.**

## 0. Executive summary

The named targets (`sub_242615520` config-file loader, `sub_2426163bc` config-content
parser, `sub_24265ea00` scaling-list loader, `sub_2425d6198` scaling-list parser) do **not**
use `fscanf`/`sscanf`/`strcpy`/`sprintf`/`fread` at all. They are built on C++
`std::ifstream` + `strtok_r` + `strtol`, and every buffer bound I could recover is
correctly enforced.

**One real finding:** a **missing recursion/re-entrancy guard** on the
`HEVCEncoderOptions` option handler (`sub_2426163bc`). The developer-added
"Config file within a config file not supported!" guard only covers the `config`
option (`sub_242615520`); the sibling `HEVCEncoderOptions` handler — which is itself a
valid option name dispatched by the same table — has no depth counter and recurses
unboundedly on a crafted option string. See §4.

Everything else is a clean negative or unlocalized.

---

## 1. Call-site table (fscanf / sscanf / fread / strcpy / sprintf / memcpy)

No `_fscanf`, `_strcpy`, `_sprintf`, `_fread`, `_strcat`, `_snprintf` call site was found in
the parser cluster. `_fscanf` **is** an imported symbol (GOT `0x2d4f7c940`, confirmed via
`bn_data_at`), but its call site could not be localized (string xrefs unavailable in this
view — see §6).

| # | Function | Call site | API (stub addr) | Format string (verbatim) | Destination | Destination size / where established | Verdict |
|---|----------|-----------|-----------------|--------------------------|-------------|----------------------------------------|---------|
| 1 | `sub_24265e794` (option `master-display`) | `0x24265e794` | `sscanf` `0x24809ad20` | `"%hu:%hu:%hu:%hu:%hu:%hu:%hu:%hu:%u:%u"` | `arg1+0x1ac,0x1ae,0x1b0,0x1b2,0x1b4,0x1b6,0x1b8,0x1ba` (8×16-bit) then `arg1+0x1bc`, `arg1+0x1c0` (2×32-bit) | option/context struct; fields are 16-bit and 32-bit respectively | **SAFE** — 10 conversions, return value checked `!= 0xa`; `%hu`→u16, `%u`→u32 match |
| 2 | `sub_24265e838` (option `ambient-viewing`) | `0x24265e838` | `sscanf` `0x24809ad20` | `"%u:%hu:%hu"` | `arg1+0x1d8` (u32), `arg1+0x1dc`, `arg1+0x1de` (u16) | option struct | **SAFE** — count checked `!= 3`; widths match |
| 3 | `sub_2426163bc` (config content parser) | `0x2426165f8` | `memcpy` `0x248095190` | n/a (copy of option name up to `'='`) | `var_480` = `sp+0x480` | 0x400 bytes (`sp+0x480..0x880`); length checked `< 0x3ff` at `0x2426165e0`; explicit NUL at `0x2426165fc` | **SAFE** |
| 4 | `sub_2426163bc` (config content parser) | `0x2426164e4` etc. | `memset` (inline `stp q0`) | n/a | token array `sp+0x80` (`var_880`) | 128 entries (`0x80..0x480`); bound `cmp x21,#0x7e; b.hi` at `0x242616520` | **SAFE** (max index 127) |
| 5 | `sub_24265ea00` (scaling-list file loader) | `0x24265eacc` | `memcpy` `0x248095190` | n/a (default scaling matrices) | `x20_1` = `operator new(0x620)` at `0x24265ea68` | 0x620 bytes; loop writes ≤ `3*0x186 + 5*0x41 + 0x41` = 0x618 | **SAFE** |
| 6 | `sub_2425d6198` (scaling-list content parser) | byte stores | n/a | n/a (parsed coefficient) | `arg1 + size_idx*0x186 + col*0x41 + 1` | buffer 0x620 (from caller `sub_24265ea00`); max write `0x556+0x40 = 0x596`; count bounded by `num_coeff` (`x24_1 >= x28_1` check) | **SAFE** |
| 7 | `sub_24265db58` (option `ref-struct`) | `0x24265dc2c` | pointer stores | n/a | token array `sp+0x60` (`var_240`) | 57 entries (`sp+0x60..0x227`), zeroed to `sp+0x230`; loop breaks at `cmp x23,#0x39` | **SAFE** |
| 8 | `sub_2426163bc` | `0x242616640, 0x24261684c, …` | `fprintf` `0x248099520` / `__fprintf_chk` `0x248095080` | `"Unable to open config file '%s'\n"`, `"'%s' option too long!\n"`, … | log stream | n/a (output) | **SAFE** |

Additional parsers checked and found bounded: `sub_24265d450` (vui-sar/max-cll), `sub_24265d894`
(bit-depth), `sub_24265db58` (ref-struct), and the helpers `sub_24265f77c`, `sub_24265f810`,
`sub_24265f8ac`, `sub_24265f9b4`, `sub_24265fa38` — all range-check before storing
(e.g. `x0 > 0xff` → error; `x0 >> 0x20` → error).

### `%15s%s%15s` — REFUTED as a scanf bug

`0x24271f9af` = `%15s%s%15s` sits in the frame-stats **output** header block. Its neighbours
are `"Time stamp"` (`0x24271f92d`), `"Frame"`, `"Dimension"`, `"Type"`, `"Complexities"`,
`"Bytes"`, `"Dlay"`, `"PSNR"`, `"Enc Time"`, `"Ref POCs"`, `"BitErrRatio"`,
`"PrevRcFrameBitRatio"` — i.e. column labels printed with `fprintf`. The unbounded middle
`%s` is a **printf** conversion (harmless), not a scanf conversion. **REFUTED.**

---

## 2. Config-file open/parse (`sub_242615520` → `sub_2426163bc`)

**`sub_242615520` @ `0x242615520`** — option handler for the literal option name `"config"`.

Evidence (disassembly, verbatim):

```
0x2426155e4  add     x0, sp, #0x140 {var_290}
0x2426155e8  mov     x1, x19                    ; x19 = arg4 = option value (path)
0x2426155ec  bl      sub_2425d6a60              ; construct ifstream + open(path, mode 8)
0x2426155f0  ldr     x8, [sp, #0x1c8 {var_208}]
0x2426155f4  cbz     x8, 0x2426157d0            ; stream not good -> error
...
0x2426157f4  add     x1, x1, #0xb2d  {data_24271db2d, "Unable to open config file '%s'\n"}
0x2426157f8  bl      0x248099520                ; fprintf
```

The file path is **arg4**, the option's argument string. `sub_2425d6a60` performs
`ifstream::open` (`0x248098290(&arg1[2], arg2, 8)`). The file is read into a
`std::string`, then handed to `sub_2426163bc`.

**`sub_2426163bc` @ `0x2426163bc`** — the config-content parser (registered as the
handler for option `"HEVCEncoderOptions"`). It:
1. `strdup`s the content (`0x248099c70`),
2. tokenises by line (`strtok_r` `0x248099cf0` with delim `"\r\n"` @ `0x24271db4e`),
3. skips leading blanks, strips trailing whitespace (`sub_2426169ec`),
4. skips `#` comments,
5. splits `option : argument` on `":"` (`0x242721cbf`),
6. dispatches each `option`/`argument` through `sub_242616a3c` → `sub_242616bb4`.

Delimiters confirmed by `bn_memory_read`:
- `0x24271db4e` = `"\r\n"`
- `0x24271db51` = `" \t"`
- `0x242721cbf` = `":"`

Bounds (all verified in §1 rows 3–4): the option-name copy is guarded by
`cmp x24, #0x3ff ; b.hs` (`0x2426165e0`), and the argv-style token array is capped at
128 entries by `cmp x21, #0x7e ; b.hi` (`0x242616520`) — exactly the 0x400 bytes
(`sp+0x80..sp+0x480`) that precede `var_480`. **No overflow.**

**Verdict for §2: clean.** No fscanf, no unbounded copy, no width mismatch.

---

## 3. Scaling-list file parse (`sub_24265ea00` → `sub_2425d6198`)

**`sub_24265ea00` @ `0x24265ea00`** — option handler for `"scaling-list-file"`.
Opens the path via `sub_2425d6a60` and, on failure, prints
`"Unable to open scaling list file '%s'\n"` (`0x24265eccc`). Allocates the 0x620-byte
scaling-matrix object (`0x2480aa590(0x620, …)` @ `0x24265ea68`) and fills defaults with
`memcpy` of 0x11/0x41-byte constant matrices at stride `i*0x186 + j*0x41` — max offset
`3*0x186 + 5*0x41 + 0x41 = 0x618 < 0x620`.

**`sub_2425d6198` @ `0x2425d6198`** — content parser. Tokenises with `strtok_r`, replaces
`'='`/`','` with spaces, parses `INTRA<size>_<plane>` / `INTER<size>_<plane>` headers and
coefficients with `strtol` (`0x248098bf0`). Size token validated against the set
`{4,8,16,32}` (`x8_9 = RORD(x0_17-4,2); x8_9 > 7 || !(1<<x8_9 & 0x8b)`), coefficient count
bounded by `num_coeff` (`x24_1 >= x28_1` → `"coeff_idx exceeded num_coeff"`), coefficient
value bounded `< 0x100`. Max write offset `0x556 + 0x40 = 0x596 < 0x620`.

**Verdict for §3: clean.**

---

## 4. Candidate finding — missing recursion guard on `HEVCEncoderOptions` (STRONG)

**Function:** `sub_2426163bc` @ `0x2426163bc` (option handler for `"HEVCEncoderOptions"`).

### The guard that exists (only on `config`)

`sub_242615520` (`"config"` handler) checks a per-table flag before doing anything:

```
0x242615558  ldrb    w8, [x0, #0x24]
0x24261555c  cmp     w8, #0x1
0x242615560  b.ne    0x2426155dc          ; flag != 1 -> proceed
...
0x242615574  add     x0, x0, #0xafc  {data_24271dafc, "Config file within a config file not supported!\n"}
0x242615590  bl      0x2480995a0          ; fwrite
...
0x2426155dc  mov     w8, #0x1
0x2426155e0  strb    w8, [x22, #0x24]     ; set the guard
```

So the `config` option is guarded at function entry. The flag is initialised to 0 in the
table constructor (`sub_2426151d0`: `*(arg1 + 0x24) = 0;`).

### The guard that does not exist

`sub_2426163bc` has **no** equivalent check. Its prologue is:

```
0x2426163bc  pacibsp
0x2426163c0  stp x28,x27,[sp,#-0x60]!
...
0x2426163dc  sub     sp, sp, #0x8a0          ; 2208-byte frame
0x2426163e0  str     x0, [sp, #0x58 {var_8a8}]
0x2426163e4  adrp x8, 0x2681b5000
...
0x2426163f4  cbz     x3, 0x242616804          ; only NULL check on the content
0x2426163f8  mov     x22, x2
0x2426163fc  mov     x0, x3
0x242616400  bl      0x248099c70              ; strdup(content)
```

There is no depth counter, no flag, no recursion limit anywhere in the 73-block function.

### Why it recurses

The handler is registered by name into the **same option table** it dispatches against:

`sub_24259d838` (encoder option-table constructor):
```
sub_242615464(&result[0x2d], -0x229921caa0554059, "HEVCEncoderOptions", sub_2426163bc, 0, 0);
sub_242615464(&result[0x2d], 0x6babb84d374647ca, "scaling-list-file", sub_24265ea00, 0, 0);
sub_242615464(&result[0x2d], 0x78039475c6a50527, "config",          sub_242615520, 0, 1);
```

`sub_242615464` stores the handler (`result[8] = arg4`) into the tree at `arg1+8`, keyed by
`arg2`; the dispatcher `sub_242616bb4` looks the option name up in that same tree and calls
`(*(*x0_5 + 8))(x0_5, arg4, x22, arg6)` — i.e. the handler receives the **table object**
as `arg1`. `sub_2426163bc` then calls `sub_242616a3c(arg1, …)` with that same object.

Therefore a content string containing the line

```
HEVCEncoderOptions : <another options string>
```

is dispatched back to `sub_2426163bc`, which `strdup`s and parses the nested string, which
can again contain `HEVCEncoderOptions : …`, etc.

### Controlling input / consequence

- The option string originates from the VideoToolbox session property
  `HEVCEncoderOptions` (an `NSString` in the session options dictionary) and, via the
  `config` option, from the contents of an attacker-named config file. Both are
  caller/attacker-influenced (see §5).
- Each recursion level consumes `0x8a0 + 0x60 ≈ 0x900` bytes of stack. A few hundred
  nested lines exhaust an iOS thread stack → **stack-overflow crash (DoS)**. No memory
  corruption is required; the failure mode is a controlled crash in the
  `mediaserverd`/VT decode-encode path.
- The `"Too many options (max %d)"` check limits options *per level* (128), not nesting
  depth, so it does not mitigate this.

### Confidence: **STRONG**

Registration, dispatch and the absence of a guard are all directly evidenced. Not
PROVEN only because I could not execute it; a single crafted property string should
confirm it.

### Secondary note (same root cause)

`sub_242615520`'s guard is a one-shot flag on the table object that is set to 1 and never
cleared inside the function. If the table object is process-global, a second legitimate
`config` load in the same process would be rejected — a functionality bug, not a
security bug. I could not confirm the object's lifetime.

---

## 5. Input provenance (are the paths attacker-controlled?)

**Yes — the parser inputs are reachable from VideoToolbox session properties.**

- `sub_2426151d0` (decoder-side table constructor) registers:
  ```
  sub_2426152b4(arg1, -0x55475c77cdb4ca47, "loglevel", &data_2702c3070, 0x2690215c0, -0x608bad228a2ab2cf);
  sub_242615464(arg1,  0x78039475c6a50527, "config",   sub_242615520, 0, 1);
  ```
- `sub_24259d838` (encoder-side table constructor) registers `HEVCEncoderOptions`,
  `scaling-list`, `scaling-list-file`, `master-display`, `ambient-viewing`, `vui-sar`,
  `max-cll`, `bit-depth`, `isp_meta_file`, `face_meta_file`, `logfile`, `fw_stats_path_prefix`,
  and ~150 more (full table recovered).
- `sub_242616bb4` dispatches `option_name → handler(table, argument, …)`, so the
  argument string of `config` / `scaling-list-file` / `HEVCEncoderOptions` is the file
  path or the option text.

These options are supplied through the `HEVCDecoderOptions` / `HEVCEncoderOptions`
dictionaries that VideoToolbox passes into the plugin. The path is **not** a fixed
system path — it is caller-supplied. This is what makes §4 reachable. (It also means the
parsers *would* be high-severity had a memory-safety bug existed; they do not.)

---

## 6. Unlocalized surface — ISP / Face metadata (`_fscanf`) — SPECULATIVE

The build imports `_fscanf` (GOT `0x2d4f7c940`; type
`int32_t(FILE*, char const*, ...)` per `bn_data_at`). Two strings in the
encoder metadata cluster are clearly **scanf** formats:

- `0x24271f45d` = `"ISP: framenum= %d capture_timestamp= %lf T= %lf AGC= %d sensorDGain= %d ispDGain= %d "`
- `0x24271f4b3` = `"AEAverage= %d AWBRGain= %d AWBGGain= %d AWBBGain= %d normalSNR= %lf\n"`
- `0x24271f4f8` = `"Face: framenum= %d capture_timestamp= %lf x= %f y= %f w= %f h= %f, "`
- `0x24271f53c` = `"face_roll= %d, face_yaw= %d\n"`

The corresponding option names `isp_meta_file` / `face_meta_file` are registered as
*string* options (`sub_24261602c(..., "isp_meta_file", &result[0x5a])`), so the file path
is again caller-supplied.

**I could not localize the function(s) that consume these formats.** `bn_data_xrefs_to`
returns empty for every address in this view (including string addresses), so I could not
enumerate the call sites; `bn_function_callees` does not resolve external symbols, so I
could not pivot from `_fscanf` either. I swept the plausibly-related functions
(`sub_24260dc54`, `sub_24260ac88`, `sub_24260b164`, `sub_2425d1fc0`, `sub_2425c6acc`,
`sub_2425d6198`, `sub_24265ea00`, …) without hitting them.

If these formats are used with `fscanf`/`sscanf`, the type choices (`%d`→int, `%lf`→double,
`%f`→float) must be checked against the destination struct — a `%lf` into a `float` field,
or `%f` into a `double`, would be an 8-byte-vs-4-byte write. **This is the single most
promising unexamined lead**, but it is **SPECULATIVE / UNCONFIRMED**: I have not seen the
call site, the destination addresses, or the destination sizes, and I will not assert a
bug from the format strings alone.

---

## 7. Confidence summary

| Candidate | Location | Class | Confidence |
|-----------|----------|-------|-----------|
| Unbounded self-recursion via nested `HEVCEncoderOptions` | `sub_2426163bc` @ `0x2426163bc` (dispatch via `sub_242616a3c`→`sub_242616bb4`) | DoS / stack exhaustion | **STRONG** |
| ISP/Face metadata `fscanf` type/width mismatch | reader unlocalized; formats @ `0x24271f45d`, `0x24271f4f8` | memory corruption | **SPECULATIVE** |
| `config`-in-`config` guard one-shot flag | `sub_242615520` @ `0x242615524`/`0x2426155e0` | logic (not security) | SPECULATIVE |
| `%15s%s%15s` unbounded `%s` | `0x24271f9af` | — | **REFUTED** (printf output, not scanf) |
| Config option-name copy overflow | `sub_2426163bc` `0x2426165f8` | — | **REFUTED** (len `< 0x3ff` guard) |
| Config argv array overflow | `sub_2426163bc` `0x242616520` | — | **REFUTED** (128-entry bound) |
| Scaling-list buffer overflow | `sub_2425d6198` / `sub_24265ea00` | — | **REFUTED** (writes ≤ 0x596 into 0x620) |
| Ref-struct token array overflow | `sub_24265db58` `0x24265dc2c` | — | **REFUTED** (57-entry bound) |
| sscanf width mismatch (master-display / ambient-viewing) | `sub_24265e794`, `sub_24265e838` | — | **REFUTED** (types match) |

---

## 8. Method / limitations

- Tools: `bn_function_decompile`, `bn_function_disassembly`, `bn_function_xrefs_to`,
  `bn_function_callers`, `bn_function_callees`, `bn_function_list`, `bn_string_list`,
  `bn_memory_read`, `bn_symbol_list`, `bn_data_at`, `bn_data_xrefs_to`, `bn_import_list`.
- `bn_data_xrefs_to` returned empty for **every** address tried (strings, GOT slots), as
  warned. All string-to-code attribution in this report is by manual `adrp`+`add`
  inspection of disassembly, not by xref queries.
- The decompiler mis-renders some 32-bit loads/stores as 64-bit and elides varargs; every
  width/bound claim above was re-checked in `bn_function_disassembly`.
- Stub addresses were identified by call signature + usage:
  `0x248099520` = `fprintf`, `0x248095080` = `__fprintf_chk`, `0x2480995a0` = `fwrite`,
  `0x24809ad20` = `sscanf`, `0x248099c70` = `strdup`, `0x248099cf0` = `strtok_r`,
  `0x248099c90` = `strlen`, `0x248099c30` = `strchr`, `0x248098bf0` = `strtol`,
  `0x248099d30` = `strtol(…,base 10)`, `0x248095190` = `memcpy`,
  `0x248098290` = `ifstream::open`. These identifications are consistent across all call
  sites examined and are corroborated by the observed argument shapes.
