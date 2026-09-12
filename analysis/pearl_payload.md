> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# ApplePearlSEPDriver — payload-size validation analysis (iOS 27.0 RC, 24A435)

Target: `com.apple.driver.ApplePearlSEPDriver` (Mach-O kext, mac-aarch64, image start
`0xfffffff00769bde0`). Analysis performed with Binary Ninja MCP only (read-only; active
binary view was never changed). All quotes below are verbatim from
`bn_function_disassembly` / `bn_function_decompile` / `bn_memory_read`.

Giant dispatcher under analysis:

* `sub_fffffff00935400c` @ `0xfffffff00935400c` .. `0xfffffff009358f13`, 1000 basic blocks,
  6152 disassembly lines / 4721 decompiler lines.
* Definition: `uint64_t(int64_t* arg1, void* arg2, int32_t* arg3, int64_t arg4, int64_t* arg5, int32_t* arg6)`
  (aapcs64: `x0=arg1, x1=arg2, x2=arg3, x3=arg4, x4=arg5, x5=arg6`).
* Prologue maps: `x19=arg1` (driver), `x24=arg2` (cmd header), `x21=arg3` (payload),
  `x20=arg4` (**payloadSize**), `x23=arg5` (outData), `x22=arg6` (outSize).

Log strings emitted at entry:
`"%s <- cmd:%p, payload:%p, payloadSize:%lu outData:%p, outSize:%p\n"` (`0xfffffff0076a7b81`)
and `"%s: command:%s (%d), value:%d, inLength:%lu, outLength:%d\n"` (`0xfffffff0076a7bc3`).
Both confirm `payloadSize == arg4` (x3/x20).

---

## 1. The two size-check sites

### 1a. `cmd_load_ref_frames_info_record_in_v1_t` (case 0x2f, cmd 0x30 = 48)

Handler + check, `0xfffffff0093547d4`:

```
0xfffffff0093547d4  {Case 0x2f}
0xfffffff0093547d8  ldrh    w8, [x24, #0x4]          ; cmd->version
0xfffffff0093547dc  cmp     w8, #0x1
0xfffffff0093547e0  b.ne    0xfffffff0093576a0       ; version != 1 -> assert
0xfffffff0093547e4  cbz     x20, 0xfffffff009357bb0  ; <== SIZE CHECK: payloadSize == 0 -> fail
0xfffffff0093547e8  ldrb    w8, [x21]                ; read payload[0]  (1 byte)
0xfffffff0093547ec  cbnz    w8, 0xfffffff0093547fc
0xfffffff0093547f0  ldr     w8, [x19, #0x7c8]
0xfffffff0093547f4  cmn     w8, #0x1
0xfffffff0093547f8  b.ne    0xfffffff009358cb4
0xfffffff0093547fc  ldr     x0, [x19, #0x170]
0xfffffff009354800  mov     w1, #0x68
0xfffffff009354804  mov     x2, x21                  ; payload
0xfffffff009354808  mov     x3, x20                  ; payloadSize
0xfffffff00935480c  mov     x4, #0
0xfffffff009354810  mov     x5, #0
0xfffffff009354814  mov     w6, #0
0xfffffff009354818  bl      sub_fffffff0093937e4     ; __auth_stub (imported)
```

The failure target `0xfffffff009357bb0` is the assert *setup* block referenced by the
release diff:

```
0xfffffff009357bb0  mov     w20, #0x2c2
0xfffffff009357bb4  movk    w20, #0xe000, lsl #0x10   ; w20 = 0xe00002c2
0xfffffff009357bb8  mov     w8, #0x542                ; source line 1346
0xfffffff009357bbc  adrp    x9, 0xfffffff00769c000
0xfffffff009357bc0  add     x9, x9, #0xaa1            ; .cpp path
0xfffffff009357bc4  stp     x9, x8, [sp, #0x20]
0xfffffff009357bc8  adrp    x8, 0xfffffff00769c000
0xfffffff009357bcc  add     x8, x8, #0xaa0
0xfffffff009357bd0  adrp    x9, 0xfffffff00769d000
0xfffffff009357bd4  add     x9, x9, #0x632            ; "payloadSize >= __builtin_offsetof(
                                                  ;   cmd_load_ref_frames_info_record_in_v1_t,
                                                  ;   refFramesInfoRecordData)"
0xfffffff009357bd8  b       0xfffffff009358370
```

**Exact comparison / constant:** `cbz x20` ⇒ enforced condition is `payloadSize != 0`
(i.e. `payloadSize >= 1`). The assert text claims `>= offsetof(...,refFramesInfoRecordData)`;
therefore `offsetof(refFramesInfoRecordData) == 1` — the struct has a 1-byte prefix
(the handler reads exactly one byte, `ldrb w8,[x21]`), so the emitted constant is consistent
with the assertion. (If the offset had been 4, the compiler would have emitted
`cmp x20,#4; b.lo`, not `cbz`.)

### 1b. `cmd_process_frame_metadata_in_v1_t` (case 0x56, cmd 0x57 = 87)

`0xfffffff009356054`:

```
0xfffffff009356054  {Case 0x56}
0xfffffff009356058  ldrh    w8, [x24, #0x4]          ; cmd->version
0xfffffff00935605c  cmp     w8, #0x1
0xfffffff009356060  b.ne    0xfffffff0093579ec
0xfffffff009356064  cmp     x20, #0x2e               ; <== SIZE CHECK
0xfffffff009356068  b.ls    0xfffffff0093580dc       ; payloadSize <= 0x2e -> fail
0xfffffff00935606c  strb    wzr, [sp, #0x50 {var_a0}]
0xfffffff009356070  ldr     x16, [x19]
0xfffffff009356074  mov     x17, x19
0xfffffff009356078  movk    x17, #0xcda1, lsl #0x30
0xfffffff00935607c  autda   x16, x17
0xfffffff009356080  mov     x17, #0x680
0xfffffff009356084  add     x16, x16, x17
0xfffffff009356088  ldr     x8, [x16]                ; vtable slot +0x680
0xfffffff00935608c  add     x2, sp, #0x50 {var_a0}
0xfffffff009356090  mov     x0, x19
0xfffffff009356094  mov     x1, x21                  ; payload  (NOTE: no size passed)
0xfffffff009356098  movk    x16, #0xb136, lsl #0x30
0xfffffff00935609c  blraa   x8, x16                  ; virtual call(driver, payload, &out)
```

**Exact comparison / constant:** `cmp x20, #0x2e ; b.ls` ⇒ `payloadSize >= 0x2f`
(sizeof `cmd_process_frame_metadata_in_v1_t` = 47).

Fail block `0xfffffff0093580dc`:

```
0xfffffff0093580dc  mov     w20, #0x2c2
0xfffffff0093580e0  movk    w20, #0xe000, lsl #0x10   ; w20 = 0xe00002c2
0xfffffff0093580e4  mov     w8, #0x749                ; source line 1865
...
0xfffffff0093580fc  adrp    x9, 0xfffffff00769d000
0xfffffff009358100  add     x9, x9, #0xa18            ; "payloadSize >= sizeof(
                                                  ;   cmd_process_frame_metadata_in_v1_t)"
0xfffffff009358104  b       0xfffffff009358370
```

### 1c. Enforced vs log-only — VERDICT

Both sites converge on the shared assert handler `0xfffffff009358370`:

```
0xfffffff009358370  stp     xzr, x8, [sp, #0x10]
0xfffffff009358374  stp     x26, x9, [sp]
0xfffffff009358378  adrp    x0, 0xfffffff00769c000
0xfffffff00935837c  add     x0, x0, #0xa56   ; "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d\n\n\n"
0xfffffff009358380  bl      sub_fffffff0093931e4
0xfffffff009358384  b       0xfffffff009357128     ; NOT fall-through: error-return path
```

`0xfffffff009357128` is the *error* path (it logs `"%s -> err:0x%x\n"` with `w20`) and
falls to the function epilogue at `0xfffffff0093572a0`:

```
0xfffffff0093572a0  ldur    x8, [fp, #-0x58]        ; stack canary
0xfffffff0093572b0  cmp     x9, x8
0xfffffff0093572b4  b.ne    0xfffffff009358dc4      ; __stack_chk_fail
0xfffffff0093572b8  mov     x0, x20                 ; return the error code
0xfffffff0093572d8  retab
```

The success path is a *different* address (`0xfffffff009357270`, reached via
`0xfffffff009357124  cbz w20, 0xfffffff009357270`). The assert path deliberately skips the
`cbz` and jumps into the error log, so it can never continue parsing.

**VERDICT: both checks are ENFORCED, not log-only.** On failure the function returns
`0xe00002c2` (or `0x102` for the `0xfffffff009356b28` variant used by the PSD-magic /
`cmd->version == 1` asserts) and performs **no** payload dereference. The
"assert compiles to log-and-continue" hypothesis is **REFUTED** for both new assertions.

---

## 2. Provenance of `payloadSize`

* `payloadSize` is **`arg4`** (`x20` in the body), fixed at the prologue:
  `0xfffffff00935403c  mov x20, x3`. It is a distinct scalar argument.
* It is **not** read from the untrusted command header. The header `arg2` is only used for:
  `ldrh w26,[x24,#0x2]` (command), `ldrh w8,[x24,#0x4]` (version),
  `ldrh w8,[x24,#0x6]` (value). So the checks compare a *separately supplied* size against a
  constant — the "attacker controls the size that is compared" trap does not apply at this
  level.
* The caller is not statically resolvable: `bn_function_callers` on `0xfffffff00935400c`
  returns **0 rows** (the routine is reached through a PAC-authenticated indirect branch,
  `blraa`/`autda`, not a direct `bl`).
* Boundary evidence: the kext contains an IOKit user client — `ApplePearlUserClient`
  (`0xfffffff0076a796c`), with `externalMethod`-style logging
  `"ApplePearlUserClient::%s <- selector:%u, arguments:%p, dispatch:..."` (`0xfffffff0076ac80d`)
  and `"IOBioUtils::writeBytesToIOMD(outData, &response, sizeof(response), outSize) == 0 "`
  (in this dispatcher). `outData`/`outSize` are therefore IOKit memory-descriptor arguments,
  i.e. this is the user-client command path. A userspace caller is the plausible origin of
  `payload`/`payloadSize`.
* **Residual uncertainty (SPECULATIVE):** whether `payloadSize` is bound to the actual
  buffer length (`structureInputSize`) or is an independent scalar could not be resolved
  without the user-client dispatcher. If it is `structureInputSize`, the checks are sound;
  if it is an unrelated scalar, they are not. Not proven either way here.

---

## 3. Command table

Dispatch is a 94-entry jump table at `0xfffffff009358f10` (read via `bn_memory_read`,
`ldrsw` offsets relative to `0xfffffff009354134`), selected by `cmd = *(u16*)(arg2+2)`,
index `cmd-1`, range `0..0x5d` (cmds 1..94). Decompiler `case N` == table index `N` ==
`cmd N+1`.

Legend: **E** = size check present and *enforced* (failure returns an error);
**—** = no size check (payload+size forwarded to an imported `__auth_stub`); the helper
receives both pointer and length. `read` = direct local dereference of `arg3`.

| cmd (hex) | case | assert string / check | enf | direct read of arg3 |
|---|---|---|---|---|
| 0x01 | 0x00 | `>= sizeof(cmd_get_cmd_protocol_version_in_v1_t)`, `arg4<=3` | E | `*arg3` 4B |
| 0x02 | 0x01 | — | — | none (forwarded) |
| 0x03 | 0x02 | `>= sizeof(cmd_enroll_mode_in_v1_t)`, `arg4<=0x4c` | E | via helper |
| 0x04 | 0x03 | `>= sizeof(cmd_match_mode_in_v1_t)`, `arg4<=0x4c` | E | via helper |
| 0x05 | 0x04 | `>= sizeof(cmd_face_detect_mode_in_v1_t)`, `arg4<=8` | E | via helper |
| 0x06 | 0x05 | — | — | none |
| 0x07 | 0x06 | `>= sizeof(cmd_request_message_data_in_v1_t)`, `arg4<=7` | E | `*arg3` 4B |
| 0x08 | 0x07 | `>= sizeof(cmd_initialize_engine_in_v1_t)`, `arg4<=1` | E | `initOptionsMask` |
| 0x09 | 0x08 | `!arg4` (+ overflow, `arg4+0x54 <= *outSize`) | E | alloc+copy (see §5) |
| 0x0a | 0x09 | `>= sizeof(*psdHeader)` `arg4<=7`, `>= sizeof(*psd3)` `arg4<=0x5b` | E | magic, version |
| 0x0b | 0x0a | — | — | none |
| 0x0c | 0x0b | `>= sizeof(cmd_get_free_identity_count_in_v1_t)`, `arg4<=3` (+`*outSize`) | E | `*arg3` |
| 0x0d | 0x0c | — | — | none |
| 0x0e | 0x0d | — | — | none |
| 0x0f | 0x0e | `>= sizeof(cmd_prepare_save_catacomb_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x10 | 0x0f | `>= sizeof(cmd_complete_save_catacomb_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x11 | 0x10 | `>= sizeof(cmd_confirm_save_catacomb_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x12 | 0x11 | `> sizeof(catacomb_header_t)`, `arg4<=0x20` | E | `arg3[2]` |
| 0x13 | 0x12 | `>= sizeof(cmd_no_catacomb_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x14 | 0x13 | — | — | none (forwarded) |
| 0x15 | 0x14 | `>= sizeof(cmd_remove_identity_in_v1_t)`, `arg4<=0x13` | E | `*arg3` |
| 0x16 | 0x15 | `>= sizeof(cmd_remove_user_data_in_v1_t)`, `arg4<=3` | E | `*arg3` (loop) |
| 0x17 | 0x16 | — | — | none |
| 0x18 | 0x17 | `>= sizeof(cmd_get_catacomb_id_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x19 | 0x18 | `>= sizeof(cmd_get_catacomb_hash_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x1a | 0x19 | `>= sizeof(cmd_get_protected_config_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x1b | 0x1a | `>= sizeof(cmd_set_protected_config_in_v1_t)`, `arg4<=0x43` | E | `*arg3` |
| 0x1c | 0x1b | — | — | none |
| 0x1d | 0x1c | `>= sizeof(cmd_set_system_protected_config_in_v1_t)`, `arg4<=0x4b` | E | via helper |
| 0x1e | 0x1d | `>= sizeof(*psdHeader)`, `>= sizeof(*psd3)`, magic/version | E | magic, version |
| 0x1f | 0x1e | `>= sizeof(cmd_set_logging_state_in_v1_t)`, `arg4<=1` | E | `arg3` to vcall (no size) |
| 0x20 | 0x1f | `>= sizeof(cmd_enable_match_auto_retry_in_v1_t)`, `!arg4` | E | `ldrb [arg3]` |
| 0x21 | 0x20 | — | — | none |
| 0x22 | 0x21 | — | — | none (forwarded) |
| 0x23 | 0x22 | — | — | none (forwarded) |
| 0x24 | 0x23 | `>= sizeof(cmd_load_fdr_class_in_v1_t)`, `arg4<=0xc` | E | via helper |
| 0x25 | 0x24 | — | — | none |
| 0x26 | 0x25 | — | — | none |
| 0x27 | 0x26 | — | — | none |
| 0x28 | 0x27 | `>= sizeof(cmd_force_biolockout_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x29 | 0x28 | `>= sizeof(cmd_get_sks_lock_state_in_v1_t)`, `arg4<=3` | E | `*arg3` |
| 0x2a | 0x29 | — | — | none |
| 0x2b | 0x2a | — (reads `ldrb [arg3]` only when `arg4!=0`) | — | `ldrb [arg3]` |
| 0x2c | 0x2b | `>= sizeof(cmd_self_check_result_in_v1_t)`, `arg4<=0x23` | E | `arg3[1..8]` |
| 0x2d | 0x2c | — | — | none |
| 0x2e | 0x2d | — | — | none (forwarded) |
| 0x2f | 0x2e | — | — | none |
| 0x30 | 0x2f | **`>= offsetof(...,refFramesInfoRecordData)` ⇒ `cbz` (≥1)** | **E** | **`ldrb [arg3]` (1B)** |
| 0x31 | 0x30 | `>= sizeof(*request)`, `arg4<=8` | E | `*arg3` 4B |
| 0x32 | 0x31 | `>= sizeof(cmd_suspend_enrollment_in_v1_t)`, `!arg4` | E | via helper |
| 0x33 | 0x32 | — | — | none (forwarded) |
| 0x34 | 0x33 | — | — | none |
| 0x35 | 0x34 | — | — | none |
| 0x36 | 0x35 | — | — | none (cmd->value only) |
| 0x37 | 0x36 | — | — | none |
| 0x38 | 0x37 | `>= sizeof(*request)`, `arg4<=2` | E | `ldrb [arg3]` |
| 0x39 | 0x38 | — | — | none (forwarded) |
| 0x3a | 0x39 | — | — | none |
| 0x3b | 0x3a | — | — | none |
| 0x3c | 0x3b | `>= sizeof(cmd_enable_combined_sequence_in_v1_t)`, `!arg4` | E | `ldrb [arg3]` |
| 0x3d | 0x3c | — | — | none |
| 0x3e | 0x3d | — | — | none (cmd->value only) |
| 0x3f | 0x3e | — | — | none |
| 0x40 | 0x3f | — | — | none (forwarded) |
| 0x41 | 0x40 | — | — | none |
| 0x42 | 0x41 | `>= sizeof(cmd_get_templates_validity_in_v1_t)`, `arg4<=3` (+out) | E | via helper |
| 0x43 | 0x42 | — | — | none |
| 0x44 | 0x43 | — | — | none |
| 0x45 | 0x44 | — | — | none (forwarded) |
| 0x46 | 0x45 | `>= sizeof(cmd_sea_cookie_handle_message_in_v1_t)`, `arg4<=0xc` | E | via helper |
| 0x47 | 0x46 | — | — | none (forwarded) |
| 0x48 | 0x47 | `>= sizeof(cmd_map_s3_in_v1_t)`, `arg4<=4` | E | `arg3` 4B |
| 0x49 | 0x48 | — | — | none |
| 0x4a | 0x49 | — | — | none |
| 0x4b | 0x4a | `payload` (`!arg3`) | E | none (forwarded) |
| 0x4c | 0x4b | `outData`/`outSize` | E | none |
| 0x4d | 0x4c | `payload` (`!arg3`) | E | none (forwarded) |
| 0x4e | 0x4d | — | — | none |
| 0x4f | 0x4e | `payload` (`!arg3`) | E | none (forwarded) |
| 0x50 | 0x4f | `payload`/`payloadSize`/`outData`/`outSize`/camIn + overflow | E | alloc+copy (see §5) |
| 0x51 | 0x50 | `>= sizeof(*psd3)`, `arg4<=0x5b`, magic/version | E | magic, version |
| 0x52 | 0x51 | `>= sizeof(cmd_alloc_map_s3c1_in_v1_t)`, `arg4<=6` | E | `arg3[0..6]` |
| 0x53 | 0x52 | `>= sizeof(cmd_set_secure_fd_state_in_v1_t)`, `arg4<=0x14` | E | `arg3` to vcall |
| 0x54 | 0x53 | — | — | none |
| 0x55 | 0x54 | — | — | none |
| 0x56 | 0x55 | — | — | none |
| 0x57 | 0x56 | **`>= sizeof(cmd_process_frame_metadata_in_v1_t)`, `arg4<=0x2e`** | **E** | **vcall(slot +0x680), no size** |
| 0x58 | 0x57 | `outData`/`outSize` | E | none |
| 0x59..0x5d | 0x58..0x5c | — (generic vtable call `[+0x628](arg2..arg6)`) | — | delegated |
| 0x5e | 0x5d | — | — | none |

**Worst row:** `cmd 0x57` (process_frame_metadata). It is the only enforced size check whose
value is **not propagated** to the code that consumes the payload (the `blraa` at
`0xfffffff00935609c` passes only `x1 = payload`). Every other direct reader is a ≤4-byte
scalar whose check covers it, or forwards `(pointer, size)` to an imported helper.

---

## 4. Read offsets vs. the size constant

Verified in **disassembly** (the decompiler over-widens many loads; e.g. it rendered
`ldrb w9,[x21]` as `uint32_t *arg3`). Confirmed 1-byte reads for the cases that looked like
4-byte over-reads:

* `cmd 0x20` (`0xfffffff009355678  ldrb w9, [x21]`) with check `>= 1` — in bounds.
* `cmd 0x3c` (`0xfffffff009356280  ldrb w8, [x21]`) with check `>= 1` — in bounds.
* `cmd 0x38` (`0xfffffff0093565e8  ldrb w8, [x21]`) with check `>= 3` — in bounds.
* `cmd 0x30` (`0xfffffff0093547e8  ldrb w8, [x21]`) with check `>= 1` — in bounds.

No command was found whose local dereference exceeds its enforced constant.

### The `load_ref_frames` array hypothesis — REFUTED (locally)

The concern was that `>= offsetof(...,refFramesInfoRecordData)` only bounds the array *start*.
In this binary the emitted constant is `1` (a `cbz`), matching a 1-byte prefix; the handler
reads exactly that one byte and then hands **both** `x2 = payload` and `x3 = payloadSize` to
`sub_fffffff0093937e4`. That target lies in `__auth_stubs`
(`0xfffffff009393174..0xfffffff009393d14`) — it is an **imported** function
(`bn_function_decompile` renders it as a stub: `/* jump -> -0x80110000025a8f70 */`).
There is no local count-driven iteration over `refFramesInfoRecordData`; the array is parsed
by the external callee, which receives the true length. **No local OOB read.**

---

## 5. Copies of `payloadSize`-derived lengths

Two commands allocate then copy; both are bounded:

* **cmd 0x09** (case 0x08): `x25 = payloadSize + 0x54`; allocation of `x25`;
  `sub_fffffff009393c64(buf + 0x44, arg3, arg4)` copies `payloadSize` bytes at offset `0x44`.
  Destination capacity is `payloadSize + 0x54`; `0x44 + payloadSize <= 0x54 + payloadSize`. Fits.
* **cmd 0x50** (case 0x4f): `x24 = payloadSize + 0x38`; allocation of
  `x24`; `sub_fffffff009393c64(buf + 0x38, arg3, arg4)`. Capacity `payloadSize + 0x38`;
  `0x38 + payloadSize <= 0x38 + payloadSize`. Fits exactly.

No unchecked length reaches a fixed-size kernel buffer. **No OOB write found.**

---

## 6. Reachability

* `bn_function_callers(sub_fffffff00935400c)` → **0 callers** (indirect PAC dispatch; not a
  direct `bl`). The routine is invoked as a virtual/gated method, not from a known callsite.
* The kext ships an IOKit user client (`ApplePearlUserClient`, `0xfffffff0076a796c`) with an
  `externalMethod` (`selector:%u, arguments:%p, dispatch:...`, `0xfffffff0076ac80d`) and
  `IOBioUtils::writeBytesToIOMD(outData, ..., outSize)` output handling. This is the
  userspace boundary; a userspace caller supplying `payload`/`payloadSize` is the plausible
  origin (STRONG, by construction of the kext, though the exact dispatch edge was not
  statically resolved).
* The actual command payload parsing is delegated to imported `__auth_stub` helpers
  (`sub_fffffff0093937c4`, `sub_fffffff0093937e4`), i.e. outside this kext image.

---

## 7. Candidates, ranked

| # | Address | Read/write | Controlling input | Consequence | Confidence |
|---|---|---|---|---|---|
| C1 | `0xfffffff00935609c` (`cmd 0x57`) | virtual call `[vtable+0x680]` receives `payload` but **not** `payloadSize` | user payload, size asserted `>= 0x2f` | if the vtable callee reads beyond the 47-byte struct, OOB read; unverifiable without the callee | **SPECULATIVE** |
| C2 | `0xfffffff0093547e4` (`cmd 0x30`) | check is `payloadSize != 0` while assert names `offsetof(...)` | user `payloadSize` | none: constant `1` matches the 1-byte prefix read; array parsed by external stub with real size | **REFUTED** |
| C3 | ~30 cases with `—` | no local size check | user payload+size | none locally: payload+size are forwarded together to imported helpers; no local dereference | **REFUTED** (as local bugs) |
| C4 | `cmd 0x09`, `cmd 0x50` | `memcpy(payloadSize)` into `alloc(payloadSize + hdr)` | user `payloadSize` | none: copy fits the allocation | **REFUTED** |
| C5 | both new asserts | `assert()` failure path | — | returns `0xe00002c2`; does **not** continue | **REFUTED** (log-only hypothesis) |

**No PROVEN BUG. Best available (unproven) lead is C1 (SPECULATIVE).**

### Methodology / limitations
* Read-only Binary Ninja MCP queries only; `bn_binary_view_set_active` and `bn_open_item_open`
  were never called.
* String/data xrefs are unreliable in this build (documented); no "unreachable" conclusion
  was drawn from an empty xref. `bn_function_callers` empty ⇒ indirect invocation only.
* All load/store widths were confirmed in `bn_function_disassembly`; the decompiler's
  over-wide `int32_t*`/`uint64_t` renderings are noted and were not relied upon.
* Constants quoted: site 1 ⇒ `1` (via `cbz x20`); site 2 ⇒ `0x2f` (via `cmp x20,#0x2e; b.ls`).
