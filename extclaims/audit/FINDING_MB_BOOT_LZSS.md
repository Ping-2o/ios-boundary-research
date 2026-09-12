> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# FINDING_MB_BOOT_LZSS.md — In-place LZSS decompression with constant output cap in iBEC recovery boot path (Apple Silicon t8140, iOS 26.6)

**Classification:** Candidate vulnerability — static analysis only. Not empirically confirmed on hardware. No exploit code shipped.
**Target:** iPhone 16e (iPhone17,5 / t8140 / V59), build 23G71 (iOS 26.6). Image: `iBEC.v59.RELEASE.im4p` → decompressed mBoot core (SHA-256 `48ff474e…`, 3,699,832 B raw AArch64, EL2, VA bias 0x1fc080000). The same core image is byte-identical across iBSS/iBEC/iBoot.
**Analysis context:** Ghidra 11.x headless via MCP; all addresses are file offsets (= Ghidra addresses, base 0). Evidence log: `AUDIT_NOTES.md` Rounds 1–9; raw receipts under `extclaims/`.

---

## 1. Executive summary

The iBEC recovery/DFU shell's image-boot path decompresses a host-supplied `comp`/`lzss` combo image **in place, into the buffer the host's data was received in**, with the LZSS output bound being the **hardcoded constant 0x1e000000** rather than the receiving allocation's size. The post-decompression size check (`decompressed == declared`) runs only after the writes are complete and therefore cannot prevent an overflow.

The receiving buffer is a `memz` allocation sized by a **host-controlled argument** (`filesize`/transfer size; capped 0x20000000). If the LZSS stream expands beyond that allocation, the decompressor writes out of bounds — **before any signature or Image4 validation** — at EL2 in the recovery shell.

The direct path is gated by a boot-mode byte (`DAT_00387488`) that only the validated loaders set; the direct `memboot → boot` flow does not set it. However, the byte is **sticky**: the boot-context property callback (`FUN_0002db0c`) writes `ctx[0] = 1` after successful Image4 property application — *before* the boot handover completes — and no code path resets it. A single failed `bootx` (validation succeeds, later stage fails, control returns to the shell) leaves the flag at 1, after which a small `memboot` of a crafted `comp` image reaches the unguarded decompression.

For contrast, the Image4 validator's own LZSS usage (post-signature, same binary) is correctly bounded with explicit CARRY8 checks against the allocation — the combo-loader site is the outlier.

**Impact shape:** pre-signature, attacker-length heap (or arena) OOB write in the iBEC recovery environment, reachable over USB from the DFU/recovery command interface. This is the same impact class as historical pre-boot bootrom/DFU bugs (the decompressor runs at EL2 with full device privilege, before the kernel exists). Exploitability specifics (arena layout, PAC, whether OOB lands in mapped heap vs unmapped) are not established by this analysis.

## 2. Evidence chain (every link static-verified)

### 2.1 The receiving buffer is host-sized
- `sh_memboot` @0x1958: parses `filesize` env (host-controlled; reject if ≥ 0x20000001 — "Combo image too large" @0x29b3a8), permission gate `FUN_0007fa3c` (receive region is the designed whitelist window — passes by design), receive via `FUN_0017d1c4`.
- `FUN_0017d1c4` @0x17d1c4: allocates the receive buffer via `FUN_000c3f84(arg_size, arg2, …)` — sizes from the command argument blob (host-controlled); result cached in globals `DAT_00336830/38`; image 4CC `rdsk` (0x7264736b).
- `FUN_000c3f84` @0xc3f84 → `FUN_000c3440` @0xc3440: creates/validates the **`memz`/`img4` allocation object** (magic check `0x4d656d7a`/`0x696d6734` at [obj+8]; recorded size at [obj+0]) from the requested size; forwards `size1`, `size2`, `size1+size2`.

### 2.2 The boot handover reaches the combo loader with the same buffer
- `sh_memboot` → `FUN_00001024(buf, size, &DAT_00387488, &DAT_00387488, 0x387538, &DAT_00202888)` (boot handler; unconditional in the receive-success path).
- `FUN_00001024` @0x1024 → `FUN_00031670` @0x31670 (sole BL caller @0x1104) → **`FUN_0002e24c`** (combo-image loader).

### 2.3 The unguarded in-place decompression (the core defect)
`FUN_0002e24c` 'comp' branch:
- Gate: `*param_3 == 1` (boot-mode byte) and image header `'comp'` (0x636f6d70) + `'lzss'` (0x6c7a7373) at the buffer start — **all host-controlled bytes**.
- Header fields: `[+0xc]` = declared decompressed size (w21; reject ≥ 0x1e000001), `[+0x10]` = compressed size (w28; reject ≥ 0x1e000001).
- Input scratch allocated at field[4] (`FUN_001dc428(0)` → `FUN_001dc3d4(u,1,size)` → `FUN_0016b780` copy).
- **The call — raw bytes at 0x2e7a8–0x2e7bc:**
```
mov x0, x24          ; dst = the memz receive buffer (host-sized)
mov w1, #0x1e000000  ; output bound = HARDCODED CONSTANT (not the allocation size)
mov x2, x26          ; src = scratch (compressed stream)
mov x3, x28          ; inLen = header field[4]
bl  0x16c738         ; LZSS decompress in place
cmp w0, w21          ; decompressed == declared — checked AFTER all writes
```
- LZSS internals (`FUN_0016c738`): classic 4096-byte ring LZSS (init 0xfee, 18-byte window copies), output bounded **only** by `param_2` (the 0x1e000000 constant), per-byte check `if (out_start + param_2 <= out) return 0`. No relation to the memz object's recorded size at any point.

### 2.4 The boot-mode byte and its stickiness
- `DAT_00387488` = boot-context struct base ([0] = boot-mode byte; [0x38] = callback fn ptr; [0x10]/[0x40] = min-latches; [0x20]–[0xa8] = region fields consumed by the kernelcache layout code).
- Writers: only `FUN_0002db0c` (the boot-context property callback), invoked by the validator family on successful property application — **`*ctx = 1` as its terminal action**. 18 xrefs to the address are reads/address-takes; **no reset path exists** (checked `FUN_0007f6c4` re-derivation, all failure paths of `FUN_00001024`/`FUN_0002e24c`).
- `sh_bootx` @0x1184: `FUN_0002d86c(ctx, 0x1e000000, 'knrl'-4CC, &flag, &flag, …)` — **enforces `bufsize ≥ 0x1e000000`** ("Kernelcache too large" @0x29e909) on its own path, then (success) proceeds into `FUN_00001024` → combo loader with `*param_3 == 1` satisfied. A failure *after* flag-set returns to the shell with the flag stuck at 1 (several distinct late-stage error returns exist: kernelcache layout @0x58c–0x8f1 panics/returns, boot-args prep, trustcache load).
- `sh_fsboot` @0xbd0 confirms the same pattern from NAND ('knrl' load → flag → boot handler).

### 2.5 The contrast that isolates the defect
The Image4 validator `FUN_00026f28` (post-signature) contains its **own** LZSS call for compressed payload sections:
```
uVar8 = FUN_0016c738(param_14, uVar18, uVar19, uVar21);
```
with `uVar19` derived from the validated region end (minus the decompressed header) and explicit CARRY8 checks (`local_5e8 + uVar21 + uVar19 <= param_18`, `local_5e8 + uVar18 + uVar19 <= param_18`) against the buffer end. Apple bounds LZSS correctly where it is post-signature; the pre-signature combo-loader site lacks the equivalent relation. (The HMAC/sysconfig strings in the binary are dead in this build — zero code references — so no additional pre-signature integrity check covers the comp path.)

## 3. Attack shape (documentation only — not executed)

```
# Recovery shell over USB serial (iPwnder-class host tooling):
memboot  <comp/lzss combo image, N bytes small>      # N ≪ expansion
bootx    <valid Image4 kernelcache ≥ 0x1e000000>     # one-time: validation OK → flag:=1,
                                                     # later stage forced to fail (e.g. bad combo)
# flag now stuck at 1
memboot  <crafted comp image, N bytes, LZSS stream expands to M ≫ N>
bootx    # combo loader decompresses M bytes into the N-byte memz → OOB
```
Ordering alternative: a single `bootx` whose `FUN_0002d86c`/validator succeeds (flag := 1) but whose subsequent layout/parse fails already returns to the shell in the sticky state.

Consequence: attacker-controlled-length OOB write into the iBEC heap/arena at EL2, pre-signature — the same stage-class where historical DFU compromises (checkm8 lineage) operated. What the analysis does **not** establish: heap/arena geometry at the moment of overflow (corruption vs guard-page crash), PAC/space-hardening interactions, or a concrete control-flow hijack. Those require device experiments, which this report deliberately does not perform.

## 4. Honest caveats

1. **Static finding.** No hardware run occurred; "works" is unproven. The memz allocator's arena behavior (`FUN_000c3440` → receive driver) could pad allocations; the analysis found no evidence of padding sized to the decompressed bound, but the allocator's internals were not exhaustively audited.
2. **Arg-mapping confidence.** Links 2.1/2.4 rest on decompiler arg tracking across wrapper layers; the LZSS call site itself (2.3) is verified from raw disassembly and is the load-bearing defect.
3. **The flag-stickiness needs one empirical confirmation** (that a post-validation failure is reachable in practice and the shell survives it — the code shows error returns to the shell, and the flag write precedes them).
4. Apple may consider the combination (recovery-shell access + host-controlled transfer sizes) as requiring physical possession; standard for boot-stage findings — the class remains what Apple patches via SEP/SPTM-era hardening and what CVEs like the checkm8 lineage were rated for.

## 5. Verification steps for an analyst
1. Reproduce the unpack: `ipsw fw iboot -o out iBEC.v59.RELEASE.im4p` → `ipsw decomp -a lzfse mBoot-*.bin` (see `AUDIT_NOTES.md`).
2. Load `mBoot.dec.bin` in Ghidra (AARCH64:LE:64:AppleSilicon, base 0). Inspect: 0x2e7a8–0x2e7bc (the call), `FUN_0016c738` (bound logic), `FUN_0017d1c4`/`FUN_000c3f84`/`FUN_000c3440` (host-sized memz), `FUN_0002db0c` (`*ctx = 1` terminal store), `FUN_0002d86c` (the ≥0x1e000000 guard on the *other* path).
3. Compare the two LZSS call sites (0x2e7a8 vs inside `FUN_00026f28`) — the bounded/unbounded asymmetry is the signature of the defect.
4. Device-side confirmation (out of scope here): instrumented iBEC or a DFU-session log capture during a crafted memboot/bootx sequence.

## 6. Recommended remediation (Apple-side)
Pass the memz object's recorded allocation size — or a dedicated output allocation — as the LZSS `param_2` bound at 0x2e7a8 (mirroring the Image4 path's CARRY8-checked bound), and/or reject `comp` images whose declared decompressed size exceeds the receiving allocation **before** decompression. Additionally, reset the boot-mode byte on any return to the recovery shell.

*Reported internally for research documentation. No CVE filed; no exploit released.*
