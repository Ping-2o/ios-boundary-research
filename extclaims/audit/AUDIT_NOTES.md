> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AUDIT_NOTES.md — Low-level boot-stage / coprocessor vulnerability audit ledger

**Goal:** find vulnerability in AOP2, iBoot, SEP, DFU, etc (low-level stages). Goal id goal-db945fee-7d2e-49dd-a900-378db066b02c.
**All audit assets live under /Users/pauyedin/DirtySlide/extclaims/audit/ — this file is the durable memory; update it every round.**

---

## Round 1 (2026-09-07) — inventory established

### Analyzable asset inventory (ALL PLAINTEXT)

| Asset | Path | Size | Format | Covers |
|---|---|---|---|---|
| **mBoot core** | `audit/dfu/ibec/mBoot.dec.bin` | 3,699,832 B | raw AArch64 (EL2 entry at 0x0) | **iBSS == iBEC == iBoot — IDENTICAL SHA-256 `48ff474efdb852d15995fdcb00bbc17e040267fa94cde6d4304c8d8fca8931ef`. One audit covers all three boot stages.** |
| **SPTM** | `/Users/pauyedin/23G71__iPhone17,5/23G71__iPhone17,5/Firmware/sptm.t8140.release` | 1,146,912 B | Mach-O arm64e, 3,582 strings, stripped, LC_UUID 3B8907F1-F82B-33B6-A483-AA620A7E83A8 | Secure Page Table Monitor (highest-value modern target) |
| **TXM** | `/Users/pauyedin/23G71__iPhone17,5/23G71__iPhone17,5/Firmware/txm.iphoneos.release` | 442,400 B | Mach-O arm64e, stripped | Trusted Execution Monitor |
| **Rose rkos** | `extclaims/work/rose_rkos.bin` (from `Rose/r2p1/ftab.bin`) | 617,376 B | RTKit-3255.160.4.release RTOS image | AOP2 kernel |
| **AOP fw segments** | `extclaims/work/aopfw_out/` (ktxt 94K, rtxt 1.45M, rdat 1.27M, ubdl 204K, …) | ~3.2M total | RTKit BUND segments (raw) | AOP firmware + user bundle |
| **AppleAOP2 kext** | KDK `.../AppleAOP2.kext/Contents/MacOS/AppleAOP2` | 131,600 B | Mach-O kext arm64e, 43 global syms | Host side of AOP2 endpoints (imports `tb_client_connection_create_with_endpoint`, `tb_service_connection_create_with_endpoint`, `tb_endpoint_set_interface_identifier` = Tightbeam RPC) |
| **SEP firmware** | `sep-firmware.v59.RELEASE.im4p` payload | 7,700,480 B | head `7f545917…` high-entropy, **0 KBAG tags** | ENCRYPTED or nonstandard wrapper — parked until a decode path is found |
| r2 function list | `audit/mbot_afl.json` | 17,648 functions | r2 aflj dump | mBoot triage index |

### Extraction commands (reproduce)
```
ipsw fw iboot -o audit/dfu/ibec  extclaims/work/23G71/Firmware/dfu/iBEC.v59.RELEASE.im4p   # dumps mBoot-*.bin (bvx2) + blobs
ipsw decomp -a lzfse -o mBoot.dec.bin mBoot-18000.162.8_RELEASE.bin                        # → 3,699,832 B raw ARM64
ipsw kernel dec kernelcache.release.v59                                                    # 23G71 kernelcache
python3 BER-walk of im4p: 30 83 <len3> → 0x16 "IM4P" → 0x16 version → 0x04 OCTET STRING payload
```

### iBEC/iBoot string-surface map (3392 strings, `audit/dfu/ibec.strings`)
- **USB/DFU**: "Apple Mobile Device (DFU Mode)", "Apple USB Serial Interface", usb-drd tunables.
- **Recovery command interpreter** (host-driven, pre-signature for query cmds): `getenv` `setenv` `setenvnp` `setpicture optmask <file path> [image_4cc] …` (`setpicture` string @0x339445, `getenv` @0x339464, `setenvnp` @0x33947a, `bootx` @0x338768). Pointer/ADRP refs to these names NOT yet located (hand ADRP scan failed — use r2 xrefs next).
- **Image4/LocalPolicy**: "Payload HMAC does not match.", "sysconfig (0x%p) or manifest (0x%p) argument was null", "sysconfig version (0X%08X) did not match manifest version", FUD paths (`Ap,SecurePageTableMonitor.img4`, `LocalPolicy.cryptex1.img4`…).
- **Memory-train/calibration debug strings** (SWCAL/WRLVL/CA/CS/Vref) = lots of %d printf surfaces.

### Ranked audit plan (next rounds)
1. **R2: USB DFU EP0/control-request state machine in mBoot** — the checkm8-class surface, reachable with zero signatures in DFU mode. Find via "Apple Mobile Device (DFU Mode)" string xref → USB device descriptor setup → DFU request dispatch. Look for: wLength/wValue misuse, alloc-size vs packet-size inconsistency, ep0 buffer reuse (the historical DFU bug class).
2. **mBoot image4/ASN.1 BER parser** — length-field integer handling in the IMG4 reader (strings: "Payload HMAC", sysconfig/manifest null checks). Pre-signature parsing.
3. **Recovery command table** — enumerate all commands via table walk (after locating via r2 `axt` on "getenv"/"setpicture"), then audit each command's argument parser (`setpicture optmask` takes addr/size/file-path args).
4. **SPTM exception/GL2 dispatch** — "[SPTM Dispatch]" strings; the GL0/GL1/GL2 exception router + XNU↔SPTM ABI. SPTM CVEs 2024-2025 were exactly here.
5. **Rose rkos** — endpoint message dispatch (24 AOP2Endpoints), patchbay slot handling, "Rose Supervisor Service" message routing.
6. **AppleAOP2.kext** — Tightbeam endpoint plumbing on the host side (symbolized, small).
7. **SEP firmware decode attempt** — research the v59 sepOS wrapper (0 KBAG but high entropy; maybe sepOS now rides SPTM-encrypted pages or a new tag).

### r2 usage notes for this image
- Entry at 0x0 is EL2 bring-up (msr vttbr_el2/mrs hcr_el2).
- `r2 -q -A` full analysis takes ~10 min; aflj saved at `audit/mbot_afl.json`.
- rabin2 -z works; hand ADRP+ADD scanning is unreliable — prefer r2 `/r` or `axt` after analysis.

---

## Round 2 (2026-09-07) — Ghidra: mBoot imported, shell command surface fully enumerated

### Ghidra MCP state (bridge socket ghidra-42973.sock, project /Users/pauyedin/DirtySlide/kernel)
- Imported: `/boot/mBoot.dec.bin` (raw AArch64 AARCH64:LE:64:AppleSilicon, base 0x0, **15,660 functions** auto-analyzed). Old program `/IOGPUFamily_71.flat` also in project.
- `run_script_inline` compiles **Java method-body** code (NOT JavaScript: no top-level function decls; hex literals ≥ 2^32 need `L` suffix; imports + statements only). Failed scripts linger in /Users/pauyedin/ghidra_scripts and re-print build errors on later runs — harmless.

### CRITICAL FINDING — image VA bias
mBoot links at **VA base = 0x1fc080000**: every stored 64-bit data pointer = `0x1fc080000 + file_offset`. (This is why all raw pointer scans found nothing.) Ghidra address = file offset = VA − 0x1fc080000. Entry code at 0x0 = EL2 bring-up. String addresses from rabin2 (e.g. getenv @0x339464) are file offsets == Ghidra addrs.

### Boot-command tables (do_boot = FUN_00004910; entry stride 0x38: [+0 name][+8 name][+0x10 name_end][+0x18 help][+0x20 fn][+0x28 help][+0x30 argc])
- Normal/secure path table @0x338fc8: `upgrade`→0x6090(attr 3), `recover`→0x6da4(0xb), `recover-once`→0x725c(0xb)
- DFU path table @0x3390a8: `fsboot`→0xbd0(1), `upgrade`→0x5b04(3), `recover`→0x6934(0xb), `recover-once`→0x6d84(0xb), `checkerboard`→0xbb0(6), `repair`→0xf40(1), `device-recovery`→0xf60(1)

### Interactive recovery/DFU shell command map (named `sh_*` in Ghidra; layout [+0 help=""][+8 name][+0x10 fn])
- `bootx`→0x1184 · `memboot`→**0x1958** · `go`→**0x2374** · `firmware`→0x4d9c · `saveenv`→0x4ea0 · `reboot`/`reset`→0x4ea4 · `bgcolor`→0x4eec · `setpicture`→**0x4f88** · `devicetree`→**0x5368** · `ramdisk`→**0x53c8** · `RestoreANS`→0xb044 · `WCHF`→0x14c1bc · `RTBuddy`→0x140600/0x18c81c · `DCP`→0x140a14/0x1aa3b0 · `Trustcache`→0x163578/0x1aa308 · `iBootData`→0x163314 · `getenv`→0x15defc · `setenv`→**0x15dff4** · `setenvnp`→0x15e21c · `clearenvp`→0x15e284 · `SPTM`→0x18ab04/0x1a2b2c · `Exclave`→0x1a2b98/0x1a353c · `rsepfirmware`→**0x19fc94**
- NVRAM variable-permission table @0x2038c0..0x203f18: per-var entries incl. `boot-args`, `dev-unset-debug-enabled`, `security-mode-change-enable`, `preserve-debuggability`, `com.apple.System.tz0-size` (audit setenv permission logic vs this table).

### Functions decompiled so far
- `FUN_00003be8` = iBEC recovery main (banner → boot-policy → do_boot(0x338fc8/0x3390a8 bounds) → "Entering recovery mode, starting command prompt").
- `FUN_00004910` = do_boot: stride-0x38 table walk, `*entry==0` = end, bounds-checked [param_2,param_3), calls entry+0x20.
- `sh_setpicture` (0x4f88): per-arg bounds vs [param_3,param_4); picture size cap 0x400001; permission gate `FUN_0007fa3c(addr,0,0,0,size)` → "Permission Denied"; then `FUN_000c36c0(addr, addr, addr+size, ...)` image load. **AUDIT: gate completeness + FUN_000c36c0 bounds.**
- `FUN_00005588` = arg-access helper (returns via x8/x9 — decompiler shows void; read disasm).

### Next-round targets (priority order)
1. `sh_memboot` (0x1958) — host-supplied image load: image4/ASN.1 parse + HMAC path ("Payload HMAC does not match", sysconfig/manifest version checks). Classic pre-signature parser surface.
2. `sh_devicetree` (0x5368), `sh_ramdisk` (0x53c8), `sh_go` (0x2374) — same class; `go` = execute-at-address, check prod-fuse gate completeness.
3. `sh_setenv` (0x15dff4) — permission logic vs NVRAM table (can host set `boot-args` / `security-mode-change-enable` on prod silicon?).
4. `sh_setpicture` gate FUN_0007fa3c — dev-fuse check completeness.
5. `sh_rsepfirmware` (0x19fc94) — SEP fw load from iBEC.
6. After DFU surface: SPTM (plaintext Mach-O — import) GL2 exception dispatch; then Rose/AOP2 endpoint message handlers; AppleAOP2.kext host side.
### Round 2 additions — memboot/go decode
- `sh_memboot` (0x1958): reads `filesize` env var (cap 0x20000000), same `FUN_0007fa3c` security gate → then grabs `tbdm`/`knrl` images (thunk_FUN_00026e54(0x69626474/0x6b726e6c)), validates (`FUN_001633bc`), prepares boot args (`FUN_0002e070`), boots (`FUN_00001024`). Breadcrumbs write. Lines: s_Filesize variable invalid / s_Combo image too large / s_Permission_Denied.
- `sh_go` (0x2374): arg = addr (from arg-blob), same `FUN_0007fa3c` gate → `FUN_000c3df8` = **image validation** against an obfuscated 32-byte magic table (`s_cebilefciladmplarmmhtreptlhptmbr` @0x2a58b8) → dispatches on 4CC {giad/trep/rbmt/tlhp = diag/trep/tmbr/tlhp image classes} → `FUN_000025e0` load-and-boot. Boot-class images (`diag`/`trep`/`tmbr`/`tlhp`) additionally require `FUN_00001654()` < 0 else panic @0x9b1.
- **THE LINCHPIN: FUN_0007fa3c (security/permission gate) — both memboot and go (and setpicture) funnel through it. Next round: decompile FUN_0007fa3c and audit whether the production/dev-fuse decision can be influenced by NVRAM (`dev-unset-debug-enabled`, `boot-args`, `security-mode-change-enable` in the var table) or boot-mode state. A prod-bypass here = arbitrary code execution from the recovery shell (checkm8-impact class, software-gated).**
- `sh_setenv`/`sh_getenv` handlers: 0x15dff4/0x15defc; NVRAM perm table @0x2038c0.

---

## Round 3 (2026-09-07) — security gate audit + ref-hunting methodology fixed

### Ghidra script gotchas (build on these, don't rediscover)
- Mnemonics are LOWERCASE in this program (`adrp`) — always `.toUpperCase()` before compare.
- `opObjects` for ADRP page operand is a **Scalar already resolved to the absolute page** (base 0x0): `adrp x0, 0x339000`. Do NOT add PC.
- Ghidra addresses = file offsets (image base 0). Stored data pointers carry VA bias 0x1fc080000 — mask to compare.
- Working pattern: walk `listing.getInstructions(true)`, map reg→page on ADRP (reg numbers parsed from "x8" strings), on ADD imm64 with src==tracked reg compute page+imm, clear reg map at RET/BR/BLR/ERET. Cross-check vs capstone raw sweep — they agree 8/8 on perm-denied.

### Security gate FUN_0007fa3c — DECODED (Round 3 core finding)
- Globals: `DAT_003dca52` bit0 = **secure-context flag**; `DAT_003dca50` = flags (init 0x222c0000, |= 0x10000000 if FUN_001bc770()>>8 bit set, |= 0x100020 if `thunk_FUN_0004c66c()`>>8 bit CLEAR, |= 0x8000000 if FUN_001bbc1c()!=0).
- Gate behavior: flag set → return TRUE (unrestricted); flag clear → require [param_1, param_1+x4) ⊆ [_DAT_003dca60, _DAT_003dca68).
- Window set by `FUN_0007f968(addr,size)` (monotonic min/max, CARRY8-overflow-checked, panic on bad); initialized by **FUN_0007f6c4(param_1)** at boot: `_DAT_003dca60=~-0; _DAT_003dca68=0` then `FUN_0007f968(0x10004000000)` — i.e. **the default restricted window is the 4-page boot-args/SRAM region at 0x10004000000**.
- `FUN_0007f6c4(1)` is called **inside the combo-image loader FUN_0002e24c (LAB_0002f54c) on the FAILURE path (lVar11==0)** — a failed image load re-derives the context (this is the boot-context transition, not a shell-time switch).
- FUN_0007fad4 = getter returning `DAT_003dca52>>6 & 1` (secure-boot bit).
- **Verdict so far: gate is a strict bounds whitelist with overflow checks; the decision flag is set once at boot from fuse/platform state, not from NVRAM. No shell-time path found that widens the window. Awaiting: xrefs to FUN_0007f968 (only FUN_0002e24c + FUN_0007f6c4) — no caller passes attacker-controlled addr/size. Not vulnerable by inspection.**

### Reference-hunting results (Ghidra + capstone sweep agree)
- "Permission Denied" @0x29b338: 8 refs — sh_bootx@0x1184(0x13e4), sh_memboot@0x1958(0x1b8c), sh_go@0x2374(0x2498), sh_firmware@0x4d9c(0x4e64), sh_setpicture@0x4f88(0x52dc), FUN_0015cc6c(0x15ce40), FUN_0017ce44(0x17cfdc), FUN_001c69a4(0x1c6ab0). FUN_0015cc6c + FUN_001c69a4 = NEW live surfaces to check (env var read + ? — audit next round).
- **"sysconfig (0x%p) or manifest" @0x2a5083, "version mismatch" @0x2a5124/0x2a513f, "Payload HMAC does not match" @0x2a53ae, "deleted flag" @0x2a4fc4, "hmacs were NULL" @0x2a4a9d: ZERO code references in the entire image** (linear capstone sweep + Ghidra walk both) and zero data pointers (6 ptrs nearby point to 0x2a55df+, different strings). These are dead strings in this build — the sysconfig/manifest HMAC validation they imply is NOT in the mBoot image path.
- "Combo image too large" @0x29b3a8: 1 ref @0x19d8 (inside sh_memboot, confirming the 0x20000000 cap).

### Combo-image loader FUN_0002e24c (called from sh_go via FUN_000c3df8 chain — the pre-auth parser)
- Accepts `CAFEFABE` (-0x35014542) combo header with per-section table; `comp` (0x636f6d70+`lzss` 0x6c7a7373) compressed payload path; decompress via FUN_0016c738 into 0x1e000000-capped buffer, **checks decompressed_len == declared_len**; kernelcache layout code with many explicit overflow-panics (CARRY8 checks on region sums @0x58c-0x8f1 line refs).
- The LZSS decompressor FUN_0016c738 is called with attacker-controlled (input, inSize, outBuf, declaredSize) — **audit the decompressor internals next: classic pre-auth overflow class. Also FUN_00032858/FUN_0016cbbc (kernelcache layout math).**
- Boot-args region 0x10024000000 mapped at FUN_0007f6c4 boot (DAT_003dca48 guard).

### Next-round queue
1. Decompile LZSS decompressor FUN_0016c738 (called from FUN_0002e24c with host sizes; verify the out-buffer bound is the CAP (0x1e000000 allocation) not the declared size — if it writes bounded only by internal LZSS semantics vs declared size, that's a heap overflow).
2. Audit FUN_0015cc6c + FUN_001c69a4 (the two unexplained perm-denied sites).
3. `sh_rsepfirmware` 0x19fc94, `sh_devicetree` 0x5368, `sh_ramdisk` 0x53c8, `sh_setenv` 0x15dff4 permission logic.
4. Then SPTM import + GL2 dispatch; Rose/AOP2 after.

---

## Round 4 (2026-09-07) — LEAD-1: in-place LZSS decompression overflow in iBEC memboot path

### The candidate (pre-signature heap overflow, host-reachable from recovery/DFU shell)
Full chain, all verified by decompile/BL-scan:
1. `sh_memboot` (0x1958): parses `filesize` env (host-set, cap 0x20000000), passes permission gate FUN_0007fa3c, receives image via FUN_0017d1c4 → returns (buf, size) into locals.
2. `FUN_0017d1c4` (0x17d1c4): **allocates the receive buffer via FUN_000c3f84(arg_size, arg2, …)** — size comes from the command arg blob (host-controlled); caches (ptr,size) in globals DAT_00336830/DAT_00336838; image 4CC 'rdsk' (0x7264736b) or fallback 0x6f737264.
3. `FUN_00001024` (0x1024) = boot handler called with (buf, size); passes &DAT_00387488 (boot-mode global, **== 1 in memboot flow**) as param_3.
4. `FUN_00031670` (0x31670, sole BL caller @0x1104 inside FUN_00001024) → `FUN_0002e24c` (combo loader).
5. FUN_0002e24c 'comp' branch: requires `*param_3 == 1` (✓ memboot flag) and header `'comp'`+`'lzss'` (0x636f6d70/0x6c7a7373) at image start (host-controlled bytes). Reads field[3]=declared decompressed ≤0x1e000000, field[4]=compressed ≤0x1e000000; allocates INPUT scratch (FUN_001dc428(0)/FUN_001dc3d4(u,1)/thunk_FUN_00034754), copies via FUN_0016b780, then:
   `FUN_0016c738(piVar2, 0x1e000000, pbVar14, field[4])` — **writes decompressed data INTO the received buffer (piVar2 = param_1 = the filesize-sized allocation), output bound = hardcoded 0x1e000000 constant, NOT the allocation size.**
6. LZSS internals (FUN_0016c738): per-byte output check `if (param_1 + param_2 <= out) return 0` — bounded ONLY by the 0x1e000000 param; input bounded by field[4]; ring buffer 4096 B on stack, standard 0xfee/18-byte LZSS; result length compared to field[3] AFTER the writes are done.
7. Post-check `decompressed == field[3]` cannot prevent the overflow — it happens during decompression.

### Attack shape (to be confirmed)
Host in recovery shell: small `filesize` + `memboot` of a 'comp'/'lzss' combo image whose LZSS stream expands to M ≫ N → in-place write of M bytes into the N-byte receive buffer → **pre-signature heap corruption in iBEC at EL2**, reachable over USB serial before any Image4/signature validation.

### Remaining verification (next round, priority order)
1. **FUN_000c3f84 allocation semantics** — confirm alloc size == arg (not max(size, field[3]) or a fixed large region). Decompile 0xc3f84.
2. FUN_0016b780 copy direction (received buf → scratch) + scratch alloc size (FUN_001dc428/001dc3d4 semantics).
3. Disasm @0x2e7b8 area: confirm the 0x1e000000 passed as LZSS size arg is the constant (movz/movk pattern), not min(field[3], …).
4. Permission gate at memboot: confirm receive buffer lies inside the whitelisted window (0x10004000000-based) so the gate passes by design for the attack path.
5. If all four hold → document PoC plan (USB serial 'memboot' with crafted comp image) — documentation only, no device run.

### Round 4 verdict evidence (disasm-confirmed)
- **LZSS call site @0x2e7a8-0x2e7bc (FUN_0002e24c 'comp' branch):**
  ```
  mov x0, x24          ; dst = received image buffer (host-sized)
  mov w1, #0x1e000000  ; out cap = HARDCODED CONSTANT (verified in raw bytes)
  mov x2, x26          ; src = scratch copy of compressed stream
  mov x3, x28          ; inSize = header field[4] (0x167ccc-validated)
  bl  0x16c738         ; LZSS decompress IN-PLACE into x0
  cmp w0, w21          ; size check AFTER decompression
  ```
- The buffer allocated BEFORE (FUN_001dc428(0) → FUN_001dc3d4(u,1,size=field[4] via w26)) is the **compressed-input scratch**, sized by field[4] — the OUTPUT destination x24 is the receive buffer from FUN_0017d1c4 (host transfer size), NOT resized for decompression.
- Caller chain: sh_memboot→FUN_00001024→FUN_00031670→FUN_0002e24c. The non-comp combo path zero-fills its own new allocation; the comp path reuses the receive buffer.
- FUN_000c3f84 (0xc3f84): thin wrapper — size1 (x19), size2 (x21), size1+size2 (x12=x19+x21) marshalled into FUN_000c3440 stack block ([sp+0x28]=size1, [sp+0x38]=size2, [sp+0x48]=size1+size2 at 0x400c add x12,x19,x21; x21=param_1=x0 = the transfer size arg). **Actual allocator = FUN_000c3440 — decompile next round (need: does it clamp/harden the requested size?).**
- Any guarded-guard: LZSS itself writes bounded by w1=0x1e000000 only. If receive alloc < expanded size → OOB heap write during decompression, pre-signature, EL2.

### Round 4 also
- sh_memboot callers of FUN_00001024 confirmed at 0x1be8+ (post-receive).

---

## Round 5 (2026-09-07) — LEAD-1 chain CLOSED end-to-end (bootx sets the flag)

### Boot-mode flag writer found — sh_bootx decompile (0x1184)
```
uVar4 = FUN_0003841c();                       // ctx
uVar5 = FUN_0007fa3c();                       // permission gate (passes by design for boot path)
...
uVar4 = FUN_0002d86c(uVar4, 0x1e000000, 0x726b726e /*'knrl'-family 4CC*/,
                     &DAT_00387488, &DAT_00387488, 0x387538, &DAT_00202888, ...);
if (uVar4 < 0) → error 0x5cb
else {
  in_ZR = DAT_00387488 == 1;                  // ← FUN_0002d86c WROTE 1 on success
  ...
  uVar4 = FUN_00001024(local_258, local_268, &DAT_00387488, &DAT_00387488, 0x387538, ...);
}                                             // → combo loader, *param_3 == 1 ✓
```
- `sh_bootx` = "boot the USB-transferred image" — the classic iBEC bootx. FUN_0002d86c(ctx, 0x1e000000, 4CC, &flag, &flag, ...) loads the received image AND sets boot-mode=1.
- `sh_fsboot` (0xbd0) confirms the same pattern from NAND: FUN_0002de78(..., 'knrl', &flag, &flag) then `ldrb w8,[flag]; cmp #1` then FUN_00001024.
- DAT_00387488 xrefs (18): all PARAM/READ in sh_bootx/sh_memboot/sh_fsboot/FUN_00001024 — the only writers are the two loaders via the passed pointer.

### COMPLETE ATTACK CHAIN (all links decompiled/disassembled)
1. Recovery shell (iBEC, USB serial): `memboot` → host image lands in memz buffer sized by host arg (FUN_0017d1c4→FUN_000c3f84→FUN_000c3440: validates 'memz'/'img4' header at [buf+8], param_18-vs-*buf size check) — permission gate passes by design (receive region = whitelisted window).
2. `bootx` → FUN_0002d86c (cap arg 0x1e000000, 4CC 'nrkr') → sets DAT_00387488=1 → FUN_00001024(buf,size,&flag) → FUN_00031670 → FUN_0002e24c.
3. FUN_0002e24c comp branch: `*param_3==1` ✓, header 'comp'+'lzss' (host bytes @buf+0/+4), field[3]=declared-decompressed ≤0x1e000000, field[4]=compressed ≤0x1e000000 → LZSS `FUN_0016c738(x24=buf, w1=0x1e000000 CONST, x26=scratch, x28=field[4])`.
4. **LZSS writes into the host-sized memz buffer bounded ONLY by the 0x1e000000 constant; size check `cmp w0,w21` AFTER the writes. Expansion beyond the memz size = OOB heap write pre-signature at EL2.**

### Final open item (single question)
- **FUN_0002d86c (0x2d86c) buffer provenance**: does it return the ORIGINAL memz transfer buffer (→ overflow stands, OOB write during decompression), or does it reallocate a decompressed-size buffer (→ benign, Apple sized it right)? It receives the same 0x1e000000 cap constant and &flag; its return (buf,size) feeds FUN_00001024. One decompile answers it. Note: even a "realloc" must handle the comp-header field[3] BEFORE the combo loader's unguarded decompression to be safe.
- Secondary: whether memz arena neighbors the region such that OOB write hits mapped heap (corruption) vs unmapped (instant crash) — affects exploitability only, not the bug class.

### Verdict state
- BUG SHAPE: CONFIRMED at instruction level (0x2e7a8-0x2e7bc raw bytes).
- REACHABILITY: chain complete except the single FUN_0002d86c provenance check.
- If FUN_0002d86c passes through the memz: **pre-signature arbitrary-length heap overflow via USB in iBEC recovery** (checkm8-class impact surface, software-gated — the gate passes by design on this path).
- Discipline: documentation only; no device run, no exploit code. PoC shape (setenv filesize=N; memboot comp-image expanding to M≫N; bootx) recorded for the write-up.

---

## Round 6 (2026-09-07) — Apple's mitigation found; REFINED bypass lead via sticky flag + memboot

### FUN_0002d86c (bootx loader) — contains the counter-mitigation
- Entry: reads arg-blob (puVar3): uVar5 = buf ptr, uVar10 = buf size; `if (uVar10 < 0x1e000000) → "Kernelcache too large" (0x29e909) → reject`.
- **The buffer-size ≥ LZSS-cap check is exactly what makes bootx's in-place decompression safe** (buffer can never be smaller than the decompression bound).
- Then FUN_000c3df8(buffer, 0x1e000000, …, 'knrl'-args, &flag, &flag, param_7, 0) — the image validator (same one sh_go uses) — receives &DAT_00387488 and **on success sets boot-mode=1** (that's the flag write; no other writer exists — all 18 xrefs to DAT_00387488 are reads or address-taking).
- Returns the SAME buffer (uVar5 = arg[0] pass-through) + size to sh_bootx → FUN_00001024.

### The refined lead — sticky flag + memboot direct path
- sh_memboot → FUN_00001024 **directly** (no FUN_0002d86c, no buffer-size ≥ 0x1e000000 check). The only gate on the combo 'comp' branch is `*param_3 == 1` (DAT_00387488).
- DAT_00387488 is written ONLY by FUN_000c3df8 on successful image validation (via the &flag args from bootx/fsboot), and **no code resets it to 0** (18 xrefs: no write-type refs; FUN_0007f6c4 failure path doesn't touch it).
- **Sticky-flag scenario**: one bootx attempt with a ≥480MB transfer that validates (flag:=1) but FAILS later inside FUN_00001024/FUN_0002e24c (e.g. malformed combo → error → returns to shell with flag STILL 1) → then `memboot` a SMALL 'comp'/'lzss' image (host filesize, no minimum) → FUN_00001024 → combo loader: flag==1 ✓, small memz buffer, in-place LZSS with 0x1e000000 cap → **OOB heap write pre-signature**.
- Also plausible simpler path: any single bootx where FUN_000c3df8 succeeds but a LATER stage fails, leaving flag=1 — then re-memboot small.

### Next round (single focus)
1. Decompile FUN_000c3df8 (0xc3df8): confirm it writes *param_4/*param_5 (=DAT_00387488) = 1, and WHEN (before/after full validation).
2. Confirm no DAT_00387488 reset on the failure paths of FUN_00001024/FUN_0002e24c (FUN_0007f6c4(1) re-derivation — grep its body for 00387488).
3. Confirm sh_memboot → FUN_00001024 has no other flag precondition (FUN_00038118(2) semantics).
4. If (1)-(3) hold: the finding is a **complete pre-signature OOB-write chain in iBEC recovery** (sticky-state + in-place LZSS constant cap). Document full write-up; no device work.

---

## Round 7 (2026-09-07) — validator structure mapped; flag-write one level deeper

### FUN_000c3df8 decoded (thin orchestrator, 0x144 bytes)
- `FUN_000c36c0(buf, buf, buf+size, …)` = find/wrap image inside buffer (returns ptr,len) — same primitive setpicture uses.
- → `FUN_000c3440(lVar2, …)` (the memz/img4 receive handler from Round 4) with the caller's out-params forwarded — **note its tail writes `*param_19 = 0`** (one out-param zeroed on this path).
- → per-4CC loader `FUN_00026f28(param_1..param_28)` — **the flag-write (=1 through the &flag out-param) lives here**, executed after the 4CC-specific load succeeds.
- FUN_000c3f3c = 'memz' magic sanity helper only (cmp 0x4d656d7a @+8, tail FUN_001b01f8).
- On any failure: FUN_000c428c(0) + return -1 (no flag write — flag only set on success ✓ consistent with bootx behavior).

### State of the lead
- Sticky-flag scenario stands: FUN_000c3df8 success → flag=1 (inside FUN_00026f28) → later-stage failure returns to shell with flag stuck at 1 → small `memboot` + in-place LZSS constant-cap overflow.
- Remaining: (a) confirm the =1 store in FUN_00026f28 and that it precedes full boot completion (it does by construction — bootx continues to FUN_00001024 after FUN_0002d86c returns success, and the loader runs INSIDE FUN_000c3df8); (b) grep FUN_0007f6c4 + FUN_0002e24c failure paths for any 00387488 reset; (c) FUN_00038118(2) semantics in sh_memboot.
- Careful point: FUN_000c3440's `*param_19 = 0` — verify WHICH out-param slot that is in the bootx caller's arg mapping (if it's the flag slot, a failure path zeroes the flag and the sticky scenario narrows to the success-then-fail-later ordering — still live because FUN_0002d86c returns success and bootx proceeds into FUN_00001024 in the same call).

### Next round queue
1. FUN_00026f28: locate the `strb #1` through the flag out-param; map the bootx arg positions (param_19 vs flag slot).
2. Failure-path reset grep (FUN_0007f6c4, FUN_0002e24c, FUN_00001024) for 0x387488 stores.
3. Then write-up + fallback queue (setenv perms, SPTM, Rose/AOP2).

---

## Round 8 (2026-09-07) — Image4 validator mapped; the LZSS contrast is now evidence

### FUN_00026f28 = the Image4 validator/loader (0x26f28..~0x28154, huge)
- Parses IMG4/ASN.1 (FUN_001d7xxx family), 4CC dispatch {'ibec' 0x69626563, 'nrkr' 0x726b726e, 'knrl' 0x6b726e6c, 'lpol' 0x6c706f6c}, signature via callback ptrs (DAT_00387c40 validity-cb / DAT_00387c00 accept-cb, DAT_00387bf8 = in-validation flag), LocalPolicy crypto block (FUN_001da5d4/FUN_001da6bc digests, 0x80/0x100/0xc0-bit keys, FUN_00086b28(0x11,...) = RSA/ECDSA verify), boot-context struct reads via (param_4+0x20/0x30/0x50/0x70/0x80/0x90) in FUN_0002d86c (so &DAT_00387488 is a STRUCT BASE: [0]=boot-mode byte, [0x38]=callback fn ptr = _DAT_003874c0).
- **Own LZSS call (image4-internal compressed payload branch):**
  `uVar8 = FUN_0016c738(param_14, uVar18 /*compressed len*/, uVar19 /*out*/, uVar21 /*declared out len*/)`
  with out = validated-region-end − header sizes, preceded by explicit CARRY8 bounds vs param_18 (buffer end): `local_5e8 + uVar21 + uVar19 <= param_18` etc. — **properly bounded**.
- This is the apples-to-apples contrast: **Apple bounds LZSS correctly inside the Image4 path (post-signature) but the combo-loader 'comp' path (pre-signature, FUN_0002e24c @0x2e7a8) uses the hardcoded 0x1e000000 cap with no allocation-size relation.**
- Flag write (DAT_00387488=1) NOT yet pinned to an instruction: raw-byte scan shows NO adrp+add→0x387488 inside FUN_00026f28 (the 0x488-add hits at 0x239488/0x260488/0x266488/0x269488 are other globals). Candidates: the `FUN_0007f860(uVar9)` call near the validator tail (uVar9=1 when image accepted and (local_3f0&0x10000)==0 && (local_2f5!=0 || local_3e8!=0)) — FUN_0007f860 sits in the security-context global neighborhood (0x7f9xx). Next round: decompile FUN_0007f860 + FUN_0002de78 (fsboot loader, the other flag writer).
- Also in FUN_00026f28: `if (param_18 < local_518) → 0x40040024` etc. — buffer-size checks exist here too.

### Standing structure of the finding (unchanged)
- Pre-signature surface = combo loader FUN_0002e24c ('CAFEFABE'/'comp'/'lzss'), reachable via memboot-with-sticky-flag (flag write location pending) or any path leaving DAT_00387488=1 with a small memz.
- The post-signature LZSS is bounded — the bug is specific to the pre-signature parser.

### Next round queue (updated)
1. Decompile FUN_0007f860 (candidate flag writer) + FUN_0002de78 (fsboot 'knrl' loader) — pin the flag=1 store precisely.
2. Failure-path reset grep for 0x387488 (FUN_0007f6c4 body, FUN_0002e24c, FUN_00001024).
3. FUN_00038118(2) semantics in sh_memboot.
4. Write-up + fallback queue (FUN_0015cc6c/FUN_001c69a4, setenv perms, SPTM GL2, Rose/AOP2).

### Round 8 addendum
- FUN_0007f860 ELIMINATED as flag writer — it toggles 0x2000000 in the security-context flags DAT_003dca50 (demo/policy bit), unrelated to DAT_00387488.
- Flag-write candidates narrowed: FUN_0002de78 (fsboot 'knrl' loader — receives &flag as x5/x6) for the fsboot case; for the bootx case the write must be a strb through the &flag pointer forwarded FUN_0002d86c→FUN_000c3df8→FUN_00026f28 (raw scan shows no global-materializing adrp+add to 0x387488 inside 26f28 — consistent with pointer-arg write). Technique for next round: STRB-immediate (#1) scan restricted to FUN_00026f28 body + FUN_0002de78, then map which base register holds the forwarded flag pointer (trace param registers).
- Also verified this round: the Image4-internal LZSS (FUN_00026f28) decompresses with out-buffer derived from the VALIDATED region end and explicit CARRY8 checks vs buffer end — Apple bounds LZSS correctly on the post-signature path; the unguarded constant-cap variant exists only in the pre-signature combo loader (FUN_0002e24c @0x2e7a8). This asymmetry is strong evidence the combo path is an oversight, not a design guarantee.

---

## Round 9 (2026-09-07) — FLAG-WRITE SITE FOUND: the boot-context callback (LEAD-1 chain structurally complete)

### FUN_0002db0c = boot-context property callback (both loaders pass it: FUN_0002d86c/0002de78 → validator → invoked with ctx)
- Receives ctx pointer (puVar3 = &DAT_00387488 struct) + property 4CC stream; fills ctx fields per tag: [0x8],[0x20],[0x28],[0x30],[0x38],[0x50],[0x58],[0x60],[0x68],[0x70],[0x78],[0x80],[0x88],[0x90],[0x98],[0xa0],[0xa8], running sums at [0x18]/[0x48], min-tracking latches at [0x10]/[0x40] (fields match the kernelcache layout reads in FUN_0002e24c — same struct).
- **Terminal action: `*puVar3 = 1;`** — ctx+0 = DAT_00387488 = boot-mode := 1. This is the flag=1 store: it fires when the validator applies image properties (post-validation, PRE-handover).
- Ordering ⇒ sticky-flag premise structurally proven: FUN_0002d86c returns success after the callback → sh_bootx proceeds → FUN_00001024/FUN_0002e24c run; ANY later failure (bad combo header, layout panic-free error return, boot-args failure) returns control to the shell **with boot-mode still 1**. No reset path exists (xref audit: 18 refs, all reads/address-takes; FUN_0007f6c4 failure path does not touch it).

### COMPLETE FINDING CHAIN (final form)
1. Recovery shell (iBEC/DFU, USB serial, EL2): `bootx` with a valid Image4 kernelcache (post-signature OK) whose boot later fails → DAT_00387488 stuck at 1.
2. `memboot` small image (host-sized memz allocation, NO minimum-size check on this path — only bootx's loader FUN_0002d86c enforces size ≥ 0x1e000000).
3. Combo loader FUN_0002e24c: `*param_3 == 1` ✓ (stuck flag) + 'CAFEFABE'/'comp'/'lzss' host-controlled header → in-place LZSS into the small memz with hardcoded 0x1e000000 output cap (verified bytes @0x2e7a8: `mov w1,#0x1e000000`), size-vs-declared check AFTER writes (cmp w0,w21).
4. LZSS expansion beyond memz size = **pre-signature OOB heap write at EL2 in iBEC** — the post-signature Image4 LZSS path IS properly bounded (CARRY8 vs buffer end), isolating the flaw to the pre-signature parser.
5. Contrast evidence: Apple validates sizes correctly on the Image4 path and on FUN_0002e24c's non-comp kernelcache path (CARRY8 panics) — the comp branch is the unguarded outlier.

### Discipline
Documentation only. No device run, no exploit code, no PoC execution. PoC shape recorded for responsible write-up (sticky-flag + small comp image). Report as iBEC recovery pre-auth OOB-write (EL2 context) candidate pending any empirical confirmation — static-analysis finding.

### Next round queue
1. Write FINDING_MB_BOOT_LZSS.md (full evidence chain w/ addresses, the two LZSS call sites compared, PoC shape, severity framing). — DONE Round 10: `audit/FINDING_MB_BOOT_LZSS.md`.
2. Fallback audit queue: FUN_0015cc6c/FUN_001c69a4 (perm-denied sites), sh_setenv permission logic vs NVRAM table, SPTM GL2 dispatch import, Rose/AOP2 endpoint handlers, AppleAOP2.kext Tightbeam host side.
3. Optional finding-hardening: verify FUN_000c3440/FUN_00026f28 arena-padding question (memz allocator internals), FUN_00038118(2) semantics. — PARTIALLY DONE Round 11:
   - FUN_001dc428(0) = generic heap allocator (FUN_001dc3e4 family), NOT the memz path.
   - FUN_00038118(2) = SPTM staging (maps 0x12c00000 / 0x8000000, one-shot latch DAT_003886b0) — NOT a flag precondition; memboot's only comp-branch gate is the sticky DAT_00387488.
   - PADDING-QUESTION CLOSING ARGUMENT (inference, not proof): sh_bootx's own loader FUN_0002d86c rejects buffers < 0x1e000000 ("Kernelcache too large"). If every memz allocation were a fixed 0x1e000000 arena, that check would be redundant — Apple would never need it. The check's existence argues memz sizes are genuinely variable (arg-driven), hence a small memz is real and the constant-cap LZSS can exceed it. Residual risk: the allocator could still pad small requests to page/arena granularity far below 0x1e000000 — any pad < 0x1e000000 keeps the bug live; only a universal 0x1e000000 arena kills it (ruled implausible by the redundancy argument).
   - Remaining hardening (optional): pin FUN_000c3440's create path (param_1==0 → error 0x40030004 = "null object" — so c3440 VALIDATES an existing object; the true creator is elsewhere, likely FUN_000c3440's caller chain on the receive side / FUN_000c37f8). Not load-bearing for the finding.

---

## Round 12 (2026-09-07) — sh_devicetree mapped; flag-write mechanism cross-confirmed

- `FUN_0015cc6c` = **sh_devicetree** (perm-denied site #5): filesize-capped (reject if transfer > filesize), permission gate, then the SAME validator `FUN_000c3df8` with 4CC `rdtr` (0x72647472) and install via FUN_0015a0ec; "Device_Tree too large"/"Device_Tree image not valid" strings.
- **CROSS-CHECK WIN**: sh_devicetree calls FUN_000c3df8 with the callback-struct args (20–24) = ALL ZEROS — no property callback → flag untouched. Only kernelcache-family loads (bootx `FUN_0002d86c`, fsboot `FUN_0002de78`) register `FUN_0002db0c` + `&DAT_00387488` — which is why the boot-mode byte is set exactly and only there. This independently corroborates the Round 9 flag-write finding and the arg-13 "write value = 1" interpretation (both bootx and devicetree pass 1 at that slot; devicetree's flag slot receives &local_6c='rdtr' instead of &flag — validator writes the loaded-image 4CC there).
- So: the "Permission Denied" site #5 belongs to a properly-gated, non-flag-writing command. Remaining unexplained site: FUN_001c69a4.
- FUN_000c3df8's validator is the SINGLE choke point for all shell-loaded images (go/memboot/bootx/devicetree/ramdisk) — its callback-slot design is what gates boot-mode transitions.

### Round 20 — SPTM imported; dispatch-logging helper located
- **Imported `/boot/sptm.t8140.release`** into Ghidra project: 509 functions, 3,908 symbol-table entries (functions NOT auto-named), base 0xfffffff027004000, size 1,163,264 B, Mach-O arm64e. Fully analyzable.
- Dispatch-logging helper found: FUN_fffffff02709a9a4 @0x9a9a4 prints "[SPTM Dispatch] Synchronous exception taken while SP1 selected in GL2" — reached via exception vectors (no direct xrefs/callers — data-driven vector flow; Ghidra missed the ref).
- SPTM surface strings mapped: sptm_uat_* family (map_table/unmap_table/set_ctx_id/remove_ctx_id/get_info/prepare_fw_unmap — the UAT (Unified Allocation Table?) management ABI = the XNU↔SPTM API surface), sptm_register_cpu, sptm_fixup, SPTMDebug, sptm_slide_region, "FTE %p should be held exclusive by sptm_retype()" (FTE = frame-table-entry retype locking — the page-type state machine), Handoff/TTBAT/TTBR1-shared-L2 region checks.
- NEXT (SPTM track): locate the GL2 exception VECTOR table (search for the standard 0x800-stride ARM64 vector layout or VBAR write), trace vector → handler → FUN_09a9a4 caller chain, then enumerate the SPTM call ABI (the sptm_call dispatch table: map/unmap/retype/ctx-id ops with their argument validation — the historical SPTM CVE class).
- Companion asset: TXM (442KB Mach-O, same project when imported) — Trusted Execution Monitor, shares the exception fabric.

### Queue (unchanged tail)
1. SPTM GL2 dispatch + call ABI audit (opened Round 20).
2. Rose/AOP2 endpoint handlers (rkos image).
3. AppleAOP2.kext Tightbeam host side.
4. (setenv surface CLOSED Round 14; recovery-shell audit COMPLETE.)

### Round 21 — SPTM exception entry + domain-transition dispatcher FULLY DECODED
- Exception entry prologue FUN_fffffff02709917c: mask DAIF, cpu struct = sysreg(3,6,15,11,1) (IMPDEF TPIDR-style), guest frame saved to cpu[0xa50..0xb20] (+x29/x30/sp), then `FUN_fffffff0270e1268(4 /*event*/, …)`.
- **Dispatcher FUN_fffffff0270e1268 — the domain-transition FSM:**
  - cpu[0xa60] = current state (≤0x16=22), event ≤0xe (14)
  - table @0x2701a780: entry = base + state*0x1e0 + event*0x20 → [0]=next_state ≤0x16, [8]=handler fn-ptr (panic "no action set" if 0), [0x10]=flags, [0x18]=options
  - flags bit0: per-domain entry resolution — caller table `DAT_…08db58 + caller_domain*0x180 + (meta>>0x20 & 0xf)*0x18`; entry validity = bitmap `[tbl+8] >> cpu[0xa30] & 1`; "Found illegal dispatch entry point" if entry==0
  - flags bit1: XNU→TXM hop check — hop depth must == 1 (cpu[0xa68]); entry address (cpu[0xa70]) resolved via FUN_0de2ec/FUN_0d2b94 to a '-'-tagged name (symbol verification)
  - metadata sanity: bits 0xff000000000000 range and 0xf000000000 must be clear (panics)
  - cpu[0xa30] = entry[0x10]; cpu[0xa60] = next_state; tail-call handler(meta, entry)
  - **DATA POINTERS ARE PAC-SIGNED**: modifier 0xc8a2… (decompiler shows manual retag) — forged data ptrs fail
- Audit value: this FSM is the historical SPTM CVE class (domain confusion, illegal transitions). Attack angles: (a) dump the 23×14 transition table + per-domain allowlist bitmaps, look for over-permissive (state,event)→handler mappings; (b) caller bitmap indexed by cpu[0xa30] which is set from entry[0x10] AFTER resolution — check for desync; (c) metadata bit checks cover only two ranges.
- Segment map saved: audit/sptm_segments.json.

### Round 22 plan
1. Dump transition table @0x2701a780 (10,240 B) + caller-domain tables @DAT_08db58 → enumerate (state,event)→(next,handler), cross-check allowlist bitmaps.
2. Flag anomalies (over-permissive mappings, index desyncs).
3. Then TXM import or Rose/AOP2.

---

## Round 23 — SPTM transition table dumped and analyzed (62 live transitions, no holes consumed)

Full 23×14 table dumped via Ghidra script. Structure interpretation:
- Distinct handler set (8 unique): 0x98258 (generic "continue/handoff" — most common), 0x9849c, 0x98110, 0x98000, 0x98318, 0x98998, 0x98174, 0xe17b0 (a stub — likely "reject/invalid" given it maps to self-states 6→6, 9→7, 11→6, 16→7, 20→6), plus per-state log wrappers 0x99xxx.
- State 18 = fully dead (no transitions) and 19→20→13→(11/8) chains exist = boot/handoff sequence states.
- **Flags observed: 0b0, 0b1, 0b10, 0b11, 0b100 — bit0 = caller-domain resolution, bit1 = XNU→TXM hop check, bit2 (0b100) only on state 7 (two entries) = a third, rarer check.**
- No next_state > 0x16; no unexpected flags. Table is dense-but-tight: every (state,event) that exists maps to a plausible handler; no (state,event) reaches a handler from a state that isn't an established peer (the 0xe17b0 self-loop entries are deliberate rejections).
- Notable: state 0 (reset/idle) reaches events 0/1/9 only; event 9 = "panic/teardown" (→19 from EVERY live state — a global exit); event 11 = TXM hop (→21 from most states, with per-state flags).
- The two 0b100-flag entries (7,2→12 and 7,11→21) deserve a look at their handler/options (o=0x1 both) — state 7 is rare (reached only from 12,5).

### Round 24 plan
1. Audit the caller-domain allowlist tables @DAT_…08db58 (domain×entry bitmap) — the remaining half of the FSM legality matrix; look for a bitmap that permits a caller-domain whose state shouldn't be allowed.
2. Decompile 0x98258 (the generic handoff) + 0xe17b0 (the reject stub) + one 0b100-flag handler pair.
3. Then TXM import or Rose/AOP2.

---

## Round 25 — caller-domain table is RUNTIME-BUILT; SPTM bootstrap fully mapped (bonus)

- `DAT_…08db58` is ZERO in the file — filled at bootstrap: `FUN_fffffff0270b1bd4` (the giant SPTM bootstrap) sets `DAT_…08db58 = uVar12 + 0x10` inside the **kernelcache ro region** ("BootKC-rs"), i.e. the caller/entry tables are constructed from boot-image data, then validated with exhaustive containment panics ("X not fully within BootKC ro region") — SPTM checks every sub-table (0x08d3d0+8, 0x08db58+0x180, 0x08d150+1, 0x08d100) against the BootKC-ro bounds BEFORE use.
- Also decoded in the bootstrap (bonus map): the FULL region-retyping program — DeviceTree/SPTM-ro/rw/le/TXM-ro/rx/bx/rw/le/BootKC-ro/rs/rx/bx/rw/le/AuxKC-*/TrustCache/CL4-*/RAMDisk/RTBuddySeg/SEPFW/SEPPatches/uStuff/preoslog/BootArgs/ExclaveOSIntegrityCatalog/ExclaveOSTrustCache each retyped via FUN_…0d4480(name, ap-perm, phys, pages, fte-type) — the FTE type codes (0x40/0x41/0x43/0x48/0x51/0x53/0x121/0x141/0x2/6…) are the page-type state machine constants.
- Domain-registration API spotted: FUN_…0e0e08(domain, FUN_…0e19ac, perms_mask) — called for domains 0,1,2,(10 if enabled) with the SAME entry function and different permission masks.
- exclaves-enabled DT prop gates "Starting SK…" (Secure Kernel) vs always "Starting TXM…" — SPTM bootstraps both monitors.
- Caller bitmap index semantics (from Round 21 decode): entry[0x10] (flags byte) becomes cpu[0xa30] AFTER handler resolution — bitmap check uses PREVIOUS cpu[0xa30]. A desync would need a transition whose entry[0x10] changes the current-domain bitmap index before the allowlist check of the NEXT hop — the hop check (flags bit1) reads cpu[0xa70] set by the PREVIOUS handler. Order-of-operations verified: no desync found.
- Bootstrap-stage latch DAT_…0f92c8 (bits 0/3/8/18) prevents re-bootstrap ("Attempted to announce bootstrap stage that has already been reached").

### Round 25 verdict + next
- SPTM dispatcher + FSM + bootstrap: no anomaly found at static level. The allowlist tables are boot-data (from the signed kernelcache region) — attacking them requires kernelcache control, which the secure boot already gates. This surface closes as **hardened**.
- Remaining SPTM surface: the sptm_uat_* ABI handlers (map_table/unmap_table/set_ctx_id — argument validation from XNU) — the actual attack surface XNU reaches. Next rounds: decompile those handlers.
- Then Rose/AOP2 (rkos), AppleAOP2.kext.

---

## Round 27 — UAT ABI internal layer opened (sptm_uat_map_table internals)

- Located the UAT layer: FUN_…0ae54c = **map_table internal** (referenced by the string-anchor fn FUN_…0ae250 which names all sptm_uat_* ops). Decoded flow:
  1. `FUN_…0be800(param_1, 2, 0xf)` — UAT state-object lookup by (id, type-mask); returns pbVar3 with **state_guard byte at [0x1a]** (must be 1, set to 2 on release — a lock-state FSM with its own panic "state_guard_release").
  2. `FUN_…0bed3c(param_2, 0x4000, pbVar3, &local_48)` — validate/decode the TTBR argument (0x4000-page granularity), returns local_48 (physical).
  3. **param_3 (which TTBR) validated by exclusion: `(byte)(param_3 - 3U) < 0xfe` → panic** — only 0/1/2 (or 1/2) accepted.
  4. Object type check: `uVar7 = local_48 >> (cpu[0x1a1] & 0x3f)` (va-bit-shift from a config struct); bit0 selects 5 or 0xe expected-type mask vs `*pbVar3`.
  5. Slot: `FUN_…0ac770(pbVar3 + (uVar7&1)*8 + 8, local_48, param_3, &old)` — returns the existing slot; `(valid & 3) == 0 → panic "not a valid UAT state object type when getting TTBR%d"`.
  6. **Old-table refcount discipline**: if old ≠ cpu[0x108] (current table), full release chain FUN_…df474(old,0x18)/dfa08(old,1)/df6a0(old); new table FUN_…dfa08(uVar4,1) must succeed; DMB; then `*slot = (uVar4 & 0x1fffffff000) | 3` — **the TTBR write masks the physical to 0x1fffffff000 (37-bit PA) with valid bits |3**.
- Audit note: the PA mask 0x1fffffff000 is the hardware constraint; the slot write is atomic-after-DMB; refcount/lock FSM (0x1a byte) has its own panic. Argument validation is exclusion-based and tight. No anomaly in this handler by inspection.
- Next: the OTHER UAT ops (unmap_table @FUN_…0ae250-family, set_ctx_id, get_info) + the top-level dispatcher that reaches these from XNU (the SMC/svc call path).
3. SPTM import + GL2 dispatch; Rose/AOP2; AppleAOP2.kext.

### Also this round
- FUN_0002e24c non-comp path: kernelcache layout with explicit CARRY8 overflow panics (0x58c-0x8f1) — clean.
- Security gate FUN_0007fa3c: strict whitelist window (monotonic min/max, overflow-checked), flag set once at boot from fuse state — no shell-time widening found.
- HMAC/sysconfig strings confirmed DEAD in this build (zero refs, both methodologies).

---

## Round 28 — SPTM call ABI reached: domain-registration + hibernate-restore decoded

- **Domain registration**: FUN_…0e18a4(domain, entry, table) — rejects double registration, domain >15; stores per-domain dispatch entries at PTR_PTR_…08db60[domain*2] + hop-depth at DAT_…08db68+domain*0x10. FUN_…0e0e08 (init filler) validates the entry against PAPT (physical-address page-table) ranges AND the domain-name table (DAT_…0f92e8 list) before writing. Caller bitmaps built with domain ∈ {0,1,2,10} × state, perms_mask as bitmap value.
- **Call-ABI tables** (PAC-signed, __DATA_CONST @0x01d2e8 / 0x01d5e8, 3 entries each): [0]=0x…0dce08, [2]=0x…0e3d68, [4]=0x…0ed224 / 0x…0d891c — per-domain dispatch. PAC mask = 0x0000ffffffffffff.
- **Hibernate-restore** (FUN_…0e2408 = hibernate_restore.c — XBS build path leaked in binary): entry[2] is the hib restore; validates hibernate_page_list (bank first/last ordering, bitmapwords == roundup/32, pages_seen == page_count, CARRY4 overflow checks — 18+ panic sites); maps handoff pages; zeroes 0x4000 control page; rebuilds page-list bitmap; retypes regions (FTE codes 0x60000000000621/0x6000000000040d/0x600000000006a1); reads DT props for GAPF enable/lock regs with page-alignment panics.
- No unbounded path found; hibernate validation is thoroughly panic-guarded.

### SPTM surface status
- Dispatcher FSM: CLOSED (62 transitions verified, no anomalies).
- Domain registration + call ABI: mapped (PAC-signed per-domain tables).
- map_table/unmap_table internals: audited clean.
- hibernate_restore: decoded, panic-guarded throughout.
- Remaining SPTM (lower priority): set_ctx_id/get_info handlers, TXM import.

### Queue
- Rose/AOP2 (rkos) endpoint handlers.
- AppleAOP2.kext Tightbeam host side.
