> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# Re-check of Reports 1–4 + 6 against iOS 27.0 (24A435, mBoot-20457.2.37)

**Date:** 09-12. **Target:** `iPhone17,5_27.0_24A435_Restore.ipsw` → `Firmware/all_flash/iBoot.v59.RELEASE.im4p`
(`ipsw img4 im4p info`: type `ibot`, `mBoot-20457.2.37`, LZFSE, 1,678,826 B → 3,832,328 B).
Payload is **unencrypted** (no KEYB/BORD): `im4p[40:]` = `bvx2` stream → `compression_decode_buffer(COMPRESSION_LZFSE)`.

Artifacts: `/tmp/ds_iboot/24a435/iboot_dec_24a435.bin` (raw, address == file offset — same convention
as the original reports) and `iboot_dec_24a435.macho` (valid arm64e Mach-O wrapper: `__TEXT`
vmaddr `0x1000`, fileoff `0x1000` → **BN VA = raw offset + 0x1000**) loaded in Binary Ninja.

## Verdict table

| # | Bug | Status on 24A435 | Evidence |
|---|---|---|---|
| 1 | DEFLATE stored-block copy ignores dst capacity | **STILL PRESENT** | live PoC: `OOBbytes=16368`, `hiApronDirty=1`, WRITE fault in firmware memcpy |
| 2 | LZVN write past caller capacity | **STILL PRESENT** | live PoC: `capSpanOOB=65536` at every dcap 64→4096; `poc_v0.bin` replays |
| 3 | LZFSE bvx1 match copier, no lower bound | **STILL PRESENT** | live PoC: `FOREIGN-A5-BYTES=2 first@47`; fault `pc=2010f4 delta=-262092` |
| 4 | `'splt'` unkeyed CRC gate / attacker-chosen decoder | **STILL PRESENT** | old forged containers still `ret=1 -> ACCEPT`; `POX!` same-CRC tamper still decodes |
| 5 | record-homing `LEN >u E-DELTA` unsigned guard (negative-DELTA wrap write) | **STILL PRESENT (static, NEW recheck)** | function recompiled to raw `0x1a31ec+`; guard `sub x8,x0,x8@0x1a39bc; cmp x28@0x1a39c0; b.hi`; NO DELTA-sign test; see Report5_HOMING/README §27.0 recheck |
| 6 | NVRAM bank images sealed only by unkeyed sums | **PRESENT (static)**, dynamic demo not replayed | real load-side check still `adler(img+0x14,size-0x14) == *(u32*)(hdr+0x10)`; fold unchanged |

Reports 1–4 all reproduce with **byte-identical firmware-side receipts**; only the offsets moved.
Report 1's claim that ids `0x505` and `0x205` were separate paths changed: both now tail-call the
same wrapper `sub_1fe8cc` with a flag (0/1) — the vulnerable path is id `0x205` (flag 0).

## Relocated offsets (raw file offset = old-style offset; BN VA = +0x1000)

| Item | 162.8 | 162.10 | **24A435 (20457.2.37)** |
|---|---|---|---|
| compression dispatcher | `0x1EB3C8` | `0x1EB448` | **`0x2026F0`** (`sub_2036f0`) |
| 2nd dispatcher (small-entry) | – | – | **`0x202644`** (`sub_203648`, ids→0x205/0x505/0x801/0x802/0x891/0x8a1) |
| id → handler | 0x100/0x101/0x205/0x505/0x891/0x8a1 | same | 0x100→`0x1FC8C4`, 0x101→`0x1FFC58`, 0x205/0x505→`0x1FD8CC`, 0x891→`0x1FFD0C`, 0x8a1→`0x20005C` |
| memcpy thunk `ldrb`/`strb` | `0x16B3E4`/`0x16B3E8` | +0x80 | **`0x16FBA8`/`0x16FBAC`** (in `sub_170ab0`) |
| R1 stored-resume `bl` / LR | `0x1E7D30`/`0x1E7D34` | +0x80 | **`0x1FE8A0`/`0x1FE8A4`** (in `sub_1ff3ac`) |
| R2 LZVN driver `bl` / LR | `0x1E8DBC`/`0x1E8DC0` | +0x80 | raw **`0x1FFCC8`/`0x1FFCD0`** (in `sub_200c58`) |
| R2 LZVN core | `0x200F6C` | +0x80 | **`0x21914C`** (`sub_21a14c`); match-copy `bl`→`0x219204` LR |
| R3 LZFSE match copier | `0x1EA100` | +0x80 | **`0x201080`** (`sub_202080`) |
| R3 faulting `ldr w8,[x10]` | `0x1EA188` | `0x1EA208` | **`0x2010F4`** |
| R4 `'splt'` gate | `0x14B4B8` | `0x14B678` | **`0x14F3B0`** (`sub_1503b0`) |
| R4 gate CRC helper | `0x1592F4` | – | **`0x15E8BC`** → `sub_1b70bc(&data_287d58)` |
| R4 loader (ctx+0x54 read) | `0x14B580` | `0x14B73C` | **`0x14F470`** (`sub_150470`) |
| R6 bank serializer | `0x16FB78` | `0x16FD38` | **`0x175F18`** (`sub_176f18`) |
| R6 Adler-32 mod 0xFFF1 | `0x158FEC` | `0x1591A4` | **`0x15D59C`** (`sub_15e59c`) — **signature widened** |
| R6 8-bit record fold | `0x1709E8` | `0x170BA8` | **`0x176E38`** (`sub_177e38`) — algorithm identical |
| R6 load-side verifier | `0x16FFA0` | `0x170160` | **`0x176370`** (`sub_177370`) |

## Static confirmations (Binary Ninja)

* **R1 root cause unchanged** — `sub_1ff3ac` resume chain is structurally identical to 162.8's:
  `ldr x12,[x19,#8]` → `csel x10,x10,x12,cc` → `cmp x10,x8` → `csel x22,x10,x8,cc` →
  `ldr x0,[x19,#0x40]` (cursor) → `mov x2,x22` → `bl sub_170ab0` @ `0x1FF8A0` (LR `0x1FF8A4`).
  The other inflate variant (`sub_1fea44`) does clamp against the remaining-capacity counter; the
  resume pass does not, and that is the pass the PoC reaches (37-byte input ≥ 9 → first pass + resume).
* **R2 note** — the new LZVN driver/fallback pass an honest `dst_end = dst + arg2` into the core, and the
  core *does* contain both an end clamp (`x27_1 = arg3 - x24`) and a start clamp (`x10_3 >= arg2`);
  the runaway still happens (64 KB past every capacity, `pc` = the thunk's `ldrb`), so the bound that is
  trusted is not the caller's. Worth re-reading before resubmission if the report's §"Root cause" text is
  reused verbatim.
* **R3 unchanged** — `sub_202080`: `add x10, x12, x13` then `cmp x10, x11` → `b.lo` → `ldr w8,[x10]`.
  `x12 = *ctx` = dst_begin is never used as a lower bound. Only cosmetic delta vs 162.8: the
  `eor/tst/movk #0xc8a2,lsl #48` pointer-tag dance was dropped (that constant now appears **0×** in the
  image, was 1× in both old builds).
* **R4 unchanged** — `sub_1503b0`: magic `0x746c7073`; `(cnt<<2)+0x18 >= blob_size` → abort;
  `crc(hdr+8) != stored[+4]` → abort; else `return 1`. Payload bytes are still outside the hashed span.
  `sub_150470` still reads the algorithm id at **ctx+0x54** and gates on it, feeding the shared dispatcher.
  Negative controls (bad magic / bad CRC / size / flag) still abort.
* **R6 unchanged in substance** — load path @ `0x1774DC`: `sub x4,x8,#0x14; add x0,x27,#0x14; bl sub_15e59c`
  → `ldr w8,[x26,#0x10]; cmp w0,w8; b.ne reject`. Fold `sub_177e38` = seed on tag byte, add `rec[2..0xF]`,
  fold `>0xFFFF` to a byte — called **4× by the serializer** (header/`/common`/`/system`/filler) and by the
  verifier, exactly as reported. No key/UID/nonce input to either.
* **R6 caveat / changed sub-claim** — the protected-name helper (`sub_15cd34`, returns the
  `boot-command` / `one-time-boot` / `auto-boot` strings) now has **4 callers** (`sub_3358c`, `sub_15cdd8`,
  `sub_15ce54`, `sub_183670`), with chains up to `sub_5080` / `sub_809f0`. The "zero-xref dead gate"
  formulation from the old builds is therefore **not confirmed** on 24A435; the reachable use looks like an
  assert/error reporter, not policy enforcement — re-verify this sub-claim before resubmitting.

## Reproduction (all commands run here)

```bash
# decrypt + decompress (payload is unencrypted bvx2)
unzip -o -q "$IPSW" "Firmware/all_flash/iBoot.v59.RELEASE.im4p" -d /tmp/x
python3 -c "d=open('/tmp/x/Firmware/all_flash/iBoot.v59.RELEASE.im4p','rb').read();i=d.find(b'bvx2');open('/tmp/pl.bvx2','wb').write(d[i:])"
clang -O2 -arch arm64 -o /tmp/dsbvx /tmp/dsbvx.c -lcompression   # compression_decode_buffer(COMPRESSION_LZFSE)
/tmp/dsbvx /tmp/pl.bvx2 /tmp/ds_iboot/24a435/iboot_dec_24a435.bin 4194304   # -> 3832328 B

# Report 1 (dispatcher retargeted to 0x2026F0)
DS_FW=/tmp/ds_iboot/24a435/iboot_dec_24a435.bin ./p1 poc_205_stored.bin
# Report 2
DS_FW=... ./q2 b0w ; DS_FW=... ./q2 pocv0 poc_v0.bin
# Report 3
DS_FW=... ./q3 poclf poc_lzfse_oobread.bin ; DS_FW=... ./q3 poclf poc_lzfse_fault.bin
# Report 4 (gate 0x14F3B0, disp 0x2026F0) — file-driven, no stream builder needed
DS_FW=... ./m4 poc_min_gate.bin disp 205 ; DS_FW=... ./m4 poc_min_tampered_same_crc.bin disp 205
DS_FW=... ./m4 poc_cell1.bin gate ; DS_FW=... ./m4 poc_cell3.bin gate
```

Offset retargeting was added as `if (strstr(g_fw_path,"24a435")) { ... }` branches in copies of the
harnesses (kept out of the report folders: `/tmp/ds_check/{p1,q2,q3,c4,m4}.c`).
`chain.c`'s `gate`/`chain` **builder** modes do not run on 24A435: they build bvx1 streams from the old
build's FSE table addresses (`TB_OFF`, `qsweep`) and old header constants, and now bail with `build fail -2`
(use `minpoc` + the shipped `.bin` containers instead — they exercise the real gate with no builder).
`Report6_NVRAM/nvram.c` needs more than an offset swap because the Adler helper's argument list widened
(2 → 5 registers); its V1/V2/T1/X1/Q1 cells were **not** re-run.

Update (09-12, later session): **Report 5 is now rechecked (see its README §27.0
recheck) and ships in this folder** (`Report5_HOMING/`, live matrices re-run on
both 26.6 builds + 24A435 static verification). The `poc_rce.bin`
control-transfer demo (`ds_iboot/rce_run{1,2,3}.log`, `chain.c` mode `rce`: REAL
gate ACCEPT → dispatcher CLEAN-WRITE smashing firmware slot `_DAT_003f6638` →
firmware `blraaz` lands PC in the attacker page, 3/3 deterministic) is composed
into `Report4_SPLT/` as the end-to-end escalation evidence.
