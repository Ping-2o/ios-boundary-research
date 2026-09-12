> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# Delivery-path analysis — how attacker bytes actually reach the iBoot decoder/loader bugs

Target: **iOS 27.0 24A435, `mBoot-20457.2.37`** (`/tmp/ds_iboot/24a435/iboot_dec_24a435.bin`).
Method: Binary Ninja call-graph, bottom-up from the vulnerable functions (all offsets raw = file
offset = the reports' convention; **BN VA = raw + 0x1000**). Every claim below is an xref/callsite
address, not prose carried over from the reports.

## 0. The reachable set is CLOSED and small

Decompression in this iBoot is *not* scattered. Everything funnels through two dispatcher functions:

| Dispatcher | raw / BN VA | id space it normalizes into |
|---|---|---|
| `sub_2036f0` | `0x2026F0` | 0x100, 0x101, 0x205, 0x505, 0x700-0x702, 0x801/0x802, 0x891, 0x8a1, 0x900/0x901 (+ unmapped 0xa18/0xb02/0xd05 → `return 0`) |
| `sub_203648` | `0x202648` | same set, "entry/small" variant (`bl 0x32dfc` prologue) |

Bottom-up proof that nothing else can reach the buggy codecs:

* `sub_20105c` (0x8a1 LZFSE bvx entry) — **exactly 1 caller**: `sub_2036f0` @ `0x2037d0`.
* `sub_202080` (the Report-3 match copier) — reached only from `sub_20105c` @ `0x201cd8`.
* `sub_21a14c` (LZVN core) — reached from `sub_200c58` @ `0x1ffcd0` and `sub_1fd8c4` @ `0x1fc9ac`; both of
  those are dispatcher handlers (`0x101`, `0x100`).
* The shared `memcpy` thunk `sub_170ab0` (raw `0x16fab0`, faulting `ldrb/strb` at `0x16FBA8/0x16FBAC`) is
  the copy primitive used by all of the above.

Therefore **the complete delivery surface = the 4 callers of the dispatchers**:

| # | Direct wrapper | Chain | Subsystem (named by its own strings) |
|---|---|---|---|
| **P1** | `sub_2339c` (`0x2239c`) | ← `sub_c66ac` ← {`sub_c6924`,`sub_c6e30`,`sub_c7378`,`sub_c75f4`} | **standard image load**: `Kernelcache image not valid`, `DeviceTree image not valid`, `Ramdisk image not valid`, `boot-object-manifests`, `secure-boot-hashes`, `BootKC`/`TrustCache`/`DeviceTree`/`RAMDisk`/`BootArgs`; consumes a `{base,size}` region descriptor (`sub_c7ae0`), reads at offset+bound-checks (`sub_c6924`) |
| **P2** | `sub_150108` (`0x14f108`) | ← `sub_150470` (the `'splt'` loader) ← `sub_3d3ec` ← `sub_3d118` | **staged-container path**, same cluster as `'wchf'` (`0x150f98`); Report 4's gate `sub_1503b0` is its single-integrity check |
| **P3** | `sub_180224` (`0x17f224`) | ← `sub_17ee08` ← `sub_1800ec` ← **8 callers**: `sub_5a9c`,`sub_5b08`,`sub_6120`,`sub_6670`,`sub_670c`,`sub_78c0`,`sub_8798`,`sub_c8640` | **iBoot self-update / staging records**: references `'iBootIm'` (`0x17e27c`), the codec-name table `'LZFSE   '` / `'VMiBoot '` (`0x180538`, inside the function that CRCs then dispatches), `'paniclog'` (`0x182804`) |
| **P4** | `sub_1a4cd8` (`0x1a3cd8`) | ← {`sub_195b74`, **`sub_1e2290`**} | `sub_195b74` region = Mach-O/`__TEXT`/`__DATA`/`compartments/kernel/metadata`/`tunables_offset` (kernelcache map); **`sub_1e2290` is reached only from `sub_150470` @ `0x1505a8`** = the SPLT loader's **CRC-failure fallback arm** |

## 1. Per-path delivery requirements (attacker precondition)

**P2 — `'splt'` staged container (Reports 4, then 1/2/3 through it).**
Integrity = `sub_15e8bc` CRC-32 over `[hdr+8, (cnt<<2)+0x18)`, payloads excluded, magic and stored-CRC
excluded. **No key.** So whoever can *place* a staged blob chooses the decoder (ctx+0x54 → P4's
`sub_1e2290`/P2's `sub_150108` → dispatcher) and the chunk lengths. Already demonstrated: the 26.6-era
forged containers (`poc_min_gate.bin`, `poc_cell1/3.bin`) still pass the 27.0 gate.
*Open question that decides its price:* the loader is invoked by exactly one chain
(`sub_3d118 → sub_3d3ec → sub_150470`), and `sub_3d3ec` is gated by a mode predicate `sub_16a4()`
(`if (!(sub_16a4() & 1)) … else …`) plus `sub_6a2f4(0x54,1)`, `sub_6a2f4(0x5f,1)` enablers. **Settling what
`sub_16a4` tests (factory/combo strap vs. any-upgrade vs. recovery) is the single highest-value remaining
check** — it is the difference between "manufacturing-position bug" and "user-physically-present bug".

**P3 — `iBootIm` / `LZFSE` staging records + `paniclog`.**
Same shape as P2 (attacker-chosen codec name, CRC32 via the *same* `sub_15e8bc`, then dispatcher) but with
**8 distinct callers**, all in the low env/command region (`0x5a9c…0x8798`) — the same region that consumes
`boot-command`, `auto-boot`, `auto-boot-once`, `device-recovery`, `delay-recovery-image`, `debug-uarts`,
`nvram-migrate`, and `paniclog` (`0x77ff8`). That breadth is what the reports should claim instead of the
single "combo staging" sentence: **more entry points, all reached from the env/boot-command layer.**

**P1 — standard signed image load.** Bytes come from a loaded image region (`{base,size}` descriptor) that
is subject to `boot-object-manifests` / `secure-boot-hashes`. Real risk here is **order of operations**: if
a payload is decompressed *before* its digest is compared (true whenever the IMG4 payload is signed but not
AEAD-encrypted — the plaintext cannot be authenticated until it exists), then any attacker who can substitute
stored bytes gets an unauthenticated decode. Needs one decisive test (below).

**P4 — kernelcache/Mach-O map decode + the SPLT *rejected-CRC* arm.** The important half is the second
caller: `sub_1e2290` is **only** reachable when the `'splt'` CRC check has already failed, and it still
hands an attacker-selected id to the dispatcher. That is the strongest single sentence in Report 4 and it
survives verbatim on 27.0.

## 2. Composition: the bugs stop being independent

* **Report 6 × P2/P3.** NVRAM bank integrity = unkeyed Adler-32 (`0x15D59C`) + 8-bit fold (`0x176E38`),
  seq counter inside the Adler span; backing store is named in this very build:
  `nvram-bank-size`, `nvram-bank-count`, `nvram-current-bank`, **`nvram-proxy-data`**, **`nvram-raw`**,
  **`nvram,nor`**, **`nor0`**. A forgeable *policy* store that feeds the env/command layer which reaches P3
  through 8 callers is a **persistence + delivery amplifier**: it converts "must control staged content" into
  "control the NOR/NVRAM bank once, and every subsequent cold boot walks the attacker's policy into the
  command/env layer." Note the contrast that makes this a *design* finding, not a nitpick: the same binary
  implements keyed protection where it chooses to — `%s Failed to validate HMAC.` in the `sysConfig3`
  code (`0x2bfe31`). NVRAM and `'splt'` simply don't use it.
* **Report 4 × Reports 1–3.** The gate's uncovered payload + attacker-chosen id is exactly what turns three
  separately-reported decoder defects into one story: integrity-light container → any codec → known-bad copy
  loops. Reports 1–3 are individually *not* exploitable without a source of unauthenticated bytes; P2/P3/P4
  are that source.
* **`'wchf'`.** `wchf image too large - 0x%zx\n` is referenced at `0x150f98`, i.e. **in the same cluster as
  the `'splt'` gate and loader**. There is at least one more container type parsed alongside `'splt'`;
  the reports cover only one. Worth an hour of reversing — a second forged-CRC container type with a
  different field layout is likely a new report, and it also strengthens Report 4 from "one loader is weak"
  to "the container format family is weak".

## 3. Ranked verdict on deliverability

1. **Strongest / cheapest to prove:** P3 (`iBootIm`/`LZFSE`/`paniclog` staging records) — 8 entry points,
   same CRC-only + attacker-chosen-codec pattern, reachable from the boot-command/env layer that NVRAM
   (Report 6) feeds. Claim this as the primary operating context.
2. **Strongest impact if the gate is off by default:** P2 via `sub_16a4` — pending the one check below.
3. **P1 order-of-operations** — highest potential value of all (a *user-presence, physical* vector: swap
   stored image bytes), but needs the auth-order test to be true.
4. Report 6 stands on its own as "no second wall in the store path" and is the multiplier for 1–2.

## 4. The four experiments that close this out

> **STATUS (09-12): ALL FOUR CLOSED** — #1 → §4a (software mode-bit, not fuse);
> #2 → §4e (NEGATIVE: P1 verifies stored bytes before decode); #3 → §4e (wchf =
> family member + log-only 4cc gate, no OOB); #4 → §4b/§4c (NVRAM→'splt' chain
> traced; Report-6 dead-gate claim corrected).

1. **Decompile `sub_16a4` (raw `0x15a4`) and its suppliers.** Question: is the `'splt'`/staging chain gated
   on a manufacturing strap/fuse, on "any upgrade in progress", or reachable in recovery? This one answer
   moves every report's severity paragraph.
2. **P1 auth-order test.** On `sub_2339c`, locate the digest/trustcache comparison relative to the
   `bl sub_2036f0`/`sub_203648` callsites (`0x24380`, `0x245ac`) and determine whether an unencrypted-but-
   signed IMG4 payload is decompressed before its hash is checked. If yes: Reports 1–3 get a
   *storage-write-only* delivery story, which is a different (higher) class than staging.
3. **`'wchf'` container RE** at `0x150f98` — does it reuse `sub_15e8bc` (CRC-only) and its own attacker-chosen
   id/length fields?
4. **NVRAM→env demonstration**: show one of P3's 8 low-region callers actually consuming an NVRAM variable
   (e.g. `delay-recovery-image` / `device-recovery` / `boot-command`) — that turns Report 6's
   "persistence amplifier" from inference into a traced chain.

## 4a. What `sub_16a4()` actually gates on (settled)

It is **not** a fuse/strap read at the call site. It is one global byte with exactly one writer and one
reader in the whole image:

```
VA 0x16a4  sub_16a4:  adrp x8,#0x3b6000 ; ldrb w0,[x8,#0x768] ; ret        (the ONLY reader)
VA 0x1680  setter   : pacibsp; mov w0,#0; bl #0x3cf94;
                      adrp x8,#0x3b6000; strb w0,[x8,#0x768]; retab         (the ONLY writer)
```

`sub_3cf94` is a leaf that memoizes a **medium/hardware property query**: it checks a cached slot
(`[x8,#0xce8]`), reads a status bit at an MMIO/ANS-class register window built from
`mov x9,#0x24 / movk x9,#0x73,lsl#16 / movk x9,#3,lsl#32` (**0x3_0073_0024**), tests bit 2 of `[base-0x24]`,
then extracts a size field and converts it to bytes as `field << 20` (MiB units), with a `>= 8` class/size
comparison before returning.

Consequences for the reports:
* The staging precondition is **software state initialized once from a device/medium capability query**, so
  it is (a) testable on-device without fuses, (b) potentially identical across retail units of this class,
  and (c) *not* evidence of a manufacturing-only mode by itself. The "gated by hardware strap/fuse policy"
  sentence in Reports 1–4 is therefore unsupported on 27.0 and should be replaced by this precise
  mechanism (cite `0x1680`/`0x16a4`/global `0x3b6768`).
* The remaining unknown is what the query returns on a retail iPhone17,5 — that is a **device-side**
  question (one `auto-boot-once` boot + one panic-log/UART read answers it), not a static one.

## 4b. TRACED CHAIN — an NVRAM env variable reaches the `'splt'` CRC-only gate

Following P2 upward (every step is a BN callsite, not an inference):

```
handler sub_81d54 (__noreturn tail-call to sub_4a68; its address is taken at VA 0x1beeac inside the
                   large boot-init/registration blob sub_34180 → i.e. installed as a callback at init)
        → sub_4a68 → sub_4a9c  (VA 0x4a9c, __noreturn)
        → sub_3d118 (VA 0x3d118)
        → sub_3d3ec (VA 0x3d3ec; gated by sub_16a4() — see §4a — plus sub_6a2f4(0x54,1)/sub_6a2f4(0x5f,1))
        → sub_150470 (VA 0x150470)  = the 'splt' staged-container loader
        → sub_1503b0 gate = unkeyed CRC-32, payload NOT covered
        → ctx+0x54 attacker-chosen algo id → sub_203648 / sub_2036f0 dispatcher
        → Reports 1 / 2 / 3 corrupting decoders
```

The page this handler lives in (VA `0x80000`–`0x83000`) is iBoot's **panic / recovery / security-mode**
subsystem, named by its own strings: `iBoot Panic: %s: %s`, `double panic in `, `recovery-reason`,
`disable-boot-wdt`, `boot-breadcrumbs`, `root_serial`, `chosen`, `mBoot-20457.2.37`,
**`dev-unset-debug-enabled`** (`0x82748`) and **`security-mode-change-enable`** (`0x82854`) — the latter being
one of the exact variables Report 6 lists as attacker-interesting. So the staging entry is not installed by a
factory-only routine: it is registered from boot init alongside the **security-mode / debug-enable** logic.

For completeness, the adjacent boot/env command page (VA `0x3a9c`–`0x5a9c`) — reached by the *same* staging
loader's neighbours — names the interface it sits next to: `boot-device`, `boot-partition`, `/boot`,
`boot-breadcrumbs`, **`auto-boot-once`** (referenced at `0x4e58`, inside `sub_4e44`, i.e. a *neighbour* of
the chain head, not the chain head itself — do not overstate this), `debug-uarts`, `nvram-migrate`,
**`boot-command`** / `device-recovery` / `delay-recovery-image` / `epochs` / `poweroff` / `command` /
`idle-off` (all inside `sub_5080`, VA `0x5080`–`0x5a9b`).

> write the NVRAM bank (unkeyed adler + 8-bit fold, forgeable) → an env-driven boot action consumes the
> staged container → its integrity is a payload-excluding CRC32 → the container picks the decompressor →
> the decompressor overruns/over-reads its destination.

**No keyed check exists at any hop of that chain.** The only remaining precondition is the storage write,
and `sub_16a4()`'s mode test.

## 4c. Correction that *raises* Report 6's bar (do not ship the dead-gate claim as-is)

`sub_5080` (VA `0x5080`–`0x5a9b`, `__noreturn`) is the function that references `boot-command`,
`device-recovery` and `delay-recovery-image` — and it calls `sub_183290 → sub_183670 → sub_15cd34`, which is
exactly where the protected-name strings (`boot-command` / `one-time-boot` / `auto-boot`) are materialized.
So on 24A435 the name list is **live on the boot-command execution path**, not dead code. Report 6's
"enforcement wrapper has zero references" statement is 162.x-specific and must be re-verified or dropped;
the durable claim is the *absence of a keyed seal*, and the target should be a variable the list does not
protect (e.g. `auto-boot-once`, which is the very variable heading the P2 chain).

## 4c. VERIFIED (09-12): Report 6's "dead gate" is a tooling artifact — and the `setenv` write surface is **iBEC's, not iBoot's**

Two facts, both checked directly in `iboot_dec_24a435.bin`:

1. **iBoot has no `setenv` command surface at all.** The command-name pool at raw `0x3592ec`–`0x359315`
   (`getenv`, `saveenv`, `setenv`, `setenvnp`, `clearenvp`; plus `bootx`/`memboot` at `0x3587e8`/`0x3587ee`)
   is referenced by **zero** ADRP+ADD sites and **zero** 8-byte pointer slots in the whole image — scanned
   exhaustively. Control: `boot-command` (raw `0x2b55d0`) has **17** ADRP+ADD code refs, so the scan does
   detect real references. The shell, its command tables, the NVRAM variable-permission table and the
   `Permission Denied` gate are **iBEC/DFU** artifacts — see `extclaims/audit/AUDIT_NOTES.md` Round 2
   (`setenvnp`→`0x15e21c`, perm table `@0x2038c0`, `do_boot` entry stride `0x38`, `[+0x20] = fn`).
2. Hence Report 6's "enforcement wrapper has ZERO xrefs" is exactly what a **table-dispatched** handler
   looks like to Ghidra's caller analysis — the same trap `AUDIT_NOTES.md` Round 3 records for these very
   names ("ADRP refs to these names NOT yet located — hand scan failed"). In iBoot 24A435 the
   protected-name materializer `sub_15cd34` has **four** callers (`sub_3358c`, `sub_15cdd8`, `sub_15ce54`,
   `sub_183670`), chaining up to `sub_5080` (VA `0x5080`–`0x5a9b`, the `boot-command`/`device-recovery`/
   `delay-recovery-image` consumer) and `sub_809f0`.

**Consequence for Report 6:** claim 4 ("nothing in this binary blocks authoring any variable name") must be
**retracted**. Its caveat 5 — the un-recorded live `setenv boot-command` refusal — is most plausibly that
name gate working as designed, on **iBEC**. The core finding survives: no keyed seal on the persisted bank
images (verified in 27.0's real load path, §P-note below).

**Evidence-integrity note for the campaign:** the repo holds **no artifact** for that refusal — no log, no
call, no return code, only Report 6 README's prose (searched repo-wide: the sole hits are README lines 24-25
and 181-183). And `AUDIT_NOTES.md`'s "setenv surface CLOSED Round 14" cites Rounds 13–19, which **are not
in the file** (it jumps Round 12 → Round 20) — i.e. the permission-logic verdict that would have settled
this was never written down. Re-deriving it means auditing `sh_setenv`/`sh_setenvnp` in `audit/dfu/ibec`
against the `@0x2038c0` table + `FUN_0007fa3c`, which is static work on files already on disk.

## 4d. DT values: NOT obtainable offline (settles the "read the DT" proposal)

The shipping `DeviceTree.v59ap` (decoded, 323,372 B) is a **template**: 87 of its values are
`syscfg/...` placeholders resolved per-unit at restore (`syscfg/RMd#/0x20`, `syscfg/MLB#/0x20`,
`syscfg/SwBh/0x10`, …). The properties in question carry **no value at all** in the blob —
`nvram-proxy-data`, `nvram-bank-size`, `nvram-bank-count`, `nvram-current-bank`,
`effective-security-mode-ap`, `effective-security-mode-sep` have zero-filled value fields and are **not**
syscfg-referenced either, unlike the identity properties. So they are **runtime-populated** (iBoot/SEP), and
the staging-precondition question cannot be answered from firmware: only a running device's live DT
(readable via `IORegistryEntryCreateCFProperty`) knows. `nvram-raw`, `nvram_raw`, `nvram,nor`, `nor0` are
**absent from this device's DT entirely** (they exist only as iBoot-side lookup names) — see §2 correction.

Control that makes the negative meaningful: string values in this blob are tagged `0x80000000 | strlen`
followed by the bytes, and that tag **is** found immediately after names that carry values
(`regulatory-model-number` → `type=0x80000011` + `syscfg/RMd#/0x20`, i.e. 17 bytes). For the six properties
above, no such tag appears anywhere in their value window — only zero bytes until the next record's name.
Caveat stated honestly: I did not complete a full kDF parse (the header's two leading `u32 = 23` are the
first record's name length, so the blob starts with records, not a global header), so this is reported as
"**no populated value and no syscfg reference present**", not as a decoded number. Also note
`security-mode` is *not* a DT name on its own here — it appears only inside
`certificate-security-mode` / `effective-security-mode-ap|sep` / `security-reg-index`; the bare
`security-mode` string exists on the iBoot side only.

## 4e. EXPERIMENTS #2 + #3 CLOSED (09-12, later session — settles §4's open list)

**#2 P1 auth-order — NEGATIVE result, P1 authenticates before decode. Do NOT ship a
storage-swap delivery claim for Reports 1–3.** Trace in `sub_2339c` (BN VA): the
verification object is established at `sub_1f04bc → sub_1f04c8` — a vtable
(`arg4 = {digest(payload, out, ≤0x30), ..., manifest-lookup, ticket}`) whose
`(*arg4)(payload_ptr, payload_len, &digest_out, digsize, arg4)` computes over the
**stored (compressed) bytes**, gated by error `0x40040008` BEFORE any dispatcher call
(`bl sub_203648/sub_2036f0` live strictly later, at VA `0x24510/0x245d0` region, with
a post-decode size-equality check `!= x20_4 → 0x40040028`). The encrypted-payload arm
runs the SEP AEAD-open (`sub_89a4c(0x11, …)`) before parse. Residual honesty: the
`'memz'` branch of `sub_246bc` copies host-supplied memimgz regions without validation,
but memz is a host-staging construct (same trust class as `'splt'`), not a P1 boot path.
**Consequence: Reports 1–3/5 delivery remains exactly P2/P3/P4 — the unkeyed-CRC
staged-container family. This NARROWS and HARDENS the set: no overclaim, and the
"why we did not claim a NAND-swap vector" question pre-answers Apple.**

**#3 'wchf' — RE'd fully enough to answer. NOT a new memory-safety bug, but a real
amplifier for Report 4 + a hardening defect.** The consumer is raw `0x14ff14` / BN VA
`sub_150f14`; it has ZERO code callers and is reached only through a **record-handler
registry** — raw `0x21ba78 {fn=0x14fed8, flags=0x80200000}` (writer) and
`0x21ba88 {fn=0x14ff14, flags=0x80700000}` (reader), one of ≥8 sibling {writer,reader}
pairs in that table (same table-dispatch trap as `sh_memboot` — IBEC_IBSS §5 applies).
Findings: (a) the 4cc type test at entry (`cmp w0,#0x77636866; b.eq @0x14ff58`) is
**LOG-ONLY** — the mismatch path logs `0x40100001` at `0x14ff68` and **falls through
into the copy body**; enforcement is entirely in the (unsigned) caller's table pick.
(b) The only size gate is `arg6 > *(head+0x10)` ("wchf image too large") at
`0x14ff88..90`, compared against the FIRST list node's capacity, and the actual copy
(`sub_170f44`, raw `0x16ff44` — the same generic record-copy helper used by P1
registration paths) writes at `*(head+8)` of that same head node = one internally
consistent bounded write; **no OOB found**. (c) No keyed check on the record path at
all. **Wording consequence: Report 4's pattern claim generalizes — unkeyed,
attacker-shaped staging records are a FAMILY ('splt', 'wchf', 'iBootIm', 'paniclog',
…), which supports the "container format family is weak" framing §2 predicted.**
Open residual (needs the LEVEL-B harness, not static): who populates the region-list
node `{data@+8, cap@+0x10}` at raw `0x3553b0` on retail boot, and whether the writer
(emitter `sub_150ed8`) can plant a node whose cap lies about its buffer.

## 5. What to change in the reports' wording (Apple's likely pushback, pre-empted)

* Reports 1–3 each say "input arrives during manufacturing/upgrade ('combo') staging handoff". On 27.0 the
  accurate and *wider* statement is: there are exactly **4** decompression entry points; **two** of them
  (P2, P4-fallback) are `'splt'`-staged with an unkeyed CRC gate, and **one** (P3) is an `iBootIm`/`LZFSE`
  record consumer with **8** callers in the boot-command/env layer. Say that, and drop the single-sentence
  combo framing.* Report 4's "boundary amplifier" is the correct frame and should be *promoted* to the lead of Reports 1–3
  (same CRC helper `sub_15e8bc` is used by P3 too — the weak-integrity container pattern is not unique to
  `'splt'`).
* Report 6 should cite the `nvram-proxy-data` / `nvram-raw` / `nvram,nor` / `nor0` property names as the
  backing store, and the in-binary `%s Failed to validate HMAC.` (sysConfig3) as proof that a keyed option
  existed and was not used on this store.
