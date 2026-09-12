> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# iBEC / iBSS — the delivery answer for Reports 1–3 (iPhone17,5, iOS 27.0 24A435)

## 0. Headline: iBoot ≡ iBEC ≡ iBSS — one image, three IMG4 tags

| component | im4p | type | version | uncompressed | sha256 (prefix) |
|---|---|---|---|---|---|
| iBoot | `Firmware/all_flash/iBoot.v59.RELEASE.im4p` | `ibot` | mBoot-20457.2.37 | 3,832,328 B | `e1b9aa20c3d00b7eeadecfb1dd04963d…` |
| iBEC | `Firmware/dfu/iBEC.v59.RELEASE.im4p` | `ibec` | mBoot-20457.2.37 | 3,832,328 B | `e1b9aa20c3d00b7eeadecfb1dd04963d…` |
| iBSS | `Firmware/dfu/iBSS.v59.RELEASE.im4p` | `ibss` | mBoot-20457.2.37 | 3,832,328 B | `e1b9aa20c3d00b7eeadecfb1dd04963d…` |

**Byte-for-byte identical** (diffed: 0 differing bytes between all three). All three payloads are
**unencrypted** `bvx2` (LZFSE), extracted with
`d[d.find(b'bvx2'):]` → `compression_decode_buffer(COMPRESSION_LZFSE)`.

Consequences:

1. **Every offset and verdict in `RECHECK_24A435_mBoot-20457.2.37.md` is simultaneously the iBEC and iBSS
   map.** No relocation work needed; the dispatcher is at raw `0x2026F0` in all three, the Report-3 copier at
   raw `0x201080`, the memcpy thunk at raw `0x16FBA8/AC`, etc.
2. The recovery/DFU shell and the vulnerable decoders **live in the same code**, so they are not separate
   attack surfaces with separate integrity stories — see §2.
3. Platform note: this is `t8140`/A18 (iPhone 16e), **not** checkm8-affected; the shell's reachability on
   retail units is a *device* question (§4), not a static one.

## 1. Asset-integrity defect in the previous audit

`extclaims/audit/dfu/ibec.strings` and `extclaims/audit/dfu/ibss.strings` are **the same file**:
`sha256 476d63064f4984e5ebba6ca03f12ed9e785b9fd8de8d150a4762fc1556d45750` for both. Round 1's
"iBEC/iBoot string-surface map (3392 strings, `audit/dfu/ibec.strings`)" therefore rests on one dump that was
also filed as the other. Harmless on *this* build (the images are identical), but the provenance is wrong and
should not be cited as independent confirmation of anything.

Also: every offset in `AUDIT_NOTES.md` Rounds 1–12 (`sh_memboot`→`0x1958`, `do_boot`=`FUN_00004910`,
gate=`FUN_0007fa3c`, `0xCAFEFABE`/`'comp'`/`'lzss'`/`'memz'`, cap `mov w1,#0x1e000000 @0x2e7a8`) belongs to a
**different build**. None of those magic 4CCs exist in the 24A435 image (scanned as both byte patterns and as
`movz/movk` immediate pairs), so the old chain must not be carried forward without the re-verification below.

## 2. Re-verified in 24A435: the memboot path, end to end

BN VA = raw + 0x1000 (the wrapper view).

```
sub_5080   (VA 0x5080–0x5a9b, __noreturn)   recovery shell main
    strings in-line: "Entering recovery mode, starting command prompt" (ref @0x5974),
    "boot-command" @0x57fc, "device-recovery", "delay-recovery-image", "debug-uarts",
    "poweroff", "idle-off", "command", "USB_"/"RSM_", "Local"/"Remote"
  │
  ├─ handler table entry VA 0x21c420 = { u32 fn=0x1944 (raw), u32 flags=0x80f00000 }
  │     (sibling entries in the same table: slot 0x21c3a8 → fn 0x121c, slot 0x21c498 → fn 0x23b0
  │      flags 0x86200000)
  │
  │   CORROBORATION vs the 26.6-era map in AUDIT_NOTES Round 2
  │   (`bootx`→0x1184 · `memboot`→0x1958 · `go`→0x2374): the same three handlers, same order,
  │   relocated by a few hundred bytes → raw 0x121c = sh_bootx, **raw 0x1944 = sh_memboot**,
  │   raw 0x23b0 = sh_go. Independent confirmation that this table is the recovery shell's
  │   command table and not something else.
  ▼
sub_2944   (VA 0x2944–0x2d3f) = sh_memboot
    x0 = sub_16290c("filesize", "filesize", "filesize variable invalid or not set, aborting\n", …)
        ← HOST-SETTABLE ENVIRONMENT VARIABLE, and x0 becomes the allocation/receive size
    if (!x0) → print "filesize variable invalid or not set, aborting"; return -1
    if (x0 < 0x20000001)                       ← only a 512 MiB ceiling, no floor
        if (!(sub_82434(...) & 1)) → print "Permission Denied"; return -1
        sub_ca2f4()                            ← USB receive of host bytes
        x8_1 = x2 - x0_1                       ← received length
        if (x0 > x8_1) → halt (sub_33d54)      ← must satisfy filesize vs received
        …
    sub_2aa34(…, 'krnl' = 0x6b726e6c, …)       ← load the received buffer AS A KERNELCACHE
  │
  ▼
sub_2aa34  (VA 0x2aa34–…)
    prologue = registry/property lookups only (sub_314a0, sub_361d8(0x2e), sub_316bc, sub_35498)
    @0x2ab44: bl sub_c6924                     ← the load/decode step
    @0x2ab48: cbz w0 … on failure prints VA 0x2b98d6 = "Kernelcache image not valid\n"
                (i.e. the verdict is emitted AFTER the decode)
  │
  ▼
sub_c6924 → sub_c66ac → sub_2339c → sub_2036f0 / sub_203648   [DECOMPRESSION DISPATCHER]
                                            id 0x205/0x505 → DEFLATE  → Report 1 (live)
                                            id 0x100/0x101 → LZVN    → Report 2 (live)
                                            id 0x8a1/0x891 → LZFSE   → Report 3 (live)
```

`sub_2339c` has exactly one caller (`sub_c66ac`) and `sub_c66ac` exactly four (`sub_c6924`, `sub_c6e30`,
`sub_c7378`, `sub_c75f4`) — so this is the complete, closed link from the shell to the codecs.

**Attacker controls both inputs.** `filesize` sets the destination size and the receive length is
host-supplied, so the same party chooses the compressed stream *and* the buffer it is inflated into. That is
materially worse than the reports' current "staged blob of unknown size" framing, and it also means the
destination-capacity clamps that Report 1's bug lacks cannot be relied on to save the attacker-free case.

## 3. The "permission gate" is not an authentication check

`sub_82434` (BN VA `0x82434`), decompiled verbatim:

```c
uint64_t sub_82434(int64_t arg1, …, int64_t arg5) {
    if (*0x3bc892 & 1) return 1;                             // global allow-all bit
    if (arg1 + arg5 >= arg1 && *0x3bc8a0 <= arg1)            // addr >= window base
        return (arg1 + arg5 <= *0x3bc8a8) ? 1 : 0;           // addr+len <= window end
    return 0;
}
```

It is a **memory-range whitelist plus one enable bit** — no fuse, no security-mode query, no certificate or
pairing check. Consistent with `AUDIT_NOTES` Round 5's own words ("permission gate passes by design
(receive region = whitelisted window)"). The 8 "Permission Denied" referrers (VA
`0x2464`,`0x2bfc`,`0x34d4`,`0x65dc`,`0x6a60`,`0x1623a4`,`0x185634`,`0x1d4b80`) are all this same range check
applied per command.

## 4. What is NOT yet proven (do not write "pre-auth" until these close)

1. **No signature/AEAD validation *before* decode is shown, but its absence is not proven.** The prologue of
   `sub_2aa34` contains only registry lookups and the invalid-image verdict prints after the decode, which is
   *consistent with* decompress-then-validate. To claim pre-signature, the check must be traced inside
   `sub_c6924 → sub_c66ac → sub_2339c` (and in `sub_2944`'s `j_sub_232c8('ibdt')`/`sub_168ca4` steps) and shown
   to run after the dispatcher returns.
2. **Is `sh_memboot`'s window whitelisted on retail?** Depends on the runtime values behind `0x3bc8a0/8a8`
   and the enable bit `0x3bc892`. Static analysis can show who writes them; a device boot answers it outright.
3. **Does the recovery command prompt actually run on a non-checkm8 A18 unit** (iBEC/iBSS are shipped, so the
   code path exists, but entry may be restricted to restore/FUD states). Device-side question.
   **ANSWERED 09-12: YES.** Retail iPhone17,5 running shipping 27.0 (24A435), buttons-entry Recovery:
   `irecovery -c "getenv …"` returns empty (shell stdout goes to the debug UART, not USB — libirecovery's
   success line is only the control-transfer ACK), but `irecovery -c "reboot"` **executed** (device left
   Recovery and booted to normal 27.0). Commands run on retail. Remaining gaps before a memboot delivery
   claim: `send`/`bootx` acceptance (the bulk-OUT path), the §4.2 window, and locked-USB behavior —
   see `DeviceRunKit/results/RUN1_finding_console_live.md`.
4. Table entries carry a flags word (`0x80f00000`, `0x86200000`) whose meaning (argc? privilege class?) is
   undetermined — it may itself encode which commands are allowed in which state.

## 5. Methodological finding worth applying to Reports 1–6

`sh_memboot` (`sub_2944`) has **zero code callers**, and is reached *only* through the handler table at VA
`0x21c420`. A Ghidra/BinNAV-style "who calls this function?" query reports it as dead code — which is exactly
the reasoning Report 6 used to declare the NVRAM protected-name gate dead. This is now a demonstrated failure
mode of that method on this very image: **table-dispatched handlers must be searched as data
(`u32`/`u64` slots holding code offsets), never as function xrefs.** Re-run that check on every "zero xrefs"
claim in the set before submitting.

## Reproduce

```bash
IPSW="/Users/pauyedin/Downloads/iPhone17,5_27.0_24A435_Restore.ipsw"
unzip -o -q "$IPSW" "Firmware/dfu/iBEC.v59.RELEASE.im4p" "Firmware/dfu/iBSS.v59.RELEASE.im4p" \
                "Firmware/all_flash/iBoot.v59.RELEASE.im4p" -d /tmp/dfu24
# payload starts at the bvx2 magic; decode with libcompression (see /tmp/dsbvx.c)
python3 -c "d=open('/tmp/dfu24/Firmware/dfu/iBEC.v59.RELEASE.im4p','rb').read();i=d.find(b'bvx2');open('/tmp/dfu24/iBEC.payload','wb').write(d[i:])"
/tmp/dsbvx /tmp/dfu24/iBEC.payload /tmp/dfu24/iBEC_dec.bin 8388608
sha256sum /tmp/dfu24/iBEC_dec.bin /tmp/dfu24/iBSS_dec.bin /tmp/ds_iboot/24a435/iboot_dec_24a435.bin
```
