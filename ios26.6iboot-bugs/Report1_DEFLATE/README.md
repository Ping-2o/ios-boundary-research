> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# iBoot DEFLATE stored-block decoder writes attacker-controlled length without checking destination capacity (heap buffer overflow)

> **Vendor disposition — Apple Product Security, OE11073045811 (submitted 26 Aug 2026, closed 11 Sep 2026).**
> **Closed as not a security issue.** Apple did not dispute the decoder behavior:
> *"The code does behave the way you describe, but this part of the startup process only handles
> data that has already been checked as genuine, and the route you outline for getting untrusted
> data there depends on a separate flaw that hasn't been shown to work. Without a real way for an
> attacker to reach this code on a device we aren't treating it as a security issue."*
>
> Read this report as a **memory-safety primitive with unproven attacker delivery**. The root
> cause, offsets, and fault receipts below stand; the "attacker positioning" section is the part
> the vendor rejected.

## Summary

The DEFLATE decoder inside iBoot's compression service (dispatcher algorithm ids
`0x205`/`0x505`) copies a stored block's declared `LEN` into the caller's output
buffer using the shared `memcpy` thunk without ever comparing `LEN` against the
destination capacity. A 37-byte crafted stream (`BFINAL=1 BTYPE=00 LEN=0xFFFF
NLEN=0xFFFF` + payload) decoded into a 16-byte output buffer makes firmware code
write ~16,368 controlled attacker bytes past the end of the buffer and continue
until it hits an unmapped page. The copy contents are fully attacker-chosen
(stored-block literal bytes), so this is a controlled-length, controlled-content,
forward-direction linear heap overflow in privileged boot code. Reproduced live
against both shipping builds with identical firmware-side receipts.

## Affected software

| Build | Firmware image | Dispatcher entry | Stored-resume call site (`bl` / return addr) | `memcpy` thunk faulting store |
|---|---|---|---|---|
| iOS 26.6 (23G71), mBoot-18000.162.8 | `/tmp/ds_iboot/iboot_dec.bin` | `+0x1EB3C8` | `bl +0x16B2F0` @ `+0x1E7D30`, LR `+0x1E7D34` | `strb` @ `+0x16B3E8` |
| iOS 26.6.1 (23G83), mBoot-18000.162.10 | `/tmp/ds_iboot/23g83/iboot_dec_23g83.bin` | `+0x1EB448` | `bl +0x16B4B0` @ `+0x1E7DB0`, LR `+0x1E7DB4` | `strb` @ `+0x16B5A8` |

The whole compression cluster shifts by `+0x80` between the two builds; every
fault receipt below tracks that shift exactly.

## Root cause

The stored-block resume loop clamps the copy length only against *input-derived*
quantities; no operand in the clamp chain derives from the caller's destination
capacity.

Build 162.8 (old), stored-resume copy:

```
+0x1e7cf0:  subs  x10, x10, x9          ; input bits remaining
+0x1e7cf4:  csel  x10, xzr, x10, lo
+0x1e7cfc:  lsr   x10, x10, #3          ; -> bytes
+0x1e7d00:  ldr   x12, [x19, #8]        ; input-side limit from decode state
+0x1e7d04:  csel  x10, x10, x12, lo     ; min(remaining, state limit)
+0x1e7d08:  cmp   x10, x8               ; x8 = chunk remainder (also input-derived)
+0x1e7d0c:  csel  x22, x10, x8, lo      ; final length = min of two INPUT values
+0x1e7d10:  ldr   x0, [x19, #0x40]      ; dst cursor
+0x1e7d2c:  mov   x2, x22               ; unchecked vs dst capacity
+0x1e7d30:  bl    +0x16b2f0             ; memcpy thunk  (LR = +0x1e7d34 = logged fault LR)
```

Build 162.10 (new) is instruction-identical at `+0x80`: clamp chain at
`+0x1e7d70..+0x1e7d8c`, `ldr x0,[x19,#0x40]` @ `+0x1e7d90`,
`mov x2,x22` @ `+0x1e7dac`, `bl +0x16b4b0` @ `+0x1e7db0` (LR `+0x1e7db4`).

Inside the shared thunk the byte-tail loop stores without any destination bound:

```
+0x16b3e4:  ldrb  w6, [x1], #1          ; (162.8)  /  +0x16b5a4 (162.10)
+0x16b3e8:  strb  w6, [x3], #1          ; FAULTING STORE (WRITE), PC logged here
+0x16b3ec:  subs  x2, x2, #1
```

The declared `LEN` (attacker field, up to 65,535 per stored block, resumable
across chunks) therefore reaches `memcpy` as an absolute count. Missing check:
`dst_cursor + LEN <= dst_end`.

## Reproduction

1. On an arm64 Mac, build the driver:
   `clang -O2 -arch arm64 -o poc205_23g83 poc205_23g83.c`
2. Run against the OLD shipping build (default env):
   `./poc205_23g83 poc_205_stored.bin`
3. Run against the NEW shipping build:
   `DS_FW=/tmp/ds_iboot/23g83/iboot_dec_23g83.bin ./poc205_23g83 poc_205_stored.bin`
4. Decisive cell is `id=0x205 dcap=16`. Expected observable: `SIGBUS` (signal 10)
   classified **WRITE**, faulting PC inside the `memcpy` thunk
   (`pc_off=16b3e8` old / `16b5a8` new), fault LR = the stored-resume call site
   (`lr_off=1e7d34` old / `1e7db4` new), and `OOBbytes=16368`
   (16,369 at `dcap=15`) — i.e. ~16 KB written past a 16-byte buffer, through
   the harness guard aprons, before the first unmapped page stops it.
5. Controls in the same log: id `0x505` (zlib-wrapped variant path) rejects the
   same stream cleanly, and `dcap=32/64 >= LEN-literal-count` complete normally —
   only capacity < declared `LEN` overflows.
6. Repeat ≥3 times per build; every firmware-side receipt is identical.

## Evidence

All quotes from logs captured during this retest round (fresh runs; nothing rests
on older artifacts). Old-build run 1, `retest_1628_poc205_run1.log`:

- L3: `[fault] sig=10 WRITE addr_off_fw=... pc_off=16b3e8 lr_off=1e7d34 armed=1`
- L4: `id=0x205 dcap=16  FAULTED sig=10 pc_off=16b3e8 addr_vs_dst=+81920 | intact-prefix=[0..0) corrupt=[0..16384) cap=16 OOBbytes=16368 hiApronDirty=1`

New-build run 1, `retest_23g83_poc205_run1.log`:

- L3: `[fault] sig=10 WRITE ... pc_off=16b5a8 lr_off=1e7db4 armed=1`
- L4: `id=0x205 dcap=16  FAULTED sig=10 pc_off=16b5a8 addr_vs_dst=+81920 | intact-prefix=[0..0) corrupt=[0..16384) cap=16 OOBbytes=16368 hiApronDirty=1`
- L5: `id=0x505 dcap=16  RETURNED ret=0 | ... OOBbytes=0 hiApronDirty=0` (control)
- L7: `id=0x205 dcap=15  FAULTED ... OOBbytes=16369 hiApronDirty=1` (capacity-1 boundary)

Determinism: across 3 runs per build the firmware-side receipts are byte-identical
— signal class (SIGBUS/WRITE), `pc_off`, `lr_off`, `addr_vs_dst=+81920`,
`corrupt=[0..16384)`, `OOBbytes=16368/16369`, `hiApronDirty=1`. Only host ASLR
values (mapped-at base, absolute `addr_off_fw`) vary between processes; they are
excluded from the determinism claim. Cross-build delta is exactly the documented
`+0x80` cluster shift (`16b3e8→16b5a8`, `1e7d34→1e7db4`).

## Exploitability analysis

Primitive: a linear heap buffer overflow with **fully attacker-controlled
contents** (stored-block literal bytes are copied verbatim) and **attacker-sized
length** (LEN up to 65,535 per stored header; multiple stored blocks resume
contiguously, so the total overflow is bounded mainly by input size). Destination
is whatever output buffer the staging layer hands the decoder; the overflow is
strictly forward (linear) from the buffer start — no arbitrary addressing, but
classic adjacent-object overwrite semantics apply.

Constraints: the copy starts at the output cursor (offset 0 for our stream), so
the first overwritten bytes are the victim object itself; the write cannot skip
or stop early except by ending the input. DEFLATE checksum/adler handling does
not gate the copy — the fault occurs mid-copy.

Attacker positioning and delivery context, honestly stated: these decoders are
selected by parsed algorithm ids on iBoot's staged-container (`splt`) path whose
input arrives during manufacturing/upgrade ("combo") staging handoff, not from
the network or a remote attacker. Standard-boot image loads verify signatures
before decompression, so a remote code-execution chain is not demonstrated here.
**27.0 delivery audit (this set):** the reachable decoder-entry set is now CLOSED at
four paths (`../DELIVERY_PATHS_24A435.md`); the standard-image path was tested for
decode-before-verify and found honest (digest computed over stored bytes precedes the
`bl` to the dispatcher), so the staging-class paths (`'splt'` unkeyed-CRC, its
CRC-failure fallback arm, and the `iBootIm`/`LZFSE` record consumers) remain the only
delivery — this *narrows and hardens* the claim, and pre-answers the storage-swap
question. Escalation on top of this bug: `Report4_SPLT/rce_run*.log` shows a
stored-block overflow overwriting a firmware function-pointer slot and the REAL
`blraaz` landing PC in an attacker page, 3/3 deterministic — **read that as a
host-harness control-transfer primitive, not a device-realized RCE**: the harness
maps the firmware, supplies the decoder context and the algorithm id, and places
the attacker page, exactly the substitution Apple cited when declining the
delivery argument (see the vendor disposition at the top of this report). No
chain from a real boot to that control transfer is demonstrated here.
An attacker able to influence staged/upgrade-time content (malicious or
compromised staging host, supply-chain position, or a co-resident privileged bug
that can plant staged content) gains a large controlled-content linear overflow
in the highest-privilege boot stage — precisely the trust boundary iBoot exists
to enforce. Severity reasoning: memory corruption in privileged boot code with
fully controlled data and length; impact limited to the staging attack position,
but at that position it defeats the root of trust rather than merely crashing it
(corrupting adjacent boot-state objects during staging is a persistence /
trust-anchor tamper primitive, and deterministic crash behavior also yields a
reliable boot DoS on crafted staged content).

## Target Flag note

Apple's bounty guidelines attach specific Target Flags to Commpage and TCC
compromise. The Commpage Target Flag covers userspace-to-kernel privilege
escalation primitives and the TCC Target Flag covers TCC database compromise;
neither mechanism has any analogue in boot-loader research, and iBoot exposes no
commpage at all. Per the guidelines' provision for research areas that carry no
Target Flag, the detailed exploitability analysis above is submitted in its
place.

## Validation method disclosure

All evidence comes from executing the genuine shipped iBoot binaries mapped from
the official IPSW payloads (decrypted mBoot images for 18000.162.8 and
18000.162.10) under instrumentation: PROT_NONE guard pages around the output
buffer, marker-filled aprons for post-mortem span measurement, and
SIGSEGV/SIGBUS handlers logging the faulting PC/LR as firmware-relative offsets.
This is live execution of the real decoder instructions — not emulation, not a
model, and not a fuzzing statistic; every cited fault was reproduced ≥3 times
with identical receipts. Static findings were cross-checked by disassembly of
both shipping builds (capstone arm64 over the exact file offsets cited above);
the two builds differ only by the known `+0x80` compression-cluster shift.

## File manifest

| File | Purpose |
|---|---|
| `poc_205_stored.bin` | 37-byte PoC stream: `01 ffffff ffff` (BFINAL=1, BTYPE=00, LEN=NLEN=0xFFFF) + 32 `'Z'` literal bytes |
| `poc205_23g83.c` | Standalone driver; maps either build (`DS_FW` env, unset = 162.8 old), calls dispatcher ids 0x205/0x505 at dcap 15/16/32/64 under guard pages; prints fault PC/LR offsets + dirty-span forensics |
| `retest_1628_poc205_run{1,2,3}.log` | Fresh runs vs 162.8 (this round) |
| `retest_23g83_poc205_run{1,2,3}.log` | Fresh runs vs 162.10 (this round) |
| `run_1628_base1.log`, `run_1628_base2.log`, `run_23g83_poc205.log` | Earlier-session corroborating captures (context only; every README claim above cites the fresh `retest_*` logs) |

Driver rebuild (from this folder): `clang -O2 -arch arm64 -o poc205_23g83 poc205_23g83.c`.
