> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleSARService — "Current Write Index is out of the bound" analysis

Binary: `com.apple.driver.AppleSARService`, iOS 27.0 RC (24A435), mac-aarch64.
Target function: `enqueueFlushSnapshotGated` @ `0xfffffff0094d3efc` (`sub_fffffff0094d3efc`).
Validation string: `"Current Write Index is out of the bound: %d\n"` @ `0xfffffff0077019ab`.

Method: Binary Ninja MCP, read-only. Every store width below was confirmed in
`bn_function_disassembly` (the decompiler's 32/64-bit rendering was cross-checked).

---

## 1. Ring / queue layout

Producer/consumer ring of **8 descriptor slots**, each pointing at a separately
allocated snapshot buffer.

Queue object = `arg1[0x4c]` (service `this` + `0x260`).

| Offset | Size | Meaning | Evidence |
|---|---|---|---|
| `+0x00` | 8 | element/record size constant `0x67` | `setupSensingCA` `0xfffffff0094d1228: mov w8,#0x67; 0xfffffff0094d122c: str x8,[x20]` |
| `+0x08` | `0x80` | descriptor array: 8 × {`ptr` u64, `count` u32} | loop `str x0,[x26]` / `str w25,[x26,#8]` at `0xfffffff0094d1170`/`0xfffffff0094d1174`; base `queue+8`, stride 16 |
| `+0x88` | 4 | **write index** (u32) | `0xfffffff0094d4408: ldr w9,[x8,#0x88]!` (x8=queue+0x88) |
| `+0x8c` | 4 | **read index** (u32) | `0xfffffff0094d4c58: ldr w9,[x8,#0x8c]` (drain path) |

Initialisation (`setupSensingCA` = `sub_fffffff0094d1000`):
- 8 buffers allocated with `sub_fffffff009557540(0x2971)` (`0xfffffff0094d10f8`), each
  filled as 103 records of `0x67` bytes (`0x67*0x67 = 0x2971`).
- Each descriptor: `ptr = buffer`, `count = 0x67 = 103` (`0xfffffff0094d1174`).
- Both indices zeroed together: `0xfffffff0094d1224: str xzr,[x20,#0x88]` (64-bit store
  clears `+0x88` and `+0x8c`).
- Queue installed at `0xfffffff0094d1230: str x20,[x19,#0x260]`; drain callback
  `submitSensingCAEventGated` registered at `0xfffffff0094d1244`.

Element size used by the write (`0x67`) matches the descriptor `count` unit and the
buffer allocation (`count*0x67`). No mismatch.

## 2. The bound check (quoted)

```
0xfffffff0094d4400  ldr   x10, [x0, #0x260]      ; x10 = queue
0xfffffff0094d4404  mov   x8, x10
0xfffffff0094d4408  ldr   w9, [x8, #0x88]!       ; w9 = write index (32-bit, zero-extended)
0xfffffff0094d440c  cmp   w9, #0x7
0xfffffff0094d4410  b.hi  0xfffffff0094d44f0     ; if (u32)index > 7 -> log & skip
```

Verdict — **correct, no off-by-one, unsigned**:
- `b.hi` = unsigned "higher"; `cmp w9,#0x7` → rejects `index >= 8`. Capacity is 8, so
  valid range is `0..7`. This is `index >= capacity`, not `index > capacity`.
- Load is `ldr w9` (32-bit) → index is unsigned 32-bit. No signed/unsigned confusion.
- The index is used only after the check.

Defence in depth after the check:
```
0xfffffff0094d4414  add   x10, x10, #0x8          ; descriptor base
0xfffffff0094d4418  subs  x11, x8, x10            ; x11 = 0x80
0xfffffff0094d4428  lsl   w9, w9, #0x4            ; index*16 (32-bit)
0xfffffff0094d442c  add   w12, w9, #0x10          ; index*16+16
0xfffffff0094d4430  cmp   w12, w11
0xfffffff0094d4434  b.hi  <bounded_ptr trap>      ; index*16+16 <= 0x80
0xfffffff0094d4438  adds  x10, x10, w9, uxtw      ; base + zero-extended index*16
```
`uxtw` zero-extends the 32-bit scaled index; `adds` overflow is trapped. The added
`>7` check also forecloses the classic 32-bit `lsl` overflow bypass (an index such as
`0x10000000` would shift to 0 and pass the `+0x10 <= 0x80` test) — that is very likely
the bug this string was added to fix. It is now closed.

## 3. Write-index provenance — internally maintained, not attacker-controlled

- Set to 0 at init (`0xfffffff0094d1224`).
- Updated only here, immediately after a successful enqueue:
  ```
  0xfffffff0094d44d0  ldr  w9, [x8]        ; reload
  0xfffffff0094d44d4  add  w9, w9, #0x1
  0xfffffff0094d44d8  negs w10, w9
  0xfffffff0094d44dc  and  w10, w10, #0x7
  0xfffffff0094d44e0  and  w9, w9, #0x7
  0xfffffff0094d44e4  csneg w9, w9, w10, mi
  0xfffffff0094d44e8  str  w9, [x8]        ; (index+1) mod 8, stays 0..7
  ```
- No external writer to `queue+0x88` exists: `setupSensingCA` zeroes it; the enqueue
  increments it mod 8. External methods (`rfSensingCAInfo` → `updateSensingCAInfoGated`)
  only touch `arg1[0x42..0x44]` (SensingCAInfo), never the queue.

## 4. The element write

```
0xfffffff0094d4450  ldr  x9, [x10]          ; descriptor.ptr (u64)
0xfffffff0094d4454  cbz  x9, <trap>         ; null ptr rejected
0xfffffff0094d4458  ldr  w10, [x10, #0x8]   ; descriptor.count (u32)
0xfffffff0094d445c  mov  w11, #0x67
0xfffffff0094d4460  umull x10, w10, w11     ; count*0x67, 32x32->64 (no overflow)
0xfffffff0094d4478  subs x10, x11, x9       ; span = count*0x67
0xfffffff0094d4480  lsr  x11, x10, #0x20
0xfffffff0094d4484  cbnz x11, <trap>        ; span must fit 32 bits
0xfffffff0094d4488  cmp  x10, #0x66
0xfffffff0094d448c  b.ls <trap>             ; require count >= 1
```
Writes (all confirmed widths): `str w28,[x9]`; `strb w19..w26,[x9,#4..#7]`;
`str w24,[x9,#8]`; `stur q0..q4,[x9,#0xc..#0x5c]`; `stur d8,[x9,#0x5c]`;
`strb w1,[x9,#0x64]`; `strb w10,[x9,#0x65]`; `strb wzr,[x9,#0x66]` → exactly
`0x67` bytes into `descriptor.ptr`. Since `count >= 1` and the buffer is exactly
`count*0x67` bytes, the write is in-bounds. `umull` (not `madd w`) rules out
multiplication truncation.

## 5. Read path

`submitSensingCAEventGated` (`sub_fffffff0094d4b98`), registered as the flush
interrupt action:
```
0xfffffff0094d4c58  ldr   w9, [x8, #0x8c]         ; read index
0xfffffff0094d4c5c  cmp   w9, #0
0xfffffff0094d4c60  cneg  w12, w9, mi             ; abs
0xfffffff0094d4c64  ubfiz x12, x12, #0x4, #0x20   ; abs*16, zero-extended
0xfffffff0094d4c68  cneg  x12, x12, lt            ; negate if original < 0
```
followed by the same `bounded_ptr` range check (`+0x10 <= 0x80`, sign-bit test). A
negative read index negates into the sign bit and traps; index 8 gives `144 > 128` and
traps. So the read index is validated by a different mechanism (trap vs. graceful log)
but is still bounded to `0..7`. It is also updated `(index+1) mod 8`. No read-index
asymmetry that yields OOB/uninitialised data: a null descriptor is logged and skipped
(`"No CA snapshot in queue"`).

## 6. Reachability

Enqueue caller chain (only one direct caller):
```
sub_fffffff0094d3efc (enqueueFlushSnapshotGated)
  <- sub_fffffff0094d3948 (tryFlushOnTickStateChange)  @ 0xfffffff0094d3b04
       <- sub_fffffff0094d33a4 (tickSensingCAGated)          @ 0xfffffff0094d3390
       |    <- sub_fffffff0094d331c (virtual; no direct callers -> vtable/timer)
       <- sub_fffffff0094d3784 (updateTxIndicator_block_invoke) @ 0xfffffff0094d37cc
```
`updateTxIndicator_block_invoke` is a block invoked on the baseband TX-indicator
notification; `tickSensingCAGated` is reached via virtual dispatch (no direct caller,
i.e. a timer/workloop callback). Neither is an `IOUserClient` external method.

IOUserClient methods present for this feature are `rfSensingCAInfo`,
`rfSensingCACurrentState`, `rfSensingCALastSubmit` (strings
`AppleSARServiceUserClient::extSARSensing*` @ `0xfffffff0076ff6a6` etc.); they only
get/set `SensingCAInfo`. They can influence the *contents* of a snapshot but cannot set
the ring indices. The dispatch table in `__const#10` uses PAC-signed function pointers
and could not be reliably resolved via `bn_memory_read` (no data xrefs available), so
no selector number is asserted.

**Reachability verdict: not directly reachable from a sandboxed app via
`IOConnectCallStructMethod`/`IOConnectCallScalarMethod`.** Trigger is firmware/timer
driven (baseband TX-indicator change, periodic tick).

---

## Ranked candidates

| # | Candidate | Confidence |
|---|---|---|
| 1 | Write-index OOB write in `enqueueFlushSnapshotGated` (off-by-one / signed / truncation / shift-overflow) | **REFUTED** — check is `(u32)index > 7` before use; index internal, init 0, `+1 mod 8`; element write bounded by `count*0x67` with `count >= 1` and buffer allocated exactly `count*0x67`. |
| 2 | Read-path OOB read / info leak via read index | **REFUTED** — read index validated by `abs`+`bounded_ptr` (`+0x10 <= 0x80`, sign-bit trap); null slots skipped. |
| 3 | Index truncation (`lsl w9`) enabling a bypass | **REFUTED** — the added `>7` check executes first and excludes any value that could overflow the 32-bit shift. |
| 4 | Producer/consumer race (no "queue full" check → overwrite of an in-flight slot) | **SPECULATIVE** — both contexts are "Gated"/workloop-serialised; would be a data-integrity issue, not a memory-safety OOB. No evidence of cross-CPU concurrency. |

## Bottom line

The newly added validation is **complete and correct**. The write index is an
internally maintained `u32` confined to `0..7`, the check is an unsigned
`index > capacity-1` performed before any offset computation, the offset scaling is
32-bit-safe, and the record write is bounded by a descriptor count that matches the
buffer allocation. No bypass was found. Clean negative.
