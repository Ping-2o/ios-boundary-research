> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# M2ScalerCSC / IOSurfaceAccelerator — Campaign Report (v164–v173)

**Target**: `AppleM2ScalerCSCDriver` (AppleM2ScalerCSCDriverUserClient + IOSurfaceAcceleratorClient), iOS 26.6 (23G71) / 26.6.1 (23G83), t8140 (iPhone17,5).
**Period**: 09-01 → 09-02. **Epochs**: v164–v173 (10 builds, 9 device runs). **Front status: CLOSED at both layers.**

> **Vendor disposition — Apple Product Security, OE110768579232 (submitted 02 Sep 2026, closed 04 Sep 2026).**
> **Closed — the validation gap does not produce memory corruption.**
> *"After review, the validation gap that you observed does not result in an out-of-bounds access."*
> This is consistent with the campaign's own run verdict in §5 ("the gate hole is real and
> client-reachable … **but the HW contained every wild rect**"). Read §5 as a **validator hole
> that the hardware neutralises**, not as an exploitable out-of-bounds access — the signed-wrap
> is real as a code observation, and no kernel-write primitive follows from it.

---

## 1. Why this target

The 23G83 kernelcache recon ranked `AppleM2ScalerCSCDriverUserClient` #1: 564KB kext, 214 classes, MSR2→MSR25 scaler generation stack, DMA reg-stream classes, and an Apple-documented hardware failure mode gated only by geometry:

> `This version of hardware can corrupt memory with dest height=%u, source width=%u, planes=%u`
> `Failure mode: dest height <= 32, source width > 128, planes > 1`
> (kext `0xfffffff00754e90a` / `0x754e967`)

If that corruption config were client-reachable from the sandboxed app, the scaler DMA would be the kernel-write primitive ("the 64747 write"). The campaign also held a second reason: the kext sits behind `vt_Copy` in the exact pixel-transfer chain the AVE crashes rode.

## 2. What was proven open (v164–v165)

- **The UC is directly openable from a sandboxed app.** `IOSurfaceAcceleratorCreate` returned a live accelerator AND `IOServiceOpen(AppleM2ScalerCSCDriver)` opened a connection in-app — no daemon, no entitlements, no kext-prompt. The static sandbox verdict (`kc blob @0xa469cb`) was **falsified**.
- The daemon path (videocodecd via `VTCompressionSession` scale) rides CPU blitters: the kernel log caught the daemon's ONE HW attempt dying at `Hal.cpp:10153 0xe00002c2` and VT silently falling back — why every campaign transfer ever rode `vt_Copy`, never the HW scaler.
- Userspace RE (`IOSurfaceAccelerator.framework`, 97KB): `TransferSurface → convertToTransform → prepareTransformBuffersAndOptions → transformSurface → IOConnectCallStructMethod(conn=acc+0x24, sel=1, struct 0x1b0)`.

## 3. The selector map (complete, v165–v166 + v173)

| sel | wrapper | transport | verdict |
|---|---|---|---|
| 0 | `CaptureSurface` | 0x40 struct in | rect bounds-checked wrapper-side; **no `user_capture` handler in kext** → paravirt/guest-only, dead on hardware |
| 1 | Transfer / WithSwap / Blit / Conditional / Transform / Paravirt(kind 2) | 0x1b0 struct in | the live DMA path (below) |
| 2 | `AbortTransfers` | scalar | inert |
| 3 | `AbortCaptures` | scalar | inert |
| 4 | `SetCustomFilter` | 0x20 struct in | taps/phases consistency-checked (`setCustomFilter ... inconsistent sizes`), `user_set_filter` |
| 5 | (unmapped) | 1-byte struct | unreached |
| 6 | `KernelTests` | 0xfa8 struct | stubbed on 26.6 (`0xe00002e2`) |
| 7 | `GetHistogram` | 8-byte struct {ptr,count} | the histogram readback (below) |
| 8 | `GetDiag` | 8-byte struct ('kDiP') | sparse dump, canary-grade |
| 9 | `GetTransformEstimation` | 0x10 struct | pure-userspace probe, estimation-only |
| 10 | `SetProperty` | — | called by Create `{kind=2, 50000, 500000}` |
| 11 | `GetFrameworkInfo` / Paravirt(kind 1) | 648B out | config dump |

## 4. The corruption-geometry gate (v166–v172) — CLOSED

**The Apple-documented corrupt-memory config (`destH<=32 + srcW>128 + planes>1`) is NOT client-reachable.**

- The gate lives at the kext UC client layer, **reads the REAL surface dims**, and rejects with `BadArgument` before the HAL (v166: 0 `[IOSA]` kernel lines on our rejections; the executing paths all rode real-fed surfaces).
- Every bypass axis probed, all dead, all verdicts by byte readback:
  - **mode word** (struct+0x2c ∈ {0,1,2,3,0xff}): gate is mode-independent; mode 2 same-size executes (v170).
  - **format-plane matrix**: BGRA/2vuy/420v mixed pairs at h32 → BadArgument or `Unsupported 0xe00002c7` (format table first) (v170).
  - **BorderFill rect** (struct+0xcc..0xd2, the 4-key option quartet): fill geometry only — R1–R4 executed the FULL 1080p dst at every rect height, A/C=0 (v171).
  - **struct-vs-surface mismatch**: a consistency check rejects declared-big/real-small; declared-small/real-big accepted but the HW is **REAL-FED** — the shape oracle (M2S0) wrote all 1080 rows while the struct declared 32 (v172, reproduced 2/2 byte-identical).
  - **post-create height flip** (`IOSurfaceSetValue(kIOSurfaceHeight)`): immutable, H stays 32 (v172).
  - **WithSwap**: queues, never flushes in-app (v168–v169); **the Gemini UAF race** (CFRelease mid-flight + surface churn): the kext retains/cancels refs, zero stale writes (v169).
  - **flags sweep** (14 bits, incl. 0x1000/0x2000/0x3000/0x12000): no bit skips the gate (v167–v169).
  - **KernelTests sel6**: stubbed (`0xe00002e2`) — not an oracle.

**Proven capital**: a sandboxed app drives real HW DMA byte-proven (same-size 1080p→1080p diffs the entire 3110400-byte dst) with zero daemon and zero entitlements — the strongest client-side primitive the campaign holds, and the vehicle for v173.

## 5. The histogram signed-offset wrap (v173) — the validation hole

Ghidra on the kext found the **only statically-proven validation hole of the campaign**, present in **both** filter generations:

- `IosaColorManagerMSR4.cpp:246` (26.6) → `FUN_fffffff008db70f8`
- `IosaColorManagerMSR23.cpp:874` (26.6.1) → `FUN_fffffff008dc0ec4`

```c
Bw = *(u32*)(desc+0x20);  Bh = *(u32*)(desc+0x24);   // REAL surface dims (descriptor)
Hw = *(u32*)(ctx+0xbe0);  Hh = *(u32*)(ctx+0xbe4);   // client HistogramWidth/Height
Hx = *(int *)(ctx+0xbd8); Hy = *(int *)(ctx+0xbdc);  // client offsets — SIGNED
if (Bw < (u32)(Hx + Hw) || Bh < (u32)(Hy + Hh)) reject;   // negative offset wraps → PASSES
```

Client keys (exported CFStrings): `kIOSurfaceAcceleratorHistogramBinMode/OffsetX/OffsetY/Width/Height`. Mode must be 1|2 (`(mode-1U)<2`). Bins are client-readable: sel7 `GetHistogram` (count from registry, bins wired at buf+4) and the `kIOSurfaceAcceleratorHistogramPixelBins` dst attachment. The kext's own `testHistogram` (`FUN_fffffff008db94a0`) drives the identical path with the same keys.

**Run verdict (18:54):** the gate hole is **real and client-reachable** — 3/3 impossible rects ACCEPTED (`{-16,0,1920,1080}`, `{0,-8,…}`, `{X=-2^28,W=2^28+16}`) while both controls REJECTED (`{X=2000,W=64}` → BadArgument + `Invalid histogram` log; mode 0 → BadArgument). **But the HW contained every wild rect**: the wrap cells returned **all-zero bins** (the engine read zero pixels from the outside-starting rects — histogram state resets per transfer, so a foreign read would have shown foreign bins) and the big-wrap clamped to a real in-surface 16-wide column (~129 px/bin = 17280px/128). Sentinels clean, dst diff identical 3098251 across cells, no panic.

**Verdict**: a genuine Apple validation bug (impossible rects ride validation into the HW program path in both generations), but the DMA containment (zero-accumulation / W:=sum clamp) sits upstream of everything the client shapes. **No OOB read, no OOB write, no R/W primitive.** The mode-2 programmable-bins variant is cut — containment is upstream of bin modes.

## 6. Method lessons (portable)

1. **"No entitlement strings in the kext binary" ≠ ungated.** Gates can be set programmatically at init (AVD does exactly this — see the AVD report). Personality plists live in the kernelcache, not the carved kexts.
2. **Chained-fixup decoding is mandatory** on kernelcache carves: kext const pointers are `VA = 0xfffffff007000000 + (raw & 0xFFFFFFFF)`; naive pointer scans (vtables, dispatch tables) return garbage until decoded. Ghidra imports do not apply the fixups — the bound functions never get split and absorb into neighbor blobs.
3. **Readback > return codes.** Every accepted-but-inert path (WithSwap queueing, real-fed DMA) was only closed by diffing bytes. Error-code verdicts lie.
4. **Controls make accepts mean something.** The JH05/JH06 rejections are what prove the JH02–04 accepts were wraps and not an absent gate.
5. **Zero-state breaks hash-diff witnesses**: JH02/03 differed from the baseline by being EMPTY, not foreign. A witness must assert bins the in-bounds set cannot produce.

## 7. Final disposition

| Axis | Verdict |
|---|---|
| Corrupt-memory geometry (destH≤32) | NOT client-reachable — real-dims gate at UC layer |
| Transfer struct/surface mismatch | HW is real-fed; declared dims inert |
| BorderFill rect | fill geometry only |
| Post-create surface mutation | immutable |
| Async/UAF (WithSwap + release) | refcounted, no stale writes |
| Histogram signed-offset wrap | **validator hole confirmed**; HW contains (zero-accum/clamp) |
| Filter coefficients (sel4) | taps/phases consistency check; bounded |
| sel0 capture / sel6 ktests / sel2-3 aborts | guest-only / stubbed / inert |

**The M2ScalerCSC front is closed at both layers** (UC gate + HW containment). Epoch budget returns to rows A–H; the successor media front is **AppleAVD** (entitlement-gated direct, videocodecd-mediated — see the AVD report).

---
*Evidence: console receipts v164–v173 (this repo, `kernel.rtf`), kernel logs, `.ips` absence as the negative witness. Row probes: `UI/probe_m2scaler.m` (I), `UI/probe_iosa_hist.m` (J). Ghidra programs: `/AppleM2ScalerCSCDriver`, `/IOSurfaceAccelerator`, `/IOSurface`, `/com.apple.kernel` in project `kernel`.*
