> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleAVD — Kernel R/W Audit Report (v174-static, session 09-02)

**Target**: `com.apple.driver.AppleAVD` (kext, 1.36MB carve, Ghidra program `/AppleAVD`, 2066 fns) + `AVD.videodecoder` (daemon-side plugin, 1.9MB).
**Reachability model**: `AppleAVDUserClient` sets `IOUserClientEntitlements = com.apple.videotoolbox.hardwarevideodecoder` **programmatically at init** (`FUN_fffffff0084bdaec`) — direct `IOServiceOpen(AppleAVD)` is kernel-gated for any third-party app. The only reachable path is **videocodecd** (the daemon holds the entitlement): app → `VTDecompressionSession` → videocodecd → AVD.videodecoder plugin → `IOServiceOpen`/`IOConnectCallStructMethod`/`IOConnectCallAsyncMethod` (imports confirmed in the plugin binary) → kext.
**Per-PID cap**: `m_pUserClientList[0..3]`, `maxUserClientCountProcess` — bounds-checked (`Attempting to set invalid client ID (%d >= %d)`).

---

## 1. The UC selector surface

Selector table at `__const 0xfffffff007db06d8` (40-byte stride, `IOExternalMethodDispatch`-shape, chained-fixup encoded):

| structIn | structOut | role (from handler/log evidence) |
|---|---|---|
| 0x1c8 (456) | 0xc0 (192) | session create / setResolutionInfo request |
| 0x4 | **0xdc8 (3528)** | big output — config/dump |
| **0xb50 (2896)** | 0x4 | big input — decode submission |
| 0x30 | 0xb0 | medium pair |
| 0xb8 | 0x4 | request |
| 0x4 | 0x4 | scalar-ish |
| 0x18 | 0x4 | small request |
| 0x4 | 0x4 | scalar-ish |
| 0x10 | ? | small request |

The 0x1c8 session-create request carries: `width=request[0]`, `height=request[1]`, codecType `request[3]`, timeout-override `request[0x48]`, flags `request[0x54]`, ClientPID `request[0x58]`, CreationTime `request[0x59]`, Storage `request[0x6a]`, ThreadId `request[0x6c]` (offsets in the create handler `FUN_fffffff0084beb84`).

## 2. Audited paths — findings

### 2a. Decrypt bounds check — AIRTIGHT (dead end)
`FUN_fffffff0084c155c` validates `byteOffset / dataLength / bufferSize` with **five** checks including an explicit overflow guard:

```c
if (bufSize(dec) != bufSize(in))            reject;  // size mismatch
if (byteOffset >= bufSize)                  reject;  // Bad decrypt byteOffset
if (bufSize < dataLength)                   reject;  // Bad decrypt dataLength
if (CARRY4(byteOffset, dataLength))         reject;  // "Input buffer write will overflow" ← explicit u32 add guard
if (bufSize < byteOffset + dataLength)      reject;  // Bad decrypt arguments
```

Apple closed the classic wrap here. The decrypt axis is dead.

### 2b. setResolutionInfo gate — honest (the 64747-analog gate)
`FUN_fffffff0084beb84` (the create/setResolution entry) computes **unsigned** max/min of the client width/height:

```c
maxDim = 0x10000;                                          // 65536
if (!(flags & 1) && !(ucFlag & 1)) maxDim = 0x41f8;        // 16888 (normal; unlimited-Resolution flag raises to 64K)
if (max(w,h) > maxDim) reject "Width or height out of range %u x %u";
minLim = (devTypeField < 400) ? 0x2000 : 0x4000;           // 8192 / 16384
if (min(w,h) > minLim) reject;
```

No signed wrap, no overflow — the gate itself is honest. The interesting arm is the **flag-raised maxDim = 0x10000** (`kVASetUnlimitedResolution` in the plugin strings): dimensions up to 65536 x 16384 are ACCEPTED — that is where any downstream multiplication (`stride * width * height`) runs at its extreme. The downstream allocation math (called as `FUN_…(kextState, contextID, codecType, w, h, stride, …)` from the create handler — Ghidra label collision, needs re-carve) is the **un-audited link**.

### 2c. The FW command patcher — a bounded kernel write engine (the best shape in the kext)
`FUN_fffffff0084c6634` = the per-frame firmware command patcher:
1. `FUN_fffffff0084c6834` translates/checks a mapped buffer (`mapType==6` only; `OOB (length=%u) for returned mapping` guard) and resolves the patch list.
2. `FUN_fffffff0084c691c` copies the decode buffer from userspace ("Copy from userspace decode buffer…").
3. `FUN_fffffff0084c6bd4` applies `numRequests` patches (count guarded `numRequests < 0x5555556` so `count*0x30 < 2^32`), each a **48-byte record** processed as:

```c
offset = rec[1];  fieldSize = byte at rec+0x14 (2 or 4 only);  mask = rec[-3] (u64, !=0);
addend = rec[2];  truncate = rec[3] (<= 0x40);  bitfieldMask = rec[4] (!=0);
if (CARRY4(offset, fieldSize) || cmdBufSize < offset + fieldSize) reject "Invalid offset";
value = resolve(rec[-5] u64 userPointer OR iosid, offset)         // kernel READS user memory / IOSurface
if (CARRY8(addend, value) || !mask || truncate > 0x40 || !bitfieldMask) reject;
written = ((value + addend) & mask) >> truncate << (bitcount(bitfieldMask)-1);
*(u32|u16*)(cmdBuf + offset) = old & ~bitfieldMask | bitfieldMask & written;   // KERNEL WRITE
```

**Assessment**: the write is bounds-checked against `cmdBufSize` with carry guards, field size restricted to 2/4, shift range guarded. The write engine stays inside the FW command buffer **if and only if `cmdBufSize` equals the real allocation**. The patch source can be a **client-visible IOSurface** (`iosid` resolution path) — the value side is app-influenced; the target side is daemon-driven (the plugin builds the patch list). **Candidate**: a size divergence between the allocation path and the `cmdBufSize` handed to the applier would convert this into an OOB kernel write. Requires the allocation audit (§2d) + the plugin RE (who builds the records).

### 2d. Un-audited (next session's list)
- The setResolutionInfo **allocation math** (`stride*w*h` class multiplications at the flag-raised maxDim extremes) and its consistency with the patcher's `cmdBufSize`.
- `addMemoryDescToGart` / DART VAddr mapping sites (`FUN_…` at the `gart-add-fail` / `dart-vaddr-fail` xrefs 0x849e018 / 0x84c2a8c) — the mapping-bound math.
- The plugin (`AVD.videodecoder`): which selectors + records videocodecd builds, and **which SPS-derived values survive its checks** (`AVC sps[%d] width %d height %d over size`, `width (%d) * height (%d) exceeds limit (%llu)`, `video resolution %ux%u exceeds allocated size %ux%u`) into the kext structs.
- `driverKernelTimeoutOverride` range check accepts wrapped u32 (`uVar9 - 180001 > 0xFFFD4142` passes for `uVar9 ≥ 0xFFFF0000`) — raw value stored to driver state `+0x3ce4`; downstream timer math unaudited (low severity, but a real check inversion).

## 3. Empirical row K design (VTDecompressionSession via the daemon, zero new entitlements)

The app drives the kext through the bitstream: SPS dims → plugin checks → `setResolutionInfo`. The campaign already owns H264 SPS crafting (13 H264SW crashes) and the decode corpus machinery.

| Cell | Content | Hypothesis |
|---|---|---|
| K0 | baseline 1080p HW decode | corpus + oracle sanity |
| K1/K2 | SPS 16888x8192 / 8192x16888 (the normal gate edge) | allocation math at extreme |
| K3/K4 | SPS 65536x16384 / 16384x65536 (the unlimited-flag arm, if the flag rides any VT config) | maxDim=0x10000 arm — `stride*w*h` overflow class |
| K5 | SPS just-under-gate vs just-over (16888/16889) | confirms the kext gate receipt in the kernel log |
| K6 | decode into undersized surfaces (declared session vs SPS dims divergence) | the surface-vs-resolution mismatch axis |
| beats | 2x | daemon liveness |

Oracle: kernel log (`AppleAVD: ERROR … setResolutionInfo`, `DART VAddr Mapping Failed`, `addMemoryDescToGart`), `.ips`, sentinels. The daemon path costs epoch ops (videocodecd sessions), so K runs ALONE after a reboot like IK.

## 4. Verdict

**No 100% kernel R/W claim delivered on AVD in this pass.** The auditable-by-hand paths (decrypt, resolution gate, patch bounds) are guarded; the remaining probability mass sits in (a) the allocation-vs-patch-bound size consistency and (b) the plugin's SPS→setResolutionInfo value flow — both require the allocation audit + the 1.9MB plugin carve. AVD is a genuine multi-session front with the strongest R/W-shaped primitive found so far (the FW patch engine) as the prize.

---
*Ghidra: project `kernel`, program `/AppleAVD` (base `0xfffffff00716a680` = the carve's real `__TEXT` vmaddr; kext const pointers chained-fixup encoded, `VA = 0xfffffff007000000 + (raw & 0xFFFFFFFF)`; Ghidra auto-xrefs on strings absent — use the adrp/add scanner scripts in `/var/folders/.../opencode/ds_avd_*.py`).*
