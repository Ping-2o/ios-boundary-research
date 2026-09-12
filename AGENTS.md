> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AGENTS.md — DirtySlide knowledge base / tips for other agents

> **CAMPAIGN REPORTS (read alongside this file): `REPORT_M2SCALER.md` (the v164-v173 M2ScalerCSC
> front, CLOSED at both layers) and `REPORT_AVD.md` (the AVD audit: entitlement gate, decrypt
> CARRY4 airtight, resolution gate honest, the FW command PATCH ENGINE = bounded kernel write
> into cmdBuf — the alloc-vs-patch-bound size consistency is the un-audited candidate; row K
> = VTDecompressionSession SPS-edge dims via videocodecd, design in the report §3).**

**v174 (09-02, current) = ROW K — THE AVD RESOLUTION-GATE EDGES (the audit + the build).**
**v174 RUN VERDICTS (r2 19:41 / r3 19:48 / r4 pending): ZERO AVD DATA YET — three harness bugs,
none kernel. r2 = SIGBUS EXC_ARM_DA_ALIGN@0x47f INSIDE OUR APP (CMBlockBufferCreateWithMemory
Block blockAllocator=NULL -> CFRetain(NULL) in CMBlockBufferAppendMemoryBlock; the v109 out-of-
guard re-raise gave a CLEAN .ips) = died at AV0's sample setup, NO decode reached the daemon.
r3 = every cell died at 'block buffer st=-12702' (kCMBlockBufferBadCustomBlockSourceErr: the
r2-fix custom source had AllocateBlock=NULL) + the NULL-spec session create returned st=0 so the
HW retry never fired = the sessions were LIKELY SOFTWARE (no daemon = a no-op row). r3 evidence
still valuable: VTDecompressionSessionCreate st=0 at ALL dims incl 16896x8192/16768x16768 (the
plugin's resolution checks do NOT gate the session create - the SPS parse is per-frame) + the
epoch counter/journal PERSISTS across reboot (cum=8 carried over - the v141 lesson again).
r4 (shipped): (1) kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder=TRUE -
a SW fallback is now impossible (create FAILS if HW can't take it = the discriminator lever);
(2) AV0 decodes the INTACT captured sample buffer under its own format desc (the r3 'cb ok=0
err=-12909 = kVTVideoDecoderBadDataErr ON THE BASELINE TOO' = my rebuilt avcC+sample never
parsed - the raw decode isolates harness-reconstruction vs daemon-rejection); (3) the borrowed
SPS/PPS pointers COPIED (the r3 AV0 SPS head=00000000 was freed format-desc memory); (4) block
buffer = kCFAllocatorNull (the canonical wrap pattern).
r4 RUN VERDICT (21:11): **AV0 = THE CHANNEL PROVEN - the intact sample decoded ok=1 out=128x128
under a HW-REQUIRE session = the daemon decode path works end-to-end.** AV1-6 ALL failed at
session create with st=-4 (unimpErr) UNIFORM across dims incl 16x16 = NOT the resolution gate =
the craft rejected at the plugin capability table: r4 hardwired profile 66/Baseline + level 62
(the captured stream = profile 100/High level 40) + the PPS said CAVLC while the captured slice
is CABAC. r5 (shipped): profile/compat/level DERIVED from the captured SPS, High-profile grammar
fields inserted after sps_id (chroma_format_idc/bit_depths/qpprime/scaling per H.264 7.3.2.1.1),
PPS entropy_coding_mode=1 (CABAC) = the DIMS are now the only variable.
r5 RUN VERDICT (21:19): identical - AV0 ok=1 out=128x128 (the channel holds) but ALL crafted
cells still st=-4 at create. THE BIT-EXACT ROUND-TRIP (ds_sps_check.py) proved the crafted SPS
parses back PERFECTLY (dims/profile/level exact) = the payloads were never the bug.
**r6 ROOT CAUSE (found by auditing the CONTAINER, not the payload): the hand-built avcC wrote
numOfPictureParameterSets = 0xE1 (= 225 PPS entries - the SPS-count byte's reserved-bit pattern
copy-pasted into the 8-bit PPS-count field) = an INVALID avcC = the format can never parse =
unimpErr(-4) at EVERY create. AV0 always worked because RAW mode uses the ENCODER's avcC.**
r6 (shipped): avcC numPPS = 0x01 + a client-side avcC readback receipt (CMVideoFormatDescription
GetH264ParameterSetAtIndex on MY format: paramSets=2 + spsLen must match = 'container VALID';
free, no daemon op) so this class can never hide again. IPA 238,630 B.
r6 RUN VERDICT (21:30): container VALID on every cell (readback paramSets=2) and the error
CHANGED -4 -> **-12911 = kVTVideoDecoderNotAvailableNowErr** = the decoder EXISTS but refuses
the FORMAT. r6-r7 BINARIES (AVD.videodecoder, plugin text 0x29fe32c28; 24 x movn -12911 sites
in 4 wrapper clusters; the plugin has a LOCAL symbol table): **_AppleAVDWrapperH264Decoder
CanAcceptFormatDescription @0x29ff2d17c = THE session-create gate** - its logic (fully disasm'd):
(1) if (instance->[0x19cc] != 6) reject; (2) if (CFEqual(instance->[0x18], incomingFormat))
ACCEPT immediately (the cache fast-path); (3) w,h = GetDimensions(fmt); if (w != instance->
[0x1458] || h != instance->[0x145c]) reject; (4) getBitDepthsAndChromaFormatFromFormatDesc
must succeed AND match instance->[x23+0..3] (bit-depths/chroma) + [x19+0x190c]; (5) log
'returning %d (0: reject; 1: accept)'. **THE MODEL: the daemon's H264 decoder is a SINGLETON
that pins the FIRST format seen after spawn - every later create must MATCH its stored dims.
AV0 (fresh boot, first create) initializes at 128x128; ALL crafted cells compared against the
stored 128x128 and rejected = -12911 uniform across dims. THE CRAFT WAS NEVER WRONG AFTER r6.**
r7 (shipped): STRUCTURAL fix - every crafted cell now calls ds_tk_kill (the v137 12s daemon
RESET tool) + waits 13s BEFORE the create = each cell is the first create of a fresh daemon
singleton (CanAccept INITIALIZES on our dims instead of comparing). Epoch: 2 ops/crafted cell
(kill + decode) x 6 + AV0 (1) + beats (2) = 15 < 24. IPA 238,776 B. Run: reboot -> row K ALONE
-> console + kernel log (~2.5 min runtime with the respawn waits).
r7 RUN VERDICT (21:45): kills 6/6 CLEAN (es=-12912 each, 13s respawns) but **-12911 PERSISTED
on every crafted cell even as the FIRST create of a fresh daemon** = the r7 'first create
initializes the singleton' model is FALSIFIED - the config CanAccept compares against is
KEXT-SIDE and SURVIVES the daemon kill (AV0's 128x128 decode set it at boot; the respawned
daemon re-queries the kext and still sees 128x128). r8 (shipped): the getBitDepths(H264 variant
@0x29ff2ebe8) disasm proves the PARSE is stateless (scratch ctx -> CreateHeaderBuffer ->
_parseAvcSps) = my payload parses; the reject is the COMPARE gates. **THE MODEL: ONE DIMS PER
KEXT LIFETIME - the first create sets the config, every later create must match it.** r8 =
parameterized one-shot-per-boot: launch args -avdsps WxH / -avdfmt WxH (divergence) /
-avdskip128 (the craft becomes the boot's first create) / -avdnokill. DEFAULT run (no args) =
AV0 baseline + AV1 PAYLOAD DISCRIMINATOR (crafted SPS/PPS at exactly 128x128 after a kill:
dims match the config so ONLY the payload is the variable - accept = the craft is
CanAccept-clean and the frontier is dims-only; reject = the payload still differs). THE
FRONTIER RUNBOOK: one boot per dims point (boot N = -avdskip128 -avdsps 16880x8192, then
8192x16880, 16768x16768, 16x16, 16896x8192, and the divergence -avdsps 16880x8192 -avdfmt
64x64). IPA 239,205 B, markers 1:1, lit-bsln 0.
r8 RUN VERDICT (22:04): **THE PAYLOAD DISCRIMINATOR ACCEPTED - AV1 (crafted avcC+SPS+PPS at
128x128, post-kill) create st=0 under HW-REQUIRE = CanAcceptFormatDescription ACCEPTS the
hand-built format end-to-end.** The decode = err=-12909 BadData (expected: my SPS poc-type-2/
PPS fields vs the slice encoded against the capture's param sets = a slice-header mismatch;
the print's out=128x128 was AV0's stale dims) - and IRRELEVANT to the frontier: the CREATE is
what drives setResolutionInfo/the kext config, the frame need not decode. THE FULL CHAIN IS
PROVEN: crafted SPS -> valid avcC (readback paramSets=2) -> CanAccept accept -> HW session.
**THE ONLY REMAINING GATE = the kext one-config-per-lifetime rule.**
r8.5 (09-02 22:30+, the flags field + the tile discovery): the v175 FLAGS FIELD (UI UITextField
injected via ds_flags_set/value/present in ds_core) works (the runbook runs tap-only now). The
one-shot virgin-boot craft @16880x8192 STILL -12911 = the kext config does NOT start empty.
**r9 BINARIES (VideoToolbox 6.6MB + AVD.videodecoder): (1) VTTileDecompressionSessionCreate IS
A PUBLIC EXPORT and its disasm shows the CLIENT gate = fmul(w,h) vs 0x41d0000000000000 =
w*h > 2^30 pixels -> -12911 (16880x8192 = 138.3M px FITS). (2) the daemon
AppleAVDWrapperH264DecoderStartTileSession (0x29ff2d388) WRITES the config fields CanAccept
compares: str x0,[x19+0x18] (the format - the CFEqual fast-path target) + str x0,[x19+0x1458]
(the dims) + logs 'codecType: AVC, %d x %d, session: %p'. (3) THE MODEL, FINAL: the TILE
pipeline is the config-setter; plain VT creates only consult CanAccept against it; the tile
limits are RUNTIME-QUERYABLE via VTTileDecompressionSessionCopySupportedPropertyDictionary
(exported) + VTTileDecoderSessionSetTileDecodeRequirements +
kVTDecompressionPropertyKey_TileDecoderRequirements / kVTTileDecoderRequirement_MaximumCanvas*
(keys exported). r9 (shipped, IPA 241,381 B): the one-shot cell now runs TILE-FIRST
(VTTileDecompressionSessionCreate at the crafted dims, kept OPEN through the plain create +
decode) + dumps the supported-properties dict = the REAL HW tile limits (the runtime answer to
the hardware-limits question; NO guessed strides/slicing - the user's 5627/64B numbers stay out
until the dict is read). Run: reboot -> flags field '-avdskip128 -avdsps 16880x8192' -> tap K. VERDICT RULES UNCHANGED: AV0 ok+128x128
= the channel works; AV1-6 err=-12909 = the DAEMON's per-frame checks rejecting (pull the kernel
log for AppleAVD lines to confirm the HW path); AV2 accepted = the kext gate did not bite at
session level; any client-fault/timeout = the wild geometry consumed.
**THE AUDIT (Ghidra, /AppleAVD + AVD.videodecoder): (1) the reachability model — AppleAVDUserClient
self-gates at init (IOUserClientEntitlements = com.apple.videotoolbox.hardwarevideodecoder set
PROGRAMMATICALLY, FUN_fffffff0084bdaec) = direct IOServiceOpen(AppleAVD) DEAD for an app; the only
path is videocodecd (VTDecompressionSession -> AVD.videodecoder plugin -> IOConnect; the plugin
imports IOConnectCallStructMethod/AsyncMethod/IOServiceOpen). (2) the UC selector table
(__const 0xfffffff007db06d8, 40B stride): structIn {0x1c8, 0x4, 0xb50, 0x30, 0xb8, 0x4, 0x18,
0x4, 0x10} structOut up to 0xdc8; the session-create request carries width/height at [0]/[1],
codecType [3], timeout-override [0x48], ClientPID [0x58]. (3) THE DECRYPT AXIS IS DEAD:
FUN_fffffff0084c155c checks byteOffset/dataLength/bufSize with an EXPLICIT CARRY4 overflow guard
('Input buffer write will overflow'). (4) THE setResolutionInfo GATE IS HONEST: FUN_fffffff0084beb84
does unsigned max/min - maxDim 0x41f8 (16888) normally / 0x10000 with the unlimited-Resolution
flag, minLim (driver+0x178 < 400) ? 0x2000 : 0x4000; NO signed wrap, NO overflow. (5) driverKernel
TimeoutOverride check accepts wrapped u32 (>= 0xFFFF0000 passes 'exceeds max timeout') - stored
raw to driver+0x3ce4; downstream timer math unaudited (low sev, real inversion). (6) THE PRIZE =
THE FW COMMAND PATCH ENGINE (FUN_fffffff0084c6634 -> FUN_fffffff0084c6bd4): per-frame 0x30-byte
patch records (count < 0x5555556 so count*0x30 < 2^32), each = a kernel bitfield write into the FW
command buffer: offset bounds-checked (CARRY4(offset,2|4) || cmdBufSize < offset+fieldSize ->
reject 'Invalid offset'), field size {2,4} only, value = (resolve(userPtr OR iosid) + addend) &
mask >> truncate (CARRY8-guarded), source resolved via FUN_fffffff0084c6834 (mapType==6 only,
length-checked) from a USER POINTER or IOSURFACE ID. The write is bounded by cmdBufSize = the
ALLOCATION-vs-PATCH-BOUND size consistency is the un-audited candidate (the allocation math chain
FUN_fffffff0084abba8 <- FUN_fffffff00849cc60(state, ctxID, codecType, w, h, ...) needs a re-carve;
Ghidra label collision on 0x849cc60 = a 2-arg context-table helper, the call site 0x8bf29c passes
7 args). ROW K (probe_avd.m, prefix K, cells AV0-AV6, each = 1 daemon decode op + 2 beats = 9
epoch ops): self-captures the corpus (2-frame 128x128 H264 encode via the v77 g_ave_cap_on hook,
AVCC NAL split SPS/PPS/slice) then re-decodes the SAME slice under a REBUILT avcC+format with a
crafted exp-golomb SPS: AV0 baseline 128x128 (captured SPS) -> AV1 ACCEPT-EDGE 16880x8192 (under
maxDim 16888, min AT minLim 8192) -> AV2 GATE-REJECT control 16896x8192 (over by 8 = the kext
'Width or height out of range' receipt) -> AV3 swapped 8192x16880 -> AV4 minLim probe 16768x16768
(min > 8192) -> AV5 below-min 16x16 -> AV6 DIVERGENCE format/dest 64x64 + SPS 16880x8192 (the
plugin's 'video resolution exceeds allocated size' arm). Oracle: dec_out_cb ok/err + OUT-DIMS
(g_dec_out_w/h) vs format = the readback; kernel log grep 'AppleAVD' + setResolutionInfo + 'out
of range' + DART/GART; a decode writing SPS-dims into a 64x64-sized dest = THE OOB WRITE; CLIENT-
FAULT/TIMEOUT/PANIC on any cell = the wild geometry consumed = escalate. Build green, IPA 238,027
B, markers 1:1, lit-bsln 0. Run: reboot -> row K ALONE -> console + kernel log.

> Read this first before working on this repo. It is the accumulated handoff from the
> v10–v29 AVE/VideoToolbox campaign. Companion docs: `FINDINGS.md` (evidence + verdicts),
> `VERSIONS.md` (campaign history), `README.md` (build/run).
>
> **v173 (09-02, current) = ROW J — THE M2-HISTOGRAM SIGNED-OFFSET WRAP (the first statically-proven
gate hole since v164; the R/W proof row).**
**v173 RUN VERDICT (18:54): THE GATE HOLE IS REAL AND CLIENT-REACHABLE — 3/3 IMPOSSIBLE RECTS
ACCEPTED — BUT THE HW HISTOGRAM ENGINE CONTAINS THE WILD RECTS. NO OOB READ, NO OOB WRITE, NO
PANIC. THE R/W CLAIM IS NOT DELIVERED — THE M2 FRONT IS NOW CLOSED AT BOTH LAYERS.**
Cell decode: JH00 GetHistogram standalone = SUCCESS count=128 (the readback oracle + the bin
geometry). JH01 in-bounds {0,0,1920,1080} mode1 = SUCCESS + dst diff 3098251 (executed) + bins
~0x3f44/bin = 2073600 luma px / 128 bins = the REAL luma histogram ACCUMULATING (the feature is
live end-to-end) + A/C clean = the BINS-BASELINE 5f260016ebfd4a30. **JH02 WRAP-X {-16,0,1920,1080}
= kr=SUCCESS — the kext ACCEPTED a rect whose honest math (1920 < 1904) REJECTS = THE VALIDATOR
WRAP CONFIRMED AT THE GATE — but GetHistogram returned ALL-ZERO bins (state resets per transfer:
JH01's 16200/bin replaced by NOTHING) = the HW read ZERO pixels from the outside-starting rect =
clamp/no-op, NOT foreign data.** JH03 WRAP-Y {0,-8,...} = accepted, all-zero bins again = same
containment. JH04 BIG-WRAP {X=-2^28, W=2^28+16} (sum=16) = accepted + bins 0x80-0x81/bin = 128-129
px/bin ~= a REAL in-surface 16-wide column histogram (17280 px / 128 bins = 135) = the HW clamped
X to 0 and programmed W=sum(16) = in-surface. JH05 {X=2000,W=64} = **BadArgument REJECT** (the
validator is the active gate) + JH06 mode-0 = **BadArgument REJECT** (the mode window is live) —
the controls make the JH02-04 accepts mean WRAP and not NO-GATE. Sentinels A/C = 0 on every cell;
dst diff identical 3098251 across JH01-04 (the blit is histogram-independent); daemon beats alive;
no .ips. **READ-OFF RULE CORRECTION for the ledger: the v173 read-off equated 'BINS-HASH != base'
with OOB-witnessed — WRONG for the zero-state case: JH02/03 differ from base by being EMPTY, not
by foreign pixels. The correct witness is bins containing values the in-bounds rect cannot
produce; all-zero = the engine read nothing = containment.** VERDICT: (1) the signed-offset
validation hole is a REAL Apple bug — impossible rects ride validation into the HW program path in
BOTH generations; (2) the DMA containment clamps every one of them (zero-accumulation / W:=sum);
(3) HistogramPixelBins attachment never appears (the bins ride the sel7 state only). The
mode-2-programmable-bins wrap variant is CUT — the containment is upstream of bin modes. The
M2ScalerCSC front is CLOSED: transfer-geometry gate (v166-v172), histogram rect (v173), filter
coeffs and the rest of the sel map bounded. The epoch budget returns to rows A-H (G MACHVM-DRB and
H IOGPU hold the strongest live surfaces; AVD-via-videocodecd setResolutionInfo needs the 1.9MB
AVD.videodecoder RE first). PULL THE KERNEL LOG for the 'Invalid histogram' JH05 receipt (the
validator-fired proof) — it does not change this verdict. The 09-02 Ghidra session (programs: /AppleAVD,
/IOSurfaceAccelerator, /AppleM2ScalerCSCDriver, /com.apple.AGXG17P, /com.apple.iokit.IOGPUFamily;
chained-fixup decoder: kext const ptr VA = 0xfffffff007000000 + (raw & 0xffffffff)) found THE
VALIDATION HOLE in BOTH M2ScalerCSC filter generations: **the histogram rect gate reads the client
HistogramOffsetX/Y as SIGNED int and tests `Bw < (u32)(Hx+Hw) || Bh < (u32)(Hy+Hh)` against the
REAL surface dims — a negative offset WRAPS the 32-bit sum and PASSES** ({-16, W=1920} -> 1904 <
1920 = accepted, HW rect starts 16px BEFORE the surface base): IosaColorManagerMSR4.cpp:246 (26.6,
FUN_fffffff008db70f8) AND IosaColorManagerMSR23.cpp:874 (26.6.1-new, FUN_fffffff008dc0ec4) share
the bug; Bw/Bh come from the real surface descriptor (src block dims), Hw/Hh from ctx+0xbe0/be4,
Hx/Hy from ctx+0xbd8/bdc; the HistDim!=DstDim case only SETS ctx+0x1fd5 (flag, NOT reject). Bins
are client-readable: sel7 GetHistogram(acc, buf) (buf[0]=count from the registry prop, bins land
wired at buf+4, R/G/B slot ptrs written at buf+0x608..) AND the kIOSurfaceAcceleratorHistogramPixelBins
dst attachment. The kext's OWN testHistogram (FUN_fffffff008db94a0) drives the identical client
path with the same 5 option keys (HistogramBinMode/OffsetX/OffsetY/Width/Height — mode MUST be 1|2,
the (mode-1U)<2 window) = LIVE code, not dead. IOSA sel-map CLOSED (v166's sel0 "stub" explained:
CaptureSurface=sel0 0x40-struct has NO user_capture kext handler = paravirt/guest-only, dead on HW;
AbortTransfers=sel2 scalar, AbortCaptures=sel3 scalar, SetCustomFilter=sel4 0x20-struct ->
user_set_filter, GetHistogram=sel7, GetTransformEstimation=sel9 0x10-struct; Transfer/WithSwap/
Blit/Conditional all = sel1 via convertToTransform). ROW J (probe_iosa_hist.m, prefix J, cells
JH00-JH06, all direct-UC wrapper calls = ZERO daemon epoch, fresh src 1080p POSITION-GRADIENT +
dst 0x41 + A/C sentinels): JH01 in-bounds {0,0,1920,1080} control = the BINS-HASH baseline ->
JH02 WRAP-X {-16,0,1920,1080} (u32 sum 1904<1920 = validate PASSES) -> JH03 WRAP-Y {0,-8,...}
(1072<1080) -> JH04 BIG-WRAP {X=-2^28, W=2^28+16} (sum=16 = the HW-field truncation probe) ->
JH05 OOB control {X=2000,W=64} (2064>1920 = must REJECT + the kext 'Invalid histogram' log line)
-> JH06 mode-0 control (fails the mode window = must REJECT) + 2 beats. VERDICT RULES: JH02-04
kr=SUCCESS with BINS-HASH != JH01 base = pixels OUTSIDE the in-bounds set accumulated = **THE OOB
DMA READ WITNESSED**; A/C sentinel diffs >0 = THE OOB WRITE = THE 64747; BINS-HASH == base = the
wrap passed validate but the HW clamped (field-truncation defense — the kernel log decides);
JH05/JH06 rejections are what make the JH02-04 passes mean WRAP and not NO-GATE; TIMEOUT/PANIC on
any JH cell = the HW consumed a wild rect = escalate. PULL THE KERNEL LOG: grep 'Invalid histogram'
+ 'histogramRequest' + 'validateHistogram'. **AVD gate cracked this session: AppleAVDUserClient
sets IOUserClientEntitlements = com.apple.videotoolbox.hardwarevideodecoder PROGRAMMATICALLY at
init (FUN_fffffff0084bdaec) — direct IOServiceOpen(AppleAVD) is kernel-gated for any app; the UC
selector table (__const 0xfffffff007db06d8, 40-byte stride, 9+ sels) carries structIn up to 0xb50 /
structOut up to 0xdc8 = the 64747-class channel behind videocodecd only. METHOD LESSON: 'no
entitlement strings in the kext binary' != ungated (the AVD gate is set in CODE; personality plists
live in the kernelcache, not the carved kexts).** Row J built green, IPA 232,460 B, markers 1:1,
lit-bsln 0. Run: reboot -> row J ALONE -> console + kernel log.

**v172 (09-02) = ROW I v172 — THE SHAPE + THE HEIGHT-FLIP (100% R/W). T1 = CLOSED.**
**v172 RUN VERDICT (16:31): M2S0 = REAL-FED — the struct declared dst=1920x32 into a
REAL 1080p dst and the HW wrote the FULL surface (3110400 bytes, rows~1619 = real);
the declared dims are INERT, the kext validates AND the HW programs the REAL surfaces
(the mismatch axis DEAD; S0b control consistent). M2S1/S2 = H 32 -> 32 (set=0) -
IOSurfaceSetValue cannot mutate geometry (the SDK-header warning confirmed by
readback) = the height-flip DEAD. **T1 FINAL VERDICT (the campaign tally, all 100%
R/W-measured): the Apple-documented 'can corrupt memory' config (destH<=32 +
srcW>128 + planes>1) is NOT client-reachable on 26.6. The gate lives at the
IOSurfaceAcceleratorClient UC layer, reads the REAL surface dims, and is enforced
across every axis probed: the executing paths (wrapper/raw sel1, modes 0/1/2), 14
flag bits, 5 format families + mixed-plane pairs (the format table Unsupported), the
BorderFill rect (fill geometry only), the struct-vs-surface mismatch (a consistency
check rejects declared-big/real-small and the HW is real-fed), the post-create
height flip (immutable), WithSwap (queues, never flushes), the UAF race (the ring
is refcounted), and KernelTests (0xe00002e2 stubbed). THE PROVEN CAPITAL: a
sandboxed app opens IOSurfaceAcceleratorClient + IOServiceOpen(AppleM2ScalerCSCDriver)
with no daemon and no entitlements and drives REAL HW DMA byte-proven (the sandbox
static-verdict FALSIFIED - the follow-on surface for the row-H-class work), plus the
full userspace/kext call map (sel1 struct 0x1b0, the option block, the HAL
Hal.cpp:10153 rejection site, the gate = real-dims-fed). RECOMMENDATION: CUT row I -
every remaining bypass needs a kernel write to reach a kernel write (circular). The
epoch budget belongs to rows A-H.**
**v171 RUN VERDICT (16:03): the BorderFill rect is FILL geometry — M2R0 (baseline)
EXECUTED (dst 3110400 bytes, A/C=0 = the R/W witness live) and M2R1-R4 (wrapper
BorderFill {0,0,1920,32}/{0,0,1920,16}/{0,1048,1920,32} + RAW sel1 rect shorts) ALL
EXECUTED the FULL 1080p dst with A/C=0 = the rect does NOT become the effective dest;
M2R5 (+0x10000000 group bit) = Unsupported (a different path). The rect axis closes.
v172 = the last two R/W-provable vectors, every verdict by readback: **M2S0/S0b = the
WRITE-SHAPE oracle** (raw sel1 struct dst=1920x32 into a REAL 1080p dst — the B-diff
ROW RANGE proves what the HW programs from: rows~32 = STRUCT-FED (the gate validates
the REAL surfaces while the HW writes the DECLARED dims = the mismatch axis live) vs
rows~1080 = REAL-FED (declared dims inert); S0b = the all-rows control) + **M2S1/S2 =
THE HEIGHT-FLIP** (create a legal 1920x32 IOSurface (small alloc) ->
IOSurfaceSetValue(kIOSurfaceHeight, 1080/2048) — NOTE: the SDK header says SetValue
"can not be used to change the underlying surface properties" and returns VOID; the
H readback proves the flip either way — if the surface REPORTS the new H while the
alloc stays 32 rows, the gate PASSES on the reported dims and the HW writes the new-H
rows into the 32-row buffer = the OOB, sentinels A/C both sides; H immutable = the
flip is dead and the R/W axis list is exhausted). M2B2 + M201 + beats. A PANIC on any
cell = THE 64747 WRITE. IPA 226,640 B, markers 1:1, lit-bsln 0.
**v172 RE-RUN VERDICT (16:33): BYTE-IDENTICAL to 16:31 - S0 REAL-FED (the full
3110400-byte write with the struct declaring 32 rows), S0b consistent, S1/S2
H 32->32 immutable, all gate rejections deterministic, M201 ACCEPT, beats alive =
the T1 closure is REPRODUCED 2/2 with deterministic readbacks. Row I is FINAL.**
>
> **v171 (09-02) = ROW I v171 — THE RECT-GEOMETRY ROUND (100% R/W).**
**v170 RUN VERDICT (15:41): the MODE WORD DOES NOT GATE — M2X8a-f all BadArgument at
+0x2c in {0,1,2,3,0xff} (+w28=1 too) on the honest corruption cfg, but M2X8g (mode 2 +
SAME-SIZE) = SUCCESS + EXECUTED (dst 3110400 bytes diffed) = mode 2 is a live transform
type and the corruption-geometry gate is MODE-INDEPENDENT. The format-plane matrix:
M2X7a/b (BGRA<->420v pairs) + X7e (420f) = BadArgument (the same gate), X7c/d (2vuy
mixed-plane) = Unsupported 0xe00002c7 = the format table rejects before the gate. THE
REMAINING AXIS: the option-block RECT at struct+0xcc..0xd2 — FOUR shorts written by
prepare from a chained 4-key option read (flag 0x2000000000000 = all-four-present) =
the BorderFill X/Y/Width/Height quartet (kIOSurfaceAcceleratorBorderFill* exported from
libIOSurface). If the HW's EFFECTIVE dest geometry comes from the rect while the gate
reads the surface dims, a 1080p dst (gate PASSES) with a 32-high rect = the bug
geometry BEHIND the gate. v171 = 100% R/W-PROVEN cells (EVERY cell = src fill 0x42 ->
dst 1920x1080 + sentinels A/C 1920x32 fill 0x41, +1.5s diff = execution proven by
READBACK only, no error-code verdicts): **M2R0 baseline no-opts** (the witness sanity:
must EXECUTE 3110400) + **M2R1/R2 wrapper BorderFill opts {0,0,1920,32}/{0,0,1920,16}**
+ **M2R3 {0,1048,1920,32} (the bottom edge - a spill crosses into C)** + **M2R4/R5 RAW
sel1 rect shorts** (flags 0x2000|0x2000000000000 [+0x10000000]) + M2B2 + M201 canary +
beats. A PANIC on any cell = THE 64747 WRITE. IPA 226,342 B, markers 1:1, lit-bsln 0.
>
> **v170 (09-02) = ROW I v170 — THE MODE-WORD + THE FORMAT MATRIX.**
**v169 RUN VERDICT (23:41): THE DIRECT PATH EXECUTES REAL HW DMA — M2X1/X2 (the
execution oracles: same-size 1080p src fill 0x42 -> dst fill 0x41, diff at +2s) diffed
THE ENTIRE dst (3110400 bytes, first=0 last=3110399) on BOTH the wrapper TransferSurface
AND the raw sel1 = a sandboxed app drives the AppleM2ScalerCSC HW in-app with ZERO
daemon, ZERO entitlements, byte-PROVEN. The v168 WithSwap no-op was NOT a read race —
M2X3 (delayed witness +2s) and M2X4 (+AbortTransfers = Unsupported stub) still saw
NOTHING = WithSwap queues and never flushes (the commit is external); M2X5 (the 14-bit
flags sweep) = NO flag bypasses the gate; M2X6 x4 (the Gemini UAF race) = NO stale
writes = the kext retains/cancels the surface refs (the ring is refcounted). THE NEW
CRACK: the wrapper's struct carries w22 in {0,1,2} at **struct+0x2c** (the transform
TYPE — transformSurface stores it at sp+0x94 = struct+0x2c; +0x28 = another word from
GetServiceObject-ish) — the gate-rejecting D2 rode mode 1, our raw K-cells rode mode 0,
and the cell 'honest corruption config + flags 0x2000 + mode 0' was NEVER fired. v170
cells: **M2X8a-d = the mode-word fuzz** (+0x2c 0/2/3/0xff on the honest corruption cfg
1920x1080 -> 1920x32, each with a dst-diff execution witness) + M2X8e (mode 1 control =
expect the D2 reject) + M2X8f (mode 0 + word28=1 = the co-feeds-gate test) + M2X8g
(mode 2 same-size = does mode 2 execute?) + **M2X7a-e = the format-plane matrix** on
the executing path (src BGRA/2vuy/420v x dst 420v/BGRA/2vuy/420f at h32 = the
planes-arm ambiguity: if the gate counts only ONE surface's planes, a mixed-plane
combo at h32 EXECUTES the bug). A PANIC on any cell = THE 64747 WRITE. IPA 224,987 B,
markers 1:1, lit-bsln 0.
>
> **v169 (09-01) = ROW I v169 — THE ASYNC ROUND + THE UAF RACE.**
**v168 RUN VERDICT (23:20): the WithSwap SUCCESS is a QUEUED NO-OP — M2C1 read +0ms saw
ZERO byte changes on A/B/C (the dst was NEVER written: B stayed 0x41) and W1-W4 accepted
EVERYTHING (h16/4K/h2/BGRA-planes=1) at t=0ms = the accept-anything queue; K2b (0x1000 +
honest corruption cfg) and K1b (0x1000 + lie-big) both BadArgument = the flags-bit theory
is DEAD (the gate + the consistency check are bit-independent). The async/ring-buffer
model (FrameDescriptorRingMSR23, Gemini's hypothesis) is the LIVE hypothesis: the call
only ENQUEUES the descriptor; the HW DMA fires on a flush/commit we have not pulled
yet; the v168 witness raced the DMA at +0ms. v169 = the ASYNC ROUND (all direct, zero
epoch): **M2X1/X2 = the EXECUTION ORACLES** (same-size 1080p src fill 0x42 -> dst fill
0x41, DIFF AT +2s — dst flips to 0x42 = the path EXECUTES (async confirmed); dst stays
= queued-never-flushed, the commit trigger is the missing piece) + **M2X3 = the DELAYED
corruption witness** (+2s, sentinels kept alive: A/C diffs = THE OOB WRITE PROVEN) +
**M2X4 = WithSwap + IOSurfaceAcceleratorAbortTransfers** (the flush arm: changes after
the abort = the abort FLUSHES the queue = the trigger) + **M2X5 = the flags-bit sweep**
(14 bits x raw sel1 honest corruption cfg — any SUCCESS = the gate-skip flag -> refire
the witness) + **M2X6 x4 = THE GEMINI UAF RACE** (WithSwap corruption cfg -> CFRelease
(dst) INSTANTLY while the ring holds the descriptor -> churn 4 same-size surfaces ->
scan them + the sentinels: a stale DMA write into a REUSED surface is OBSERVABLE
without a panic (the STALE-DMA receipt); a PANIC there = THE 64747 WRITE; nothing = the
kext retains/cancels the surface refs on free). M201 canary + beats. Run after a
reboot, ALONE; paste console + kernel log (grep IOSA + the X-cell stamps). IPA 228,087 B,
markers 1:1, lit-bsln 0.
>
> **v168 (09-01) = ROW I v168 — THE WITNESS + THE 0x1000 BIT.**
**v167 RUN VERDICT (23:11): M2D3 TransferSurfaceWithSwap 1080p->h32 = SUCCESS — THE
CORRUPTION CONFIG RODE AND EXECUTED on the WithSwap path (no daemon, no entitlements!)
while D2 (Transfer) / D4 (Transform) / K1/K3 (lie-big raw) = BadArgument and K2
(declared-tiny, real-big) = SUCCESS with the gate NOT firing on its declared dims. THE
MODEL: (1) the corruption-geometry gate fires on CONSISTENT (struct==real) transfers
WITHOUT flags-bit 0x1000 (prepare sets 0x1000 when the entry's mode param is even —
WithSwap rides it, Transfer passes 1); (2) a separate consistency check rejects
declared-big/real-small (K1/K3) but accepts declared-small/real-big (K2). M2K0/b/c all
SUCCESS at flags {0x2000,0x3000,0x12000} = the hand-crafted 0x1b0 struct builder is
VALID and the honest-same-size config is flags-agnostic. kernel.rtf (23:11) = ZERO
[IOSA] lines (successes are silent; the canary's daemon rode CPU from start = the HW
decision is cached per daemon lifetime). M2F1 still NULL (IOSurfaceCreate with
AllocSize rejected). v168 cells: **M2C1 THE CORRUPTION WITNESS** (sentinel surfaces
A/B/C 1920x32 420v back-to-back around the tiny dst, fill 0x41, WithSwap 1080p->B,
diff vs 0x41 — A/C diffs>0 = THE OOB WRITE PROVEN with the first/last-offset shape)
+ M2K2b (raw struct flags=0x12000 + honest corruption config = the bit theory via the
raw path) + M2K1b (raw struct 0x12000 + lie-big = does 0x1000 ALSO skip the consistency
check = the declared-big/real-small OOB arm) + M2W1/W2/W3/W4 (WithSwap h16 / 4K / h2 /
BGRA-planes=1 = the accepted path generalizes?). A PANIC on any cell = THE 64747 WRITE.
IPA 225,897 B, markers 1:1, lit-bsln 0.
**v166 RUN VERDICT (22:59): T1 ANSWERED — the corruption config is CLIENT-REACHABLE and
GEOMETRY-GATED at the kext UC client layer. M2D1 Xfer SAME-SIZE 1080p = SUCCESS (a
sandboxed app drives the M2ScalerCSC HW in-app, no daemon, no entitlements!) + M2H1 tiny
64x64 = SUCCESS + M2E1/E2 Estimation = SUCCESS for BOTH geometries (the userspace prepare
layer is CLEAN even for the corruption geometry) — while M2D2/G1/D8 (destH<=32 + srcW>128
+ planes>1) = BadArgument with ZERO [IOSA] kernel lines = the kext UC CLIENT layer rejects
BEFORE the HAL (the daemon canary's 3 attempts at 22:59:43.501-503 still die at
Hal.cpp:10153 — the ONLY [IOSA] lines in the log). M2G1 BindAccel = SUCCESS but a NO-OP
(needs=0/0) and does not change the rejection; KernelTests = 0xe00002e2 Unsupported (sel6
stubbed on 26.6); GetDiag('kDiP') = SUCCESS (sparse: +0x00=0x6b, +0x20=0x01, +0x40=0x04,
no [iosaDiag] log); M2B2 sel-map = sel0 Unsupported (stub) + sel1-sel10 BadArgument-on-
zeros (all live) + sel11 SUCCESS 648B out (the client config dump: +0x00=0x16, +0x20=0x01,
+0x40=0x04); M2F1 IOSurfaceCreate pair came back NULL (AllocSize prop rejected - v167
fixes to BytesPerElement). **THE STRUCT: transformSurface passes the 0x1e0 prepare
DESCRIPTOR itself as the sel1 struct (inCnt=0x1b0) — layout: +0x00 srcID +0x04 dstID
(u32, IOSurfaceGetID), +0x20 flags (u64; 0x2000 = no-options, plane-class<<15, 0x1000 =
async-est bit), +0x48 srcW +0x4c srcH (GetWidth 08b0 / GetHeight 0890), +0x70 dstW +0x74
dstH.** v167 = the RAW sel1 cells (IOConnectCallStructMethod on a fresh direct conn, the
userspace wrapper BYPASSED): M2K0/K0b/K0c honest same-size with the flags sweep
{0x2000,0x3000,0x12000} = validates the hand-crafted builder + pins the flags; **M2K1/K3
= LIE-BIG (struct declares dst=1920x1080, the REAL dst surface is 1920x32/1920x16) = if
the gate reads the struct and the HW programs from the struct = the 1080-row write into a
32/16-row surface = THE 64747 OOB WRITE**; M2K2 = declared-tiny control (struct dst=32,
real dst 1080p — the gate-vs-struct check); M2D3/D4 = WithSwap/Transform entry paths on
the corruption geometry (gate-sharing check). A PANIC/TIMEOUT on M2K1/K3 = THE 64747
WRITE. IPA 224,237 B, markers 1:1, lit-bsln 0.
>
> **v167 (09-01) = ROW I v167 — THE RAW sel1 STRUCT + THE LIE-BIG OOB SHOT.**
>
> **v166 (09-01) = ROW I v166 — THE G-ARMS (BIND/DIAG/KTESTS) + THE G10 FIX.**
**v165 RUN VERDICT (21:54): the DIRECT calls REACHED THE KEXT — 27 [IOSA] lines (9 HAL
attempts, 3 lines each: Hal.cpp:10153 0xe00002c2 + Driver:3235/3267) on our in-app
TransferSurfaces = the SAME rejection the daemon's transfer got (the rejection layer is
HAL-program-load, common to BOTH paths; it is NOT surface-lookup — the full client->
driver->HAL chain runs for our calls). The app then DIED at 21:54:57
(DirtySlide-215457.ips: SIGBUS in ds_m2_direct_cell -> __NSDictionaryM setObject ->
cold realizeClass = the G10 class) — v165 passed &CFStringRef (the dlsym'd export IS a
CFStringRef VARIABLE) as the dict key in M2D8's opts build = a bogus 'object' key ->
CFRetain -> objc retain -> realizeClass on garbage isa. The crash was OUTSIDE the guard
(dict build precedes the transfer guard) and killed the run before M2B2/M201.** RE
additions this round: libIOSurface exports **IOSurfaceBindAccel(surface, w1, w2) /
IOSurfaceNeedsBindAccel / IOSurfaceClientBindAccel** (the bind = IOConnect sel 0xc on
IOSurfaceRoot with {surfID, w1, w2}, skipped when the surface's bind-state halfword is 0)
= the surface->accelerator registry step; the IOSurfaceAccelerator fw exports
**IOSurfaceAcceleratorGetDiag(acc, int* cookie)** (cookie must be 'kDiP' 0x6944506b; then
IOConnect sel 8 with the 8-byte cookie struct = the driver diagnostic dump, [iosaDiag]
kernel-log lines) and **IOSurfaceAcceleratorKernelTests(acc, uint32* buf)** (*buf must be
<= 1000; then IOConnect sel 6 with a 0xfa8=4008-byte struct = the kext SELF-TEST) and
IOSurfaceAcceleratorSetProperty(acc, dict) = kext sel10 {kind=2, 50000, 500000} (ALREADY
called by Create — not the missing step). v166 cells: M2E1/E2 estimation discriminators +
M2D1/D2 xfer control/corruption-config + M2H1 tiny 64x64 floor + **M2G1 NeedsBindAccel/
BindAccel(0,0) both surfaces + xfer** + **M2G2 GetDiag** + **M2G3 KernelTests** (HW health
WITHOUT surfaces: SUCCESS = the scaler core is fine and the rejection is per-transfer
state; FAIL = the core rejects everything on 26.6) + M2F1 raw+chroma (deref-fixed) +
M2D8 opts (deref-fixed, re-armed) + M2B2 selmap + M201 canary. THE G10 FIX: ds_m2_cfstr()
= dlsym -> DEREF -> CFGetTypeID-validate. ZERO daemon epoch except M201. IPA 222,689 B,
markers 1:1, lit-bsln 0.
>
> **v165 (09-01) = ROW I v165 — THE DIRECT-UC MATRIX + THE SANDBOX FALSIFICATION.**
**v164 RUN VERDICT (20:54): M2A IOSurfaceAcceleratorCreate returned a LIVE acc=0x11615de30
AND M2B IOServiceOpen(AppleM2ScalerCSCDriver) OPEN conn=0x9d13 FROM THE APP = the static
sandbox verdict (kc blob @0xa469cb) is FALSIFIED — IOSurfaceAcceleratorClient is directly
openable from a standard container.** The 10-cell daemon matrix all ACCEPTed clean (CPU
blitter fallback) and the kernel log caught the ONE HW attempt: `[IOSA][ERROR][HAL]
[AppleM2ScalerCSCHal.cpp:10153] failed with result: 0xe00002c2` + Driver:3235/3267 = the
kext HAL rejected the FIRST daemon transfer (M2C0) and VT silently fell back to CPU
blitters for the whole epoch (explains why every campaign transfer ever rode vt_Copy,
never the HW scaler). Our direct M2A xfer BadArgument produced NO [IOSA] line = it died
BEFORE the kext. **USERSPACE RE (IOSurfaceAccelerator.framework, 97KB, extracted from the
23G71 cache + Ghidra): IOSurfaceAcceleratorTransferSurface(acc,src,dst,opts) ->
convertToTransform -> prepareTransformBuffersAndOptions(src,dst,opts,1,desc 0x1e0B) ->
transformSurface -> IOConnectCallStructMethod(acc+0x24, sel=1, struct 0x1b0) = the kext
sel1 ASYNC-TRANSFER entry (kext FUN_008dbc7d8: struct_size==0x1b0 -> FUN_008dbc298 ->
request{this[0x23], srcID=struct+8, dstID=struct+0x10, this[0x25]} -> submit -> HW
program); prepare() BadArgument sites = NULL args + the DST kIOSurfaceChromaLocationTopField
attachment NOT matching one of 7 kIOSurfaceChromaLocation_* strings + option-parse rejects
(libIOSurfaceAccelerator imports IOSurfaceCopyValue + ONLY kIOSurfaceChromaLocationTopField
as a key). v165 fires the DIRECT-UC EMPIRICAL MATRIX (all in-app, guarded 6s, ZERO daemon
epoch): M2E1/M2E2 GetTransformEstimation (the PURE-USERSPACE can-transform probe = the
LAYER DISCRIMINATOR: Est-fail = prepare/attr parse; Est-ok + Xfer-fail = the kext
registry/bind layer) + M2D1 Xfer same-size control + M2D2 Xfer 1080p->h32 THE CORRUPTION
CONFIG + M2D3 WithSwap / M2D4 Transform (8-arg shapes) / M2D5 xform control / M2D6 Blit /
M2D7 Conditional / M2D8 opts{ForceMaxSpeed,LockInScaler,UseNearestFilter} + M2F1 RAW
IOSurfaceCreate pair + chroma attachment on both (the attr-parse discriminator) + M2B2
direct-conn 12-selector scalar map (sel5 struct1 + sel11 struct0x288 out-dump) + M201
daemon canary + MH beats. Census fixed (bases printed WHILE LOCKED — v164 printed
post-unlock 0x0). A PANIC on any direct cell = THE 64747 WRITE WITH NO DAEMON PROXY.
IPA 219,995 B, markers 1:1, lit-bsln 0.
>
> **v164 (09-01) = ROW I: M2SCALER-CSC T1 — THE CORRUPT-MEMORY GEOMETRY.** probe_m2scaler.m fires the 23G83 AppleM2ScalerCSCDriver RE lead (Target 1, T1 = PARTIAL:
the UC dispatch is HARDENED — IOSurfaceAcceleratorClient, 12 sels x 0x30, max struct 0x288
exact-size bounded memcpy, NO kIOUCVariableStructureSize, NO IOUserClientEntitlements — the
surface is NOT a direct UC primitive): an Apple-documented HW MEMORY-CORRUPTION failure
mode gated ONLY by geometry — `This version of hardware can corrupt memory with dest
height=%u, source width=%u, planes=%u` @0xfffffff00754e90a + `Failure mode: dest height
<= 32, source width > 128, planes > 1` @0x754e967. HYPOTHESIS: the corruption config rides
the videocodecd pixel-transfer proxy (VTCompressionSession scale big->tiny on a multi-plane
IOSurface; the daemon sandbox ALLOWS IOSurfaceAcceleratorClient per kc blob @0xab5f03,
the app container does NOT @0xa469cb) and a filter path (MSR23BackwardsCompatibleFilter,
ctor sites 0x8d910b4/0x8d911e8/0x8d92018) SKIPS the gate -> DMA OOB = PANIC = THE 64747
write. Cells: M2A (in-app dlsym IOSurfaceAcceleratorCreate/TransferSurface direct oracle,
ZERO epoch) + M2B (IOServiceOpen AppleM2ScalerCSCDriver sandbox oracle, ZERO epoch) +
M2C0 control (1080p->1080p) + **M201 THE EXACT CORRUPTION CONFIG** (1920x1080 IOSURF 420v
planes=2 -> 1920x32 session = destH<=32 + srcW>128 + planes>1 ALL THREE ARMS) + M202 h48 /
M205 w128 / M206 BGRA-planes1 (each ONE arm outside = the geometry-addressing proof) +
M203 h16 (deep) + M204 w144 (smallest armed) + M207 420f / M208 2vuy (format-table paths)
+ M209 4K src (max DMA distance) + MH beats. ALL inputs IOSURF-backed (the v72/v73 lesson:
byte-backed biplanar = the NULL-plane killer class is FORBIDDEN here; the pbCensus line
prints planes+bases per cell so any NULL-plane death downstream is NOT our construction).
ORACLE: pull the KERNEL LOG and grep `can corrupt memory` (a line there = the check FIRED
with our exact geometry = the corruption config is CLIENT-REACHABLE and gated = T1
partial -> next hunt the gate-skipping filter path); SILENCE + PANIC/corruption = a path
SKIPPED the gate = THE 64747 WRITE; all-ACCEPT + silence = the transfer rode CPU blitters
(the HW selection lever needs the next run). 10 daemon cells + 2 beats = 12 epoch ops;
direct cells free. Run after a reboot, ALONE. IPA 218,615 B, markers 1:1, lit-bsln 0.
>
> **v142 (08-24, current) = THE 26.6 RE-BASELINE + THE A-D REGROUP.** The device is
**iOS 26.6 (23G71)** (downgraded from 27b1 24A5355q; 26.6 released 07-27). The 08-24
v141 IK run on 26.6 fired the X5 kill **7/7 with byte-identical .ips class**
(`-[__NSCFString containsKey:]` <- AVE_CFDict_GetSInt32+72 <- AVE_Ref_RetrieveArray+176
<- AVE_GetPerFrameData+3732) = **the kill factory is LIVE ON SHIPPING 26.6**. The
26.6 reports are FULLY SYMBOLICATED and the plugin is RENAMED: ave.videoencoder ->
**H264H9.videoencoder** (1,404 symbols - the campaign's hand-RE'd names confirmed
verbatim by Apple's own symbolication). The 4-agent 26.6 RE sweep (extraction at
/Users/pauyedin/23G71__iPhone17,5/) delivered: **A** the kill factory (10 unconditional
CFNumberGetValue keys in AVE_GetPerFrameData @0x2a05881d0 incl NEW POCLsb/
CalculateYUVChecksum/MarkCurrentFrameAsLTR + UserQpMap no-type-check @0x8948 + SetDPB
bare CFArrayGetCount @0x2a05a1f54 + ReferenceL0 element-conf); **B** the multipass
mode==1 unchecked memmove(stats, blob, 1574) @0x2a060e99c (short-blob heap OOB read);
**C** the kernel paths (QP-map byte-identical, -13 gate, 130560 still; ungated Prepare
fields SHRUNK to MCTFEdgeCount/FilterGroupSize/AmbientViewingEnvironment; userDPB
2..17; USL wedge intact; iaPSData check now int32-cast = signed-wrap candidate);
**D** the new surfaces (tile encoder, 21-key DPB_* per-frame family, FirstMbInRecvSlices,
HEVC H9 NaluType/TemporalID + MCTFParams, vt_Copy blitters STILL guard-free).
**FIXED ON 26.6**: MCTFStrengthLevel count-driven OOB loop (2-iter unrolled),
VTMultiPassStorageClose stack overflow (heap-chunked). **43805 ORACLE RENAMED**:
Client_Die 2413->2333, StopClient:2302 -> CheckStopped:2379/CleanClient:2445 (the
flood row is CUT; grep manually if needed). SPTM/TXM recon = NOT app-reachable
(zero smc, dispatch-domain validation, ~224 VIOLATION_ invariants) - the viral
"14 SPTM vulns" X post has zero corroboration. v142 rows: A T-KILL (14 kills) /
B OOB-PRIMITIVE / C KERNEL-QP / D NEW-SURFACES / E escape / F MG spoof; CUT
mediaremoted + the 43805 flood; logs leaned (silent epoch, 2-line beats, short
banners/read-offs). IPA 216,951 B, markers 1:1.

**v132 (08-12) = FIELD+SPARSE SWEEP (current) — the RE-driven map dissection.** The v131 run
> (08:52) + kernel log FALSIFIED the v130 "threshold=51" and "odd-width walk leak" models:
> (1) **THE MAP IS A 1-BIT-PER-MB FLAG** — the v131 T-cells broke 51 (0x31=49 fired +455,
> 0x34=52/0x40=64 flat): collapse ALL v129-v131 fills by LSB = every ODD fill fires
> (+448..+455), every EVEN fill is inert (+0..+9) = the kernel consumes **byte-0-LSB of each
> 16-byte entry as a per-MB "QP-mod present" flag** (the "51" read was sampling coincidence);
> the per-MB cost is a constant **0.446 bits/MB** (M3: 8160x0.446=455; D3M: 32400x0.430=1740);
> (2) **THE D1M "ODD-WIDTH LEAK" IS A FRAME-CONTENT ARTIFACT** — the kernel log PROVES the
> client dims 1921x1081/1922x1080/1936x1080 ALL normalize to the SAME kernel grid
> 1936x1088 (121x68 MBs): no kernel-side walk difference exists; the D1A anchor was 943 B
> (odd-dims frame) vs 574 B (even) = the collapse is skip-structure of the odd frame, not a
> kernel walk bug; (3) **X5's kernel witness**: ID 170 opens 1920x1088 Input 0/0 + AVE WARN
> EnableUserQPMap + instant close. **DRIVER/BINARY/KERNELCACHE RE (v132):** daemon
> PrepareMBInputCtrl @0x2b9558870 = memcpy(GetAddr(surface), userQpMap, w19) with w19
> size-gated to CalcBufSizeOfMBInputCtrl(**SESSION** dims @drv+0x134/0x138) = exact-size into
> the same-sized DART surface = NO overflow daemon-side; kernel saMBInputCtrl[i].iAddr
> checks = kernel-ASSIGNED field validation (log-only sites, no deref of our bytes) = the
> channel is closed for OOB at BOTH ends as shipped. v132 = 15 shots: C0/M3a/M3 +
> **E0/E1/E4/E8** (fill high byte = field-isolation: byte0/1/4/8 = which 16-byte field the
> kernel reads) + **V0/V1/V2** (flag@0 + hostile 32-bit word in bytes1-4: 0x7FFFFFFF /
> 0x80000000 / 0xFFFFFFFF — distinct after the 4-byte fix) + **S0-S3** (sparse density:
> MB0 / last MB / row-0 / checkerboard = the delta must scale with the flagged-MB COUNT =
> position-addressability) + X5 kill LAST. CUT (dead/answered): T7-T9 (parity answered),
> D1/D5/D6 pairs (kernel normalizes all to 1936x1088 = artifact), D3A-M (4K answered),
> ES09+mode 9 (opendir errno=1 even with the extension = dead). THE OOB SetDPB dead path
> (sdpb = xKey-200) is CUT — the V-cell xKeys (0x7FFFFFFF) would index sVal[]/sCnt[] at 2.1
> billion = the v56 OOM class. VERDICT the run decides: E1/E4/E8 EFFECT = a 2nd consumed
> field (NEW surface); V-row B != M3 = the value word reaches the stream (clamp bypass);
> S3-delta ~ half M3 + S0/S1 near-zero = the kernel walks OUR positions.
> **v133 (08-12, current) = VALUE+POSITION SWEEP — THE SINT32 WINDOW + LAMBDA-INDEX OOB SHOT:**
> the v132 run (09:51) + RE CRACKED the entry: **SInt32@0 LE, bit-0 = enable, bytes 0-3 =
> the value window** (V1==E0 byte-exact at 1031, byte-4 outside; E1/E4/E8 were CONFOUNDED -
> SInt32@0 was 0/even in all three = parity, NOT field) and **negatives ESCAPE the clamp**
> (-1/-255 -> 1017 vs +1 -> 1031 = the signed path feeds FW lambda/RC math; per-H.264
> lambda = 0.85*2^((QP-12)/3) = a negative QP = a negative lambda-table index = the OOB
> read candidate). Position-addressability confirmed (S3 1226 vs S0 596 vs 569). v133 =
> the CLEAN value axis via pk==10 (full 32-bit LE word @bytes 0-3 every MB): W1 +1 / W2 +3
> / W3 +51 (TRUE 51, never fired clean) / W4 +127 / W5 +0x7FFF / **W6 +INTMAX** / W8 -255
> / **W9 INTMIN+1 (0x80000001 odd)** / W10 -1 + the position+value compound P0/P2 (INTMAX
> word at MB0 amid 0 / amid 0x33) + X5 LAST. **W6/W9 = the 1<<(qp/6) lambda-table-index
> OOB shot — a KILLED/PANIC there = THE 64747 write.** CUT: E1/E4/E8 (confounded),
> V0-V2 (subsumed), S0-S3 (answered). EPOCH 21 ops. KERNEL log = oracle.
> **v130 (08-12) = THRESH-PIN + DIMS-ISO SWEEP:** the v129 run (07:51) DELIVERED the
> first map-content-dependent kernel response in the campaign — the exact-size 130560B map
> at 2vuy-IOSURF: fill 0x33/0xFF = B 1024/1017 vs the M3a no-map anchor 569 (+455/+448 =
> +80%), fill 0x00/0x10 = 577/578 (+8/+9) — a step-function QP side-channel with the gate
> constant between 16 and 51, and the +455B ≈ the per-MB delta-syntax cost (8160 MBs) = the
> encoder ITERATES our attacker bytes at slice-build. The oversize axis (2x/25x) PROVEN DEAD
> (B == anchor = map dropped at the size gate), MG-recon DEAD (4 keys, 0 AVE-relevant), and
> ES07 leaked the daemon paths: /var/mobile/Library/Caches/com.apple.videocodecd/ REACHABLE
> (the kernel VIOLATION), prefs plist ENOENT. v130 = 17 shots: C0/K1 + M3a (per-dims no-map
> anchor) + M3 (0x33 repro) + T1-T6 (0x18/0x20/0x26/0x28/0x2C/0x32 = the threshold pin) +
> D1A-M/D2A-M/D3A-M (1921x1081 / 1920x1095 / 4K = ceil(W/16)*ceil(H/16)*16 formula-divergence
> overflow shots, per-dims anchors, 4K = 518400B = the devType<29 branch PROVEN at 1080p) +
> X5 kill LAST. ES08 = prefs-plant probe (creates the first-created com.apple.videocodecd
> domain plist + readback = cfprefsd reads disk = X5 restart consumes the plant). WATCH:
> bFam anchors only on delivered no-map cells (D-cell EFFECT is only valid if its anchor
> delivered). **NOTE: the v130 splice script duplicated the whole opt block (enum/row/sweep/
> probe) - repaired with .ds_v130_fix.py + .ds_v130_fix2.py (single copies, build green);
> when splicing, anchor on exact text and re-count symbols after.**
> **v129 (08-12) = M3-ISOLATION SWEEP:** the v128 run's kernel receipts gave the
> campaign its FIRST size-visible effect — M3 (exact-size 130560B map) = kernel ID 60
> `Input: 2 Process: 2`, B 1024 vs C0 265243 (a designed nF=2 flat-IOSURF session, NOT a
> truncation). v129 isolates it WITHIN the family: M3a (pf=2 no-map anchor) vs M3 (0x33)
> vs M3b/c/d (content gradient 0x00/0x10/0xFF) vs M3e/f (oversize 2x/25x); a B-response
> to the fill = the map is CONSUMED = delivery proof + a kernel QP side channel; oversize
> B != M3a = the overflow shot. New EFFECT verdict class (B vs the family ref / cb < nF
> flags instead of silent ACCEPT). S1 (SetDPB) + ES04 CUT; ES07 added (exact-path probe:
> access() on the kernel-leaked /var/mobile/Library/Caches/com.apple.videocodecd/ + prefs
> plist = the prefs-plant reachability test + a Caches/Documents scan). Startup banner
> trimmed 60 -> 3 lines. EPOCH 14 ops. Kernel log per-session Input/Process = the oracle.
>
> **v128 (08-11) = 64747 LEAN-ROW + ESCAPE COMBINE + MG RECON:** the deep
> binary analysis PROVED the daemon reads disk state we can reach — `nm -u` shows
> ave.videoencoder (the AVE plugin) imports `_MGGetStringAnswer` + `_CFPreferencesCopyAppValue`
> and VideoToolbox imports 5 CFPreferences APIs; the MobileGestalt cache plist (R/W
> confirmed v126) = the strongest daemon-manipulation lever. User chose READ-ONLY MG
> recon first. v128: the dead SetDPB frame-7 family (S2/S3/S3b/S6, 7 epochs of ACCEPT)
> + H-hash noise CUT from `ds_opt_qpmap_sweep` (16 -> 6 shots: C0/C0b/K1/M3/S1/X5); the
> bad_query escape moved INTO the OP row (ES01-04 R/W + NEW ES05 read-only MG-cache key
> dump = the v129 manipulation candidates + ES06 Data/System daemon-container identify
> = the read-back oracle); IK row trimmed to the race hammers. EPOCH = 10 encode ops.

---

- **v126 (08-11) = the ROW-CUT + IOKIT-43805 RACE + bad_query ESCAPE (the PIVOT):**
  per user direction the GA/SK/TI/SM/DC/SW rows were DELETED (probe fns, row-only
  helpers, g_dc_* globals + the g_dc_capture hook in ave_out_cb, main.m's dead
  `-parsechild`/`-aiffchild` branches; UI/ViewController.m 6660 -> 5200 lines). The
  harness is now 3 rows: mediaremoted 28973 + AVE OPT-SMUGGLE 64747 (unchanged) +
  the NEW ROW 8 **IK. IOKIT 43805 RACE + bad_query ESCAPE (v126)**. Stage 1 = the
  bad_query sandbox escape ported to pure C (`ds_esc_consume`: dlopen
  libsystem_containermanager, class-13 MCMSharedSystemDataContainer, group
  systemgroup.com.apple.mobilegestaltcache, part 3 Library/Caches, 8-level `..`
  traversal, flags 0x8000000000 -> token -> sandbox_extension_consume; all 14
  symbols verified exported in the 24A5355q lib, daemons on-disk-only, in-range
  26.0-26.6.1/27.0b4 per FINDINGS 99). ES01-04 = MG-plist R/W verify / write+readback
  / /var/containers/Data/System list / release+revoke. Stage 2 = the 43805 race
  hammers through videocodecd (FINDINGS 98: AppleAVE2UserClient deferred-surface free
  list + AttachEUC/DetachEUC + eKPIState): IOK01 P1 sequential guarded x10, IOK02 P2
  2-worker concurrent x6, IOK03 P3 2-worker x6 with MIXED geometry (worker-0 4K).
  v126-r (reviewer): per-cell HEAP IokRaceCtx (the shared static + per-cell memset
  raced detached workers from the previous cell) + GCC-builtin ATOMIC callback
  counters (__sync_fetch_and_add on g_ave_cb_fires/ok/bytes + fetch_and_xor on the
  hash - the two race workers call ave_out_cb concurrently, plain sig_atomic_t ++
  lost updates). Verdict in the KERNEL log ('release delayed surface' / 'failed to
  release fence' / 'DetachEUC' = the race FIRED; PANIC/reboot = THE 43805 write).
  EPOCH 3 race cells + 2 beats = 5 ops (ES cells are file-only). IPA 203,924 B.
  **RUN VERDICT (23:20, FINDINGS 100): the ESCAPE CONFIRMED LIVE 4/4 on 24A5355q**
  (ES01 MG-plist R/W errno=0, ES02 write+readback 19/19, ES03 System-container
  opendir = 4 live UUIDs, ES04 revoke clean; handles 2/3/4/5) = a REAL cross-container
  R/W primitive for the campaign. 43805 race NEGATIVE at 5 ops: kernel log = clean
  open->dump->close cycles (AVE IDs 30..110, ~30ms), ZERO 'release delayed surface'/
  'DetachEUC'/fence lines, no daemon death/panic. Next: crank the hammers (x24 +
  churn worker).
- **v141 (08-12, current) = the 43805 FLOOD-X8 (Qwen's probabilistic pivot, made buildable):**
  the v139 state-repro run FALSIFIED the naive trigger tests - an open DID land 8ms
  after the kill with 4 concurrent clients and `AVE_Client_Die:2413` stayed silent =
  the ERR is a RARE (~1-in-7 per compound) kernel fault, NOT a reproducible phase
  (P(0/6 | p=1/7) ~ 40%, so the rare-race model is NOT falsified). v141 floods the
  probability instead of chasing the exact timeline: the IK compound runs **8x per
  epoch** (IOK04-11, was 4x), **2 jittered CHURN workers** (was 1 - 2x the mid-create
  traffic at the kill instant), **user-interactive QoS on every attack thread**
  (`pthread_set_qos_class_self_np` - the iOS equivalent of affinity; Qwen suggested
  `pthread_setaffinity_np` which DOES NOT EXIST on iOS - it would not compile), a
  **0-30ms randomized kill-phase delay** per compound (arc4random_uniform - the
  reviewer caught that libc `rand()` was a DATA RACE: srand on the probe thread vs
  rand() in 2 churn workers + the probe thread = UB on a global LCG; replaced with
  the thread-safe self-seeded arc4random, verified in the binary via nm) and
  **0-50ms churn create jitter**. IOK02/03 hammers CUT (never hit, each costs a
  shot). EPOCH: 1 hammer + 8 compounds x2 bumps + 2 beats = 19 ops (IK ALONE after
  a reboot). The oracle stays the kernel log: 'AVE ERR: AVE_Client_Die:2413
  pClient != nullptr' / 'StopClient:2302 total number of commands' inside a kill
  window = FIRED; 2+ ERR hits across the 8 = reproducible; PANIC/reboot = THE 43805
  write. v140's v141 IPA saved as DirtySlide-v140.ipa. Build green, IPA 214,500 B,
  markers 1:1 / cut 0 / lit-bsln 0.
- **v141 RUN VERDICT (14:00, FLOOD-X8): 0/8.** All 8 compounds fired with the
  attach barrier (live=2 on 7/8, live=1 on IOK10), the mid-attach teardown WARNs
  (StopClient:2302 command-history dumps) appeared in 7/8 kill windows (23
  AVE_ClientDie + 24 StopClient rows), 532 opens == 532 closes (zero leak), and
  the 10 AVE ERR lines are ALL benign Analytics pixel-format noise. ZERO
  'AVE_Client_Die:2413 pClient != nullptr' - the v138 golden did NOT reproduce.
  SECOND v141 RUN (14:03, degraded): the user re-ran IK WITHOUT a reboot - the
  app-side epoch counter persisted (cum started at 20), so only IOK04/IOK05 fired
  before the 24-op hard cap, BOTH at live=1 (below the barrier target - weak
  shots), and the kernel log (6,639 lines, 14:03:55-14:04:40) shows ZERO
  'AVE_Client_Die:2413' again + zero StopClient:2302 witnesses + 140 opens == 140
  closes + no panic. Campaign tally: 1/17 forced-detach compounds (v138 1/1,
  v139 0/4, v139-state 0/2, v141 0/8, v141b 0/2). P(0/16 post-golden | p=1/17)
  ~ 38% - the rare-race model still fits, but 17 compounds across 5 configs
  produced ONE logged ERR and ZERO escalation (no panic, no write ever). The
  43805 front is at hard diminishing returns: an 8-shot flood is ~38% for a
  single ERR (a logged fault, NOT the write), and every flood costs a full epoch
  + 8 daemon kills. RECOMMENDATION: CUT 43805 - the epoch budget belongs to the
  MG devType plant (the controllable kernel-config lever, reboot test pending)
  and TK (the deterministic primitive). NOTE for any future IK run: the epoch
  counter is APP-SIDE and persists - a REBOOT between IK epochs is mandatory
  for a full 8-compound flood (the 14:03 run was invalidated at shot 3).
  Campaign tally: 1/15 forced-detach compounds (v138 1/1, v139 0/4, v139-state
  0/2, v141 0/8). P(0/14 post-golden | p=1/15) ~ 38% = the rare-race model still
  fits, but the honest p is ~1-in-15 per compound (an 8-shot flood = ~42% odds of
  >=1 ERR) and even a reproduced ERR is a LOGGED FAULT PATH - the 43805 kernel
  WRITE (PANIC) has never appeared in 15 compounds. The v141 mechanics are now
  fully proven; the fault is rarer than the target. Decision gate: one more flood
  is ~40/60 for a single ERR hit; a 2+ hit or a PANIC = escalate; otherwise the
  epoch budget belongs to the MG devType plant (controllable kernel-config lever)
  and TK (the deterministic primitive).
- 
## 1. What this project is NOW ES mode-2/7 listings collapsed to count-only receipts (the per-UUID caches/docs scan + entry lists were proven-unchanged noise; the ES09 read-back consumer was cut) - the epoch log is now ~40 lines leaner.

- **Originally**: DirtySlide — an unpriv→root **macOS LPE** (8-byte OOB R/W in
  `vm_shared_region_slide_page_v5`, syscall 536, patched in macOS 26.5.2). That code lives in
  `src/` + `scripts/` + `Makefile` and is unchanged (see the bottom of `README.md`).
- **Now also**: an **iOS privileged-boundary research harness** ("DirtySlide Privileged
  Boundary Hunter v6") — a plain Xcode app whose **5 table rows** each run a probe suite
  (`UI/ViewController.m`, ~950 lines). **v37 (08-08): 5 rows** — **mediaremoted 28973**
  (MediaRemote path handling → ROOT), **Gemini Audit v12** (geometry audit), **SceneKit
  FILE-PARSE 43723** + **ImageIO TIFF-IFD 64740** (crafted SCN/DAE/USDA/TIFF files parsed
  in a CHILD process — a parser crash = clean .ips + SIGNAL receipt) and **AVE
  DIM-SMUGGLE 64747** (per-frame VRA dim smuggling past the create gates). The v14–v33
  families' evidence lives on in `FINDINGS.md`/`VERSIONS.md`.
- The crash evidence that made the campaign interesting: 19 `.ips` files = **13× H264SW
  byte-identical + 2× vt_Copy + 1× client SIGTRAP** + **2× SpringBoard watchdog kills + 1×
  PANIC** (`panic-full-2026-08-10-125451.0002.ips` = the v84 UPS-count USL-wedge cascade →
  SpringBoard hang → watchdog timeout panic — the campaign's FIRST full-device reboot, fired
  from the AppleAVD kext watchdog path). See `FINDINGS.md` (history kept).

## 2. Project layout (paths that matter)

```
/Users/pauyedin/DirtySlide/
  UI/ViewController.m        <- THE harness: all probes live here (single ~4000-line file)
  UI/ViewController.h        <- trivial
  DirtySlide.xcodeproj/      <- Xcode project (builds the "UI" app into DirtySlide.app)
  DirtySlide/                <- app metadata (Info.plist, assets, entitlements)
  src/  scripts/  Makefile   <- ORIGINAL macOS LPE PoC (unchanged, unrelated to the harness)
  *.ips                      <- CRASH EVIDENCE pulled from the device (see section 5)
  .ds_*.py/.sh               <- leftover helper scripts from previous agent sessions (safe to ignore/reuse)
```

**The ONE file to edit for new probes: `UI/ViewController.m`.** All state lives there.

### External resources (firmware, ON THE MAC, not in the repo)

```
/Users/pauyedin/23G71__iPhone17,5/             <- iOS 26.6 (23G71) iPhone17,5 extraction (CURRENT)
  23G71__iPhone17,5/dyld_shared_cache_arm64e*  <- 84 split-cache slices + .symbols
  bin/H264H9.videoencoder                      <- 1.5 MB AVC encoder plugin, 1404 SYMBOLS (the kill target)
  bin/H9.videoencoder                          <- the HEVC sibling (NaluType/TemporalID/MCTFParams)
  bin/VideoToolbox                             <- 6.6 MB, 11k symbols (client+server)
  bin/com.apple.driver.AppleAVE2               <- 2.7 MB encoder kext 905.40.1 (10 UC selectors)
  bin/com.apple.driver.AppleAVD                <- decoder kext
  fs/.../usr/libexec/videocodecd               <- 58 KB STUB (unchanged shape)
  Firmware/sptm.t8140.release|txm.iphoneos.release|all_flash/iBoot...  <- boot chain (recon'd)
/Users/pauyedin/24A5355q__iPhone17,5/          <- iOS 27.0 (24A5355q) extraction (STALE - history)
```

Key static offsets — **27b1 STALE, see the v142 block for the 26.6 offsets**
(PrepareMBInputCtrl @0x2a06211e0, AVE_GetPerFrameData @0x2a05881d0, Ref_Retrieve
@0x2a059f810, CFDict_GetSInt32 @0x2a059fab8, MultipassDataFetch @0x2a060e374):

| Thing | Where | Value |
|---|---|---|
| H264SW sw-codec module | `.42` | image @`0x3058000`, TEXT vm `0x23b458000`, size `0x1d4360` — `/System/Library/VideoCodecs/H264SW.videocodec` (JVTLib.cpp) |
| H264SW crash offsets | .ips | faulting `+0x16dfc0`, callers `+0x16e974`, `+0xca94`; fault ADDRESS `0x2232b47` (wild) |
| ave.videoencoder (daemon plugin) | `.71` | image @`0x1007000`, TEXT vm `0x2b9407000`, size `0x2350b8` — 6744 total strings, ~1677 of them "AVE %s:" gates |
| Geometry gate string | `.71` | `FIG: dimensions (%dx%d) not supported %d.` |
| QP-map gate string | `.71` | `UserQpMapSize (%d) does not match required size (%d), disabling userQPMap feature` |
| Size-math strings | `.71` | `SEIBufferSize %d`, `m_CodedBuffSize[0] >= FinalOutput_FRAME_Size`, `Copy LRME Best MV data: %d x %d MBs, FinalOutputSize %lu` |
| vt_Copy blitter | `VideoToolbox` | `vt_Copy_x420_420v` fn `+0x1a5928` (B1 crash PC `+0x1a597c` = fn+0x54); `vt_Copy_420v_Crop` fn `+0x1a8c4` (B2 crash PC `+0x1a948` = fn+0x84). **Both have NO NULL checks on plane bases** (RE'd 08-08; the standalone binary is offset-identical to the loaded image — `otool -tv -p <symbol>` works 1:1). The kext `AppleAVE2` DOES validate (`iAddr != 0`, `stride % 64 == 0`) |
| dvdc + tile | `VideoToolbox` | `dssxpc_CreateTile`, `TileDecoderRequirements`, `TiledDecompression` spec key |

## 3. THE build → package → verify loop (use exactly this)

The project is built on the mac, packaged into an IPA, and run on the device by the USER.
An agent's job is to produce a **green build + a verified IPA**. No device access from the
agent — the user installs and runs, then pastes the console + pulls new `.ips`.

```bash
# 1. build (no codesign; the user re-signs/sideloads)
xcodebuild -project DirtySlide.xcodeproj -scheme DirtySlide -configuration Release \
  -sdk iphoneos -derivedDataPath /tmp/ds_dd build CODE_SIGNING_ALLOWED=NO

# 2. package the IPA
rm -rf /tmp/ds_pkg /Users/pauyedin/DirtySlide/DirtySlide.ipa
mkdir -p /tmp/ds_pkg/Payload && cp -R /tmp/ds_dd/Build/Products/Release-iphoneos/DirtySlide.app /tmp/ds_pkg/Payload/
cd /tmp/ds_pkg && zip -qry /Users/pauyedin/DirtySlide/DirtySlide.ipa Payload

# 3. verify markers INSIDE the built binary (never trust the source grep alone)
unzip -q DirtySlide.ipa -d /tmp/ipa_check
U=$(find /tmp/ipa_check/Payload -name UI -path '*UI.framework*' | head -1)
strings -a "$U" | grep -c 'v29 H264SW'        # each row's banner string must == 1
```

**Marker discipline:** every new probe must carry unique banner/row strings; the verify
step counts them in the **binary** (strings on the extracted `UI` binary). Counts: new
banner `=1`, each row tag `=1`, read-offs `=1`, old buttons still `=1` (regression check),
`lit-bsln=0` (no literal `\n` in binary — see gotcha G3).

## 4. How the harness works (the conventions to follow)

- **Rows**: `kProbes[]` table (`ProbeEntry {name, desc, probe_fn}`) near the end of
  `UI/ViewController.m`; each button runs `probe_*(const char *pfx)`.
- **Banners**: each probe starts `== Xx. TITLE ==` (letter-prefixed: MR, GA) and
  ends with a `Xx read-offs:` block explaining how to judge each row + `sweep done - .ips
  captureTime <-> [stamp]`.
- **Rows**: `I[TG01 ...]` prefixed lines; every row prints a **receipt** (OSStatus, cb
  fires/ok, out bytes, elapsed ms) so the verdict is readable without the code.
- **Beats**: probes end with 4× `XxH01..04 1x1 beat` — a tiny 1×1 H264 encode that
  proves the daemon is still alive (a NO-callback beat = post-corruption daemon state).
- **Guard**: `ds_ave_guard_run(^int{...}, &rc)` runs a block under SIGSEGV/BUS/ILL/TRAP/ABRT
  recovery; `>0` = caught signal (print `FAULTED at 0x..`), `0` = ok. **Callbacks**
  (`ave_out_cb` encode / `dec_out_cb` decode) count fires/ok/bytes into globals
  (`g_ave_cb_fires/ok/err/bytes/fire_mach`, `g_dec_out_*`). Reset them before each row.
- **Corpus**: the decode probes capture a real H264/HEVC sample + param sets
  (`ds_dec_capture`) once, mutate it per row, and **free it in the cleanup tail**.
- **Timing**: rows that can grind are annotated `(grind ~Ns - NOT a hang)`; wait loops
  break early on the first callback.
- **Pipe**: stdout is piped to the UI log on a SEPARATE drain queue (v88/v89 fix — the
  64 KB pipe must be drained concurrently or the probe deadlocks). Probes are serialized
  by a busy flag (v67). Never spawn a second probe mid-run.

## 5. Reading the crash evidence (`*.ips`)

`.ips` files are **two-line NDJSON**: line 1 = metadata header, line 2 = the pretty-printed
body. Parse with `json.JSONDecoder().raw_decode(text, text.find('\n')+1)`. A worked parser:
`.ds_ips_parse.py` pattern (keep a copy around). Key fields: `exception`,
`faultingThread`, `threads[ft].frames[].imageOffset/symbol`, `usedImages[].name`,
`captureTime`. The 16 files on disk:

- 13× `videocodecd-2026-08-07-*` files (e.g. `videocodecd-2026-08-07-133400.ips` … `videocodecd-2026-08-07-162323.ips`) → `H264SW.videocodec+0x16dfc0`, fault **KERN_INVALID_ADDRESS at 0x2232b47** (the v14 class).
- `videocodecd-2026-08-07-162438` → `vt_Copy_x420_420v`, fault at 0x1.
- `videocodecd-2026-08-08-141839` (**NEWEST, 08-08 14:18:39 — CONFIRMED against the v29
  console**) → `_platform_memmove` ← `vt_Copy_420v_Crop` ← software pixel-transfer chain
  under `vtCompressionSessionPixelTransferSessionWork`, fault at **0x0 (NULL memmove)**.
  It fired at **SW01 = the 1920×1080 CONTROL row (sane dims)** — the "huge session"
  hypothesis is FALSIFIED. Registers: `memmove(dst, src=NULL, len=256)` = NULL plane base,
  len = the 256-wide luma row. RE'd 08-08: no NULL check in the blitter. **v30 (14:58) did
  NOT reproduce on a warm daemon** — trigger model = first pixel-transfer after a daemon
  start/restart with a byte-backed 2-plane 420 input (see FINDINGS §2).
- `DirtySlide-2026-08-07-224330` → EXC_BREAKPOINT SIGTRAP in OUR app
  (`CFEqual.cold.7` ← `ds_ave_cfg_meta` ← config probe) — client-side trap, not the daemon.

**Correlating runs**: every probe prints timestamps `[HH:MM:SS.mmm]`; match a new `.ips`
`captureTime` to the row that was running at that moment.

## 6. Static-analysis toolbox (the recon scripts)

All the `python3 + mmap` tricks work on the raw cache slices (no otool needed for strings):
- **Find an image containing a file offset**: backscan for `\xcf\xfa\xed\xfe`, walk
  `LC_SEGMENT_64` (cmd 0x19), read `__TEXT` vmaddr/vmsize/fileoff.
- **Strings in a slice**: `re.finditer(rb'[ -~]{6,220}', mm[off:off+size])`.
- **Gate catalog**: dump ave.videoencoder's strings and grep for validate/error patterns —
  that catalog IS the server-side attack surface map.
- Copy the pattern scripts from the repo root (`.ds_recon_*.py`) — they are proven.

## 7. Version + row naming conventions

- **Buttons** are named `<Target> <CVE/ID>`: `AVEVideoEncoder 64747`, `VideoToolbox TILED 64747`, …
- **Probe versions** bump per feature (v25, v26 … v29) and are embedded in the banner:
  `v29 H264SW FORCE-SW SIZE-SWEEP`. Keep the version in the kProbes `desc` and the banner.
- **Row prefixes** are unique per probe: MR (mediaremoted 28973), GA/BB/GS/GE/GCH (audit gate
  cells), GE (audit P-E IOSurface injection), GCH (audit beats), MRH (mediaremoted beats),
  SK (SceneKit file-parse cells), TI (ImageIO TIFF cells), SM (AVE dim-smuggle cells).
  Beats are `<prefix>H01..04`.

## 8. Editing gotchas (learned the hard way — READ BEFORE EDITING ViewController.m)

- **G1 — heredoc escaping**: NEVER paste complex python with embedded quotes/newlines into a
  basher command — write the script with `write_file` to a `.ds_*.py` and run `python3 it`.
- **G2 — block placement**: when splicing a new function into `ViewController.m`, anchor on
  a line that is UNIQUE and verify it is at **top level** (a `}` preceded by the function
  tail). The v29 block was once inserted INSIDE `probe_ave_flags` (before its closing `}`)
  → `error: function definition is not allowed here`. Fix = cut + re-insert after the `}`.
- **G3 — format strings**: banner text containing `%d`/`%lu` must be escaped `%%` in the
  `dprintf` format string or you get `-Wformat-insufficient-args` (and runtime garbage).
  Also: `\n` in C strings must be a single backslash — a double backslash prints literal
  `\n` (check `lit-bsln=0` in the binary).
- **G4 — SDK constant names**: iOS has `kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder`
  (no "Video") but `kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder`
  (with "Video"). Verify names in
  `$(xcrun --sdk iphoneos --show-sdk-path)/System/Library/Frameworks/VideoToolbox.framework/Headers/*.h`
  before use. Some flags differ from macOS (e.g. no `2xRealTimePlayback` on iOS; temporal = bit 1<<3).
- **G5 — new probes must free what they allocate** (corpus, CF objects, malloc) on EVERY
  path — the reviewer checks CF balance.
- **G6 — SDK APIs** like `kVTVideoEncoderSpecification_*` are iOS 17.4+; the deployment
  target builds them fine, but availability warnings are the sign you typo'd the name.
- 
