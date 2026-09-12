> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

<p align="center"><img src="dirtyslide.png" width="55%" alt="DirtySlide"></p>

# DirtySlide

Two things live in this repo:

1. **Unprivileged → root macOS LPE** — the original project (below, unchanged).
2. **An iOS privileged-boundary research harness** — the current work: a single-file Xcode
   app (`UI/ViewController.m`) that sweeps AVFoundation/VideoToolbox attack surfaces for
   parser/allocation bugs on iOS 27.0 (24A5355q), with **on-device crash evidence** in the
   repo root (`*.ips`).

> **Read `AGENTS.md` first** if you are an agent or new contributor — it has the file
> paths, build/verify loop, static-analysis toolbox, and every editing gotcha we learned.
> Findings + verdicts: `FINDINGS.md`. Version history: `VERSIONS.md`.

---

## Part 1 — the iOS research harness ("Privileged Boundary Hunter")

A plain Xcode app whose table rows each run a probe suite against system services.
Probes print timestamped console receipts per row; runs are guard-recovered
(SIGSEGV/BUS/ILL/TRAP/ABRT → the app never dies) and end with stability beats. **The
daemon (`videocodecd` / `mediaremoted`) may crash — that is the goal; correlate new
`.ips` to the row that was running via `captureTime <-> [stamp]`.**

### Buttons (6 rows — v142, the iOS 26.6 A-D regroup)

| Row | Target |
|---|---|
| A. AVE T-KILL 26.6 | The daemon-kill factory: 14 hostile-container cells on the symbol-pinned 23G71 abort sites — the 10 unconditional `CFNumberGetValue` keys in `AVE_GetPerFrameData` @0x2a05881d0 (incl. NEW POCLsb / CalculateYUVChecksum / MarkCurrentFrameAsLTR / the SliceQP scalar twin), `UserQpMap` (no type check @0x8948), `SetDPB` (bare `CFArrayGetCount` @0x2a05a1f54), `ReferenceL0` element-conf (the 7/7 .ips witness, LAST). The .ips is the receipt |
| B. AVE OOB-PRIMITIVE 26.6 | The multipass mode==1 unchecked `memmove(stats, blob, 1574)` @0x2a060e99c fed a <1574B blob via the PUBLIC `VTMultiPassStorageSetDataAtTimeStamp` = a daemon heap OOB READ feeding kernel-bound RC structs (the info-leak candidate). B01 short-blob / B02 1574-gate / B03 seq+round-trip |
| C. AVE KERNEL-QP 26.6 | The QP-map channel repro (M3 exact-size 130560 + the +455B side-channel + the clean SInt32@0 value axis +1/−255/INTMAX), the 3 SURVIVING ungated Prepare fields (MCTFEdgeCount / FilterGroupSize / AmbientViewingEnvironment INTMAX), the userDPB 2..17 boundary. Zero-death by design; the kernel log is the oracle |
| D. AVE NEW-SURFACES 26.6 | The never-fired 23G71 surfaces: the 21-key `DPB_*` per-frame family (incl. `DPB_ReferenceFrames_IOSurfaceID`), `FirstMbInRecvSlices` (the CFData multi-slice driver), the HEVC H9 keys `NaluType`/`TemporalID`, and the vt_Copy NULL-plane blitter repro (guard-free `ldrb` @fn+0x40 on 23G71) |
| E. DAEMON-CACHE escape | The bad_query class-13 sandbox-escape receipts (proven 4/4 on 26.x) — the support primitive for the MG row |
| F. MobileGestalt 64747 | The device-identity spoof via the escape (O_RDWR on the MG cache plist); a REBOOT-SURVIVING devType flip = a controllable kernel-config input (the UserQpMap size formula branches on devType). The reboot test is the verdict |

CUT in v142: mediaremoted 28973 (dead since v40), the IOKit 43805 flood (1/17, never
escalated; the 26.6 oracle strings are RENAMED — `AVE_Client_Die:2333`,
`CheckStopped:2379`, `CleanClient:2445` — grep the kernel log manually if needed).

> **v38 (08-08):** the 19:57 run proved the LiveContainer sandbox blocks `posix_spawn`
> (every SK/TI cell dead) and that the SM row's sys-alloc 420f input instant-rejected
> before the VRA key was read. Both fixed in v38 (in-process guarded parse fallback;
> SM on the byte-backed 420v10 B-class input). Full `driver+binaries/` RE catalog
> (AVD decoder VRA, H264H8/MP4VH8 NALU gates, AV1SW overflow string, ProRes
> dims-after-rounding) in `FINDINGS.md` §14.

> **v40 (08-08):** the 21:09 run corrected the B1 attribution — the fresh `.ips`
> (vt_Copy_x420_420v @0x1, no crash loop) fired at run START on the **control** cell:
> B1 = the B-class byte-backed 420v10 input in the daemon-start window (dims irrelevant;
> the 20:52 SM04 'INTMAX hit' was a crash-loop tail). v40: SM01 INTMAX FIRST on a fresh
> daemon (attribution test — reboot first), SK `SCNERR source==nil` diagnosis + USDA
> SK11-14 overflow shapes (SCN/DAE rejected at source; USDA is the only live SceneKit
> input), TI read-offs (21:04 proved TI live + clean — 64740 handled on iOS 27).

> **v41 (08-08):** the v40 run verdicts landed — the INTMAX-first determinism test was
> **clean** (SM01 on a fresh daemon: no crash): B1 is a race, ~1-in-2 fresh starts
> (21:09 crashed on the control cell, 21:30 didn't on INTMAX), and every VRA cell returns
> the same -12912 as the control (smuggle has no observable effect). SK11-14 USDA
> overflow shapes all handled (43723 clean via USDA); TI clean on both runs; SCNERR
> diagnosis visibility fixed (printf→dprintf — the in-process pipe swallowed the
> buffered line).

> **v42 (08-08):** the 21:45 run = **B1 hit #5** (2-of-3 fresh starts, still the
> encoder-side vt_Copy race) — v42 adds the **VT DECODE-SPS row** to attack the other
> half: in-app 64×64 H264 corpus, bit-level SPS rewrite (exp-golomb, ep-safe; wild
> dims 65536/131072/1048576/both + lying NAL length + slice pps_id=255) decoded via
> VTDecompressionSession. The SPS rewriter was validated host-side (Python mirror + C
> harness of the exact device functions) — it caught a real exp-golomb decode
> off-by-one that would have corrupted every cell; fixed, all 5 cells byte-identical.
> DC ops consume the G8 epoch budget — run DC FIRST after a reboot.

> **v43 (08-08):** the DC row was **void on first run** — iOS 27 VT emits **AVCc mode**
> (SPS/PPS live in the format description, length-prefixed sample, zero start codes).
> v43 pulls the param sets via `CMVideoFormatDescriptionGetH264ParameterSetAtIndex`
> and walks the sample as AVCC. Deep RE over the **AppleAVE2 kernel kext** found the
> 64747 money string (`iOffset + iSize <= sizeof(iaPSData)`) + the kernel AVC_Level
> gate — v43 adds DC09 naluLenSize=2, DC10 PPS FMO, DC11 SPS level_idc=99 (kernel
> gate; a kernel-side .ips/panic is the goal). New bit surgery verified byte-identical
> C-vs-Python. sbuf use-after-free fixed (freed only after the async drain).

> **v43 RAN 3× (08-08 22:23+):** all three runs **completely clean** — DC01/09/11
> DECODED, DC02-05/08 `fmtdesc create=-12710` (client wrap rejects wild dims),
> DC06/07 `-12909` (decoder rejects lying NAL/pps_id), DC10 FMO `-666` — the decoder
> route is characterized and CLOSED on this build.

> **v44 (08-08):** the deep ave.videoencoder RE found the **per-frame option channel**
> — daemon receipts for ReferenceL0 count / NaluType / TemporalID / LTR / AttachDPB /
> ResetRCState / DPBRequirements / UserDPBFrames, mapping DIRECTLY onto AppleAVE2
> **kernel** gates. v44 adds the **AVE OPT-SMUGGLE row** (13 cells + 2 beats = 15 ops):
> per-frame options on the same channel as the inert VRA dims, with
> DPBRequirements/UserDPBFrames delivered both via session property (OP10/11) and via
> the **encoder-specification dict** (OP12/13 — the verbatim-forward AVE_Prop_*
> channel). A kernel .ips/panic on OP03/04/06/07/10-13 = the 64747 goal.

> **v44 RAN (08-08 22:41):** CLEAN — every option cell uniform -12912 (the frame never
> reaches the FIG gates; OP10/11 client-gated as predicted; OP13's 20.3s = the G8 2×
> curve, not a hit). The 22:46 `.ips` = **B1 hit #6** (consecCrash 5 crash-loop).

> **v45 (08-08):** RE pinned both real bugs at the instruction level — **B1** =
> `vt_Copy_x420_420v +0x54` deref of a NULL source plane (`[NULL]+1` → 0x1; the 14:18
> `vt_Copy_420v_Crop` hit = the same NULL plane into memmove → 0x0); **H264SW +0x16dfc0**
> = OOB jump-table dispatch (+0xca94 is a `.word` table, not code) → MB-loop +0x16e974 →
> wild-stack store (13/13 byte-identical, deterministic). v45 adds the **H264SW REPLAY row**
> (giant force-SW 5952²/5984² sessions — the v14 trigger restored after the v34 reset),
> the campaign's most reliable daemon kill. Run SW first after a reboot, alone.

> **v46 (08-08):** the v45 run PROVED the force-SW keys are ignored (SW01-07 uniform
> -12912, force-SW property -12900, HW everywhere — the 13× kill did NOT replay; the
> v14 class ran through the NULL-spec fallback at 5952²/5984², per FINDINGS §1). v46 SW
> row = SW00 `VTCopyVideoEncoderList` dump + NULL-spec v14-exact 5952²/5984² cells + an
> EncoderID-forced cell + v14-era 420f input + a declared>backing guard-page cell;
> per-cell `kVTCompressionPropertyKey_EncoderID` readback tells you the ACTUAL encoder the
> daemon picked — an H264SW id there = the crash class is live (0x2232b47 replay shot).

> **v57 (08-09):** the v56 run (19:03–19:05) **DIED IN OUR OWN CLIENT at OP02** — the v56
> `RefL0 count=INTMAX` cell built a **2.1-billion-CFNumber CFArray** = OOM SIGSEGV, zero
> evidence (ReportCrashService sandbox-denied on the LiveContainer-hosted binary; the
> relaunch at 19:05:34 + kernel MemoryPressure.critical at 19:05:37 = it fired twice).
> **v57 fixes the client suicide**: the REFL0 array is clamped to 16 (the kernel iNum≤9
> gate makes >9 the OOB range; an INTMAX array dies in the client before it can ever reach
> the daemon) and adds the **RUN JOURNAL** (`~/Documents/ds_journal.log` — a START/DONE
> line per op, read back on launch; a START with no DONE names the cell at a **CLIENT**
> death (OOM/SIGKILL/segfault); daemon deaths stay log-correlation — **pull the journal
> FILE with the log window**, it lives in the app container's Documents). OP04–13
> (RefL0=16/10 OOB, NaluType=15, TemporalID=63, ResetRCState=1, the DPB/LTR family with
> INTMAX single-values, the SPEC-dict verbatim channel, the 2..17 under-probe) are built
> to finally fire. **RUN ORDER: reboot → OP FIRST, ALONE (13 cells + 2 beats = 15 ops) →
> reboot → SW** (the kill-window map). IPA ~200K, markers 1:1.

> **v58 (08-09):** the v57 run (19:37) fired **ALL 13 OP cells + 2 beats** with zero
> client crashes and zero daemon deaths — the **FIRST COMPLETE oracle**: 13/13 fp-identical
> (`fp=0000003606052d47564adc5c`) = the per-frame `AVE_kVTEncoderFrameOptionKey_*` surface
> (ReferenceL0 16/10, NaluType, TemporalID, LTR, AttachDPB, ResetRCState) is **OBSERVABLY
> CLOSED**. But the v57 daemon log exposed the **ONE live channel**:
> `VTSessionSetProperty(DPBRequirements)` IS forwarded to the AVE plugin
> (`AVE_Prop_AVC_SetDPBRequirements:5574 psINS->pcVCP != __null | fail to get VCP` → -1015
> → **-17691**) — gated ONLY pre-encode (pcVCP null). UserDPBFrames = client **-12900**
> dead; SPEC-dict DPB keys = no AVE_Prop lines = dead. **v58 shoots the gate**:
> DPBRequirements set **AFTER a warm-up frame** (pcVCP live), num_frames=INTMAX/18/17/1
> (OP02–05), OP06 = pre-encode re-confirm, OP07–09 = discriminator close-outs —
> **9 cells + 2 beats = 11 ops**. `DPB set AFTER warm-up = 0` = gate PASSED, the hostile
> value rides to the DPB alloc (AppleAVE2 PANIC = THE 64747 goal); -17691 = the DPB
> channel is closed too. The hostile encode skips the second Prepare; a warm-up fault
> aborts the cell. **RUN ORDER: reboot → OP FIRST, ALONE → pull the daemon log + the
> journal file + any .ips → reboot → SW.** IPA ~200.7K, markers 1:1.

> **v65 (08-09):** the v64 run (22:09, daemon 427, zero deaths) **SOLVED the −12900 mystery** — the daemon's
> `AVE_Plugin_AVC_SetProperty Exit ... -2004 -12900` lines prove the client maps the plugin's −2004 to −12900,
> so the census-listed keys were DELIVERED + value-gated, NOT client-blocked. **The gate bounds leaked verbatim**: NumberOfSlices [1,32]
> (v61's −12900 WAS the plugin reject — the kernel slice table reachable since v61), log2_max_minus4 [0,12],
> UserParameterSetsIds 'ParameterSetId <= 31' (**NO visible floor**), SoftMinQP [−12,51] = min(−6×(bd−8)),
> MaxEncoderPixelRate −2002 plugin-unsupported; new ACCEPTED (0): UseLongTermReference (the real LTR name),
> VBVMaxBitRate (the 6th hostile numeric key), DataRateLimits={INTMAX,1} (the seconds-bypass rode). **v65 = the
> GATE-BOUNDARY SWEEP**: legal-edge extremes (32 slices / log2=12 / PPS 31 / QP −12), first-past (33/13/32/−13),
> DataRateLimits={INTMAX,2} ×4 (the int64 overflow hypothesis), a VBVMaxBitRate ×8 grind, and the
> **UserParameterSetsIds={−1,−1} MISSING-FLOOR probe** (0 = −1 rides the kernel PPS-table index = the OOB read shape).
> **v67 (08-09):** the v66 run (22:39, daemon 386, zero deaths) delivered three verdicts — **(1) the PPS COUNT gate LEAKED = [0,9]**
> (`SetUserParameterSetsIds:7381 UserParameterSetIdsCount <= 9` — capped at NINE at the plugin, so OP08 {0}x33 / OP09 {0}x32 / OP10 {0}x64 all
> died −2004 → −12900 before the kernel) and **OP11 {31}x8 = 0 ACCEPTED = the FIRST multi-PPS delivery** (new FIG: `Multiple PPSs and eRCMode 1
> is not supported. Forcing the PPS count to 1` — the count 8 rode the Configure marshal into AVE_ManageSessionSettings); **(2) the −2003 TYPE gate** —
> StrictKeyFrameInterval=CFBooleanTrue → `CFNumberGetTypeID() == CFGetTypeID(pValue) | wrong property type` = **it wants a CFNumber** (the v61
> EnableUserQPMap bypass precedent); **(3) the USAGE gate** — EnableWeightedPrediction=true → **0 ACCEPTED** then the defaults path FIG'd
> `bWeightedPredictionis true and usage is default. not yet supported...` but the session **SURVIVED** (Prepare Exit 0, fp = control) = a non-default
> EncoderUsage is the escape. The RCQPRange discriminator answered: OP03 {−12,51}/OP05 {−1,51}/OP06 {−12,48} all 0/0 then **−1001 → −12902** =
> the 8-bit floor 0 rejects ANY negative SoftMin, pair-independent; SoftMax=52 → −2004 (full formula). **v67 = the USAGE-COMPOUND SWEEP**:
> StrictKeyFrameInterval CFNumber bypass (INTMAX/1/−1), EnableWeightedPrediction+EncoderUsage compound (Streaming/VideoProcessing + ×8 grind),
> PPS count edge ({0}x9/{31}x9 legal, {0}x10 first-past), and the QP-mix MinAllowed=0+SoftMin=−12 validator-floor discriminator.
>
> **v68 (08-09):** the v67 run (22:56, daemon 369, zero deaths) **DELIVERED the type-gate bypass** — StrictKeyFrameInterval=CFNumber{INTMAX} →
> **0 ACCEPTED** (the right CF type turned the v66 −2003 CFBoolean rejection into 0 = the **8th hostile numeric key** rides the marshal; OP12 −1 →
> −12900 `iStrictKeyFrameInterval >= 0` = the clamp floor is 0, TWO-SIDED) and **SPLIT the usage map** — EncoderUsage=4 Streaming → −12900
> `kVTCompressionPropertyKey_Usage 4 not supportd` = **DEAD at the plugin** (the v67 escape failed on the usage side), but EncoderUsage=1
> VideoProcessing → **0 ACCEPTED = the FIRST accepted usage** and the compound **RODE INTO THE PROCESS PATH** (`AVE_UC_Process:471 /
> AVE_USL_Drv_Process:1573 fail to process -1015` → client cb −17691); the PPS count gate [0,9] holds (9 = 0 + cb fires=2 double-fire, 10 = −2004)
> and the QP-mix discriminator ANSWERED (MinAllowed=0 + SoftMin=−12 → −12902 = SoftMin feeds the validator, MinAllowed does NOT rescue). **v68 =
> the DELIVERY-GRIND SWEEP**: StrictKeyFrameInterval=INTMAX grinds (x8 + x24 deep drain), EWP+usage-1 compound grinds (x8 + x24 of the −1015
> USL fault + the usage-1-alone control), untried usages (2 StillImage / 3 FastSource), the PPS count-9 x8 grind, and the QP-mix mirror
> (MinAllowed=−1 + SoftMin=0).
>
> **v69 (08-09):** the v68 run (23:12, daemon 391, zero deaths) **FULLY MAPPED the usage gate** — usages 2/3 BOTH → −12900
> `kVTCompressionPropertyKey_Usage N not supportd` = DEAD at the plugin like Streaming 4, **ONLY usage 1 VideoProcessing is
> accepted** — and **PROVED the −1015 USL fault is USAGE-1-DRIVEN** (OP08 usage-1 ALONE → cb −17691 with no EWP) with the
> teardown leaking **NEW receipts per session**: `AVE_BlkPool::Destroy ... -1016` + `AVE_DAL::DestroyPool:243 -1016` +
> `AVE_SEI::Uninit SEI Frame # 0` (a per-session block-pool destroy failure); the **QP-mix angle CLOSED** (OP13 {MinAllowed=−1,
> SoftMin=0} → −12902 `Incorrect BlkQPRange [-1 48]` = MinAllowed feeds a SEPARATE validator (BlkQPRange) from SoftMin's
> (RCQPRange) = per-field gates, no cross-rescue); StrictKFI=INTMAX rode x8 AND x24 clean; the PPS count-9 grind SINGLE-FIRED.
> **v69 = the USL-CHURN COMPOUND SWEEP**: usage-1 session-churns (x8 + x24 — the −1016 block-pool leak accumulation), input
> variants (420v8b/420v10/256² 2vuy), faulting-path compounds (StrictKFI/MaxKeyFrameIntervalDuration/DebugMetadataSEI), and the
> usage-gate shape (0 explicit + EWP, −1).
>
> **v71 (08-09):** the v70 run (23:50, daemons 374/382/385) **PROVED THE TRIGGER** — OP03 usage-1 420v8b-64 killed daemon 374
> 86ms into the cell (`Corpse allowed 1 of 5`, launchd exit 11), OP04 420v10-64 killed daemon 382 (`2 of 5`), and daemon 385
> SURVIVED the 256² 2vuy size-only cell + all 40 churn sessions + the beats with ZERO deaths = the **420-family input is the
> daemon-SEGV trigger (single session, single frame)**; 2vuy never kills; the churn is EXONERATED; the −1016/SEI leak is
> fault-path-specific; the width-0 pixel-pool beat receipt is a benign 1×1 quirk; and DebugMetadataSEI's gate is a **CFBoolean
> TYPE gate**. **v71 = the FORMAT-TRIGGER ISOLATION + USAGE-GATE SWEEP**: isolates the kill geometry (420v8b-256/420v10-256/
> 420v8b-32 crosses), re-confirms both killers, shoots the SEI key with the right CFBoolean type, compounds killer+SEI, runs
> THE USAGE DISCRIMINATOR (usage-0 + 420v8b-64), and escalates the killer into a x4 churn (the deterministic-crash primitive).
>
> **v72 (08-10):** the v71 run (00:12) **CRASHED THE DAEMON 11 TIMES**; the two pulled reports — `001212` (pid 432 = the 420v8b-32
> geometry cell, captureTime 00:12:11.3534) and `001253` (pid 485 = the killer-churn session 1, 00:12:53.2200) — are BOTH
> `_platform_memmove <- vt_Copy_420v_Crop` faulting at **0x0 (NULL read)**: the input-scaling blitter memmoves from a **NULL src row**
> (dissected: `x1 = src-row-array[i] = 0x0, x2(len) = 64`), **PRE-AVE** — the −1015 USL fault is a SEPARATE benign usage-1 fault.
> **v72 = the NULL-ROW ISOLATION + BLITTER DISCRIMINATION SWEEP**: rebuilds the killer 420v8b-64 input CORRECTLY (planar-bytes
> explicit 2-plane + IOSurface-backed real-app path) to discriminate the NULL's source — clean = our CreateWithBytes biplanar layout
> was the malformed half (a sandbox-app → daemon NULL-memmove DoS); still-0x0 = a GENUINE VideoToolbox bug — plus session@64²
> (blitter-required), Trim/Letterbox chain-geometry levers, a 2vuy+Trim control, the 420v10 + 420v8b-256 re-confirms, the usage-0
> discriminator, and the killer x4 churn (the pb census line = the NULL-plane oracle).
>
> **v73 (08-10):** the v72 run (00:48) **CRASHED THE DAEMON ~12 TIMES** and **ANSWERED THE DISCRIMINATOR**: the pb census
> proved the NULL plane is **CLIENT-side** — every mode-0 (CreateWithBytes) 420v buffer reports `planes=0 p1=(nil)` while
> planar-bytes + IOSurface report `planes=2` valid — so the daemon's `vt_Copy_420v_Crop` NULL-memmove is OUR missing-plane
> construction = a **LEGAL-API sandbox-app → daemon DoS** (public APIs), NOT real-app reach (AVFoundation = IOSurface = safe),
> NOT a kernel OOB. usage-0 does NOT rescue (the format alone kills); the x4 kill-churn killed 4 fresh daemons ~120–160ms each =
> the deterministic primitive; `Corpse failure, too many 6` = the forensics defeat (reports stop after ~6 rapid deaths); the
> v72 Trim/Letterbox levers were NO-OPS (−12900). **v73 = the CLEAN-WINDOW DISCRIMINATOR + DOS-CADENCE SWEEP**: re-runs the
> planar/IOSurface discriminators on a guaranteed-clean daemon (v72's verdicts were dead-window contaminated), the mode-0 killer
> contrast, sess64/usage-0/Letterbox re-runs, the **x8 kill-churn** (per-session death latency), the killer+SEI compound, and the
> DPB mechanism control — with the scaling lever re-armed via the `PixelTransferProperties` sub-dict.
>
> **v74 (08-10):** the v73 run (07:27) **CLOSED the NULL-plane DoS surface** — OP03 planar-bytes = **−19643** (the daemon-side
> deserializer rejects the correct 2-plane construction), OP04 IOSurface = **−17691 NO death** (the real-app path is SAFE), the
> mode-0 kills + the `planes=0 p1=(nil)` client-side census pin the NULL to our missing-plane construction (legal-API DoS, not
> kernel-reachable), and OP13 killer+SEI = **NO death** (the DebugMetadataSEI slot SUPPRESSES the NULL-row crash). **v74 = the
> UNGAITED KEXT MARSHAL-FIELD SWEEP**: dissecting `driver+binaries/` proved the transfer map (app → XPC → ave.videoencoder →
> `IOConnectCallStructMethod(S_AVE_UCInParam_Config)` → AppleAVE2 `AVE_UCCmd_CheckParam_Config`); the kext logs 6 marshal fields
> with NO value gate (MotionVectorSize / MCTFEdgeCount / InitialRCSegmentCtxSize / InsertTrailingBytes / FilterGroupSize /
> AmbientViewingEnvironment) and the AVC MCTFEdgeCount setter's ONLY gate is `iEdgeCnt >= 0` (**ONE-SIDED** — INTMAX rides the
> Config marshal into the kext ungated = the kernel MCTF edge-sizing OOB shot); the HDR CFData props (AVE 8 dwords / CLL 4 dwords,
> the latter a PUBLIC SDK key) sweep lengths past the plugin 'invalid size' gate into the kext's fixed-width copies; the x4 churn
> escalates the cadence. A device REBOOT = PANIC = THE 64747 kernel OOB.
>
> **v75 (08-10) = the CORRECT-CHANNEL SWEEP**: the v74 run (08:08) **PROVED the channel split** — the
> census oracle shows the BARE `AmbientViewingEnvironment`/`ContentLightLevelInfo` **IN-LIST** while the
> `kVTCompressionPropertyKey_`-prefixed variants are **BLOCKED** (the v74 HDR cells self-blocked with the
> prefixed names — every OP08–12 = −12900, never left the client); **InsertTrailingBytes REACHED the
> plugin** (the daemon log: `AVE_Prop_HEVC_SetInsertTrailingBytes:9317 CFDataGetTypeID() == CFGetTypeID-
> (pValue) | wrong property type … -2003` with our hostile value riding in) = the setter **WANTS CFData**
> (the CFNumber shot hit the TYPE-gate); **MCTFEdgeCount NEVER forwards via SetProperty** (the daemon VT
> wrapper −12900 at VTCompressionSession.c:4958, no AVE_Prop line) = dead on that channel. v75 fires the
> CORRECT channel: bare-name HDR CFData 24/32/33/64 + 16/4096/8192 (the kext's fixed 8/4-dword copies),
> CFData-typed InsertTrailingBytes 1/65536 (the count rides the kext `%p %lld InsertTrailingBytes %d`
> marshal).
>
> **v81 (08-10) = the MCTF-KERNEL-DELIVERY SWEEP**: the v80 run (10:35) delivered the FIRST MCTF format-sweep KILL - a fresh .ips = `vt_Copy_x420_Crop` NULL-source memmove (VideoToolbox +0x1B578) on the preparationQueue during OP08 TRUE 10-bit x420 byte-backed 64x64 -> 1920x1080 scale transfer; daemon 357 died mid-cell, daemon 371 respawned and finished with all remaining cells ImgBuf -17691-gated = the SCALE-TRANSFER chain is the crash site, not the MCTF kernel parse. The user-prepared file deep-read (the REAL videocodecd daemon, the AppleAVE2 kext, VideoToolbox, IOKit): the plugin format table @0x2b95d0d88 accepts 420v/420f/x420/xf20/422v; the kext MCTF kernel parse EXISTS (AVE_MCTF_SMap_Parse); vt_CopyAvg_2vuy_x420 exists. v81 = MATCHED-SIZE 1920x1080 buffers (the scale chain GONE) + NO-TX (AllowPixelTransfer=false via the LOCAL ds_kAllowPixelTransfer key - the SDK constant is macOS-only) + the VEPBA encoder-input format pin + IOSurface-backed x420 + the PINNED 2vuy->x420 arm. The decisive receipt: ok=1 encode with NO ImgBuf line = the hostile MCTF values finally RIDE the S_AVE_UCInParam_Config marshal into the kext parser; a PANIC/reboot = THE 64747 kernel OOB. POST-BUILD RECT-FIX (before first run): v81 v1 fed a SQUARE 1920x1920 buffer into the 1920x1080 session = the transfer chain stayed ALIVE (the NULL-p1 blitter class could still fire); the fix adds inH=sessH so every MCTF cell feeds a MATCHED 1920x1080 buffer (the "scale chain GONE" claim is now TRUE - the daemon log proves the sessions are 1920x1080). Plus the NO-TX-failure GUARD: if the AllowPixelTransfer=false set fails (noTX!=0), the byte-backed biplanar cells (mf 2/3 - the 11:06 v80 census PROVED the planes=0 p1=NULL shape) VOID with a receipt instead of re-firing the known vt_Copy_x420_Crop NULL-memmove crash; the mf4 IOSURF + mf1 2vuy cells carry the test.
> **v80 (08-10) = the MCTF-FORMAT-FIX + KERNEL-CONSUMPTION SWEEP**: the v79 run (10:05) VERDICT = ALL FOUR MCTF channels DELIVERED but the encode hit the NEW pre-kernel gate `AVE_ImgBuf_Verify:444 pixel format is not supported 875704438` (=420v) -> -17691 = the MCTF config flips the session source format to 420v and the verify rejects it = the INTMAX edge count + the 30 hostile strength slots NEVER reached the kext; AND the -12909 decode class is DEFINITIVELY CLOSED with the mechanism (AppleAVD `parseHevcNALUs(): NALU bad size! 1515870810` = 0x5a5a5a5a = our trailing bytes read as a NAL length prefix -> protective rejection, not a bug). New kind DS_OPT_MCTF_FMT fires the SAME MCTF config on (1) 2vuy + create-time source hint, (2) TRUE 10-bit 420v, (3) 420v8b planar-bytes. OP14 = the MCTF-ARM x4 session-churn. The decisive receipt: ok=1 encode with NO ImgBuf line = the hostile strengths RIDE into the kext; a PANIC/reboot = THE 64747 kernel OOB.

> **v79 (08-10) = the MCTF-PARAMS ARRAY FULL-FIRE + STRENGTH-SPEC SWEEP + COMPOUND-REFEED HAMMER**: the v78 run (09:35) VERDICT = OP07's TB-COMPOUND REFEED produced the **first-ever decoder error -12909 kVTVideoDecoderBadDataErr** (v77's SEI-only refeeds all DECODED) = the 512 trailing bytes perturb the decoder NAL parse = the compound NAL is bad-data-not-crash; the TB-EMITTER GRINDS ran 48 frames × 512B with zero deaths; `EnableMCTF=true` DELIVERED but on AVC where MCTF is use-time-blocked. v79 fires the **MCTFParams CFArray x600 full-fire** (the plugin's `AVE_Prop_HEVC_SetMCTFParams` parses a FLAT CFArray by fixed indices into session+0x8C8 = all 30 attacker strength slots ride the marshal), the **MCTFStrengthLevel SPEC sweep** (INTMAX/25 past the setter's 0..24 gate = the kext array-index OOB candidate), and the **compound-refeed hammer x8/x16** (the -12909 bad-data NAL parsed repeatedly). 15 cells + 2 beats = 17 ops.
>
> **v78 (08-10) = the TB-COMPOUND REFEED + TB-EMITTER GRIND + MCTF ENABLE-ARM**: the v77
> run (09:07) VERDICT = all four SEI-REFEED SELF-DECODE cells DECODED with ZERO daemon deaths =
> **the decoder tolerates the truncated ST2094-40 SEI (8B AVE / 4B CLL / 24B MDCV)** — the
> decode-side SEI-parse class is CLOSED. The kernel push goes through the only fully-live count
> channel: **InsertTrailingBytes** (v75-77 all DELIVERED; the count rides the kext's
> `%p %lld InsertTrailingBytes %d` Config marshal at 3 kernel sites). v78 fires the
> **TB-COMPOUND REFEED** (TB512 + AVE8+CLL4+MDCV24 on one session = hostile SEI + 512 trailing
> bytes on one NAL → refeed), the **TB-EMITTER GRINDS x8/x16/x24** (the kext NAL emitter copies
> 512 trailing bytes per frame = the repeated kernel copy), and the **MCTF ENABLE-ARM**
> (EnableMCTF=true + the MCTFEdgeCount=INTMAX SPEC dict — the kext MCTF config parser
> +0x408..+0x498 consumes it). IOKit transfer re-verified: `IOConnectCallStructMethod`
> @0x19252661c. A decoder death/.ips in OP07 = the compound parse OOB; a PANIC/reboot = THE
> 64747 kernel OOB.
>

> **v62 (08-09):** the v61 run (20:52–20:53) was the **first delivery since the campaign
> began** — **LookAheadFrames=INTMAX → 0 ACCEPTED** and **MaxKeyFrameInterval=INTMAX →
> 0 ACCEPTED** (no gate line, no error): the raw-key session-prop channel packs the
> hostile values into the kernel-bound config struct. The daemon log proved 4 keys are
> delivered-then-plugin-gated (MaxAllowedFrameQP/SoftMaxQuantizationParameter
> `[-12, 51]`, SpatialAdaptiveQPLevel `[-1, 0]` via −2004; EnableUserQPMap **TYPE-gate
> −2003 — it wants CFBoolean**), 5 are client-blocked (`Unsupported property key`),
> InputPixelFormat=0x7FFFFFFF is value-gated (−12902), and the **OP14 DPBRequirements
> mechanism control = −17691 exactly** (channel anchored). **v62 = the DELIVERY shots**: OP02/03
> LookAheadFrames=INTMAX ×8/×24-frame grinds + drains (push the kernel lookahead ring
> alloc), OP04 the compound (both keys, one marshal), OP05 MaxKeyFrameInterval ×16, OP06
> EnableUserQPMap=kCFBooleanTrue (the type-gate bypass), OP07–09 UserQPMap=CFData
> {1/32640/32641B} (kernel UserQpMapSize gate — 32640 = exact = the feature ACTIVATES
> with attacker bytes), OP10/11 real-FourCC InputPixelFormat (`'v308'`/`'BGRA'`), OP12
> control. **12 cells + 2 beats = 14 ops.** A PANIC/reboot on any cell = the 64747 kernel
> OOB = the goal. **RUN: reboot → OP FIRST, ALONE (14 ops) → pull → reboot → SW (19 ops)
> → pull ALL .ips + FULL log + journal.** IPA ~202.5K, markers 1:1.

> **v61 (08-09):** the v60 run (20:29) fired **6 daemon deaths** — SW04 (4096² sess +
> 256² 420v8b input) killed **TWO fresh daemons** (B-class `vt_Copy_x420_420v` @0x1 re-fire),
> SW14/16/17/18 (5952² 420-family fmt=2/1 same-size) killed one each (daemons 447/461/476/490)
> — the RE-KILL cells are live again. The log pinned the **plugin resolution gate at ≥4480²**
> (`AVE_Session_AVC_StartSession:4286 resolution is out of range` → -2001 → -19354 on
> 4480²/4608²/5120²; 4096² = the last HW-reachable square); SW08 8192² = the -21772
> pixel-transfer storm (`vtScaler_ValidateRect` width 128 > fullWidth 0). **NEW KERNEL
> VECTOR**: `kernelcache.release.iPhone17,5` (77.5 MB) is in the extraction and contains
> the **AppleAVE2 kext + AppleAVE2UserClient** with the kernel-side gate catalog
> (`%lld %d AVE %s: ... <Prop> %d` for `DPBNumberOfFrames`/`NumberOfSlices`/
> `SourceFramePixelFormat`/`STRNumOfBFrameL0/L1`/`STRNumOfPFrame`/`MotionVectorSize`/
> `EnableUserQPMap`/`UserQPMap`/…). **v61 = the SESSION-PROP KERNEL-GATE SWEEP**: the
> daemon plugin's `AVE_Prop_AVC_Set*` dispatcher (all 11 kernel-vector getters verified
> in the .71 slice: `InputPixelFormat`, `LookAheadFrames`, `NumberOfSlices`,
> `RefNumOfBFrameL0/P`, `VBVBufferSize`, `MaxAllowedFrameQP`, `SoftMaxQuantizationParameter`,
> `EnableUserQPMap`, `InitialQPI`, `MaxKeyFrameInterval`, `SpatialAdaptiveQPLevel`)
> receives **raw key literals via `VTSessionSetProperty`** — the only channel proven to
> forward into the AVE plugin (the v57 DPBRequirements forward). OP01 control, OP02–13
> the 12 hostile values (INTMAX/255/0x7FFFFFFF), **OP14 = DPBRequirements=INTMAX
> mechanism control** (known forwarder — expect the -17691 pcVCP gate; proves the
> raw-key channel still works THIS run). **14 cells + 2 beats = 16 ops.** The receipt
> `AVE prop set <key>=<val> -> 0` = the value packs into the kernel-bound struct (watch
> the `AVE_Prop_AVC_Set<key>` line in the daemon log); -12900 = not in the daemon
> supported list; **a PANIC/reboot = the kext OOB = THE 64747 goal.** SW row unchanged
> (17 cells + 2 beats = 19 ops — the 6-death RE-KILL set re-fires on the fresh daemon).
> **RUN ORDER: reboot → OP FIRST, ALONE (16 ops) → pull journal + log + .ips → reboot
> → SW (19 ops) → pull ALL new .ips + FULL log + journal.** IPA ~201.2K, markers 1:1.

> **v60 (08-09):** the v59 run (20:13) fired all 9 cells + 2 beats cleanly and settled
> the FIG-line question — **ZERO `FIG:` lines in the full 20:13 daemon window even for
> the PUBLIC `kVTEncodeFrameOptionKey_*` names** — the per-frame option channel is
> closed at the client for both namespaces (the option-smuggle campaign v57→v59 is
> done). The user pulled the device: **25 .ips now on the Mac** — 13× H264SW `+0x16dfc0`
> (fault `0x2232b47` wild, CompleteFrames drain), 7× `vt_Copy_x420_420v` (fault 0x1),
> **1× H264SW `+0x1709ac` (fault 0x0 = NULL-memmove in the ENCODE path — 08-09 00:49,
> NEW class)**, 1× `vt_Copy_420v_Crop` (fault 0x0, v29 crop). **The v14 recipe
> recovered**: NULL-spec giant dims + SAME-SIZE byte-backed `3·in²` backing declared
> 420v8b (fmt=2 mis-declared) at 5952²/5984² — killed at the CompleteFrames drain. The
> 2vuy ladder reached H264SW ok=1 without crashing — fmt=2 same-size was the missing
> ingredient. **v60 restores the RE-KILL (SW14–18)** + the v29 CROP re-kill (SW18). The
> `0x2232b47` wild store is the closest corruption primitive in the campaign. **RUN:
> reboot → OP (11 ops) → pull → reboot → SW (19 ops) → pull ALL .ips + FULL log +
> journal.** IPA ~200.7K, markers 1:1.

> **v59 (08-09):** the v58 run (20:01) fired all 9 cells cleanly, but the DPB-after shot
> died at the **SAME -17691 pcVCP gate even after a warm-up frame** — the warm-up does
> NOT cure the gate; DPBRequirements is closed at that layer (the OP02–05 fp delta
> `0000005121e1047fcdf4e8ac` = the frame-2 P-frame artifact, identical across the rejected
> INTMAX/18/17/1 — NOT a delivery signal). **THE v59 TURN (recon-proven):** the
> ave.videoencoder string catalog shows the daemon's per-frame FIG getter **reads the
> PUBLIC `kVTEncodeFrameOptionKey_*` names** (`SetDPB` → the UserDPBFrames 2..17 gate,
> `SliceQP`, `PicParameterSetId`, `VRAUsedDimension`, `RequestNonReferenceFrame`,
> `FinalFrame`, `ForceRefresh`) — the `AVE_kVT...` private keys of v57/v58 **never
> produced a `FIG:` line in the daemon log = stripped CLIENT-side**; the "surface closed"
> verdict covers only that stripped namespace. **v59 sends the public names**: OP02
> SetDPB=INTMAX / OP03 SetDPB=CFArray 32× INTMAX / OP04 SliceQP=CFArray 128× INTMAX /
> OP05 PicParameterSetId=255 / OP06 VRAUsedDimension={8192,8192} (SM02–04 already sent it
> fp-identical — delivery unproven; OP06 settles it) / OP07–09 the flag keys —
> **9 cells + 2 beats = 11 ops**. **THE ORACLE = the daemon log**: a `FIG: received
> kVTEncodeFrameOptionKey_...` line near a cell's stamp = the key REACHED the FIG getter
> (channel LIVE — watch the UserDPBFrames/SliceQP/PPS/VRA gates); NO FIG line = stripped
> at the client = the per-frame surface is done. **RUN ORDER: reboot → OP FIRST, ALONE →
> pull the FULL daemon log window + journal + .ips → reboot → SW.** IPA ~201.6K, markers
> 1:1.

> **v56 (08-09):** the v55 run (18:40–18:42) produced **4/4 witnessed daemon kills**,
> all below the ~5120² StartSession gate (SW01 1080p fmt=2 B2 #4, SW09 4096², SW10
> 4K-sess — daemon 403 died 4 ms after Prepare, SW11 1080p fmt=1 — daemon 417 died 60 ms
> after Prepare, the 010417 `vt_Copy_x420_420v` family); corpse counts 2/3-of-5, ZERO
> .ips synced to the Mac — **pull ALL .ips off the DEVICE + the log window** (the
> reports live on-device). **THE B-CLASS KILL-WINDOW IS PROVEN:** any session dims
> below ~5120² + a tiny byte-backed 420 input (fmt=1 or 2) = **deterministic daemon
> death** (the v30 '-12912 ≤ 4096²' entries were deaths, not breaks). **5120² gate
> pinned daemon-side** (`AVE_Session_AVC_StartSession:4286 resolution is out of range`
> → -2001/-19354; the -21772 receipt = the scaler reject firing first). The -21772
> storm daemon-side trace confirmed; the 2vuy ladder 5/5 (level-6.0 maxFS 139264
> pinned). **SM row CLOSED by the fp oracle** (SM01-04 all = the HW-control fp
> constant — the VRA/RVRA dim smuggle never reaches the encoder). **OP = the last
> standing kernel vector** (RefL0=1/9 inert, then EPOCH-EXHAUSTED — OP04-13 unshot).
> **RUN ORDER: reboot → OP FIRST, ALONE (the oracle row: RefL0 INTMAX/16 OOB +
> NaluType/TemporalID/ResetRC discriminators + DPB family + the 2..17 under-probe) →
> reboot → SW** (the kill-window map: 4 kill re-confirms + 4480²/4608² window probes +
> the 5120² gate re-confirm + the storm + the 2vuy ladder + controls); 13 + 2 beats =
> 15 ops each (30 > the 24-op epoch cap — they cannot share a session).

> **v54 (08-08):** the TWO v53 runs (14:44 + 14:46) produced **ZERO new .ips = ZERO
> daemon deaths** — B1/B2 missed the fresh-start race 2× (v52 hit) and the v51 H264SW
> NULL-memmove missed a 3rd time. NEW deterministic v53 finding: **fmt=2** (mis-declared
> 8-bit `'420v'` + 3·in² backing, the FINDINGS:638 state) does **NOT** frame-1 break —
> es=0, ALL frames run, every output callback **err=-21772** (private byte-backed
> 2-plane-420 drop code; the -2177x family = daemon/AVE layer, same family as the
> -21776 height gate). v54 SW row: SW01 = the **exact 08-08 14:18 B2 config** (1920×1080
> sess + 256² byte-backed 420v input ×1) FIRST-OP on the fresh daemon (the B-class
> first-transfer race window) + B2-shape grinds + the -21772 sustained cluster + giant
> grinds (pressure toward the v51 8.6GB MALLOC state) + the back-to-back 420v10×32 →
> 420v8b×8 kill-seq twice. 13 cells + 2 beats = 15 ops. Pull ALL new .ips.

> **v53 (08-08):** the v52 run **reproduced B1 byte-identical** —
> `videocodecd-2026-08-09-010417.ips` (01:04:17.08): fault **0x1**, `vt_Copy_x420_420v`
> on the preparationQueue, `atPC` **== the 22:46:49 B1 hit exactly** (B1 is
> instruction-deterministic like the 13×). Daemon born 01:04:16.94 (crash-loop
> respawn) dead 0.14s later; **consecCrash 5 = ≥4 invisible deaths** while every
> receipt said `-12912 'graceful'` — **receipts are unreliable; pull ALL new .ips and
> correlate stamps against captureTime**. The crashed daemon was born after SW06's
> session began → the daemon serving SW06 died mid-wait and the respawned daemon died
> on its **first pixel transfer** = the B1 crash-loop self-feed. Correlate SW06
> (5952×5984 sess + 5952² input 420v10 ×32), but 'mixed-dims = trigger' vs
> 'crash-loop window = trigger' are equally supported — v53's SW04/05 same-size 420
> cells are the **falsification test**. The v51 H264SW NULL-memmove (004907) did NOT
> replay; the -10279 gate doesn't apply to the 420 class. v53 SW row = 13 cells + 2
> beats = 15 ops.

> **v52 (08-08):** the v51 run **CRASHED THE DAEMON for the first time since the 13×** —
> `videocodecd-2026-08-09-004907.ips` (00:49:06.97): fault **0x0**, `_platform_memmove`
> (src=NULL, len=5952) ← H264SW +0x1709ac/+0x16f4f8/+0x16e1fc/**+0x16e974**/+0xdd38 ←
> `vtCompressionSessionCompressionWork` — and **+0x16e974 is one of the two known 13×
> callers** (faulting +0x16dfc0): the 13× family is **alive as a NULL-memmove**, its 2nd
> manifestation. The client receipts said `-12912 'graceful'` while the daemon died —
> **daemon deaths are invisible to client receipts**; only `.ips` captureTime + the
> `consecutiveCrashCount` (3 in this .ips = it had died ≥2× earlier in the same run)
> witness them. Trigger: 5952² 420v10 ×32 + 420v8b ×8 back-to-back on a memory-loaded
> daemon. v52 SW row = 13 cells (isolation on the fresh daemon, kill-sequence replay,
> bisect/grind/over-cap) + 2 beats = 15 ops.

> **v51 (08-08):** the **repeat-run determinism map** is in (two v50 runs): **SW12/SW16
> (tiny-input ×32) break EncodeFrame at frame 23 in all 4 runs** (input-size
> independent), **SW13/14 (420v10) break at frame 1 every run**, SW08 (×16) is the racy
> coin-flip, SW10 (×32) never breaks — all graceful MalfunctionErr, **still zero daemon
> crashes** since the 08-07 H264SW era. The `-10279` gate is **consistent with the
> level-6.0 maxFS (139,264 MBs): 5952² legal, 5984² over** — 5952² is the largest legal
> square = the v14 crash-band edge. **v51 restores the B1/B2 daemon-start window**: SW01
> = 1920×1080 + 420v10 ×1 FIRST-OP on the fresh daemon (the byte-backed 2-plane-420
> class that fired 6 vt_Copy NULL-plane hits on 08-08 — v48's 2vuy switch had killed
> the trigger), SW02 = the v14-exact 5952² + 420v10 single-frame drain in the same
> window, SW15 = the pre-v50 mis-declared `'420v'` variant, SW17 = broken-session reuse.
> SW epoch 19 ops.

> **v50 (08-08):** the v49 run **corrected v48** — SW08 (×16)/SW10 (×32) at 5952² were
> CLEAN; the "MalfunctionErr under multi-frame pressure" was a one-off. The break is
> **shape-specific**: SW11 (5952×5984 ×16) = 6/16 MalfunctionErr **via the callback**
> (es=0 — the new CB-level receipt prints okf/fires + the actual err), SW12 (5952²+256²
> ×32) = EncodeFrame `-12912` at frame 23. **v50 restores the v14-exact byte-backed 420v10
> multi-frame cells** (SW13 ×8 / SW14 ×32 at 5952² — only ever single-frame since v14)
> with a reviewer-fixed true 10-bit `'x420'` constant, pushes the cb-level break to ×32
> (SW15, mid-loop drains every 8), and adds a real **64×64** tiny-input grind (SW16, shape
> 3 — the old shape-1 256 duplicated SW12). SW epoch 18 ops.

> **v49 (08-08):** the v48 run was a landmark: a **campaign correction — `-12912` is
> `kVTVideoEncoderMalfunctionErr`** (the SDK has no "unsupported" constant — every
> "-12912 drop" reading was the encoder malfunctioning), **SW08 (5952² ×16 2vuy)
> produced 13 MalfunctionErr callbacks** = the SW encoder breaks under multi-frame giant
> pressure (closest state to the v14 drain crash), SW01 (sane-dims 2vuy) hit the **HW
> AVE `ok=1`** = kernel delivery proven, 5984²/8192² reject `-10279` (a daemon dims gate
> between the two v14 crash dims), and SM01-04 + OP01-13 all `ok=1` but byte-identical =
> the dim/option smuggle is **inert**. v49 adds the **`fp=` delivery oracle** (first bytes
> of each encoded sample — proves whether the smuggled options changed the stream or
> were stripped) and SW grind cells (×32 with mid-loop drains, mixed-dims ×16).

> **v48 (08-08):** the v47 run CLOSED the input-class question — **byte-backed 2vuy
> (`422YpCbCr8`) is THE reachable class**: SW07 (5952² SW session) encoded a frame
> (`ok=1 bytes=6948` — first H264SW encode at the v14 dims since v14), while every
> sys-alloc 420v/420f input is a `-19640` void in both paths. So **the SM (DIM-SMUGGLE)
> and OP (OPT-SMUGGLE) rows now ride 2vuy** — the VRA dims and per-frame option family
> finally reach the AVE gates at sane dims (HW id) = the AppleAVE2 kernel target; the **SW
> row is all-2vuy with multi-frame drains** (×8/×16) = the v14 CompleteFrames shape for
> the 0x2232b47 replay.

> **v47 (08-08):** the v46 run was a breakthrough — the `EncoderID` readback PROVED the
> NULL-spec fallback selects the **SW H.264 encoder at giant dims** (`anon-1` = H264SW on
> all 8 giant cells; HW id at sane dims). But every input dropped `-12912` (byte-backed
> 420v10, G11) or `-19640` (420f) BEFORE the encoder, and the guard-page cell faulted
> CLIENT-side — the input class was the void, not the encoder. v47 feeds **REACHABLE
> inputs** (sys-alloc 420v/420f, byte-backed 2vuy) into the SW path at 5952²/5984²:
> `ok=1` / `bytes>0` / a non-drop err on a giant cell = the frame reached the SW encoder's
> drain = the 0x2232b47 replay precondition.

> **v34 reset (08-08):** all v14–v33 probe rows were DELETED per request ("delete
> absolutely everything… starting from blank list"). v37 restored two proven rows and
> added three RE-driven families from the `driver+binaries/` set (see `FINDINGS.md` §12
> for the AppleAVE2 / H264SW / ave.videoencoder / MediaRemote / SceneKit / ImageIO
> reverse-engineering notes). Advisory mapping per the 26.6/27.0 bulletins: MediaRemote
> path-handling = **28973**, SceneKit = **43723**, AVEVideoEncoder = **64747**, ImageIO =
> **64740**.

### Build & run on iOS

```sh
# build + package (macOS; the user sideloads/installs the IPA)
xcodebuild -project DirtySlide.xcodeproj -scheme DirtySlide -configuration Release \
  -sdk iphoneos -derivedDataPath /tmp/ds_dd build CODE_SIGNING_ALLOWED=NO
# zip /tmp/ds_dd/Build/Products/Release-iphoneos/DirtySlide.app into DirtySlide.ipa (see AGENTS.md)

# launch on device with console streaming:
xcrun devicectl device process launch --device $CORE_DEVICE_ID --console --no-activate $APP_BUNDLE_ID
# (Linux/Windows: pymobiledevice3 developer dvt launch --stream $APP_BUNDLE_ID)
```

### Current headline evidence (28 `.ips` in the repo root)

- **FIRST DEVICE PANIC (08-10 12:54:51)** — `panic-full-2026-08-10-125451.0002.ips`: the v84
  UPS-count-21 USL-wedge cascade (OP07/OP11 wedged the kext USL FrameReceiver → daemon RPC-kills
  380/590 → OP12 left SpringBoard's main thread hung → watchdog kills 12:52/12:53 → watchdog
  timeout panic fired from **AppleAVD(988.0)** with **IOSurface** a dependency, videocodecd
  pegged at 4,954,987 cpu_usage. Kernel-level impact (full reboot) — DoS-class, the OOB shot is
  the v85 gate-bypass run.

- **08-10 23:52 (v105→v106) AVE multipass KERNEL DELIVERY** — kernel log: session 30
  `Pass: 2 + RCMode: 20 + MultiPassStorage 0x73a38ac0c0 ATTACHED + RCQPRange [0,51] +
  EnableUserQPMap 1` then kernel Reset reject `-1015 invalid frame queue index`;
  session 40 `MaxAllowedFrameQP 51 / MinAllowedFrameQP 0` kernel-visible. NEW lethal
  client kill: `VTCompressionSessionRemote_Invalidate` blocked on the dead FigRPC
  connection (`FigSemaphoreWaitRelative`) + death-callback wild-jump into freed heap
  = `CODESIGNING/Invalid Page` SIGKILL (uncatchable by the guard). v106 ships
  poison-guard teardown (never Invalidate once poisoned; bounded leak; 1-wedge sweep cap).
- **08-11 00:19 (v105→v107) session-CREATE KILL + delivery** — kernel log: OPC0's
  2-frame sweep shots rode the kext (sessions 40/50/60 `Pass: 2` + `MultiPassStorage
  0x7c1af200c0` ATTACHED + `RCQPRange [0,48]`; 70/80 `Input: 0 0` = daemon stopped =
  the wedge). The kill moved from Invalidate to **session-CREATE**: the next cell's
  `VTCompressionSessionCreate` **hung in `mach_msg` inside the guard** (no signal =
  never caught) + a **pc=0 death-callback wild-jump** (`__CFStringCreateImmutableFunnel3`)
  = `CODESIGNING/Invalid Page` SIGKILL (uncatchable). v107 ships **sticky poison**
  (cell-gate - never create on a dead conn) + a **10s guard watchdog** (SIGALRM
  `pthread_kill`, epoch-checked, never-restored swallow handler) converting any hang
  into a caught fault.
- **08-11 00:37 (v107→v108) STACK-SMASH at session-CREATE + delivery** —
  kernel sessions 40/50 `Pass: 2` + `MultiPassStorage 0x75a2e88780/88600` ATTACHED +
  `RCQPRange [0,48]` (4th delivery run; v107's watchdog + sticky poison held) then the
  next create **smashed a stack buffer in the FigRPC plist path**
  (`__CFBinaryPlistWriteOrPresize`, `asi: "stack buffer overflow"`, pc=0 wiped frame =
  `CODESIGNING/Invalid Page` SIGKILL, uncatchable — the v102 class reappearing at
  CREATE). v108 ships **per-shot journaling** (`ds_journal.log` START/DONE — a death
  leaves START w/o DONE = the exact dying byte/size the `.ips` cannot name) + a new
  **OPD0 blob-SIZE oracle** (shuffled {512..32640}, one 0xFF multipass shot each) to
  discriminate size-driven vs count-driven on the Apple overflow.

- **08-11 09:44 (v108→v109) COUNT-DRIVEN, cross-thread, SIGBUS** — OPD0's blob-size
  oracle rode **all 8 sizes** (512..32640) clean, then OPC0's byte sweep died at
  shot **0x7a = the 122nd create** (journal START w/o DONE). The death:
  `EXC_ARM_DA_ALIGN` SIGBUS on **Thread 5 — a non-probe CoreMedia/FigRPC worker**
  (empty frames, pc = odd address inside its own stack, fp/lr wiped) = smashed-frame
  return-through-garbage off the probe thread. **Size-vs-count answered:
  count-driven create-accumulation** (the same class as the 00:37 FigRPC plist
  stack smash and the 08-07 H264SW ~2-3-shot kills). v109 ships the **FOREIGN-FAULT
  WITNESS** (guard handler re-raises out-of-guard/foreign-thread faults via an
  async-signal-safe write + SIG_DFL + raise, so the `.ips` stays clean instead of a
  UB cross-thread siglongjmp garbage jump) + the **OPC1 fixed-byte count oracle**
  (0x7a ×256 on a fresh conn, journaled with the count — dies at ~122 = count
  confirmed; survives = byte value matters).

- **08-11 (v113) QPMAP-FIRST**: the 11:09 v111 run died at OPC1b n039 (0x41 count-death #2,
  no .ips - the uncatchable SIGKILL class) but OPC1b ran FIRST, so the CVE-64747 oracles never
  executed. v112 runs OPC3 (stats-frameNumber x16) + OPC4 (UserQPMap size-match 1080p+4K) on the
  fresh conn first (~30 sessions, under the 39-55 death window) with [alive] phase beats +
  phys_footprint, then OPC1b x96 as the count-death tail. Also corrected the v110 over-read:
  "0x41 rode in OPD0" was unproven - OPD0's DONE tag is rode-or-reject ambiguous; 10:35 proved
  every byte rejects at EndPass. OPC4 death with after-OPC3 beat ALIVE = the QP-map overflow live.
- **08-11 (v117) TYPE+VALUE CONFUSION**: the 12:41 run's 3x videocodecd .ips (crash
  storm, consecCrash=12) all = `-[__NSCFArray _getValue:forType:]` SIGABRT in
  `AVE_GetPerFrameData` - the v116 bare `SliceQP` CFArray twin hit an unconditional
  typed getter. Kernel log shows `EnableUserQPMap 1` + `QPModFeature 0x10202` on every
  session = the user-map memcpy gate can FIRE. OPC5 = TYPE+VALUE sweep + KILLED
  verdicts; the daemon-abort at T1 is a 100% reliable `.ips`-producing primitive.
  incl the 25x-mismatch M1 = the fp-dict UserQpMap never reaches PrepareMBInputCtrl's
  == gate; the client key table (VideoToolbox) reads BARE names while the daemon
  expects FULL names; OPC5 now rides the map as a PB attachment (the v95 OP87 'dual'
  carrier - the only untested channel) + fp twins + bare SliceQP twin + both
  EnableUserQPMap spellings + valid 0x33 fill so a LAND is visible in the output size
  vs C0; M1/M2 = the dims-mismatch memcpy overflow attempt.
- **08-11 (v115) BINARY-READ + CUT + EXACT-GATE**: the 11:58 run proved the frame-options channel rides (kernel session ID 150, QP 26 26 26) but every 4K size missed the real 522240 req (the ave.videoencoder disasm: gate ==, unguarded memcpy, AVC dev>=29 4K req = 522240); OPC1 rode 96 clean = the count-death window theory is dead; CUT the 4 dead sweep functions + 9 dead driver cells; OPC5 = exact-gate cb-verdict attack with C0 transport oracle + M1/M2 dims-mismatch overflow attempts
  channel DEAD (12/12 rejects @~15ms, zero kernel sessions = the v63 -12900 client-side wall;
  the CVE-64747 size gate was never reached on it). OPC4 rebuilt on the PROVEN v96/v98
  frame-options transport (EncodeFrame arg-5 dict + HW-encoder create spec) sweeping both
  size formulas (130560/518400 vs 32640/129600). OPC3 cut to x2 (stats route CLOSED).

- **08-11 (v111) CVE-2026-64747 STATIC BREAKTHROUGH + GATE-PASSING ORACLES**: deep-read of the
  24A5355q binaries mapped the overflow - `PrepareMBInputCtrl` memcpys our `UserQPMap` bytes into the
  MB-input USurface with **no destination-capacity check** (gate only compares our declared size to
  `AVE_CalcBufSizeOfMBInputCtrl(w,h)` = `w16*((h+15)>>4)` for H264 - both attacker-influenced). The
  multipass stats blob is trusted after one gate: its `frameNumber` field is at **blob+0x2c** - the
  byte swept as 0x7a/0x41 all along. v111 ships **OPC3** (stats frameNumber sweep - first RODE = stats
  accepted) and **OPC4** (UserQPMap size-match sweep - daemon death at sz=req with a new signature =
  the overflow is LIVE = RCE path). H264SW +0x16dfc0 decoded as NULL+const byte-write (DoS only).
- **08-11 10:12 (v109→v110) THE BYTE QUESTION RE-ANSWERED + MINIMAL-PRIMITIVE**
  — OPC1 fired the 09:44 dying byte 0x7a **×256 on a fresh conn**: **all 55 shots
  REJECTED at the client** (es≠0) yet the **kernel rode all 55** (sessions 30..570,
  frames encoded), and the death came at **n054 = the 55th create** with the dying
  kernel session **EMPTY-EU (no encoder unit) + Input: 0** — the daemon session-
  create path broke mid-allocate. Death window across runs: **42 / 132 / 57
  creates = count/state-driven, 40–130 window**; the byte value only flips client
  accept/reject, never the corruption. **No .ips for 10:12** (uncatchable-class
  kill or unpulled). v110 ships the **OPC1b benign-0x41 count control** (is the
  byte value needed at all?), the **OPC2 create-only oracle** (is the pass/frame
  path even required, or does create+attach alone corrupt?), and **OPC1
  reject@C/A/P/B/F/E stage journaling** (the all-reject pattern now self-decodes).

- **13× `H264SW.videocodec+0x16dfc0`** — deterministic `KERN_INVALID_ADDRESS at 0x2232b47` on the CompleteFrames drain of the **software H.264 encoder** at 5952²/5984² (08-07 13:33→16:23). Wild, byte-identical fault address — an attacker-dims-sizeable bug, not yet dissected.
- **1× H264SW `+0x1709ac` @0x0** — NULL-memmove **in the encode path** (`vtCompressionSessionCompressionWork` → +0xdd38 → +0x16e974 → …), 08-09 00:49 — the 13× family's 2nd manifestation (share the +0x16e974 caller).
- **8× `vt_Copy`** — 7× `vt_Copy_x420_420v` @0x1 (NULL-source-plane deref, the B-class blitter, deterministic on byte-backed 420 inputs — re-fired 2× fresh-daemon at 4096² in the v60 run) + 1× `vt_Copy_420v_Crop` → `_platform_memmove` @0x0 (the v29 crop).
- **1× client-side SIGTRAP** — `CFEqual` in the config probe (our app, 08-07 22:43) — not the daemon.
- **The v60 run (20:29) = 6 daemon deaths** (SW04 ×2 B-class, SW14/16/17/18 H264SW 420-family); the plugin resolution gate is ≥4480² (`resolution is out of range` → -2001 → -19354), 4096² = the last HW-reachable square.
- Every v20–v28 VideoToolbox surface closed with data (see `FINDINGS.md` §4); the per-frame option channel is closed client-side for both `AVE_kVT…` and public names (v57–v59); **the session-prop `AVE_Prop_AVC_Set*` channel DELIVERS** (v61): `LookAheadFrames=INTMAX` and `MaxKeyFrameInterval=INTMAX` accepted at the kernel-bound struct; **v62** closed the angles (LookAheadFrames → daemon cap at 20; UserQPMap data → no such prop; non-420 InputPixelFormat → plugin table) and proved **EnableUserQPMap=CFBoolean → 0** (the type-gate bypass, QP-map path open) — **v63 = the PUBLIC-key sweep + supported-list census** (FINDINGS §38): the client translates raw→public kVT names, so the supported dict IS the forwardable set, and the IOKit Configure marshal (AppleAVE2Driver → AppleAVE2UserClient) is the transfer under attack. **v64 (FINDINGS §39) = the CENSUS-DEEP SWEEP**: the v63 run (21:47, daemon 428, zero deaths) completed the delivery map — 5 ACCEPTED keys, the first live daemon FIG gate (DataRateLimitsSeconds), the −2002 plugin-unsupported mapping, the −2004 gate-formula leaks, and the census proving NumberOfSlices is forwardable (v61's −12900 was ambiguous) — so v64 grinds the 3 new accepted keys ×8, re-fires NumberOfSlices, hits the census-revealed never-tried keys (log2_max_minus4, UserParameterSetsIds, SoftMinQuantizationParameter, UseLongTermReference, VBVMaxBitRate, MaxEncoderPixelRate) and sends DataRateLimits={INTMAX,1} to bypass the seconds clamp. **v65 (FINDINGS §40) = the GATE-BOUNDARY SWEEP**: the v64 run (22:09, daemon 427, zero deaths) solved the −12900 mystery (the client maps plugin −2004 → −12900; the daemon log leaked the exact gate bounds: NumberOfSlices [1,32], log2_max_minus4 [0,12], UserParameterSetsIds 'ParameterSetId <= 31' with no visible floor, SoftMinQP [−12,51]) — v65 shoots the boundaries (32/12/31/−12 legal edges, 33/13/32/−13 first-past, DataRateLimits={INTMAX,2} overflow, VBVMaxBitRate ×8 grind, and the UserParameterSetsIds={−1,−1} missing-floor probe). **v66 (FINDINGS §41) = the RCQPRANGE COMPOUND SWEEP**: the v65 run (22:23, daemon 430, zero deaths) closed the PPS missing-floor (OP09 {−1,−1} leaked 'ParameterSetId >= 0' = TWO-SIDED [0,31]) and opened the deepest reach — OP13 SoftMin=−12 = prop 0 then killed at Prepare ('FIG: Incorrect RCQPRange [-12 48]' → −1001 → −12902) = the SetSoftMin gate is bitdepth-generic vs the RCQPRange validator bitdepth-specific (the two gates disagree) — so v66 maps the RCQPRange validator with compound {SoftMin,SoftMax} pairs and hits the PPS element-COUNT ({0}x33/{0}x32/{0}x64/{31}x8). **v67 (FINDINGS §42) = the USAGE-COMPOUND SWEEP**: the v66 run (22:39, daemon 386, zero deaths) leaked the PPS count gate = [0,9] at the plugin (`UserParameterSetIdsCount <= 9`, OP11 {31}x8 = 0 ACCEPTED = the first multi-PPS delivery with the 'Forcing the PPS count to 1' FIG), found the −2003 type gate (StrictKeyFrameInterval wants a CFNumber), and delivered EnableWeightedPrediction into the 'usage is default' FIG (session survived = a non-default EncoderUsage is the escape) — so v67 shoots the StrictKeyFrameInterval CFNumber bypass, the EnableWeightedPrediction+EncoderUsage compound, the PPS count edge, and the QP-mix MinAllowed+SoftMin validator-floor discriminator. **v68 (FINDINGS §43) = the DELIVERY-GRIND SWEEP**: the v67 run (22:56, daemon 369, zero deaths) delivered the type-gate bypass (StrictKeyFrameInterval=CFNumber{INTMAX} → 0 = the 8th hostile numeric key rides), split the usage map (4 Streaming dead 'not supportd' / 1 VideoProcessing accepted + the compound's −1015 AVE_USL_Drv_Process fault → client cb −17691), re-confirmed the PPS count gate [0,9], and answered the QP-mix discriminator (SoftMin feeds the validator) — so v68 grinds the delivered StrictKFI=INTMAX (x8 + x24), the EWP+usage-1 compound (x8 + x24 of the −1015 USL fault), the untried usages 2/3, the PPS count-9 double-fire path, and the QP-mix mirror. **v69 (FINDINGS §44) = the USL-CHURN COMPOUND SWEEP**: the v68 run (23:12, daemon 391, zero deaths) fully mapped the usage gate (2/3/4 dead 'not supportd', only usage 1 live), proved the −1015 USL fault is usage-1-driven with new per-session teardown leaks (−1016 block-pool destroy + SEI Frame 0), and closed the QP-mix angle (MinAllowed → BlkQPRange / SoftMin → RCQPRange, per-field) — so v69 churns the usage-1 fault (x8 + x24 sessions), characterizes the −1015 with input variants, rides hostile keys on the faulting path, and pins the usage gate shape. **v70 (FINDINGS §45) = the SEGV-ISOLATION + CHURN-ESCALATION SWEEP**: the v69 run (23:29) CRASHED the daemon (launchd exit 11 SIGSEGV ×2 after the 40-session usage-1 churn, during the 420v8b/420v10 variants — OP06/07 verdicts were crash artifacts) — v70 re-runs the variants FIRST on a clean daemon, maps the new DebugMetadataSEI value gate, discriminates the −1016 leak with a usage-0 churn, re-fires the relaunch-window hostile keys, and escalates the churn (x16 boundary) to find the death count. **v71 (FINDINGS §46) = the FORMAT-TRIGGER ISOLATION + USAGE-GATE SWEEP**: the v70 run (23:50) PROVED THE TRIGGER — OP03 420v8b-64 killed daemon 374 86ms into the cell, OP04 420v10-64 killed 382, and daemon 385 survived 256² 2vuy + all 40 churn sessions + the beats with zero deaths = the 420-family input is the single-session daemon-SEGV trigger, 2vuy never kills, and the churn is exonerated (the −1016/SEI leak is fault-path-specific, the width-0 pixel-pool receipt is a benign 1×1 quirk, and the SEI gate is a CFBoolean TYPE gate) — v71 isolates the kill geometry (420v8b-256/420v10-256/420v8b-32), re-confirms both killers, shoots SEI as CFBoolean TRUE/FALSE, compounds killer+SEI, runs the usage-0 + 420v8b discriminator, and escalates the killer to a x4 churn. **v72 (FINDINGS §47) = the NULL-ROW ISOLATION + BLITTER DISCRIMINATION SWEEP**: the v71 run (00:12) CRASHED the daemon 11× — the two pulled reports are BOTH `_platform_memmove <- vt_Copy_420v_Crop` at 0x0 = a NULL src-row in the input-scaling blitter (dissected pre-AVE; the −1015 USL fault is a separate benign usage-1 fault) — v72 rebuilds the killer 420v8b-64 input CORRECTLY (planar-bytes explicit 2-plane + IOSurface-backed real-app path) to discriminate whether the NULL is our malformed CreateWithBytes buffer or a genuine VideoToolbox marshal bug, plus session@64² (blitter-required), Trim/Letterbox chain-geometry levers, and the killer x4 churn (the pb census line = the NULL-plane oracle). **v73 (FINDINGS §48) = the CLEAN-WINDOW DISCRIMINATOR + DOS-CADENCE SWEEP**: the v72 run (00:48) CRASHED the daemon ~12× and ANSWERED the discriminator — the pb census proved the NULL plane is CLIENT-side (mode-0 CreateWithBytes = planes=0 p1=(nil) every cell; planar/IOSurface = planes=2 valid) = a legal-API sandbox-app -> daemon DoS, NOT real-app reach, NOT a kernel OOB; usage-0 does NOT rescue; the x4 kill-churn killed 4 fresh daemons (~120-160ms) = the deterministic primitive + the 'Corpse failure, too many 6' forensics defeat; the Trim/Letterbox levers were NO-OPS (-12900) — v73 re-runs the clean constructions on a guaranteed-clean daemon, the x8 kill-churn cadence, and re-arms the scaling lever via the 'PixelTransferProperties' sub-dict. **v74 (FINDINGS §49) = the UNGAITED KEXT MARSHAL-FIELD SWEEP**: the v73 run (07:27) closed the NULL-plane DoS surface (planar −19643 daemon-side reject, IOSurface safe, OP13 SEI suppresses the NULL-row crash); dissecting driver+binaries/ proved the transfer map (app → XPC → plugin → `IOConnectCallStructMethod(S_AVE_UCInParam_Config)` → AppleAVE2 `AVE_UCCmd_CheckParam_Config`) and the kext's 6 ungated marshal fields — the AVC MCTFEdgeCount setter's ONLY gate is `iEdgeCnt >= 0` (ONE-SIDED: INTMAX rides the Config marshal into the kext ungated = the kernel MCTF edge-sizing OOB shot), the HDR CFData props (AVE 8 dwords / CLL 4 dwords, a PUBLIC SDK key) sweep lengths past the plugin 'invalid size' gate into the kext's fixed-width copies, and the x4 churn escalates. **v75 (FINDINGS §50) = the CORRECT-CHANNEL SWEEP**: the v74 run (08:08) PROVED the channel split — the census oracle shows the BARE AmbientViewingEnvironment/ContentLightLevelInfo IN-LIST while the kVTCompressionPropertyKey_-prefixed variants are BLOCKED (the v74 HDR cells self-blocked with the prefixed names, every OP08–12 = −12900, never left the client); InsertTrailingBytes REACHED the plugin but hit the −2003 CFData TYPE-gate (`CFDataGetTypeID() == CFGetTypeID(pValue)` with the hostile value riding in) = the setter wants CFData; MCTFEdgeCount never forwards via SetProperty (the daemon VT wrapper −12900, no AVE_Prop line) — v75 fires the correct channel (bare-name HDR CFData + CFData-typed TrailingBytes + the MCTF SPEC-dict second chance + the x4 trailing-bytes churn). A PANIC/reboot = THE 64747 kernel OOB.

---

## Part 2 — the original macOS LPE

An 8-byte OOB read/write into kernel memory adjacent to a dyld shared-cache page, from a
missing in-page bounds check in the v5 slide walk (`vm_shared_region_slide_page_v5`),
reachable via syscall 536.

**Patched** in macOS 26.5.2 (`25F84`, `xnu-12377.121.10`). Vulnerable through the 26.5
betas (`xnu-12377.120.72`).

Writeup: https://gracecondition.github.io/posts/dirtyslide/

### Build & run (macOS)

```sh
make                 # builds the payload into ./dist
./dist/run.sh        # run on the target VM as an unprivileged user → root shell
```

Tested on macOS 26.5 (`25F5042g`) arm64 under Apple Virtualization (VMAPPLE). The physical
scan panics ~50% of runs; the guest reboots, just run again.

### Build & run on iOS (original kernel-panic demo)

```sh
make                 # builds the payload into ./dist
```
Then launch the app and press "Crash in dsc region", launching with:
```sh
export CORE_DEVICE_ID=iPhone-0x11-cua-Duy.coredevice.local
export APP_BUNDLE_ID=com.ios.DirtySlide
xcrun devicectl device process launch --device $CORE_DEVICE_ID --console --no-activate \
  -e '{"_SafeMode": "1", "DYLD_SHARED_CACHE_DIR": "/a"}' $APP_BUNDLE_ID
```
- Done. Kernel panicked. If it doesn't work try again after 3 minutes.

- **v82 (08-10) = the FORMAT-TABLE MATRIX**: the 11:18 v81 run PROVED the MCTF arm
  delivers (EnableMCTF=0, NO-TX=0) but the MCTF-armed verify gates every video-range
  format (-17691 on clean IOSURF x420). v82 sweeps the plugin's own DevCap table's
  untried members (420f/xf20/P420/pf20 + 422v/422f/x422/xf22) on the proven IOSURF+
  NO-TX arm with the VEPBA pin moved to the CREATE-TIME spec dict; the INTMAX
  value/STR/ARM + x4 churn ride xf20 (the prime candidate).

- **v83 (08-10) = the MCTF-420 MATRIX on the missing vehicle**: the 11:48 v82
  run proved every DevCap-table member is gated (all -17691 on clean IOSURF
  planes) - MCTF is 420-only per the plugin's chroma gate (tst #0x3c0). A
  harness bug (IOSURF only for mf 4+) meant clean IOSURF 420v/2vuy/x420 were
  never delivered. v83 fixes bMode=2 for every mf and fires the MCTF
  PARAMS/INTMAX/STR/ARM/churn matrix on the three 420-family IOSURF vehicles.


- **v84 run verdict = FIRST DEVICE PANIC** (12:54:51, see headline) — count-21 UPS wedges the
  kext USL driver deterministically, SpringBoard hangs, watchdog panics.
- **v95** — the QP-MAP -13 UNLOCK: the kernel gate ('either QP map or slice QP
  has to be set') that rejected every ride frame at -13 is bypassed with
  EnableUserQPMap=TRUE + a per-frame UserQpMap pixel-buffer attachment (32640B) so
  the kernel finally consumes our config + our 0xFF MB-map bytes = the 64747 OOB shot.
- **v97 (08-10)**: AVC MAX-WIDTH DELIVERY through the OPEN -13 gate. The 19:56 v96
  run PROVED the kernel transport: OP85 AVC = ok=1 ACCEPT with our UserQpMap + SliceQP
  riding PerFrameData into the kernel AVC encoder. HEVC unlock cells all died at
  HEVC_RPS (GOP config) = cut. v97 fires userSliceQP=INTMAX + 0xFFFFFFFF per-MB QP map
  words (0xFF vs 0x00 vs LAST-4B/FIRST-4B marks) through the open gate. The plugin
  memcpy's our map into kernel-visible DART memory (content free after the size gate).
  A fault/PANIC in the AVC encoder/rate-control QP consumption = THE 64747 kernel result.
- **v96** — the FRAMEOPTIONS -13 UNLOCK: the frameProperties dict (EncodeFrame arg 5) with SliceQP{26} + UserQpMap CFData 32640B; the 19:31 kernel log proved the v95 pixel-buffer attachment never reached PerFrameData.userQpMap. IOKit deep-check: kext 0x704a44 element copy not attacker-reachable.

- **v94**: the strength words (0x18/0x01/INTMAX) ride to kext dump words 4-5 (0x8b4/0x8b8); the receipt is the KERNEL log MCTFStrengthLevel[4]/[5]. NEW OP5C HEVC INTMAX = the kext strength-consumer OOB candidate. Kext 0x704a44 element-copy OOB CLOSED (zero-filled marshal count). ~4s row.
- **v93 (08-10)** — the STR25-SPEC VALUE-SWEEP + MCTFParams run: legal strength values
  (1..24) ride the count-8 validated path to kext dump words 4-5 (0x8b4/0x8b8); INTMAX
  rejected by the <25 setter gate ('out of range' = the proof); MCTFParams x32 create-dict
  probes the kext 0x704a44 count-driven element copy (the OOB-write candidate). Dead cells
  (word2/DEEP/QSM) cut; ~6s row.
- **v92 (08-10)** — the DOUBLE-RIDE + DEEP-MARSHAL + STR25-SPEC run (AVC count-9→8 ride proven; 17:51:45 .ips = RPCTimeout; the count-16/19 DEEP marshals carry our words into the kext dump window; 3s wedge bail — FAST row).
- **v91 (08-10)** — THE CORRECTED count-8 RIDE: v90 proved **w22=8** (OP12
  'ch_qp_index_offset_cnt = 8'), so UPS10+CQP16+Usage rides UNFORCED at count-8 = the kext
  dump loop (0x6fe1a8) reads 8 words from 0x8a4 — words 0-3 ours, 4-5 via the NEW
  MCTFStrengthLevel co-arm (values <25 land at sess+0x8b4/0x8b8). count-19 is CLOSED
  (QSM scaling flag built after Validate; SetRCMode rejects 0; no RateControl key). The
  15:37-15:41 panic chain = userspace-watchdog class x2 (the wedge -> daemon RPC-kill ->
  SpringBoard no-checkins 180s -> reboot) — DoS, not corruption. v91 = 17 ops, wedge LAST.

- **v90 (08-10)** — THE VALIDATED count-7 RIDE (v89 proved count-19 closed: the session-60
  Forcing warning killed the QSM claim; SetRCMode rejects 0; no kext write twin. v90 rides
  count-7 == w22=7: kext dump reads our halfwords + the 0x8b4-0x8c0 heap-leak window +
  our word-2 feeds the USL MCTF threshold; wedge cell last).
- **v89 (08-10)** — the MCTF CO-ARM + CONFIRMED-RIDE panic run (v88 verdict: the QSM2
  deep-OOB shot wedged the USL before the plugin logged CreateInstance = RPC-kill, no
  .ips; v89 adds the EnableMCTF co-arm so the count-19 dump-loop OOB feeds the armed
  strength region, fast cells first, 10s wedge-bail).
- **v88 (08-10)** — the HEVC UPS-COUNT QSM-FLAG DEEP-OOB sweep: v87 PROVED Usage=1 gives
  eRCMode=HwVal but the QPMod ch_qp gate caps the count at 8 (w22 oracle). v88 fires the
  QSM scaling-flag presets FIRST (count-19 rides, no ch_qp), then the validated count-7
  ride (Usage=1 + ChromaQP16), w22 oracles, known-wedge control last.
- **v87 (08-10)** — the HEVC UPS-COUNT GATE-BYPASS run via the **PUBLIC** `EncoderUsage=1` key

  (-> sess+0x9ec -> eRCMode=0x14 HwVal -> the kext force-to-1 gate skips -> count-19 rides the
  dump loop = the 19-word OOB kernel-heap read). Bypass cells first on the fresh daemon,
  known-wedge control last, 15s wedge-bail.
- **v86 (08-10)**: HEVC UPS-COUNT GATE-BYPASS with the REAL registered RC keys
  (`RateControlMode`, `CodecPropertyBitRateControlMode`, `LowLatencyEnabled`, `MultipassEnabled`
  - recovered from cache slices .05/.15/.28) + custom QSM presets 2/3/5/7 + the drain-skip
  speed fix (wedge cells ~30s not 240s). Kext dump loop @0xfffffff0086fe1a8 reads the
  plugin-stored cnt-2 (19) with NO upper bound = 19-word OOB kernel-heap read.
- **v85 (08-10) = the HEVC UPS-COUNT GATE-BYPASS run**: the v84 run PROVED the UPS
  count-19 rides the marshal into the plugin, the force-to-1 gate caps the kext dump-loop bound
  (OOB gated), and the no-bypass cells wedged the USL driver (FrameReceiver 120 s timeout) killing
  daemons 380 + 590 via RPC self-terminate. v85 fires the disassembled bypass (QSM-preset 1/2
  public key + eRCMode=20 HwVal spec keys) so the count-19 rides UNFORCED into the kext
  dump-loop bound = 19 OOB kernel-heap reads; a panic/reboot = THE 64747 kernel OOB.

- **v84 (08-10) = the HEVC UPS-COUNT kernel-read run**: the 12:06 v83 verdict
  TRIPLE-closed the MCTF format matrix (420v-IOSURF STILL -17691). The kext
  session-config dump @0xfffffff0086f5844 reads count=[sess+0x8a0] with no
  upper bound (loops [sess+0x8a4 + idx*4] as MCTFStrengthLevel) — and the
  plugin AVE_Prop_HEVC_SetUserParameterSetsIds writes the client CFArray count
  (gate [1,21]) into exactly that field. v65-72 UPS was AVC-only (count [0,9]).
  v84 fires HEVC UPS {0xF}x21 (the untried 21-count) + MCTF co-arm bits + the
  20/21 boundary + x4 churn. kext MCTFStrengthLevel[N] lines with N>=7 = the
  OOB kernel-heap reads LIVE; a device reboot = PANIC = THE 64747 kernel OOB.
