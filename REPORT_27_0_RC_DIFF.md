> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# REPORT — iOS 27.0 diff review: beta 8 (24A5430a) → RC (24A435)

Source: `blacktop/ipsw-diffs`, directory `27_0_24A5430a_vs_27_0_24A435`
(4,341 `.md` diffs: 297 kexts, 1,414 filesystem Mach-O, 2,414 DSC dylibs, sandbox, firmware,
feature flags, entitlements). Reviewed locally by sparse-cloning the repo and building a
corpus of all 104,946 added / 31,297 removed diff lines.

## 0. ORIENTATION — read this first

**24A435 is the RC. It is the NEWER side, and it is the build on our device.**
24A5430a is beta 8, the OLDER side.

Every `-` line below is beta 8 only; every `+` line is new in the RC (24A435).

Evidence: repo root README titles the pair `27.0 beta 8 (24A5430a) .vs 27.0 RC (24A435)`, and
every other entry follows `<older> .vs <newer>`. Cross-check: `WebKit.framework/WebKit` shows
`-625.1.29.10.28` → `+625.1.29.10.29`, and the diff README's DSC table maps 24A5430a→`.28`,
24A435→`.29`. So `+` = RC = us.

Do **not** use kernel compile timestamps to order these two: the RC's kernel is
`13432.2.10~2` built 13 Aug 21:41 PDT, beta 8's is `~5` built 13 Aug 22:27 PDT. The RC's kernel
is *older by compile time* because the release branch was cut before the beta branch stopped
building. The two builds diverge in **both** directions — the RC is not a superset of beta 8
(e.g. the `com.apple.kec.AppleEncryptedArchive` kext exists in beta 8 and is gone in the RC).
Treat every RC/beta-8 comparison as "different branch", not "older/newer".

## 1. TL;DR — the five things that actually matter

1. **AVD gains two whole hardware generations.** `AVD.videodecoder` goes 4,124 → 4,380
   functions (+150 KB) with full `CAHDec{Borage,Kopsia}{Avc,Avx,Hevc,Lgh}` decoder classes, and
   the `"Borage/Kopsia AVD is not supported in this AppleAVD driver!!!"` strings are deleted.
   `com.apple.driver.AppleAVD` grows +35,836 B / +166 functions with matching
   `CAvdApComm|CAvdWrapCtrl|CAvdMcpu|CPriorityQueue × {Borage,Kopsia}` classes.
2. **`VCPHEVC.videocodec` grows +113 KB and 168 → 1,372 C strings**, gaining a config-file /
   scaling-list-file / frame-stats-file facility and CFPreferences reads, with new `fscanf`,
   `mkdir`, `stat` imports. New user-influenced string+file parsing surface in a codec plugin.
3. **`com.apple.WebKit.WebContent.Development` is the only sandbox profile whose IOKit
   user-client policy changed**, and it flipped allow→deny, naming `AppleJPEGDriverUserClient`
   explicitly. The `AppleJPEGDriver` kext also grew +0x784 B in the same build.
4. **New silicon support: T8152, T8160, T8320** (plus GPU IDs G17D/G18G/G19A/G19P). USB is the
   biggest code growth in the entire kext set (+88 KB on `AppleSynopsysUSB40XHCI` alone).
5. **Face ID capture moved into the Exclave** (`H16ISPGraphExclaveFaceIDNode`,
   `kFigCaptureStreamMetadataOutputConfigurationKey_SecureFaceIDEnabled`), and the Exclave
   sharedcache gains a camera/mic **strobe alternative privacy indicator** state machine.

## 2. Video / media stack (our core area)

### 2.1 `AVD.videodecoder` — the big one
`DYLIBS/System/Library/VideoDecoders/AVD.videodecoder.md` (version `993.1.0.0.0`, unchanged)

| metric | beta 8 | RC (24A435) |
|---|---|---|
| `__TEXT.__text` | 0x16bd88 | **0x18f7dc** (+150,612) |
| `__AUTH_CONST.__const` | 0x4e40 | 0x5940 |
| Functions | 4,124 | **4,380** |
| Symbols | 3,393 | **3,705** |
| CStrings | 2,072 | 2,064 |

Added symbol families — 8 complete decoder classes plus their vtables/typeinfo:

- `CAHDecBorageAvc`, `CAHDecBorageAvx`, `CAHDecBorageHevc`, `CAHDecBorageLgh`
- `CAHDecKopsiaAvc`, `CAHDecKopsiaAvx`, `CAHDecKopsiaHevc`, `CAHDecKopsiaLgh`

Removed strings (i.e. these stubs existed in beta 8 and are gone in the RC):
`"AppleAVD: INFO: %{public}s(): Borage AVD is not supported in this AppleAVD driver!!!\n"`,
the same for Kopsia, and `createBorageAvcDecoder` / `createBorageAvxDecoder` /
`createBorageHevcDecoder` / `createBorageLghDecoder` + the four `createKopsia*` equivalents.
Added: `"~CAHDecBorageLgh"`, `"~CAHDecKopsiaLgh"`.

Why this matters for row K: the new classes are **per-hardware register and buffer geometry**,
and they contain exactly the shape of code our un-audited candidate lives in —

- `ppsWorkBufSizeIncrease`, `getPPSWorkBufSize`, `allocWorkBuf_PPS`, `allocWorkBuf_SPS`,
  `freeWorkBuf_PPS`, `freeWorkBuf_SPS`, `decodeBufferSize` — allocation vs. patch-bound sizing
- `getTileStartCTU` / `getTileEndCTU` / `getTileIdxAbove` / `populateTiles` /
  `populateClearTiles` / `populateTileRegisters` — tile geometry
- `calc_az_left_tile_size`, `calc_lf_left_tile_size`, `calc_lr_left_tile_size`,
  `calc_lf_above_pix_tile_size`, `getUpscaleConvolveX0`, `getUpscaleConvolveStep`
- `populateDecryptionRegisters` (Avx classes) — decryption register path
- `getSWRStride`, `decHdrYSize`/`decHdrCSize`/`decHdrYStride`/`decHdrCStride`/`decHdrYLinAddr`/`decHdrCLinAddr`

This is a large body of **new, never-audited size/geometry math** in the binary we are already
working in. The `ppsWorkBufSizeIncrease` / `allocWorkBuf_PPS` pairing is the most direct hit on
the alloc-vs-patch-bound consistency question.

### 2.2 `com.apple.driver.AppleAVD` (993.1.0.0.0)
Functions 2,162 → **2,328** (+166, the largest function delta in the whole kext set);
`__TEXT_EXEC.__text` +0x8bfc; `__TEXT.__const` 0xcc129 → **0xf53cc** (+166 KB);
`kalloc_type` 0x3680 → 0x3b00; `kalloc_var` 0xd70 → 0xe10.

New classes: `CAvdApCommBorage`, `CAvdApCommKopsia`, `CAvdWrapCtrlBorage`, `CAvdWrapCtrlKopsia`,
`CAvdMcpuBorage`, `CAvdMcpuKopsia`, `CPriorityQueueBorage`, `CPriorityQueueKopsia`
(each with a matching `site.*` kalloc type). New strings:

```
"AppleAVD: INFO: %s(): m_hwDeviceType = %d - Borage\n\n"
"AppleAVD: %s(): bActiveMode = %d, msgbox_mailbox_connection_val = %d\n"
"msgbox-mailbox-connection"
"AppleAVD: ERROR: %s(): [l:%u] PO Msg Box mapping failed\n"
"AppleAVD: ERROR: %s(): mcpu is null!\n"
"AppleAVD: ERROR: %s(): FW size is 0!. This is unexpected. Check if mBoot/IPCE had loaded AVD FW or not.\n"
"AppleAVD: INFO: %s(): avd.start (driver image) fwVer = %08x, size = %8d.. sizeof(uCAvdCmd24) = %zu\n"
```

Two structural consequences:

1. The kext is now **multi-variant** (`m_hwDeviceType` selects Borage/Kopsia). The 166 KB of new
   `__const` is most plausibly per-variant config tables. The row-K model ("one dims per kext
   lifetime", the config `CanAcceptFormatDescription` compares against is kext-side) assumed a
   *single* kext-side config. If that config is now selected per `m_hwDeviceType`, the comparison
   target may be per-variant rather than global — which changes what a daemon kill does.
2. Every kext-side offset we have hardcoded for row K is likely shifted and possibly now inside a
   per-variant struct. **Re-baseline before trusting any row-K verdict measured on this build.**
   Note the plugin-side address we disassembled (`_AppleAVDWrapperH264Decoder
   CanAcceptFormatDescription @0x29ff2d17c`) is in `AVD.videodecoder`, not the kext, so it moves
   for a different reason — the whole `__TEXT.__text` shifted +150 KB.
3. AVD firmware is now expected to have been loaded by **mBoot/IPCE** before the driver starts
   (`"FW size is 0"` check). There is **no AVD FW entry** among the 15 updated firmware images,
   which is consistent with it moving into an image4 bundle rather than being unchanged.

### 2.3 `VCPHEVC.videocodec` — the second big one
`DYLIBS/System/Library/VideoCodecs/VCPHEVC.videocodec.md`

| metric | beta 8 | RC (24A435) |
|---|---|---|
| `__TEXT.__text` | 0x132684 | **0x14eae8** (+113,508) |
| `__TEXT.__cstring` | 0x214d6 | 0x2a6fc |
| Functions | 2,440 | 2,461 |
| Symbols | 411 | 425 |
| CStrings | 168 | **1,372** |

New imports: `_fprintf`, `_fputc`, `_fscanf`, `_mkdir`, `_stat`, `_strftime`, `_localtime_r`,
`_setlocale`, `_log10`, `_strrchr`, `_time`, `__os_log_impl`.

New capability surface (verbatim strings):

```
"%s/LrpEnc_%s_FrameStats.txt"
"/private/var/logs/mediaserverd/VideoProcessing"
"Unable to open config file '%s'\n"      "Unable to open file '%s'\n"
"Unable to open scaling list file '%s'\n" "Unable to close file\n"
"Config file within a config file not supported!\n"
"Read preference (%s, %s)\n"
"Profile argument not a string"          "Unsupported profile %s"
"Profile %d not supported\n"             "Unable to determine a profile\n"
"SPS change resulted in different profile!\n"
"Error updating pixel format requirements for requested profile\n"
"CFArrayCreate (CreateProfileLevelDict) failed!"
"CFDictionaryCreate (CreateProfileLevelDict) failed!"
"Dump NALU type %d with error %d"  "Dump SEI NALU: error %d"  "Dump Slice NALU: error %d"
"Both tiles and wavefront enabled!\n"  "SAO enabled partway through processing frame\n"
"Temporal MVP enabled but pointing to invalid reference\n"
"MPT isn't supported/tested with another enabled options; disabling MPT\n"
"Callback already set and can't be changed!\n"   "Failed to init thread data\n"
"SinglepassRatecontroller RefStruct: only supports RC_MODE_FILESIZE_CONTROL"
"Frame %d: Failed in MptRcAquireGopStatsUpdateModel\n"
"ave_bin_path"  "ave_log_path"  "cabac_estimation_enable_"
"HEVCDecoderOptions"  "HEVCEncoderOptions"  "Complexities"  "Dimension"
```

Read: a **config-file-driven option system** (config file, scaling-list file, nested-config
rejection), a **frame-stats/PSNR/rate-control dump** facility writing to
`/private/var/logs/mediaserverd/VideoProcessing` (hence `_mkdir`, `_strftime`, `_fscanf` for
2-pass re-read), **CFPreferences reads**, a **profile-string parser**, and a NALU dump path.
`HEVCDecoderOptions` / `HEVCEncoderOptions` are new dictionary keys — i.e. new session
properties that reach this parser. Path strings + a profile-string argument is exactly the
class of thing worth fuzzing through VideoToolbox session properties.

### 2.4 The rest of the media stack — size-only, no new strings

Verified as **no string/symbol changes** (pure code growth, so a fix or rework rather than a
feature) unless noted:

| binary | `__text` delta | note |
|---|---|---|
| `com.apple.driver.AppleM2ScalerCSCDriver` | +0x4c08 (19,464) | **0 new functions**, `__const`/`__cstring` byte-identical, version `200.62.4.0.0` unchanged → existing functions reworked, tables untouched |
| `com.apple.driver.AppleJPEGDriver` | +0x784 | paired with the WebKit sandbox deny (see §4) |
| `com.apple.driver.AppleProResHW` | +0x18bc | size-only |
| `com.apple.driver.DCPAVFamilyProxy` | +0x7a0 | size-only |
| `com.apple.iokit.IOAVFamily` | +0x1780 | +1 function |
| `com.apple.driver.AppleAVE2` | +0x2168 | size-only |
| `com.apple.driver.AppleH16CameraInterface` | +0xf18 | size-only |
| `AppleVideoEncoder.bundle` | −0x58 | size-only |
| `AppleMCTF.bundle` | +0x88 | size-only |
| `VideoProcessing.framework` / `DeepVideoProcessingCore` | small | size-only |
| `AV1SW` / `AppleProResSWDecoder` / `VCPMP4V` / `VCH263` / `H264SW` / `ave.videoencoder` | small | size-only |
| `com.apple.driver.AppleH16ANEInterface` | +0x344c | **has new strings** — see below |
| `VideoToolbox.framework` | +0x2530 | 9,248 → 9,250 functions, 2 symbols dropped, **CStrings unchanged** (2,238) |

`AppleM2ScalerCSCDriver` deserves emphasis: +19,464 bytes of code with **zero new functions and
identical `__const`/`__cstring`**. That is the signature of rewriting the logic inside existing
functions — the "bounded kernel write into cmdBuf / alloc-vs-patch-bound size consistency"
candidate from `REPORT_M2SCALER.md`. Worth a symbol-level re-diff against our current disassembly.

`AppleH16ANEInterface` new strings: `"ane1-exclave-proxy"`, `"function-ane1_power_func"`,
`"%s: %s: ANE0 harvested. Enable IPC/Exclave on ANE1\n"`, `"%s: ANE1 power function%s found\n"`,
plus `h18g` / `h19` / `m12` and `MTRCluster`. Read: ANE0 harvested → ANE1 takes over with an
Exclave IPC proxy.

## 3. New silicon

Confirmed by grep, **zero hits in the removed set**:

- **T8152** — `AppleProcessorTraceT8152`, `AppleT8152USBXHCI` + `AppleT8152USBXHCICommandRing`,
  `AppleT8152USBXDCI`, `AppleT8152DPTXPort`
- **T8160** — `AppleProcessorTraceT8160`, `AppleT8160USBXHCI`, `AppleT8160USBXDCI`
- **T8320** — `AppleProcessorTraceT8320` only
- **GPU** — `com.apple.AGXG18P` gains IDs `G17D`, `G18G`, `G19A`, `G19P`
- **T8140** — no new support

Kexts by `__TEXT_EXEC.__text` growth (our own computation over all 297):

```
   +88,680  +80 fn  com.apple.driver.usb.AppleSynopsysUSB40XHCI
   +70,944  +53 fn  com.apple.driver.usb.AppleSynopsysUSBXHCI
   +66,584  +70 fn  com.apple.driver.AppleUSBXDCIARM
   +35,836 +166 fn  com.apple.driver.AppleAVD            <-- ours
   +34,632 +129 fn  com.apple.driver.AppleProcessorTrace
   +33,468  +40 fn  com.apple.driver.AppleSARService
   +19,464    0 fn  com.apple.driver.AppleM2ScalerCSCDriver   <-- ours
   +15,784 +103 fn  com.apple.driver.AppleDisplayCrossbar
   +13,684    0 fn  com.apple.iokit.IOThunderboltFamily
   +13,388   +1 fn  com.apple.driver.AppleH16ANEInterface
```

New kalloc types (`site.*`): `AppleProcessorTraceT8152/T8160/T8320`, `AppleT8152DPTXPort`,
`AppleT8152USBXDCI`, `AppleT8152USBXHCI`, `AppleT8152USBXHCICommandRing`, `AppleT8160USBXDCI`,
`AppleT8160USBXHCI`, `IOPearlExclaveCameraFrame`, and AVD's eight `CAvd*/CPriorityQueue` types.
A new **command ring** class in an XHCI driver is a textbook DMA / ring-index target.

Also new: `com.apple.driver.AppleDisplayCrossbar` gains `phySetActiveLaneCount`, the `asdc-*-tunables`
and `lane-shm-regs-N-tunables` register blobs, and a guard string
`"requested zero laneCount with wake=%d, exiting.."` (i.e. the zero-lane-count case was a bug).

## 4. Sandbox

Only 21 profiles changed, and **the vast majority of the line churn is re-sorting** — e.g.
`baseline.md` is 8+/4− and is purely wrapping two existing paths in a `require-any`. Real changes:

1. **ThreadNetwork is now entitlement-gated** across `MobileSlideShow`, `container`, `maild`,
   `quicklookd`: `(global-name "com.apple.ThreadNetwork.xpc")` moved *out* of the blanket
   mach-lookup allow-list into
   `(require-all (global-name "com.apple.ThreadNetwork.xpc") (require-any (%entitlement-is-bool-true "com.apple.developer.networking.manage-thread-network-credentials") (xpc-service-name ".viewservice")))`.
   Thread access from sandboxed apps now requires an entitlement. **This is a hardening.**
2. **`com.apple.WebKit.WebContent.Development` — the only profile in the whole diff whose IOKit
   user-client policy changed**, and it inverted:

```
-(allow iokit-open-user-client
-	(with report)
-	(system-attribute developer-mode)
+(deny iokit-open-user-client
+	(with no-report)
+	(iokit-registry-entry-class "AppleJPEGDriverUserClient")
 )
+(deny iokit-open-user-client)
-
-(deny iokit-open-service)
-(allow iokit-open-service
-(with report)
-(system-attribute developer-mode)
+(deny iokit-open-service
```

   Developer-mode WebContent **lost** the ability to open IOKit user clients, and
   `AppleJPEGDriverUserClient` is denied **by name**. Named denials like this usually mean the
   path was live and reachable. `com.apple.WebKit.GPU.Development` and
   `...Networking.Development` kept their allows (only restructured), so this is specific to
   WebContent. `AppleJPEGDriver`'s kext also grew +0x784 B in the same build.
3. New referenced collection profile name: `com.apple.WebKit.WebContent.EnhancedSecurity`.
4. `blastdoor-messages` / `blastdoor-airlock`: `MSC_thread_get_special_reply_port` moved out of
   the unconditional `allow syscall-mach` into a block guarded by
   `(require-not (state-flag "blastdoor-post-launch"))` — i.e. denied after launch. Hardening.
5. Protobox/Autobox (`appleh16camerad`, `cameracaptured`, `cameraispd`, `visionhwserverd`) — 4–8
   line changes each, no new capability found.

## 5. Entitlements

Small diff, nothing AVD-related — **our entitlement gate did not change**. Notable grants:

- `ServicesPaymentAngel` gains the whole CDP/Walrus set: `com.apple.cdp.walrus`,
  `com.apple.cdp.walrus.pcskeys`, `com.apple.cdp.recoverykey`, `com.apple.cdp.telemetry`,
  `com.apple.mkb.usersession.keybagopaquedata`, `com.apple.keystore.device`, plus 7 new
  mach-lookup services (`com.apple.cdp.daemon`, `com.apple.aa.identity.xpc`, …).
- `nfcd` gains `com.apple.seserviced.presentment-authorization`, `com.apple.timed`,
  `com.apple.stockholm.services.NFReportingService`, and two nfrestore firmware hash paths.
  Loses `AppleSMCSensorDispatcherUserClient`.
- **New hardware user-client surfaces reachable from Diagnostics/CheckerBoard**:
  `AppleSPUHIDDriverUserClient` added to `iokit-user-client-class` in `CheckerBoard`,
  the brand-new `Diagnostic-6024`, and `proximitycontrold`; plus
  `com.apple.aop.hid-driver.user-client` with an `orientation_1 → send-command` dict.
  `Diagnostic-4009` gains `AppleCameraUserClient` + a `com.apple.cameraispd` mach lookup.
  `Diagnostic-6023` (new) gains `AppleBiometricServicesUserClient`.
  `Diagnostic-6025` (new) gains `com.apple.private.mobilerepair.shipmode`.
- `callservicesd` gains iCloud container/services, clouddocs, librarian, MobileDocuments storage.
- New `AMSNearFieldExtension.appex` (see §7).

If we ever want a second, cheaper probe target than AVD, these newly-opened driver user clients
reachable from Diagnostics/CheckerBoard are the obvious candidates.

## 6. Exclave and firmware

- **Face ID moves into the Exclave.** `H16ISP.mediacapture` gains
  `H16ISPGraphExclaveFaceIDNode` (ctor/dtor, `onActivate`, `onDeactivate`, `onMessageProcessing`,
  `GetNodeProcessingState`, `AddFaceIDMetadata(..., ISPExclaveCoreChRunKitFidResult, ...)`) and
  `H16ISPGraphExclaveAutoExposureNode::runFaceIDAEBracketCapture`, plus new keys
  `kFigCaptureStreamMetadataOutputConfigurationKey_SecureFaceIDEnabled` /
  `..._SecureFaceIDConfiguration` and
  `kFigCaptureStreamCaptureSecureFaceIDBracketKey_{DoubleOrder,NumberOfDoubles,ProbePatternIndex,ProbePatternType}`.
  Face ID capture, including AE bracket capture driven by the exclave FID result, is now an
  Exclave graph node. This is a biometric trust-boundary change.
- **New ExclaveOS frameworks (36 new files, none present in beta 8):**
  `ShazamExclave.framework` + `ShazamExclaveComponent.framework` (Shazam moved into the exclave),
  `AppleCameraT8160_{IR,RGB}_ISP_EK_Component.framework`,
  `AppleCameraT8160_CoreAAClientKit`, `AppleCameraT8160_ExclaveISPSharedLib_exclavekit`,
  `AtlantisProxTrustedFDR.framework`,
  `FaceIDCoreLib_exclavekit.framework/models/{D9X,V6X}.bundle/*` (new Face ID model sets:
  `face_detection_ir/rgb`, `attention_detection_ir/rgb`, `glasses_classifier`, `glasswingnet`,
  `landmark_semantic_face`, `obstruction_detection`, `backlit_sun_classifier`),
  `SISP_EK_AlgoModels.framework/Networks.bundle/ANST.bundle/H17D.bundle/ANST.H17D.hwx`.
  Two new Face ID hardware revisions, **D9X** and **V6X**.
- **ExclaveCore bundle** (`Firmware/image4/exclavecore_bundle.t8150.RELEASE[.restore].im4p`) is
  functional growth, not a version bump: `exclave_roottask` 19,271 → 19,291 functions;
  `exclave_sharedcache` (RELEASE) 50,460 → 50,531 functions and **16,273 → 16,384 CStrings**.
- **New camera/mic strobe privacy indicator in the exclave sharedcache.** A state machine with
  `"INDICATOR: STROBE ALT -> {PREPARE,ON,OFF,PENDING STOP,PENDING STOP CANCELED}"`,
  `"INDICATOR: STROBE FLASH ALT -> …"`, `"INDICATOR: CAM -> OFF ("`, `"INDICATOR: MIC -> OFF ("`,
  `"DEFAULT INDICATOR MACHINE: "`, `"Display issue detected: switching to strobe alternative indicator"`,
  `" not allowed while strobe alternative indicator is active"`, `"Failed to notify corerepaird of strobe start"`,
  `"Failed to get Medina state"`, and a `policy-alt-indicator` / `octopus_fang_alt_indicator` policy.
  Read: when the normal camera/mic indicator can't be shown, the exclave falls back to a **strobe
  indicator**. The privacy-indicator policy is now partly exclave-owned — and it can refuse an
  operation while the strobe is active.
- Other firmware: `sptm.t8150` (build date 2026-08-10 → 2026-08-08, `__text` 0x61258 → 0x612f4),
  `txm.iphoneos` (`AppleImage4_txm-374~7051` → `~7022`, `__text` 0x49358 → 0x49a90),
  `ansf`/`rans` (build-number only), `msr`/`rmsr` (`__const` only, no strings),
  `h18_ane_fw_apollo_v5x` (`__const` only), `AppleAVE2FW_H18` (`__DATA.__data` 0x1590 → 0x1588),
  `isp_bni/adc-silenus-v5x` (10 functions resized, real code change).
  AppleImage4 is now version **7.0.0** (`AppleImage4-374~14049`).
- `ExclaveOS` Mach-O updates are mostly micro: `TokenGeneration` /
  `TokenGenerationInference` change by 4–16 bytes; `TokenGenerationInferenceExclaveComponent`,
  `CodeCoverageDelegate`, `IISAudioOutputStreamClientNotifierComponent` change **only object-file
  path hashes** (pure build churn). Only substantive one: `usr/lib/dyld` gains
  `__ZN5dyld3L14archCacheMagicE` and cstrings `"dyld_v1  arm64e"` / `"dyld_v1arm64ex1"`.

## 7. New binaries and frameworks

- New Mach-O in filesystem (10): `Diagnostic-6023/6024/6025.appex`,
  `t8150.RELEASE{.restore}.stripped.sharedcache` (ExclaveCore),
  `MobileDevices-0001` / `-0003`, `AMSNearFieldExtension.appex`,
  `NTKHermes2026FaceBundle` / `NTKHero27FaceBundle`.
- New DSC dylibs (5): `AppliedSensingFitness`, `CRShipModeUI`, `ChassisTriagePlaneClient`,
  `HearingRelevance`, and `/usr/lib/objc/libobjcMsgSend34.dylib` (moved out of SystemOS into
  the shared cache).
- `AMSNearFieldExtension` is a full NFC/Tap-to-Pay client: `com.apple.nfcd.hwmanager`,
  `com.apple.nfcd.session.se`, `com.apple.nfcd.session.reader.internal`,
  `com.apple.nfcd.background.tag.reading.extension.urls` (`https://giftcard.apple.com`,
  `https://gc.apple.com`), `com.apple.seserviced.key`, `com.apple.private.fairplay.FPDI`,
  `com.apple.keystore.device`, `com.apple.payment.card-on-file`,
  `com.apple.private.attestation`-adjacent grants. `AppleMediaServices` also gains
  `AMSNearFieldEngagementModel`, `NFHardwareManager`, `NFSecureElementManagerSession`,
  `NFReaderSessionPollConfig`, `NFTag`, `SESShortLivedKeyService`.
- `CRShipModeUI` / `CoreRepairCore` add `CRShipModeBatteryClient/ServerNotifier/ServerResponse`
  and services `com.apple.mobilerepair.shipmode[.batteryclient/.client]`, gated by the new
  `com.apple.private.mobilerepair.shipmode` entitlement — a new daemon RPC taking client input.

## 8. Feature flags

**New plists (4):** `Domain/Genlock.plist` (`fall_2026` = FeatureComplete),
`Domain/Provolone.plist` (`Provenance` = FeatureComplete),
`Unified/Domain/AONSense.plist` (`localAmbientSensing`, `vlOnLocationClient` — both
UnderDevelopment, TargetRelease 27.A), `Unified/Domain/Health.plist` (`DaytimeMetrics`,
`VitalsEnhancements` — UnderDevelopment).

**Newly FeatureComplete (shipping in this release):** RelevancePlatform —
`audioUnderstandingSecure`, `instantShazam`; NanoTimeKit — `hermes2026`, `hero27`;
FindMy — `Mojito`; Health — `AllDayHRV`, `AllDayHeartRate`, `DaytimeMetrics`,
`VitalsEnhancements`, `heartRateStreamingChart`, `hermitV2`, `liveHeartRateComplications`;
Workout — `LowPowerModeUpLevel`, `Readiness`; Accessibility — `BSI_8Dots`,
`SoundRecognition_NoiseNotifications`; Home — `ThreadTesterExperiment`; GlobalDisclosures — new
UUID `1b3196a9-6a20-4559-60fd-bb3743219ab3`.

**Newly UnderDevelopment:** Wallet — `TreeStar` (27.A); UnifiedFeatureFlagsDemo — `DemoDynamic`.

**Removed in the RC:** `Domain/Security.plist` loses `OctagonRKTLKOwnershipProof` (its only
change); `AppleIntelligenceReporting` loses `session_based_upload`; `Messages` loses
`AssistantActionSuggestions`. No new security toggles.

## 9. Removals, and things worth a second look

- `com.apple.kec.AppleEncryptedArchive` kext — present in beta 8, gone in the RC.
- `/usr/libexec/memoryanalyticsd` + its launchd plist — gone. No replacement by that name;
  `PeriodicSystemMetricsCore` changed only trivially (+4 bytes), so this is not a rename.
- `AirPlayDiagnosticExtension.appex`, `SystemConfiguration/get-mobility-info`, and ~20
  `Preferences/Logging/Subsystems/*.plist` (FaceTime, Home, IDS, Messages, Registration,
  StatusKit, Transport, apsd, calls.*, voicemail) — logging subsystem declarations removed.
- **`com.apple.kernel` coredump strings removed outright.** Every one of these is a `-` line and
  none reappears anywhere in the added corpus: `"called with invalid length %llu"`,
  `"called with too much data, %llu written, %llu left"`,
  `"ran out of space to save threads with %llu of %llu remaining"`,
  `"coredump size limit exceeded: attempted %llu bytes, limit is %llu bytes"`,
  `"coredump_save_segment_descriptions() called too many times, …"`, plus the whole
  `kern_coredump_routine` / `kcc_coredump_save_*` set. A new symbol `"ucoredump"` appears.
  The most likely reading is that the coredump machinery was **relocated or reworked**, not that
  validation was dropped — but the RC's kernel lost ~20 identifiable bounds/length checks and
  gained a differently-named facility, so it is worth a direct look at what `ucoredump` is.
- `com.apple.kernel` also gains `perflevel2` CPU topology + cache geometry (`sharesl2`, L1/L2/L3
  sizes, "Number of CPUs sharing an L2 cache for perflevel2") and new ARM feature bits:
  `FEAT_CPA`, `FEAT_CPA2`, `FEAT_FAMINMAX`, `FEAT_FP8`, `FEAT_FPMR`, `FEAT_LUT`, `FEAT_PAuth_LR`,
  `FEAT_SME_F8F16`, `FEAT_SME_F8F32`, `FEAT_SME_LUTv2`. `FEAT_PAuth_LR` (PAC using LR) and the
  SME FP8/LUTv2 set are new architecture the kernel now probes for.
- `com.apple.driver.AppleSARService` (+33,468 B, +40 functions) is the **only kext in the whole
  diff with new user-client external methods**:
  `AppleSARServiceUserClient::extSARSensingCACurrentState`, `extSARSensingCAInfo`,
  `extSARSensingCALastSubmit`, `extStateABOsiris`, with new validation strings
  `"output size mismatch (%u vs %zu)"` and `"Current Write Index is out of the bound: %d\n"`.
  New CoreAnalytics sensing with orientation/face-distance/pitch/roll duration buckets
  (`angle_0_duration_s` … `angle_neg_duration_s`, `fd_dist_closer_duration_s`, …) and
  `"com.apple.Telephony.hsarSensingDecisionVerdict"`. Added validation strings tell you where a
  bug *was*; check whether sibling externals share the pattern.
- `com.apple.driver.ApplePearlSEPDriver` (+31 functions, +0x16ec) — the standout for biometrics:
  - new asserts `"payloadSize >= __builtin_offsetof(cmd_load_ref_frames_info_record_in_v1_t, refFramesInfoRecordData)"`
    and `"payloadSize >= sizeof(cmd_process_frame_metadata_in_v1_t)"`
  - **a second accepted PSD magic**:
    `"psdHeader->magic == (0x45674567) || (psdHeader->magic == (0xdead4567) && isV63p1Psd2MagicAllowed())"`
    (also for `psd3->hdr`) — a new magic value routed into the same parser
  - new SEP crypto ops `PSEstablishSharedSecret`, `PSGenerateHostEphemeralKey`,
    `PSGenerateHostUnwrapData`, `PSSetSensorUnwrapData`, `PSClearSession`
  - new class `IOPearlExclaveCameraFrame` (+ `site.IOPearlExclaveCameraFrame` kalloc type) with
    frame refcount tracking, and a widened sensor check
    `kSavageSensorTypeAries || kSavageSensorTypeHamal`
  - `"request->verifyOnly || _refFramesInfoRecordInSEP == kBoolNotSet"`
- `com.apple.iokit.IOMobileGraphicsFamily` / DCP — new userspace-settable runtime properties
  `enableGenLock`, `genLockFrequency`, `EnableHingeAngleOverride`, `HingeAngleOverrideValue`
  (`iomfb_RuntimeProperty_*`), a new `genlock_error_notify_gated` path with
  `"userspace client registered for notifications"`, and `HingeAngle` in `IOHIDFamily`.
  Genlock = synchronised video output timing; **hinge angle** implies a foldable.
- `AppleAuthCP` — `_processDeferredCommandGated`, `"invalid data received for CMD=0x%x"`,
  `"no dictionary received for CMD=0x%x"`, challenge/signature mismatch handling.

## 10. What is churn (do not spend time on it)

- The bulk of `FILES/filesystem.NEW.md` (2,256 entries) is localization (`.loctable`, `.strings`,
  `-V63/-V68`), watch faces, HEIC/EXR/USDZ assets, `pipelinelib` variants and `_CodeSignature`.
- The `AppOS` update list is entirely Safari/WebKit binaries; WebKit's own version bump
  `.28 → .29` plus the WebKit sandbox profiles are the visible part of this release.
- `baseline.md` and most of the WebKit sandbox line churn is re-sorting, not new policy.
- 275 of 297 kexts changed sizes only, with no string or symbol diff.
- Photo `MediaConversionService` XPCs are updated, not new.

## 11. Recommended next steps for row K

1. **Re-baseline every AVD offset on 24A435** before measuring anything: `AVD.videodecoder`
   `__TEXT.__text` moved +150 KB and 8 new decoder classes were added; the kext moved +0x8bfc and
   gained per-variant config tables. Any verdict produced on this build with offsets derived from
   an earlier build is suspect.
2. **Re-examine the row-K model against `m_hwDeviceType`.** Confirm whether the kext-side config
   that `CanAcceptFormatDescription` compares against is one global or one-per-variant. That
   single question determines whether the "one dims per kext lifetime" rule still holds.
3. **Audit `ppsWorkBufSizeIncrease` / `getPPSWorkBufSize` / `allocWorkBuf_PPS` in the new
   `CAHDec{Borage,Kopsia}Avx` classes.** This is the alloc-vs-patch-bound consistency question
   sitting in brand-new, never-fuzzed code — the highest-value target in the diff.
4. **Look at `VCPHEVC`'s new config/scaling-list/profile-string parsers** via VideoToolbox
   session properties (`HEVCDecoderOptions` / `HEVCEncoderOptions` dictionaries). New file+string
   parsing reachable from a normal app.
5. If we want a different target: the new `AppleSPUHIDDriverUserClient` / `AppleCameraUserClient`
   user clients now reachable from Diagnostics and CheckerBoard, and the new T8152 USB
   `CommandRing` class.
6. Treat `com.apple.kernel`'s `ucoredump` refactor as an open question.

---

### Method / reproduction

```bash
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/blacktop/ipsw-diffs.git
cd ipsw-diffs && git sparse-checkout init --cone
git sparse-checkout set 27_0_24A5430a_vs_27_0_24A435 && git checkout
```

Direction was established from the repo root README (`27.0 beta 8 (24A5430a) .vs 27.0 RC (24A435)`)
and independently confirmed via `DYLIBS/.../WebKit.framework/WebKit.md` showing
`-625.1.29.10.28` → `+625.1.29.10.29` against the README's DSC table. All claims in §2–§7 were
checked directly against the on-disk `.md` files; `+`-only tokens were cross-checked against the
removed corpus so that reformatting is not reported as new.
