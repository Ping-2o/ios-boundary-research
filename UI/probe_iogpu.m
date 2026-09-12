//  probe_iogpu.m - DirtySlide ROW H: IOGPUDeviceUserClient (v160)
//  The 23G83 RE: IOGPUFamily (com.apple.iokit.IOGPUFamily) has NO
//  IOUserClientEntitlements / DefaultLocking registry = LEGACY
//  getTargetAndMethodForIndex dispatch, 56 selectors x 0x30 @0xfffffff008106140
//  (sel 42-55 = the 0xe00002e2 unsupported stubs), NO per-selector entitlements.
//  Metal apps open this UC from a standard container. Pinned handlers:
//    sel 3  = s_new_command_queue (0x9c2012c: queue-cap + EXACT args-size gate
//             >= 0x408 vs device value, leak-watchdog "possibly leaking?")
//    sel 4  = s_new_resource (0x9c204bc -> 0x9c3e0a4: args >= 0x58, resType
//             switch 0/3/0x40/0x80/0x82, cache_mode byteswap>9 gate, WIRE-BUDGET
//             gate "try to wire down too much memory", IOSurface-id + plane
//             validation, suballoc-flag-needs-parent gate)
//    sel 13 = struct 0xc w/ descriptor; sel 20/21 = 2-scalar + 2-out
//  The event/fence family (t_signal/t_wait shared_event/mtl_event) has raw
//  uintptr_t handles from userland = the refcount/UAF shot.
//  ZERO epoch cost (no videocodecd ops). MAY CRASH KERNEL (GPU).
#include "ds_core.h"

/* IOKit is NOT in the iOS SDK - the return codes are defined here (IOReturn.h values) */
#define DS_IO_SUCCESS        0
#define DS_IO_NO_DEVICE      0xe00002c0
#define DS_IO_NOT_PERMITTED  0xe00002c1   /* the sandbox-denied verdict */
#define DS_IO_BAD_ARGUMENT   0xe00002c2
#define DS_IO_EXCLUSIVE      0xe00002c5
#define DS_IO_UNSUPPORTED    0xe00002c7
#define DS_IO_UNSUPPORTED_2E 0xe00002e2   /* the IOGPU 42-55 stub cap */
#define DS_MIG_BAD_ARGUMENTS 0xfffffed0
#define DS_MIG_BAD_ID        0xfffffed2
#define DS_IO_GUARD_TMO      0xe0000001   /* guard timeout sentinel */

/* ---- IOKit via dlopen (private framework, not in the iOS SDK) ---- */
typedef mach_port_t io_object_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_iterator_t;

typedef CFMutableDictionaryRef (*ds_pIOServiceMatching)(const char *);
typedef io_object_t (*ds_pIOServiceGetMatchingService)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*ds_pIOServiceGetMatchingServices)(mach_port_t, CFDictionaryRef, io_iterator_t *);
typedef io_object_t (*ds_pIOIteratorNext)(io_iterator_t);
typedef kern_return_t (*ds_pIOObjectGetClass)(io_object_t, char *, uint32_t);
typedef kern_return_t (*ds_pIOServiceOpen)(io_object_t, task_t, uint32_t, io_connect_t *);
typedef kern_return_t (*ds_pIOServiceClose)(io_connect_t);
typedef kern_return_t (*ds_pIOObjectRelease)(io_object_t);
typedef kern_return_t (*ds_pIOConnectCallScalarMethod)(io_connect_t, uint32_t,
        const uint64_t *, uint32_t, uint64_t *, uint32_t *);
typedef kern_return_t (*ds_pIOConnectCallStructMethod)(io_connect_t, uint32_t,
        const void *, size_t, void *, size_t *);

static ds_pIOServiceMatching               pMatch;
static ds_pIOServiceGetMatchingService     pGet1;
static ds_pIOServiceGetMatchingServices    pGetN;
static ds_pIOIteratorNext                  pNext;
static ds_pIOObjectGetClass                pClass;
static ds_pIOServiceOpen                   pOpen;
static ds_pIOServiceClose                  pClose;
static ds_pIOObjectRelease                 pRelease;
static ds_pIOConnectCallScalarMethod       pScalar;
static ds_pIOConnectCallStructMethod       pStruct;
typedef kern_return_t (*ds_pIOConnectCallMethod)(io_connect_t, uint32_t,
        const uint64_t *, uint32_t, const void *, size_t, uint64_t *, uint32_t *, void *, size_t *);
static ds_pIOConnectCallMethod             pMethod;

static int ds_gp_load(void)
{
    void *k = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!k) { dprintf(STDOUT_FILENO, "  I[GP] dlopen IOKit FAILED: %s\n", dlerror()); return -1; }
    pMatch   = (ds_pIOServiceMatching)dlsym(k, "IOServiceMatching");
    pGet1    = (ds_pIOServiceGetMatchingService)dlsym(k, "IOServiceGetMatchingService");
    pGetN    = (ds_pIOServiceGetMatchingServices)dlsym(k, "IOServiceGetMatchingServices");
    pNext    = (ds_pIOIteratorNext)dlsym(k, "IOIteratorNext");
    pClass   = (ds_pIOObjectGetClass)dlsym(k, "IOObjectGetClass");
    pOpen    = (ds_pIOServiceOpen)dlsym(k, "IOServiceOpen");
    pClose   = (ds_pIOServiceClose)dlsym(k, "IOServiceClose");
    pRelease = (ds_pIOObjectRelease)dlsym(k, "IOObjectRelease");
    pScalar  = (ds_pIOConnectCallScalarMethod)dlsym(k, "IOConnectCallScalarMethod");
    pStruct  = (ds_pIOConnectCallStructMethod)dlsym(k, "IOConnectCallStructMethod");
    pMethod  = (ds_pIOConnectCallMethod)dlsym(k, "IOConnectCallMethod");
    if (!pMatch || !pGet1 || !pOpen || !pClose || !pRelease || !pScalar || !pStruct) {
        dprintf(STDOUT_FILENO, "  I[GP] dlsym incomplete - IOKit surface changed\n");
        return -1;
    }
    return 0;
}

static const char *ds_gp_kr(kern_return_t k)
{
    switch (k) {
    case DS_IO_SUCCESS: return "SUCCESS(0)";
    case DS_IO_NOT_PERMITTED: return "NotPermitted(sandbox!)";
    case DS_IO_BAD_ARGUMENT: return "BadArgument";
    case DS_IO_UNSUPPORTED: return "Unsupported";
    case DS_IO_UNSUPPORTED_2E: return "Unsupported(2e2)";
    case DS_IO_NO_DEVICE: return "NoDevice";
    case DS_IO_EXCLUSIVE: return "ExclusiveAccess";
    case DS_MIG_BAD_ARGUMENTS: return "MIG_BAD_ARGUMENTS";
    case DS_MIG_BAD_ID: return "MIG_BAD_ID";
    case DS_IO_GUARD_TMO: return "GUARD-TIMEOUT";
    default: return "?";
    }
}

/* guarded scalar call */
static kern_return_t ds_gp_scalar(io_connect_t conn, uint32_t sel, const uint64_t *in, uint32_t nIn,
                                  uint64_t *out, uint32_t *nOut, int *timedOut)
{
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    int sig = ds_ave_guard_run_tmo(^int {
        kr = pScalar(conn, sel, in, nIn, out, nOut);
        return 0;
    }, &rc, 4000);
    if (sig == SIGALRM) { if (timedOut) *timedOut = 1; return DS_IO_GUARD_TMO; }
    if (sig > 0) { if (timedOut) *timedOut = 2; return (kern_return_t)0xe0000000 | sig; }
    return kr;
}

static kern_return_t ds_gp_struct(io_connect_t conn, uint32_t sel, const void *in, size_t inSz,
                                  void *out, size_t *outSz, int *timedOut)
{
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    int sig = ds_ave_guard_run_tmo(^int {
        kr = pStruct(conn, sel, in, inSz, out, outSz);
        return 0;
    }, &rc, 4000);
    if (sig == SIGALRM) { if (timedOut) *timedOut = 1; return DS_IO_GUARD_TMO; }
    if (sig > 0) { if (timedOut) *timedOut = 2; return (kern_return_t)0xe0000000 | sig; }
    return kr;
}

void probe_iogpu(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== H. IOGPU-UC (v165 - all-connections sel100 probe x AGX map) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  RE: 56-sel legacy dispatch @0x8106140, no entitlements/locking; sel3=newCQ\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (0x408 args gate), sel4=newResource (0x58+, resType/cache/wire gates).\n", pfx);

    if (ds_gp_load() != 0) return;

    /* GP00 v165: OPEN-ORACLE - sweep open TYPES 0..8, print EVERY type's kr,
     * keep ALL successful connections (v164 kept only type1). The map cells then
     * probe EACH connection with sel 0x100: the one that answers non-BADARG is
     * the AGXDeviceUserClient dispatch. */
    static const char *svcs[] = { "IOGPUDevice", "AGXAccelerator", "AGXDevice", "AppleParavirtGPU" };
    io_connect_t conns[9];
    uint32_t connTypes[9];
    const char *connSvcs[9];
    int nConns = 0;
    for (size_t i = 0; i < sizeof(svcs) / sizeof(svcs[0]); i++) {
        char tg[40];
        snprintf(tg, sizeof(tg), "GP00 open %s", svcs[i]);
        ds_journal_write("START", tg);
        CFMutableDictionaryRef m = pMatch(svcs[i]);
        if (!m) { dprintf(STDOUT_FILENO, "%s  I[GP00] %s: matching failed\n", pfx, svcs[i]); ds_journal_write("DONE", tg); continue; }
        io_iterator_t it = MACH_PORT_NULL;
        int cnt = 0;
        if (pGetN && pGetN(0, m, &it) == KERN_SUCCESS) {
            io_object_t o;
            while ((o = pNext(it)) != MACH_PORT_NULL) {
                char cls[128] = "?";
                pClass(o, cls, sizeof(cls));
                dprintf(STDOUT_FILENO, "%s  I[GP00] %s hit[%d] class=%s\n", pfx, svcs[i], cnt, cls);
                if (cnt == 0) {
                    for (uint32_t t = 0; t <= 8 && nConns < 9; t++) {
                        io_connect_t c = MACH_PORT_NULL;
                        kern_return_t kr = pOpen(o, mach_task_self(), t, &c);
                        if (kr != KERN_SUCCESS || c == MACH_PORT_NULL) {
                            dprintf(STDOUT_FILENO, "%s  I[GP00] %s type%u -> %s (%d)\n", pfx, svcs[i], t, ds_gp_kr(kr), kr);
                            continue;
                        }
                        char ucls[128] = "";
                        kern_return_t krC = pClass(c, ucls, sizeof(ucls));
                        dprintf(STDOUT_FILENO, "%s  I[GP00] %s type%u OPEN conn=%#x CLASS=%s (getclass kr=%d)\n",
                                pfx, svcs[i], t, c, ucls[0] ? ucls : "<empty>", krC);
                        conns[nConns] = c; connTypes[nConns] = t; connSvcs[nConns] = svcs[i];
                        nConns++;
                    }
                }
                pRelease(o);
                cnt++;
            }
            pRelease(it);
        }
        dprintf(STDOUT_FILENO, "%s  I[GP00] %s: %d service(s)\n", pfx, svcs[i], cnt);
        ds_journal_write("DONE", tg);
    }
    if (nConns == 0) {
        dprintf(STDOUT_FILENO, "%s  I[GP00] NO CONNECTION - the sandbox denied every open (kIOReturnNotPermitted\n", pfx);
        dprintf(STDOUT_FILENO, "%s  = the seatbelt verdict: IOGPU UC not app-openable on this boot). ROW ENDS.\n", pfx);
        for (int b = 1; b <= 2; b++) {
            char htag[16];
            snprintf(htag, sizeof(htag), "GPH%02d beat", b);
            ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        }
        return;
    }

    /* GP01 v165: probe EVERY open connection with sel 0x100 (+ the 0x107 NULL
     * control); run the full 19-sel map on the connection whose 0x100 answers
     * non-BADARG (the real AGXDeviceUserClient dispatch). */
    ds_journal_write("START", "GP01 agxmap");
    static const struct { uint32_t sel; uint32_t sin; uint32_t sout; } tbl[] = {
        { 0x100, 0x0,   0x98  }, { 0x101, 0x0,   0xa0  }, { 0x102, 0x0,   0x1c8 },
        { 0x103, 0x0,   0x20  }, { 0x104, 0x0,   0x10  }, { 0x105, 0x48,  0x48  },
        { 0x106, 0x8,   0x0   }, { 0x107, 0x0,   0x0   }, { 0x108, 0x0,   0x0   },
        { 0x109, 0x8,   0x8   }, { 0x10a, 0x0,   0x10  }, { 0x10b, 0x10,  0x10  },
        { 0x10c, 0x10,  0x0   }, { 0x10d, 0x8,   0x8   }, { 0x10e, 0x0,   0x0   },
        { 0x10f, 0x0,   0x20  }, { 0x110, 0x8,   0x0   }, { 0x111, 0x0,   0x0   },
        { 0x112, 0x0,   0x1b0 },
    };
    int pickIdx = -1;
    for (int ci = 0; ci < nConns && pickIdx < 0; ci++) {
        uint64_t in[3] = { 0, 0, 0 };
        uint64_t sout[8] = { 0 };
        uint32_t nSO = 8;
        int tmo = 0;
        kern_return_t kr100 = ds_gp_scalar(conns[ci], 0x100, in, 3, sout, &nSO, &tmo);
        uint64_t sout2[8] = { 0 };
        uint32_t nSO2 = 8;
        int tmo2 = 0;
        kern_return_t kr107 = ds_gp_scalar(conns[ci], 0x107, in, 3, sout2, &nSO2, &tmo2);
        dprintf(STDOUT_FILENO, "%s  I[GP01] conn[%d] %s type%u: sel100 -> %s (%d) | sel107 -> %s (%d)\n",
                pfx, ci, connSvcs[ci], connTypes[ci], ds_gp_kr(kr100), kr100, ds_gp_kr(kr107), kr107);
        if (!tmo && kr100 != DS_IO_BAD_ARGUMENT && kr100 != DS_MIG_BAD_ARGUMENTS) pickIdx = ci;
    }
    if (pickIdx < 0) {
        dprintf(STDOUT_FILENO, "%s  I[GP01] NO connection answered non-BADARG on sel100 - the AGXDeviceUserClient\n", pfx);
        dprintf(STDOUT_FILENO, "%s  dispatch is not among the opened types; map cells skipped this run.\n", pfx);
    } else {
        io_connect_t conn = conns[pickIdx];
        dprintf(STDOUT_FILENO, "%s  I[GP01] riding conn[%d] %s type%u for the full map\n",
                pfx, pickIdx, connSvcs[pickIdx], connTypes[pickIdx]);
        int nAns = 0, nTmo = 0;
        for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
            uint32_t sel = tbl[i].sel;
            char tag[24];
            snprintf(tag, sizeof(tag), "GP01 s%03x", sel);
            ds_journal_write("START", tag);
            uint64_t in[3] = { 0, 0, 0 };
            uint64_t sout[8] = { 0 };
            uint32_t nSO = 8;
            uint8_t sbuf[0x1c8];
            memset(sbuf, 0, sizeof(sbuf));
            uint8_t obuf[0x1c8];
            memset(obuf, 0, sizeof(obuf));
            size_t oSz = sizeof(obuf);
            int tmo = 0;
            char hit[96] = "";
            if (sel == 0x107 || sel == 0x108 || sel == 0x10e || sel == 0x111) {
                snprintf(hit, sizeof(hit), "NULL-TABLE (BADARG expected)");
            } else if (tbl[i].sin == 0) {
                kern_return_t kr = ds_gp_scalar(conn, sel, in, 3, sout, &nSO, &tmo);
                snprintf(hit, sizeof(hit), "%s(%d)", ds_gp_kr(kr), kr);
            } else {
                uint64_t *inp = in; uint8_t *sbp = sbuf, *obp = obuf;
                uint64_t *sop = sout; uint32_t *nsop = &nSO; size_t *oszp = &oSz;
                __block kern_return_t kr = KERN_FAILURE;
                __block int rc = 0;
                int sig = ds_ave_guard_run_tmo(^int {
                    kr = pMethod(conn, sel, inp, 3, sbp, tbl[i].sin, sop, nsop, obp, oszp);
                    return 0;
                }, &rc, 4000);
                if (sig != 0) { tmo = 1; kr = DS_IO_GUARD_TMO; }
                snprintf(hit, sizeof(hit), "%s(%d) out=%zu", ds_gp_kr(kr), kr, oSz);
            }
            if (tmo) nTmo++; else nAns++;
            dprintf(STDOUT_FILENO, "%s  I[GP01] sel %03x sin=%#x sout=%#x -> %s\n",
                    pfx, sel, tbl[i].sin, tbl[i].sout, hit);
            ds_journal_write("DONE", tag);
        }
        dprintf(STDOUT_FILENO, "%s  I[GP01] agx-map done: answered=%d tmo=%d\n", pfx, nAns, nTmo);
    }
    ds_journal_write("DONE", "GP01 agxmap");

    /* GP02 v165: VALUE SWEEP on the big-struct sels with EXACT shapes */
    io_connect_t conn = (pickIdx >= 0) ? conns[pickIdx] : MACH_PORT_NULL;
    if (conn == MACH_PORT_NULL) {
        dprintf(STDOUT_FILENO, "%s  I[GP02-05] skipped (no answering connection)\n", pfx);
        for (int b = 1; b <= 2; b++) {
            char htag[16];
            snprintf(htag, sizeof(htag), "GPH%02d beat", b);
            ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        }
        dprintf(STDOUT_FILENO, "%s  H read-offs: no type served the AGX map - pull the kernel log for the\n", pfx);
        dprintf(STDOUT_FILENO, "%s  open-type receipts; the UC class mystery rides on GP00's CLASS= lines.\n", pfx);
        dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
        return;
    }
    ds_journal_write("START", "GP02 values");
    {
        static const struct { uint32_t sel; uint32_t sin; uint32_t pat; const char *nm; } vs[] = {
            { 0x100, 0x98,  0x00, "s100-zero" },
            { 0x100, 0x98,  0xff, "s100-ff"   },
            { 0x101, 0xa0,  0x00, "s101-zero" },
            { 0x101, 0xa0,  0xff, "s101-ff"   },
            { 0x102, 0x1c8, 0x00, "s102-zero" },
            { 0x102, 0x1c8, 0xff, "s102-ff"   },
            { 0x112, 0x1b0, 0x00, "s112-in1b0" },
        };
        for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
            uint8_t inb[0x1c8];
            memset(inb, vs[i].pat, sizeof(inb));
            uint64_t in[3] = { 0, 0, 0 };
            uint64_t sout[8] = { 0 };
            uint32_t nSO = 8;
            uint8_t obuf[0x1c8];
            memset(obuf, 0, sizeof(obuf));
            size_t oSz = sizeof(obuf);
            char tg[32];
            snprintf(tg, sizeof(tg), "GP02 %s", vs[i].nm);
            ds_journal_write("START", tg);
            uint64_t *inp = in; uint8_t *ibp = inb, *obp = obuf;
            uint64_t *sop = sout; uint32_t *nsop = &nSO; size_t *oszp = &oSz;
            __block kern_return_t kr = KERN_FAILURE;
            __block int rc = 0;
            int sig = ds_ave_guard_run_tmo(^int {
                kr = pMethod(conn, vs[i].sel, inp, 3, ibp, vs[i].sin, sop, nsop, obp, oszp);
                return 0;
            }, &rc, 4000);
            kern_return_t krr = sig ? DS_IO_GUARD_TMO : kr;
            dprintf(STDOUT_FILENO, "%s  I[GP02] %s -> %s (%d) out=%zu\n", pfx, vs[i].nm, ds_gp_kr(krr), krr, oSz);
            ds_journal_write("DONE", tg);
        }
    }
    ds_journal_write("DONE", "GP02 values");

    /* GP03 v163: IOSurface-ID cells - surface id poked at the classic offsets */
    ds_journal_write("START", "GP03 iosurf");
    {
        CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        int w = 64, h = 64, bpe = 32;
        CFNumberRef wn = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
        CFNumberRef hn = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &h);
        CFNumberRef bn = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bpe);
        if (wn) CFDictionarySetValue(props, CFSTR("IOSurfaceWidth"), wn);
        if (hn) CFDictionarySetValue(props, CFSTR("IOSurfaceHeight"), hn);
        if (bn) CFDictionarySetValue(props, CFSTR("IOSurfaceBytesPerElement"), bn);
        IOSurfaceRef surf = IOSurfaceCreate(props);
        if (wn) CFRelease(wn);
        if (hn) CFRelease(hn);
        if (bn) CFRelease(bn);
        if (props) CFRelease(props);
        if (!surf) {
            dprintf(STDOUT_FILENO, "%s  I[GP03] IOSurfaceCreate failed - cells skipped\n", pfx);
        } else {
            uint32_t sid = (uint32_t)IOSurfaceGetID(surf);
            dprintf(STDOUT_FILENO, "%s  I[GP03] IOSurface id=%#x (64x64)\n", pfx, sid);
            static const struct { uint32_t sel; uint32_t sin; uint32_t off; const char *nm; } cs[] = {
                { 0x100, 0x98,  0x38, "s100+38" },
                { 0x101, 0xa0,  0x38, "s101+38" },
                { 0x105, 0x48,  0x38, "s105+38" },
                { 0x112, 0x1b0, 0x38, "s112+38" },
                { 0x112, 0x1b0, 0x30, "s112+30" },
            };
            for (size_t i = 0; i < sizeof(cs) / sizeof(cs[0]); i++) {
                uint8_t inb[0x1c8];
                memset(inb, 0, sizeof(inb));
                *(uint32_t *)(inb + cs[i].off) = sid;
                uint64_t in[3] = { 0, 0, 0 };
                uint64_t sout[8] = { 0 };
                uint32_t nSO = 8;
                uint8_t obuf[0x1c8];
                memset(obuf, 0, sizeof(obuf));
                size_t oSz = sizeof(obuf);
                char tg[32];
                snprintf(tg, sizeof(tg), "GP03 %s", cs[i].nm);
                ds_journal_write("START", tg);
                uint64_t *inp = in; uint8_t *ibp = inb, *obp = obuf;
                uint64_t *sop = sout; uint32_t *nsop = &nSO; size_t *oszp = &oSz;
                __block kern_return_t kr = KERN_FAILURE;
                __block int rc = 0;
                int sig = ds_ave_guard_run_tmo(^int {
                    kr = pMethod(conn, cs[i].sel, inp, 3, ibp, cs[i].sin, sop, nsop, obp, oszp);
                    return 0;
                }, &rc, 4000);
                kern_return_t krr = sig ? DS_IO_GUARD_TMO : kr;
                dprintf(STDOUT_FILENO, "%s  I[GP03] %s sid@%#x -> %s (%d) out=%zu\n",
                        pfx, cs[i].nm, cs[i].off, ds_gp_kr(krr), krr, oSz);
                ds_journal_write("DONE", tg);
            }
            CFRelease(surf);
        }
    }
    ds_journal_write("DONE", "GP03 iosurf");

    /* GP04 v163: hostile-handle sweep on the small u64-struct sels */
    ds_journal_write("START", "GP04 handles");
    {
        static const struct { uint32_t sel; uint32_t sin; } hs[] = {
            { 0x106, 0x8 }, { 0x109, 0x8 }, { 0x10b, 0x10 }, { 0x10c, 0x10 },
            { 0x10d, 0x8 }, { 0x110, 0x8 }, { 0x103, 0x20 }, { 0x104, 0x10 },
        };
        for (size_t i = 0; i < sizeof(hs) / sizeof(hs[0]); i++) {
            uint8_t inb[0x20];
            memset(inb, 0, sizeof(inb));
            *(uint64_t *)inb = 0xdeadbeefdeadbeefULL;
            uint64_t in[3] = { 0, 0, 0 };
            uint64_t sout[8] = { 0 };
            uint32_t nSO = 8;
            uint8_t obuf[0x40];
            size_t oSz = sizeof(obuf);
            char tg[32];
            snprintf(tg, sizeof(tg), "GP04 s%03x", hs[i].sel);
            ds_journal_write("START", tg);
            uint64_t *inp = in; uint8_t *ibp = inb, *obp = obuf;
            uint64_t *sop = sout; uint32_t *nsop = &nSO; size_t *oszp = &oSz;
            __block kern_return_t kr = KERN_FAILURE;
            __block int rc = 0;
            int sig = ds_ave_guard_run_tmo(^int {
                kr = pMethod(conn, hs[i].sel, inp, 3, ibp, hs[i].sin, sop, nsop, obp, oszp);
                return 0;
            }, &rc, 4000);
            kern_return_t krr = sig ? DS_IO_GUARD_TMO : kr;
            dprintf(STDOUT_FILENO, "%s  I[GP04] sel %03x sin=%#x deadbeef -> %s (%d) out=%zu\n",
                    pfx, hs[i].sel, hs[i].sin, ds_gp_kr(krr), krr, oSz);
            ds_journal_write("DONE", tg);
        }
        dprintf(STDOUT_FILENO, "%s  I[GP04] read: any SUCCESS on 0xdeadbeef handles = the handle-table hole.\n", pfx);
    }
    ds_journal_write("DONE", "GP04 handles");

    /* GP05 v163: churn on the 0x98-shape sel (leak/cap oracle) */
    ds_journal_write("START", "GP05 churn");
    {
        uint8_t inb[0x98];
        memset(inb, 0, sizeof(inb));
        for (int i = 0; i < 8; i++) {
            uint64_t in[3] = { 0, 0, 0 };
            uint64_t sout[8] = { 0 };
            uint32_t nSO = 8;
            uint8_t obuf[0x98];
            size_t oSz = sizeof(obuf);
            char tg[24];
            snprintf(tg, sizeof(tg), "GP05 churn#%d", i);
            ds_journal_write("START", tg);
            uint64_t *inp = in; uint8_t *ibp = inb, *obp = obuf;
            uint64_t *sop = sout; uint32_t *nsop = &nSO; size_t *oszp = &oSz;
            __block kern_return_t kr = KERN_FAILURE;
            __block int rc = 0;
            int sig = ds_ave_guard_run_tmo(^int {
                kr = pMethod(conn, 0x100, inp, 3, ibp, 0x98, sop, nsop, obp, oszp);
                return 0;
            }, &rc, 4000);
            kern_return_t krr = sig ? DS_IO_GUARD_TMO : kr;
            dprintf(STDOUT_FILENO, "%s  I[GP05] churn#%d sel100 -> %s (%d)\n", pfx, i, ds_gp_kr(krr), krr);
            ds_journal_write("DONE", tg);
        }
    }
    ds_journal_write("DONE", "GP05 churn");

    /* GP06: close + reopen - the teardown path (refcount shot) */
    ds_journal_write("START", "GP06 close-reopen");
    {
        kern_return_t kr = pClose(conn);
        dprintf(STDOUT_FILENO, "%s  I[GP06] IOServiceClose -> %s (%d)\n", pfx, ds_gp_kr(kr), kr);
        conn = MACH_PORT_NULL;
    }
    ds_journal_write("DONE", "GP06 close-reopen");

    /* beats - the system-alive witnesses (a GPU wedge shows here) */
    for (int b = 1; b <= 2; b++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "GPH%02d beat", b);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(300000);
    }

    dprintf(STDOUT_FILENO, "%s  H read-offs: GP00 = the seatbelt verdict + the UC class (type1). GP01 = the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  RE'd AGX map (0x100-0x112): NULL-table sels must BADARG; live sels with exact\n", pfx);
    dprintf(STDOUT_FILENO, "%s  shapes = the true gate map. GP03 = valid IOSurfaceID rides; kernel log = strings.\n", pfx);
}
