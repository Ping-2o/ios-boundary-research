/* ds_core.h - DirtySlide shared harness API (v142 - iOS 26.6 regroup)
 *
 * v142 regroups the harness around the 26.6 RE re-baseline (23G71), four
 * AVE rows A-D + the escape rows. Cross-file contract: ds_core.h shared by
 * ds_core.m (guard, callbacks, journal, epoch, replay, teardown, escape),
 * probe_ave_tkill.m (row A), probe_ave_opts.m (rows B/C/D),
 * probe_daemon_cache.m, probe_mobilegestalt.m.
 */
#ifndef DS_CORE_H
#define DS_CORE_H

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
#include <pthread.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_time.h>
#include <dispatch/dispatch.h>
#include <xpc/xpc.h>
#include <dirent.h>

/* ---- VTMultiPassStorage private API (in .tbd, not in the public header) ---- */
extern OSStatus VTMultiPassStorageSetDataAtTimeStamp(
    VTMultiPassStorageRef storage,
    const CMTime *pts,
    CFDataRef data,
    CFErrorRef *errorOut) API_AVAILABLE(macos(10.10), ios(8.0), tvos(10.2), visionos(1.0));

/* ---- encoder-output callback counters (ave_out_cb/dec_out_cb, ds_core.m) ---- */
extern volatile sig_atomic_t g_ave_cb_fires;   /* encoder-output callbacks (any status) */
extern volatile sig_atomic_t g_ave_cb_ok;      /* callbacks with st==0 (real sample out) */
extern volatile sig_atomic_t g_ave_cb_err;     /* last non-zero OSStatus seen by the cb */
extern volatile uint64_t g_ave_cb_fire_mach;   /* mach_absolute_time of the first cb fire */
extern volatile uint64_t g_ave_cb_bytes;       /* compressed output bytes seen by the cb */
extern volatile uint64_t g_ave_cb_hash;        /* v124: FNV-1a-64 over ok samples - the byte-level oracle */
extern volatile int g_ave_mk_on;               /* v153: the marker scan enable */
extern volatile uint8_t g_ave_mk[4];           /* v153: the 4-byte marker */
extern volatile int g_ave_mk_hits;             /* v153: hits in this cell's samples */
extern volatile uint64_t g_ave_cb_tlast;       /* v155: mach time of the LAST ok cb (0 = none) */
extern volatile int g_ave_cb_ivn;              /* v155: inter-ok-cb interval samples this cell */
extern volatile uint64_t g_ave_cb_ivsum;       /* v155: sum of intervals (microseconds) */
extern volatile uint64_t g_ave_cb_ivmax;       /* v155: max interval (microseconds) */
extern volatile int g_ave_fp_on;               /* v49: fingerprint the LAST ok output sample (1 = capture) */
extern volatile int g_ave_fp_len;
extern volatile uint8_t g_ave_fp[12];          /* first 12 bytes of the last ok sample */
extern volatile int g_ave_cap_on;              /* v77: retain the FULL first ok sample (SEI-REFEED) */
extern CMSampleBufferRef g_ave_cap_sb;         /* v77: the retained sample (released in the SELF-DECODE tail) */
extern volatile sig_atomic_t g_dec_cb_fires, g_dec_cb_ok, g_dec_cb_err;
extern volatile int64_t g_dec_out_w, g_dec_out_h;
extern uintptr_t g_ave_fault_addr;             /* last guarded fault address (read by receipt printers) */
extern volatile int g_opt_conn_poisoned;       /* v106: 1 = FigRPC conn died - NEVER Invalidate once set */
extern int g_ds_epoch_ops;                     /* daemon-epoch op counter (G8 exponential-slow cap) */
#define DS_EPOCH_CAP 24

/* ---- shared functions (ds_core.m) ---- */
extern void ds_fp_hex(char *out, size_t n);
extern void ave_out_cb(void *refcon, void *sfr, OSStatus st, VTEncodeInfoFlags fl, CMSampleBufferRef sb);
extern void dec_out_cb(void *refcon, void *sfr, OSStatus st, VTDecodeInfoFlags fl, CVImageBufferRef ib,
                       CMTime pts, CMTime dur);
extern void ds_ave_stamp(char *buf, size_t n);
extern void ds_ave_wd_arm(long tmoMs);
extern void ds_ave_wd_disarm(void);
extern int ds_ave_guard_run(int (^blk)(void), int *rcOut);
extern int ds_ave_guard_run_tmo(int (^blk)(void), int *rcOut, long tmoMs);
extern double ds_ave_elapsed_ms(uint64_t t0);
extern void ds_journal_init(void);
extern void ds_journal_write(const char *ev, const char *tag);
extern int ds_journal_readback(char *out, size_t n);
extern void ds_epoch_bump(const char *pfx, const char *tag);
extern int ds_epoch_exhausted(const char *pfx);
extern void ds_ave_replay(const char *pfx, const char *tag, int sessW, int sessH, int inSize,
                          FourCharCode codec, OSType inFmt, int frames, int doComplete);
extern void ds_opt_teardown(const char *pfx, const char *tag, VTCompressionSessionRef s);
extern int64_t ds_esc_consume(const char *path);   /* bad_query class-13 sandbox-extension consume */
extern void ds_esc_release(int64_t h);
extern const char *ds_esc_err(long long h);
extern void ds_esc_row(const char *pfx, const char *tag, const char *path, int mode);

/* ---- probe entry points (one button each) ---- */
extern void probe_ave_tkill(const char *pfx);     /* row A - the kill factory */
extern void probe_ave_oob(const char *pfx);       /* row B - memory corruption */
extern void probe_ave_opts(const char *pfx);      /* row C - kernel paths */
extern void probe_ave_newsurf(const char *pfx);   /* row D - new surfaces */
extern void probe_daemon_cache(const char *pfx);
extern void probe_mobilegestalt(const char *pfx);
extern void probe_machvm_dr(const char *pfx);     /* row G - mach_vm DRB MIG 4825-4829 */
extern void probe_iogpu(const char *pfx);         /* row H - IOGPUDeviceUserClient */
extern void probe_iogpu_uaf(const char *pfx);     /* row L - IOGPUFamily UAF 64788 */
extern void probe_iogpu_uaf_og(const char *pfx);  /* row N - IOGPU UAF 64788 reclaim-differential */
extern void probe_m2scaler(const char *pfx);      /* row I - M2ScalerCSC corrupt-memory geometry */
extern void probe_iosa_hist(const char *pfx);     /* row J - M2ScalerCSC histogram signed-offset wrap */
extern void probe_avd(const char *pfx);           /* row K - AppleAVD resolution-gate edges */
extern void probe_imageio_65346(const char *pfx); /* row M - ImageIO 65346 scaler rowBytes wrap */

/* v137: the X5 deterministic daemon kill (ReferenceL0 CFArray-of-CFString), exported
 * so the IOK 43805 row can fire it mid-race as the FORCED kext-detach trigger. */
extern void ds_tk_kill(const char *pfx, const char *tag);

/* ---- v175: the UI FLAGS FIELD (injected run args) ----
 * The ViewController pushes the text field content here on every probe start;
 * probes parse it like launch args (ds_flags_* names INCLUDE the leading dash). */
extern void ds_flags_set(const char *text);            /* tokenize + store */
extern int ds_flags_present(const char *name);         /* "-avdskip128" -> 1/0 */
extern const char *ds_flags_value(const char *name);   /* "-avdsps" -> next token or NULL */

/* ---- kProbes table row type (ViewController.m shell) ---- */
typedef struct {
    const char *name;
    const char *desc;
    void (*probe)(const char *pfx);
} ProbeEntry;

#endif /* DS_CORE_H */
