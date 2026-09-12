//  ViewController.m - DirtySlide UI SHELL ONLY (v136 surface-split, v142 regroup)
//  The harness is divided by attack surface; this file holds the table + runner
//  + streaming log pane. v142 = the iOS 26.6 (23G71) RE-baseline regroup:
//    probe_ave_tkill.m       ROW A - the daemon-kill factory (14 symbol-pinned aborts)
//    probe_ave_rows_bd.m     ROW B - multipass short-blob OOB read
//    probe_ave_opts.m        ROW C - kernel-QP paths (map repro + ungated fields + DPB)
//    probe_ave_rows_bd.m     ROW D - new surfaces (DPB_* family, HEVC H9, NULL-plane)
//    probe_daemon_cache.m    escape receipts (the class-13 primitive)
//    probe_mobilegestalt.m   the MG devType spoof (reboot test pending)
//  CUT v142: mediaremoted 28973 (dead since v40), IOKit 43805 flood (1/17, never
//  escalated - the race witnesses are renamed on 26.6: Client_Die:2333 /
//  CheckStopped:2379 / CleanClient:2445; grep the kernel log manually if needed).
#import "ds_core.h"
#import "ViewController.h"

static ProbeEntry kProbes[] = {
    { "A. AVE T-KILL 26.6",
      "The FINAL kill factory: 12 deterministic kills (all re-confirmed 23:43). CUT: MarkCurrentFrameAsLTR + SetDPB x2 (inert - the DPB-snapshot parse never runs on our session shape). The .ips is the receipt. MAY CRASH DAEMON",
      probe_ave_tkill },
    { "B. AVE OOB-PRIMITIVE 26.6",
      "SAME-CLASS DOUBLE-HIT DISCRIMINATOR v158: v157 landed two hits (FI1 Inf + FN2 NaN, both B+575 CONS-CLASS); FI1 bytes equalled v156-SA3 BIT-EXACT across boots while FN2 differed at equal size - content effect vs encoder-state ordinality UNRESOLVED. K0 + FB0 + FI x5 / FN x4 / FA x3 fanout grinds: two same-class hits with EQUAL H = content-only encoding => FN != FI at equal B = byte-level TAINT-DIVERGENT; unequal H = ordinality rules. MAY WEDGE/CRASH DAEMON",
      probe_ave_oob },
    { "C. AVE KERNEL 26.6",
      "The QP-map REGRESSION CORE v145: M3/W6/B180/K4c/K4W = the pinned 26.6 classes (1029/1022/1018/4053/4042). The MCTF front is CLOSED (the armed sessions die at ImgBuf-verify pre-kernel - the 23:30 kernel log). Any class drift = the firmware changed. MAY CRASH KERNEL",
      probe_ave_opts },
    { "D. AVE BLITTER-KILL 26.6",
      "The vt_Copy NULL-plane repro (v143 trim: the D01-D04 discovery cells rode INERT and are CUT): mode-0 biplanar 420v CreateWithBytes -> the guard-free blitter ldrb @fn+0x40 = the second deterministic daemon-kill class on 23G71. MAY CRASH DAEMON",
      probe_ave_newsurf },
    { "E. DAEMON-CACHE ESCAPE 26.6",
      "RECIPE SWEEP v159: the legacy class-13/gestaltcache recipe is DENIED (-3) on this boot, but upstream bad_query claims /var/mobile/Containers/Data/{Application,InternalDaemon,PluginKitPlugin} on 26.x. EC90 sweeps class x group x part x flags (incl. SecTask-discovered app groups = the iOS-26 sacrifice arm) then AUTO-HUNTS videocodecd\'s InternalDaemon container (prefs-identified) for staged stats/surface sentinels - READ-ONLY, no epoch cost.",
      probe_daemon_cache },
    { "F. MobileGestalt 64747",
      "The DEVICE-IDENTITY SPOOF: the escape grants O_RDWR on the MobileGestalt cache plist; the plant flips CacheVersion/ProductType/ChipID + CacheData display slots. ave.videoencoder imports _MGGetStringAnswer and the kernel UserQpMap size formula branches on devType - a REBOOT-SURVIVING flip = a controllable kernel-config input. The reboot test is the verdict. MAY CRASH MOBILEGESTALTD",
      probe_mobilegestalt },
    { "G. MACHVM-DRB 64747",
      "The NEW mach_vm MIG family (26.6: subsystem end=4830, slots 4825-4829 = deferred-reclamation): REGISTER takes user {tag,start,end}[] on the OWN task port with NO entitlement, tag top-byte rides the vm-enter flags bits 24-31, NO guarded-page validation, shadow cap 1024. Cells: status/reg/query/unreg lifecycle + 8 gate-negatives + tag-hi sweep + the register-x-unmap RACE + the 1024-cap grind. ZERO epoch cost. MAY CRASH KERNEL",
      probe_machvm_dr },
    { "H. IOGPU-UC 64747",
      "The UNENTITLED GPU user client - v163 rides the RE'd AGXDeviceUserClient dispatch (getTargetAndMethodForIndex 0x82c8b60: sels 0x100-0x112, 19-entry table @0xd544f0, scalarIn=3 each): GP00 open+class, GP01 exact-shape map, GP02 zero/FF value sweep, GP03 valid-IOSurfaceID cells, GP04 deadbeef-handle sweep, GP05 churn. ZERO epoch cost. MAY CRASH KERNEL (GPU)",
      probe_iogpu },
    { "I. M2SCALER-CSC 64747",
      "THE CORRUPT-MEMORY GEOMETRY v164: the 23G83 kext RE found an Apple-documented HW corruption failure mode gated ONLY by geometry (dest height<=32, source width>128, planes>1 - 'This version of hardware can corrupt memory...'). M201 fires the EXACT config through the videocodecd pixel-transfer proxy (1920x1080 IOSURF 420v -> 1920x32 session); M202/203/205/206 isolate each arm; M207/208/209 sweep the format table + 4K max-width; M2A/M2B probe the DIRECT IOSurfaceAcceleratorClient/IOServiceOpen route. KERNEL LOG + PANIC = the verdict. MAY CRASH KERNEL",
      probe_m2scaler },
    { "J. M2-HISTOGRAM 64747",
      "THE SIGNED-OFFSET WRAP v173: the kext histogram rect gate (IosaColorManagerMSR4.cpp:246 AND the 26.6.1-new MSR23.cpp:874) reads client HistogramOffsetX/Y as SIGNED int and tests Bw < (u32)(Hx+Hw) - a negative offset WRAPS the sum and PASSES ({-16, W=1920} -> 1904 < 1920) with the HW rect starting OUTSIDE the surface; the mismatch case only sets ctx+0x1fd5 (flag, not reject). Bins are client-readable (sel7 GetHistogram + the dst HistogramPixelBins attachment). JH01 in-bounds control -> JH02/03/04 the wraps -> JH05/06 must-REJECT controls; src = POSITION-GRADIENT so OOB pixels can never produce the in-bounds bin set. BINS-HASH != base = THE OOB DMA READ WITNESSED; A/C sentinel diffs = THE OOB WRITE. A PANIC = THE 64747. MAY CRASH KERNEL",
      probe_iosa_hist },
    { "K. AVD-RES-EDGE 64747",
      "THE RESOLUTION GATE EDGES v174: AppleAVD self-gates at init (com.apple.videotoolbox.hardwarevideodecoder set programmatically - direct IOServiceOpen DEAD); the path is videocodecd. The kext setResolutionInfo gate is honest unsigned (maxDim 16888, minLim 8192/16384, no wrap) - row K drives CRAFTED SPS DIMS AT THE EDGES through it via VTDecompressionSession: AV0 baseline 128x128, AV1 accept-edge 16880x8192, AV2 over-gate reject control 16896x8192, AV3 swapped 8192x16880, AV4 minLim probe 16768x16768, AV5 below-min 16x16, AV6 divergence (format 64x64 vs SPS 16880x8192 = the plugin's exceeds-allocated-size arm). The prize behind the gate = the FW command PATCH ENGINE (bounded kernel bitfield writes; the alloc-vs-bound size consistency is the candidate). Oracle: dec_out_cb dims + kernel log + .ips. MAY CRASH KERNEL",
      probe_avd },
    { "L. IOGPU-UAF 64788",
      "THE STALE-RESOURCE-TABLE UAF v178 (23G71 Ghidra + macOS 26.6 KDK-verified): get_resource_by_id (FUN_023ad728) grabs table[ns+0x10][id] with NO liveness check (obj->[0xc]++ on a possibly-freed IOGPUSysMemory); the purgeable dispatcher runs the +0x24/+0x28 dance on the found object. The KDK gives the REAL interface: IOGPUNewResourceArgs 0x58 (type@0 cacheMode@4 [ror(w,8)<10 gate] flags@15 sizes@20/28 planes@30 iosurfaceID@38 plane@3c opt5@40 alloc@48), sel9 = s_new_resource (StIn VARIABLE), sel12 = s_set_resource_purgeable (2 scalars), trap3 = t_set_resource_purgeable(m,m,m); type 0x82 chain = find_iosurface_for_id(args+0x38, task) -> plane check -> newResourceWithIOSurface - THE DIMS COME FROM THE SURFACE (the 1x65535 vector). GU0 conn -> GU1 dual-oracle baseline -> GU2 direct 0x82 creates (64x64 control vs 1x65535 plant + variants, stale sweep after each) -> GU3 broad sweep -> GU4 IOSurface-churn spray + dual-oracle confirm (0xe00002be = the deref ran on reclaimed heap) -> GU5 3x stability. ZERO epoch. MAY CRASH KERNEL (GPU)",
      probe_iogpu_uaf },
    { "M. IMAGEIO 65346",
      "THE SCALER ROWBYTES WRAP v179 (the 26.6.1 diff #1 = CVE-2026-65346): _CGImageCreateByScaling (iio71 @0x18654d44c) computes the CG-fallback rowBytes as mul w22,w27,w8 @0x18654daa0 (dstWidth*bpp, 32-BIT) -> undersized malloc + a scale blit that fills rows of the TRUE geometry = controlled heap overflow, attacker-controlled content; 23G83 adds the 64-bit 'CG fallback rowBytes overflow: dstWidth=%zu * bpp=%u' gate (string ABSENT in iio71 - byte-verified). IOT00 control 64x64 -> IOT01 the wrap (thumbnail on a W*4>=2^32 crafted source) -> IOT02 the direct dlsym scaler (the symbol IS exported in 26.6) -> IOT03 the width ladder = the 26.6 decode-clamp characterization -> IOH01-04 beats. Image bytes IN MEMORY (own deflate). MAY CRASH THE APP; A PANIC = THE 64747",
      probe_imageio_65346 },
    { "N. IOGPU-UAF-RECLAIM 64788",
      "THE RECLAIM-DIFFERENTIAL v185 OG (row L found the stale entry; row N makes the slot SPEAK): create_resource_iosurface leaks a kalloc(0x100) IOGPUSysMemory on the dims-overflow path (table entry NOT cleared, NO release) and set_resource_purgeable derefs it (+0x24 atomic dec, +0x28/+0x10 loads) with NO zone_require (verified: xnu-12377 has NO element sequestration for kalloc.256 - the freed slot is LIFO-recyclable IMMEDIATELY; the only 'sequestered list' is empty VA chunks refilled with ZEROED pages). OG00 Metal sanity + the purgeable channel map (fast-path sel12/trap3 from row L, fallback sweep 0..24) -> OG01 overflow creates (Metal arm + row-L sel9 1x0xFFFF plant) + stale sweep = the PRE witness -> OG02 the 512x0x100 mach_msg kalloc.256 reclaim burst with CONTROLLED BYTES (+0x10=4142434445464748, +0x24=4, +0x28=0) = the POST witness (OUT=ATTACKER-BYTES = RECLAIM PROVEN) -> OG03 never-created-id control (must stay 0xe00002c2) -> OG04 300x MTLBuffer(0x100) = the original PoC arm (arbitrates the primitive). ZERO epoch (4 beats). MAY CRASH KERNEL (GPU)",
      probe_iogpu_uaf_og },
};
static const int kNumProbes = sizeof(kProbes) / sizeof(kProbes[0]);

/* ---- ViewController -------------------------------------------------- */

@interface ViewController ()
@property (nonatomic, strong) NSMutableString *logBuffer;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UITextField *flagField;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.logBuffer = [NSMutableString string];

    /* footer: the v175 FLAGS FIELD + the streaming log pane */
    CGFloat fw = self.tableView.bounds.size.width;
    if (fw <= 0) fw = 320;
    UIView *ftr = [[UIView alloc] initWithFrame:CGRectMake(0, 0, fw, 380)];
    UITextField *ff = [[UITextField alloc] initWithFrame:CGRectMake(8, 4, fw - 16, 32)];
    ff.borderStyle = UITextBorderStyleRoundedRect;
    ff.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    ff.autocorrectionType = UITextAutocorrectionTypeNo;
    ff.autocapitalizationType = UITextAutocapitalizationTypeNone;
    ff.placeholder = @"flags: -avdskip128 -avdsps 16880x8192";
    ff.clearButtonMode = UITextFieldViewModeWhileEditing;
    ff.backgroundColor = [UIColor secondarySystemBackgroundColor];
    [ftr addSubview:ff];
    self.flagField = ff;
    UITextView *log = [[UITextView alloc] initWithFrame:CGRectMake(0, 40, fw, 336)];
    log.editable = NO;
    log.selectable = YES;
    log.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    log.backgroundColor = [UIColor systemBackgroundColor];
    log.textColor = [UIColor labelColor];
    log.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    log.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    self.logView = log;
    [ftr addSubview:log];
    self.tableView.tableFooterView = ftr;

    /* v126: -autorun <row> launch-arg automation (devicectl CLI - no tapping).
     * Row index into kProbes (0..kNumProbes-1); saves the REAL stdout so
     * appendLog tees every receipt to it, then runs the probe after the UI is up.
     * Example: xcrun devicectl device process launch --console <udid> <bundle> -- -autorun 6 */
    {
        NSArray *args = [[NSProcessInfo processInfo] arguments];
        for (NSUInteger ai = 0; ai + 1 < [args count]; ai++) {
            if ([[args objectAtIndex:ai] isEqualToString:@"-autorun"]) {
                int row = [[args objectAtIndex:ai + 1] intValue];
                if (row >= 0 && row < kNumProbes) {
                    ProbeEntry *e = &kProbes[row];
                    g_ds_autorun = 1;
                    g_ds_orig_stdout = dup(STDOUT_FILENO);
                    [self appendLog:[NSString stringWithFormat:@"[+] autorun: row %d = %s\n", row, e->name]];
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{
                        [self runProbe:e->probe name:e->name desc:e->desc tag:"autorun-CLI"];
                    });
                }
                break;
            }
        }
    }

    [self appendLog:[NSString stringWithFormat:@"[+] DirtySlide Privileged Boundary Hunter v6 (iOS %@) - v175 FLAGS FIELD + AVD RESOLUTION-GATE EDGES row\n",
        [[UIDevice currentDevice] systemVersion]]];
    [self appendLog:@"[+] rows: A T-KILL | B OOB | C KERNEL | D BLITTER | E escape | F MG | G MACHVM-DRB | H IOGPU | I M2SCALER | J M2-HISTOGRAM | K AVD-RES | L IOGPU-UAF | M IMAGEIO-65346 | N OG-RECLAIM\n"];
}

- (void)appendLog:(NSString *)text {
    [self.logBuffer appendString:text];
    if (self.logBuffer.length > 800000)
        [self.logBuffer deleteCharactersInRange:NSMakeRange(0, self.logBuffer.length - 800000)];
    self.logView.text = self.logBuffer;
    if (self.logBuffer.length > 0)
        [self.logView scrollRangeToVisible:NSMakeRange(self.logBuffer.length - 1, 1)];
    /* v126: -autorun CLI mode - tee every log line to the REAL stdout (saved BEFORE
     * the probe pipe redirect) so devicectl device process launch --console captures
     * the full receipts. Never write to STDOUT_FILENO here - during a probe that is
     * the pipe (would self-feed the drain loop). */
    if (g_ds_autorun && g_ds_orig_stdout >= 0) {
        const char *utf = [text UTF8String];
        if (utf) { ssize_t w = write(g_ds_orig_stdout, utf, strlen(utf)); (void)w; }
    }
}

/* ---- table ----------------------------------------------------------- */

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 1; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return kNumProbes; }

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *cid = @"ProbeCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cid];
    if (!cell)
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:cid];
    ProbeEntry *e = &kProbes[ip.row];
    cell.textLabel.text = [NSString stringWithUTF8String:e->name];
    cell.detailTextLabel.text = [NSString stringWithUTF8String:e->desc];
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

static int g_ds_probe_busy = 0;   /* v67: serialize probes - shared static state */
static int g_ds_autorun = 0;        /* v126: -autorun N launch arg (devicectl CLI automation - no tapping) */
static int g_ds_orig_stdout = -1;   /* v126: the REAL stdout saved before the probe pipe redirect - appendLog tees to it so devicectl --console sees every receipt */

- (void)runProbe:(void (*)(const char *))probe name:(const char *)name desc:(const char *)desc tag:(const char *)tag {
    if (g_ds_probe_busy) {
        [self appendLog:@"[+] a probe is already running - wait for it to finish, then re-tap\n"];
        return;
    }
    g_ds_probe_busy = 1;
    /* v175: push the FLAGS FIELD into the harness - every probe parses it like
     * launch args (ds_flags_*); devicectl launch args still work alongside */
    [self.flagField resignFirstResponder];
    ds_flags_set(self.flagField.text.UTF8String);
    [self appendLog:[NSString stringWithFormat:@"[+] flags field: %@\n",
        self.flagField.text.length ? self.flagField.text : @"(empty - launch args only)"]];
    [self appendLog:[NSString stringWithFormat:@"[+] scanning: %s - %s\n", name, desc]];

    /* v57: read back the run journal - a START without a DONE names the cell that
       was running when any death (client OOM/SIGKILL or daemon kill) landed. */
    {
        char jb[1024];
        if (ds_journal_readback(jb, sizeof(jb)))
            [self appendLog:[NSString stringWithFormat:@"%s", jb]];
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int origStdout = dup(STDOUT_FILENO);
        int pfd[2];
        if (pipe(pfd) != 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                g_ds_probe_busy = 0;
            });
            return;
        }
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);
        int rd = pfd[0];

        /* v89: drain the pipe on a SEPARATE queue WHILE the probe runs - the 64KB
           pipe must be drained concurrently or the probe deadlocks on dprintf. */
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            char rbuf[16384];
            ssize_t n;
            for (;;) {
                n = read(rd, rbuf, sizeof(rbuf) - 1);
                if (n > 0) {
                    rbuf[n] = 0;
                    NSString *chunk = [[NSString alloc] initWithBytes:rbuf length:(NSUInteger)n encoding:NSUTF8StringEncoding];
                    if (!chunk) chunk = [NSString stringWithFormat:@"%s", rbuf];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [self appendLog:chunk];
                    });
                    continue;
                }
                if (n < 0 && errno == EINTR) continue;
                break;
            }
            close(rd);
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendLog:@"\n"];
                g_ds_probe_busy = 0;
                /* v126: autorun CLI mode - the run is done, exit so devicectl --console returns */
                if (g_ds_autorun) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{
                        exit(0);
                    });
                }
            });
        });

        probe("");
        dprintf(STDOUT_FILENO, "[ ] done - %s (%s)\n", name, tag);

        close(STDOUT_FILENO);
        dup2(origStdout, STDOUT_FILENO);
        close(origStdout);
    });
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tableView deselectRowAtIndexPath:ip animated:YES];
    ProbeEntry *e = &kProbes[ip.row];
    [self runProbe:e->probe name:e->name desc:e->desc tag:"runtime, real-action"];
}

@end
