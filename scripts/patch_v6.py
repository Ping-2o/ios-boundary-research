#!/usr/bin/env python3
"""v6: the main dyld cache is a STUB - enumerate subcaches + per-file images."""
import sys

p = 'UI/ViewController.m'
src = open(p).read()

HELPER = r'''
/* map a cache file offset to a vm address (inverse of ds_v5_map_addr) */
static uint64_t ds_v5_map_file_to_vm(int fd, uint64_t fsize, uint32_t moff, uint32_t mcnt,
                                     int stride, uint64_t foff) {
    for (uint32_t i = 0; i < mcnt; i++) {
        uint8_t me[40];
        off_t eoff = (off_t)((uint64_t)moff + (uint64_t)i * (uint64_t)stride);
        if (eoff < 0 || eoff + stride > (off_t)fsize) break;
        if (pread(fd, me, stride, eoff) != stride) break;
        uint64_t a, s, fo;
        memcpy(&a, me, 8);
        memcpy(&s, me + 8, 8);
        memcpy(&fo, me + 16, 8);
        if (foff >= fo && foff < fo + s && a > 0) return a + (foff - fo);
    }
    return 0;
}

/* read a bounded NUL-terminated path from a cache file; returns length or -1 */
static int ds_v6_read_path(int fd, uint64_t fsize, uint64_t pOff, uint32_t pSize,
                           char *out, size_t outsz) {
    if (pOff >= fsize || pSize == 0 || pSize > 4096 || outsz == 0) return -1;
    uint32_t pr = pSize < outsz - 1 ? pSize : (uint32_t)(outsz - 1);
    if (pread(fd, out, pr, (off_t)pOff) != (ssize_t)pr) return -1;
    out[pr] = 0;
    return (int)pr;
}

static void ds_gi_scan_cache(void) {
    dprintf(STDOUT_FILENO, "[V] --- v6: stub detection + subcache image enumeration ---\n");
    dprintf(STDOUT_FILENO, "[V] main file may be a STUB (tables only); images live in\n");
    dprintf(STDOUT_FILENO, "[V] subcaches (.1-.8, .dylddata). Enumerate EVERY cache file.\n");
    const char *paths[] = {
        "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
        NULL
    };
    int fd = -1;
    const char *used = NULL;
    for (int i = 0; paths[i]; i++) {
        fd = open(paths[i], O_RDONLY);
        if (fd >= 0) { used = paths[i]; break; }
        dprintf(STDOUT_FILENO, "[V]   cache %-52s %s\n", paths[i], strerror(errno));
    }
    if (fd < 0) {
        dprintf(STDOUT_FILENO, "[V]   dyld cache not readable - scanner cannot run.\n");
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return; }
    uint64_t fsize = (uint64_t)st.st_size;
    dprintf(STDOUT_FILENO, "[V]   A) main cache READABLE: %s\n", used);
    dprintf(STDOUT_FILENO, "[V]      file size = %llu bytes (%llu MB)\n",
            (unsigned long long)fsize, (unsigned long long)(fsize >> 20));

    uint8_t hdr[0x100];
    ssize_t gr = pread(fd, hdr, sizeof(hdr), 0);
    if (gr < 0x20) { close(fd); return; }
    char magic[17]; memcpy(magic, hdr, 16); magic[16] = 0;
    uint32_t moff, mcnt;
    memcpy(&moff, hdr + 0x10, 4);
    memcpy(&mcnt, hdr + 0x14, 4);
    dprintf(STDOUT_FILENO, "[V]      magic=\"%s\" mappings=%u @0x%x\n", magic, mcnt, moff);
    if (memcmp(magic, "dyld", 4) != 0 || mcnt == 0 || mcnt > 0x1000 || moff >= fsize) {
        dprintf(STDOUT_FILENO, "[V]      not a dyld cache - abort\n");
        close(fd);
        return;
    }

    /* dump ALL mapping entries + mapping-size SUM (stub test) */
    int stride = 40;
    {
        uint8_t m0[40];
        if (pread(fd, m0, sizeof(m0), (off_t)moff) == (ssize_t)sizeof(m0)) {
            uint64_t a0; uint32_t mp, ip;
            memcpy(&a0, m0, 8);
            memcpy(&mp, m0 + 24, 4);
            memcpy(&ip, m0 + 28, 4);
            if (a0 > 0x100000000ULL && mp <= 7 && ip <= 7) stride = 32;
        }
    }
    uint64_t mapSum = 0;
    dprintf(STDOUT_FILENO, "[V]      mapping table (stride=%d):\n", stride);
    for (uint32_t i = 0; i < mcnt && i < 0x400; i++) {
        uint8_t me[40];
        off_t eoff = (off_t)((uint64_t)moff + (uint64_t)i * (uint64_t)stride);
        if (pread(fd, me, stride, eoff) != stride) break;
        uint64_t a, s, fo;
        uint32_t mp2, ip2;
        memcpy(&a, me, 8); memcpy(&s, me + 8, 8); memcpy(&fo, me + 16, 8);
        if (stride == 40) { memcpy(&mp2, me + 32, 4); memcpy(&ip2, me + 36, 4); }
        else { memcpy(&mp2, me + 24, 4); memcpy(&ip2, me + 28, 4); }
        dprintf(STDOUT_FILENO, "[V]        m%u: addr=0x%llx size=0x%llx fileOff=0x%llx maxProt=%u initProt=%u\n",
                i, (unsigned long long)a, (unsigned long long)s,
                (unsigned long long)fo, mp2, ip2);
        mapSum += s;
    }
    dprintf(STDOUT_FILENO, "[V]      mapping size SUM = 0x%llx (%llu MB) vs file %llu MB -> %s\n",
            (unsigned long long)mapSum, (unsigned long long)(mapSum >> 20),
            (unsigned long long)(fsize >> 20),
            (mapSum > fsize * 4) ? "STUB: content mapped beyond this file" : "self-contained");

    uint64_t itOff = 0, itCnt = 0, imOff = 0, imCnt = 0;
    memcpy(&itOff, hdr + 0x88, 8);
    memcpy(&itCnt, hdr + 0x90, 8);
    memcpy(&imOff, hdr + 0x98, 8);
    memcpy(&imCnt, hdr + 0xa0, 8);
    dprintf(STDOUT_FILENO, "[V]      imagesText=%llu @0x%llx   images=%llu @0x%llx\n",
            (unsigned long long)itCnt, (unsigned long long)itOff,
            (unsigned long long)imCnt, (unsigned long long)imOff);

    /* ---- B: subcache discovery: header array + standard name probes ---- */
    enum { MAXF = 16, MAXG = 8 };
    static int cfd[MAXF];
    static uint64_t csize[MAXF];
    static char cfname[MAXF][300];
    int nf = 0;
    cfd[0] = fd; csize[0] = fsize; snprintf(cfname[0], sizeof(cfname[0]), "%s", used); nf = 1;

    uint64_t scOff = 0, scCnt = 0;
    memcpy(&scOff, hdr + 0xb8, 8);
    memcpy(&scCnt, hdr + 0xc0, 8);
    dprintf(STDOUT_FILENO, "[V]   B) subCacheArray = %llu @0x%llx (main header)\n",
            (unsigned long long)scCnt, (unsigned long long)scOff);
    const char *dirs[] = {
        "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld",
        "/System/Library/Caches/com.apple.dyld",
        NULL
    };
    if (scCnt > 0 && scCnt < 0x100 && scOff < fsize) {
        int scStride = 48;   /* try entry2 (w/ cacheFileOffset) first */
        for (int t = 0; t < 2; t++) {
            int st = (t == 0) ? 48 : 40;
            uint8_t e[48];
            if (scOff + st > fsize) continue;
            if (pread(fd, e, st, (off_t)scOff) != st) continue;
            uint32_t pOff, pSz;
            if (st == 48) { memcpy(&pOff, e + 40, 4); memcpy(&pSz, e + 44, 4); }
            else { memcpy(&pOff, e + 32, 4); memcpy(&pSz, e + 36, 4); }
            if (pOff < fsize && pSz > 0 && pSz < 512) { scStride = st; break; }
        }
        dprintf(STDOUT_FILENO, "[V]      subcache entry stride = %d\n", scStride);
        for (uint64_t i = 0; i < scCnt && nf < MAXF; i++) {
            uint8_t e[48];
            off_t eoff = (off_t)(scOff + i * scStride);
            if (eoff < 0 || eoff + scStride > (off_t)fsize) break;
            if (pread(fd, e, scStride, eoff) != scStride) break;
            uint64_t vmOff, fSz;
            uint32_t pOff, pSz;
            memcpy(&vmOff, e + 16, 8);
            memcpy(&fSz, e + 24, 8);
            if (scStride == 48) { memcpy(&pOff, e + 40, 4); memcpy(&pSz, e + 44, 4); }
            else { memcpy(&pOff, e + 32, 4); memcpy(&pSz, e + 36, 4); }
            char nm[300];
            if (ds_v6_read_path(fd, fsize, pOff, pSz, nm, sizeof(nm)) < 0) continue;
            dprintf(STDOUT_FILENO, "[V]      subcache[%llu] \"%s\" size=%llu MB vmOff=0x%llx\n",
                    (unsigned long long)i, nm, (unsigned long long)(fSz >> 20),
                    (unsigned long long)vmOff);
            for (int d = 0; d < 2 && nf < MAXF; d++) {
                char full[400];
                snprintf(full, sizeof(full), "%s/%s", dirs[d], nm);
                int sfd = open(full, O_RDONLY);
                if (sfd < 0) continue;
                struct stat ss;
                if (fstat(sfd, &ss) != 0 || ss.st_size <= 0) { close(sfd); continue; }
                cfd[nf] = sfd; csize[nf] = (uint64_t)ss.st_size;
                snprintf(cfname[nf], sizeof(cfname[nf]), "%s", full);
                dprintf(STDOUT_FILENO, "[V]        opened: %s (%llu MB)\n", full,
                        (unsigned long long)((uint64_t)ss.st_size >> 20));
                nf++;
                break;
            }
        }
    }
    /* standard-name probes regardless of the array */
    const char *stdNames[] = {
        "dyld_shared_cache_arm64e.1", "dyld_shared_cache_arm64e.2",
        "dyld_shared_cache_arm64e.3", "dyld_shared_cache_arm64e.4",
        "dyld_shared_cache_arm64e.5", "dyld_shared_cache_arm64e.6",
        "dyld_shared_cache_arm64e.7", "dyld_shared_cache_arm64e.8",
        "dyld_shared_cache_arm64e.dylddata",
        "dyld_shared_cache_arm64e.symbols",
        NULL
    };
    for (int i = 0; stdNames[i] && nf < MAXF; i++) {
        char full[400];
        for (int d = 0; d < 2; d++) {
            snprintf(full, sizeof(full), "%s/%s", dirs[d], stdNames[i]);
            int dup = 0;
            for (int k = 0; k < nf; k++) if (strcmp(cfname[k], full) == 0) { dup = 1; break; }
            if (dup) continue;
            int sfd = open(full, O_RDONLY);
            if (sfd < 0) continue;
            struct stat ss;
            if (fstat(sfd, &ss) != 0 || ss.st_size <= 0) { close(sfd); continue; }
            cfd[nf] = sfd; csize[nf] = (uint64_t)ss.st_size;
            snprintf(cfname[nf], sizeof(cfname[nf]), "%s", full);
            dprintf(STDOUT_FILENO, "[V]      probe \"%s\" -> %llu MB\n", full,
                    (unsigned long long)((uint64_t)ss.st_size >> 20));
            nf++;
            break;
        }
    }
    dprintf(STDOUT_FILENO, "[V]   B) %d cache file(s) readable (main + subcaches)\n", nf);

    /* ---- C: per-file image enumeration (first 20 paths UNFILTERED) ---- */
    static uint64_t gAddr[MAXG];
    static int gFile[MAXG];
    int gN = 0;
    for (int f = 0; f < nf; f++) {
        int cfdX = cfd[f];
        uint64_t cfSize = csize[f];
        uint8_t ch[0x100];
        if (pread(cfdX, ch, sizeof(ch), 0) != (ssize_t)sizeof(ch)) continue;
        char cm[17]; memcpy(cm, ch, 16); cm[16] = 0;
        uint32_t cmOff, cmCnt;
        memcpy(&cmOff, ch + 0x10, 4);
        memcpy(&cmCnt, ch + 0x14, 4);
        uint64_t citOff = 0, citCnt = 0;
        memcpy(&citOff, ch + 0x88, 8);
        memcpy(&citCnt, ch + 0x90, 8);
        dprintf(STDOUT_FILENO, "[V]   C) file %d: %s (%llu MB) magic=\"%s\" mappings=%u\n",
                f, cfname[f], (unsigned long long)(cfSize >> 20), cm, cmCnt);
        if (memcmp(cm, "dyld", 4) != 0 || citCnt == 0 || citCnt > 0x200000 ||
            citOff == 0 || citOff >= cfSize) {
            dprintf(STDOUT_FILENO, "[V]      no image-text table here (data subcache?)\n");
            continue;
        }
        /* raw dump of first 3 entries (debug) */
        for (int r = 0; r < 3; r++) {
            uint8_t e[48];
            off_t eoff = (off_t)(citOff + (uint64_t)r * 48);
            if (eoff < 0 || eoff + 48 > (off_t)cfSize) break;
            if (pread(cfdX, e, sizeof(e), eoff) != (ssize_t)sizeof(e)) break;
            uint64_t la, ts, po; uint64_t pz64; uint32_t pz;
            memcpy(&la, e + 16, 8);
            memcpy(&ts, e + 24, 8);
            memcpy(&po, e + 32, 8);
            memcpy(&pz64, e + 40, 8);
            pz = (uint32_t)pz64;
            dprintf(STDOUT_FILENO, "[V]      raw[%d] loadAddr=0x%llx textSize=0x%llx pathOff=0x%llx pathSize=%u\n",
                    r, (unsigned long long)la, (unsigned long long)ts,
                    (unsigned long long)po, pz);
        }
        /* enumerate: first 20 paths unfiltered + count + Game* collect */
        uint64_t resolved = 0;
        uint64_t total = citCnt;
        dprintf(STDOUT_FILENO, "[V]      %llu image entries; first 20 paths:\n",
                (unsigned long long)total);
        for (uint64_t i = 0; i < citCnt; i++) {
            uint8_t e[48];
            off_t eoff = (off_t)(citOff + i * 48);
            if (eoff < 0 || eoff + 48 > (off_t)cfSize) break;
            if (pread(cfdX, e, sizeof(e), eoff) != (ssize_t)sizeof(e)) break;
            uint64_t la, po64; uint32_t pz;
            memcpy(&la, e + 16, 8);
            memcpy(&po64, e + 32, 8);
            memcpy(&pz, e + 40, 4);
            char nm[300];
            int rl = ds_v6_read_path(cfdX, cfSize, po64, pz, nm, sizeof(nm));
            if (rl < 0) continue;   /* path lives in another subcache */
            if (resolved < 20)
                dprintf(STDOUT_FILENO, "[V]      %llu %s\n", (unsigned long long)i, nm);
            resolved++;
            if (strstr(nm, "Game") != NULL || strstr(nm, "game") != NULL ||
                strstr(nm, "GameCenter") != NULL || strstr(nm, "gamed") != NULL) {
                if (gN < MAXG) { gAddr[gN] = la; gFile[gN] = f; gN++; }
            }
        }
        dprintf(STDOUT_FILENO, "[V]      %llu path(s) resolved in-file\n",
                (unsigned long long)resolved);
    }
    dprintf(STDOUT_FILENO, "[V]   C) %d Game*/game* image(s) across all cache files\n", gN);
    for (int g = 0; g < gN; g++)
        dprintf(STDOUT_FILENO, "[V]      game[%d] file=%d loadAddr=0x%llx\n",
                g, gFile[g], (unsigned long long)gAddr[g]);

    /* ---- D: Mach-O metadata walk on Game* images (on their own file) ---- */
    for (int g = 0; g < gN; g++) {
        int f = gFile[g];
        int cfdX = cfd[f];
        uint64_t cfSize = csize[f];
        uint8_t ch[0x100];
        if (pread(cfdX, ch, sizeof(ch), 0) != (ssize_t)sizeof(ch)) continue;
        uint32_t cmOff, cmCnt;
        memcpy(&cmOff, ch + 0x10, 4);
        memcpy(&cmCnt, ch + 0x14, 4);
        int st2 = 40;
        {
            uint8_t m0[40];
            if (pread(cfdX, m0, sizeof(m0), (off_t)cmOff) == (ssize_t)sizeof(m0)) {
                uint64_t a0; uint32_t mp, ip;
                memcpy(&a0, m0, 8);
                memcpy(&mp, m0 + 24, 4);
                memcpy(&ip, m0 + 28, 4);
                if (a0 > 0x100000000ULL && mp <= 7 && ip <= 7) st2 = 32;
            }
        }
        off_t hdrOff = ds_v5_map_addr(cfdX, cfSize, cmOff, cmCnt, st2, gAddr[g]);
        dprintf(STDOUT_FILENO, "[V]   D) game[%d] file=%d 0x%llx -> fileOff=%lld\n",
                g, f, (unsigned long long)gAddr[g], (long long)hdrOff);
        if (hdrOff < 0) continue;
        /* verify MH_MAGIC_64 then walk sections */
        uint32_t mg = 0;
        if (pread(cfdX, &mg, 4, hdrOff) != 4) continue;
        dprintf(STDOUT_FILENO, "[V]      mach magic=0x%x %s\n", mg,
                mg == 0xfeedfacf ? "(MH_MAGIC_64 OK)" : "(not a Mach-O header)");
        if (mg != 0xfeedfacf) continue;
        const struct { const char *sect; const char *tag; int cap; } secs[] = {
            { "__objc_methname", "SEL", 10 },
            { "__objc_classname", "CLASS", 6 },
            { "__objc_protocols", "PROTO", 4 },
            { "__objc_protolist", "PROTOLIST", 3 },
        };
        for (int s = 0; s < 4; s++) {
            uint64_t saddr = 0, ssize = 0;
            if (ds_v5_find_section(cfdX, cfSize, hdrOff, secs[s].sect, &saddr, &ssize) == 0) {
                off_t foff = ds_v5_map_addr(cfdX, cfSize, cmOff, cmCnt, st2, saddr);
                uint64_t backVm = 0;
                if (foff >= 0) backVm = ds_v5_map_file_to_vm(cfdX, cfSize, cmOff, cmCnt, st2, (uint64_t)foff);
                dprintf(STDOUT_FILENO, "[V]      sect %-16s vm=0x%llx size=0x%llx fileOff=%lld vm-roundtrip=0x%llx\n",
                        secs[s].sect, (unsigned long long)saddr,
                        (unsigned long long)ssize, (long long)foff,
                        (unsigned long long)backVm);
                if (foff >= 0)
                    ds_v5_dump_strs(cfdX, cfSize, (uint64_t)foff, ssize, secs[s].tag, secs[s].cap);
            } else {
                dprintf(STDOUT_FILENO, "[V]      sect %s: not found\n", secs[s].sect);
            }
        }
    }

    /* ---- E: indicator scan across ALL readable cache files ---- */
    {
        static const char *needles[] = {
            "NSXPCInterface", "BSServiceConnection", "GKDaemonProxy",
            "GKDataTransport", "GKConnection", "GKXPCRemoteProcess",
            "com.apple.gamecenter", "com.apple.gamed", "platform-application",
            "xpc_connection_create", "xpc_dictionary_create", "isEntitled",
            NULL
        };
        static char chunk[0x400000 + 256];
        for (int f = 0; f < nf; f++) {
            size_t carry = 0, total = 0;
            off_t fileOff = 0;
            int nHits[12] = {0}, shown[12] = {0};
            dprintf(STDOUT_FILENO, "[V]   E) indicator scan: %s\n", cfname[f]);
            for (;;) {
                ssize_t got = pread(cfd[f], chunk + carry, 0x400000, fileOff);
                if (got == 0) break;
                if (got < 0) { dprintf(STDOUT_FILENO, "[V]      read err %d (%s)\n", errno, strerror(errno)); break; }
                size_t n = carry + (size_t)got;
                for (int k = 0; needles[k]; k++) {
                    size_t nl = strlen(needles[k]);
                    const char *p = chunk;
                    while ((p = ds_gi_find(p, n - (size_t)(p - chunk), needles[k], nl)) != NULL) {
                        nHits[k]++;
                        if (shown[k] < 2) {
                            size_t pos = (size_t)(p - chunk);
                            ds_gi_cache_window(chunk, pos, n, needles[k], &shown[k], 2);
                        }
                        p += nl;
                        if (p - chunk > n) break;
                    }
                }
                fileOff += (off_t)got;
                total += (size_t)got;
                if (n > 256) { memmove(chunk, chunk + n - 256, 256); carry = 256; }
                else carry = n;
                if (total > 0x10000000) {   /* 256MB/file cap */
                    dprintf(STDOUT_FILENO, "[V]      capped at 256MB\n");
                    break;
                }
            }
            dprintf(STDOUT_FILENO, "[V]      scanned %zu MB:", total >> 20);
            for (int k = 0; needles[k]; k++)
                dprintf(STDOUT_FILENO, " %s=%d", needles[k], nHits[k]);
            dprintf(STDOUT_FILENO, "\n");
        }
    }

    /* ---- F: hypothesis table ---- */
    dprintf(STDOUT_FILENO, "[V]   F) interface hypothesis table:\n");
    dprintf(STDOUT_FILENO, "[V]      candidate            | evidence                | location       | conf\n");
    dprintf(STDOUT_FILENO, "[V]      com.apple.gamed      | bootstrap_look_up OK    | bootstrap ns   | HIGH (proven)\n");
    dprintf(STDOUT_FILENO, "[V]      main cache is STUB  | %llu MB, %u mapping(s)    | %s | %s\n",
            (unsigned long long)(fsize >> 20), mcnt, used,
            (mapSum > fsize * 4) ? "CONFIRMED" : "NO");
    dprintf(STDOUT_FILENO, "[V]      cache files scanned | %d (main+subcaches)     | Caches dir    | %s\n",
            nf, nf > 1 ? "OK" : "MAIN ONLY");
    dprintf(STDOUT_FILENO, "[V]      Game* images       | %d found across %d files | cache Mach-O  | %s\n",
            gN, nf, gN > 0 ? "SEE D" : "LOW");
    dprintf(STDOUT_FILENO, "[V]      XPC markers        | indicator scan phase E   | cache strings  | SEE E\n");
    for (int k = 1; k < nf; k++) close(cfd[k]);
    close(fd);
    dprintf(STDOUT_FILENO, "[V]   done - stub diagnosis + per-file image enumeration above\n");
}
'''

# Locate current ds_gi_scan_cache (v5) and replace with v6 (helper + function)
start_marker = 'static void ds_gi_scan_cache(void) {'
si = src.index(start_marker)
depth = 0
end = -1
lines = src[si:].split('\n')
for idx, ln in enumerate(lines):
    depth += ln.count('{') - ln.count('}')
    if depth == 0:
        end = si + len('\n'.join(lines[:idx + 1]))
        break
if end < 0:
    print('FAIL: could not find end of ds_gi_scan_cache')
    sys.exit(1)

src = src[:si] + HELPER + src[end:]

# Banner update
old_banner = '''    dprintf(STDOUT_FILENO, "[V] v5: validate the SCANNER first - the last 0-hit run read\\n");
    dprintf(STDOUT_FILENO, "[V] 0 MB (sequential read denied; scanner never ran). Phases:\\n");
    dprintf(STDOUT_FILENO, "[V] A read-path proof, B image enumeration, C Mach-O metadata,\\n");
    dprintf(STDOUT_FILENO, "[V] D indicator scan, E hypothesis table. No blind windows.\\n");'''
new_banner = '''    dprintf(STDOUT_FILENO, "[V] v6: the main dyld cache may be a STUB (tables only, 1 mapping)\\n");
    dprintf(STDOUT_FILENO, "[V] - all image content lives in subcaches (.1-.8, .dylddata).\\n");
    dprintf(STDOUT_FILENO, "[V] v6 enumerates EVERY cache file's image table, then hunts\\n");
    dprintf(STDOUT_FILENO, "[V] Game*/gamed and parses __objc_* metadata where it exists.\\n");'''
if old_banner in src:
    src = src.replace(old_banner, new_banner)
else:
    print('WARN: v5 banner not found (may already be v6)')

old_done = '''    dprintf(STDOUT_FILENO, "[V] done - see the five phases above\\n");'''
new_done = '''    dprintf(STDOUT_FILENO, "[V] done - see phases A-F above\\n");'''
if old_done in src:
    src = src.replace(old_done, new_done)
else:
    print('WARN: done line not found')

open(p, 'w').write(src)
print('OK - v6 stub-detection scanner patch applied')
