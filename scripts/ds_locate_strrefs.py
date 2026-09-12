#!/usr/bin/env python3
"""ds_locate_strrefs.py -- locate code that materialises a given data address.

Locator only. Given a Mach-O and a list of target virtual addresses (strings /
consts), scan executable sections for AArch64 `adrp`+`add` (or `adrp`+`ldr`)
pairs whose computed target equals one of them, and print the containing code
address. All *analysis* is done afterwards in Binary Ninja.

Usage:
    ds_locate_strrefs.py <macho> <target_va> [<target_va> ...]
    ds_locate_strrefs.py <macho> --range 0xSTART 0xEND      # any target in range
"""
import struct
import sys


def parse_macho(path):
    data = open(path, "rb").read()
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:
        raise SystemExit("not a 64-bit little-endian Mach-O (magic=%#x)" % magic)
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    sections = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr = struct.unpack_from("<Q", data, off + 24)[0]
            vmsize = struct.unpack_from("<Q", data, off + 32)[0]
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            soff = off + 72
            for _ in range(nsects):
                sname = data[soff:soff + 16].rstrip(b"\0").decode()
                saddr = struct.unpack_from("<Q", data, soff + 32)[0]
                ssize = struct.unpack_from("<Q", data, soff + 40)[0]
                sfoff = struct.unpack_from("<I", data, soff + 48)[0]
                flags = struct.unpack_from("<I", data, soff + 64)[0]
                sections.append({
                    "seg": segname, "name": sname, "addr": saddr,
                    "size": ssize, "fileoff": sfoff, "flags": flags,
                })
                soff += 80
            del vmsize, fileoff
        off += cmdsize
    return data, sections


def sx21(v):
    v &= 0x1FFFFF
    return v - 0x200000 if v & 0x100000 else v


def scan(data, sections, targets=None, target_range=None, window=6):
    """Return list of (code_va, target_va, kind)."""
    exec_secs = [s for s in sections if s["flags"] & 0x80000000 and s["size"]]
    hits = []
    for s in exec_secs:
        base = s["addr"]
        start = s["fileoff"]
        n = s["size"] // 4
        words = struct.unpack_from("<%dI" % n, data, start)
        # map reg -> (pc, page) from adrp, expire after `window` insns
        pending = {}
        for i, w in enumerate(words):
            pc = base + i * 4
            if (w & 0x9F000000) == 0x90000000:            # ADRP
                rd = w & 0x1F
                imm = sx21(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3))
                page = (pc & ~0xFFF) + (imm << 12)
                pending[rd] = (i, page)
            elif (w & 0xFF000000) == 0x91000000:          # ADD (imm, 64-bit)
                rn, rd = (w >> 5) & 0x1F, w & 0x1F
                if rn == rd and rn in pending:
                    pi, page = pending[rn]
                    if i - pi <= window:
                        imm12 = (w >> 10) & 0xFFF
                        sh = (w >> 22) & 3
                        tgt = page + (imm12 << (12 if sh else 0))
                        if (targets and tgt in targets) or \
                           (target_range and target_range[0] <= tgt < target_range[1]):
                            hits.append((pc, tgt, "adrp+add"))
            elif (w & 0xFFC00000) == 0xF9400000:          # LDR (imm, 64-bit)
                rn, rt = (w >> 5) & 0x1F, w & 0x1F
                if rn in pending:
                    pi, page = pending[rn]
                    if i - pi <= window:
                        imm12 = (w >> 10) & 0xFFF
                        tgt = page + (imm12 << 3)
                        if (targets and tgt in targets) or \
                           (target_range and target_range[0] <= tgt < target_range[1]):
                            hits.append((pc, tgt, "adrp+ldr"))
            # expire stale entries
            for r in [r for r, (pi, _) in pending.items() if i - pi > window]:
                del pending[r]
    return hits


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    args = sys.argv[2:]
    data, sections = parse_macho(path)
    if args[0] == "--range":
        rng = (int(args[1], 0), int(args[2], 0))
        hits = scan(data, sections, target_range=rng)
    else:
        targets = set(int(a, 0) for a in args)
        hits = scan(data, sections, targets=targets)
    for va, tgt, kind in hits:
        print("%#x  ->  %#x  (%s)" % (va, tgt, kind))
    print("-- %d hits" % len(hits))


if __name__ == "__main__":
    main()
