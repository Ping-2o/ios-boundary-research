#!/usr/bin/env python3
"""
ds_extmethods.py - locate IOExternalMethodDispatch tables in an arm64e kext.

Why this exists: iOS kexts are stripped, so there is no symbol to hang an audit on.
But every IOUserClient external-method table is a static array of

    struct IOExternalMethodDispatch {   // sizeof == 24 on arm64
        IOExternalMethodAction function;         // +0x00  8 bytes (PAC'd in kernelcache)
        uint32_t checkScalarInputCount;          // +0x08
        uint32_t checkStructureInputSize;        // +0x0c
        uint32_t checkStructureOutputSize;       // +0x10
        uint32_t _pad;                           // +0x14  == 0
    };

The three check fields survive stripping and tell you, per selector, whether the
kernel validates the size of what userspace hands it. Entries with
0xFFFFFFFF (kIOUCVariableStructureSize) or an undersized check are where
out-of-bounds reads/writes live.

Usage:
    python3 ds_extmethods.py <kext> [--min N] [--all]

Prints: section, file offset, VM address, entry count, and per-selector check
triplets. Flagged entries are marked.
"""
import struct
import sys

MAGIC = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
VAR = 0xFFFFFFFF  # kIOUCVariableStructureSize / kIOUCVariableScalarInputCount

SCAN_SECTIONS = ("__const", "__constdata", "__data", "__auth_const", "__AUTH_CONST")


def sections(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != MAGIC:
        return [], data
    ncmds = struct.unpack_from("<I", data, 0x10)[0]
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for _s in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode()
                s_segname = data[so + 16:so + 32].rstrip(b"\0").decode()
                s_addr, s_size = struct.unpack_from("<QQ", data, so + 32)
                s_off = struct.unpack_from("<I", data, so + 40)[0]
                out.append({
                    "seg": segname, "sect": sectname, "segname": s_segname,
                    "addr": s_addr, "size": s_size, "fileoff": s_off,
                    "vmaddr": vmaddr, "fileoff_seg": fileoff, "filesize": filesize,
                })
                so += 80
        off += cmdsize
    return out, data


def plausible(v):
    return v == VAR or v <= 0x20000


def entry_at(data, i):
    if i + 24 > len(data):
        return None
    fn = struct.unpack_from("<Q", data, i)[0]
    a, b, c, pad = struct.unpack_from("<IIII", data, i + 8)
    if pad != 0:
        return None
    if fn == 0:
        return None
    if not (plausible(a) and plausible(b) and plausible(c)):
        return None
    if a == 0 and b == 0 and c == 0:
        return None
    # a function pointer in a kernelcache is either a real VA (high bits set)
    # or a PAC'd/slided value - both are > 0xFFFF. Low values are not code.
    if fn < 0x10000:
        return None
    return (fn, a, b, c)


def scan(path, min_entries=3, show_all=False):
    secs, data = sections(path)
    if not secs:
        print(f"{path}: not a 64-bit Mach-O (or unreadable)")
        return
    found = 0
    for s in secs:
        if s["sect"] not in SCAN_SECTIONS and not show_all:
            continue
        if s["fileoff"] == 0 or s["size"] == 0:
            continue
        start = s["fileoff"]
        end = start + s["size"]
        if end > len(data):
            end = len(data)
        i = start
        while i + 24 <= end:
            run = []
            j = i
            while True:
                e = entry_at(data, j)
                if not e:
                    break
                run.append(e)
                j += 24
            if len(run) >= min_entries:
                found += 1
                base = s["addr"] + (i - start)
                print(f"\n[TABLE] {s['seg']},{s['sect']}  file=0x{i:x}  "
                      f"va=0x{base:x}  entries={len(run)}")
                for n, (fn, a, b, c) in enumerate(run):
                    fl = []
                    if a == VAR:
                        fl.append("SCALAR-VAR")
                    if b == VAR:
                        fl.append("STRUCTIN-VAR")
                    if c == VAR:
                        fl.append("STRUCTOUT-VAR")
                    if b != VAR and b <= 8:
                        fl.append("STRUCTIN-TINY")
                    if a != VAR and a == 0 and b != VAR and b == 0:
                        fl.append("NO-INPUT-CHECK")
                    mark = "  <<< " + ",".join(fl) if fl else ""
                    print(f"   sel {n:3d}  fn=0x{fn:x}  scalarIn={a:#x} "
                          f"structIn={b:#x} structOut={c:#x}{mark}")
                i = j
            else:
                i += 8 if i % 8 else 4
                continue
            continue
    if not found:
        print(f"{path}: no IOExternalMethodDispatch table found "
              f"(try --min 2 or --all; the table may be built at runtime)")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    min_entries = 3
    show_all = False
    if "--min" in sys.argv:
        min_entries = int(sys.argv[sys.argv.index("--min") + 1])
    if "--all":
        show_all = True
    if not args:
        print(__doc__)
        sys.exit(1)
    for a in args:
        print(f"===== {a} =====")
        scan(a, min_entries, show_all)
