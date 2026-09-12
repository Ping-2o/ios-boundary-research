#!/usr/bin/env python3
"""bn_query.py -- fast Binary Ninja query CLI over a .bndb (or raw binary).

Binary Ninja only.

Usage:
    bn_query.py <target.bndb|binary> <command> [args] [--limit N]

Commands:
    info                          file/section/function summary
    funcs [SUBSTR]                list functions (name substring)
    syms  [SUBSTR]                list symbols
    strings [SUBSTR]              list strings
    decomp <SYM|0xADDR>           decompiled C for a function
    disasm <SYM|0xADDR>           disassembly for a function
    xrefs  <SYM|0xADDR>           code+data references TO an address/symbol
    callers <SYM|0xADDR>          who calls this function
    callees <SYM|0xADDR>          what this function calls
    bytes <0xADDR> <LEN>          raw bytes (hex)
    grep <SUBSTR>                 functions + symbols + strings in one shot
    segs                          segments/sections
    const <0xADDR> <LEN>          read a const pointer table (u64 LE, decode)
"""
import os
import sys
import argparse
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bn_lib import (  # noqa: E402
    open_view, find_funcs, find_syms, find_strings, resolve_func,
    pseudo_c, disasm, xrefs_to, callers, callees, fmt_func,
)


def _sym_of(f):
    try:
        return f.symbol.full_name if f.symbol else f.name
    except Exception:
        return f.name


def cmd_info(bv, a):
    print("file:      %s" % bv.file.filename)
    print("arch:      %s" % bv.arch)
    print("platform:  %s" % bv.platform)
    print("entry:     %#x" % bv.entry_point)
    print("start/end: %#x - %#x" % (bv.start, bv.end))
    print("functions: %d" % len(bv.functions))
    print("symbols:   %d" % len(bv.get_symbols()))
    print("strings:   %d" % len(bv.get_strings()))
    print("sections:")
    for s in bv.sections.values():
        print("  %-24s %#010x  size=%#x" % (s.name, s.start, s.end - s.start))


def cmd_funcs(bv, a):
    q = a.arg or ""
    fs = find_funcs(bv, q, limit=a.limit)
    for f in fs:
        print(fmt_func(f))
    print("-- %d shown" % len(fs))


def cmd_syms(bv, a):
    for s in find_syms(bv, a.arg or "", limit=a.limit):
        print("%#x  %s" % (s.address, s.full_name))


def cmd_strings(bv, a):
    for s in find_strings(bv, a.arg or "", limit=a.limit):
        v = s.value.replace("\n", "\\n")
        print("%#x  %s" % (s.start, v[:220]))


def cmd_decomp(bv, a):
    f = resolve_func(bv, a.arg)
    if not f:
        print("!! not found: %s" % a.arg)
        return
    print("// %s @ %#x" % (_sym_of(f), f.start))
    print(pseudo_c(f))


def cmd_disasm(bv, a):
    f = resolve_func(bv, a.arg)
    if not f:
        print("!! not found: %s" % a.arg)
        return
    print("// %s @ %#x" % (_sym_of(f), f.start))
    print(disasm(f))


def _addr_of(bv, expr):
    f = resolve_func(bv, expr)
    if f:
        return f.start
    try:
        return int(expr, 16)
    except Exception:
        return None


def cmd_xrefs(bv, a):
    addr = _addr_of(bv, a.arg)
    if addr is None:
        print("!! cannot resolve %s" % a.arg)
        return
    for r in bv.get_code_refs(addr):
        fn = r.function
        print("code %#x  in %s" % (r.address, _sym_of(fn) if fn else "?"))
    for r in bv.get_data_refs(addr):
        print("data %#x" % r)


def cmd_callers(bv, a):
    f = resolve_func(bv, a.arg)
    if not f:
        print("!! not found")
        return
    for c in f.callers:
        print("%#x  %s" % (c.address, _sym_of(c.function)))


def cmd_callees(bv, a):
    f = resolve_func(bv, a.arg)
    if not f:
        print("!! not found")
        return
    for c in f.callees:
        print("%#x  %s" % (c.start, _sym_of(c)))


def cmd_bytes(bv, a):
    addr = _addr_of(bv, a.arg)
    ln = int(a.arg2, 0)
    data = bv.read(addr, ln)
    print(" ".join("%02x" % b for b in data))


def cmd_grep(bv, a):
    q = a.arg
    print("== functions ==")
    for f in find_funcs(bv, q, limit=min(a.limit, 100)):
        print(fmt_func(f))
    print("== symbols ==")
    for s in find_syms(bv, q, limit=min(a.limit, 100)):
        print("%#x  %s" % (s.address, s.full_name))
    print("== strings ==")
    for s in find_strings(bv, q, limit=min(a.limit, 100)):
        print("%#x  %s" % (s.start, s.value.replace("\n", "\\n")[:200]))


def cmd_segs(bv, a):
    for s in bv.segments:
        print("%-20s %#010x - %#010x  (%#x)" % (s.name or "-", s.start, s.end, s.end - s.start))


def cmd_const(bv, a):
    addr = _addr_of(bv, a.arg)
    ln = int(a.arg2, 0)
    for i in range(0, ln, 8):
        v = int.from_bytes(bv.read(addr + i, 8), "little")
        print("%#x  %#018x" % (addr + i, v))


CMDS = {
    "info": cmd_info, "funcs": cmd_funcs, "syms": cmd_syms, "strings": cmd_strings,
    "decomp": cmd_decomp, "disasm": cmd_disasm, "xrefs": cmd_xrefs,
    "callers": cmd_callers, "callees": cmd_callees, "bytes": cmd_bytes,
    "grep": cmd_grep, "segs": cmd_segs, "const": cmd_const,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("command")
    ap.add_argument("arg", nargs="?", default="")
    ap.add_argument("arg2", nargs="?", default="0")
    ap.add_argument("--limit", type=int, default=200)
    a = ap.parse_args()
    if a.command not in CMDS:
        print("unknown command %r; have: %s" % (a.command, ", ".join(sorted(CMDS))))
        sys.exit(2)
    bv = open_view(a.target, update=False)
    CMDS[a.command](bv, a)


if __name__ == "__main__":
    main()
