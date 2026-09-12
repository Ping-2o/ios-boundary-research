#!/usr/bin/env python3
"""bn_lib.py -- shared Binary Ninja headless helpers for the 24A435 CVE hunt.

Binary Ninja only. No other RE engine is used anywhere in this pipeline.

Usage from a script:
    from bn_lib import open_view, find_funcs, decompile, ...
"""
import os
import sys
import re

BN_RES = "/Applications/Binary Ninja.app/Contents/Resources/python"
BN_LIB = "/Applications/Binary Ninja.app/Contents/MacOS"

os.environ.setdefault("DYLD_FALLBACK_LIBRARY_PATH", BN_LIB)
if BN_RES not in sys.path:
    sys.path.insert(0, BN_RES)

import binaryninja as bn  # noqa: E402

bn.disable_default_log()


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
def open_view(path, update=True, quiet=True):
    """Load a binary or .bndb and (optionally) run analysis to completion."""
    if quiet:
        bn.disable_default_log()
    bv = bn.load(path)
    if bv is None:
        raise RuntimeError("binaryninja.load() returned None for %r" % path)
    if update:
        bv.update_analysis_and_wait()
    return bv


def save_db(bv, out_path):
    """Persist an analyzed view as a .bndb database."""
    d = os.path.dirname(out_path)
    if d:
        os.makedirs(d, exist_ok=True)
    bv.save(out_path)
    return out_path


def build_db(binary_path, out_path=None, quiet=True):
    """Analyze a binary and save a .bndb next to it (or at out_path)."""
    if out_path is None:
        out_path = os.path.splitext(binary_path)[0] + ".bndb"
    bv = open_view(binary_path, update=True, quiet=quiet)
    save_db(bv, out_path)
    return out_path, bv


# --------------------------------------------------------------------------
# queries
# --------------------------------------------------------------------------
def find_funcs(bv, substr, limit=500):
    """Case-insensitive substring match over function symbol names."""
    s = substr.lower()
    out = []
    for f in bv.functions:
        try:
            name = f.symbol.short_name if f.symbol else f.name
        except Exception:
            name = f.name
        if s in (name or "").lower() or s in (f.name or "").lower():
            out.append(f)
            if len(out) >= limit:
                break
    return out


def find_syms(bv, substr, limit=1000):
    s = substr.lower()
    out = []
    for sym in bv.get_symbols():
        if s in (sym.short_name or "").lower() or s in (sym.full_name or "").lower():
            out.append(sym)
            if len(out) >= limit:
                break
    return out


def find_strings(bv, substr, limit=1000):
    s = substr.lower()
    out = []
    for st in bv.get_strings():
        try:
            v = st.value
        except Exception:
            continue
        if s in v.lower():
            out.append(st)
            if len(out) >= limit:
                break
    return out


def resolve_func(bv, expr):
    """Resolve a symbol name or hex address to a single Function."""
    expr = expr.strip()
    # direct hex
    try:
        if re.fullmatch(r"(0x)?[0-9a-fA-F]+", expr):
            addr = int(expr, 16) if not expr.startswith("0x") else int(expr, 16)
            f = bv.get_function_at(addr)
            if f:
                return f
    except Exception:
        pass
    # exact symbol name
    for f in bv.functions:
        try:
            if f.symbol and f.symbol.full_name == expr:
                return f
        except Exception:
            pass
    # substring (first hit)
    hits = find_funcs(bv, expr, limit=2)
    if len(hits) == 1:
        return hits[0]
    if hits:
        return hits[0]
    # try symbol table
    syms = find_syms(bv, expr, limit=2)
    if syms:
        addr = syms[0].address
        f = bv.get_function_at(addr)
        if f:
            return f
    return None


def decompile(f):
    try:
        lines = f.hlil.instructions  # noqa: F841  (touch to force lift)
    except Exception:
        pass
    try:
        return f.hlil.root  # not used
    except Exception:
        pass


def pseudo_c(f):
    """Return decompiled C text for a Function."""
    try:
        r = f.hlil
        if r is None:
            f.view.update_analysis_and_wait()
            r = f.hlil
        return str(f.hlil)
    except Exception as e:
        return "// decompile failed: %s" % e


def disasm(f):
    try:
        out = []
        for blk in f.basic_blocks:
            for il in blk:
                try:
                    out.append("%#x  %s" % (il.address, " ".join(str(t) for t in il.tokens)))
                except Exception:
                    out.append("%#x  %s" % (il.address, il))
        return "\n".join(out)
    except Exception as e:
        return "// disasm failed: %s" % e


def xrefs_to(bv, addr):
    return list(bv.get_code_refs(addr)) + list(bv.get_data_refs(addr))


def callers(f):
    return list(f.callers)


def callees(f):
    return list(f.callees)


def fmt_func(f):
    try:
        return "%#x  %s" % (f.start, f.symbol.full_name if f.symbol else f.name)
    except Exception:
        return "%#x  %s" % (f.start, f.name)


def main():
    print("bn_lib: BN %s / %s" % (bn.core_version(), bn.core_build_id()))


if __name__ == "__main__":
    main()
