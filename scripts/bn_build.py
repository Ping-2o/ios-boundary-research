#!/usr/bin/env python3
"""bn_build.py -- analyze a binary with Binary Ninja and save a .bndb database.

Usage:
    bn_build.py <binary> [<binary> ...] [--out DIR] [--jobs N]

Runs analysis in parallel worker processes (one Binary Ninja view per process),
so large binaries do not serialize.
"""
import os
import sys
import argparse
import multiprocessing as mp

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _worker(args):
    binary, out = args
    try:
        from bn_lib import build_db
        db, bv = build_db(binary, out)
        n = len(bv.functions)
        return (binary, out, n, None)
    except Exception as e:
        return (binary, out, -1, repr(e))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("--out", default=None, help="output dir for .bndb (default: alongside binary)")
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()

    jobs = []
    for b in a.binaries:
        b = os.path.abspath(b)
        if a.out:
            out = os.path.join(a.out, os.path.basename(b) + ".bndb")
        else:
            out = b + ".bndb"
        jobs.append((b, out))

    if len(jobs) == 1:
        res = [_worker(jobs[0])]
    else:
        with mp.Pool(min(a.jobs, len(jobs))) as p:
            res = p.map(_worker, jobs)

    rc = 0
    for binary, out, n, err in res:
        if err:
            print("FAIL %s -> %s" % (binary, err))
            rc = 1
        else:
            print("OK   %s  fns=%d  -> %s" % (binary, n, out))
    sys.exit(rc)


if __name__ == "__main__":
    main()
