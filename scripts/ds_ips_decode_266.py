import json, sys, os
from datetime import datetime

def ts(s):
    if not s: return None
    try:
        return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

for f in sys.argv[1:]:
    name = os.path.basename(f)
    text = open(f, "r", errors="replace").read()
    nl = text.find("\n")
    try:
        meta = json.JSONDecoder().raw_decode(text)[0]
        body = json.JSONDecoder().raw_decode(text, nl + 1)[0]
    except Exception as e:
        print(f"== {name}: PARSE FAIL {e}")
        continue
    ct = meta.get("captureTime", "?")
    pid = meta.get("pid", "?")
    launch = meta.get("procLaunch", "?")
    osv = body.get("osVersion", {})
    build = osv.get("build", "?") if isinstance(osv, dict) else "?"
    exc = body.get("exception", {})
    term = body.get("termination", {})
    asi = body.get("asi")
    ft = body.get("faultingThread", 0)
    threads = body.get("threads", [])
    imgs = body.get("usedImages", [])
    ccc = body.get("ConsecutiveCrashCount", meta.get("consecutiveCrashCount", "?"))
    up = body.get("uptime", "?")

    life = ""
    a, b = ts(launch), ts(ct)
    if a and b:
        d = (b - a).total_seconds()
        life = f" lived {d:.2f}s"

    print(f"== {name}")
    print(f"   capture={ct} build={build} pid={pid} launch={launch}{life} consecCrash={ccc} uptime={up}")
    et = exc.get("type", "?"); esig = exc.get("signal", ""); evals = exc.get("exception", {})
    print(f"   exception: {et} signal={esig} vals={evals}")
    if term:
        print(f"   termination: {term}")
    if asi:
        print(f"   asi: {asi}")
    if ft is not None and isinstance(threads, list) and ft < len(threads):
        thr = threads[ft]
        print(f"   faultingThread {ft} queue={thr.get('queue','?')}")
        for i, fr in enumerate(thr.get("frames", [])[:8]):
            ii = fr.get("imageIndex", -1)
            img = imgs[ii].get("name", "?") if 0 <= ii < len(imgs) else "?"
            sym = fr.get("symbol", "")
            off = fr.get("imageOffset", "?")
            so = fr.get("symbolLocation", "")
            print(f"     {i}: {img} +{off} {sym} +{so}" if sym else f"     {i}: {img} +{off}")
    print()
