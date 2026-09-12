#!/bin/bash
# step0_pullcrash.sh — snapshot crash/panic reports (normal mode) for a BEFORE baseline
# (and re-run AFTER the PoC steps for the AFTER receipts). Uses the crash-report service
# (no jailbreak needed).
set -u
cd "$(dirname "$0")"
TAG="${1:-before}"; DST="results/crash_$TAG"; mkdir -p "$DST"
command -v idevicecrashreport >/dev/null || { echo "brew install libimobiledevice"; exit 1; }
echo "[step0] pulling crash reports to $DST (takes a few minutes)..."
idevicecrashreport -e "$DST" 2>&1 | tail -3
ls "$DST" | grep -icE "panic|boot|iboot" | sed 's/^/[step0] panic-ish files: /'
grep -rilE "iboot|panic" "$DST" 2>/dev/null | head -5 | sed 's/^/[step0]   /'
