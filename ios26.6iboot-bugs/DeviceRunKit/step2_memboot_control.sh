#!/bin/bash
# step2_memboot_control.sh — CONTROL run: send a CLEAN (non-PoC) IM4P via memboot and bootx it.
# Purpose: establish the receipt vocabulary (decode-before-verify ordering) WITHOUT a corrupting
# stream: a well-formed but wrong-content krnl blob should get "Kernelcache image not valid"
# AFTER the decoder runs. Compare timing/behavior vs the PoC step3.
# Safety: RAM-only (memz). No NOR/NVRAM write. Device always exits via step9_hold.sh or
#         forced reboot (vol-down+side 10s).
set -u
cd "$(dirname "$0")"
OUT="results/step2_$(date +%Y%m%d_%H%M%S).log"; mkdir -p results
log(){ echo "[step2] $*" | tee -a "$OUT"; }

[ -f payloads/control_krnl.im4p ] || { log "run payloads/make_payloads.sh first"; exit 1; }

log "waiting for recovery device..."
for i in $(seq 1 45); do irecovery -m >/dev/null 2>&1 && break; sleep 2; done
irecovery -m >/dev/null 2>&1 || { log "no recovery device"; exit 1; }

log "SEND control payload (filesize -> send -> bootx)"
S=$(stat -f%z payloads/control_krnl.im4p)
irecovery -c "setenv filesize $S" 2>&1 | tee -a "$OUT"
irecovery -f payloads/control_krnl.im4p 2>&1 | tee -a "$OUT"
T0=$(date +%s)
irecovery -c "bootx" 2>&1 | tee -a "$OUT"
log "bootx returned after $(( $(date +%s)-T0 ))s (expect 'Kernelcache image not valid' OR hang/reset)"
log "RECEIPT LEGEND:"
log "  'not valid' text            = shell live; decode ran before the verdict (ordering proof)"
log "  device vanishes from USB    = reset/panic = decoder consumed the stream (step0_pullcrash.sh after reboot)"
log "  PERMISSION DENIED / silence = memboot gated on retail -> stop; Reports 1-3 stay staging-class (honest)"
