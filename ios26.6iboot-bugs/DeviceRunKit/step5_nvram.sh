#!/bin/bash
# step5_nvram.sh — Report 6 LIVE demo: write a non-protected NVRAM var via iBEC setenv,
# reboot, cold-boot, read it back from the recovery shell. If it PERSISTS with no keyed
# check anywhere in the loop (step1 already read the bank props), the unkeyed-seal
# finding is device-proven at the exact target class (boot policy store).
# Chosen var: auto-boot-once — DELIVERY_PATHS §4c: NOT on the protected-name list
# (boot-command/one-time-boot/auto-boot ARE; do not use those).
set -u
cd "$(dirname "$0")"
OUT="results/step5_$(date +%Y%m%d_%H%M%S).log"; mkdir -p results
log(){ echo "[step5] $*" | tee -a "$OUT"; }

log "waiting for recovery device..."
for i in $(seq 1 60); do irecovery -m >/dev/null 2>&1 && break; sleep 2; done
irecovery -m >/dev/null 2>&1 || { log "no recovery device"; exit 1; }

log "pre: getenv auto-boot-once -> $(irecovery -c 'getenv auto-boot-once' 2>&1 | tr -d '\r')"
log "write NO: $(irecovery -c 'setenv auto-boot-once NO' 2>&1 | tr -d '\r')"
log "readback same-boot: $(irecovery -c 'getenv auto-boot-once' 2>&1 | tr -d '\r')"
log "rebooting to normal (auto-boot-once should be CONSUMED by iBoot on boot):"
irecovery -c "reset" 2>&1 | tee -a "$OUT"
log "wait ~60s for boot, THEN re-enter recovery (vol+, vol-, side) and re-run:"
log "  step5_nvram.sh verify    # just reads getenv back"
if [ "${1:-}" = verify ]; then
  for i in $(seq 1 60); do irecovery -m >/dev/null 2>&1 && break; sleep 2; done
  log "post-boot getenv auto-boot-once -> $(irecovery -c 'getenv auto-boot-once' 2>&1 | tr -d '\r')"
  log "RECEIPT: consumed/absent = the once-semantics ran on OUR write = the write was LIVE"
  log "RECEIPT: still NO = value persists cold boot -> policy store forgeability, device-proven"
  log "clear: irecovery -c 'setenv auto-boot-once' (empty) then reset"
fi
