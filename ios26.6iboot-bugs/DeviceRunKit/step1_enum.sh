#!/bin/bash
# step1_enum.sh — iBEC recovery-shell reachability + whitelist enumeration (READ-ONLY)
# Answers: IBEC_IBSS_24A435.md §4.2/§4.3 (does the shell run on this retail A18 unit?)
#          DELIVERY_PATHS §4a mode-bit (via getenv/peek if allowed)
# Safety:  only getenv/peek queries. No writes, no bootx, no state change.
set -u
cd "$(dirname "$0")"
OUT="results/step1_$(date +%Y%m%d_%H%M%S).log"; mkdir -p results
log(){ echo "[step1] $*" | tee -a "$OUT"; }

command -v irecovery >/dev/null || { log "irecovery not installed (brew install libirecovery)"; exit 1; }

log "put device in RECOVERY mode (vol+, vol-, hold side btn until recovery screen), keep USB attached"
log "waiting for recovery-mode device (90s)..."
FOUND=0
for i in $(seq 1 45); do
  if irecovery -m >/dev/null 2>&1; then FOUND=1; break; fi
  sleep 2
done
[ $FOUND -eq 1 ] || { log "NO recovery-mode device seen - aborting"; exit 1; }

irecovery -q >>"$OUT" 2>&1; log "device query:"; cat "$OUT" | tail -8 | sed 's/^/[step1]   /'
log "current mode: $(irecovery -m 2>&1)"

for V in build-version build-style secure-mode security-mode production-status \
         certificate-production-status effective-production-status-ap \
         effective-security-mode-ap effective-security-mode-sep \
         certificate-epoch boot-nonce apnonce chipid boardid unique-chip-id \
         auto-boot boot-command device-recovery delay-recovery-image debug-uarts \
         unlocknvram boot-breadcrumbs recovery-reason nvram-bank-size nvram-bank-count \
         nvram-current-bank nvram-proxy-data panic-log; do
  R=$(irecovery -c "getenv $V" 2>&1 | tr -d '\r')
  log "getenv $V -> $R"
done

log "peek attempts (dev-surface probe; expect rejection on retail):"
# sub_16a4 capability reg (0x3_0073_0024 - ANS window) and the global it memoizes (image-static, not runtime VA)
irecovery -c "peek 0x300730024 8" 2>&1 | tee -a "$OUT" | sed 's/^/[step1]   /'

log "done. If EVERY command returned nothing / the device never enumerated a recovery serial ->"
log "  the shell does not run on retail A18 (documented outcome; Reports 1-3 stay staging-class)."
log "log: $OUT"
