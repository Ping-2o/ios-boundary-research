#!/bin/bash
# step9_recover.sh — safe exit: reboot out of recovery/DFU into normal mode.
set -u
cd "$(dirname "$0")"
if irecovery -m >/dev/null 2>&1; then
  echo "[step9] recovery device seen -> issuing reboot to normal"
  irecovery -n || echo "[step9] -n refused: HOLD Vol- + Side button ~10s on the device to force reboot"
else
  echo "[step9] no recovery device attached; if stuck: hold Vol- + Side 10s (forced reboot)."
fi
