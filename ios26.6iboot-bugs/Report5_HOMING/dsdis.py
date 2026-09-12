#!/usr/bin/env python3
# dis.py <fw.bin> <start_off_hex> <end_off_hex> [symbol-hint]
import sys, capstone
fw, start, end = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
data = open(fw, 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = False
n = 0
for i in md.disasm(data[start:end], start):
    ann = ''
    op = i.op_str
    # annotate bl/b targets
    for t in ('bl', 'b', 'cbz', 'cbnz', 'tbz', 'tbnz', 'adr', 'adrp'):
        if i.mnemonic == t or i.mnemonic.startswith(t + '.') or (t == 'b' and i.mnemonic.startswith('b.')):
            try:
                tgt = int(op.split('#')[-1].split(',')[0].strip(), 0) if '#' in op or t in ('adr', 'adrp') else int(op.split(', ')[-1].strip(), 0)
                ann = f'   ; -> 0x{tgt:x}'
            except Exception:
                pass
            break
    print(f"0x{i.address:06x}:  {i.bytes.hex(' ')}  {i.mnemonic:8s} {op}{ann}")
    n += 1
    if n > 4000: break
