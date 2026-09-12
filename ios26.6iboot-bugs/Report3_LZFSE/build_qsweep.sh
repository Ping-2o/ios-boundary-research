#!/bin/bash
set -e
cd /tmp/ds_iboot/harness
clang -O2 -arch arm64 -o qsweep qsweep.c -lcompression 2>&1
echo BUILD-OK
