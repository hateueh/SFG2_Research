#!/usr/bin/env bash
# find_native_thunk.sh - Find the native function address behind one of
# UE4's reflected UFunction names (e.g. RegisterServer) inside libUE4.so.
#
# UE4 fills a table of (name-string pointer, function pointer) pairs via
# ELF relocations at load time, so a plain cross-reference search in
# radare2/Ghidra finds nothing for these. This script finds the name
# string's relocation slot, then reads the function pointer at the very
# next relocation slot (verified layout: the two are 8 bytes apart).
#
# Usage: ./find_native_thunk.sh <path-to-libUE4.so> <UFunction-name>
set -euo pipefail
LIB="$1"
NAME="$2"

V=$(rabin2 -z "$LIB" | awk -v n="$NAME" '$NF==n {print $3; exit}')
if [ -z "$V" ]; then
    echo "string '$NAME' not found in $LIB" >&2
    exit 1
fi
A=$(printf '%x' "$V")
readelf -rW "$LIB" > /tmp/rela.txt
SLOT=$(grep -E "R_AARCH64_RELATIVE +$A\$" /tmp/rela.txt | head -1 | awk '{print $1}')
if [ -z "$SLOT" ]; then
    echo "no relocation points at string offset 0x$A" >&2
    exit 1
fi
NEXT=$(printf '%016x' $((0x$SLOT + 8)))
echo "name string : 0x$A"
echo "name slot   : 0x$SLOT"
echo "next slot   : 0x$NEXT"
grep -E "^$NEXT " /tmp/rela.txt
echo
echo "To decompile the function at that address:"
echo "  r2 -q -e bin.cache=true -c \"s <addr>; af; pdr\" $LIB"
echo "Ghidra address = radare2 address + 0x100000 (Ghidra's image base)."
