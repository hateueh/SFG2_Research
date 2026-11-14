#!/usr/bin/env python3
"""
so_strings.py - Extract and search text stored inside libUE4.so.

UE4 stores most UI/network text as UTF-16LE, packed in a pool where
neighbouring strings can sit in the same 16-byte-aligned chunk and run
into each other - "strings -a" on a UTF-16 file shows them concatenated
or truncated. The *_near functions below decode a wide window around a
known marker so you see the real neighbours instead of a single cut
fragment.

Usage:
    python3 so_strings.py <path-to-libUE4.so> ascii   [regex]
    python3 so_strings.py <path-to-libUE4.so> utf16   [regex]
    python3 so_strings.py <path-to-libUE4.so> near <needle-text> [window]
    python3 so_strings.py <path-to-libUE4.so> ips
"""
import re
import sys


def iter_ascii_strings(data: bytes, minlen: int = 5):
    cur = []
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                yield bytes(cur).decode("ascii")
            cur = []
    if len(cur) >= minlen:
        yield bytes(cur).decode("ascii")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path, cmd = sys.argv[1], sys.argv[2]
    data = open(path, "rb").read()

    if cmd == "ascii":
        pat = re.compile(sys.argv[3]) if len(sys.argv) > 3 else None
        for s in iter_ascii_strings(data):
            if pat is None or pat.search(s):
                print(s)

    elif cmd == "utf16":
        text = data.decode("utf-16-le", errors="ignore")
        pat = re.compile(sys.argv[3], re.I) if len(sys.argv) > 3 else None
        # crude utf16 string splitter on non-printable runs
        for s in re.split(r"[^\x20-\x7e]+", text):
            if len(s) >= 5 and (pat is None or pat.search(s)):
                print(s)

    elif cmd == "near":
        needle = sys.argv[3]
        window = int(sys.argv[4]) if len(sys.argv) > 4 else 400
        key = needle.encode("utf-16-le")
        i = data.find(key)
        if i == -1:
            sys.exit(f"'{needle}' not found as UTF-16")
        print(f"offset: {hex(i)}")
        chunk = data[max(0, i - window): i + window]
        print(chunk.decode("utf-16-le", errors="replace"))
        print("--- raw hex ---")
        print(chunk.hex())

    elif cmd == "ips":
        ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        found = set()
        found |= set(ip_re.findall(data.decode("utf-16-le", errors="ignore")))
        found |= set(ip_re.findall(data.decode("latin-1")))
        for ip in sorted(found):
            print(ip)

    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
