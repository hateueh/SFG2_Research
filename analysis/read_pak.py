#!/usr/bin/env python3
"""
read_pak.py - List and read files inside SFG2's encrypted .pak using its
AES-256 key.

The pak is at (inside the extracted OBB):
    SpecialForces/Content/Paks/SpecialForces-Android_Multi.pak

Requires: pip install pyuepak --break-system-packages

The AES-256 key is NOT included in this repo (see docs/README section on
the pak). Put it in an environment variable before running this script:
    export SFG2_PAK_KEY=<64 hex chars>

Usage:
    python3 read_pak.py <path-to.pak> list
    python3 read_pak.py <path-to.pak> read <internal/path/to/file>
    python3 read_pak.py <path-to.pak> folders
"""
import os
import sys

from pyuepak import PakFile  # noqa: E402


def open_pak(path: str) -> PakFile:
    key_hex = os.environ.get("SFG2_PAK_KEY")
    if not key_hex:
        sys.exit("set SFG2_PAK_KEY to the pak's AES-256 key (hex) first")
    pak = PakFile()
    pak.key = bytes.fromhex(key_hex)
    pak.read(path)
    return pak


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    pak_path, cmd = sys.argv[1], sys.argv[2]
    pak = open_pak(pak_path)

    if cmd == "list":
        for f in pak.list_files():
            print(f)

    elif cmd == "read":
        if len(sys.argv) < 4:
            sys.exit("usage: read_pak.py <pak> read <internal path>")
        data = pak.read_file(sys.argv[3])
        sys.stdout.buffer.write(data)

    elif cmd == "folders":
        folders = set()
        for f in pak.list_files():
            if "/" in f:
                folders.add("/".join(f.split("/")[:-1]))
        for folder in sorted(folders):
            level = folder.count("/")
            print("    " * level + folder.split("/")[-1])
        print(f"\n{len(folders)} folders found.", file=sys.stderr)

    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
