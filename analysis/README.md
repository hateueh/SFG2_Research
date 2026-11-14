# Analysis tools

Static and dynamic analysis of the APK/OBB and `libUE4.so`. See the
main `README.md` for what each file does, and `../docs/packet_notes.md`
/ `../docs/Work.txt` for what was found with them.

Quick index:
- `read_pak.py`           - list/extract the encrypted .pak
- `so_strings.py`         - read strings (incl. UE4's UTF-16 pool) from libUE4.so
- `find_native_thunk.sh`  - find a UFunction's native address via relocations
- `DecompAt.py`           - Ghidra headless decompile of specific addresses
- `frida_close_tracer.js` - trace the client's own close-connection call path
