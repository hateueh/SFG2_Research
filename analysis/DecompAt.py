"""
DecompAt.py - Ghidra headless post-script. Decompiles one or more
functions at given radare2-style hex addresses (relative to the binary's
load address, i.e. WITHOUT Ghidra's 0x100000 image base offset added -
this script adds it for you).

Run with analyzeHeadless, for example:

    ~/ghidra/support/analyzeHeadless ~/ghproj sfg2 -process libUE4.so \
        -noanalysis -scriptPath <this-folder> -postScript DecompAt.py \
        101c3ec 101b60c 1777628 e601d0

(-noanalysis is fine here because we only decompile specific addresses;
drop it to run Ghidra's full auto-analysis first, which takes much
longer but gives better results across the whole binary.)
"""
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase().getOffset()
print("image base: 0x%x" % base)

ifc = DecompInterface()
ifc.openProgram(currentProgram)

for a in getScriptArgs():
    addr = toAddr(int(a, 16) + base)
    f = getFunctionContaining(addr)
    if f is None:
        disassemble(addr)
        f = createFunction(addr, None)
    if f is None:
        print("no function at %s" % a)
        continue
    r = ifc.decompileFunction(f, 120, ConsoleTaskMonitor())
    print("=== %s @ %s (arg 0x%s) ===" % (f.getName(), f.getEntryPoint(), a))
    if r.decompileCompleted():
        print(r.getDecompiledFunction().getC())
    else:
        print("decompile failed: %s" % r.getErrorMessage())
