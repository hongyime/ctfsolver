# Ghidra headless postScript (Python) — baked into ctf-re image.
# Dumps decompiled functions + strings for a binary, for the run_ghidra MCP tool.
# Invoked by analyzeHeadless: it runs after auto-analysis with the program loaded.
#
# Output is plain text to stdout (analyzeHeadless forwards script stdout), which the
# MCP tool captures. Kept intentionally simple/stable (the §6a "decade-stable" path).
# @category CTF

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

MAX_FUNCS = 40
MAX_DECOMP_CHARS = 2000


def run():
    program = getCurrentProgram()
    if program is None:
        print("ERROR: no program loaded")
        return
    print("=== GHIDRA: %s ===" % program.getName())

    fm = program.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    print("function_count: %d" % len(funcs))

    # Interesting functions first: main / entry / named (non-FUN_/thunk)
    def score(f):
        n = f.getName()
        if n in ("main", "entry", "_start"):
            return 0
        if n.startswith("FUN_") or f.isThunk():
            return 2
        return 1
    funcs.sort(key=score)

    decomp = DecompInterface()
    decomp.openProgram(program)
    monitor = ConsoleTaskMonitor()

    shown = 0
    for f in funcs:
        if shown >= MAX_FUNCS:
            break
        try:
            res = decomp.decompileFunction(f, 60, monitor)
            if res and res.decompileCompleted():
                code = res.getDecompiledFunction().getC()
                print("\n--- %s @ %s ---" % (f.getName(), f.getEntryPoint()))
                print(code[:MAX_DECOMP_CHARS])
                shown += 1
        except Exception as e:
            print("decompile error %s: %s" % (f.getName(), e))


run()
