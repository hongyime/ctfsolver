#!/usr/bin/env python3
"""Ghidra warm-JVM broker — baked into the ctftoolkit/ctf-re image.

Runs ONCE per session inside a detached container. Boots the JVM and analyzes the
target binary a single time, then serves JSONL requests on stdin/stdout until EOF
or a shutdown request. This is the warm path the run_ghidra one-shot can't provide
(it pays cold-JVM + analysis on every call).

Protocol (one JSON object per line):
  Request:  {"id": <str>, "op": <str>, "args": {...}}
  Response: {"id": <str>, "ok": true, "data": ...} | {"id": <str>, "ok": false, "error": <str>}
Readiness (emitted once, before the request loop):
  {"ready": true, "program": "<name>"} | {"ready": false, "error": "..."}

stdout is the protocol channel; all logging goes to stderr.

API notes (verified against pyghidra 3.1.0 / Ghidra 12.1 in-image):
  * pyghidra.start(); pyghidra.open_program(path, analyze=True) -> FlatProgramAPI ctx
  * FunctionManager.getFunctions(str, bool) does NOT exist -> resolve names by
    iterate+filter. Other symbol/string APIs are wrapped defensively with fallbacks.
"""

import sys
import json
import logging
import traceback
from pathlib import Path

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s [ghidra-broker] %(levelname)s %(message)s")
log = logging.getLogger("ghidra_broker")


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _s(x) -> str:
    try:
        return str(x)
    except Exception:
        return repr(x)


def _off(addr):
    try:
        return addr.getOffset()
    except Exception:
        return None


import pyghidra  # noqa: E402


class State:
    def __init__(self):
        self.ctx = None
        self.flat = None
        self.program = None
        self.decomp = None

    def open(self, path: str) -> None:
        # pyghidra 3.1.0's import-hook find_spec can recurse deeply during JVM
        # launch (launcher.py:116 'from ghidra.framework import Application').
        # Raise the recursion limit so that deep-but-finite import chain resolves.
        sys.setrecursionlimit(10000)
        log.info("pyghidra.start() ...")
        pyghidra.start()
        log.info("open_program(%s, analyze=True) ...", path)
        self.ctx = pyghidra.open_program(path, analyze=True)
        self.flat = self.ctx.__enter__()
        self.program = self.flat.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface
        self.decomp = DecompInterface()
        self.decomp.openProgram(self.program)
        log.info("ready: %s", self.program.getName())

    def close(self):
        try:
            if self.decomp:
                self.decomp.dispose()
        except Exception:
            pass
        try:
            if self.ctx:
                self.ctx.__exit__(None, None, None)
        except Exception:
            pass


def _resolve(state: State, args: dict):
    fm = state.program.getFunctionManager()
    if args.get("name"):
        nm = args["name"]
        for f in fm.getFunctions(True):
            if _s(f.getName()) == nm:
                return f
        return None
    if args.get("address"):
        a = args["address"]
        a = int(a, 16) if isinstance(a, str) else int(a)
        sp = state.program.getAddressFactory().getDefaultAddressSpace()
        return fm.getFunctionAt(sp.getAddress(a))
    return None


def op_list_functions(state: State, args: dict):
    fm = state.program.getFunctionManager()
    out = []
    for f in fm.getFunctions(True):
        try:
            size = f.getBody().getNumAddresses()
        except Exception:
            size = None
        out.append({"name": _s(f.getName()),
                    "entry": hex(_off(f.getEntryPoint()) or 0),
                    "size": size})
    return out


def op_decompile(state: State, args: dict):
    from ghidra.util.task import ConsoleTaskMonitor
    fn = _resolve(state, args)
    if fn is None:
        raise ValueError(f"function not found: {args}")
    res = state.decomp.decompileFunction(fn, 60, ConsoleTaskMonitor())
    if res is None or not res.decompileCompleted():
        msg = _s(res.getErrorMessage()) if res else "null result"
        raise RuntimeError(f"decompile failed: {msg}")
    dfn = res.getDecompiledFunction()
    return {"name": _s(fn.getName()),
            "entry": hex(_off(fn.getEntryPoint()) or 0),
            "c": _s(dfn.getC()) if dfn else "(no output)"}


def op_strings(state: State, args: dict):
    min_len = int(args.get("min_length", 4))
    filt = (args.get("filter") or "").lower()
    out = []
    # Preferred: DefinedDataIterator.definedStrings; fall back to listing scan.
    try:
        from ghidra.program.util import DefinedDataIterator
        it = DefinedDataIterator.definedStrings(state.program)
    except Exception:
        it = None
    if it is not None:
        for d in it:
            try:
                v = _s(d.getValue())
            except Exception:
                continue
            if len(v) >= min_len and (not filt or filt in v.lower()):
                out.append({"address": hex(_off(d.getAddress()) or 0), "value": v})
    else:
        listing = state.program.getListing()
        for d in listing.getDefinedData(True):
            try:
                if "string" in _s(d.getDataType().getName()).lower():
                    v = _s(d.getValue())
                    if len(v) >= min_len and (not filt or filt in v.lower()):
                        out.append({"address": hex(_off(d.getAddress()) or 0), "value": v})
            except Exception:
                continue
    return out[:1000]


def op_xrefs(state: State, args: dict):
    fn = _resolve(state, args)
    if fn is None:
        raise ValueError(f"function not found: {args}")
    rm = state.program.getReferenceManager()
    out = []
    for ref in rm.getReferencesTo(fn.getEntryPoint()):
        out.append({"from": hex(_off(ref.getFromAddress()) or 0),
                    "type": _s(ref.getReferenceType())})
    return {"function": _s(fn.getName()), "xrefs_to": out}


def op_imports(state: State, args: dict):
    st = state.program.getSymbolTable()
    out = []
    try:
        syms = st.getExternalSymbols()
    except Exception:
        syms = []
    for sym in syms:
        out.append({"name": _s(sym.getName()),
                    "address": hex(_off(sym.getAddress()) or 0) if sym.getAddress() else None})
    return out


def op_exports(state: State, args: dict):
    st = state.program.getSymbolTable()
    out = []
    try:
        for sym in st.getAllSymbols(True):
            if sym.isExternalEntryPoint():
                out.append({"name": _s(sym.getName()),
                            "address": hex(_off(sym.getAddress()) or 0)})
    except Exception:
        pass
    return out


HANDLERS = {
    "list_functions": op_list_functions,
    "decompile": op_decompile,
    "strings": op_strings,
    "xrefs": op_xrefs,
    "imports": op_imports,
    "exports": op_exports,
}


def main() -> None:
    if len(sys.argv) < 2:
        emit({"ready": False, "error": "usage: ghidra_broker.py <binary>"})
        sys.exit(1)
    binary = sys.argv[1]
    if not Path(binary).exists():
        emit({"ready": False, "error": f"binary not found: {binary}"})
        sys.exit(1)

    state = State()
    try:
        state.open(binary)
    except Exception as e:
        emit({"ready": False, "error": str(e), "traceback": traceback.format_exc()[:2000]})
        sys.exit(1)

    emit({"ready": True, "program": _s(state.program.getName())})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            emit({"id": None, "ok": False, "error": f"bad json: {e}"})
            continue
        rid = req.get("id", "?")
        op = req.get("op", "")
        if op == "shutdown":
            emit({"id": rid, "ok": True, "data": "bye"})
            break
        h = HANDLERS.get(op)
        if h is None:
            emit({"id": rid, "ok": False, "error": f"unknown op {op!r}; valid={list(HANDLERS)}"})
            continue
        try:
            emit({"id": rid, "ok": True, "data": h(state, req.get("args", {}))})
        except Exception as e:
            log.error("op %s failed: %s", op, traceback.format_exc())
            emit({"id": rid, "ok": False, "error": f"{type(e).__name__}: {e}"})

    state.close()
    log.info("broker exit")


if __name__ == "__main__":
    main()
