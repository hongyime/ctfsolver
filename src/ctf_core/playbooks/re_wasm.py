"""re_wasm playbook — WebAssembly reverse engineering."""

from . import Playbook

PLAYBOOK = Playbook(
    name="re_wasm",
    category="re",
    triggers=("wasm", "webassembly", "wat", "wasm2wat", ".wasm", "emscripten",
              "wasm-bindgen", "browser challenge"),
    tools=("run_wasm2wat", "run_z3", "run_angr"),
    workflow=(
        "1. Convert the module to text: run_wasm2wat(path) -> readable .wat.\n"
        "2. Locate the check/validate function (often exported, e.g. 'check', 'verify').\n"
        "3. Read the comparison logic: constants, memory loads, the transform applied\n"
        "   to input before comparison (xor/add/permute are common).\n"
        "4. If the constraints are non-trivial, model them in run_z3 and solve for input.\n"
        "5. For heavy/obfuscated logic, lift to angr (run_angr) and let it find the input\n"
        "   reaching the 'success' path.\n"
        "6. Reconstruct the flag from the solved input bytes."
    ),
    skeleton=(
        "# 1) run_wasm2wat('chal.wasm')  -> inspect the exported check function\n"
        "# 2) model the per-byte constraints in z3 (run_z3):\n"
        "from z3 import *\n"
        "n = 32\n"
        "flag = [BitVec(f'b{i}', 8) for i in range(n)]\n"
        "s = Solver()\n"
        "# Example constraint shape from the .wat (replace with the real transform):\n"
        "# for i in range(n): s.add((flag[i] ^ KEY[i]) == TARGET[i])\n"
        "if s.check() == sat:\n"
        "    m = s.model()\n"
        "    print(bytes(m[flag[i]].as_long() for i in range(n)))\n"
    ),
)
