"""crypto_lattice playbook — LLL/CVP lattice attacks (GREYCTF 'caexor' pattern)."""

from . import Playbook

PLAYBOOK = Playbook(
    name="crypto_lattice",
    category="crypto",
    triggers=("lattice", "lll", "bkz", "cvp", "svp", "knapsack", "hidden number",
              "hnp", "lcg", "truncated", "small roots", "coppersmith", "caexor"),
    tools=("run_lll", "run_sage", "run_z3"),
    workflow=(
        "1. Identify the lattice structure: what unknowns, what modular relations?\n"
        "   Common shapes: hidden-number-problem (ECDSA nonce leak), truncated-LCG,\n"
        "   knapsack/subset-sum, Coppersmith small-roots (stereotyped message / partial key).\n"
        "2. Build the basis matrix so the short vector encodes the secret.\n"
        "3. Reduce with fpylll LLL/BKZ (run_lll) or `flatter` for big bases; for\n"
        "   Coppersmith / algebraic steps use run_sage (small_roots, matrices).\n"
        "4. Read the secret out of the shortest reduced vector; sanity-check modulus.\n"
        "5. Recover the flag and verify its format."
    ),
    skeleton=(
        "from fpylll import IntegerMatrix, LLL\n"
        "# Example: build a basis B (rows = lattice vectors) and reduce.\n"
        "# Replace with the challenge-specific construction.\n"
        "rows = [\n"
        "    [1, 0, 0, A],\n"
        "    [0, 1, 0, B],\n"
        "    [0, 0, 1, C],\n"
        "    [0, 0, 0, N],\n"
        "]\n"
        "M = IntegerMatrix.from_matrix(rows)\n"
        "LLL.reduction(M)\n"
        "for i in range(M.nrows):\n"
        "    print([M[i, j] for j in range(M.ncols)])  # inspect short vectors\n"
        "# The secret is usually a small entry in one of the first reduced rows.\n"
    ),
)
