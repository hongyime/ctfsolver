"""crypto_rsa playbook — common RSA attacks."""

from . import Playbook

PLAYBOOK = Playbook(
    name="crypto_rsa",
    category="crypto",
    triggers=("rsa", "modulus", "public key", "n =", "e =", "ciphertext", "factor",
              "wiener", "low exponent", "common modulus", "fermat", "pem"),
    tools=("run_rsactftool", "run_sage", "run_z3"),
    workflow=(
        "1. Gather n, e, c (and any extra leaks). Note e (3/small? large near n?).\n"
        "2. Try the automated path first: run_rsactftool with --publickey / -n -e and\n"
        "   --uncipher c. It covers Wiener, Fermat, small-e, common-modulus, factordb,\n"
        "   Boneh-Durfee, partial-key, etc.\n"
        "3. If n is small or has special structure, factor (factordb via RsaCtfTool,\n"
        "   or sympy.factorint in run_sage). For multi-prime / CRT use run_sage.\n"
        "4. Decrypt: m = c^d mod n; long_to_bytes(m). Verify flag format.\n"
        "5. For low-e + stereotyped message, fall back to crypto_lattice (Coppersmith)."
    ),
    skeleton=(
        "# Fast path: let RsaCtfTool try every known attack.\n"
        "#   run_rsactftool('--publickey /workspace/key.pem --uncipher 0x<c>')\n"
        "# Manual path once factored:\n"
        "from Crypto.Util.number import long_to_bytes, inverse\n"
        "p, q = ..., ...\n"
        "n = p * q; e = 65537; c = ...\n"
        "d = inverse(e, (p - 1) * (q - 1))\n"
        "print(long_to_bytes(pow(c, d, n)))\n"
    ),
)
