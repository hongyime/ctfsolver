---
name: ctf-pwn-debugging
description: Binary debugging with GDB and pwntools
tags: [pwn, gdb, debugging]
prerequisites: [binary_file]
---

# CTF Pwn - Binary Debugging

## When to Use
Use for:
- Understanding program flow
- Finding buffer overflow offsets
- Analyzing crashes
- Developing ROP chains

## Decision Framework
1. Run normally to understand behavior
2. Set breakpoints at key functions
3. Examine registers and stack
4. Identify vulnerability point

## Execution Steps

### Step 1: Basic GDB Setup
```bash
gdb -q ./challenge
(gdb) break *main
(gdb) run
(gdb) info registers
(gdb) x/20gx $rsp  # Examine stack
```

### Step 2: Pwntools Debugging
```python
from pwn import *

context.binary = './challenge'
p = gdb.debug('./challenge', '''
break *main+50
continue
''')
p.sendline(b'A'*100)
p.interactive()
```

### Step 3: Cyclic Pattern (Find Offset)
```python
from pwn import *

# Generate pattern
python3 -c "from pwn import *; print(cyclic(200))"

# Find offset after crash
python3 -c "from pwn import *; print(cyclic_find(0x61616162))"
```

## Common Pitfalls
- Use `set disable-randomization off` for ASLR testing
- Check for canaries before overwriting return address
- Use `info proc mappings` to find addresses
