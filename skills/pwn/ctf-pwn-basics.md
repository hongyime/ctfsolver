---
name: ctf-pwn-basics
description: Binary exploitation fundamentals with pwntools
tags: [pwn, binary, exploitation]
prerequisites: [binary_file]
---

# CTF Pwn - Binary Exploitation Basics

## When to Use
Use for:
- Buffer overflow challenges
- Return-to-libc attacks
- ROP chain construction
- Format string vulnerabilities

## Decision Framework
1. Check binary protections: `checksec --file binary`
2. Identify vulnerability type: overflow, format string, use-after-free
3. Determine exploitation strategy: overflow → ROP, leak → ret2libc

## Execution Steps

### Step 1: Binary Analysis
```bash
checksec --file ./challenge
file ./challenge
strings ./challenge | grep -i flag
```

### Step 2: Dynamic Analysis
```bash
gdb -q ./challenge
# In gdb: break *main, run, info registers
```

### Step 3: Exploit Development
```python
from pwn import *

p = process('./challenge')
# or remote: p = remote('target', port)

payload = b'A' * 64 + p64(0x401123)  # ROP example
p.sendline(payload)
p.interactive()
```

## Common Pitfalls
- Always check for ASLR, NX, Stack Canary
- Use `strace` to understand syscalls
- Test locally before remote exploitation
