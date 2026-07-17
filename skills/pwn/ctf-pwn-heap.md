---
name: ctf-pwn-heap
description: Heap exploitation techniques including use-after-free and heap overflow
tags: [pwn, heap, use-after-free, overflow]
prerequisites: [binary_file]
---

# CTF Pwn - Heap Exploitation

## When to Use
Use for:
- Use-after-free vulnerabilities
- Heap overflow attacks
- Tcache poisoning
- House of spirit/force/etc

## Decision Framework
1. Identify heap operations
2. Find vulnerability type
3. Plan exploitation strategy
4. Craft payload

## Execution Steps

### Step 1: Analyze Heap Usage
```python
from pwn import *

elf = ELF('./challenge')
# Check for malloc/free calls
# Identify chunk sizes
```

### Step 2: Use-After-Free
```python
# Allocate, free, then use
payload = p64(0) * 5  # Fake chunk
payload += p64(0x21)  # Size
payload += p64(symbol)  # FD pointer
```

### Step 3: Exploit
```python
p = process('./challenge')
p.sendline(payload)
p.interactive()
```

## Expected Output Format
```
Heap Analysis:
  - Vulnerability: Use-after-free
  - Technique: Tcache poisoning
  - Target: __free_hook -> system
  - Shell: Obtained
```

## Common Pitfalls
- Glibc version matters
- Tcache has limits
- ASLR affects heap addresses
- Always leak addresses first
