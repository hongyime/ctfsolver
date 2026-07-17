---
name: ctf-re-basics
description: Reverse engineering fundamentals with radare2 and Ghidra
tags: [re, reverse, binary]
prerequisites: [binary_file]
---

# CTF RE - Reverse Engineering Basics

## When to Use
Use for:
- Analyzing unknown binaries
- Understanding program logic
- Finding hidden strings and functions
- Decompiling obfuscated code

## Decision Framework
1. Static analysis first: strings, file type, imports
2. Dynamic analysis: run with debugger, trace execution
3. Decompile: use Ghidra/radare2 for C-like output
4. Identify: crypto, encoding, anti-debugging

## Execution Steps

### Step 1: Initial Analysis
```bash
file ./challenge
strings ./challenge | head -50
checksec --file ./challenge
```

### Step 2: radare2 Analysis
```bash
r2 ./challenge
[0x00401000]> aaa          # Analyze all
[0x00401000]> afl          # List functions
[0x00401000]> s sym.main   # Seek to main
[0x00401000]> VV           # Visual graph view
```

### Step 3: Extract Information
```bash
# Find interesting strings
rabin2 -z ./challenge

# List imports (potential functions)
rabin2 -i ./challenge

# Find entry point
rabin2 -e ./challenge
```

## Common Pitfalls
- Always run `aaa` (analyze all) in radare2
- Look for strcmp/strncmp (password checks)
- Check for anti-debugging (ptrace, IsDebuggerPresent)
