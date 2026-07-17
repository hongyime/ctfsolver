---
name: ctf-re-radare2
description: Binary analysis and reverse engineering using radare2
tags: [re, radare2, binary, analysis]
prerequisites: [binary_file]
---

# CTF RE - Radare2 Binary Analysis

## When to Use
Use for:
- Static binary analysis
- Function identification
- String and cross-reference analysis
- Patching binaries

## Decision Framework
1. Load binary and analyze
2. List functions and strings
3. Identify main logic
4. Find vulnerabilities

## Execution Steps

### Step 1: Initial Analysis
```bash
r2 ./binary
[0x00400000]> aaa  # Analyze all
[0x00400000]> afl  # List functions
```

### Step 2: String Analysis
```bash
[0x00400000]> iz  # List strings
[0x00400000]> izq  # Quiet mode
```

### Step 3: Disassembly
```bash
[0x00400000]> s main  # Seek to main
[0x00401234]> pdf  # Print disassembly function
[0x00401234]> VV  # Visual mode
```

## Expected Output Format
```
Binary Analysis:
  - Architecture: x86-64
  - Functions: 25
  - Main: 0x401234
  - Strings: flag{...}, password check
```

## Common Pitfalls
- Analysis can take time on large binaries
- Stripped binaries harder to analyze
- Always verify function boundaries
- Use visual mode for complex functions
