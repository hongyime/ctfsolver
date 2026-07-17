---
name: ctf-forensics-memory
description: Memory dump analysis using Volatility for forensic investigation
tags: [forensics, memory, volatility, analysis]
prerequisites: [memory_dump]
---

# CTF Forensics - Memory Analysis

## When to Use
Use for:
- Analyzing memory dumps
- Finding hidden processes
- Extracting passwords from memory
- Investigating malware

## Decision Framework
1. Identify OS profile
2. List processes
3. Search for strings
4. Extract artifacts

## Execution Steps

### Step 1: Identify Profile
```bash
volatility -f memory.dump imageinfo
# Note the suggested profile
```

### Step 2: Process Listing
```bash
volatility -f memory.dump --profile=Win10x64 pslist
volatility -f memory.dump --profile=Win10x64 pstree
```

### Step 3: Search for Strings
```bash
volatility -f memory.dump --profile=Win10x64 strings > strings.txt
grep -i "flag\|password" strings.txt
```

## Expected Output Format
```
Memory Analysis:
  - OS: Windows 10 x64
  - Processes: 45
  - Suspicious: svchost.exe (PID 1234) - no parent
  - Strings: flag{memory_analysis_complete}
```

## Common Pitfalls
- Wrong profile gives garbage output
- Large dumps take time
- Some data may be paged out
- Always verify with multiple plugins
