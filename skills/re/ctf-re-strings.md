---
name: ctf-re-strings
description: String extraction and analysis from binary files
tags: [re, strings, binary-analysis]
prerequisites: [binary_file]
---

# CTF RE - String Extraction Analysis

## When to Use
Use for:
- Initial binary reconnaissance
- Finding hardcoded credentials
- Discovering function names and API calls
- Locating potential flag strings

## Decision Framework
1. Extract all strings first
2. Filter for interesting patterns
3. Look for flag formats
4. Identify library functions

## Execution Steps

### Step 1: Basic String Extraction
```bash
strings ./binary > strings_output.txt
strings -n 6 ./binary > longer_strings.txt
```

### Step 2: Filter for Interesting Content
```bash
# Look for flag patterns
strings ./binary | grep -i "flag\|ctf\|key\|password"

# Look for URLs
strings ./binary | grep -E "http|ftp|www"

# Look for file paths
strings ./binary | grep -E "/[a-z0-9/]+"
```

### Step 3: Analyze with Context
```bash
# Show strings with context
strings -e s ./binary | less
```

## Expected Output Format
```
Extracted Strings (50+):
  - /bin/sh
  - Welcome to the challenge
  - Enter password:
  - flag{...}
  - Incorrect password
```

## Common Pitfalls
- Encrypted/encoded strings won't be readable
- Short strings may be missed (use -n flag)
- Unicode strings need -e flag
- Always combine with other analysis methods
