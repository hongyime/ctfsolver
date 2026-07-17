---
name: ctf-re-binwalk
description: Firmware and binary analysis using binwalk for embedded content discovery
tags: [re, binwalk, firmware, embedded]
prerequisites: [binary_file, firmware_file]
---

# CTF RE - Binwalk Firmware Analysis

## When to Use
Use Binwalk for:
- Analyzing firmware images
- Finding embedded files in binaries
- Detecting compressed data
- Identifying file system structures

## Decision Framework
1. Scan for known signatures
2. Extract identified files
3. Analyze extracted content
4. Look for hidden/encrypted data

## Execution Steps

### Step 1: Firmware Scan
```bash
binwalk firmware.bin > binwalk_scan.txt
```

### Step 2: Extract Content
```bash
binwalk -e firmware.bin
# Extracted files go to _firmware.bin.extracted/
```

### Step 3: Entropy Analysis
```bash
binwalk -E firmware.bin
# High entropy areas may be encrypted or compressed
```

## Expected Output Format
```
Binwalk Results:
  - 0x00000000 uImage header
  - 0x00010000 Squashfs filesystem
  - 0x00100000 ELF binary
  - 0x00200000 JFFS2 filesystem
```

## Common Pitfalls
- Extraction may fail on encrypted data
- Large files take time to analyze
- False positives on random data
- Always verify extracted files
