---
name: ctf-forensics-steganography
description: Steganography detection and data extraction techniques
tags: [forensics, steganography, hidden-data]
prerequisites: [suspect_file]
---

# CTF Forensics - Steganography Analysis

## When to Use
Use for:
- Images with hidden data
- Audio files with embedded messages
- Files with unusual sizes
- Challenges mentioning "hidden" or "stego"

## Decision Framework
1. Check file type: `file suspect.jpg`
2. Look for unusual file size
3. Try multiple stego tools
4. Check for appended data

## Execution Steps

### Step 1: Basic Analysis
```bash
file suspect.jpg
exiftool suspect.jpg
strings suspect.jpg | grep -i flag
```

### Step 2: Steghide Analysis
```bash
steghide info suspect.jpg
steghide extract -sf suspect.jpg -xf extracted.txt
```

### Step 3: Advanced Analysis
```bash
# Check for appended data
binwalk suspect.jpg

# Extract hidden files
 foremost suspect.jpg
```

## Expected Output Format
```
Steghide Analysis:
  - No embedding detected OR
  - Embedded data found, extracted to extracted.txt
```

## Common Pitfalls
- Try empty passphrase first
- Some tools require specific file formats
- Data may be encrypted
- Check multiple tools - each detects different methods
