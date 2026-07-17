---
name: ctf-forensics-metadata
description: Metadata analysis using exiftool and file examination
tags: [forensics, metadata, exif]
prerequisites: [file_path]
---

# CTF Forensics - Metadata Analysis

## When to Use
Use for:
- Image metadata extraction (EXIF)
- Document property analysis
- Hidden data in file metadata
- File creation/modification timestamps

## Decision Framework
1. Extract all metadata: exiftool
2. Look for anomalies: timestamps, software, GPS
3. Check for hidden data: strings, binwalk
4. Compare with expected values

## Execution Steps

### Step 1: Extract Metadata
```bash
exiftool image.jpg
exiftool -all image.jpg  # Remove all metadata
```

### Step 2: Deep Analysis
```bash
# Extract GPS data
exiftool -GPS* image.jpg

# Check for steganography indicators
steghide info image.jpg
```

### Step 3: Document Analysis
```bash
# PDF metadata
exiftool document.pdf

# Office document analysis
oleid document.docx
```

## Common Pitfalls
- Metadata can be faked - verify with multiple tools
- Some tools strip metadata on save
- Check for appended data after file EOF
