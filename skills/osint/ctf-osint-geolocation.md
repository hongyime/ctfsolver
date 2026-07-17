---
name: ctf-osint-geolocation
description: Geolocation and image analysis techniques for OSINT
tags: [osint, geolocation, image-analysis]
prerequisites: [image_file, coordinates]
---

# CTF OSINT - Geolocation Analysis

## When to Use
Use for:
- Identifying locations from images
- Analyzing metadata
- Cross-referencing landmarks
- Verifying photo authenticity

## Decision Framework
1. Extract metadata
2. Identify landmarks/features
3. Use mapping tools
4. Verify with multiple sources

## Execution Steps

### Step 1: Metadata Extraction
```bash
exiftool image.jpg
# Look for GPS coordinates, timestamps
```

### Step 2: Visual Analysis
```bash
# Identify key features
- Buildings/landmarks
- Vegetation type
- Road signs/language
- Weather/shadows
```

### Step 3: Map Correlation
```
# Use Google Maps/Earth
# Search for matching landmarks
# Check sun position for time verification
```

## Expected Output Format
```
Geolocation Analysis:
  - Coordinates: 37.7749, -122.4194
  - Location: San Francisco, CA
  - Confidence: High
  - Verification: Landmark match
```

## Common Pitfalls
- Metadata may be stripped
- Similar locations exist
- Shadows change with time/season
- Always verify with multiple sources
