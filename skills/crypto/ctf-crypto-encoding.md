---
name: ctf-crypto-encoding
description: Encoding detection and decoding techniques for CTF challenges
tags: [crypto, encoding, decoding, base64]
prerequisites: [encoded_text]
---

# CTF Crypto - Encoding and Decoding

## When to Use
Use for:
- Decoding base64, hex, ROT13
- Identifying encoding schemes
- Converting between formats
- Reversing obfuscation

## Decision Framework
1. Look for encoding indicators (= for base64, 0x for hex)
2. Try common decodings
3. Check for multiple encoding layers
4. Use CyberChef for complex transformations

## Execution Steps

### Step 1: Base64 Decoding
```bash
echo "SGVsbG8gV29ybGQ=" | base64 -d
# Output: Hello World
```

### Step 2: Hex Decoding
```bash
echo "48656c6c6f20576f726c64" | xxd -r -p
# Output: Hello World
```

### Step 3: ROT13
```bash
echo "Uryyb Jbeyq" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: Hello World
```

## Expected Output Format
```
Encoding Analysis:
  - Detected: Base64
  - Decoded: Hello World
```

## Common Pitfalls
- Multiple encoding layers common
- Not all strings are encoded
- Check for custom alphabets
- Padding characters matter
