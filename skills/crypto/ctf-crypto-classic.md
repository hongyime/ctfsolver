---
name: ctf-crypto-classic
description: Classical cipher analysis and decryption techniques
tags: [crypto, classical, cipher, decryption]
prerequisites: [ciphertext]
---

# CTF Crypto - Classical Cipher Analysis

## When to Use
Use for:
- Caesar cipher decryption
- Vigenère analysis
- Substitution ciphers
- Transposition ciphers

## Decision Framework
1. Analyze letter frequency
2. Look for patterns
3. Try common ciphers
4. Use automated tools

## Execution Steps

### Step 1: Caesar Cipher
```bash
# Try all 26 shifts
for i in {1..25}; do
  echo "$CIPHERTEXT" | tr 'A-Za-z' "$(echo {A..Z} | cut -d' ' -f$i-26,1-$((i-1)))" 
done
```

### Step 2: Vigenère
```python
# Use vigenere solver
python3 vigenere_solver.py ciphertext.txt
```

### Step 3: Frequency Analysis
```python
from collections import Counter
freq = Counter(ciphertext.upper())
print(freq.most_common())
```

## Expected Output Format
```
Cipher Analysis:
  - Type: Caesar
  - Shift: 13 (ROT13)
  - Plaintext: the quick brown fox
```

## Common Pitfalls
- Short texts harder to analyze
- Mixed ciphers possible
- Non-English text needs different frequency
- Always try multiple approaches
