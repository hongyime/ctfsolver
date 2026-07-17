---
name: ctf-crypto-basics
description: Cryptographic analysis and hash cracking fundamentals
tags: [crypto, hash, encryption]
prerequisites: [encrypted_file, hash_value]
---

# CTF Crypto - Cryptographic Analysis

## When to Use
Use for:
- Hash cracking (MD5, SHA, NTLM)
- Cipher identification and decryption
- RSA key analysis
- Encoding detection (base64, hex, etc.)

## Decision Framework
1. Identify encoding: base64, hex, rot13
2. Identify hash type: use hash-identifier tools
3. Check for weak encryption: XOR, Caesar, Vigenere
4. Determine attack vector: brute-force, dictionary, known-plaintext

## Execution Steps

### Step 1: Identify Hash Type
```bash
# Use hash-identifier or online tools
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashid
```

### Step 2: Crack with Hashcat
```bash
hashcat -m 0 hash.txt wordlist.txt  # MD5
hashcat -m 100 hash.txt wordlist.txt  # NTLM
```

### Step 3: Crack with John
```bash
john --wordlist=wordlist.txt hash.txt
john --show hash.txt
```

## Common Pitfalls
- Always try online databases first (CrackStation)
- Check for salted hashes
- Try multiple hash types if unsure
