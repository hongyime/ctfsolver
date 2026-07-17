---
name: ctf-crypto-hashing
description: Hash identification and cracking techniques
tags: [crypto, hash, cracking]
prerequisites: [hash_value]
---

# CTF Crypto - Hash Analysis and Cracking

## When to Use
Use for:
- Identifying unknown hash types
- Cracking password hashes
- Verifying hash integrity
- Reverse-engineering hash formats

## Decision Framework
1. Identify hash type first
2. Check online databases (CrackStation)
3. Try hashcat with appropriate mode
4. Use rules for complex passwords

## Execution Steps

### Step 1: Hash Identification
```bash
# Use hash-identifier or hashid
hashid "5f4dcc3b5aa765d61d8327deb882cf99"
# Output: MD5
```

### Step 2: Hashcat Cracking
```bash
# MD5
hashcat -m 0 hash.txt wordlist.txt

# NTLM
hashcat -m 100 hash.txt wordlist.txt

# SHA256
hashcat -m 1400 hash.txt wordlist.txt
```

### Step 3: John the Ripper
```bash
john --wordlist=wordlist.txt hash.txt
john --show hash.txt
```

## Expected Output Format
```
Hash Type: MD5
Cracking Status: Found
Password: password123
```

## Common Pitfalls
- Wrong hash mode wastes time
- Always try online databases first
- Use appropriate wordlists
- Consider salted hashes
