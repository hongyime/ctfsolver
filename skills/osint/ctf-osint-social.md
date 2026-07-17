---
name: ctf-osint-social
description: Social media and username enumeration techniques
tags: [osint, social-media, username, enumeration]
prerequisites: [username, email]
---

# CTF OSINT - Social Media Enumeration

## When to Use
Use for:
- Finding user accounts across platforms
- Gathering personal information
- Identifying connections
- Building target profiles

## Decision Framework
1. Start with username search
2. Check major platforms first
3. Look for reused usernames
4. Cross-reference findings

## Execution Steps

### Step 1: Username Search
```bash
# Use sherlock or manual search
sherlock targetuser
# Checks 300+ platforms
```

### Step 2: Email Search
```bash
# Check for breaches
haveibeenpwned email@example.com
```

### Step 3: Google Dorking
```
site:twitter.com "targetuser"
site:linkedin.com "targetuser"
site:github.com "targetuser"
```

## Expected Output Format
```
Username: targetuser
Accounts Found:
  - Twitter: @targetuser
  - GitHub: targetuser
  - Instagram: targetuser
```

## Common Pitfalls
- Common usernames have false positives
- Private accounts limit information
- Some platforms block automated search
- Always verify findings manually
