---
name: ctf-osint-basics
description: Open-source intelligence gathering techniques
tags: [osint, reconnaissance, information]
prerequisites: [target_domain, username, email]
---

# CTF OSINT - Open Source Intelligence

## When to Use
Use for:
- Username enumeration across platforms
- Email address research
- Domain and subdomain discovery
- Social media footprinting

## Decision Framework
1. Start passive: Google dorks, social media
2. Expand: Username check across platforms
3. Deep dive: Data breaches, public records
4. Correlate: Link findings together

## Execution Steps

### Step 1: Username Search
```bash
# Use theHarvester for email/domain research
theHarvester -d target.com -b google,linkedin,github -f results.xml
```

### Step 2: Domain Research
```bash
# Subdomain enumeration
amass enum -d target.com -o subdomains.txt

# Certificate transparency
crt.sh?q=%.target.com
```

### Step 3: Breach Data
```bash
# Check haveibeenpwned (manual)
# Use holehe for account checking
holehe email@target.com
```

## Common Pitfalls
- Always work from copies, never original data
- Document sources for verification
- Respect rate limits and ToS
