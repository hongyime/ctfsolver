---
name: ctf-recon-amass
description: Advanced subdomain enumeration using Amass for comprehensive reconnaissance
tags: [recon, subdomain, enumeration, amass]
prerequisites: [target_domain]
---

# CTF Recon - Amass Subdomain Enumeration

## When to Use
Use Amass for:
- Discovering subdomains of a target domain
- Mapping attack surface
- Finding hidden services
- OSINT reconnaissance phase

## Decision Framework
1. Passive mode first: `amass enum -passive`
2. Active mode for deeper results: `amass enum -active`
3. Use with multiple data sources
4. Combine with other tools (subfinder, assetfinder)

## Execution Steps

### Step 1: Passive Enumeration
```bash
amass enum -passive -d target.com -o /workspace/subdomains_passive.txt
```

### Step 2: Active Enumeration
```bash
amass enum -active -d target.com -o /workspace/subdomains_active.txt
```

### Step 3: Brute Force
```bash
amass brute -d target.com -w /usr/share/wordlists/subdomains.txt -o /workspace/subdomains_brute.txt
```

## Output Parsing
- Results stored as discovered targets
- Subdomains added to targets table
- Guides subsequent scanning activities

## Expected Output Format
```
Discovered Subdomains (15):
  - www.target.com
  - mail.target.com
  - api.target.com
  - admin.target.com
  - dev.target.com
```

## Common Pitfalls
- Active mode is slow - use passive for quick results
- Requires API keys for some data sources
- May trigger rate limits on external services
- Results need validation before scanning
