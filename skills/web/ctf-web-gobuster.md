---
name: ctf-web-gobuster
description: Web directory and DNS enumeration using Gobuster
tags: [web, fuzzing, directory, gobuster]
prerequisites: [target_url]
---

# CTF Web - Gobuster Directory Enumeration

## When to Use
Use Gobuster for:
- Discovering hidden directories and files
- DNS subdomain enumeration
- Virtual host discovery
- Fast, targeted brute-forcing

## Decision Framework
1. Start with common wordlist: `directory-list-2.3-small.txt`
2. Use recursive mode for deep discovery
3. Filter by status codes of interest
4. Switch to ffuf for more advanced needs

## Execution Steps

### Step 1: Directory Enumeration
```bash
gobuster dir -u http://<TARGET_URL> -w /usr/share/wordlists/dirb/common.txt -o /workspace/gobuster.txt
```

### Step 2: Recursive Scan
```bash
gobuster dir -u http://<TARGET_URL> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -o /workspace/gobuster_recursive.txt
```

### Step 3: DNS Enumeration
```bash
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt -o /workspace/gobuster_dns.txt
```

## Output Parsing
- Discovered paths stored in web_directories table
- Status codes indicate content type
- Results guide manual exploration

## Expected Output Format
```
/admin (Status: 301)
/uploads (Status: 301)
/api (Status: 200)
/backup (Status: 403)
```

## Common Pitfalls
- Default wordlist may miss custom paths
- Recursive mode can be slow
- 404 filtering may miss custom error pages
- Wildcards can cause false positives
