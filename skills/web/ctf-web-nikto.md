---
name: ctf-web-nikto
description: Web server vulnerability scanning using Nikto
tags: [web, vulnerability, scanning, nikto]
prerequisites: [target_url]
---

# CTF Web - Nikto Vulnerability Scanning

## When to Use
Use Nikto for:
- Identifying outdated server software
- Finding dangerous files/CGIs
- Detecting server misconfigurations
- Comprehensive web server auditing

## Decision Framework
1. Run after initial port scan finds HTTP/HTTPS
2. Use for baseline vulnerability assessment
3. Combine with manual testing for best results
4. Run before targeted exploitation

## Execution Steps

### Step 1: Basic Scan
```bash
nikto -h http://<TARGET_URL> -output /workspace/nikto.txt -Format txt
```

### Step 2: SSL Scan
```bash
nikto -h https://<TARGET_URL> -ssl -output /workspace/nikto_ssl.txt
```

### Step 3: Authentication Scan
```bash
nikto -h http://<TARGET_URL> -id user:pass -output /workspace/nikto_auth.txt
```

## Output Parsing
- Vulnerabilities extracted and stored
- Server information logged
- Dangerous files/paths identified

## Expected Output Format
```
+ Server: Apache/2.4.49
+ /admin/: Directory indexing found
+ /phpinfo.php: PHP info page found
+ OSVDB-3092: /backup/: This might be interesting...
```

## Common Pitfalls
- Nikto is noisy - avoid when stealth needed
- Many false positives - verify findings manually
- Can be slow on large sites
- May trigger WAF/IDS alerts
