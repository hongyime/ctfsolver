---
name: ctf-osint-domain
description: Domain and DNS reconnaissance for OSINT investigations
tags: [osint, domain, dns, reconnaissance]
prerequisites: [target_domain]
---

# CTF OSINT - Domain Reconnaissance

## When to Use
Use for:
- Discovering subdomains
- Finding domain ownership
- Mapping infrastructure
- Identifying related domains

## Decision Framework
1. Start with passive DNS
2. Check certificate transparency
3. Look for related domains
4. Map infrastructure

## Execution Steps

### Step 1: WHOIS Lookup
```bash
whois target.com
# Look for registrant info, nameservers, dates
```

### Step 2: DNS Enumeration
```bash
dig target.com ANY
dig target.com MX
dig target.com NS
```

### Step 3: Certificate Transparency
```bash
# Use crt.sh
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u
```

## Expected Output Format
```
Domain Information:
  - Registrar: Example Inc.
  - Nameservers: ns1.example.com, ns2.example.com
  - Subdomains Found: 15
```

## Common Pitfalls
- WHOIS data may be private
- Rate limits on lookup services
- Some domains use privacy protection
- DNS may be split across providers
