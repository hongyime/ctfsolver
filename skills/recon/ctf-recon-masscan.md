---
name: ctf-recon-masscan
description: High-speed port scanning using Masscan for large-scale network discovery
tags: [recon, network, scanning, masscan]
prerequisites: [target_ip]
---

# CTF Recon - Masscan High-Speed Scanning

## When to Use
Use Masscan for:
- Rapid scanning of large networks
- Full port range scans (1-65535)
- Initial reconnaissance before detailed Nmap scans
- Scanning multiple targets simultaneously

## Decision Framework
1. Use for initial broad scanning: `-p1-65535 --rate 1000`
2. Follow up with Nmap for service detection
3. Use for networks with many hosts
4. Avoid when stealth is required (Masscan is noisy)

## Execution Steps

### Step 1: Full Port Scan
```bash
masscan -p1-65535 --rate 1000 -oX /workspace/masscan.xml <TARGET_IP>
```

### Step 2: Targeted Scan
```bash
masscan -p80,443,22,21,25,53,8080,8443 --rate 500 -oX /workspace/masscan_targeted.xml <TARGET_IP>
```

### Step 3: Follow-up with Nmap
```bash
# Use Masscan results to guide Nmap
nmap -sV -sC -p <PORTS_FROM_MASSCAN> -oX /workspace/nmap_followup.xml <TARGET_IP>
```

## Output Parsing
- XML output is automatically parsed
- Open ports stored in services table
- Results guide subsequent detailed scans

## Expected Output Format
```
Host: 10.10.10.10
  Open Ports: 5
    22/tcp
    80/tcp
    443/tcp
    3306/tcp
    8080/tcp
```

## Common Pitfalls
- Masscan doesn't do service detection - always follow with Nmap
- Can overwhelm networks - use --rate to limit
- May trigger IDS/IPS - use only when stealth not required
- Requires root/admin privileges in container
