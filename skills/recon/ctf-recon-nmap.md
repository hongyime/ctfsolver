---
name: ctf-recon-nmap
description: Network reconnaissance using Nmap for port scanning and service enumeration
tags: [recon, network, scanning]
prerequisites: [target_ip]
---

# CTF Recon - Nmap Network Scanning

## When to Use
Use Nmap for initial network reconnaissance to discover:
- Open ports and services
- Service versions and banners
- Operating system detection
- Network topology

## Decision Framework
1. Start with basic scan: `-sV -sC` (version detection + default scripts)
2. If many ports found, run comprehensive scan: `-p- --min-rate 1000`
3. For stealth: `-sS -T2` (SYN scan, slow timing)
4. For OS detection: `-O` (requires root in container)

## Execution Steps

### Step 1: Basic Service Scan
```bash
nmap -sV -sC -oX /workspace/nmap_basic.xml <TARGET_IP>
```

### Step 2: Full Port Scan (if needed)
```bash
nmap -p- --min-rate 1000 -oX /workspace/nmap_all_ports.xml <TARGET_IP>
```

### Step 3: Targeted Deep Scan
```bash
# For specific ports of interest
nmap -sV -sC -sU -p 53,67,68,69,123,137,138,161,162,500,514,520,1900 -oX /workspace/nmap_udp.xml <TARGET_IP>
```

## Output Parsing
- XML output is automatically parsed by the system
- Services are stored in the database
- Summary is returned to the planner

## Expected Output Format
```
Host: 10.10.10.10
  OS: Linux 3.2 - 4.9
  Open Ports:
    22/tcp: ssh - OpenSSH 7.2p2
    80/tcp: http - Apache httpd 2.4.18
    443/tcp: https - Apache httpd 2.4.18 (OpenSSL/1.0.2g)
```

## Common Pitfalls
- Don't use `-O` without understanding it may crash some services
- Always use `-oX` for XML output (auto-parsed)
- Consider rate limiting (`--min-rate`) for large networks
