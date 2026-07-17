---
name: ctf-forensics-pcap
description: Network packet analysis using tshark for forensic investigation
tags: [forensics, pcap, network, tshark]
prerequisites: [pcap_file]
---

# CTF Forensics - Network Packet Analysis

## When to Use
Use for:
- Analyzing network captures
- Finding transmitted credentials
- Identifying malicious traffic
- Extracting files from traffic

## Decision Framework
1. Overview of traffic
2. Filter by protocol
3. Extract files/credentials
4. Look for anomalies

## Execution Steps

### Step 1: Traffic Overview
```bash
tshark -r capture.pcap -q -z io,stat,0
```

### Step 2: HTTP Analysis
```bash
# List HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract credentials
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data
```

### Step 3: File Extraction
```bash
# Export HTTP objects
tshark -r capture.pcap --export-objects http,/workspace/extracted/

# Export SMB files
tshark -r capture.pcap --export-objects smb,/workspace/extracted/
```

## Expected Output Format
```
Network Analysis:
  - Total Packets: 10,000
  - HTTP Requests: 150
  - Credentials Found: admin:password123
  - Files Extracted: 3
```

## Common Pitfalls
- Encrypted traffic needs decryption
- Large files slow analysis
- Some protocols need special handling
- Always check for follow-up traffic
