---
name: ctf-web-fuzzing
description: Web directory and file discovery using Feroxbuster/FFUF
tags: [web, fuzzing, directory]
prerequisites: [target_url]
---

# CTF Web - Directory Fuzzing

## When to Use
Use to discover:
- Hidden directories and files
- Admin panels
- Backup files
- API endpoints
- Configuration files

## Decision Framework
1. Start with common wordlist: `/usr/share/wordlists/dirb/common.txt`
2. If many results, use larger wordlist: ` SecLists/Discovery/Web-Content`
3. For recursive: add `-r` flag
4. Filter by status: `-s 200,301,302,401,403`

## Execution Steps

### Step 1: Basic Directory Scan
```bash
feroxbuster -u "http://<TARGET_URL>" -w /usr/share/wordlists/dirb/common.txt -o /workspace/ferox.json --json
```

### Step 2: Recursive Deep Scan
```bash
feroxbuster -u "http://<TARGET_URL>" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -o /workspace/ferox_deep.json --json
```

### Step 3: FFUF Alternative (more control)
```bash
ffuf -u "http://<TARGET_URL>/FUZZ" -w wordlist.txt -of json -o /workspace/ffuf.json
```

## Output Parsing
- JSONL output is automatically parsed
- Discovered paths stored in web_directories table
- Status codes indicate content type

## Expected Output Format
```
[200] http://target/admin
[301] http://target/uploads -> http://target/uploads/
[403] http://target/backup
```

## Common Pitfalls
- Don't forget to handle rate limiting
- Use `-t` to limit threads if target is slow
- Filter out 404s with `-N` (filter by size)
