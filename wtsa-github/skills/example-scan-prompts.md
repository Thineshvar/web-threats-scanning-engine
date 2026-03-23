# WTSA — Example Scan Prompts

A reference guide for getting the most out of WTSA in chat-native mode.

---

## Basic Scans

### Minimal — just a URL
```
http://testphp.vulnweb.com
```
WTSA will infer all modules and scan everything it finds.

### With module focus
```
http://www.itsecgames.com — scan for SQLi and XSS only
```

```
http://dvwa.local — run all modules, focus on command injection
```

### With scope hint
```
http://my-app.com — check the login form and the search page for XSS and SQLi
```

---

## Authenticated Scans

### Cookie paste
```
http://app.example.com — authenticated scan
Cookie: PHPSESSID=abc123def456; session_token=xyz789
```

### With login credentials (for Mode B / Python backend)
```
http://testapp.local — auto-login scan
Login URL: http://testapp.local/login
Username field: user
Password field: pass
Credentials: admin / password123
```

---

## Training App Scans

### bWAPP (default credentials: bee / bug)
```
http://www.itsecgames.com — full scan, all modules
```

### DVWA (default credentials: admin / password)
```
http://dvwa.local — scan at security level low
```

### Altoro Mutual (IBM's Java banking demo)
```
http://altoro.testfire.net — focus on login bypass and search SQLi
```

### WebGoat (OWASP training app)
```
http://localhost:8080/WebGoat — scan for XSS and injection vulnerabilities
```

### Acunetix test target
```
http://testphp.vulnweb.com
```

---

## Focused Scans

### SQLi only, specific endpoint
```
http://target.com/search.php?q=test — SQLi scan only, focus on q parameter
```

### XSS hunt across a domain
```
http://target.com — XSS scan only, look at all GET parameters and forms
```

### Blind injection investigation
```
http://target.com/api/user?id=1 — test for blind SQLi (time-based) and blind CMDi
```

### WAF bypass mode
```
http://target.com — WAF bypass mode, use tier 2 and tier 3 payloads from the start
Note: Target uses Cloudflare WAF
```

---

## CTF Scans

### HackTheBox / TryHackMe style
```
http://10.10.10.100 — CTF target, scan everything, I need the flags
Backend appears to be PHP based on the login page
```

### With specific intelligence
```
http://10.10.10.100/login.php — I found a login form with username and password fields
The app uses MySQL based on error messages I've seen
Try SQLi on the username field
```

---

## Follow-up Prompts

### After a scan completes
```
Can you go deeper on the SQLi finding in the title parameter?
Write me the full sqlmap command to exploit it.
```

```
Give me the complete Python exploit script for finding 02.
```

```
What's the CVSS vector string for the stored XSS finding?
```

```
Generate a Burp Suite intruder payload list for the XSS threats detected.
```

### Report customisation
```
Can you rewrite the executive summary to be less technical — it's for a non-technical client.
```

```
Add a risk matrix to the Notion report.
```

```
Update the remediation status for finding 01 to Fixed in Notion.
```

---

## Bulk Scanning

### Multiple targets in sequence
```
Please scan these three targets one after the other:
1. http://testphp.vulnweb.com
2. http://www.itsecgames.com
3. http://altoro.testfire.net

All are training apps. Full scan for each. Separate Notion reports.
```

---

## Tips

**Be specific about what you already know.** The more context you give Claude about the target (stack, framework, known parameters), the more targeted and accurate the scan will be.

**Use the Notion report links.** Every scan produces a full Notion page. Open it and export to PDF for a professional deliverable.

**Iterate on threats detected.** After a scan, you can ask Claude to go deeper on any individual finding, generate more payload variants, or write additional exploit scripts.

**Chain prompts.** Start broad, then narrow: first scan all modules, then ask for deeper analysis on the most critical finding.
