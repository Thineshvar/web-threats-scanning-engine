# WTSA — Notion Workspace Setup

Paste this prompt into Claude (with Notion MCP connected) to create all five WTSA databases in your workspace automatically.

---

## Setup Prompt (paste into Claude)

Please set up my WTSA workspace in Notion. I need you to create the following structure:

**Step 1:** Create a hub page called "WTSA — Web Threat Scanning App" with a 🕷️ icon.

**Step 2:** Under that hub page, create these five databases:

---

### Database 1: Scan Sessions
One record per scan run.

Columns:
- "Session Name" — TITLE
- "Session ID" — UNIQUE_ID with prefix 'SCAN'
- "Target URL" — URL
- "Status" — SELECT: Queued (gray), Running (blue), Completed (green), Failed (red)
- "Auth Method" — MULTI_SELECT: Cookie/Token (purple), Auto-Login (blue), Session Replay (brown), None (gray)
- "Modules Enabled" — MULTI_SELECT: XSS (orange), SQLi (red), CMDi (pink), CSRF/SSRF/XXE (brown)
- "Total Threats Detected" — NUMBER
- "Critical" — NUMBER
- "High" — NUMBER
- "Medium" — NUMBER
- "Low" — NUMBER
- "Started At" — CREATED_TIME
- "Last Updated" — LAST_EDITED_TIME
- "Notes" — RICH_TEXT

Add a board view grouped by "Status".

---

### Database 2: Threat Reports
One record per confirmed finding.

Columns:
- "Finding Title" — TITLE
- "Finding ID" — UNIQUE_ID with prefix 'FIND'
- "Vulnerability Type" — SELECT: XSS - Reflected (orange), XSS - Stored (orange), XSS - DOM (orange), SQLi - Classic (red), SQLi - Blind Boolean (red), SQLi - Blind Time (red), CMDi (pink), CSRF (brown), SSRF (brown), XXE (brown)
- "Severity" — SELECT: Critical (red), High (orange), Medium (yellow), Low (blue), Informational (gray)
- "CVSS Score" — NUMBER
- "CWE ID" — RICH_TEXT
- "Target URL" — URL
- "Vulnerable Parameter" — RICH_TEXT
- "Payload Used" — RICH_TEXT
- "Raw Request" — RICH_TEXT
- "Raw Response" — RICH_TEXT
- "Detection Method" — SELECT: DOM Diff (purple), Error Pattern (red), Time Delta (orange), Manual Confirm (green)
- "Confidence" — SELECT: Confirmed (green), Likely (blue), Suspected (yellow)
- "Script Formats" — MULTI_SELECT: requests.py (green), playwright.py (green), curl.sh (gray), burp.txt (orange)
- "Remediation Status" — SELECT: Open (red), In Progress (yellow), Fixed (green), Accepted Risk (gray)
- "AI Escalated" — CHECKBOX
- "Reproduction Steps" — RICH_TEXT
- "Remediation Advice" — RICH_TEXT
- "Created" — CREATED_TIME
- "Last Updated" — LAST_EDITED_TIME

Add views: "By Severity" board grouped by Severity, "By Type" board grouped by Vulnerability Type, "Open Threats Detected" table filtered to Remediation Status = Open sorted by CVSS Score ascending.

---

### Database 3: Detection Signatures
Static and AI-generated payloads with effectiveness tracking.

Columns:
- "Payload Name" — TITLE
- "Payload ID" — UNIQUE_ID with prefix 'PLD'
- "Attack Type" — SELECT: XSS (orange), SQLi (red), CMDi (pink), CSRF (brown), SSRF (brown), XXE (brown)
- "Payload String" — RICH_TEXT
- "Tier" — SELECT: Tier 1 - Static (green), Tier 2 - Static (yellow), Tier 3 - Static (orange), AI Generated (purple)
- "Source" — SELECT: Static Library (gray), Claude Generated (purple), User Added (blue)
- "Target Stack" — MULTI_SELECT: PHP (blue), Python (green), Node.js (yellow), Java (orange), Any (gray)
- "Target DB" — MULTI_SELECT: MySQL (blue), PostgreSQL (purple), SQLite (gray), MSSQL (orange), Any (gray)
- "WAF Safe" — CHECKBOX
- "Encoding" — SELECT: None (gray), URL Encoded (blue), HTML Encoded (green), Base64 (orange), Unicode (purple), Double Encoded (red)
- "Success Rate" — NUMBER
- "Times Used" — NUMBER
- "Times Confirmed" — NUMBER
- "Context Notes" — RICH_TEXT
- "Created" — CREATED_TIME
- "Last Used" — LAST_EDITED_TIME

Add views: "By Tier" board grouped by Tier, "AI Generated Payloads" table filtered to Source = Claude Generated sorted by Times Confirmed descending.

---

### Database 4: Target Profiles
One record per scan's recon phase.

Columns:
- "Recon Name" — TITLE
- "Recon ID" — UNIQUE_ID with prefix 'RCN'
- "Target URL" — URL
- "Backend Language" — SELECT: PHP (blue), Python (green), Node.js (yellow), Java (orange), Ruby (red), Unknown (gray)
- "Database Type" — SELECT: MySQL (blue), PostgreSQL (purple), SQLite (gray), MSSQL (orange), MongoDB (green), Unknown (gray)
- "WAF Detected" — SELECT: None (green), Cloudflare (orange), ModSecurity (red), Akamai (blue), AWS WAF (orange), Unknown WAF (yellow)
- "SPA Detected" — CHECKBOX
- "Auth Required" — CHECKBOX
- "Forms Found" — NUMBER
- "Inputs Found" — NUMBER
- "Reflection Points" — RICH_TEXT
- "Response Headers" — RICH_TEXT
- "Error Signatures" — RICH_TEXT
- "Fingerprint Confidence" — SELECT: High (green), Medium (yellow), Low (red)
- "Scanned At" — CREATED_TIME

---

### Database 5: Threat Assessment Reports
Full exportable PDF report pages — one per scan.

Columns:
- "Report Title" — TITLE
- "Report ID" — UNIQUE_ID with prefix 'RPT'
- "Target URL" — URL
- "Scan Date" — DATE
- "Total Threats Detected" — NUMBER
- "Critical" — NUMBER
- "High" — NUMBER
- "Medium" — NUMBER
- "Low" — NUMBER
- "Backend Stack" — RICH_TEXT
- "Modules Tested" — MULTI_SELECT: XSS (orange), SQLi (red), CMDi (pink), CSRF (brown), SSRF (brown), XXE (brown)
- "Overall Risk" — SELECT: Critical (red), High (orange), Medium (yellow), Low (blue), Informational (gray)
- "Status" — SELECT: Draft (gray), Final (green), Reviewed (blue)
- "Notes" — RICH_TEXT
- "Created" — CREATED_TIME

---

After creating all five databases, please reply with:
1. The page ID of the hub page
2. The database ID for each of the five databases
3. Confirmation that all views were created

I will add these IDs to my `.env` file and the WTSA skill.
