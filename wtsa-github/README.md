# ◈ WTSA — Web Threat Scanning App

> **AI-powered web vulnerability scanner that runs natively inside Claude.**
> Send a URL. Get a full threat scan report. Everything syncs to Notion automatically.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Claude](https://img.shields.io/badge/Claude-Sonnet%204-purple.svg)
![Notion](https://img.shields.io/badge/Notion-MCP-black.svg)
![Python](https://img.shields.io/badge/Python-3.11+-green.svg)

---

## What is WTSA?

WTSA is a security research tool that uses Claude AI to conduct web vulnerability assessments. It operates in two modes:

**Mode A — Chat-Native (Primary):** You send a URL directly in a Claude conversation. Claude researches the target, reasons through attack surfaces, evaluates payloads, writes exploit scripts, and posts a full threats detected report — right in the chat. Everything syncs to Notion automatically and exports to PDF in one click.

**Mode B — Python Backend (Full):** A locally-hosted FastAPI server that performs real HTTP injection, Playwright browser crawling, timing-delta blind injection detection, and DOM diffing. Use this when live HTTP testing is required.

---

## ⚠️ Legal Disclaimer

**This tool is for authorised security testing only.**

- Only run WTSA against targets you own or have explicit written permission to test
- Designed for CTF platforms (HackTheBox, TryHackMe), deliberately insecure training apps (bWAPP, DVWA, WebGoat, Altoro Mutual), and authorised bug bounty targets
- Unauthorised scanning is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), and equivalent laws worldwide
- The authors accept no liability for misuse

All generated exploit scripts include a legal disclaimer comment. The Notion detection signature library stores only payload strings and context notes — never live credentials or exfiltrated data.

---

## Quick Start — Chat-Native Mode (Mode A)

### 1. Prerequisites

- A [Claude.ai](https://claude.ai) account (Pro or Team recommended)
- A [Notion](https://notion.so) account
- The Notion MCP connector enabled in Claude

### 2. Connect Notion to Claude

1. In Claude.ai, go to **Settings → Integrations**
2. Find **Notion** and click **Connect**
3. Authorise the integration for your workspace

### 3. Set up your Notion workspace

Run the setup script to create all five databases automatically:

```
Copy the contents of skills/notion-setup-prompt.md and paste it into Claude.
Claude will create all databases and confirm with links.
```

Or create them manually — see [`skills/notion-setup-prompt.md`](skills/notion-setup-prompt.md) for the exact database schemas.

### 4. Install the WTSA skill in Claude

Copy the contents of [`skills/WTSA-SKILL.md`](skills/WTSA-SKILL.md) and paste it into Claude as your first message in a new conversation. This installs WTSA's scan behaviour, detection signature library awareness, Notion sync logic, and report format.

### 5. Run a scan

```
http://testphp.vulnweb.com — scan for XSS and SQLi
```

That's it. Claude will:
1. Research the target
2. Fingerprint the stack
3. Evaluate payloads across all inputs
4. Write exploit scripts
5. Sync all threats detected to Notion
6. Post the full report in chat
7. Create a Notion page you can export as PDF

---

## Quick Start — Python Backend Mode (Mode B)

### 1. Clone the repo

```bash
git clone https://github.com/your-org/wtsa.git
cd wtsa
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY and NOTION_API_KEY
```

### 3. Install and run

```bash
./start.sh
```

Backend runs at `http://localhost:8000`. API docs at `http://localhost:8000/docs`.

### 4. Connect the UI

Open a Claude conversation, paste the contents of [`frontend/App.jsx`](frontend/App.jsx) as a React Artifact, and connect it to your running backend.

---

## Repository Structure

```
wtsa/
├── README.md                    ← You are here
├── LICENSE                      ← MIT License
├── .gitignore
├── .env.example                 ← Environment config template
├── requirements.txt             ← Python dependencies
├── start.sh                     ← One-command backend startup
│
├── backend/                     ← Mode B: Python backend
│   ├── main.py                  ← FastAPI server + WebSocket
│   ├── threat_scanner.py           ← Scan coordinator (all phases)
│   ├── models.py                ← Shared dataclasses + enums
│   ├── notion_client.py         ← Notion API read/write
│   ├── report_generator.py      ← Jinja2 HTML + JSON reports
│   └── modules/
│       ├── fingerprinter.py     ← Stack/WAF/reflection detection
│       ├── crawler.py           ← Playwright SPA crawler
│       ├── payload_library.py   ← Static XSS/SQLi/CMDi payloads
│       ├── probe engine.py          ← Async HTTP injection
│       ├── analyser.py          ← Signal detection + CVSS
│       └── orchestrator.py      ← Claude AI: strategy + escalation
│
├── frontend/
│   └── App.jsx                  ← React Artifact UI (Mode B)
│
├── skills/
│   ├── WTSA-SKILL.md            ← Paste into Claude to install WTSA
│   ├── notion-setup-prompt.md   ← Paste into Claude to set up Notion
│   └── example-scan-prompts.md  ← Example prompts and workflows
│
└── examples/
    ├── altoro-mutual-report.md  ← Example scan: Altoro Mutual
    ├── bwapp-report.md          ← Example scan: bWAPP
    └── sample-payloads.md       ← Sample payload reference
```

---

## Supported Scan Modules

| Module | Sub-types | Detection method |
|---|---|---|
| XSS | Reflected, Stored, DOM | DOM diff, unescaped reflection |
| SQLi | Classic, Boolean blind, Time-based blind | Error patterns, response delta, timing |
| CMDi | Output-reflected, Blind timing | Output patterns, sleep delta |
| CSRF | Token absence detection | Form analysis |
| SSRF | URL parameter probing | Response anomaly |
| XXE | XML entity injection | File disclosure |

---

## Notion Databases

WTSA writes to five Notion databases after every scan:

| Database | Purpose |
|---|---|
| Scan Sessions | One record per scan run |
| Threat Reports | One record per confirmed finding |
| Detection Signatures | Static + AI-generated payloads with effectiveness tracking |
| Target Profiles | Target fingerprint data per scan |
| Threat Assessment Reports | Full richly-formatted report pages (export to PDF) |

---

## Exporting Reports as PDF

Every scan creates a full Notion report page with cover, executive summary, per-finding detail, exploit scripts, and remediation checklist.

**To export:** Open the report in Notion → click `···` (top right) → `Export` → `PDF`

---

## Tech Stack

| Component | Technology |
|---|---|
| AI orchestration | Anthropic Claude API (`claude-sonnet-4-5`) |
| Notion integration | Notion MCP (chat-native) / `notion-client` Python SDK (backend) |
| Backend framework | Python 3.11 + FastAPI |
| Browser automation | Playwright (Python) |
| HTTP client | `requests` + `httpx` (async) |
| HTML parsing | BeautifulSoup4 |
| Report generation | Jinja2 |

---

## Attack Surface Coverage

WTSA has been validated against:

- **Altoro Mutual** (`altoro.testfire.net`) — Java/JSP banking demo by IBM — 5 threats detected
- **bWAPP** (`itsecgames.com`) — PHP/MySQL training app by Malik Mesellem — 7 threats detected
- **testphp.vulnweb.com** — Acunetix test target
- CTF challenges on HackTheBox and TryHackMe

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-module`)
3. Add payloads to `backend/modules/payload_library.py`
4. Update `skills/WTSA-SKILL.md` if the scan behaviour changes
5. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE)
