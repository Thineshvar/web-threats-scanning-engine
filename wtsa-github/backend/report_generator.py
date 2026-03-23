"""
WTSA — Report Generator
Produces report.html (visual) and report.json (machine-readable)
from a completed ScanSession.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from jinja2 import Template
from .models import ScanSession, Finding, Severity


# ── HTML Template ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WTSA Report — {{ session.session_name }}</title>
<style>
  :root {
    --bg: #0a0c0f; --surface: #111418; --border: #1e2530;
    --text: #c8d8e8; --muted: #5a7080; --accent: #00d4ff;
    --green: #00e676; --amber: #ffb300; --red: #ff4444;
    --critical: #ff1744; --high: #ff6d00; --medium: #ffd600;
    --low: #69f0ae; --info: #40c4ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'IBM Plex Mono', 'Fira Code', monospace; padding: 32px; }
  h1 { font-size: 28px; color: var(--accent); letter-spacing: 0.05em; margin-bottom: 6px; }
  h2 { font-size: 14px; color: var(--muted); font-weight: 400; letter-spacing: 0.12em; margin-bottom: 32px; }
  h3 { font-size: 13px; color: var(--accent); letter-spacing: 0.08em; margin-bottom: 12px; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .meta-card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; }
  .meta-card .label { font-size: 10px; color: var(--muted); letter-spacing: 0.1em; margin-bottom: 6px; }
  .meta-card .value { font-size: 16px; font-weight: 700; color: var(--text); }
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
  .section-header { padding: 12px 18px; border-bottom: 1px solid var(--border); background: #0d1117; font-size: 11px; color: var(--accent); letter-spacing: 0.1em; font-weight: 700; }
  .section-body { padding: 18px; }
  .summary-text { font-size: 13px; line-height: 1.9; color: var(--text); white-space: pre-wrap; }
  .sev-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
  .sev-card { border-radius: 6px; padding: 14px; text-align: center; }
  .sev-card .num { font-size: 28px; font-weight: 700; }
  .sev-card .lbl { font-size: 9px; letter-spacing: 0.1em; margin-top: 4px; }
  .sev-critical { background: #2a0010; border: 1px solid #ff174433; } .sev-critical .num { color: var(--critical); } .sev-critical .lbl { color: #ff174488; }
  .sev-high     { background: #1a0f00; border: 1px solid #ff6d0033; } .sev-high .num     { color: var(--high); }     .sev-high .lbl     { color: #ff6d0088; }
  .sev-medium   { background: #1a1400; border: 1px solid #ffd60033; } .sev-medium .num   { color: var(--medium); }   .sev-medium .lbl   { color: #ffd60088; }
  .sev-low      { background: #001a0d; border: 1px solid #69f0ae33; } .sev-low .num      { color: var(--low); }      .sev-low .lbl      { color: #69f0ae88; }
  .sev-info     { background: #001018; border: 1px solid #40c4ff33; } .sev-info .num     { color: var(--info); }     .sev-info .lbl     { color: #40c4ff88; }
  .finding { border-radius: 6px; margin-bottom: 14px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 10px; padding: 12px 16px; }
  .finding-body { padding: 0 16px 16px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; letter-spacing: 0.06em; }
  .badge-critical { color: var(--critical); background: #ff174422; border: 1px solid #ff174444; }
  .badge-high     { color: var(--high);     background: #ff6d0022; border: 1px solid #ff6d0044; }
  .badge-medium   { color: var(--medium);   background: #ffd60022; border: 1px solid #ffd60044; }
  .badge-low      { color: var(--low);      background: #69f0ae22; border: 1px solid #69f0ae44; }
  .badge-info     { color: var(--info);     background: #40c4ff22; border: 1px solid #40c4ff44; }
  .badge-purple   { color: #bb86fc;         background: #bb86fc15; border: 1px solid #bb86fc33; }
  .badge-green    { color: var(--green);    background: #00e67615; border: 1px solid #00e67633; }
  .badge-ai       { color: #f48fb1;         background: #f48fb115; border: 1px solid #f48fb133; }
  .finding-title  { flex: 1; font-size: 13px; }
  .cvss-score     { font-size: 11px; color: var(--muted); }
  .field-grid     { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
  .field label    { font-size: 10px; color: var(--muted); display: block; margin-bottom: 3px; letter-spacing: 0.06em; }
  .field span     { font-size: 12px; color: var(--text); word-break: break-all; }
  .code-block     { background: #0a0c0f; border: 1px solid var(--border); border-radius: 4px; padding: 12px; font-size: 11px; color: var(--text); white-space: pre-wrap; line-height: 1.7; margin-top: 10px; overflow-x: auto; }
  .remediation    { background: rgba(0,230,118,0.04); border: 1px solid rgba(0,230,118,0.15); border-radius: 4px; padding: 12px; font-size: 11px; color: var(--green); white-space: pre-wrap; line-height: 1.7; margin-top: 10px; }
  .script-tags    { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }
  .notion-links   { display: flex; gap: 10px; flex-wrap: wrap; }
  .notion-link    { display: inline-block; padding: 6px 12px; background: rgba(0,212,255,0.08); border: 1px solid rgba(0,212,255,0.2); border-radius: 4px; color: var(--accent); font-size: 11px; text-decoration: none; }
  .disclaimer     { margin-top: 32px; padding: 12px 16px; background: rgba(255,68,68,0.05); border: 1px solid rgba(255,68,68,0.15); border-radius: 6px; font-size: 11px; color: #ff444488; line-height: 1.6; }
  hr { border: none; border-top: 1px solid var(--border); margin: 24px 0; }
</style>
</head>
<body>

<h1>◈ WTSA Vulnerability Report</h1>
<h2>WEB EXPLOITATION AUTOMATION ENGINE — {{ generated_at }}</h2>

<div class="meta">
  <div class="meta-card"><div class="label">SESSION</div><div class="value" style="font-size:13px">{{ session.session_name }}</div></div>
  <div class="meta-card"><div class="label">TARGET</div><div class="value" style="font-size:12px; color: #00d4ff">{{ session.config.target_url }}</div></div>
  <div class="meta-card"><div class="label">STACK</div><div class="value" style="font-size:13px">{{ ctx.backend_language }} / {{ ctx.database_type }}</div></div>
  <div class="meta-card"><div class="label">WAF</div><div class="value" style="font-size:13px">{{ ctx.waf_detected }}</div></div>
  <div class="meta-card"><div class="label">STATUS</div><div class="value" style="color: #00e676">{{ session.status.upper() }}</div></div>
</div>

{% if executive_summary %}
<div class="section">
  <div class="section-header">// EXECUTIVE SUMMARY</div>
  <div class="section-body"><p class="summary-text">{{ executive_summary }}</p></div>
</div>
{% endif %}

<div class="section">
  <div class="section-header">// SEVERITY BREAKDOWN</div>
  <div class="section-body">
    <div class="sev-grid">
      <div class="sev-card sev-critical"><div class="num">{{ counts.Critical }}</div><div class="lbl">CRITICAL</div></div>
      <div class="sev-card sev-high">    <div class="num">{{ counts.High }}</div>    <div class="lbl">HIGH</div></div>
      <div class="sev-card sev-medium">  <div class="num">{{ counts.Medium }}</div>  <div class="lbl">MEDIUM</div></div>
      <div class="sev-card sev-low">     <div class="num">{{ counts.Low }}</div>     <div class="lbl">LOW</div></div>
      <div class="sev-card sev-info">    <div class="num">{{ counts.Informational }}</div><div class="lbl">INFO</div></div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-header">// FINDINGS ({{ threats detected|length }} total)</div>
  <div class="section-body">
    {% for f in threats detected %}
    {% set sev_cls = f.severity.value.lower() %}
    {% if sev_cls == "informational" %}{% set sev_cls = "info" %}{% endif %}
    <div class="finding" style="background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--{{ sev_cls }});">
      <div class="finding-header">
        <span class="badge badge-{{ sev_cls }}">{{ f.severity.value.upper() }}</span>
        <span class="finding-title">{{ f.title }}</span>
        <span class="badge badge-purple">{{ f.attack_type.value }}</span>
        <span class="cvss-score">CVSS {{ f.cvss_score }}</span>
        {% if f.ai_escalated %}<span class="badge badge-ai">AI ✦</span>{% endif %}
      </div>
      <div class="finding-body">
        <div class="field-grid">
          <div class="field"><label>URL</label><span>{{ f.target_url }}</span></div>
          <div class="field"><label>PARAMETER</label><span>{{ f.vulnerable_param }}</span></div>
          <div class="field"><label>CWE</label><span>{{ f.cwe_id }}</span></div>
          <div class="field"><label>DETECTION</label><span>{{ f.detection_method.value }}</span></div>
          <div class="field"><label>CONFIDENCE</label><span>{{ f.confidence.value }}</span></div>
          <div class="field"><label>PAYLOAD</label><span>{{ f.payload_used[:120] }}</span></div>
        </div>

        {% if f.raw_request %}
        <div style="margin-top:12px; font-size:10px; color:var(--muted); letter-spacing:0.06em">RAW REQUEST</div>
        <div class="code-block">{{ f.raw_request[:600] }}</div>
        {% endif %}

        {% if f.reproduction_steps %}
        <div style="margin-top:12px; font-size:10px; color:var(--muted); letter-spacing:0.06em">REPRODUCTION STEPS</div>
        <div class="code-block">{{ f.reproduction_steps }}</div>
        {% endif %}

        {% if f.remediation_advice %}
        <div style="margin-top:12px; font-size:10px; color:var(--muted); letter-spacing:0.06em">REMEDIATION</div>
        <div class="remediation">{{ f.remediation_advice }}</div>
        {% endif %}

        {% if f.script_formats %}
        <div class="script-tags">
          {% for fmt in f.script_formats %}
          <span class="badge badge-green">{{ fmt }}</span>
          {% endfor %}
        </div>
        {% endif %}
      </div>
    </div>
    {% else %}
    <p style="color: var(--muted); font-size: 13px; padding: 20px 0; text-align: center;">No threats detected recorded.</p>
    {% endfor %}
  </div>
</div>

<div class="section">
  <div class="section-header">// NOTION WORKSPACE</div>
  <div class="section-body">
    <div class="notion-links">
      <a class="notion-link" href="https://notion.so/eb840a4a96e4467490b21ab0ff1fa708" target="_blank">↗ Scan Sessions</a>
      <a class="notion-link" href="https://notion.so/675f50bffdff44c79e46906ad118fe41" target="_blank">↗ Threat Reports</a>
      <a class="notion-link" href="https://notion.so/029bbed89aaf4ed8ac0f89fc216d6a38" target="_blank">↗ Detection Signatures</a>
      <a class="notion-link" href="https://notion.so/56fccd451ce54872933a14835836244c" target="_blank">↗ Target Profiles</a>
    </div>
  </div>
</div>

<div class="disclaimer">
  ⚠ Legal disclaimer: This report was generated by the WTSA automated security scanner.
  All testing was conducted against authorised targets only.
  Unauthorised use of this tool or its threats detected against systems you do not own or have
  explicit written permission to test is illegal and unethical.
  The authors accept no liability for misuse.
</div>

</body>
</html>"""


# ── Script file template ──────────────────────────────────────────────────────

MASTER_SCRIPT_TEMPLATE = """#!/usr/bin/env python3
\"\"\"
WTSA — Master Exploit Script
Session: {session_name}
Target:  {target_url}
Generated: {generated_at}

LEGAL DISCLAIMER: For authorised security testing only.
Unauthorised use is illegal. The authors accept no liability for misuse.
\"\"\"

import requests
import sys

TARGET = "{target_url}"
FINDINGS = {threats detected_count}

def run_all():
    print(f"[WTSA] Running {FINDINGS} confirmed exploit(s) against {{TARGET}}")
    results = []

{exploit_blocks}
    return results

if __name__ == "__main__":
    run_all()
"""


# ── Generator class ───────────────────────────────────────────────────────────

class ReportGenerator:
    def __init__(self, output_dir: str = "scan_output"):
        self.output_dir = Path(output_dir)

    def generate(self, session: ScanSession, scripts: dict,
                 executive_summary: str = "") -> dict:
        """
        Generates all output artefacts.
        Returns dict of {filename: path} for all generated files.
        """
        # Create timestamped output directory
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        name = session.session_name.replace(" ", "_").replace("-", "_")
        out  = self.output_dir / f"{name}_{ts}"
        out.mkdir(parents=True, exist_ok=True)

        (out / "scripts").mkdir(exist_ok=True)
        (out / "burp").mkdir(exist_ok=True)
        (out / "curl").mkdir(exist_ok=True)

        generated = {}

        # ── report.html ──
        html = self._render_html(session, executive_summary)
        p = out / "report.html"
        p.write_text(html, encoding="utf-8")
        generated["report.html"] = str(p)

        # ── report.json ──
        data = self._build_json(session, executive_summary)
        p = out / "report.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        generated["report.json"] = str(p)

        # ── Per-finding scripts ──
        xss_blocks = []
        sqli_blocks = []
        cmdi_blocks = []

        for finding in session.threats detected:
            fid = id(finding)
            finding_scripts = scripts.get(fid, {})
            safe_name = finding.vulnerable_param.replace("/", "_").replace("?", "_")[:30]
            slug = f"{finding.attack_type.value.replace(' ', '_').replace('-', '_')}_{safe_name}"

            # requests.py
            if finding_scripts.get("requests_py"):
                p = out / "scripts" / f"{slug}_requests.py"
                p.write_text(finding_scripts["requests_py"], encoding="utf-8")
                generated[f"{slug}_requests.py"] = str(p)
                _append_to_master(finding, finding_scripts["requests_py"],
                                  xss_blocks, sqli_blocks, cmdi_blocks)

            # playwright.py
            if finding_scripts.get("playwright_py"):
                p = out / "scripts" / f"{slug}_playwright.py"
                p.write_text(finding_scripts["playwright_py"], encoding="utf-8")
                generated[f"{slug}_playwright.py"] = str(p)

            # curl.sh
            if finding_scripts.get("curl_sh"):
                p = out / "curl" / f"{slug}.sh"
                p.write_text(f"#!/bin/bash\n# LEGAL DISCLAIMER: Authorised use only\n{finding_scripts['curl_sh']}\n", encoding="utf-8")
                generated[f"{slug}.sh"] = str(p)

            # burp.txt
            if finding_scripts.get("burp_txt"):
                p = out / "burp" / f"{slug}.txt"
                p.write_text(finding_scripts["burp_txt"], encoding="utf-8")
                generated[f"{slug}_burp.txt"] = str(p)

        # ── Module master scripts ──
        for module_name, blocks in [("xss", xss_blocks), ("sqli", sqli_blocks), ("cmdi", cmdi_blocks)]:
            if blocks:
                content = _build_module_script(module_name, session, blocks)
                p = out / "scripts" / f"{module_name}.py"
                p.write_text(content, encoding="utf-8")
                generated[f"{module_name}.py"] = str(p)

        # ── master_scan.py ──
        all_blocks = xss_blocks + sqli_blocks + cmdi_blocks
        if all_blocks:
            master = MASTER_SCRIPT_TEMPLATE.format(
                session_name=session.session_name,
                target_url=session.config.target_url,
                generated_at=datetime.utcnow().isoformat(),
                threats detected_count=len(session.threats detected),
                exploit_blocks="\n".join(all_blocks)
            )
            p = out / "scripts" / "master_scan.py"
            p.write_text(master, encoding="utf-8")
            generated["master_scan.py"] = str(p)

        return generated

    def _render_html(self, session: ScanSession, executive_summary: str) -> str:
        ctx    = session.context
        counts = {s: 0 for s in ["Critical","High","Medium","Low","Informational"]}
        for f in session.threats detected:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        tmpl = Template(HTML_TEMPLATE)
        return tmpl.render(
            session=session,
            ctx=ctx,
            threats detected=session.threats detected,
            counts=counts,
            executive_summary=executive_summary,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        )

    def _build_json(self, session: ScanSession, executive_summary: str) -> dict:
        ctx    = session.context
        counts = {s: 0 for s in ["Critical","High","Medium","Low","Informational"]}
        for f in session.threats detected:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        return {
            "meta": {
                "session_name":    session.session_name,
                "target_url":      session.config.target_url,
                "status":          session.status,
                "generated_at":    datetime.utcnow().isoformat(),
                "total_threats detected":  len(session.threats detected),
                "severity_counts": counts,
                "executive_summary": executive_summary,
            },
            "context": {
                "backend_language":      ctx.backend_language if ctx else "",
                "database_type":         ctx.database_type    if ctx else "",
                "waf_detected":          ctx.waf_detected     if ctx else "",
                "spa_detected":          ctx.spa_detected     if ctx else False,
                "fingerprint_confidence":ctx.fingerprint_confidence if ctx else "",
            },
            "threats detected": [
                {
                    "title":              f.title,
                    "attack_type":        f.attack_type.value,
                    "severity":           f.severity.value,
                    "cvss_score":         f.cvss_score,
                    "cwe_id":             f.cwe_id,
                    "target_url":         f.target_url,
                    "vulnerable_param":   f.vulnerable_param,
                    "payload_used":       f.payload_used,
                    "raw_request":        f.raw_request,
                    "raw_response":       f.raw_response[:500],
                    "detection_method":   f.detection_method.value,
                    "confidence":         f.confidence.value,
                    "ai_escalated":       f.ai_escalated,
                    "script_formats":     f.script_formats,
                    "reproduction_steps": f.reproduction_steps,
                    "remediation_advice": f.remediation_advice,
                    "notion_id":          f.notion_id,
                }
                for f in session.threats detected
            ],
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _append_to_master(finding, script_text, xss_blocks, sqli_blocks, cmdi_blocks):
    func_name = f"exploit_{finding.attack_type.value.replace(' ','_').replace('-','_').lower()}"
    block = f"""
    # ── {finding.title} ──
    # Severity: {finding.severity.value} | CVSS: {finding.cvss_score} | {finding.cwe_id}
    try:
        resp = requests.get({repr(finding.target_url)},
                            params={{{repr(finding.vulnerable_param)}: {repr(finding.payload_used)}}},
                            timeout=15)
        results.append({{"finding": {repr(finding.title)}, "status": resp.status_code}})
        print(f"[✓] {finding.title} — status {{resp.status_code}}")
    except Exception as e:
        print(f"[✗] {finding.title} — {{e}}")
"""
    if "XSS" in finding.attack_type.value:
        xss_blocks.append(block)
    elif "SQLi" in finding.attack_type.value:
        sqli_blocks.append(block)
    else:
        cmdi_blocks.append(block)


def _build_module_script(module: str, session: ScanSession, blocks: list) -> str:
    return f"""#!/usr/bin/env python3
\"\"\"
WTSA — {module.upper()} Exploit Module
Session: {session.session_name}
Target:  {session.config.target_url}

LEGAL DISCLAIMER: For authorised security testing only.
Unauthorised use is illegal.
\"\"\"

import requests

TARGET = {repr(session.config.target_url)}

def run():
    results = []
{"".join(blocks)}
    return results

if __name__ == "__main__":
    run()
"""
