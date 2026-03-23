"""
WTSA — Notion Client
Handles all reads and writes to the four Notion databases.
"""

import os
import json
from typing import Optional
from notion_client import Client
from .models import (
    ScanSession, TargetContext, Finding, Payload,
    AttackType, Severity, DetectionMethod, Confidence, PayloadTier
)


class NotionClient:
    def __init__(self):
        self.client = Client(auth=os.environ["NOTION_API_KEY"])
        self.scan_db    = os.environ["NOTION_SCAN_SESSIONS_DB"]
        self.vuln_db    = os.environ["NOTION_VULN_REPORTS_DB"]
        self.payload_db = os.environ["NOTION_PAYLOAD_LIBRARY_DB"]
        self.recon_db   = os.environ["NOTION_RECON_DB"]

    # ── Scan Sessions ────────────────────────────────

    def create_scan_session(self, session: ScanSession) -> str:
        resp = self.client.pages.create(
            parent={"database_id": self.scan_db},
            properties={
                "Session Name": {"title": [{"text": {"content": session.session_name}}]},
                "Target URL":   {"url": session.config.target_url},
                "Status":       {"select": {"name": "Running"}},
                "Auth Method":  {"multi_select": [{"name": session.config.auth_method.value}]},
                "Modules Enabled": {"multi_select": [{"name": m} for m in session.config.modules]},
                "Total Threats Detected": {"number": 0},
                "Critical": {"number": 0},
                "High":     {"number": 0},
                "Medium":   {"number": 0},
                "Low":      {"number": 0},
            }
        )
        return resp["id"]

    def update_scan_session(self, notion_id: str, session: ScanSession):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in session.threats detected:
            if f.severity.value in counts:
                counts[f.severity.value] += 1

        self.client.pages.update(
            page_id=notion_id,
            properties={
                "Status":         {"select": {"name": session.status}},
                "Total Threats Detected": {"number": len(session.threats detected)},
                "Critical": {"number": counts["Critical"]},
                "High":     {"number": counts["High"]},
                "Medium":   {"number": counts["Medium"]},
                "Low":      {"number": counts["Low"]},
            }
        )

    # ── Threat Reports ────────────────────────

    def create_finding(self, finding: Finding) -> str:
        props = {
            "Finding Title":    {"title": [{"text": {"content": finding.title}}]},
            "Vulnerability Type": {"select": {"name": finding.attack_type.value}},
            "Severity":         {"select": {"name": finding.severity.value}},
            "CVSS Score":       {"number": finding.cvss_score},
            "CWE ID":           {"rich_text": [{"text": {"content": finding.cwe_id}}]},
            "Target URL":       {"url": finding.target_url},
            "Vulnerable Parameter": {"rich_text": [{"text": {"content": finding.vulnerable_param}}]},
            "Payload Used":     {"rich_text": [{"text": {"content": finding.payload_used[:1900]}}]},
            "Raw Request":      {"rich_text": [{"text": {"content": finding.raw_request[:1900]}}]},
            "Raw Response":     {"rich_text": [{"text": {"content": finding.raw_response[:1900]}}]},
            "Detection Method": {"select": {"name": finding.detection_method.value}},
            "Confidence":       {"select": {"name": finding.confidence.value}},
            "Script Formats":   {"multi_select": [{"name": s} for s in finding.script_formats]},
            "Remediation Status": {"select": {"name": "Open"}},
            "AI Escalated":     {"checkbox": finding.ai_escalated},
            "Reproduction Steps": {"rich_text": [{"text": {"content": finding.reproduction_steps[:1900]}}]},
            "Remediation Advice": {"rich_text": [{"text": {"content": finding.remediation_advice[:1900]}}]},
        }
        resp = self.client.pages.create(
            parent={"database_id": self.vuln_db},
            properties=props
        )
        return resp["id"]

    # ── Detection Signatures ──────────────────────────────

    def fetch_payloads(self, attack_type: Optional[str] = None,
                       waf_safe: Optional[bool] = None,
                       tier: Optional[str] = None) -> list[dict]:
        filters = []
        if attack_type:
            filters.append({"property": "Attack Type", "select": {"equals": attack_type}})
        if waf_safe is not None:
            filters.append({"property": "WAF Safe", "checkbox": {"equals": waf_safe}})
        if tier:
            filters.append({"property": "Tier", "select": {"equals": tier}})

        query = {"database_id": self.payload_db}
        if filters:
            query["filter"] = {"and": filters} if len(filters) > 1 else filters[0]

        results = []
        resp = self.client.databases.query(**query)
        results.extend(resp["results"])
        while resp.get("has_more"):
            resp = self.client.databases.query(**query, start_cursor=resp["next_cursor"])
            results.extend(resp["results"])

        payloads = []
        for r in results:
            props = r["properties"]
            payloads.append({
                "id":      r["id"],
                "name":    props["Payload Name"]["title"][0]["text"]["content"] if props["Payload Name"]["title"] else "",
                "string":  props["Payload String"]["rich_text"][0]["text"]["content"] if props["Payload String"]["rich_text"] else "",
                "tier":    props["Tier"]["select"]["name"] if props["Tier"]["select"] else "",
                "waf_safe": props["WAF Safe"]["checkbox"],
                "encoding": props["Encoding"]["select"]["name"] if props["Encoding"]["select"] else "None",
                "context_notes": props["Context Notes"]["rich_text"][0]["text"]["content"] if props["Context Notes"]["rich_text"] else "",
            })
        return payloads

    def save_ai_payload(self, payload: Payload) -> str:
        resp = self.client.pages.create(
            parent={"database_id": self.payload_db},
            properties={
                "Payload Name":   {"title": [{"text": {"content": payload.name}}]},
                "Payload String": {"rich_text": [{"text": {"content": payload.string}}]},
                "Attack Type":    {"select": {"name": payload.attack_type.value.split(" - ")[0]}},
                "Tier":           {"select": {"name": "AI Generated"}},
                "Source":         {"select": {"name": "Claude Generated"}},
                "WAF Safe":       {"checkbox": payload.waf_safe},
                "Encoding":       {"select": {"name": payload.encoding}},
                "Context Notes":  {"rich_text": [{"text": {"content": payload.context_notes}}]},
                "Times Used":     {"number": 1},
                "Times Confirmed":{"number": 0},
            }
        )
        return resp["id"]

    def increment_payload_stats(self, notion_id: str, confirmed: bool = False):
        page = self.client.pages.retrieve(page_id=notion_id)
        props = page["properties"]
        used = props["Times Used"]["number"] or 0
        conf = props["Times Confirmed"]["number"] or 0
        updates = {"Times Used": {"number": used + 1}}
        if confirmed:
            updates["Times Confirmed"] = {"number": conf + 1}
        self.client.pages.update(page_id=notion_id, properties=updates)

    # ── Target Profiles ─────────────────────────

    def save_recon(self, session_name: str, ctx: TargetContext) -> str:
        resp = self.client.pages.create(
            parent={"database_id": self.recon_db},
            properties={
                "Recon Name":    {"title": [{"text": {"content": f"Recon — {session_name}"}}]},
                "Target URL":    {"url": ctx.url},
                "Backend Language": {"select": {"name": ctx.backend_language}},
                "Database Type": {"select": {"name": ctx.database_type}},
                "WAF Detected":  {"select": {"name": ctx.waf_detected}},
                "SPA Detected":  {"checkbox": ctx.spa_detected},
                "Auth Required": {"checkbox": ctx.auth_required},
                "Forms Found":   {"number": ctx.forms_found},
                "Inputs Found":  {"number": ctx.inputs_found},
                "Reflection Points": {"rich_text": [{"text": {"content": "\n".join(ctx.reflection_points)}}]},
                "Response Headers":  {"rich_text": [{"text": {"content": json.dumps(ctx.response_headers, indent=2)[:1900]}}]},
                "Error Signatures":  {"rich_text": [{"text": {"content": "\n".join(ctx.error_signatures)}}]},
                "Fingerprint Confidence": {"select": {"name": ctx.fingerprint_confidence}},
            }
        )
        return resp["id"]
