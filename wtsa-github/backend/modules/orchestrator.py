"""
WTSA — Claude Orchestrator
Uses the Anthropic API for three tasks:
  A. Scan strategy planning (reads TargetContext, outputs ScanStrategy)
  B. Mid-scan escalation (decides tier upgrades or writes custom payloads)
  C. Report generation (executive summary, per-finding analysis, remediation)
"""

import os
import json
import anthropic
from typing import Optional, Callable
from ..models import (
    TargetContext, Finding, Payload, Signal, DiscoveredInput,
    AttackType, SignalLevel, PayloadTier, Severity, Confidence
)


MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5")


class ScanStrategy:
    def __init__(self, data: dict):
        self.priority_modules:    list[str] = data.get("priority_modules", ["XSS", "SQLi", "CMDi"])
        self.start_tier:          int        = data.get("start_tier", 1)
        self.waf_bypass_mode:     bool       = data.get("waf_bypass_mode", False)
        self.timing_enabled:      bool       = data.get("timing_enabled", True)
        self.bool_blind_enabled:  bool       = data.get("bool_blind_enabled", True)
        self.reasoning:           str        = data.get("reasoning", "")


class Orchestrator:
    def __init__(self, log: Optional[Callable] = None):
        self.client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.log    = log or print

    # ── Phase A: Scan Strategy ───────────────────────

    async def plan_strategy(self, ctx: TargetContext,
                            enabled_modules: list[str]) -> ScanStrategy:
        self.log("[Orchestrator] Planning scan strategy...")

        prompt = f"""You are a security researcher planning a web vulnerability scan.
Based on the target fingerprint below, decide the optimal scan strategy.

{ctx.to_prompt_summary()}

Enabled scan modules: {', '.join(enabled_modules)}

Respond with a JSON object (no markdown, no preamble) with these fields:
{{
  "priority_modules": ["list of modules in priority order from the enabled ones"],
  "start_tier": 1,
  "waf_bypass_mode": false,
  "timing_enabled": true,
  "bool_blind_enabled": true,
  "reasoning": "one sentence explaining your strategy"
}}

Rules:
- If WAF is detected, set waf_bypass_mode=true and start_tier=2
- If MySQL or PostgreSQL detected, timing_enabled and bool_blind_enabled should be true
- If SQLi is enabled, always prioritise it first when a DB is detected
- If no DB detected, prioritise XSS first
- Keep reasoning concise (one sentence)
"""
        resp = self.client.messages.create(
            model=MODEL, max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text.strip()
        try:
            data = json.loads(raw)
        except Exception:
            self.log(f"[Orchestrator] Strategy parse error, using defaults. Raw: {raw[:200]}")
            data = {}

        strategy = ScanStrategy(data)
        self.log(f"[Orchestrator] Strategy: {strategy.reasoning}")
        return strategy

    # ── Phase B: Escalation Decision ────────────────

    async def escalation_decision(self, signal: Signal,
                                  inp: DiscoveredInput,
                                  ctx: TargetContext,
                                  attack_type: AttackType,
                                  current_tier: int) -> dict:
        """
        Returns dict with keys:
          action: "skip" | "tier_up" | "custom_payload"
          next_tier: int (if tier_up)
          custom_payload: str (if custom_payload)
          reasoning: str
        """
        if signal.level == SignalLevel.NONE:
            return {"action": "skip", "reasoning": "No signal detected"}

        self.log(f"[Orchestrator] Escalating: {signal.level.value} signal on {inp.param_name}")

        prompt = f"""You are a security researcher doing mid-scan escalation.

Target context:
{ctx.to_prompt_summary()}

Input being tested:
- URL: {inp.url}
- Parameter: {inp.param_name}
- Input type: {inp.input_type}
- Reflection context: {inp.context or 'N/A'}

Attack type: {attack_type.value}
Current payload tier: {current_tier}
Signal level: {signal.level.value}
Signal evidence: {signal.evidence}
Time delta: {signal.time_delta:.2f}s

Decide what to do next. Respond with JSON only (no markdown):
{{
  "action": "tier_up" or "custom_payload" or "skip",
  "next_tier": 2,
  "custom_payload": "the exact payload string to try next, or empty string",
  "reasoning": "one sentence"
}}

Rules:
- If signal is WEAK and current_tier < 3, action should be "tier_up"
- If signal is STRONG OR current_tier is already 3, action should be "custom_payload"
- For custom_payload: craft a payload specifically for this input context, stack ({ctx.backend_language}), and DB ({ctx.database_type})
- For XSS custom payloads: consider the reflection context and escape accordingly
- For SQLi custom payloads: use DB-specific syntax for {ctx.database_type}
- For CMDi: try OS-specific commands for what appears to be the backend OS
- Keep custom payload concise and targeted
"""
        resp = self.client.messages.create(
            model=MODEL, max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text.strip()
        try:
            return json.loads(raw)
        except Exception:
            self.log(f"[Orchestrator] Escalation parse error: {raw[:200]}")
            return {"action": "tier_up", "next_tier": min(current_tier + 1, 3),
                    "custom_payload": "", "reasoning": "parse fallback"}

    # ── Phase B: Write Custom Payload ────────────────

    async def write_custom_payload(self, inp: DiscoveredInput,
                                   ctx: TargetContext,
                                   attack_type: AttackType,
                                   signal: Signal) -> Payload:
        self.log(f"[Orchestrator] Writing custom payload for {inp.param_name}...")

        prompt = f"""You are an expert threat scaner. Write a single, precise attack payload.

Target:
- URL: {inp.url}
- Parameter: {inp.param_name}
- Reflection context in HTML: {inp.context or 'unknown'}
- Backend: {ctx.backend_language}
- Database: {ctx.database_type}
- WAF: {ctx.waf_detected}
- Attack type: {attack_type.value}
- Signal evidence so far: {signal.evidence}

Respond with JSON only:
{{
  "payload": "the exact payload string",
  "name": "short descriptive name",
  "encoding": "None or URL Encoded or HTML Encoded or Base64 or Unicode",
  "waf_safe": true or false,
  "reasoning": "one sentence explaining why this payload"
}}

Requirements:
- The payload should be tailored exactly to this context
- If WAF is present ({ctx.waf_detected}), use bypass techniques
- For XSS: escape out of the reflection context properly
- For SQLi: use {ctx.database_type}-specific syntax
- For CMDi: use appropriate OS operators
- Be precise — this is for a CTF/authorised security scan only
"""
        resp = self.client.messages.create(
            model=MODEL, max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text.strip()
        try:
            data = json.loads(raw)
        except Exception:
            data = {"payload": signal.evidence, "name": "AI fallback",
                    "encoding": "None", "waf_safe": False, "reasoning": "fallback"}

        return Payload(
            name=data.get("name", "AI Custom Payload"),
            string=data.get("payload", ""),
            attack_type=attack_type,
            tier=PayloadTier.AI,
            source="Claude Generated",
            waf_safe=data.get("waf_safe", False),
            encoding=data.get("encoding", "None"),
            context_notes=f"{data.get('reasoning','')} | Input: {inp.param_name} @ {inp.url}"
        )

    # ── Phase C: Report Generation ───────────────────

    async def generate_report_section(self, finding: Finding,
                                      ctx: TargetContext) -> dict:
        """Generate reproduction steps and remediation for a single finding."""
        prompt = f"""You are writing a professional threat scan report.

Finding: {finding.title}
Type: {finding.attack_type.value}
Severity: {finding.severity.value}
URL: {finding.target_url}
Parameter: {finding.vulnerable_param}
Payload: {finding.payload_used}
Detection: {finding.detection_method.value}
Evidence: {finding.raw_response[:500]}
Backend: {ctx.backend_language}
Database: {ctx.database_type}

Respond with JSON only:
{{
  "reproduction_steps": "numbered step-by-step guide to reproduce this vulnerability",
  "remediation_advice": "specific remediation code snippet and explanation in {ctx.backend_language}"
}}
"""
        resp = self.client.messages.create(
            model=MODEL, max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text.strip()
        try:
            return json.loads(raw)
        except Exception:
            return {
                "reproduction_steps": f"1. Navigate to {finding.target_url}\n2. Inject payload '{finding.payload_used}' into '{finding.vulnerable_param}'\n3. Observe response.",
                "remediation_advice": "Validate and sanitise all user input. Use parameterised queries for database operations."
            }

    async def generate_executive_summary(self, threats detected: list[Finding],
                                         ctx: TargetContext,
                                         session_name: str) -> str:
        counts = {}
        for f in threats detected:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        prompt = f"""Write a concise executive summary for a threat scan report.

Target: {ctx.url}
Session: {session_name}
Stack: {ctx.backend_language} + {ctx.database_type}
WAF: {ctx.waf_detected}

Threats Detected:
{chr(10).join(f'- {f.title} ({f.severity.value}, {f.attack_type.value})' for f in threats detected[:20])}

Severity breakdown: {json.dumps(counts)}
Total threats detected: {len(threats detected)}

Write a 2-3 paragraph executive summary suitable for a bug bounty or CTF report.
Plain text, no JSON, no markdown headers.
"""
        resp = self.client.messages.create(
            model=MODEL, max_tokens=600,
            messages=[{"role": "user", "content": prompt}]
        )
        return resp.content[0].text.strip()

    # ── Script generation ────────────────────────────

    async def generate_exploit_scripts(self, finding: Finding,
                                       ctx: TargetContext) -> dict[str, str]:
        """Generate exploit scripts in all formats for a finding."""
        prompt = f"""Generate exploit scripts for this confirmed vulnerability.

Finding: {finding.title}
Type: {finding.attack_type.value}
URL: {finding.target_url}
Parameter: {finding.vulnerable_param}
Payload: {finding.payload_used}
Method: {finding.raw_request.split()[0] if finding.raw_request else 'GET'}
Backend: {ctx.backend_language}
Is SPA: {ctx.spa_detected}

Respond with JSON only (no markdown fences):
{{
  "requests_py": "full annotated Python requests script",
  "playwright_py": "full annotated Python Playwright script (only if SPA)",
  "curl_sh": "one-liner curl command",
  "burp_txt": "raw HTTP request in Burp format"
}}

Requirements:
- Add a legal disclaimer comment at top of each script
- requests_py must be a complete runnable Python script with imports
- playwright_py only needed if is_spa is true
- curl_sh must be a single shell command
- burp_txt must be valid raw HTTP format importable to Burp Repeater
- All scripts must include inline comments explaining each step
"""
        resp = self.client.messages.create(
            model=MODEL, max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text.strip()
        # Strip markdown code fences if present
        raw = raw.replace("```json", "").replace("```", "").strip()
        try:
            return json.loads(raw)
        except Exception:
            return {
                "requests_py": f"# Legal disclaimer: Authorised use only\nimport requests\nresp = requests.get('{finding.target_url}', params={{'{finding.vulnerable_param}': '{finding.payload_used}'}})\nprint(resp.text)",
                "playwright_py": "",
                "curl_sh": f"curl -G '{finding.target_url}' --data-urlencode '{finding.vulnerable_param}={finding.payload_used}'",
                "burp_txt": f"GET {finding.target_url}?{finding.vulnerable_param}={finding.payload_used} HTTP/1.1\nHost: {finding.target_url.split('/')[2]}\n"
            }
