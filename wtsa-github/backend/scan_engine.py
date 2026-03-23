"""
WTSA — Scan Engine
Coordinates all modules: fingerprint → crawl → attack → analyse → report.
Emits log messages via an async callback for real-time UI streaming.
"""

import asyncio
import uuid
from datetime import datetime
from typing import Callable, Optional
from .modules.fingerprinter import Fingerprinter
from .modules.crawler import Crawler
from .modules.payload_library import (
    get_payloads_for_context, get_timing_payload,
    get_bool_blind_pairs, SQLI_TIME_BASED
)
from .modules.probe engine import Probe Engine
from .modules.analyser import Analyser
from .modules.orchestrator import Orchestrator
from .notion_client import NotionClient
from .models import (
    ScanConfig, ScanSession, TargetContext, DiscoveredInput,
    Finding, Payload, AttackType, Severity, Confidence,
    SignalLevel, DetectionMethod
)


class ScanEngine:
    def __init__(self, config: ScanConfig, log: Callable):
        self.config      = config
        self.log         = log
        self.session     = ScanSession(
            session_name=f"Scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            config=config
        )
        self.notion      = NotionClient()
        self.orchestrator= Orchestrator(log=log)
        self.analyser    = Analyser(timing_threshold=config.timing_threshold)
        self.probe engine    = Probe Engine(config, log=log)
        self._scripts    = {}  # finding_id -> scripts dict

    # ── Entry point ──────────────────────────────────

    async def run(self) -> ScanSession:
        self.session.status = "Running"
        session_notion_id = self.notion.create_scan_session(self.session)
        self.session.notion_id = session_notion_id

        try:
            # Phase 1: Fingerprint
            self.log("━━━ Phase 1: Fingerprinting ━━━")
            await self._phase_fingerprint()

            # Phase 2: Crawl
            self.log("━━━ Phase 2: Crawling ━━━")
            await self._phase_crawl()

            # Phase 3: Strategy planning
            self.log("━━━ Phase 3: Planning Strategy ━━━")
            strategy = await self.orchestrator.plan_strategy(
                self.session.context, self.config.modules
            )
            self.log(f"[Strategy] {strategy.reasoning}")

            # Phase 4: Attack
            self.log("━━━ Phase 4: Attacking ━━━")
            await self._phase_attack(strategy)

            # Phase 5: Report generation
            self.log("━━━ Phase 5: Generating Report ━━━")
            await self._phase_report()

            self.session.status = "Completed"

        except Exception as e:
            self.log(f"[Engine] Fatal error: {e}")
            self.session.status = "Failed"
            import traceback
            self.log(traceback.format_exc())

        finally:
            self.notion.update_scan_session(session_notion_id, self.session)

        self.log(f"[Engine] Scan complete. {len(self.session.threats detected)} threats detected.")
        return self.session

    # ── Phase 1: Fingerprint ─────────────────────────

    async def _phase_fingerprint(self):
        fp = Fingerprinter(
            cookies=self._parse_cookies(),
            rate_limit=self.config.rate_limit
        )
        ctx = await fp.fingerprint(self.config.target_url)
        self.session.context = ctx

        self.log(f"[Fingerprint] Backend: {ctx.backend_language}")
        self.log(f"[Fingerprint] Database: {ctx.database_type}")
        self.log(f"[Fingerprint] WAF: {ctx.waf_detected}")
        self.log(f"[Fingerprint] SPA: {ctx.spa_detected}")
        self.log(f"[Fingerprint] Confidence: {ctx.fingerprint_confidence}")

        # Save to Notion
        recon_id = self.notion.save_recon(self.session.session_name, ctx)
        self.log(f"[Fingerprint] Saved recon to Notion: {recon_id[:8]}...")

    # ── Phase 2: Crawl ───────────────────────────────

    async def _phase_crawl(self):
        crawler = Crawler(self.config, log=self.log)
        inputs  = await crawler.crawl()

        # Map reflection points
        fp = Fingerprinter(cookies=self._parse_cookies(),
                           rate_limit=self.config.rate_limit)
        reflection_points = await fp.map_reflection_points(
            self.config.target_url, inputs
        )
        if self.session.context:
            self.session.context.reflection_points = reflection_points
            self.session.context.forms_found  = sum(1 for i in inputs if i.input_type == "form")
            self.session.context.inputs_found = len(inputs)

        self.session.inputs = inputs
        self.log(f"[Crawl] {len(inputs)} inputs found, {len(reflection_points)} reflection points")

    # ── Phase 4: Attack ──────────────────────────────

    async def _phase_attack(self, strategy):
        ctx = self.session.context

        for module in strategy.priority_modules:
            if module not in self.config.modules:
                continue
            self.log(f"[Attack] Starting module: {module}")

            for inp in self.session.inputs:
                if module == "XSS":
                    await self._attack_xss(inp, ctx, strategy)
                elif module == "SQLi":
                    await self._attack_sqli(inp, ctx, strategy)
                elif module == "CMDi":
                    await self._attack_cmdi(inp, ctx, strategy)

    # ── XSS Attack ───────────────────────────────────

    async def _attack_xss(self, inp: DiscoveredInput,
                          ctx: TargetContext, strategy):
        baseline = await self.probe engine.get_baseline(inp)
        start_tier = strategy.start_tier

        for tier in range(start_tier, 4):
            attack_type = AttackType.XSS_REFLECTED
            payloads = get_payloads_for_context(
                "XSS", tier,
                waf_detected=ctx.waf_detected != "None"
            )
            if not payloads:
                continue

            results = await self.probe engine.inject_batch(inp, payloads)

            for result in results:
                signal = self.analyser.analyse_xss(result, baseline)

                if signal.level == SignalLevel.NONE:
                    continue

                self.log(f"[XSS] {signal.level.value} signal on {inp.param_name} — {signal.evidence}")

                if signal.level == SignalLevel.STRONG:
                    await self._record_finding(
                        inp=inp, ctx=ctx, result=result, signal=signal,
                        attack_type=attack_type, ai_escalated=False
                    )
                    return  # Move to next input

                # Escalate
                decision = await self.orchestrator.escalation_decision(
                    signal, inp, ctx, attack_type, tier
                )
                if decision["action"] == "custom_payload":
                    custom = await self.orchestrator.write_custom_payload(
                        inp, ctx, attack_type, signal
                    )
                    self.notion.save_ai_payload(custom)
                    custom_result = await self.probe engine.inject(inp, custom)
                    custom_signal = self.analyser.analyse_xss(custom_result, baseline)
                    if custom_signal.level != SignalLevel.NONE:
                        await self._record_finding(
                            inp=inp, ctx=ctx, result=custom_result,
                            signal=custom_signal, attack_type=attack_type,
                            ai_escalated=True
                        )
                    return

    # ── SQLi Attack ──────────────────────────────────

    async def _attack_sqli(self, inp: DiscoveredInput,
                           ctx: TargetContext, strategy):
        baseline = await self.probe engine.get_baseline(inp)
        db = ctx.database_type if ctx else "Any"

        # Classic + bool blind
        for tier in range(strategy.start_tier, 4):
            payloads = get_payloads_for_context("SQLi", tier, db_type=db)
            results  = await self.probe engine.inject_batch(inp, payloads[:10])

            for result in results:
                signal = self.analyser.analyse_sqli(
                    result, baseline, AttackType.SQLI_CLASSIC
                )
                if signal.level == SignalLevel.NONE:
                    continue

                self.log(f"[SQLi] {signal.level.value} signal on {inp.param_name}")

                if signal.level == SignalLevel.STRONG:
                    await self._record_finding(
                        inp=inp, ctx=ctx, result=result, signal=signal,
                        attack_type=AttackType.SQLI_CLASSIC, ai_escalated=False
                    )
                    break

                # Escalate
                if strategy.timing_enabled:
                    await self._sqli_timing_probe(inp, ctx, baseline, db)
                return

        # Timing-based blind (always try if enabled)
        if strategy.timing_enabled:
            await self._sqli_timing_probe(inp, ctx, baseline, db)

    async def _sqli_timing_probe(self, inp, ctx, baseline, db):
        timing_str = get_timing_payload("SQLi", db_type=db, delay=5)
        if not timing_str:
            return
        timing_payload = Payload(
            name=f"SQLi Timing — {db}",
            string=timing_str,
            attack_type=AttackType.SQLI_BLIND_TIME,
            tier=PayloadTier.TIER2 if True else None
        )
        from .models import PayloadTier
        timing_payload.tier = PayloadTier.TIER2
        result = await self.probe engine.inject(inp, timing_payload)
        signal = self.analyser.analyse_sqli(result, baseline, AttackType.SQLI_BLIND_TIME)
        if signal.level != SignalLevel.NONE:
            self.log(f"[SQLi-Time] {signal.level.value} signal — {signal.evidence}")
            await self._record_finding(
                inp=inp, ctx=ctx, result=result, signal=signal,
                attack_type=AttackType.SQLI_BLIND_TIME, ai_escalated=False
            )

    # ── CMDi Attack ──────────────────────────────────

    async def _attack_cmdi(self, inp: DiscoveredInput,
                           ctx: TargetContext, strategy):
        baseline = await self.probe engine.get_baseline(inp)

        for tier in range(strategy.start_tier, 3):
            payloads = get_payloads_for_context("CMDi", tier)
            results  = await self.probe engine.inject_batch(inp, payloads[:8])

            for result in results:
                signal = self.analyser.analyse_cmdi(result, baseline)
                if signal.level == SignalLevel.NONE:
                    continue

                self.log(f"[CMDi] {signal.level.value} signal on {inp.param_name}")

                if signal.level == SignalLevel.STRONG:
                    await self._record_finding(
                        inp=inp, ctx=ctx, result=result, signal=signal,
                        attack_type=AttackType.CMDI, ai_escalated=False
                    )
                    return

        # Blind timing probe
        timing_str = get_timing_payload("CMDi", delay=5)
        timing_payload = Payload(
            name="CMDi Timing Blind",
            string=timing_str,
            attack_type=AttackType.CMDI,
            tier=None
        )
        from .models import PayloadTier
        timing_payload.tier = PayloadTier.TIER2
        result = await self.probe engine.inject(inp, timing_payload)
        signal = self.analyser.analyse_cmdi(result, baseline, blind_timing=True)
        if signal.level != SignalLevel.NONE:
            self.log(f"[CMDi-Time] {signal.level.value} signal — {signal.evidence}")
            await self._record_finding(
                inp=inp, ctx=ctx, result=result, signal=signal,
                attack_type=AttackType.CMDI, ai_escalated=False
            )

    # ── Record Finding ────────────────────────────────

    async def _record_finding(self, inp, ctx, result, signal,
                              attack_type, ai_escalated):
        conf_map = {
            SignalLevel.STRONG: Confidence.CONFIRMED,
            SignalLevel.WEAK:   Confidence.LIKELY,
        }
        confidence = conf_map.get(signal.level, Confidence.SUSPECTED)
        cvss, cwe = self.analyser.estimate_cvss(attack_type, confidence.value)
        severity  = _cvss_to_severity(cvss)

        # Generate report section
        finding = Finding(
            title=f"{attack_type.value} in {inp.param_name}",
            attack_type=attack_type,
            severity=severity,
            target_url=inp.url,
            vulnerable_param=inp.param_name,
            payload_used=result.payload.string,
            raw_request=result.raw_request,
            raw_response=result.raw_response,
            detection_method=signal.detection_method,
            confidence=confidence,
            cvss_score=cvss,
            cwe_id=cwe,
            ai_escalated=ai_escalated,
        )

        # Generate reproduction steps + remediation
        report_data = await self.orchestrator.generate_report_section(finding, ctx)
        finding.reproduction_steps = report_data.get("reproduction_steps", "")
        finding.remediation_advice = report_data.get("remediation_advice", "")

        # Generate scripts
        scripts = await self.orchestrator.generate_exploit_scripts(finding, ctx)
        self._scripts[id(finding)] = scripts
        finding.script_formats = [k for k, v in scripts.items() if v]

        # Save to Notion
        notion_id = self.notion.create_finding(finding)
        finding.notion_id = notion_id

        self.session.threats detected.append(finding)
        self.log(f"[Finding] ★ {finding.severity.value}: {finding.title} (CVSS {cvss})")

    # ── Phase 5: Report ──────────────────────────────

    async def _phase_report(self):
        if not self.session.threats detected:
            self.log("[Report] No threats detected to report.")
            return

        summary = await self.orchestrator.generate_executive_summary(
            self.session.threats detected,
            self.session.context,
            self.session.session_name
        )
        self.session.executive_summary = summary
        self.log("[Report] Executive summary generated.")

        # Generate output files
        from .report_generator import ReportGenerator
        rg = ReportGenerator(output_dir="scan_output")
        artefacts = rg.generate(self.session, self._scripts, summary)
        self.session.artefacts = artefacts
        self.log(f"[Report] {len(artefacts)} output files written.")
        for name, path in artefacts.items():
            self.log(f"[Report]   → {name}")

        # Update Notion session with final counts
        self.notion.update_scan_session(self.session.notion_id, self.session)

    # ── Helpers ──────────────────────────────────────

    def _parse_cookies(self) -> dict:
        cookies = {}
        if self.config.auth_cookie:
            for part in self.config.auth_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    cookies[k.strip()] = v.strip()
        return cookies

    def get_scripts(self) -> dict:
        return self._scripts


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0: return Severity.CRITICAL
    if score >= 7.0: return Severity.HIGH
    if score >= 4.0: return Severity.MEDIUM
    if score > 0:    return Severity.LOW
    return Severity.INFORMATIONAL
