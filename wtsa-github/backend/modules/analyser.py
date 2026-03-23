"""
WTSA — Analyser
Scores injection results using DOM diffing, error pattern matching,
and timing delta analysis. Returns Signal objects for the orchestrator.
"""

import re
from difflib import SequenceMatcher
from .probe engine import InjectionResult
from ..models import Signal, SignalLevel, DetectionMethod, AttackType


# ── XSS detection patterns (execution evidence) ───────────────────────────────

XSS_EXECUTION_PATTERNS = [
    r'<script[^>]*>.*?alert\(',
    r'onerror\s*=\s*["\']?alert',
    r'onload\s*=\s*["\']?alert',
    r'javascript:alert',
    r'<svg[^>]*onload',
    r'<img[^>]*onerror',
    r'<iframe[^>]*src\s*=\s*["\']?javascript',
]

# Patterns indicating the payload was reflected unescaped
XSS_REFLECTION_UNESCAPED = [
    r'<script>',
    r'<img\s+src\s*=\s*["\']?x["\']?\s+onerror',
    r'<svg\s+onload',
    r'onerror\s*=\s*alert',
    r'onload\s*=\s*alert',
]


# ── SQLi error pattern db ─────────────────────────────────────────────────────

SQLI_ERROR_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"mysql_fetch_array\(\)",
        r"mysql server version",
        r"supplied argument is not a valid mysql",
        r"column count doesn't match value count",
    ],
    "PostgreSQL": [
        r"pg_query\(\).*pg_last_error\(\)",
        r"postgresql.*error",
        r"error:\s+syntax error at or near",
        r"pg::syntaxerror",
        r"invalid input syntax for",
    ],
    "MSSQL": [
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
        r"sqlstate\[42000\]",
    ],
    "SQLite": [
        r"sqlite_error",
        r"sqlite3::exception",
        r"unrecognized token:",
        r"no such column:",
        r"no such table:",
    ],
    "Generic": [
        r"sql syntax",
        r"sql error",
        r"database error",
        r"warning.*sql",
        r"odbc.*driver.*error",
        r"jdbc.*error",
    ],
}


# ── CMDi patterns ─────────────────────────────────────────────────────────────

CMDI_OUTPUT_PATTERNS = [
    r"uid=\d+\(\w+\)",       # id / whoami Linux
    r"root:\w+:\d+:\d+:",    # /etc/passwd
    r"Volume Serial Number", # Windows dir
    r"\\Users\\",            # Windows path
    r"command not found",    # Blind indicator
    r"sh: .* not found",
]


class Analyser:
    def __init__(self, timing_threshold: float = 4.0):
        self.timing_threshold = timing_threshold

    # ── XSS Analysis ─────────────────────────────────

    def analyse_xss(self, result: InjectionResult,
                    baseline: InjectionResult) -> Signal:
        body    = result.body.lower()
        payload = result.payload.string.lower()

        # Check for unescaped reflection
        for pattern in XSS_REFLECTION_UNESCAPED:
            if re.search(pattern, result.body, re.IGNORECASE):
                return Signal(
                    level=SignalLevel.STRONG,
                    detection_method=DetectionMethod.DOM_DIFF,
                    evidence=f"Unescaped reflection: {pattern}"
                )

        # Check for execution evidence
        for pattern in XSS_EXECUTION_PATTERNS:
            if re.search(pattern, result.body, re.IGNORECASE):
                return Signal(
                    level=SignalLevel.STRONG,
                    detection_method=DetectionMethod.DOM_DIFF,
                    evidence=f"Execution evidence: {pattern}"
                )

        # DOM diff — check if the response changed significantly due to our payload
        diff_ratio = _dom_diff(baseline.body, result.body)
        if payload[:20] in result.body.lower():
            return Signal(
                level=SignalLevel.WEAK,
                detection_method=DetectionMethod.DOM_DIFF,
                evidence=f"Payload reflected (possibly escaped). Diff ratio: {diff_ratio:.2f}"
            )

        return Signal(level=SignalLevel.NONE,
                      detection_method=DetectionMethod.DOM_DIFF)

    # ── SQLi Analysis ─────────────────────────────────

    def analyse_sqli(self, result: InjectionResult,
                     baseline: InjectionResult,
                     attack_type: AttackType = AttackType.SQLI_CLASSIC) -> Signal:

        if attack_type == AttackType.SQLI_BLIND_TIME:
            return self._analyse_timing(result, baseline)

        if attack_type == AttackType.SQLI_BLIND_BOOL:
            return self._analyse_bool_blind(result, baseline)

        # Classic: error pattern matching
        body_lower = result.body.lower()
        for db, patterns in SQLI_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body_lower):
                    return Signal(
                        level=SignalLevel.STRONG,
                        detection_method=DetectionMethod.ERROR_PATTERN,
                        evidence=f"[{db}] error pattern: {pattern}"
                    )

        # Weak: response length significantly different from baseline
        diff = abs(len(result.body) - len(baseline.body))
        if diff > 200:
            return Signal(
                level=SignalLevel.WEAK,
                detection_method=DetectionMethod.ERROR_PATTERN,
                evidence=f"Response length diff: {diff} bytes",
                response_diff=diff
            )

        return Signal(level=SignalLevel.NONE,
                      detection_method=DetectionMethod.ERROR_PATTERN)

    # ── CMDi Analysis ────────────────────────────────

    def analyse_cmdi(self, result: InjectionResult,
                     baseline: InjectionResult,
                     blind_timing: bool = False) -> Signal:

        if blind_timing:
            return self._analyse_timing(result, baseline)

        for pattern in CMDI_OUTPUT_PATTERNS:
            if re.search(pattern, result.body, re.IGNORECASE):
                return Signal(
                    level=SignalLevel.STRONG,
                    detection_method=DetectionMethod.ERROR_PATTERN,
                    evidence=f"CMDi output: {pattern}"
                )

        return Signal(level=SignalLevel.NONE,
                      detection_method=DetectionMethod.ERROR_PATTERN)

    # ── Timing analysis ───────────────────────────────

    def _analyse_timing(self, result: InjectionResult,
                        baseline: InjectionResult) -> Signal:
        delta = result.elapsed - baseline.elapsed
        if delta >= self.timing_threshold:
            return Signal(
                level=SignalLevel.STRONG,
                detection_method=DetectionMethod.TIME_DELTA,
                evidence=f"Time delta: {delta:.2f}s (threshold: {self.timing_threshold}s)",
                time_delta=delta
            )
        if delta >= self.timing_threshold * 0.6:
            return Signal(
                level=SignalLevel.WEAK,
                detection_method=DetectionMethod.TIME_DELTA,
                evidence=f"Partial time delta: {delta:.2f}s",
                time_delta=delta
            )
        return Signal(level=SignalLevel.NONE,
                      detection_method=DetectionMethod.TIME_DELTA,
                      time_delta=delta)

    # ── Boolean blind ─────────────────────────────────

    def _analyse_bool_blind(self, result_true: InjectionResult,
                            result_false: InjectionResult) -> Signal:
        """
        For boolean blind, result_true is the true-condition response
        and result_false is the false-condition response (passed as baseline).
        """
        diff = abs(len(result_true.body) - len(result_false.body))
        ratio = _dom_diff(result_true.body, result_false.body)

        if diff > 100 or ratio < 0.85:
            return Signal(
                level=SignalLevel.STRONG,
                detection_method=DetectionMethod.ERROR_PATTERN,
                evidence=f"Boolean blind: responses differ by {diff} bytes (ratio {ratio:.2f})",
                response_diff=diff
            )
        return Signal(level=SignalLevel.NONE,
                      detection_method=DetectionMethod.ERROR_PATTERN)

    # ── CVSS helper ───────────────────────────────────

    @staticmethod
    def estimate_cvss(attack_type: AttackType, confidence: str) -> tuple[float, str]:
        """Returns (score, cwe_id)."""
        base_scores = {
            AttackType.XSS_REFLECTED:   (6.1,  "CWE-79"),
            AttackType.XSS_STORED:      (8.8,  "CWE-79"),
            AttackType.XSS_DOM:         (6.1,  "CWE-79"),
            AttackType.SQLI_CLASSIC:    (9.8,  "CWE-89"),
            AttackType.SQLI_BLIND_BOOL: (8.8,  "CWE-89"),
            AttackType.SQLI_BLIND_TIME: (7.5,  "CWE-89"),
            AttackType.CMDI:            (9.8,  "CWE-78"),
            AttackType.CSRF:            (6.5,  "CWE-352"),
            AttackType.SSRF:            (8.6,  "CWE-918"),
            AttackType.XXE:             (8.2,  "CWE-611"),
        }
        score, cwe = base_scores.get(attack_type, (5.0, "CWE-0"))
        if confidence == "Suspected":
            score = round(score * 0.7, 1)
        elif confidence == "Likely":
            score = round(score * 0.85, 1)
        return score, cwe


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dom_diff(a: str, b: str) -> float:
    """Returns similarity ratio between two response bodies."""
    return SequenceMatcher(None, a[:5000], b[:5000]).ratio()
