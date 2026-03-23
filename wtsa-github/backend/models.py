"""
WTSA — Core Models
All shared data structures used across the engine.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class AttackType(str, Enum):
    XSS_REFLECTED  = "XSS - Reflected"
    XSS_STORED     = "XSS - Stored"
    XSS_DOM        = "XSS - DOM"
    SQLI_CLASSIC   = "SQLi - Classic"
    SQLI_BLIND_BOOL= "SQLi - Blind Boolean"
    SQLI_BLIND_TIME= "SQLi - Blind Time"
    CMDI           = "CMDi"
    CSRF           = "CSRF"
    SSRF           = "SSRF"
    XXE            = "XXE"


class Severity(str, Enum):
    CRITICAL      = "Critical"
    HIGH          = "High"
    MEDIUM        = "Medium"
    LOW           = "Low"
    INFORMATIONAL = "Informational"


class SignalLevel(str, Enum):
    NONE   = "none"
    WEAK   = "weak"
    STRONG = "strong"


class AuthMethod(str, Enum):
    COOKIE        = "Cookie/Token"
    AUTO_LOGIN    = "Auto-Login"
    SESSION_REPLAY= "Session Replay"
    NONE          = "None"


class DetectionMethod(str, Enum):
    DOM_DIFF       = "DOM Diff"
    ERROR_PATTERN  = "Error Pattern"
    TIME_DELTA     = "Time Delta"
    MANUAL_CONFIRM = "Manual Confirm"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY    = "Likely"
    SUSPECTED = "Suspected"


class PayloadTier(str, Enum):
    TIER1 = "Tier 1 - Static"
    TIER2 = "Tier 2 - Static"
    TIER3 = "Tier 3 - Static"
    AI    = "AI Generated"


# ─────────────────────────────────────────────
# Target Context — built by fingerprinter
# ─────────────────────────────────────────────

@dataclass
class TargetContext:
    url:                  str
    backend_language:     str  = "Unknown"
    database_type:        str  = "Unknown"
    waf_detected:         str  = "None"
    spa_detected:         bool = False
    auth_required:        bool = False
    forms_found:          int  = 0
    inputs_found:         int  = 0
    reflection_points:    list[str] = field(default_factory=list)
    response_headers:     dict = field(default_factory=dict)
    error_signatures:     list[str] = field(default_factory=list)
    fingerprint_confidence: str = "Low"

    def to_prompt_summary(self) -> str:
        return (
            f"Target: {self.url}\n"
            f"Backend: {self.backend_language}\n"
            f"Database: {self.database_type}\n"
            f"WAF: {self.waf_detected}\n"
            f"SPA: {self.spa_detected}\n"
            f"Forms: {self.forms_found}, Inputs: {self.inputs_found}\n"
            f"Reflection points: {', '.join(self.reflection_points) or 'None found'}\n"
            f"Error signatures: {', '.join(self.error_signatures) or 'None'}\n"
            f"Fingerprint confidence: {self.fingerprint_confidence}"
        )


# ─────────────────────────────────────────────
# Discovered Input — from crawler
# ─────────────────────────────────────────────

@dataclass
class DiscoveredInput:
    url:        str
    param_name: str
    input_type: str   # "query", "form", "header", "cookie", "json_body"
    method:     str   = "GET"
    form_action: str  = ""
    reflects:   bool  = False
    context:    str   = ""   # surrounding HTML context for reflection point


# ─────────────────────────────────────────────
# Payload
# ─────────────────────────────────────────────

@dataclass
class Payload:
    name:         str
    string:       str
    attack_type:  AttackType
    tier:         PayloadTier
    source:       str          = "Static Library"
    target_stack: list[str]    = field(default_factory=lambda: ["Any"])
    target_db:    list[str]    = field(default_factory=lambda: ["Any"])
    waf_safe:     bool         = False
    encoding:     str          = "None"
    context_notes: str         = ""
    notion_id:    Optional[str]= None


# ─────────────────────────────────────────────
# Signal — returned by analyser
# ─────────────────────────────────────────────

@dataclass
class Signal:
    level:            SignalLevel
    detection_method: DetectionMethod
    evidence:         str   = ""
    time_delta:       float = 0.0
    response_diff:    int   = 0   # byte difference vs baseline


# ─────────────────────────────────────────────
# Finding — a confirmed or suspected vulnerability
# ─────────────────────────────────────────────

@dataclass
class Finding:
    title:             str
    attack_type:       AttackType
    severity:          Severity
    target_url:        str
    vulnerable_param:  str
    payload_used:      str
    raw_request:       str
    raw_response:      str
    detection_method:  DetectionMethod
    confidence:        Confidence
    cvss_score:        float = 0.0
    cwe_id:            str   = ""
    script_formats:    list[str] = field(default_factory=list)
    reproduction_steps:str  = ""
    remediation_advice:str  = ""
    ai_escalated:      bool = False
    notion_id:         Optional[str] = None


# ─────────────────────────────────────────────
# Scan Config — from UI
# ─────────────────────────────────────────────

@dataclass
class ScanConfig:
    target_url:     str
    modules:        list[str] = field(default_factory=lambda: ["XSS", "SQLi", "CMDi"])
    auth_method:    AuthMethod = AuthMethod.NONE
    auth_cookie:    str        = ""
    login_url:      str        = ""
    login_user:     str        = ""
    login_pass:     str        = ""
    har_path:       str        = ""
    scope_domains:  list[str]  = field(default_factory=list)
    max_depth:      int        = 5
    rate_limit:     int        = 10
    timing_threshold: float    = 4.0


# ─────────────────────────────────────────────
# Scan Session — tracks a full scan run
# ─────────────────────────────────────────────

@dataclass
class ScanSession:
    session_name:  str
    config:        ScanConfig
    scan_id:       str   = ""
    notion_id:     Optional[str] = None
    context:       Optional[TargetContext] = None
    inputs:        list[DiscoveredInput]   = field(default_factory=list)
    threats detected:      list[Finding]           = field(default_factory=list)
    status:        str   = "Queued"
