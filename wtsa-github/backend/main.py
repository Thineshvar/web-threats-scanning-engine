"""
WTSA — FastAPI Backend
REST + WebSocket server. Accepts scan config from UI,
runs the engine, and streams logs back in real time.
"""

import asyncio
import json
import os
from datetime import datetime
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

load_dotenv()

from .threat_scanner import ScanEngine
from .models import ScanConfig, AuthMethod, ScanSession

# ── Pydantic request/response models ────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url:       str
    modules:          list[str] = ["XSS", "SQLi", "CMDi"]
    auth_method:      str       = "None"
    auth_cookie:      str       = ""
    login_url:        str       = ""
    login_user:       str       = ""
    login_pass:       str       = ""
    scope_domains:    list[str] = []
    max_depth:        int       = 5
    rate_limit:       int       = 10
    timing_threshold: float     = 4.0


class ScanStatus(BaseModel):
    scan_id:    str
    status:     str
    threats detected:   int
    started_at: str


# ── In-memory scan registry ──────────────────────────────────────────────────

active_scans: dict[str, dict] = {}
scan_logs:    dict[str, list]  = {}


# ── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="WTSA — Web Threat Scanning App", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/scan/start")
async def start_scan(req: ScanRequest):
    """Start a new scan. Returns scan_id immediately."""
    import uuid
    scan_id = str(uuid.uuid4())[:8]

    config = ScanConfig(
        target_url=req.target_url,
        modules=req.modules,
        auth_method=AuthMethod(req.auth_method),
        auth_cookie=req.auth_cookie,
        login_url=req.login_url,
        login_user=req.login_user,
        login_pass=req.login_pass,
        scope_domains=req.scope_domains,
        max_depth=req.max_depth,
        rate_limit=req.rate_limit,
        timing_threshold=req.timing_threshold,
    )

    scan_logs[scan_id] = []
    active_scans[scan_id] = {
        "status": "starting",
        "started_at": datetime.utcnow().isoformat(),
        "threats detected": 0,
        "session": None,
    }

    # Run scan in background
    asyncio.create_task(_run_scan(scan_id, config))

    return {"scan_id": scan_id, "message": "Scan started. Connect to /ws/{scan_id} for live logs."}


@app.get("/scan/{scan_id}/status")
def scan_status(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    info = active_scans[scan_id]
    return ScanStatus(
        scan_id=scan_id,
        status=info["status"],
        threats detected=info["threats detected"],
        started_at=info["started_at"]
    )


@app.get("/scan/{scan_id}/threats detected")
def scan_threats detected(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    session: ScanSession = active_scans[scan_id].get("session")
    if not session:
        return {"threats detected": []}
    return {
        "threats detected": [
            {
                "title":          f.title,
                "severity":       f.severity.value,
                "type":           f.attack_type.value,
                "url":            f.target_url,
                "param":          f.vulnerable_param,
                "cvss":           f.cvss_score,
                "cwe":            f.cwe_id,
                "confidence":     f.confidence.value,
                "detection":      f.detection_method.value,
                "ai_escalated":   f.ai_escalated,
                "script_formats": f.script_formats,
                "notion_id":      f.notion_id,
            }
            for f in session.threats detected
        ]
    }


@app.get("/scan/{scan_id}/report")
def scan_report(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    session: ScanSession = active_scans[scan_id].get("session")
    if not session:
        return {"report": None}

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in session.threats detected:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    return {
        "session_name":       session.session_name,
        "target_url":         session.config.target_url,
        "status":             session.status,
        "total_threats detected":     len(session.threats detected),
        "severity_breakdown": counts,
        "executive_summary":  getattr(session, "executive_summary", ""),
        "context": {
            "backend":  session.context.backend_language if session.context else "",
            "database": session.context.database_type    if session.context else "",
            "waf":      session.context.waf_detected     if session.context else "",
            "spa":      session.context.spa_detected     if session.context else False,
        },
        "threats detected": [
            {
                "title":               f.title,
                "severity":            f.severity.value,
                "type":                f.attack_type.value,
                "url":                 f.target_url,
                "param":               f.vulnerable_param,
                "cvss":                f.cvss_score,
                "cwe":                 f.cwe_id,
                "confidence":          f.confidence.value,
                "detection":           f.detection_method.value,
                "ai_escalated":        f.ai_escalated,
                "payload":             f.payload_used,
                "reproduction_steps":  f.reproduction_steps,
                "remediation_advice":  f.remediation_advice,
                "raw_request":         f.raw_request,
                "raw_response":        f.raw_response[:500],
                "script_formats":      f.script_formats,
            }
            for f in session.threats detected
        ]
    }


@app.get("/scan/{scan_id}/logs")
def scan_logs_endpoint(scan_id: str, since: int = 0):
    if scan_id not in scan_logs:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"logs": scan_logs[scan_id][since:]}


# ── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    pointer = 0
    try:
        while True:
            logs = scan_logs.get(scan_id, [])
            if pointer < len(logs):
                for entry in logs[pointer:]:
                    await websocket.send_json({"type": "log", "message": entry})
                pointer = len(logs)

            info = active_scans.get(scan_id, {})
            if info.get("status") in ("completed", "failed"):
                await websocket.send_json({"type": "done", "status": info["status"]})
                break

            await asyncio.sleep(0.2)
    except WebSocketDisconnect:
        pass


# ── Background scan runner ───────────────────────────────────────────────────

async def _run_scan(scan_id: str, config: ScanConfig):
    def log(msg: str):
        entry = f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}"
        scan_logs[scan_id].append(entry)
        active_scans[scan_id]["threats detected"] = len(
            (active_scans[scan_id].get("session") or ScanSession("", config)).threats detected
        )

    try:
        engine  = ScanEngine(config, log=log)
        session = await engine.run()
        active_scans[scan_id]["session"]  = session
        active_scans[scan_id]["status"]   = session.status.lower()
        active_scans[scan_id]["threats detected"] = len(session.threats detected)
    except Exception as e:
        log(f"[Engine] Fatal: {e}")
        active_scans[scan_id]["status"] = "failed"


@app.get("/scan/{scan_id}/artefacts")
def scan_artefacts(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    session: ScanSession = active_scans[scan_id].get("session")
    if not session:
        return {"artefacts": {}}
    return {"artefacts": getattr(session, "artefacts", {})}
