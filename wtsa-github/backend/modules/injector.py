"""
WTSA — Probe Engine
Fires payloads against discovered inputs using async batched HTTP requests.
Handles GET params, POST forms, headers, and cookies.
"""

import asyncio
import time
import httpx
from typing import Optional, Callable
from ..models import DiscoveredInput, Payload, ScanConfig


class InjectionResult:
    def __init__(self, inp: DiscoveredInput, payload: Payload,
                 status: int, body: str, headers: dict,
                 elapsed: float, raw_request: str):
        self.input        = inp
        self.payload      = payload
        self.status       = status
        self.body         = body
        self.headers      = headers
        self.elapsed      = elapsed
        self.raw_request  = raw_request
        self.raw_response = f"HTTP/1.1 {status}\n" + \
                            "\n".join(f"{k}: {v}" for k, v in headers.items()) + \
                            f"\n\n{body[:2000]}"


class Probe Engine:
    def __init__(self, config: ScanConfig, log: Optional[Callable] = None):
        self.config     = config
        self.log        = log or print
        self._last_req  = 0.0
        self._semaphore = asyncio.Semaphore(5)  # max 5 concurrent

    # ── Baseline ─────────────────────────────────────

    async def get_baseline(self, inp: DiscoveredInput) -> InjectionResult:
        """Fire a clean request to establish response baseline."""
        dummy = Payload(name="baseline", string="WTSA_BASELINE_TOKEN",
                        attack_type=None, tier=None)
        return await self._fire(inp, dummy)

    # ── Single injection ─────────────────────────────

    async def inject(self, inp: DiscoveredInput, payload: Payload) -> InjectionResult:
        async with self._semaphore:
            await self._rate_limit()
            return await self._fire(inp, payload)

    # ── Batch injection ──────────────────────────────

    async def inject_batch(self, inp: DiscoveredInput,
                           payloads: list[Payload]) -> list[InjectionResult]:
        tasks = [self.inject(inp, p) for p in payloads]
        return await asyncio.gather(*tasks, return_exceptions=False)

    # ── Core fire method ─────────────────────────────

    async def _fire(self, inp: DiscoveredInput, payload: Payload) -> InjectionResult:
        cookies = self._build_cookies()
        headers = self._build_headers()
        start   = time.monotonic()

        try:
            async with httpx.AsyncClient(
                cookies=cookies,
                headers=headers,
                follow_redirects=True,
                timeout=max(self.config.timing_threshold + 3, 15.0),
                verify=False,
            ) as client:

                if inp.input_type == "query" or inp.method == "GET":
                    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
                    parsed = urlparse(inp.url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[inp.param_name] = [payload.string]
                    new_query = urlencode(params, doseq=True)
                    url = urlunparse(parsed._replace(query=new_query))
                    raw_req = f"GET {url} HTTP/1.1\nHost: {parsed.netloc}\n"
                    resp = await client.get(url)

                elif inp.input_type == "form" and inp.method == "POST":
                    data = {inp.param_name: payload.string}
                    raw_req = f"POST {inp.form_action} HTTP/1.1\nHost: {_host(inp.form_action)}\n\n{data}"
                    resp = await client.post(inp.form_action, data=data)

                else:
                    from urllib.parse import urlparse
                    url = inp.url
                    raw_req = f"GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n"
                    resp = await client.get(url)

        except httpx.TimeoutException:
            elapsed = time.monotonic() - start
            return InjectionResult(
                inp=inp, payload=payload,
                status=0, body="[TIMEOUT]",
                headers={}, elapsed=elapsed,
                raw_request=f"[TIMEOUT after {elapsed:.1f}s]"
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            return InjectionResult(
                inp=inp, payload=payload,
                status=0, body=f"[ERROR: {e}]",
                headers={}, elapsed=elapsed,
                raw_request=f"[ERROR: {e}]"
            )

        elapsed = time.monotonic() - start
        return InjectionResult(
            inp=inp, payload=payload,
            status=resp.status_code,
            body=resp.text,
            headers=dict(resp.headers),
            elapsed=elapsed,
            raw_request=raw_req
        )

    # ── Helpers ──────────────────────────────────────

    async def _rate_limit(self):
        gap = 1.0 / max(self.config.rate_limit, 1)
        elapsed = time.monotonic() - self._last_req
        if elapsed < gap:
            await asyncio.sleep(gap - elapsed)
        self._last_req = time.monotonic()

    def _build_cookies(self) -> dict:
        if self.config.auth_method.value == "Cookie/Token" and self.config.auth_cookie:
            cookies = {}
            for part in self.config.auth_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    cookies[k.strip()] = v.strip()
            return cookies
        return {}

    def _build_headers(self) -> dict:
        return {
            "User-Agent": "Mozilla/5.0 (WTSA Security Scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
