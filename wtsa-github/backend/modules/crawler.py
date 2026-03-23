"""
WTSA — Crawler
Playwright-based SPA-aware crawler. Discovers all pages, forms, inputs,
and URL parameters within the defined scope.
"""

import asyncio
import json
import re
from urllib.parse import urlparse, urljoin, parse_qs, urldefrag
from typing import Optional, Callable
from playwright.async_api import async_playwright, Page, BrowserContext
from ..models import DiscoveredInput, ScanConfig, AuthMethod


class Crawler:
    def __init__(self, config: ScanConfig, log: Optional[Callable] = None):
        self.config    = config
        self.log       = log or print
        self.visited   = set()
        self.inputs    = []
        self.base_domain = urlparse(config.target_url).netloc

    async def crawl(self) -> list[DiscoveredInput]:
        async with async_playwright() as p:
            browser  = await p.chromium.launch(headless=True)
            context  = await self._make_context(browser)
            page     = await context.new_page()

            # Intercept XHR/fetch to catch API routes
            await page.route("**/*", self._intercept_request)

            await self._crawl_page(page, self.config.target_url, depth=0)

            await context.close()
            await browser.close()

        self.log(f"[Crawler] Found {len(self.inputs)} inputs across {len(self.visited)} pages")
        return self.inputs

    # ── Auth setup ───────────────────────────────────

    async def _make_context(self, browser) -> BrowserContext:
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (WTSA Security Scanner)"
        )

        if self.config.auth_method == AuthMethod.COOKIE and self.config.auth_cookie:
            # Parse raw cookie string into list of dicts
            cookies = []
            for part in self.config.auth_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, _, value = part.partition("=")
                    cookies.append({
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": self.base_domain,
                        "path": "/"
                    })
            await context.add_cookies(cookies)
            self.log("[Crawler] Injected session cookies")

        elif self.config.auth_method == AuthMethod.AUTO_LOGIN:
            await self._auto_login(context)

        elif self.config.auth_method == AuthMethod.SESSION_REPLAY and self.config.har_path:
            await self._replay_session(context)

        return context

    async def _auto_login(self, context: BrowserContext):
        page = await context.new_page()
        try:
            self.log(f"[Crawler] Auto-login → {self.config.login_url}")
            await page.goto(self.config.login_url, wait_until="networkidle", timeout=15000)

            # Find username + password fields
            await page.fill(f'[name="{self.config.login_user}"]', self.config.login_user)
            await page.fill(f'[name="{self.config.login_pass}"]', self.config.login_pass)

            async with page.expect_navigation(wait_until="networkidle", timeout=10000):
                await page.click('[type="submit"]')

            self.log("[Crawler] Auto-login successful")
        except Exception as e:
            self.log(f"[Crawler] Auto-login failed: {e}")
        finally:
            await page.close()

    async def _replay_session(self, context: BrowserContext):
        try:
            with open(self.config.har_path) as f:
                har = json.load(f)
            cookies = []
            for entry in har.get("log", {}).get("entries", []):
                for h in entry.get("request", {}).get("cookies", []):
                    cookies.append({
                        "name": h["name"],
                        "value": h["value"],
                        "domain": self.base_domain,
                        "path": "/"
                    })
            if cookies:
                await context.add_cookies(cookies[:50])  # Limit to first 50
                self.log(f"[Crawler] Replayed {len(cookies)} cookies from HAR")
        except Exception as e:
            self.log(f"[Crawler] Session replay failed: {e}")

    # ── Core crawl loop ──────────────────────────────

    async def _crawl_page(self, page: Page, url: str, depth: int):
        url, _ = urldefrag(url)
        if (url in self.visited
                or depth > self.config.max_depth
                or len(self.visited) >= self.config.max_pages_per_scan
                or not self._in_scope(url)):
            return

        self.visited.add(url)
        self.log(f"[Crawler] Visiting ({depth}) {url}")

        try:
            await page.goto(url, wait_until="networkidle", timeout=15000)
            await page.wait_for_timeout(800)  # let JS render
        except Exception as e:
            self.log(f"[Crawler] Failed to load {url}: {e}")
            return

        # Extract inputs from this page
        await self._extract_inputs(page, url)

        # Discover links for further crawling
        links = await self._extract_links(page, url)
        for link in links:
            await self._crawl_page(page, link, depth + 1)

    async def _extract_inputs(self, page: Page, page_url: str):
        # URL query parameters
        parsed = urlparse(page_url)
        if parsed.query:
            for param in parse_qs(parsed.query):
                self.inputs.append(DiscoveredInput(
                    url=page_url, param_name=param,
                    input_type="query", method="GET"
                ))

        # Form fields
        forms = await page.query_selector_all("form")
        for form in forms:
            action = await form.get_attribute("action") or page_url
            method = (await form.get_attribute("method") or "GET").upper()
            action = urljoin(page_url, action)

            fields = await form.query_selector_all(
                "input:not([type=submit]):not([type=button]):not([type=image])"
                ", textarea, select"
            )
            for field in fields:
                name = await field.get_attribute("name") or await field.get_attribute("id")
                if not name:
                    continue
                ftype = await field.get_attribute("type") or "text"
                self.inputs.append(DiscoveredInput(
                    url=page_url, param_name=name,
                    input_type="form", method=method,
                    form_action=action
                ))

        # Search for URL params in inline JavaScript (API routes)
        scripts = await page.query_selector_all("script:not([src])")
        for script in scripts:
            content = await script.inner_text()
            # Look for fetch/axios/XHR calls with query params
            for match in re.finditer(r'["\']([^"\']*\?[^"\']+)["\']', content):
                candidate = match.group(1)
                if candidate.startswith("/") or candidate.startswith("http"):
                    full = urljoin(page_url, candidate)
                    for param in parse_qs(urlparse(full).query):
                        inp = DiscoveredInput(
                            url=full, param_name=param,
                            input_type="query", method="GET"
                        )
                        if inp.url not in {i.url for i in self.inputs}:
                            self.inputs.append(inp)

    async def _extract_links(self, page: Page, base: str) -> list[str]:
        hrefs = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)"
        )
        links = []
        for href in hrefs:
            href, _ = urldefrag(href)
            if self._in_scope(href) and href not in self.visited:
                links.append(href)
        return list(set(links))[:20]  # Max 20 links per page to prevent explosion

    async def _intercept_request(self, route):
        """Log XHR/fetch requests to discover API routes."""
        url = route.request.url
        if route.request.resource_type in ("xhr", "fetch"):
            parsed = urlparse(url)
            if parsed.query and self._in_scope(url):
                for param in parse_qs(parsed.query):
                    self.inputs.append(DiscoveredInput(
                        url=url, param_name=param,
                        input_type="query", method=route.request.method
                    ))
        await route.continue_()

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.scheme.startswith("http"):
            return False
        if parsed.netloc != self.base_domain:
            # Check user-defined extra scope domains
            return parsed.netloc in self.config.scope_domains
        return True

    @property
    def max_pages_per_scan(self):
        return getattr(self.config, "max_pages", 100)
