from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass
from typing import Optional
import httpx
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

from .models import (
    Signature, Target, Settings, TestResult, TestMethod, Verdict
)


# Known WAF response headers that indicate blocking
WAF_HEADERS = {
    "cf-ray", "cf-cache-status", "server", "x-sucuri-id", "x-waf-status",
    "x-protected-by", "x-cdn", "x-akamai-transformed", "x-incap-sess",
    "x-iinfo", "x-cdn-request-id", "x-amz-cf-id", "x-cloudfront-request-id",
}


@dataclass
class RunnerStats:
    requests_made: int = 0
    requests_failed: int = 0


class HTTPXRunner:
    """Direct HTTP requests using httpx - fast, no browser overhead"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.client: Optional[httpx.AsyncClient] = None
        self.stats = RunnerStats()

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.timeout),
            follow_redirects=self.settings.follow_redirects,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()

    async def run(self, signature: Signature, target: Target, method: TestMethod) -> TestResult:
        url = target.full_url
        headers = dict(signature.headers)
        if signature.user_agent:
            headers["User-Agent"] = signature.user_agent

        start = time.perf_counter()
        error = None
        status_code = None
        response_headers = {}
        response_body = ""
        redirected_to = None
        waf_headers = {}
        verdict = Verdict.ERROR

        for attempt in range(self.settings.retries + 1):
            try:
                self.stats.requests_made += 1
                req = self.client.build_request(
                    method.value,
                    url,
                    headers=headers,
                )
                resp = await self.client.send(req, stream=True)

                status_code = resp.status_code
                response_headers = dict(resp.headers)

                # Check for WAF-specific headers
                waf_headers = {
                    k: v for k, v in response_headers.items()
                    if k.lower() in WAF_HEADERS
                }

                # Read limited body
                body_chunks = []
                async for chunk in resp.aiter_bytes():
                    body_chunks.append(chunk)
                    if sum(len(c) for c in body_chunks) > self.settings.max_body_size:
                        break
                response_body = b"".join(body_chunks).decode("utf-8", errors="replace")

                # Determine verdict
                if 200 <= status_code < 300:
                    verdict = Verdict.ALLOWED
                elif 300 <= status_code < 400:
                    verdict = Verdict.REDIRECTED
                    redirected_to = response_headers.get("location")
                elif 400 <= status_code < 500:
                    # 403, 429, 406, etc. often indicate blocking
                    if status_code in (403, 429, 406, 503):
                        verdict = Verdict.BLOCKED
                    else:
                        verdict = Verdict.ALLOWED  # Other 4xx might be app errors
                elif 500 <= status_code < 600:
                    verdict = Verdict.ERROR

                break

            except httpx.TimeoutException:
                error = f"Timeout after {self.settings.timeout}s"
                self.stats.requests_failed += 1
            except httpx.TooManyRedirects:
                error = "Too many redirects"
                self.stats.requests_failed += 1
            except httpx.RequestError as e:
                error = f"Request error: {type(e).__name__}: {e}"
                self.stats.requests_failed += 1
            except Exception as e:
                error = f"Unexpected error: {type(e).__name__}: {e}"
                self.stats.requests_failed += 1

            if attempt < self.settings.retries:
                await asyncio.sleep(0.5 * (attempt + 1))

        elapsed_ms = (time.perf_counter() - start) * 1000

        return TestResult(
            signature_name=signature.name,
            method=method,
            url=url,
            status_code=status_code,
            verdict=verdict,
            response_headers=response_headers,
            response_body_snippet=response_body[:500],
            error=error,
            elapsed_ms=elapsed_ms,
            redirected_to=redirected_to,
            waf_headers=waf_headers,
        )


class PlaywrightRunner:
    """Browser-based testing with real TLS fingerprints and JS execution"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.stats = RunnerStats()

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-setuid-sandbox",
            ],
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.browser:
            await self.browser.close()
        if hasattr(self, "playwright"):
            await self.playwright.stop()

    async def _create_context(self, signature: Signature) -> BrowserContext:
        """Create a browser context with the signature's fingerprint"""
        user_agent = signature.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )

        # Extra headers via init script
        extra_headers = dict(signature.headers)
        if "User-Agent" not in extra_headers and signature.user_agent:
            extra_headers["User-Agent"] = signature.user_agent

        context = await self.browser.new_context(
            user_agent=user_agent,
            extra_http_headers=extra_headers,
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="America/New_York",
            permissions=[],
        )

        # Inject script to hide automation
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            window.chrome = { runtime: {} };
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
        """)

        return context

    async def run(self, signature: Signature, target: Target, method: TestMethod) -> TestResult:
        url = target.full_url
        start = time.perf_counter()
        error = None
        status_code = None
        response_headers = {}
        response_body = ""
        redirected_to = None
        waf_headers = {}
        verdict = Verdict.ERROR

        context = await self._create_context(signature)
        page = await context.new_page()

        # Capture response
        captured_response = None

        async def handle_response(response):
            nonlocal captured_response
            if response.url == url or response.url.startswith(url):
                captured_response = response

        page.on("response", handle_response)

        for attempt in range(self.settings.retries + 1):
            try:
                self.stats.requests_made += 1
                resp = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=int(self.settings.timeout * 1000),
                )

                if resp:
                    status_code = resp.status
                    response_headers = dict(resp.headers)

                    waf_headers = {
                        k: v for k, v in response_headers.items()
                        if k.lower() in WAF_HEADERS
                    }

                    try:
                        body = await resp.body()
                        response_body = body.decode("utf-8", errors="replace")
                    except Exception:
                        response_body = ""

                    # Determine verdict
                    if 200 <= status_code < 300:
                        verdict = Verdict.ALLOWED
                    elif 300 <= status_code < 400:
                        verdict = Verdict.REDIRECTED
                        redirected_to = response_headers.get("location")
                    elif status_code in (403, 429, 406, 503):
                        verdict = Verdict.BLOCKED
                    elif 400 <= status_code < 500:
                        verdict = Verdict.ALLOWED
                    else:
                        verdict = Verdict.ERROR
                else:
                    # No response object - might be blocked at network level
                    verdict = Verdict.BLOCKED
                    error = "No response received (likely blocked at network level)"

                break

            except Exception as e:
                error = f"{type(e).__name__}: {e}"
                self.stats.requests_failed += 1
                if attempt < self.settings.retries:
                    await asyncio.sleep(0.5 * (attempt + 1))

        await context.close()
        elapsed_ms = (time.perf_counter() - start) * 1000

        return TestResult(
            signature_name=signature.name,
            method=method,
            url=url,
            status_code=status_code,
            verdict=verdict,
            response_headers=response_headers,
            response_body_snippet=response_body[:500],
            error=error,
            elapsed_ms=elapsed_ms,
            redirected_to=redirected_to,
            waf_headers=waf_headers,
        )


async def run_all_tests(
    config_path: str,
    use_browser: bool = False,
    signatures_filter: Optional[list[str]] = None,
) -> list[TestResult]:
    """Main entry point to run all tests"""
    from .models import Config

    config = Config.from_yaml(config_path)

    # Filter signatures if requested
    signatures = config.signatures
    if signatures_filter:
        signatures = [s for s in signatures if s.name in signatures_filter]

    results = []

    if use_browser:
        async with PlaywrightRunner(config.settings) as runner:
            for sig in signatures:
                for method in config.settings.methods:
                    result = await runner.run(sig, config.target, method)
                    results.append(result)
                    await asyncio.sleep(config.settings.delay)
    else:
        async with HTTPXRunner(config.settings) as runner:
            for sig in signatures:
                for method in config.settings.methods:
                    result = await runner.run(sig, config.target, method)
                    results.append(result)
                    await asyncio.sleep(config.settings.delay)

    return results