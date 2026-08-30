# Bot Defense Auditor

Test your WAF/bot detection rules against known signatures. Run against your own staging site to verify legitimate crawlers (Googlebot, Bingbot, etc.) aren't blocked while suspicious traffic is caught.

## Why This Is Different

| Tool | Approach | Limitation |
|------|----------|------------|
| **wafw00f** | Fingerprints WAF vendor | Doesn't test *your* specific rules against *your* traffic |
| **nginx-waf-tester** | Unit tests for ModSecurity rules | Requires rule access, not black-box testing |
| **Custom scripts** | Ad-hoc curl loops | No signature library, no false-positive/negative detection, no reporting |

**This tool** runs a curated matrix of 16+ real-world client signatures (legitimate crawlers, real browsers, headless automation, script kiddies) against *your live endpoint* and explicitly flags:
- **False positives** — Legitimate bots that got blocked (SEO disaster)
- **False negatives** — Suspicious bots that slipped through (security gap)

The one genuinely new piece: **a classified signature library + automated false-positive/negative detection** that tells you exactly which rules to tune.

## How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  config.yaml │────▶│  Signature Runner │────▶│  Results Table  │
│  (16 sigs)  │     │  (httpx/Playwright)│     │  + Summary      │
└─────────────┘     └──────────────────┘     └─────────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              Fast HTTP      Real Browser
              (httpx)        (Playwright)
              ~200ms/req     ~2s/req
              No TLS fp      Real TLS/JS
```

Two execution modes:
1. **httpx** (default) — Direct HTTP requests, ~200ms per signature, no browser overhead
2. **Playwright** (`--browser`) — Real Chromium with full TLS fingerprint, JS execution, automation hiding

Each signature defines: User-Agent, custom headers. The runner hits your target, classifies response (2xx=ALLOWED, 403/429/503=BLOCKED, 3xx=REDIRECTED), extracts WAF headers (Cloudflare, Akamai, etc.), and builds a summary with explicit false-positive/negative lists.

## How to Run

```bash
# 1. Clone and install
git clone https://github.com/yourname/bot-defense-auditor
cd bot-defense-auditor
pip install -r requirements.txt
pip install -e .              # Installs `bot-audit` command
playwright install chromium   # Only needed for --browser mode

# 2. Configure your target (edit config.yaml)
#    target.url: "https://staging.yoursite.com"

# 3. Run fast HTTP mode (default)
bot-audit config.yaml

# 4. Or run browser mode for real TLS fingerprints
bot-audit config.yaml --browser

# 5. JSON output for CI/CD
bot-audit config.yaml --json > results.json

# Exit code 1 if false positives found (legitimate bots blocked)
```

## Example Output

Running against `https://httpbin.org/headers` (no WAF — all allowed):

```
Starting audit against https://httpbin.org/headers
Using httpx direct HTTP mode (fast)
╭──────────────────────────────── Bot Defense Audit Results ───────────────────────────────╮
│ Signature           Verdict   Status   Time (ms)   WAF Headers          Error / Redirect │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ Googlebot           ✓ ALLOWED   200         1012   server: gunicorn     —                │
│ Bingbot             ✓ ALLOWED   200          227   server: gunicorn     —                │
│ Googlebot-Mobile    ✓ ALLOWED   200          225   server: gunicorn     —                │
│ Chrome-Latest       ✓ ALLOWED   200          226   server: gunicorn     —                │
│ Firefox-Latest      ✓ ALLOWED   200          265   server: gunicorn     —                │
│ Safari-MacOS        ✓ ALLOWED   200          718   server: gunicorn     —                │
│ ⚠ Python-Requests   ✓ ALLOWED   200          224   server: gunicorn     —                │
│ ⚠ cURL              ✓ ALLOWED   200          224   server: gunicorn     —                │
│ ⚠ Go-http-client    ✓ ALLOWED   200          224   server: gunicorn     —                │
│ ⚠ Java-HttpClient   ✓ ALLOWED   200          225   server: gunicorn     —                │
│ ⚠ Node-Fetch        ✓ ALLOWED   200          229   server: gunicorn     —                │
│ ⚠ Headless-Chrome   ✓ ALLOWED   200          231   server: gunicorn     —                │
│ ⚠ PhantomJS         ✓ ALLOWED   200          227   server: gunicorn     —                │
│ ⚠ No-User-Agent     ✓ ALLOWED   200          225   server: gunicorn     —                │
│ ⚠ No-Accept-Header  ✓ ALLOWED   200          230   server: gunicorn     —                │
│ ⚠ Bot-Like-Headers  ✓ ALLOWED   200          482   server: gunicorn     —                │
╰──────────────────────────────────────────────────────────────────────────────────────────╯

╭──────────────────────────────────── Summary ────────────────────────────────────────────╮
│ Total Tests:  16                                                                         │
│   ✓ Allowed:    16                                                                       │
│   ✗ Blocked:     0                                                                       │
│   → Redirected:  0                                                                       │
│   ⚠ Errors:      0                                                                       │
│                                                                                        │
│ FALSE NEGATIVES (Suspicious bots allowed):                                             │
│   • Python-Requests                                                                      │
│   • cURL                                                                                 │
│   • Go-http-client                                                                       │
│   • Java-HttpClient                                                                      │
│   • Node-Fetch                                                                           │
│   • Headless-Chrome                                                                      │
│   • PhantomJS                                                                            │
│   • No-User-Agent                                                                        │
│   • No-Accept-Header                                                                     │
│   • Bot-Like-Headers                                                                     │
│                                                                                        │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

⚠ = Signature classification (✓ Legitimate crawler/browser, ⚠ Suspicious/malformed)

**Expected result on unprotected endpoint**: All allowed, false negatives listed (suspicious bots not blocked — correct, since there's no WAF).

**On a protected staging site**, you'd see:
- ✓ Googlebot, Bingbot, Chrome, Firefox, Safari → ALLOWED (good)
- ✗ Headless-Chrome, PhantomJS, cURL, Python-Requests → BLOCKED (good)
- ⚠ **FALSE POSITIVE** if Googlebot shows BLOCKED → Fix your WAF rule immediately
- ⚠ **FALSE NEGATIVE** if Headless-Chrome shows ALLOWED → Your bot detection has a gap

## Tech Stack + Libraries Reused

| Library | Purpose | Why Not Custom |
|---------|---------|----------------|
| **httpx** | Async HTTP client | Battle-tested, HTTP/2, connection pooling, retries |
| **Playwright** | Real browser automation | Only tool with reliable stealth mode + TLS fingerprint control |
| **pydantic** | Config validation | Type-safe YAML parsing with defaults |
| **rich** | Terminal tables/panels | Professional output, zero boilerplate |
| **click** | CLI framework | Composable, well-documented, standard |
| **pyyaml** | Config format | Human-readable, supports comments |

## Known Limitations / What's Next

- **No TLS fingerprint analysis** — Playwright mode uses real Chrome TLS but doesn't export/analyze JA3. Would need `mitmproxy` or `tlsfingerprint` integration.
- **Single endpoint only** — Config supports one URL. Could add path list or sitemap crawling.
- **No rate-limit testing** — Doesn't test 429 behavior over time. Could add burst mode.
- **No auth support** — Can't test behind login. Could add header/cookie injection from env.
- **Signature library is static** — Could auto-update from public UA lists (udger.com, etc.).
- **No historical comparison** — Could store baseline and diff on each run.

---

**License**: MIT — Use freely, audit your own infrastructure responsibly.