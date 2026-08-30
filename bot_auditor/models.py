from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl
import yaml


class TestMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"


class Verdict(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    REDIRECTED = "REDIRECTED"


@dataclass
class Signature:
    name: str
    user_agent: str
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> Signature:
        return cls(
            name=data["name"],
            user_agent=data.get("user_agent", ""),
            headers=data.get("headers", {}),
        )


@dataclass
class Target:
    url: str
    path: str = "/"

    @property
    def full_url(self) -> str:
        from urllib.parse import urljoin
        return urljoin(self.url.rstrip("/") + "/", self.path.lstrip("/"))

    @classmethod
    def from_dict(cls, data: dict) -> Target:
        return cls(url=data["url"], path=data.get("path", "/"))


@dataclass
class Settings:
    timeout: float = 10.0
    retries: int = 2
    delay: float = 1.0
    methods: list[TestMethod] = field(default_factory=lambda: [TestMethod.GET])
    follow_redirects: bool = True
    max_body_size: int = 1048576

    @classmethod
    def from_dict(cls, data: dict) -> Settings:
        methods = [TestMethod(m) for m in data.get("methods", ["GET"])]
        return cls(
            timeout=data.get("timeout", 10.0),
            retries=data.get("retries", 2),
            delay=data.get("delay", 1.0),
            methods=methods,
            follow_redirects=data.get("follow_redirects", True),
            max_body_size=data.get("max_body_size", 1048576),
        )


@dataclass
class TestResult:
    signature_name: str
    method: TestMethod
    url: str
    status_code: Optional[int]
    verdict: Verdict
    response_headers: dict[str, str]
    response_body_snippet: str
    error: Optional[str] = None
    elapsed_ms: float = 0.0
    redirected_to: Optional[str] = None
    waf_headers: dict[str, str] = field(default_factory=dict)

    def is_blocked(self) -> bool:
        return self.verdict == Verdict.BLOCKED

    def is_allowed(self) -> bool:
        return self.verdict == Verdict.ALLOWED


@dataclass
class Config:
    target: Target
    signatures: list[Signature]
    settings: Settings

    @classmethod
    def from_yaml(cls, path: str) -> Config:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls(
            target=Target.from_dict(data["target"]),
            signatures=[Signature.from_dict(s) for s in data["signatures"]],
            settings=Settings.from_dict(data.get("settings", {})),
        )


@dataclass
class RunSummary:
    total: int
    allowed: int
    blocked: int
    errors: int
    redirected: int
    false_positives: list[str]  # Legitimate bots that were blocked
    false_negatives: list[str]  # Suspicious bots that were allowed

    @classmethod
    def from_results(cls, results: list[TestResult], legitimate_bots: set[str], suspicious_bots: set[str]) -> RunSummary:
        allowed = sum(1 for r in results if r.is_allowed())
        blocked = sum(1 for r in results if r.is_blocked())
        errors = sum(1 for r in results if r.verdict == Verdict.ERROR)
        redirected = sum(1 for r in results if r.verdict == Verdict.REDIRECTED)

        false_positives = [
            r.signature_name for r in results
            if r.signature_name in legitimate_bots and r.is_blocked()
        ]
        false_negatives = [
            r.signature_name for r in results
            if r.signature_name in suspicious_bots and r.is_allowed()
        ]

        return cls(
            total=len(results),
            allowed=allowed,
            blocked=blocked,
            errors=errors,
            redirected=redirected,
            false_positives=false_positives,
            false_negatives=false_negatives,
        )


# Legitimate bot names that should NOT be blocked
LEGITIMATE_BOTS = {
    "Googlebot", "Bingbot", "Googlebot-Mobile", "YandexBot", "DuckDuckBot",
    "Baiduspider", "Yahoo! Slurp", "facebookexternalhit", "Twitterbot",
    "LinkedInBot", "Slackbot", "TelegramBot", "WhatsApp",
}

# Suspicious bot names that MAY be blocked
SUSPICIOUS_BOTS = {
    "Python-Requests", "cURL", "Go-http-client", "Java-HttpClient",
    "Node-Fetch", "Headless-Chrome", "PhantomJS", "No-User-Agent",
    "No-Accept-Header", "Bot-Like-Headers",
}