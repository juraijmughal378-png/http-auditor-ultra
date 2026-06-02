"""HTTP deep analysis — methods, cookies, redirects, rate limiting, CORS.

Features:
- HTTP methods enumeration (PUT, DELETE, TRACE, OPTIONS)
- Cookie security analysis (Secure, HttpOnly, SameSite)
- Full redirect chain tracking
- Rate limiting detection
- CORS policy analysis
- Content-Type security check
- Cache control analysis
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CookieInfo:
    name: str
    value_length: int
    secure: bool = False
    http_only: bool = False
    same_site: str = "not set"
    path: str = "/"
    domain: str = ""
    expires: str = ""

    @property
    def risk_level(self) -> str:
        if not self.secure and not self.http_only:
            return "HIGH"
        elif not self.secure or not self.http_only:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "path": self.path,
            "risk_level": self.risk_level,
        }


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "status_code": self.status_code, "location": self.location}


@dataclass
class CORSInfo:
    allowed_origins: str = ""
    allowed_methods: str = ""
    allowed_headers: str = ""
    allow_credentials: bool = False
    wildcard_origin: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_origins": self.allowed_origins,
            "allowed_methods": self.allowed_methods,
            "allowed_headers": self.allowed_headers,
            "allow_credentials": self.allow_credentials,
            "wildcard_origin": self.wildcard_origin,
            "risk": "HIGH" if self.wildcard_origin and self.allow_credentials else
                    "MEDIUM" if self.wildcard_origin else "LOW",
        }


@dataclass
class HTTPAnalysisResult:
    url: str
    allowed_methods: List[str] = field(default_factory=list)
    dangerous_methods: List[str] = field(default_factory=list)
    cookies: List[CookieInfo] = field(default_factory=list)
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    rate_limit_detected: bool = False
    rate_limit_headers: Dict[str, str] = field(default_factory=dict)
    cors: Optional[CORSInfo] = None
    content_type: str = ""
    x_content_type_nosniff: bool = False
    clickjacking_protected: bool = False
    hsts_enabled: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "allowed_methods": self.allowed_methods,
            "dangerous_methods": self.dangerous_methods,
            "cookies": [c.to_dict() for c in self.cookies],
            "redirect_chain": [r.to_dict() for r in self.redirect_chain],
            "rate_limit_detected": self.rate_limit_detected,
            "rate_limit_headers": self.rate_limit_headers,
            "cors": self.cors.to_dict() if self.cors else {},
            "content_type": self.content_type,
            "security": {
                "x_content_type_nosniff": self.x_content_type_nosniff,
                "clickjacking_protected": self.clickjacking_protected,
                "hsts_enabled": self.hsts_enabled,
            },
            "error": self.error or "",
        }


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def _parse_cookies(set_cookie_headers: List[str]) -> List[CookieInfo]:
    cookies: List[CookieInfo] = []
    for header in set_cookie_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue
        name_value = parts[0].split("=", 1)
        name = name_value[0].strip()
        value_len = len(name_value[1]) if len(name_value) > 1 else 0

        cookie = CookieInfo(name=name, value_length=value_len)
        for part in parts[1:]:
            part_lower = part.lower()
            if part_lower == "secure":
                cookie.secure = True
            elif part_lower == "httponly":
                cookie.http_only = True
            elif part_lower.startswith("samesite="):
                cookie.same_site = part.split("=", 1)[1].strip()
            elif part_lower.startswith("path="):
                cookie.path = part.split("=", 1)[1].strip()
            elif part_lower.startswith("domain="):
                cookie.domain = part.split("=", 1)[1].strip()
        cookies.append(cookie)
    return cookies


async def _enumerate_methods(
    url: str,
    client: httpx.AsyncClient,
) -> Tuple[List[str], List[str]]:
    """Test which HTTP methods are allowed."""
    methods_to_test = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD", "CONNECT"]
    allowed: List[str] = []
    dangerous: List[str] = []
    dangerous_set = {"PUT", "DELETE", "TRACE", "CONNECT"}

    # First try OPTIONS
    try:
        resp = await client.options(url)
        allow_header = resp.headers.get("allow", "") or resp.headers.get("Allow", "")
        if allow_header:
            for method in methods_to_test:
                if method in allow_header.upper():
                    allowed.append(method)
                    if method in dangerous_set:
                        dangerous.append(method)
            return allowed, dangerous
    except Exception:
        pass

    # Manual test
    sem = asyncio.Semaphore(5)

    async def _test_method(method: str) -> None:
        async with sem:
            try:
                resp = await client.request(method, url)
                if resp.status_code not in (405, 501):
                    allowed.append(method)
                    if method in dangerous_set:
                        dangerous.append(method)
            except Exception:
                pass

    tasks = [asyncio.create_task(_test_method(m)) for m in methods_to_test]
    await asyncio.gather(*tasks, return_exceptions=True)
    return allowed, dangerous


async def _get_redirect_chain(url: str, user_agent: str, verify_ssl: bool) -> List[RedirectHop]:
    """Track full redirect chain."""
    chain: List[RedirectHop] = []
    current_url = url
    max_hops = 10

    async with httpx.AsyncClient(
        timeout=10.0,
        headers={"User-Agent": user_agent},
        verify=verify_ssl,
        follow_redirects=False,
    ) as client:
        for _ in range(max_hops):
            try:
                resp = await client.get(current_url)
                location = resp.headers.get("location", "")
                chain.append(RedirectHop(
                    url=current_url,
                    status_code=resp.status_code,
                    location=location,
                ))
                if resp.status_code not in (301, 302, 303, 307, 308) or not location:
                    break
                if location.startswith("/"):
                    from urllib.parse import urlparse
                    parsed = urlparse(current_url)
                    current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                elif location.startswith("http"):
                    current_url = location
                else:
                    break
            except Exception:
                break
    return chain


async def analyze_http(
    url: str,
    user_agent: str = "Mozilla/5.0",
    timeout: float = 15.0,
    verify_ssl: bool = True,
) -> HTTPAnalysisResult:
    """Perform deep HTTP analysis on a URL."""
    result = HTTPAnalysisResult(url=url)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": user_agent},
            verify=verify_ssl,
            follow_redirects=True,
        ) as client:
            # Main request
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Content type
            result.content_type = headers.get("content-type", "")

            # Security headers
            result.x_content_type_nosniff = headers.get("x-content-type-options", "").lower() == "nosniff"
            result.clickjacking_protected = "x-frame-options" in headers or "content-security-policy" in headers
            result.hsts_enabled = "strict-transport-security" in headers

            # Cookies
            set_cookie_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
            result.cookies = _parse_cookies(set_cookie_headers)

            # Rate limiting headers
            rate_headers = {}
            for h in ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
                      "retry-after", "x-rate-limit-limit", "ratelimit-limit"]:
                if h in headers:
                    rate_headers[h] = headers[h]
            if rate_headers:
                result.rate_limit_detected = True
                result.rate_limit_headers = rate_headers

            # CORS
            cors_origin = headers.get("access-control-allow-origin", "")
            if cors_origin:
                result.cors = CORSInfo(
                    allowed_origins=cors_origin,
                    allowed_methods=headers.get("access-control-allow-methods", ""),
                    allowed_headers=headers.get("access-control-allow-headers", ""),
                    allow_credentials=headers.get("access-control-allow-credentials", "").lower() == "true",
                    wildcard_origin=cors_origin == "*",
                )

            # HTTP methods
            result.allowed_methods, result.dangerous_methods = await _enumerate_methods(url, client)

        # Redirect chain
        result.redirect_chain = await _get_redirect_chain(url, user_agent, verify_ssl)

        logger.info(
            "HTTP analysis complete for %s — methods:%d cookies:%d redirects:%d",
            url, len(result.allowed_methods), len(result.cookies), len(result.redirect_chain),
        )

    except Exception as exc:
        result.error = str(exc)
        logger.error("HTTP analysis failed for %s: %s", url, exc)

    return result
