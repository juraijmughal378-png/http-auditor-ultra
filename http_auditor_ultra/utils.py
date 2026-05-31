"""Utility functions — extended for Ultra capabilities."""

from __future__ import annotations

import asyncio
import logging
import random
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_URL_SCHEME_PATTERN: re.Pattern[str] = re.compile(r"^https?$", re.IGNORECASE)
_UNRESERVED: str = r"a-zA-Z0-9\-._~"
_SUB_DELIMS: str = r"!$&'()*+,;="
_PCHAR: str = rf"[{_UNRESERVED}{_SUB_DELIMS}:@%]"
_VALID_URL_PATTERN: re.Pattern[str] = re.compile(
    rf"^https?://"
    rf"(?:\[[0-9a-fA-F:.]+\]|[{_UNRESERVED}{_SUB_DELIMS}\-]+(?:\.[{_UNRESERVED}{_SUB_DELIMS}\-]+)*)"
    rf"(?::\d{{1,5}})?"
    rf"(?:/{_PCHAR}*)*"
    rf"(?:\?{_PCHAR}*)?"
    rf"(?:#{_PCHAR}*)?$",
)

_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_TXT_EXTENSIONS: frozenset[str] = frozenset({".txt", ".lst", ".urls"})


@dataclass
class RetryState:
    attempt: int = 0
    max_retries: int = 3
    backoff: float = 1.0
    jitter: float = 0.1

    @property
    def is_exhausted(self) -> bool:
        return self.attempt > self.max_retries

    @property
    def delay(self) -> float:
        base: float = self.backoff * (2.0 ** self.attempt)
        return base + random.uniform(0, self.jitter)

    def next(self) -> RetryState:
        return RetryState(
            attempt=self.attempt + 1,
            max_retries=self.max_retries,
            backoff=self.backoff,
            jitter=self.jitter,
        )


@dataclass
class AuditStatistics:
    total_urls: int = 0
    successful: int = 0
    failed: int = 0
    retried: int = 0
    total_time_sec: float = 0.0
    status_counts: Dict[int, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    subdomains_found: int = 0
    paths_found: int = 0
    open_ports: int = 0
    wafs_detected: int = 0
    tls_issues: int = 0
    missing_security_headers: int = 0

    def record_status(self, status_code: int) -> None:
        self.status_counts[status_code] = self.status_counts.get(status_code, 0) + 1

    def summary(self) -> Dict[str, object]:
        success_rate = (self.successful / self.total_urls * 100.0) if self.total_urls > 0 else 0.0
        return {
            "total_urls": self.total_urls,
            "successful": self.successful,
            "failed": self.failed,
            "retried": self.retried,
            "total_time_seconds": round(self.total_time_sec, 3),
            "average_time_per_url_seconds": (
                round(self.total_time_sec / self.total_urls, 3) if self.total_urls > 0 else 0.0
            ),
            "success_rate_percent": round(success_rate, 1),
            "unique_status_codes": {str(k): v for k, v in sorted(self.status_counts.items())},
            "error_count": len(self.errors),
            "subdomains_found": self.subdomains_found,
            "paths_found": self.paths_found,
            "open_ports_found": self.open_ports,
            "wafs_detected": self.wafs_detected,
            "tls_security_issues": self.tls_issues,
            "missing_security_headers": self.missing_security_headers,
        }


def validate_url(url: str) -> Optional[str]:
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if "://" not in url:
        url = f"https://{url}"
    parsed = urlparse(url)
    if not _URL_SCHEME_PATTERN.match(parsed.scheme or ""):
        return None
    if not parsed.netloc:
        return None
    if not _VALID_URL_PATTERN.match(url):
        return None
    return url


def extract_domain(url: str) -> Optional[str]:
    parsed = urlparse(url)
    host = parsed.hostname
    if host:
        return host.split(":")[0]
    return None


def load_urls(source: str) -> List[str]:
    path = Path(source)
    if path.suffix.lower() in _TXT_EXTENSIONS or path.is_file():
        if not path.exists():
            raise FileNotFoundError(f"URL list file not found: {source}")
        lines = path.read_text(encoding="utf-8").splitlines()
        urls: List[str] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            validated = validate_url(line)
            if validated:
                urls.append(validated)
        if not urls:
            raise ValueError(f"No valid URLs found in {source}.")
        return urls
    validated = validate_url(source)
    if not validated:
        raise ValueError(f"Invalid URL: {source!r}.")
    return [validated]


def is_retryable(status_code: int, method: str = "GET") -> bool:
    return status_code in _RETRYABLE_STATUS_CODES


async def resolve_hostname(hostname: str) -> Optional[str]:
    try:
        loop = asyncio.get_running_loop()
        info = await loop.getaddrinfo(hostname, 443, socket.AF_INET)
        if info:
            return info[0][4][0]
    except OSError as exc:
        logger.debug("DNS resolution failed for %s: %s", hostname, exc)
    return None


async def resolve_hostname_all(hostname: str) -> List[str]:
    addresses: List[str] = []
    try:
        loop = asyncio.get_running_loop()
        info = await loop.getaddrinfo(hostname, 443, socket.AF_INET)
        for entry in info:
            ip = entry[4][0]
            if ip not in addresses:
                addresses.append(ip)
    except OSError as exc:
        logger.debug("DNS multi-resolution failed for %s: %s", hostname, exc)
    return addresses


async def check_tcp_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


class Timer:
    def __init__(self) -> None:
        self._start: float = 0.0
        self._end: float = 0.0

    def __enter__(self) -> Timer:
        self._start = time.monotonic()
        return self

    def __exit__(self, *args: object) -> None:
        self._end = time.monotonic()

    @property
    def elapsed(self) -> float:
        if self._end:
            return self._end - self._start
        return time.monotonic() - self._start


async def rate_limit_sleep(delay: float) -> None:
    if delay > 0:
        await asyncio.sleep(delay)


def chunked(items: List[str], size: int) -> Generator[List[str], None, None]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def load_wordlist(path: Optional[Path], builtin_name: str) -> List[str]:
    if path is not None and path.exists():
        logger.info("Loading wordlist from %s", path)
        return _read_wordlist(path)
    pkg_dir = Path(__file__).resolve().parent
    builtin_path = pkg_dir / "data" / builtin_name
    if builtin_path.exists():
        logger.info("Loading built-in wordlist from %s", builtin_path)
        return _read_wordlist(builtin_path)
    logger.warning("Wordlist not found at %s or built-in %s. Using minimal default.", path, builtin_path)
    return _default_minimal_wordlist(builtin_name)


def _read_wordlist(path: Path) -> List[str]:
    entries: List[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line.lower())
    except OSError as exc:
        logger.error("Failed to read wordlist %s: %s", path, exc)
    return entries


def _default_minimal_wordlist(name: str) -> List[str]:
    if "subdomain" in name:
        return ["www", "mail", "admin", "blog", "api", "dev", "test",
                "stage", "portal", "cdn", "app", "m", "mobile", "remote",
                "vpn", "webmail", "support", "help", "docs", "status"]
    return ["admin", "login", "wp-admin", "admin.php", "config.php",
            ".env", "backup", "robots.txt", "sitemap.xml",
            "api", "v1", "api/v1", "swagger", "docs",
            ".git/config", ".git/HEAD", "phpinfo.php", "info.php",
            "wp-content", "wp-includes", "upload", "uploads",
            "manager", "console", "panel", "dashboard"]
