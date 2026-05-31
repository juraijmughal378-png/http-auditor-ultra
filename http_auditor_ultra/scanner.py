"""Port scanning, subdomain enumeration, and path discovery."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import httpx

from http_auditor_ultra.config import AuditorConfig
from http_auditor_ultra.utils import check_tcp_port, extract_domain, load_wordlist, resolve_hostname

logger = logging.getLogger(__name__)

_COMMON_SERVICES: Dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8000: "HTTP-Alt",
    8888: "HTTP-Alt2",
    9443: "HTTPS-Alt2",
    3000: "Node.js-Dev",
    5000: "Flask-Dev",
    9000: "PHP-FPM",
}


@dataclass
class ScanResult:
    host: str
    port: int
    open: bool
    service: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"host": self.host, "port": self.port, "open": self.open, "service": self.service}


@dataclass
class SubdomainResult:
    subdomain: str
    resolved: Optional[str] = None
    source: str = "dns"

    def to_dict(self) -> Dict[str, object]:
        return {"subdomain": self.subdomain, "resolved": self.resolved or "", "source": self.source}


@dataclass
class PathResult:
    url: str
    status_code: int
    size: int = -1

    def to_dict(self) -> Dict[str, object]:
        return {"url": self.url, "status_code": self.status_code, "size": self.size}


async def scan_ports(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    progress_callback: Optional[Callable[[int, int], Any]] = None,
) -> List[ScanResult]:
    """Scan a list of TCP ports on the given host."""
    total = len(ports)
    results: List[Optional[ScanResult]] = [None] * total
    processed = 0

    async def _scan_one(index: int, port: int) -> None:
        nonlocal processed
        is_open = await check_tcp_port(host, port, timeout)
        service = _COMMON_SERVICES.get(port, "")
        results[index] = ScanResult(host=host, port=port, open=is_open, service=service)
        processed += 1
        if progress_callback:
            cb = progress_callback(processed, total)
            if asyncio.iscoroutine(cb):
                await cb

    tasks = [asyncio.create_task(_scan_one(i, p)) for i, p in enumerate(ports)]
    await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if r is not None]


async def enumerate_subdomains_dns(
    domain: str,
    wordlist: List[str],
    max_concurrent: int = 20,
    progress_callback: Optional[Callable[[int, int], Any]] = None,
) -> List[SubdomainResult]:
    """Enumerate subdomains via DNS brute-force."""
    total = len(wordlist)
    found: List[SubdomainResult] = []
    processed = 0
    sem = asyncio.Semaphore(max_concurrent)

    async def _try_sub(sub: str) -> None:
        nonlocal processed
        async with sem:
            fqdn = f"{sub}.{domain}"
            ip = await resolve_hostname(fqdn)
            processed += 1
            if ip:
                found.append(SubdomainResult(subdomain=fqdn, resolved=ip, source="dns"))
            if progress_callback:
                cb = progress_callback(processed, total)
                if asyncio.iscoroutine(cb):
                    await cb

    tasks = [asyncio.create_task(_try_sub(sub)) for sub in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found


async def enumerate_subdomains_ct(domain: str) -> List[SubdomainResult]:
    """Enumerate subdomains via Certificate Transparency logs (crt.sh)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found: List[SubdomainResult] = []
    seen: Set[str] = set()

    try:
        async with httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "HTTP-Auditor-Ultra/2.0"},
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and sub not in seen:
                            seen.add(sub)
                            found.append(SubdomainResult(subdomain=sub, source="ct"))
        logger.info("CT log enumeration found %d subdomains for %s", len(found), domain)
    except Exception as exc:
        logger.warning("CT log enumeration failed for %s: %s", domain, exc)

    return found


async def enumerate_subdomains(
    domain: str,
    config: AuditorConfig,
    wordlist: List[str],
    progress_callback: Optional[Callable[[int, int], Any]] = None,
) -> List[SubdomainResult]:
    """Full subdomain enumeration (DNS brute-force + CT logs)."""
    logger.info("Starting subdomain enumeration for %s", domain)
    seen_subdomains: Set[str] = set()
    all_results: List[SubdomainResult] = []

    dns_results = await enumerate_subdomains_dns(domain, wordlist, config.max_concurrent, progress_callback)
    for r in dns_results:
        if r.subdomain not in seen_subdomains:
            seen_subdomains.add(r.subdomain)
            all_results.append(r)

    ct_results = await enumerate_subdomains_ct(domain)
    for r in ct_results:
        if r.subdomain not in seen_subdomains:
            seen_subdomains.add(r.subdomain)
            all_results.append(r)

    logger.info("Subdomain enumeration complete: %d found for %s", len(all_results), domain)
    return all_results


async def discover_paths(
    base_url: str,
    wordlist: List[str],
    config: AuditorConfig,
    progress_callback: Optional[Callable[[int, int], Any]] = None,
) -> List[PathResult]:
    """Discover paths/directories via wordlist brute-force."""
    total = len(wordlist)
    found: List[PathResult] = []
    processed = 0
    sem = asyncio.Semaphore(config.max_concurrent)
    base = base_url.rstrip("/")

    async def _try_path(path: str) -> None:
        nonlocal processed
        async with sem:
            url = f"{base}/{path.lstrip('/')}"
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(config.timeout),
                    headers={"User-Agent": config.user_agent},
                    verify=config.verify_ssl,
                    follow_redirects=False,
                ) as client:
                    resp = await client.get(url)
                    processed += 1
                    if resp.status_code not in (404,):
                        found.append(PathResult(url=url, status_code=resp.status_code, size=len(resp.content)))
                    if progress_callback:
                        cb = progress_callback(processed, total)
                        if asyncio.iscoroutine(cb):
                            await cb
            except (httpx.HTTPError, OSError, asyncio.TimeoutError):
                processed += 1

    tasks = [asyncio.create_task(_try_path(p)) for p in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("Path discovery complete: %d paths found from %d attempts", len(found), total)
    return found
