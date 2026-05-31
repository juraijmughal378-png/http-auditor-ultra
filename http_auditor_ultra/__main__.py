"""Entry point — HTTP Auditor Ultra orchestrator."""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from typing import List, Optional

from http_auditor_ultra.cli import config_from_namespace, parse_args
from http_auditor_ultra.client import AuditResult, HttpClient
from http_auditor_ultra.config import AuditorConfig
from http_auditor_ultra.fingerprint import (
    analyze_security_headers,
    detect_tech_stack,
    detect_waf,
)
from http_auditor_ultra.logging_config import configure_logging
from http_auditor_ultra.reporter import AuditReport
from http_auditor_ultra.scanner import (
    PathResult,
    ScanResult,
    SubdomainResult,
    discover_paths,
    enumerate_subdomains,
    scan_ports,
)
from http_auditor_ultra.tls_auditor import TLSInfo, audit_tls_multi
from http_auditor_ultra.utils import (
    extract_domain,
    load_urls,
    load_wordlist,
)

logger = logging.getLogger(__name__)


async def _progress(processed: int, total: int) -> None:
    pct = (processed / total) * 100
    logger.info("Progress: [%d/%d] %.1f%%", processed, total, pct)


async def _run(config: AuditorConfig, urls: List[str]) -> AuditReport:
    """Execute the full Ultra audit pipeline."""
    logger.info("Starting Ultra audit: %d URL(s), %d concurrent workers", len(urls), config.max_concurrent)

    t0 = time.monotonic()

    # ── Phase 1: HTTP audit ─────────────────────────────────────────────────
    async with HttpClient(config) as client:
        results: List[AuditResult] = await client.audit_urls(
            urls, method="GET", progress_callback=_progress,
        )

        # ── Phase 1b: Fingerprinting ────────────────────────────────────────
        if config.fingerprint_enabled:
            logger.info("Running WAF detection & tech fingerprinting...")
            for result in results:
                if result.status_code > 0:
                    result.waf_name = detect_waf(result)
                    result.tech_stack = detect_tech_stack(result)
                    result.security_headers = analyze_security_headers(result)
                    missing = sum(
                        1 for h in result.security_headers.values()
                        if h["status"] == "missing"
                    )
                    client.stats.missing_security_headers += missing
                    if result.waf_name:
                        client.stats.wafs_detected += 1

        client.stats.total_time_sec = time.monotonic() - t0
        stats = client.stats

    # ── Phase 2: TLS audit ──────────────────────────────────────────────────
    tls_results: List[TLSInfo] = []
    if config.tls_audit_enabled:
        seen: set[str] = set()
        for url in urls:
            domain = extract_domain(url)
            if domain and domain not in seen:
                seen.add(domain)
                logger.info("Auditing TLS for %s", domain)
                tls_list = await audit_tls_multi(domain, timeout=config.scan_timeout)
                tls_results.extend(tls_list)
                for t in tls_list:
                    if t.error or t.weak_signature or t.is_expired or t.is_expiring_soon:
                        stats.tls_issues += 1

    # ── Phase 3: Subdomain enumeration ──────────────────────────────────────
    subdomain_results: List[SubdomainResult] = []
    if config.subdomain_enum_enabled:
        seen = set()
        for url in urls:
            domain = extract_domain(url)
            if domain and domain not in seen:
                seen.add(domain)
                wordlist = load_wordlist(config.subdomain_wordlist, "subdomains.txt")
                subs = await enumerate_subdomains(domain, config, wordlist, _progress)
                subdomain_results.extend(subs)
                stats.subdomains_found += len(subs)

    # ── Phase 4: Port scanning ──────────────────────────────────────────────
    port_scan_results: List[ScanResult] = []
    if config.port_scan_enabled:
        seen = set()
        for url in urls:
            domain = extract_domain(url)
            if domain and domain not in seen:
                seen.add(domain)
                ports = list(config.common_ports[: config.max_scan_ports])
                logger.info("Scanning %d ports on %s", len(ports), domain)
                scan_res = await scan_ports(domain, ports, config.scan_timeout, _progress)
                open_ports = [r for r in scan_res if r.open]
                port_scan_results.extend(open_ports)
                stats.open_ports += len(open_ports)

    # ── Phase 5: Path discovery ─────────────────────────────────────────────
    path_results: List[PathResult] = []
    if config.path_discovery_enabled:
        wordlist = load_wordlist(config.path_wordlist, "paths.txt")
        base_urls = [r.url for r in results if r.success]
        for base_url in base_urls[:1]:
            logger.info("Discovering paths on %s (%d words)", base_url, len(wordlist))
            paths = await discover_paths(base_url, wordlist, config, _progress)
            path_results.extend(paths)
            stats.paths_found += len(paths)

    return AuditReport(
        results=results,
        statistics=stats,
        config=config,
        tls_results=tls_results,
        subdomain_results=subdomain_results,
        port_scan_results=port_scan_results,
        path_results=path_results,
    )


def main(argv: Optional[List[str]] = None) -> int:
    try:
        ns = parse_args(argv)
        config = config_from_namespace(ns)
        configure_logging(config.log_level)

        urls = load_urls(ns.target)
        report = asyncio.run(_run(config, urls))

        if config.output_json:
            report.to_json(config.output_json)
        if config.output_csv:
            report.to_csv(config.output_csv)
        if config.output_html:
            report.to_html(config.output_html)

        print(report.summary_text(), file=sys.stderr)
        logger.info("Audit completed successfully.")
        return 0

    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAudit cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        logger.exception("Unexpected error")
        print(f"UNEXPECTED ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
