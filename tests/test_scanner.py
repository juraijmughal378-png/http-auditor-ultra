"""Tests for scanner module."""

from __future__ import annotations

import pytest

from http_auditor_ultra.config import AuditorConfig
from http_auditor_ultra.scanner import (
    PathResult,
    ScanResult,
    SubdomainResult,
    discover_paths,
    scan_ports,
)


class TestDataClasses:
    def test_scan_result_to_dict(self) -> None:
        r = ScanResult(host="example.com", port=443, open=True, service="HTTPS")
        d = r.to_dict()
        assert d["host"] == "example.com"
        assert d["port"] == 443
        assert d["open"] is True
        assert d["service"] == "HTTPS"

    def test_subdomain_result_to_dict(self) -> None:
        r = SubdomainResult(subdomain="admin.example.com", resolved="1.2.3.4", source="dns")
        d = r.to_dict()
        assert d["subdomain"] == "admin.example.com"
        assert d["resolved"] == "1.2.3.4"
        assert d["source"] == "dns"

    def test_path_result_to_dict(self) -> None:
        r = PathResult(url="https://example.com/admin", status_code=200, size=512)
        d = r.to_dict()
        assert d["url"] == "https://example.com/admin"
        assert d["status_code"] == 200
        assert d["size"] == 512


@pytest.mark.asyncio
async def test_scan_ports_closed() -> None:
    """Scanning ports on a non-routable address should return all closed."""
    results = await scan_ports("192.0.2.1", [80, 443], timeout=0.3)
    assert len(results) == 2
    assert all(not r.open for r in results)


@pytest.mark.asyncio
async def test_discover_paths_unreachable() -> None:
    """Path discovery on unreachable host returns empty list gracefully."""
    config = AuditorConfig(
        timeout=0.5,
        max_retries=0,
        max_concurrent=3,
        verify_ssl=False,
        follow_redirects=False,
    )
    results = await discover_paths(
        "https://192.0.2.1",
        ["admin", "login"],
        config,
    )
    assert isinstance(results, list)
