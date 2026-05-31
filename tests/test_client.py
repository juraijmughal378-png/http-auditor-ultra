"""Tests for HTTP client module."""

from __future__ import annotations

import httpx
import pytest
import respx

from http_auditor_ultra.client import AuditResult, HttpClient
from http_auditor_ultra.config import AuditorConfig


@pytest.fixture
def config() -> AuditorConfig:
    return AuditorConfig(
        timeout=5.0,
        max_retries=1,
        backoff_factor=0.01,
        max_concurrent=5,
        rate_limit_delay=0.0,
        verify_ssl=False,
        fingerprint_enabled=False,
        tls_audit_enabled=False,
        log_level="DEBUG",
    )


@pytest.mark.asyncio
async def test_successful_request(config: AuditorConfig) -> None:
    with respx.mock:
        route = respx.get("https://example.com/") % httpx.Response(200, json={"ok": True})
        async with HttpClient(config) as client:
            result = await client.audit_url("https://example.com/")
        assert route.called
        assert result.status_code == 200
        assert result.success is True
        assert result.error is None


@pytest.mark.asyncio
async def test_404_no_retry(config: AuditorConfig) -> None:
    with respx.mock:
        route = respx.get("https://example.com/nf") % httpx.Response(404)
        async with HttpClient(config) as client:
            result = await client.audit_url("https://example.com/nf")
        assert result.status_code == 404
        assert result.client_error is True
        assert route.call_count == 1  # no retry on 404


@pytest.mark.asyncio
async def test_retry_on_500(config: AuditorConfig) -> None:
    with respx.mock:
        route = respx.get("https://example.com/retry")
        route.side_effect = [httpx.Response(500), httpx.Response(200)]
        async with HttpClient(config) as client:
            result = await client.audit_url("https://example.com/retry")
        assert route.call_count == 2
        assert result.status_code == 200
        assert result.success is True


@pytest.mark.asyncio
async def test_retry_exhaustion(config: AuditorConfig) -> None:
    with respx.mock:
        route = respx.get("https://example.com/bad")
        route.side_effect = [httpx.Response(503), httpx.Response(503)]
        async with HttpClient(config) as client:
            result = await client.audit_url("https://example.com/bad")
        assert route.call_count == 2
        assert result.error is not None


@pytest.mark.asyncio
async def test_timeout(config: AuditorConfig) -> None:
    with respx.mock:
        route = respx.get("https://example.com/timeout")
        route.side_effect = httpx.TimeoutException("timed out")
        async with HttpClient(config) as client:
            result = await client.audit_url("https://example.com/timeout")
        assert result.error is not None
        assert "Timeout" in result.error


@pytest.mark.asyncio
async def test_batch_audit(config: AuditorConfig) -> None:
    urls = ["https://example.com/a", "https://example.com/b", "https://example.com/c"]
    with respx.mock:
        for u in urls:
            respx.get(u) % httpx.Response(200)
        async with HttpClient(config) as client:
            results = await client.audit_urls(urls)
        assert len(results) == 3
        assert all(r.success for r in results)
        assert client.stats.total_urls == 3
        assert client.stats.successful == 3


@pytest.mark.asyncio
async def test_body_snippet_captured(config: AuditorConfig) -> None:
    with respx.mock:
        respx.get("https://example.com/body") % httpx.Response(200, text="Hello world")
        async with HttpClient(config) as client:
            result = await client.audit_url("https://example.com/body", collect_body=True)
        assert "Hello world" in result.body_snippet
