"""Tests for utils module."""

from __future__ import annotations

import pytest

from http_auditor_ultra.utils import (
    AuditStatistics,
    RetryState,
    is_retryable,
    load_urls,
    validate_url,
)


class TestValidateURL:
    def test_valid_https(self) -> None:
        assert validate_url("https://example.com") == "https://example.com"

    def test_valid_http(self) -> None:
        assert validate_url("http://example.com/path") == "http://example.com/path"

    def test_no_scheme_defaults_https(self) -> None:
        assert validate_url("example.com") == "https://example.com"

    def test_invalid_scheme(self) -> None:
        assert validate_url("ftp://example.com") is None

    def test_empty_returns_none(self) -> None:
        assert validate_url("") is None

    def test_strips_whitespace(self) -> None:
        assert validate_url("  https://example.com  ") == "https://example.com"

    def test_url_with_port(self) -> None:
        assert validate_url("https://example.com:8080/api") == "https://example.com:8080/api"

    def test_truly_broken_url(self) -> None:
        assert validate_url("://broken") is None


class TestLoadURLs:
    def test_single_url(self) -> None:
        assert load_urls("https://example.com") == ["https://example.com"]

    def test_invalid_url_raises(self) -> None:
        with pytest.raises(ValueError):
            load_urls("://broken")


class TestRetryState:
    def test_initial(self) -> None:
        s = RetryState()
        assert s.attempt == 0
        assert not s.is_exhausted

    def test_exponential_delay(self) -> None:
        s = RetryState(backoff=1.0, jitter=0)
        assert abs(s.delay - 1.0) < 0.01
        assert abs(s.next().delay - 2.0) < 0.01
        assert abs(s.next().next().delay - 4.0) < 0.01

    def test_exhausted(self) -> None:
        assert RetryState(max_retries=2, attempt=3).is_exhausted

    def test_not_exhausted(self) -> None:
        assert not RetryState(max_retries=3, attempt=2).is_exhausted


class TestAuditStatistics:
    def test_defaults(self) -> None:
        s = AuditStatistics()
        assert s.total_urls == 0
        assert s.wafs_detected == 0
        assert s.tls_issues == 0

    def test_record_status(self) -> None:
        s = AuditStatistics()
        s.record_status(200)
        s.record_status(200)
        s.record_status(404)
        assert s.status_counts == {200: 2, 404: 1}

    def test_summary_keys(self) -> None:
        s = AuditStatistics(total_urls=5, successful=4, failed=1, total_time_sec=2.5)
        summary = s.summary()
        assert summary["total_urls"] == 5
        assert summary["success_rate_percent"] == 80.0
        assert "subdomains_found" in summary
        assert "wafs_detected" in summary
        assert "tls_security_issues" in summary


class TestIsRetryable:
    def test_429(self) -> None:
        assert is_retryable(429) is True

    def test_500(self) -> None:
        assert is_retryable(500) is True

    def test_503(self) -> None:
        assert is_retryable(503) is True

    def test_200(self) -> None:
        assert is_retryable(200) is False

    def test_404(self) -> None:
        assert is_retryable(404) is False
