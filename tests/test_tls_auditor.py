"""Tests for TLS auditor module."""

from __future__ import annotations

import pytest

from http_auditor_ultra.tls_auditor import TLSInfo, audit_tls


class TestTLSInfo:
    def test_defaults(self) -> None:
        info = TLSInfo(hostname="example.com")
        assert info.hostname == "example.com"
        assert info.port == 443
        assert info.error is None
        assert not info.weak_signature
        assert not info.self_signed

    def test_is_expired_false_when_no_date(self) -> None:
        info = TLSInfo(hostname="example.com", days_remaining=0, not_after="")
        assert not info.is_expired

    def test_is_expired_true(self) -> None:
        info = TLSInfo(hostname="example.com", days_remaining=-5, not_after="2020-01-01T00:00:00")
        assert info.is_expired

    def test_is_expiring_soon(self) -> None:
        info = TLSInfo(hostname="example.com", days_remaining=15, not_after="2026-06-15T00:00:00")
        assert info.is_expiring_soon

    def test_not_expiring_soon(self) -> None:
        info = TLSInfo(hostname="example.com", days_remaining=90, not_after="2026-08-30T00:00:00")
        assert not info.is_expiring_soon

    def test_to_dict_keys(self) -> None:
        info = TLSInfo(hostname="example.com", tls_version="TLSv1.3")
        d = info.to_dict()
        for key in ("hostname", "port", "tls_version", "tls_version_assessment",
                    "cipher_suite", "certificate_valid", "days_remaining",
                    "expiring_soon", "expired", "issuer", "common_name",
                    "subject_alt_names", "weak_signature", "self_signed"):
            assert key in d

    def test_tls_version_assessment_known(self) -> None:
        info = TLSInfo(hostname="example.com", tls_version="TLSv1.3")
        d = info.to_dict()
        assert "strong" in d["tls_version_assessment"]

    def test_tls_version_assessment_deprecated(self) -> None:
        info = TLSInfo(hostname="example.com", tls_version="TLSv1.1")
        d = info.to_dict()
        assert "deprecated" in d["tls_version_assessment"]


@pytest.mark.asyncio
async def test_audit_tls_unreachable() -> None:
    """TLS audit on non-routable address should return error gracefully."""
    info = await audit_tls("192.0.2.1", port=443, timeout=1.0)
    assert info.error is not None
    assert info.hostname == "192.0.2.1"


@pytest.mark.asyncio
async def test_audit_tls_invalid_hostname() -> None:
    """TLS audit on invalid hostname should return error gracefully."""
    info = await audit_tls("this-host-definitely-does-not-exist-xyz.invalid", timeout=2.0)
    assert info.error is not None
