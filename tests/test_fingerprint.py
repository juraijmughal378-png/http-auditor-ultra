"""Tests for WAF detection, tech fingerprinting, and security header analysis."""

from __future__ import annotations

import pytest

from http_auditor_ultra.client import AuditResult
from http_auditor_ultra.fingerprint import (
    analyze_security_headers,
    compute_security_header_score,
    detect_tech_stack,
    detect_waf,
)


def _result(headers: dict, body: str = "", status: int = 200, size: int = 1000) -> AuditResult:
    return AuditResult(
        url="https://example.com",
        status_code=status,
        headers=headers,
        body_snippet=body,
        content_length=size,
    )


class TestDetectWAF:
    def test_cloudflare_server_header(self) -> None:
        r = _result({"server": "cloudflare", "cf-ray": "abc123"})
        assert detect_waf(r) == "Cloudflare"

    def test_cloudflare_cf_ray_only(self) -> None:
        r = _result({"cf-ray": "7abc123-LHR"})
        assert detect_waf(r) == "Cloudflare"

    def test_akamai_detected(self) -> None:
        r = _result({"server": "AkamaiGHost"})
        assert detect_waf(r) == "Akamai GHOST"

    def test_aws_waf_header(self) -> None:
        r = _result({"x-amzn-requestid": "req-abc123"})
        assert "AWS" in (detect_waf(r) or "")

    def test_imperva_header(self) -> None:
        r = _result({"x-iinfo": "12-34567890-0"})
        assert "Imperva" in (detect_waf(r) or "")

    def test_no_waf(self) -> None:
        r = _result({"server": "nginx/1.24.0", "content-type": "text/html"})
        assert detect_waf(r) is None

    def test_heuristic_403_block(self) -> None:
        r = _result({"server": "nginx"}, body="access denied by firewall", status=403, size=200)
        waf = detect_waf(r)
        assert waf is not None
        assert "heuristic" in (waf or "").lower()

    def test_heuristic_not_triggered_large_body(self) -> None:
        # Large body should NOT trigger heuristic
        r = _result({"server": "nginx"}, body="access denied by firewall", status=403, size=5000)
        waf = detect_waf(r)
        assert waf is None


class TestDetectTechStack:
    def test_nginx(self) -> None:
        r = _result({"server": "nginx/1.24.0"})
        assert "Nginx" in detect_tech_stack(r)

    def test_apache(self) -> None:
        r = _result({"server": "Apache/2.4.51"})
        assert "Apache" in detect_tech_stack(r)

    def test_php(self) -> None:
        r = _result({"x-powered-by": "PHP/8.2.0"})
        assert "PHP" in detect_tech_stack(r)

    def test_aspnet(self) -> None:
        r = _result({"x-powered-by": "ASP.NET"})
        assert "ASP.NET" in detect_tech_stack(r)

    def test_wordpress_body(self) -> None:
        r = _result({"server": "nginx"}, body="loading wp-content/themes/twentytwentyfour")
        assert "WordPress" in detect_tech_stack(r)

    def test_cloudfront_cdn(self) -> None:
        r = _result({"x-amz-cf-id": "abc123xyz"})
        assert "CloudFront" in detect_tech_stack(r)

    def test_no_tech(self) -> None:
        r = _result({"server": "unknown-server-xyz"})
        assert detect_tech_stack(r) == []


class TestSecurityHeaders:
    def test_all_present_high_score(self) -> None:
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "x-xss-protection": "1; mode=block",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
            "cross-origin-resource-policy": "same-origin",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
        }
        r = _result(headers)
        analysis = analyze_security_headers(r)
        score = compute_security_header_score(analysis)
        assert score == 100

    def test_none_present_zero_score(self) -> None:
        r = _result({})
        analysis = analyze_security_headers(r)
        score = compute_security_header_score(analysis)
        assert score == 0

    def test_partial_score(self) -> None:
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-xss-protection": "1; mode=block",
        }
        r = _result(headers)
        analysis = analyze_security_headers(r)
        score = compute_security_header_score(analysis)
        assert 0 < score < 100

    def test_analysis_has_severity(self) -> None:
        r = _result({})
        analysis = analyze_security_headers(r)
        for header_data in analysis.values():
            assert "severity" in header_data
            assert header_data["severity"] in ("HIGH", "MEDIUM", "LOW")

    def test_missing_has_recommended(self) -> None:
        r = _result({})
        analysis = analyze_security_headers(r)
        for header_data in analysis.values():
            assert header_data["status"] == "missing"
            assert header_data["recommended"] is not None
