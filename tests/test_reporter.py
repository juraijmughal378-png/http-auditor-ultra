"""Tests for reporter module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import List

import pytest

from http_auditor_ultra.client import AuditResult
from http_auditor_ultra.config import AuditorConfig
from http_auditor_ultra.reporter import AuditReport
from http_auditor_ultra.utils import AuditStatistics


@pytest.fixture
def sample_results() -> List[AuditResult]:
    return [
        AuditResult(url="https://example.com/", status_code=200, response_time=0.1,
                    content_length=1024, server="nginx", waf_name="Cloudflare",
                    tech_stack=["Nginx", "PHP"]),
        AuditResult(url="https://example.com/404", status_code=404, response_time=0.05),
        AuditResult(url="https://example.com/err", error="Connection refused"),
    ]


@pytest.fixture
def sample_stats() -> AuditStatistics:
    s = AuditStatistics(total_urls=3, successful=1, failed=1, retried=1, total_time_sec=2.0)
    s.record_status(200)
    s.record_status(404)
    s.wafs_detected = 1
    return s


@pytest.fixture
def report(sample_results: List[AuditResult], sample_stats: AuditStatistics) -> AuditReport:
    return AuditReport(
        results=sample_results,
        statistics=sample_stats,
        config=AuditorConfig(),
    )


class TestAuditReport:
    def test_summary_text(self, report: AuditReport) -> None:
        s = report.summary_text()
        assert "HTTP Auditor Ultra" in s
        assert "3" in s
        assert "WAFs detected" in s

    def test_to_json_string(self, report: AuditReport) -> None:
        j = report.to_json()
        assert j is not None
        data = json.loads(j)
        assert "results" in data
        assert "tls_audit" in data
        assert "subdomains" in data
        assert "port_scan" in data
        assert "paths_discovered" in data
        assert len(data["results"]) == 3

    def test_to_json_file(self, report: AuditReport) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            p = Path(f.name)
        try:
            assert report.to_json(p) is None
            data = json.loads(p.read_text())
            assert len(data["results"]) == 3
        finally:
            p.unlink(missing_ok=True)

    def test_to_csv_string(self, report: AuditReport) -> None:
        csv_str = report.to_csv()
        assert csv_str is not None
        assert "url,status_code" in csv_str
        assert "https://example.com/" in csv_str

    def test_to_csv_file(self, report: AuditReport) -> None:
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            p = Path(f.name)
        try:
            assert report.to_csv(p) is None
            content = p.read_text()
            assert "url,status_code" in content
        finally:
            p.unlink(missing_ok=True)

    def test_to_html_string(self, report: AuditReport) -> None:
        html = report.to_html()
        assert html is not None
        assert "HTTP Auditor Ultra" in html
        assert "https://example.com/" in html
        assert "Cloudflare" in html
        assert "<table>" in html

    def test_to_html_file(self, report: AuditReport) -> None:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            p = Path(f.name)
        try:
            assert report.to_html(p) is None
            content = p.read_text()
            assert "<!DOCTYPE html>" in content
        finally:
            p.unlink(missing_ok=True)
