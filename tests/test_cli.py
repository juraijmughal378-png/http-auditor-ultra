"""Tests for CLI argument parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from http_auditor_ultra.cli import build_parser, config_from_namespace, parse_args


class TestArgparse:
    def test_minimal(self) -> None:
        ns = parse_args(["https://example.com"])
        assert ns.target == "https://example.com"

    def test_all_ultra_flags(self) -> None:
        ns = parse_args([
            "https://example.com",
            "--subdomains",
            "--scan-ports",
            "--discover-paths",
            "--no-tls",
            "--no-fingerprint",
        ])
        assert ns.subdomain_enum_enabled is True
        assert ns.port_scan_enabled is True
        assert ns.path_discovery_enabled is True
        assert ns.tls_audit_enabled is False
        assert ns.fingerprint_enabled is False

    def test_output_flags(self) -> None:
        ns = parse_args([
            "https://example.com",
            "--json", "out.json",
            "--csv", "out.csv",
            "--html", "out.html",
        ])
        assert ns.output_json == Path("out.json")
        assert ns.output_csv == Path("out.csv")
        assert ns.output_html == Path("out.html")

    def test_custom_ports(self) -> None:
        ns = parse_args(["https://example.com", "--custom-ports", "80,443,8080"])
        assert ns.custom_ports == [80, 443, 8080]

    def test_version(self) -> None:
        with pytest.raises(SystemExit) as exc:
            parse_args(["--version"])
        assert exc.value.code == 0

    def test_no_verify_ssl(self) -> None:
        ns = parse_args(["https://example.com", "--no-verify-ssl"])
        assert ns.verify_ssl is False


class TestConfigFromNamespace:
    def test_defaults(self) -> None:
        ns = parse_args(["https://example.com"])
        cfg = config_from_namespace(ns)
        assert cfg.timeout == 30.0
        assert cfg.max_retries == 3
        assert cfg.log_level == "INFO"

    def test_cli_overrides(self) -> None:
        ns = parse_args([
            "https://example.com",
            "--timeout", "45",
            "--max-retries", "5",
            "--log-level", "DEBUG",
        ])
        cfg = config_from_namespace(ns)
        assert cfg.timeout == 45.0
        assert cfg.max_retries == 5
        assert cfg.log_level == "DEBUG"

    def test_custom_ports_become_tuple(self) -> None:
        ns = parse_args(["https://example.com", "--custom-ports", "80,443"])
        cfg = config_from_namespace(ns)
        assert isinstance(cfg.common_ports, tuple)
        assert cfg.common_ports == (80, 443)

    def test_ultra_flags_enabled(self) -> None:
        ns = parse_args(["https://example.com", "--subdomains", "--scan-ports"])
        cfg = config_from_namespace(ns)
        assert cfg.subdomain_enum_enabled is True
        assert cfg.port_scan_enabled is True
