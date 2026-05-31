"""Tests for config module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from http_auditor_ultra.config import AuditorConfig, default_config


class TestAuditorConfig:
    def test_defaults(self) -> None:
        cfg = default_config()
        assert cfg.timeout == 30.0
        assert cfg.max_retries == 3
        assert cfg.max_concurrent == 10
        assert cfg.verify_ssl is True
        assert cfg.fingerprint_enabled is True
        assert cfg.tls_audit_enabled is True
        assert cfg.subdomain_enum_enabled is False
        assert cfg.port_scan_enabled is False
        assert cfg.path_discovery_enabled is False

    def test_validation_timeout(self) -> None:
        with pytest.raises(ValueError, match="timeout"):
            AuditorConfig(timeout=-1)

    def test_validation_max_retries(self) -> None:
        with pytest.raises(ValueError, match="max_retries"):
            AuditorConfig(max_retries=-1)

    def test_validation_max_concurrent(self) -> None:
        with pytest.raises(ValueError, match="max_concurrent"):
            AuditorConfig(max_concurrent=0)

    def test_validation_log_level(self) -> None:
        with pytest.raises(ValueError, match="log_level"):
            AuditorConfig(log_level="VERBOSE")

    def test_validation_scan_timeout(self) -> None:
        with pytest.raises(ValueError, match="scan_timeout"):
            AuditorConfig(scan_timeout=-1.0)

    def test_from_dict(self) -> None:
        cfg = AuditorConfig.from_dict({"timeout": 10.0, "max_retries": 1, "log_level": "DEBUG"})
        assert cfg.timeout == 10.0
        assert cfg.max_retries == 1
        assert cfg.log_level == "DEBUG"

    def test_from_dict_common_ports_list_to_tuple(self) -> None:
        cfg = AuditorConfig.from_dict({"common_ports": [80, 443, 8080]})
        assert isinstance(cfg.common_ports, tuple)
        assert cfg.common_ports == (80, 443, 8080)

    def test_from_dict_path_conversion(self) -> None:
        cfg = AuditorConfig.from_dict({"output_json": "/tmp/out.json"})
        assert isinstance(cfg.output_json, Path)

    def test_from_yaml_file(self) -> None:
        data = {"timeout": 15.0, "max_retries": 2, "log_level": "WARNING"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            p = Path(f.name)
        try:
            cfg = AuditorConfig.from_file(p)
            assert cfg.timeout == 15.0
            assert cfg.log_level == "WARNING"
        finally:
            p.unlink(missing_ok=True)

    def test_from_json_file(self) -> None:
        data = {"timeout": 5.0, "max_concurrent": 3}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            p = Path(f.name)
        try:
            cfg = AuditorConfig.from_file(p)
            assert cfg.timeout == 5.0
            assert cfg.max_concurrent == 3
        finally:
            p.unlink(missing_ok=True)

    def test_from_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            AuditorConfig.from_file(Path("/no/such/file.yaml"))

    def test_from_file_bad_extension(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("x = 1\n")
            p = Path(f.name)
        try:
            with pytest.raises(ValueError, match="Unsupported"):
                AuditorConfig.from_file(p)
        finally:
            p.unlink(missing_ok=True)

    def test_to_dict_roundtrip(self) -> None:
        cfg = AuditorConfig(timeout=7.0, max_retries=0)
        d = cfg.to_dict()
        assert d["timeout"] == 7.0
        assert d["max_retries"] == 0
        assert "fingerprint_enabled" in d
        assert "common_ports" in d
