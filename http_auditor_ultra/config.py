"""Configuration management — Ultra edition."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Self

import yaml

_DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

_DEFAULT_TIMEOUT_SECONDS: float = 30.0
_DEFAULT_MAX_RETRIES: int = 3
_DEFAULT_BACKOFF_FACTOR: float = 1.0
_DEFAULT_MAX_CONCURRENT: int = 10
_DEFAULT_RATE_LIMIT_DELAY: float = 0.0
_DEFAULT_COMMON_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 8888, 9443)

_VALID_LOG_LEVELS: frozenset[str] = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


@dataclass(frozen=True)
class AuditorConfig:
    """Immutable configuration container — Ultra edition."""

    # Base
    timeout: float = _DEFAULT_TIMEOUT_SECONDS
    max_retries: int = _DEFAULT_MAX_RETRIES
    backoff_factor: float = _DEFAULT_BACKOFF_FACTOR
    max_concurrent: int = _DEFAULT_MAX_CONCURRENT
    rate_limit_delay: float = _DEFAULT_RATE_LIMIT_DELAY
    user_agent: str = _DEFAULT_USER_AGENT
    headers: Dict[str, str] = field(default_factory=dict)
    verify_ssl: bool = True
    follow_redirects: bool = True
    log_level: str = "INFO"

    # Ultra modules
    fingerprint_enabled: bool = True
    tls_audit_enabled: bool = True
    subdomain_enum_enabled: bool = False
    port_scan_enabled: bool = False
    path_discovery_enabled: bool = False

    common_ports: tuple[int, ...] = _DEFAULT_COMMON_PORTS
    subdomain_wordlist: Optional[Path] = None
    path_wordlist: Optional[Path] = None
    max_scan_ports: int = 100
    scan_timeout: float = 3.0

    # Output
    output_json: Optional[Path] = None
    output_csv: Optional[Path] = None
    output_html: Optional[Path] = None
    config_file: Optional[Path] = None

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError(f"timeout must be >0, got {self.timeout}")
        if self.max_retries < 0:
            raise ValueError(f"max_retries must be >=0, got {self.max_retries}")
        if self.backoff_factor < 0:
            raise ValueError(f"backoff_factor must be >=0, got {self.backoff_factor}")
        if self.max_concurrent < 1:
            raise ValueError(f"max_concurrent must be >=1, got {self.max_concurrent}")
        if self.rate_limit_delay < 0:
            raise ValueError(f"rate_limit_delay must be >=0, got {self.rate_limit_delay}")
        if self.log_level.upper() not in _VALID_LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(_VALID_LOG_LEVELS)}, got {self.log_level!r}")
        if self.max_scan_ports < 1:
            raise ValueError(f"max_scan_ports must be >=1, got {self.max_scan_ports}")
        if self.scan_timeout <= 0:
            raise ValueError(f"scan_timeout must be >0, got {self.scan_timeout}")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        known_keys: set[str] = {
            "timeout", "max_retries", "backoff_factor", "max_concurrent",
            "rate_limit_delay", "user_agent", "headers", "verify_ssl",
            "follow_redirects", "log_level",
            "fingerprint_enabled", "tls_audit_enabled",
            "subdomain_enum_enabled", "port_scan_enabled", "path_discovery_enabled",
            "common_ports", "subdomain_wordlist", "path_wordlist",
            "max_scan_ports", "scan_timeout",
            "output_json", "output_csv", "output_html",
        }
        filtered = {k: v for k, v in data.items() if k in known_keys}
        for path_key in ("output_json", "output_csv", "output_html",
                         "subdomain_wordlist", "path_wordlist"):
            value = filtered.get(path_key)
            if isinstance(value, str):
                filtered[path_key] = Path(value)
        if "common_ports" in filtered and isinstance(filtered["common_ports"], list):
            filtered["common_ports"] = tuple(filtered["common_ports"])
        return cls(**filtered)

    @classmethod
    def from_file(cls, path: Path) -> Self:
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        suffix = path.suffix.lower()
        raw = path.read_text(encoding="utf-8")
        if suffix in {".yaml", ".yml"}:
            data: Dict[str, Any] = yaml.safe_load(raw) or {}
        elif suffix == ".json":
            data = json.loads(raw) or {}
        else:
            raise ValueError(f"Unsupported config file type: {suffix!r}. Use .yaml, .yml, or .json.")
        if not isinstance(data, dict):
            raise ValueError(f"Config file must contain a top-level object (dict), got {type(data).__name__}")
        config: Self = cls.from_dict(data)
        object.__setattr__(config, "config_file", path)
        return config

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "backoff_factor": self.backoff_factor,
            "max_concurrent": self.max_concurrent,
            "rate_limit_delay": self.rate_limit_delay,
            "user_agent": self.user_agent,
            "headers": self.headers,
            "verify_ssl": self.verify_ssl,
            "follow_redirects": self.follow_redirects,
            "log_level": self.log_level,
            "fingerprint_enabled": self.fingerprint_enabled,
            "tls_audit_enabled": self.tls_audit_enabled,
            "subdomain_enum_enabled": self.subdomain_enum_enabled,
            "port_scan_enabled": self.port_scan_enabled,
            "path_discovery_enabled": self.path_discovery_enabled,
            "common_ports": list(self.common_ports),
            "max_scan_ports": self.max_scan_ports,
            "scan_timeout": self.scan_timeout,
            "output_json": str(self.output_json) if self.output_json else None,
            "output_csv": str(self.output_csv) if self.output_csv else None,
            "output_html": str(self.output_html) if self.output_html else None,
            "subdomain_wordlist": str(self.subdomain_wordlist) if self.subdomain_wordlist else None,
            "path_wordlist": str(self.path_wordlist) if self.path_wordlist else None,
        }


def default_config() -> AuditorConfig:
    return AuditorConfig()
