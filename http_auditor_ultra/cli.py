"""CLI for HTTP Auditor Ultra."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Sequence

from http_auditor_ultra._version import __version__
from http_auditor_ultra.config import AuditorConfig


def _positive_float(value: str) -> float:
    try:
        f = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid float: {value!r}")
    if f <= 0:
        raise argparse.ArgumentTypeError(f"Value must be positive: {value!r}")
    return f


def _non_negative_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid integer: {value!r}")
    if n < 0:
        raise argparse.ArgumentTypeError(f"Value must be >= 0: {value!r}")
    return n


def _port_list(value: str) -> List[int]:
    try:
        ports = [int(p.strip()) for p in value.split(",") if p.strip()]
        if not ports:
            raise ValueError
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range: {p}")
        return ports
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid port list {value!r}. Use comma-separated integers e.g. 80,443,8080. {exc}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="http-auditor-ultra",
        description=(
            "HTTP Auditor Ultra — Advanced HTTP auditing & reconnaissance "
            "for authorized security assessments."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s https://example.com\n"
            "  %(prog)s target.com --subdomains --html report.html\n"
            "  %(prog)s urls.txt --scan-ports --discover-paths --json report.json\n"
            "  %(prog)s https://example.com --config ultra.yaml --log-level DEBUG\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", type=str,
                        help="Target URL, domain, or path to URL list file")
    parser.add_argument("-c", "--config", type=Path, metavar="FILE",
                        help="YAML/JSON configuration file")

    conn = parser.add_argument_group("Connection settings")
    conn.add_argument("--timeout", type=_positive_float, metavar="SECONDS")
    conn.add_argument("--max-retries", dest="max_retries", type=_non_negative_int, metavar="N")
    conn.add_argument("--backoff-factor", dest="backoff_factor", type=_positive_float, metavar="SECONDS")
    conn.add_argument("--max-concurrent", dest="max_concurrent", type=_non_negative_int, metavar="N")
    conn.add_argument("--rate-limit-delay", dest="rate_limit_delay", type=_positive_float, metavar="SECONDS")
    conn.add_argument("--user-agent", dest="user_agent", type=str, metavar="STRING")
    conn.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl",
                      help="Disable SSL certificate verification")
    conn.add_argument("--no-follow-redirects", action="store_false", dest="follow_redirects",
                      help="Do not follow HTTP redirects")

    ultra = parser.add_argument_group("Ultra scanning modules")
    ultra.add_argument("--no-fingerprint", action="store_false", dest="fingerprint_enabled",
                       help="Disable WAF/tech fingerprinting")
    ultra.add_argument("--no-tls", action="store_false", dest="tls_audit_enabled",
                       help="Disable TLS/SSL audit")
    ultra.add_argument("--subdomains", action="store_true", dest="subdomain_enum_enabled",
                       help="Enable subdomain enumeration (DNS + CT logs)")
    ultra.add_argument("--subdomain-wordlist", dest="subdomain_wordlist", type=Path, metavar="FILE")
    ultra.add_argument("--scan-ports", action="store_true", dest="port_scan_enabled",
                       help="Enable port scanning")
    ultra.add_argument("--custom-ports", dest="custom_ports", type=_port_list, metavar="80,443,8080")
    ultra.add_argument("--scan-timeout", dest="scan_timeout", type=_positive_float, metavar="SECONDS")
    ultra.add_argument("--discover-paths", action="store_true", dest="path_discovery_enabled",
                       help="Enable path/directory discovery")
    ultra.add_argument("--path-wordlist", dest="path_wordlist", type=Path, metavar="FILE")

    out = parser.add_argument_group("Output settings")
    out.add_argument("-j", "--json", dest="output_json", type=Path, metavar="FILE")
    out.add_argument("--csv", dest="output_csv", type=Path, metavar="FILE")
    out.add_argument("--html", dest="output_html", type=Path, metavar="FILE")

    parser.add_argument("--log-level", type=str.upper, metavar="LEVEL",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    return parser


def parse_args(args: Optional[Sequence[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(args)


def config_from_namespace(ns: argparse.Namespace) -> AuditorConfig:
    """Build AuditorConfig from parsed CLI args. CLI overrides config file."""
    overrides: dict = {}

    if getattr(ns, "config", None) is not None:
        file_config = AuditorConfig.from_file(ns.config)
        overrides.update(file_config.to_dict())

    for attr in (
        "timeout", "max_retries", "backoff_factor", "max_concurrent",
        "rate_limit_delay", "user_agent", "log_level",
        "output_json", "output_csv", "output_html",
        "fingerprint_enabled", "tls_audit_enabled",
        "subdomain_enum_enabled", "port_scan_enabled",
        "path_discovery_enabled", "scan_timeout",
        "subdomain_wordlist", "path_wordlist",
    ):
        val = getattr(ns, attr, None)
        if val is not None:
            overrides[attr] = val

    # Boolean flags: argparse sets False when --no-X is used
    for attr in ("verify_ssl", "follow_redirects"):
        val = getattr(ns, attr, None)
        if val is not None:
            overrides[attr] = val

    custom_ports = getattr(ns, "custom_ports", None)
    if custom_ports is not None:
        overrides["common_ports"] = tuple(custom_ports)

    return AuditorConfig.from_dict(overrides)
