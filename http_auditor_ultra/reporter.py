"""Report generation — Ultra Edition with JSON, CSV, and HTML output."""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from http_auditor_ultra.client import AuditResult
from http_auditor_ultra.config import AuditorConfig
from http_auditor_ultra.utils import AuditStatistics

logger = logging.getLogger(__name__)

_CSV_FIELD_NAMES: List[str] = [
    "url", "status_code", "success", "response_time_seconds",
    "content_length", "server", "redirect_url", "error", "retries",
    "http_method", "waf_detected", "tech_stack",
]


class AuditReport:
    """Complete audit report with results, statistics, and all Ultra findings."""

    def __init__(
        self,
        results: List[AuditResult],
        statistics: AuditStatistics,
        config: AuditorConfig,
        tls_results: Optional[List[Any]] = None,
        subdomain_results: Optional[List[Any]] = None,
        port_scan_results: Optional[List[Any]] = None,
        path_results: Optional[List[Any]] = None,
    ) -> None:
        self.results = results
        self.statistics = statistics
        self.config = config
        self.tls_results = tls_results or []
        self.subdomain_results = subdomain_results or []
        self.port_scan_results = port_scan_results or []
        self.path_results = path_results or []

    # -- JSON ---------------------------------------------------------------

    def to_json(self, path: Optional[Path] = None) -> Optional[str]:
        """Generate a JSON report. Writes to file if path given, else returns string."""
        data: Dict[str, object] = {
            "metadata": {
                "tool": "HTTP Auditor Ultra",
                "version": "2.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "config": self.config.to_dict(),
            },
            "statistics": self.statistics.summary(),
            "results": [r.to_dict() for r in self.results],
            "tls_audit": [t.to_dict() for t in self.tls_results],
            "subdomains": [s.to_dict() for s in self.subdomain_results],
            "port_scan": [p.to_dict() for p in self.port_scan_results],
            "paths_discovered": [p.to_dict() for p in self.path_results],
        }
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        if path is not None:
            path.write_text(json_str, encoding="utf-8")
            logger.info("JSON report written to %s", path)
            return None
        return json_str

    # -- CSV ----------------------------------------------------------------

    def to_csv(self, path: Optional[Path] = None) -> Optional[str]:
        """Generate a CSV report. Writes to file if path given, else returns string."""
        if path is None:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=_CSV_FIELD_NAMES)
            writer.writeheader()
            for result in self.results:
                writer.writerow(result.to_csv_row())
            csv_str = buf.getvalue()
            buf.close()
            return csv_str

        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=_CSV_FIELD_NAMES)
            writer.writeheader()
            for result in self.results:
                writer.writerow(result.to_csv_row())
        logger.info("CSV report written to %s", path)
        return None

    # -- HTML ---------------------------------------------------------------

    def to_html(self, path: Optional[Path] = None) -> Optional[str]:
        """Generate a dark-themed HTML dashboard report."""
        stats = self.statistics.summary()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # --- results table rows ---
        results_rows = ""
        for r in self.results:
            if r.error:
                cls = "error"
            elif r.success:
                cls = "success"
            else:
                cls = "warn"
            tech = "; ".join(r.tech_stack) if r.tech_stack else ""
            results_rows += (
                f"<tr>"
                f"<td>{r.url}</td>"
                f"<td class='{cls}'>{r.status_code}</td>"
                f"<td>{r.response_time:.3f}s</td>"
                f"<td>{r.content_length}</td>"
                f"<td>{r.server or ''}</td>"
                f"<td>{r.waf_name or ''}</td>"
                f"<td>{tech}</td>"
                f"<td class='error'>{r.error or ''}</td>"
                f"</tr>\n"
            )

        # --- TLS rows ---
        tls_rows = ""
        for t in self.tls_results:
            weak = "<span class='error'>YES</span>" if getattr(t, "weak_signature", False) else "No"
            exp = "<span class='error'>EXPIRED</span>" if getattr(t, "is_expired", False) else (
                "<span class='warn'>SOON</span>" if getattr(t, "is_expiring_soon", False) else "OK"
            )
            tls_rows += (
                f"<tr>"
                f"<td>{getattr(t, 'hostname', '')}</td>"
                f"<td>{getattr(t, 'tls_version', '')}</td>"
                f"<td>{getattr(t, 'cipher_suite', '')}</td>"
                f"<td>{getattr(t, 'days_remaining', '')}d</td>"
                f"<td>{weak}</td>"
                f"<td>{exp}</td>"
                f"<td class='error'>{getattr(t, 'error', '') or ''}</td>"
                f"</tr>\n"
            )

        # --- subdomain rows ---
        sub_rows = "".join(
            f"<tr><td>{getattr(s, 'subdomain', '')}</td>"
            f"<td>{getattr(s, 'resolved', '')}</td>"
            f"<td>{getattr(s, 'source', '')}</td></tr>\n"
            for s in self.subdomain_results
        )

        # --- port rows (open only) ---
        port_rows = "".join(
            f"<tr><td>{getattr(p, 'host', '')}</td>"
            f"<td>{getattr(p, 'port', '')}</td>"
            f"<td>{getattr(p, 'service', '')}</td></tr>\n"
            for p in self.port_scan_results
            if getattr(p, "open", False)
        )

        # --- path rows ---
        path_rows = "".join(
            f"<tr><td>{getattr(p, 'url', '')}</td>"
            f"<td>{getattr(p, 'status_code', '')}</td>"
            f"<td>{getattr(p, 'size', '')}</td></tr>\n"
            for p in self.path_results
        )

        def _card(value: Any, label: str, color: str = "#58a6ff") -> str:
            return (
                f'<div class="card">'
                f'<div class="value" style="color:{color}">{value}</div>'
                f'<div class="label">{label}</div>'
                f'</div>'
            )

        cards = (
            _card(stats["total_urls"], "URLs Scanned")
            + _card(stats["successful"], "Successful", "#3fb950")
            + _card(stats["failed"], "Failed", "#f85149")
            + _card(f"{stats['success_rate_percent']}%", "Success Rate")
            + _card(f"{stats['total_time_seconds']}s", "Duration")
            + _card(stats["retried"], "Retries")
            + _card(stats["subdomains_found"], "Subdomains")
            + _card(stats["open_ports_found"], "Open Ports")
            + _card(stats["paths_found"], "Paths Found")
            + _card(stats["wafs_detected"], "WAFs Detected", "#d29922")
            + _card(stats["tls_security_issues"], "TLS Issues", "#d29922")
            + _card(stats["missing_security_headers"], "Missing Sec Headers", "#d29922")
        )

        extra_sections = ""
        if tls_rows:
            extra_sections += f"""
  <h3 class="section-title">TLS / SSL Certificate Analysis</h3>
  <table>
    <thead><tr><th>Host</th><th>TLS Version</th><th>Cipher</th><th>Expires In</th><th>Weak Sig</th><th>Status</th><th>Error</th></tr></thead>
    <tbody>{tls_rows}</tbody>
  </table>"""

        if sub_rows:
            extra_sections += f"""
  <h3 class="section-title">Subdomain Enumeration ({len(self.subdomain_results)} found)</h3>
  <table>
    <thead><tr><th>Subdomain</th><th>Resolved IP</th><th>Source</th></tr></thead>
    <tbody>{sub_rows}</tbody>
  </table>"""

        if port_rows:
            extra_sections += f"""
  <h3 class="section-title">Open Ports</h3>
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Service</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>"""

        if path_rows:
            extra_sections += f"""
  <h3 class="section-title">Discovered Paths ({len(self.path_results)} found)</h3>
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>Size (bytes)</th></tr></thead>
    <tbody>{path_rows}</tbody>
  </table>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HTTP Auditor Ultra — Report</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#e6edf3;padding:24px}}
  .container{{max-width:1440px;margin:0 auto}}
  h1{{color:#58a6ff;font-size:1.8rem;margin-bottom:4px}}
  .subtitle{{color:#8b949e;font-size:.9rem;margin-bottom:28px}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:32px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}}
  .card .value{{font-size:1.7rem;font-weight:700}}
  .card .label{{font-size:.75rem;color:#8b949e;margin-top:6px;text-transform:uppercase;letter-spacing:.05em}}
  .section-title{{color:#58a6ff;font-size:1.1rem;margin:28px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;margin-bottom:8px;font-size:.83rem}}
  th{{background:#21262d;color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;padding:9px 12px;text-align:left;border-bottom:1px solid #30363d}}
  td{{padding:7px 12px;border-bottom:1px solid #1c2128;word-break:break-all}}
  tr:last-child td{{border-bottom:none}}
  tr:hover{{background:#1c2128}}
  .success{{color:#3fb950;font-weight:600}}
  .warn{{color:#d29922;font-weight:600}}
  .error{{color:#f85149}}
  footer{{text-align:center;color:#8b949e;font-size:.75rem;margin-top:48px;padding-top:16px;border-top:1px solid #21262d}}
</style>
</head>
<body>
<div class="container">
  <h1>&#x1F6E1; HTTP Auditor Ultra</h1>
  <div class="subtitle">Security Audit Report &mdash; {ts}</div>

  <div class="summary">{cards}</div>

  <h3 class="section-title">HTTP Responses ({len(self.results)} URLs)</h3>
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>Time</th><th>Size</th><th>Server</th><th>WAF</th><th>Tech Stack</th><th>Error</th></tr></thead>
    <tbody>{results_rows}</tbody>
  </table>
  {extra_sections}
  <footer>Generated by <strong>HTTP Auditor Ultra v2.0.0</strong></footer>
</div>
</body>
</html>"""

        if path is not None:
            path.write_text(html, encoding="utf-8")
            logger.info("HTML report written to %s", path)
            return None
        return html

    # -- Console summary ----------------------------------------------------

    def summary_text(self) -> str:
        stats = self.statistics.summary()
        lines: List[str] = [
            "=" * 68,
            "  HTTP Auditor Ultra v2.0.0 — Execution Summary",
            "=" * 68,
            f"  URLs scanned:           {stats['total_urls']}",
            f"  Successful:             {stats['successful']}",
            f"  Failed:                 {stats['failed']}",
            f"  Retries performed:      {stats['retried']}",
            f"  Success rate:           {stats['success_rate_percent']}%",
            f"  Total time:             {stats['total_time_seconds']}s",
            f"  Avg time / URL:         {stats['average_time_per_url_seconds']}s",
            "",
            "  Ultra findings:",
            f"  Subdomains discovered:  {stats['subdomains_found']}",
            f"  Paths discovered:       {stats['paths_found']}",
            f"  Open ports found:       {stats['open_ports_found']}",
            f"  WAFs detected:          {stats['wafs_detected']}",
            f"  TLS security issues:    {stats['tls_security_issues']}",
            f"  Missing sec headers:    {stats['missing_security_headers']}",
            "",
            "  Status code distribution:",
        ]
        for code, count in stats["unique_status_codes"].items():  # type: ignore[union-attr]
            lines.append(f"    HTTP {code}: {count}")
        if stats["error_count"]:
            lines.append("")
            lines.append("  Errors:")
            for err in self.statistics.errors:
                lines.append(f"    - {err}")
        lines.append("=" * 68)
        return "\n".join(lines)
