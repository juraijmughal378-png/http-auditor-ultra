"""Report generation — Ultra v3.0.0 with enhanced HTML dashboard."""

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
from http_auditor_ultra.fingerprint import (
    compute_security_header_score,
    get_security_grade,
)
from http_auditor_ultra.utils import AuditStatistics

logger = logging.getLogger(__name__)

_CSV_FIELD_NAMES: List[str] = [
    "url", "status_code", "success", "response_time_seconds",
    "content_length", "server", "redirect_url", "error", "retries",
    "http_method", "waf_detected", "tech_stack",
]


class AuditReport:
    """Complete audit report — Ultra v3.0.0."""

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

    def to_json(self, path: Optional[Path] = None) -> Optional[str]:
        data: Dict[str, object] = {
            "metadata": {
                "tool": "HTTP Auditor Ultra",
                "version": "3.0.0",
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

    def to_csv(self, path: Optional[Path] = None) -> Optional[str]:
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

    def to_html(self, path: Optional[Path] = None) -> Optional[str]:
        stats = self.statistics.summary()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Security score
        all_scores = []
        for r in self.results:
            if r.security_headers:
                score = compute_security_header_score(r.security_headers)
                all_scores.append(score)
        avg_score = int(sum(all_scores) / len(all_scores)) if all_scores else 0
        grade = get_security_grade(avg_score)
        grade_color = {"A+": "#3fb950", "A": "#3fb950", "B": "#58a6ff",
                       "C": "#d29922", "D": "#f85149", "F": "#f85149"}.get(grade, "#8b949e")

        # Results rows
        results_rows = ""
        for r in self.results:
            cls = "error" if r.error else ("success" if r.success else "warn")
            tech = "; ".join(r.tech_stack[:3]) if r.tech_stack else ""
            waf = f'<span class="waf-badge">{r.waf_name}</span>' if r.waf_name else ""
            score_html = ""
            if r.security_headers:
                s = compute_security_header_score(r.security_headers)
                g = get_security_grade(s)
                gc = {"A+": "#3fb950", "A": "#3fb950", "B": "#58a6ff",
                      "C": "#d29922", "D": "#f85149", "F": "#f85149"}.get(g, "#8b949e")
                score_html = f'<span style="color:{gc};font-weight:700">{g} ({s}%)</span>'
            results_rows += (
                f"<tr>"
                f"<td class='url-cell'>{r.url}</td>"
                f"<td class='{cls}'><b>{r.status_code}</b></td>"
                f"<td>{r.response_time:.3f}s</td>"
                f"<td>{r.content_length:,}</td>"
                f"<td>{r.server or ''}</td>"
                f"<td>{waf}</td>"
                f"<td>{tech}</td>"
                f"<td>{score_html}</td>"
                f"<td class='error'>{r.error or ''}</td>"
                f"</tr>\n"
            )

        # TLS rows
        tls_rows = ""
        for t in self.tls_results:
            ver = getattr(t, "tls_version", "")
            ver_color = "#3fb950" if "1.3" in ver else ("#d29922" if "1.2" in ver else "#f85149")
            weak = '<span class="error">⚠ WEAK</span>' if getattr(t, "weak_signature", False) else "✓"
            days = getattr(t, "days_remaining", 0)
            exp_color = "#f85149" if days <= 0 else ("#d29922" if days <= 30 else "#3fb950")
            exp_text = f'<span style="color:{exp_color}">{days}d</span>'
            tls_rows += (
                f"<tr>"
                f"<td><b>{getattr(t, 'hostname', '')}</b></td>"
                f"<td style='color:{ver_color}'>{ver}</td>"
                f"<td>{getattr(t, 'cipher_suite', '')}</td>"
                f"<td>{getattr(t, 'common_name', '')}</td>"
                f"<td>{exp_text}</td>"
                f"<td>{weak}</td>"
                f"<td class='error'>{getattr(t, 'error', '') or ''}</td>"
                f"</tr>\n"
            )

        sub_rows = "".join(
            f"<tr><td>{getattr(s,'subdomain','')}</td><td>{getattr(s,'resolved','')}</td>"
            f"<td><span class='badge'>{getattr(s,'source','')}</span></td></tr>\n"
            for s in self.subdomain_results
        )

        port_rows = "".join(
            f"<tr><td>{getattr(p,'host','')}</td>"
            f"<td><b>{getattr(p,'port','')}</b></td>"
            f"<td><span class='badge-green'>{getattr(p,'service','')}</span></td></tr>\n"
            for p in self.port_scan_results if getattr(p, "open", False)
        )

        path_rows = "".join(
            f"<tr><td class='url-cell'>{getattr(p,'url','')}</td>"
            f"<td class='{'success' if 200<=getattr(p,'status_code',0)<300 else 'warn'}'>"
            f"{getattr(p,'status_code','')}</td>"
            f"<td>{getattr(p,'size',0):,}</td></tr>\n"
            for p in self.path_results
        )

        def card(value: Any, label: str, color: str = "#58a6ff") -> str:
            return (f'<div class="card"><div class="value" style="color:{color}">{value}</div>'
                    f'<div class="label">{label}</div></div>')

        cards = (
            card(stats["total_urls"], "URLs Scanned")
            + card(stats["successful"], "Successful", "#3fb950")
            + card(stats["failed"], "Failed", "#f85149")
            + card(f"{stats['success_rate_percent']}%", "Success Rate")
            + card(f"{stats['total_time_seconds']}s", "Duration")
            + card(stats["wafs_detected"], "WAFs Detected", "#d29922")
            + card(stats["subdomains_found"], "Subdomains")
            + card(stats["open_ports_found"], "Open Ports")
            + card(stats["paths_found"], "Paths Found")
            + card(stats["tls_security_issues"], "TLS Issues", "#d29922")
            + card(stats["missing_security_headers"], "Missing Headers", "#d29922")
            + card(f'<span style="color:{grade_color}">{grade}</span>', "Security Grade")
        )

        extra = ""
        if tls_rows:
            extra += f"""
  <h3 class="section-title">🔒 TLS / SSL Certificate Analysis</h3>
  <table><thead><tr><th>Host</th><th>TLS Version</th><th>Cipher Suite</th>
  <th>Common Name</th><th>Expires In</th><th>Sig Algorithm</th><th>Error</th></tr></thead>
  <tbody>{tls_rows}</tbody></table>"""

        if sub_rows:
            extra += f"""
  <h3 class="section-title">🌐 Subdomain Enumeration ({len(self.subdomain_results)} found)</h3>
  <table><thead><tr><th>Subdomain</th><th>Resolved IP</th><th>Source</th></tr></thead>
  <tbody>{sub_rows}</tbody></table>"""

        if port_rows:
            extra += f"""
  <h3 class="section-title">🔌 Open Ports</h3>
  <table><thead><tr><th>Host</th><th>Port</th><th>Service</th></tr></thead>
  <tbody>{port_rows}</tbody></table>"""

        if path_rows:
            extra += f"""
  <h3 class="section-title">📂 Discovered Paths ({len(self.path_results)} found)</h3>
  <table><thead><tr><th>URL</th><th>Status</th><th>Size</th></tr></thead>
  <tbody>{path_rows}</tbody></table>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HTTP Auditor Ultra v3.0.0 — Report</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#e6edf3;padding:24px;min-height:100vh}}
  .container{{max-width:1600px;margin:0 auto}}
  .header{{display:flex;align-items:center;gap:12px;margin-bottom:6px}}
  h1{{color:#58a6ff;font-size:1.9rem;font-weight:800}}
  .version-badge{{background:#21262d;border:1px solid #30363d;border-radius:20px;padding:3px 10px;font-size:.75rem;color:#58a6ff}}
  .subtitle{{color:#8b949e;font-size:.9rem;margin-bottom:28px}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:32px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;transition:border-color .2s}}
  .card:hover{{border-color:#58a6ff}}
  .card .value{{font-size:1.6rem;font-weight:800}}
  .card .label{{font-size:.72rem;color:#8b949e;margin-top:6px;text-transform:uppercase;letter-spacing:.06em}}
  .section-title{{color:#e6edf3;font-size:1.05rem;font-weight:600;margin:28px 0 12px;padding-bottom:8px;border-bottom:1px solid #21262d}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;margin-bottom:8px;font-size:.82rem}}
  th{{background:#1c2128;color:#8b949e;font-size:.70rem;text-transform:uppercase;letter-spacing:.07em;padding:10px 14px;text-align:left;border-bottom:1px solid #30363d;white-space:nowrap}}
  td{{padding:8px 14px;border-bottom:1px solid #1c2128;vertical-align:middle}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1c2128}}
  .url-cell{{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:.78rem}}
  .success{{color:#3fb950;font-weight:700}}
  .warn{{color:#d29922;font-weight:700}}
  .error{{color:#f85149}}
  .waf-badge{{background:#3d1f00;color:#d29922;border:1px solid #d29922;border-radius:4px;padding:2px 7px;font-size:.72rem;font-weight:600}}
  .badge{{background:#21262d;color:#8b949e;border-radius:4px;padding:2px 7px;font-size:.72rem}}
  .badge-green{{background:#0d2818;color:#3fb950;border-radius:4px;padding:2px 7px;font-size:.72rem;font-weight:600}}
  footer{{text-align:center;color:#8b949e;font-size:.75rem;margin-top:48px;padding-top:16px;border-top:1px solid #21262d}}
  footer a{{color:#58a6ff;text-decoration:none}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ HTTP Auditor Ultra</h1>
    <span class="version-badge">v3.0.0</span>
  </div>
  <div class="subtitle">Security Audit Report &mdash; {ts}</div>
  <div class="summary">{cards}</div>
  <h3 class="section-title">🔍 HTTP Responses ({len(self.results)} URLs)</h3>
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>Time</th><th>Size</th>
    <th>Server</th><th>WAF</th><th>Tech Stack</th><th>Sec Grade</th><th>Error</th></tr></thead>
    <tbody>{results_rows}</tbody>
  </table>
  {extra}
  <footer>Generated by <a href="https://github.com/juraijmughal378-png/http-auditor-ultra">
  <strong>HTTP Auditor Ultra v3.0.0</strong></a> &mdash; {ts}</footer>
</div>
</body>
</html>"""

        if path is not None:
            path.write_text(html, encoding="utf-8")
            logger.info("HTML report written to %s", path)
            return None
        return html

    def summary_text(self) -> str:
        stats = self.statistics.summary()
        all_scores = [
            compute_security_header_score(r.security_headers)
            for r in self.results if r.security_headers
        ]
        avg_score = int(sum(all_scores) / len(all_scores)) if all_scores else 0
        grade = get_security_grade(avg_score)

        lines: List[str] = [
            "=" * 68,
            "  🛡️  HTTP Auditor Ultra v3.0.0 — Execution Summary",
            "=" * 68,
            f"  URLs scanned:           {stats['total_urls']}",
            f"  Successful:             {stats['successful']}",
            f"  Failed:                 {stats['failed']}",
            f"  Retries performed:      {stats['retried']}",
            f"  Success rate:           {stats['success_rate_percent']}%",
            f"  Total time:             {stats['total_time_seconds']}s",
            f"  Avg time / URL:         {stats['average_time_per_url_seconds']}s",
            "",
            "  🔍 Ultra Findings:",
            f"  Security grade:         {grade} ({avg_score}%)",
            f"  Subdomains discovered:  {stats['subdomains_found']}",
            f"  Paths discovered:       {stats['paths_found']}",
            f"  Open ports found:       {stats['open_ports_found']}",
            f"  WAFs detected:          {stats['wafs_detected']}",
            f"  TLS security issues:    {stats['tls_security_issues']}",
            f"  Missing sec headers:    {stats['missing_security_headers']}",
            "",
            "  Status code distribution:",
        ]
        for code, count in stats["unique_status_codes"].items():  # type: ignore
            lines.append(f"    HTTP {code}: {count}")
        if stats["error_count"]:
            lines.append("")
            lines.append("  Errors:")
            for err in self.statistics.errors:
                lines.append(f"    - {err}")
        lines.append("=" * 68)
        return "\n".join(lines)
