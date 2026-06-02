"""Report generation — Super Duper Ultra v4.0.0."""

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
from http_auditor_ultra.fingerprint import compute_security_header_score, get_security_grade
from http_auditor_ultra.utils import AuditStatistics

logger = logging.getLogger(__name__)

_CSV_FIELD_NAMES: List[str] = [
    "url", "status_code", "success", "response_time_seconds",
    "content_length", "server", "redirect_url", "error", "retries",
    "http_method", "waf_detected", "tech_stack",
]


class AuditReport:
    """Complete audit report — Super Duper Ultra v4.0.0."""

    def __init__(
        self,
        results: List[AuditResult],
        statistics: AuditStatistics,
        config: AuditorConfig,
        tls_results: Optional[List[Any]] = None,
        subdomain_results: Optional[List[Any]] = None,
        port_scan_results: Optional[List[Any]] = None,
        path_results: Optional[List[Any]] = None,
        cve_results: Optional[List[Any]] = None,
        dns_results: Optional[List[Any]] = None,
        harvester_results: Optional[List[Any]] = None,
        http_analysis_results: Optional[List[Any]] = None,
    ) -> None:
        self.results = results
        self.statistics = statistics
        self.config = config
        self.tls_results = tls_results or []
        self.subdomain_results = subdomain_results or []
        self.port_scan_results = port_scan_results or []
        self.path_results = path_results or []
        self.cve_results = cve_results or []
        self.dns_results = dns_results or []
        self.harvester_results = harvester_results or []
        self.http_analysis_results = http_analysis_results or []

    def to_json(self, path: Optional[Path] = None) -> Optional[str]:
        data: Dict[str, object] = {
            "metadata": {
                "tool": "HTTP Auditor Ultra",
                "version": "4.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "config": self.config.to_dict(),
            },
            "statistics": self.statistics.summary(),
            "results": [r.to_dict() for r in self.results],
            "tls_audit": [t.to_dict() for t in self.tls_results],
            "cve_findings": [c.to_dict() for c in self.cve_results],
            "dns_analysis": [d.to_dict() for d in self.dns_results],
            "harvester": [h.to_dict() for h in self.harvester_results],
            "http_analysis": [h.to_dict() for h in self.http_analysis_results],
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

        # Security grade
        all_scores = [compute_security_header_score(r.security_headers) for r in self.results if r.security_headers]
        avg_score = int(sum(all_scores) / len(all_scores)) if all_scores else 0
        grade = get_security_grade(avg_score)
        grade_color = {"A+": "#3fb950", "A": "#3fb950", "B": "#58a6ff", "C": "#d29922", "D": "#f85149", "F": "#f85149"}.get(grade, "#8b949e")

        # CVE count
        total_cves = sum(len(getattr(c, "findings", [])) for c in self.cve_results)
        critical_cves = sum(getattr(c, "critical_count", 0) for c in self.cve_results)

        # Emails found
        total_emails = sum(len(getattr(h, "emails", [])) for h in self.harvester_results)
        total_secrets = sum(len(getattr(h, "secrets", [])) for h in self.harvester_results)

        def card(value: Any, label: str, color: str = "#58a6ff") -> str:
            return (f'<div class="card"><div class="value" style="color:{color}">{value}</div>'
                    f'<div class="label">{label}</div></div>')

        cards = (
            card(stats["total_urls"], "URLs Scanned")
            + card(stats["successful"], "Successful", "#3fb950")
            + card(stats["failed"], "Failed", "#f85149")
            + card(f'<span style="color:{grade_color}">{grade}</span>', "Security Grade")
            + card(f"{stats['total_time_seconds']}s", "Duration")
            + card(stats["wafs_detected"], "WAFs Detected", "#d29922")
            + card(f'<span style="color:#f85149">{critical_cves}</span>', "Critical CVEs")
            + card(total_cves, "Total CVEs", "#f85149" if total_cves > 0 else "#3fb950")
            + card(stats["subdomains_found"], "Subdomains")
            + card(stats["open_ports_found"], "Open Ports")
            + card(stats["paths_found"], "Paths Found")
            + card(total_emails, "Emails Found", "#58a6ff")
            + card(total_secrets, "Secrets Found", "#f85149" if total_secrets > 0 else "#3fb950")
            + card(stats["tls_security_issues"], "TLS Issues", "#d29922")
            + card(stats["missing_security_headers"], "Missing Headers", "#d29922")
        )

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
                gc = {"A+": "#3fb950", "A": "#3fb950", "B": "#58a6ff", "C": "#d29922", "D": "#f85149", "F": "#f85149"}.get(g, "#8b949e")
                score_html = f'<span style="color:{gc};font-weight:700">{g}({s}%)</span>'
            results_rows += (
                f"<tr><td class='url-cell'>{r.url}</td>"
                f"<td class='{cls}'><b>{r.status_code}</b></td>"
                f"<td>{r.response_time:.3f}s</td>"
                f"<td>{r.server or ''}</td>"
                f"<td>{waf}</td>"
                f"<td>{tech}</td>"
                f"<td>{score_html}</td>"
                f"<td class='error'>{r.error or ''}</td></tr>\n"
            )

        # CVE rows
        cve_rows = ""
        for cve_result in self.cve_results:
            for finding in getattr(cve_result, "findings", [])[:20]:
                sev = getattr(finding, "severity", "")
                sev_color = {"CRITICAL": "#f85149", "HIGH": "#d29922", "MEDIUM": "#58a6ff", "LOW": "#8b949e"}.get(sev, "#8b949e")
                cvss = getattr(finding, "cvss_score", 0)
                cve_rows += (
                    f"<tr><td><b>{getattr(finding,'cve_id','')}</b></td>"
                    f"<td style='color:{sev_color};font-weight:700'>{sev}</td>"
                    f"<td><b>{cvss}</b></td>"
                    f"<td>{getattr(finding,'tech','')}</td>"
                    f"<td>{getattr(finding,'description','')}</td>"
                    f"<td class='success'>{getattr(finding,'fix','')}</td></tr>\n"
                )

        # DNS rows
        dns_rows = ""
        for dns in self.dns_results:
            domain = getattr(dns, "domain", "")
            a_rec = ", ".join(getattr(dns, "a_records", [])[:3])
            geoip = getattr(dns, "geoip", None)
            location = f"{getattr(geoip,'city','')} {getattr(geoip,'country','')}" if geoip else ""
            org = getattr(geoip, "org", "") if geoip else ""
            security = getattr(dns, "security", None)
            spf = "✅" if getattr(security, "spf_valid", False) else "❌"
            dmarc = "✅" if getattr(security, "dmarc_valid", False) else "❌"
            ns = ", ".join(getattr(dns, "ns_records", [])[:2])
            dns_rows += (
                f"<tr><td><b>{domain}</b></td>"
                f"<td>{a_rec}</td>"
                f"<td>{location}</td>"
                f"<td>{org}</td>"
                f"<td>{ns}</td>"
                f"<td>{spf}</td>"
                f"<td>{dmarc}</td></tr>\n"
            )

        # Harvester rows
        harvest_rows = ""
        for h in self.harvester_results:
            emails = ", ".join(getattr(h, "emails", [])[:5])
            secrets_count = len(getattr(h, "secrets", []))
            phones = ", ".join(getattr(h, "phones", [])[:3])
            socials = ", ".join(getattr(h, "social_links", {}).keys())
            sec_color = "#f85149" if secrets_count > 0 else "#3fb950"
            harvest_rows += (
                f"<tr><td class='url-cell'>{getattr(h,'url','')}</td>"
                f"<td>{emails or 'None'}</td>"
                f"<td>{phones or 'None'}</td>"
                f"<td>{socials or 'None'}</td>"
                f"<td style='color:{sec_color};font-weight:700'>{secrets_count}</td></tr>\n"
            )

        # HTTP analysis rows
        http_rows = ""
        for ha in self.http_analysis_results:
            methods = ", ".join(getattr(ha, "allowed_methods", []))
            dangerous = ", ".join(getattr(ha, "dangerous_methods", []))
            danger_html = f'<span class="error">{dangerous}</span>' if dangerous else '<span class="success">None</span>'
            cookies_count = len(getattr(ha, "cookies", []))
            redirects = len(getattr(ha, "redirect_chain", []))
            rate_limit = "✅" if getattr(ha, "rate_limit_detected", False) else "❌"
            cors = getattr(ha, "cors", None)
            cors_risk = getattr(cors, "risk", "N/A") if cors else "N/A"
            cors_color = "#f85149" if cors_risk == "HIGH" else "#d29922" if cors_risk == "MEDIUM" else "#3fb950"
            http_rows += (
                f"<tr><td class='url-cell'>{getattr(ha,'url','')}</td>"
                f"<td>{methods}</td>"
                f"<td>{danger_html}</td>"
                f"<td>{cookies_count}</td>"
                f"<td>{redirects}</td>"
                f"<td>{rate_limit}</td>"
                f"<td style='color:{cors_color}'>{cors_risk}</td></tr>\n"
            )

        # TLS rows
        tls_rows = ""
        for t in self.tls_results:
            ver = getattr(t, "tls_version", "")
            ver_color = "#3fb950" if "1.3" in ver else "#d29922" if "1.2" in ver else "#f85149"
            days = getattr(t, "days_remaining", 0)
            exp_color = "#f85149" if days <= 0 else "#d29922" if days <= 30 else "#3fb950"
            weak = '<span class="error">⚠ WEAK</span>' if getattr(t, "weak_signature", False) else '<span class="success">✓</span>'
            tls_rows += (
                f"<tr><td><b>{getattr(t,'hostname','')}</b></td>"
                f"<td style='color:{ver_color}'>{ver}</td>"
                f"<td>{getattr(t,'cipher_suite','')}</td>"
                f"<td>{getattr(t,'common_name','')}</td>"
                f"<td style='color:{exp_color}'>{days}d</td>"
                f"<td>{weak}</td>"
                f"<td class='error'>{getattr(t,'error','') or ''}</td></tr>\n"
            )

        # Subdomain rows
        sub_rows = "".join(
            f"<tr><td>{getattr(s,'subdomain','')}</td>"
            f"<td>{getattr(s,'resolved','')}</td>"
            f"<td><span class='badge'>{getattr(s,'source','')}</span></td></tr>\n"
            for s in self.subdomain_results
        )

        # Port rows
        port_rows = "".join(
            f"<tr><td>{getattr(p,'host','')}</td>"
            f"<td><b>{getattr(p,'port','')}</b></td>"
            f"<td><span class='badge-green'>{getattr(p,'service','')}</span></td></tr>\n"
            for p in self.port_scan_results if getattr(p, "open", False)
        )

        # Path rows
        path_rows = "".join(
            f"<tr><td class='url-cell'>{getattr(p,'url','')}</td>"
            f"<td class='{'success' if 200<=getattr(p,'status_code',0)<300 else 'warn'}'>{getattr(p,'status_code','')}</td>"
            f"<td>{getattr(p,'size',0):,}</td></tr>\n"
            for p in self.path_results
        )

        # Build extra sections
        extra = ""
        if cve_rows:
            extra += f"""
  <h3 class="section-title">🚨 CVE Vulnerabilities ({total_cves} found — {critical_cves} Critical)</h3>
  <table><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Technology</th><th>Description</th><th>Fix</th></tr></thead>
  <tbody>{cve_rows}</tbody></table>"""

        if dns_rows:
            extra += f"""
  <h3 class="section-title">🌐 DNS Analysis</h3>
  <table><thead><tr><th>Domain</th><th>A Records</th><th>Location</th><th>Organization</th><th>Name Servers</th><th>SPF</th><th>DMARC</th></tr></thead>
  <tbody>{dns_rows}</tbody></table>"""

        if harvest_rows:
            extra += f"""
  <h3 class="section-title">📧 Email & Secret Harvesting</h3>
  <table><thead><tr><th>URL</th><th>Emails Found</th><th>Phones</th><th>Social Media</th><th>Secrets</th></tr></thead>
  <tbody>{harvest_rows}</tbody></table>"""

        if http_rows:
            extra += f"""
  <h3 class="section-title">🔬 HTTP Deep Analysis</h3>
  <table><thead><tr><th>URL</th><th>Allowed Methods</th><th>Dangerous Methods</th><th>Cookies</th><th>Redirects</th><th>Rate Limit</th><th>CORS Risk</th></tr></thead>
  <tbody>{http_rows}</tbody></table>"""

        if tls_rows:
            extra += f"""
  <h3 class="section-title">🔒 TLS/SSL Analysis</h3>
  <table><thead><tr><th>Host</th><th>TLS Version</th><th>Cipher</th><th>Common Name</th><th>Expires</th><th>Signature</th><th>Error</th></tr></thead>
  <tbody>{tls_rows}</tbody></table>"""

        if sub_rows:
            extra += f"""
  <h3 class="section-title">🌐 Subdomains ({len(self.subdomain_results)} found)</h3>
  <table><thead><tr><th>Subdomain</th><th>IP</th><th>Source</th></tr></thead>
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
<title>HTTP Auditor Ultra v4.0.0 — Super Duper Ultra Report</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#e6edf3;padding:24px}}
  .container{{max-width:1800px;margin:0 auto}}
  .header{{display:flex;align-items:center;gap:12px;margin-bottom:4px}}
  h1{{color:#58a6ff;font-size:2rem;font-weight:900}}
  .badge{{background:#21262d;border:1px solid #30363d;border-radius:20px;padding:3px 10px;font-size:.75rem;color:#58a6ff}}
  .badge-v4{{background:#1a0a2e;border:1px solid #8957e5;color:#d2a8ff;border-radius:20px;padding:3px 10px;font-size:.75rem}}
  .subtitle{{color:#8b949e;font-size:.88rem;margin-bottom:28px}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:32px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;transition:all .2s;cursor:default}}
  .card:hover{{border-color:#58a6ff;transform:translateY(-2px)}}
  .card .value{{font-size:1.5rem;font-weight:800}}
  .card .label{{font-size:.70rem;color:#8b949e;margin-top:6px;text-transform:uppercase;letter-spacing:.06em}}
  .section-title{{color:#e6edf3;font-size:1.05rem;font-weight:700;margin:28px 0 12px;padding-bottom:8px;border-bottom:2px solid #21262d}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;margin-bottom:8px;font-size:.80rem}}
  th{{background:#1c2128;color:#8b949e;font-size:.68rem;text-transform:uppercase;letter-spacing:.07em;padding:9px 12px;text-align:left;border-bottom:1px solid #30363d;white-space:nowrap}}
  td{{padding:7px 12px;border-bottom:1px solid #1c2128;vertical-align:middle}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1c2128}}
  .url-cell{{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:.76rem}}
  .success{{color:#3fb950;font-weight:600}}
  .warn{{color:#d29922;font-weight:600}}
  .error{{color:#f85149}}
  .waf-badge{{background:#3d1f00;color:#d29922;border:1px solid #d29922;border-radius:4px;padding:2px 7px;font-size:.70rem;font-weight:700}}
  .badge{{background:#21262d;color:#8b949e;border-radius:4px;padding:2px 7px;font-size:.70rem}}
  .badge-green{{background:#0d2818;color:#3fb950;border-radius:4px;padding:2px 7px;font-size:.70rem;font-weight:600}}
  footer{{text-align:center;color:#8b949e;font-size:.75rem;margin-top:56px;padding-top:16px;border-top:1px solid #21262d}}
  footer a{{color:#58a6ff;text-decoration:none}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ HTTP Auditor Ultra</h1>
    <span class="badge">v4.0.0</span>
    <span class="badge-v4">✨ Super Duper Ultra</span>
  </div>
  <div class="subtitle">Complete Security Audit Report &mdash; {ts}</div>
  <div class="summary">{cards}</div>
  <h3 class="section-title">🔍 HTTP Responses ({len(self.results)} URLs)</h3>
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>Time</th><th>Server</th><th>WAF</th><th>Tech Stack</th><th>Sec Grade</th><th>Error</th></tr></thead>
    <tbody>{results_rows}</tbody>
  </table>
  {extra}
  <footer>Generated by <a href="https://github.com/juraijmughal378-png/http-auditor-ultra">
  <strong>HTTP Auditor Ultra v4.0.0 — Super Duper Ultra Edition</strong></a> &mdash; {ts}</footer>
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
        all_scores = [compute_security_header_score(r.security_headers) for r in self.results if r.security_headers]
        avg_score = int(sum(all_scores) / len(all_scores)) if all_scores else 0
        grade = get_security_grade(avg_score)
        total_cves = sum(len(getattr(c, "findings", [])) for c in self.cve_results)
        critical_cves = sum(getattr(c, "critical_count", 0) for c in self.cve_results)
        total_emails = sum(len(getattr(h, "emails", [])) for h in self.harvester_results)
        total_secrets = sum(len(getattr(h, "secrets", [])) for h in self.harvester_results)

        lines: List[str] = [
            "=" * 68,
            "  🛡️  HTTP Auditor Ultra v4.0.0 — Super Duper Ultra",
            "=" * 68,
            f"  URLs scanned:           {stats['total_urls']}",
            f"  Successful:             {stats['successful']}",
            f"  Failed:                 {stats['failed']}",
            f"  Success rate:           {stats['success_rate_percent']}%",
            f"  Total time:             {stats['total_time_seconds']}s",
            "",
            "  🔍 Security Findings:",
            f"  Security grade:         {grade} ({avg_score}%)",
            f"  CVEs found:             {total_cves} ({critical_cves} Critical)",
            f"  WAFs detected:          {stats['wafs_detected']}",
            f"  TLS issues:             {stats['tls_security_issues']}",
            f"  Missing headers:        {stats['missing_security_headers']}",
            "",
            "  📊 Recon Findings:",
            f"  Emails harvested:       {total_emails}",
            f"  Secrets found:          {total_secrets}",
            f"  Subdomains:             {stats['subdomains_found']}",
            f"  Open ports:             {stats['open_ports_found']}",
            f"  Paths discovered:       {stats['paths_found']}",
            "",
            "  Status codes:",
        ]
        for code, count in stats["unique_status_codes"].items():  # type: ignore
            lines.append(f"    HTTP {code}: {count}")
        if stats["error_count"]:
            lines.append("\n  Errors:")
            for err in self.statistics.errors:
                lines.append(f"    - {err}")
        lines.append("=" * 68)
        return "\n".join(lines)
