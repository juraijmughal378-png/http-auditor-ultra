"""WAF detection, technology fingerprinting, and security header analysis."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from http_auditor_ultra.client import AuditResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF signatures: (name, det_type, target, pattern)
# det_type: "header" | "cookie" | "body" | "status"
# ---------------------------------------------------------------------------

WAF_SIGNATURES: List[Tuple[str, str, str, str]] = [
    ("Cloudflare", "header", "server", r"cloudflare"),
    ("Cloudflare", "header", "cf-ray", r"."),
    ("Cloudflare", "body", "__cf_chl_f_tm", r"."),
    ("Cloudflare", "body", "attention required", r"."),
    ("AWS WAF (CloudFront)", "header", "x-amz-cf-id", r"."),
    ("AWS WAF", "header", "x-amzn-requestid", r"."),
    ("AWS WAF", "body", "Request blocked by AWS WAF", r"."),
    ("ModSecurity", "header", "x-powered-by", r"ModSecurity"),
    ("ModSecurity", "body", "ModSecurity", r"."),
    ("F5 BIG-IP ASM", "header", "x-waf-result", r"."),
    ("F5 BIG-IP ASM", "cookie", "TS", r"\w{6,}"),
    ("F5 BIG-IP ASM", "body", "The requested URL was rejected", r"."),
    ("Akamai GHOST", "header", "server", r"AkamaiGHost"),
    ("Akamai", "header", "x-akamai-request-id", r"."),
    ("Imperva Incapsula", "header", "x-iinfo", r"."),
    ("Imperva Incapsula", "cookie", "incap_ses", r"."),
    ("Imperva Incapsula", "cookie", "visid_incap", r"."),
    ("Imperva Incapsula", "body", "incapsula", r"."),
    ("Sucuri", "header", "x-sucuri-id", r"."),
    ("Sucuri", "body", "cloudproxy@sucuri", r"."),
    ("Barracuda", "cookie", "barra_counter", r"."),
    ("Barracuda", "body", "Barracuda", r"."),
    ("Wordfence", "header", "x-powered-by", r"Wordfence"),
    ("Wordfence", "body", "Wordfence", r"."),
    ("StackPath", "header", "x-stackpath", r"."),
    ("Radware AppWall", "header", "x-sl-compstate", r"."),
    ("Citrix NetScaler", "cookie", "NSC_", r"."),
    ("FortiWeb", "cookie", "FORTIWAFS", r"."),
    ("Alibaba Cloud WAF", "header", "ali-swift", r"."),
    ("LiteSpeed", "header", "server", r"LiteSpeed"),
    ("SafeLine", "header", "server", r"Safeline"),
    ("SafeLine", "header", "x-safeline", r"."),
    ("Huawei Cloud WAF", "header", "x-hw-waf", r"."),
]

# ---------------------------------------------------------------------------
# Technology fingerprinting: (name, match_spec, pattern)
# match_spec: "header:key" | "body"
# ---------------------------------------------------------------------------

TECH_SIGNATURES: List[Tuple[str, str, str]] = [
    ("Nginx", "header:server", r"nginx"),
    ("Apache", "header:server", r"Apache"),
    ("IIS", "header:server", r"Microsoft-IIS"),
    ("Tomcat", "header:server", r"Tomcat"),
    ("Jetty", "header:server", r"Jetty"),
    ("Caddy", "header:server", r"Caddy"),
    ("OpenResty", "header:server", r"openresty"),
    ("PHP", "header:x-powered-by", r"PHP"),
    ("ASP.NET", "header:x-powered-by", r"ASP\.NET"),
    ("Python/Django", "header:server", r"WSGIServer"),
    ("Python/Flask", "header:server", r"Werkzeug"),
    ("Node.js/Express", "header:x-powered-by", r"Express"),
    ("Ruby on Rails", "header:server", r"Phusion"),
    ("Java/Spring", "header:x-application-context", r"."),
    ("WordPress", "header:x-powered-by", r"WordPress"),
    ("WordPress", "body", r"wp-content"),
    ("WordPress", "body", r"wp-includes"),
    ("Drupal", "header:x-generator", r"Drupal"),
    ("Drupal", "body", r"Drupal"),
    ("Joomla", "header:x-generator", r"Joomla"),
    ("Joomla", "body", r"joomla"),
    ("Magento", "body", r"Magento"),
    ("Shopify", "body", r"shopify"),
    ("Shopify", "header:x-shopid", r"."),
    ("React", "body", r"react"),
    ("Angular", "body", r"ng-version"),
    ("Vue.js", "body", r"vue"),
    ("jQuery", "body", r"jquery"),
    ("Cloudflare CDN", "header:cf-ray", r"."),
    ("Akamai CDN", "header:x-akamai-request-id", r"."),
    ("Fastly", "header:x-fastly-request-id", r"."),
    ("CloudFront", "header:x-amz-cf-id", r"."),
]

# ---------------------------------------------------------------------------
# OWASP security header requirements
# ---------------------------------------------------------------------------

SECURITY_HEADERS_REQUIRED: Dict[str, Dict[str, Any]] = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security (HSTS) — enforces HTTPS",
        "severity": "HIGH",
        "recommended_value": "max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "description": "Content Security Policy — prevents XSS",
        "severity": "HIGH",
        "recommended_value": "default-src 'self'",
    },
    "x-frame-options": {
        "description": "X-Frame-Options — prevents clickjacking",
        "severity": "HIGH",
        "recommended_value": "SAMEORIGIN or DENY",
    },
    "x-content-type-options": {
        "description": "X-Content-Type-Options — prevents MIME sniffing",
        "severity": "MEDIUM",
        "recommended_value": "nosniff",
    },
    "x-xss-protection": {
        "description": "X-XSS-Protection — browser XSS filter",
        "severity": "MEDIUM",
        "recommended_value": "1; mode=block",
    },
    "referrer-policy": {
        "description": "Referrer-Policy — controls referrer header",
        "severity": "LOW",
        "recommended_value": "strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "description": "Permissions Policy — restricts browser APIs",
        "severity": "LOW",
        "recommended_value": "geolocation=()",
    },
    "cross-origin-resource-policy": {
        "description": "Cross-Origin-Resource-Policy — restricts cross-origin reads",
        "severity": "LOW",
        "recommended_value": "same-origin",
    },
    "cross-origin-opener-policy": {
        "description": "Cross-Origin-Opener-Policy — isolates cross-origin windows",
        "severity": "LOW",
        "recommended_value": "same-origin-allow-popups",
    },
    "cross-origin-embedder-policy": {
        "description": "Cross-Origin-Embedder-Policy — COEP isolation",
        "severity": "LOW",
        "recommended_value": "require-corp",
    },
}


def detect_waf(result: AuditResult) -> Optional[str]:
    """Detect WAF by analyzing response headers, body, cookies, and status."""
    headers_lower = {k.lower(): v for k, v in result.headers.items()}
    body = result.body_snippet.lower()
    cookies = headers_lower.get("set-cookie", "")

    for waf_name, det_type, target, pattern in WAF_SIGNATURES:
        try:
            if det_type == "header":
                value = headers_lower.get(target, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    return waf_name
            elif det_type == "cookie":
                if cookies and re.search(target, cookies, re.IGNORECASE):
                    if re.search(pattern, cookies, re.IGNORECASE):
                        return waf_name
            elif det_type == "body":
                if body and re.search(target.lower(), body):
                    return waf_name
        except re.error:
            continue

    # Heuristic: small 403/406 with block-related keywords
    if result.status_code in (403, 406) and result.content_length < 1000 and body:
        block_phrases = ["blocked", "denied", "rejected", "security", "firewall", "waf", "attack"]
        if any(phrase in body for phrase in block_phrases):
            return "Unknown WAF (heuristic)"

    return None


def detect_tech_stack(result: AuditResult) -> List[str]:
    """Detect technology stack from response headers and body."""
    headers_lower = {k.lower(): v for k, v in result.headers.items()}
    body = result.body_snippet.lower()
    detected: List[str] = []

    for tech_name, match_spec, pattern in TECH_SIGNATURES:
        try:
            if match_spec.startswith("header:"):
                header_key = match_spec[7:]
                value = headers_lower.get(header_key, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    if tech_name not in detected:
                        detected.append(tech_name)
            elif match_spec == "body":
                if body and re.search(pattern, body):
                    if tech_name not in detected:
                        detected.append(tech_name)
        except re.error:
            continue

    return detected


def analyze_security_headers(result: AuditResult) -> Dict[str, Any]:
    """Analyze HTTP security headers against OWASP recommendations."""
    headers_lower = {k.lower(): v for k, v in result.headers.items()}
    analysis: Dict[str, Any] = {}

    for header_name, info in SECURITY_HEADERS_REQUIRED.items():
        value = headers_lower.get(header_name)
        analysis[header_name] = {
            "status": "present" if value else "missing",
            "value": value,
            "description": info["description"],
            "severity": info["severity"],
            "recommended": info["recommended_value"],
        }

    return analysis


def compute_security_header_score(analysis: Dict[str, Any]) -> int:
    """Compute a numeric security header score (0–100)."""
    total = len(analysis)
    if total == 0:
        return 0
    present = sum(1 for h in analysis.values() if h["status"] == "present")
    return int((present / total) * 100)
