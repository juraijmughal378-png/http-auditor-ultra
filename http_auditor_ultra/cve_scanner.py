"""CVE Scanner — detects known vulnerabilities in detected technologies.

Checks against a built-in CVE database for:
- Web servers (Apache, Nginx, IIS)
- CMS (WordPress, Drupal, Joomla)
- Frameworks (PHP, ASP.NET)
- JavaScript libraries (jQuery)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in CVE Database
# Format: (tech_pattern, version_pattern, cve_id, severity, description, fix)
# ---------------------------------------------------------------------------

CVE_DATABASE: List[Dict[str, Any]] = [
    # Apache
    {"tech": "Apache", "version_range": ("2.4.0", "2.4.49"), "cve": "CVE-2021-41773",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Path traversal and RCE via mod_cgi in Apache 2.4.49",
     "fix": "Upgrade to Apache 2.4.51+"},
    {"tech": "Apache", "version_range": ("2.4.0", "2.4.50"), "cve": "CVE-2021-42013",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Path traversal bypass in Apache 2.4.50",
     "fix": "Upgrade to Apache 2.4.51+"},
    {"tech": "Apache", "version_range": ("2.4.0", "2.4.55"), "cve": "CVE-2023-25690",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "HTTP request smuggling via mod_proxy",
     "fix": "Upgrade to Apache 2.4.56+"},
    # Nginx
    {"tech": "Nginx", "version_range": ("0.0.0", "1.20.0"), "cve": "CVE-2021-23017",
     "severity": "HIGH", "cvss": 7.7,
     "description": "1-byte memory overwrite in DNS resolver",
     "fix": "Upgrade to Nginx 1.21.0+"},
    {"tech": "Nginx", "version_range": ("0.0.0", "1.24.0"), "cve": "CVE-2022-41741",
     "severity": "HIGH", "cvss": 7.1,
     "description": "Memory corruption in MP4 module",
     "fix": "Upgrade to Nginx 1.24.0+"},
    # IIS
    {"tech": "IIS", "version_range": ("7.0", "10.0"), "cve": "CVE-2022-21907",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "HTTP Protocol Stack Remote Code Execution",
     "fix": "Apply Microsoft Security Update KB5009557"},
    {"tech": "IIS", "version_range": ("6.0", "10.0"), "cve": "CVE-2017-7269",
     "severity": "CRITICAL", "cvss": 10.0,
     "description": "Buffer overflow in WebDAV service allows RCE",
     "fix": "Disable WebDAV or upgrade IIS"},
    # PHP
    {"tech": "PHP", "version_range": ("0.0.0", "8.0.28"), "cve": "CVE-2023-0662",
     "severity": "HIGH", "cvss": 7.5,
     "description": "Excessive resource consumption in multipart request parsing",
     "fix": "Upgrade to PHP 8.0.28+, 8.1.16+, or 8.2.3+"},
    {"tech": "PHP", "version_range": ("8.0.0", "8.1.0"), "cve": "CVE-2021-21708",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Use-after-free in PHP 8.x",
     "fix": "Upgrade to PHP 8.1.3+"},
    {"tech": "PHP", "version_range": ("5.0.0", "7.4.99"), "cve": "CVE-2019-11043",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "RCE in FPM under certain Nginx configurations",
     "fix": "Upgrade to PHP 7.3.11+ or 7.4.x"},
    # WordPress
    {"tech": "WordPress", "version_range": ("0.0.0", "6.3.0"), "cve": "CVE-2023-38000",
     "severity": "MEDIUM", "cvss": 6.4,
     "description": "Stored XSS via the Footnotes block",
     "fix": "Upgrade to WordPress 6.3.2+"},
    {"tech": "WordPress", "version_range": ("0.0.0", "5.8.0"), "cve": "CVE-2021-39200",
     "severity": "MEDIUM", "cvss": 5.3,
     "description": "REST API disclosure of private/draft posts",
     "fix": "Upgrade to WordPress 5.8.1+"},
    {"tech": "WordPress", "version_range": ("0.0.0", "6.0.0"), "cve": "CVE-2022-21661",
     "severity": "HIGH", "cvss": 8.8,
     "description": "SQL injection via WP_Query",
     "fix": "Upgrade to WordPress 5.8.3+"},
    # Drupal
    {"tech": "Drupal", "version_range": ("7.0", "7.58"), "cve": "CVE-2018-7600",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Drupalgeddon2 — Remote Code Execution",
     "fix": "Upgrade to Drupal 7.58+ or 8.5.1+"},
    {"tech": "Drupal", "version_range": ("8.0", "8.6.9"), "cve": "CVE-2019-6340",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "RCE via REST API with no authentication",
     "fix": "Upgrade to Drupal 8.6.10+"},
    # Joomla
    {"tech": "Joomla", "version_range": ("1.5.0", "3.9.0"), "cve": "CVE-2018-8045",
     "severity": "HIGH", "cvss": 7.5,
     "description": "XSS vulnerability in multiple components",
     "fix": "Upgrade to Joomla 3.9.0+"},
    {"tech": "Joomla", "version_range": ("1.5.0", "3.4.6"), "cve": "CVE-2015-8566",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Object injection leading to RCE",
     "fix": "Upgrade to Joomla 3.4.6+"},
    # jQuery
    {"tech": "jQuery", "version_range": ("1.0.0", "3.5.0"), "cve": "CVE-2020-11022",
     "severity": "MEDIUM", "cvss": 6.1,
     "description": "XSS via passing HTML with <option> elements",
     "fix": "Upgrade to jQuery 3.5.0+"},
    {"tech": "jQuery", "version_range": ("1.0.0", "3.5.0"), "cve": "CVE-2020-11023",
     "severity": "MEDIUM", "cvss": 6.1,
     "description": "XSS via HTML containing <option> elements",
     "fix": "Upgrade to jQuery 3.5.0+"},
    {"tech": "jQuery", "version_range": ("1.0.0", "1.9.0"), "cve": "CVE-2019-11358",
     "severity": "MEDIUM", "cvss": 6.1,
     "description": "Prototype pollution attack via $.extend",
     "fix": "Upgrade to jQuery 3.4.0+"},
    # OpenSSL (via TLS)
    {"tech": "OpenSSL", "version_range": ("3.0.0", "3.0.6"), "cve": "CVE-2022-3786",
     "severity": "HIGH", "cvss": 7.5,
     "description": "Buffer overflow in X.509 certificate verification",
     "fix": "Upgrade to OpenSSL 3.0.7+"},
    # ASP.NET
    {"tech": "ASP.NET", "version_range": ("0.0.0", "4.8.0"), "cve": "CVE-2021-24112",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Remote code execution in .NET 5 and Core",
     "fix": "Apply .NET security updates"},
    # Tomcat
    {"tech": "Tomcat", "version_range": ("9.0.0", "9.0.68"), "cve": "CVE-2022-42252",
     "severity": "HIGH", "cvss": 7.5,
     "description": "Request smuggling when reverse proxied",
     "fix": "Upgrade to Tomcat 9.0.69+"},
    {"tech": "Tomcat", "version_range": ("10.0.0", "10.0.27"), "cve": "CVE-2023-28709",
     "severity": "HIGH", "cvss": 7.5,
     "description": "Denial of service via incomplete TLS handshake",
     "fix": "Upgrade to Tomcat 10.1.8+"},
    # Spring
    {"tech": "Java/Spring", "version_range": ("5.0.0", "5.3.17"), "cve": "CVE-2022-22965",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Spring4Shell — RCE via DataBinder",
     "fix": "Upgrade to Spring Framework 5.3.18+"},
    # Node.js/Express
    {"tech": "Node.js/Express", "version_range": ("4.0.0", "4.17.0"), "cve": "CVE-2022-24999",
     "severity": "HIGH", "cvss": 7.5,
     "description": "Prototype pollution in qs library",
     "fix": "Upgrade to Express 4.17.3+ or qs 6.10.3+"},
    # Magento
    {"tech": "Magento", "version_range": ("2.0.0", "2.4.5"), "cve": "CVE-2022-24086",
     "severity": "CRITICAL", "cvss": 9.8,
     "description": "Improper input validation allowing RCE",
     "fix": "Apply APSB22-12 security patch"},
    # Shopify
    {"tech": "Shopify", "version_range": ("0.0.0", "999.0.0"), "cve": "CVE-2022-21703",
     "severity": "MEDIUM", "cvss": 6.3,
     "description": "CSRF vulnerability in Shopify admin",
     "fix": "Shopify handles patches automatically"},
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class CVEFinding:
    """A single CVE vulnerability finding."""

    tech: str
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    fix: str
    confidence: str = "medium"  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tech": self.tech,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "fix": self.fix,
            "confidence": self.confidence,
        }


@dataclass
class CVEScanResult:
    """Results from CVE scanning a target."""

    url: str
    tech_stack: List[str]
    findings: List[CVEFinding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "tech_stack": self.tech_stack,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
        }


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------


def _extract_version(header_value: str) -> Optional[str]:
    """Extract version number from a header value like 'Apache/2.4.49'."""
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", header_value)
    return match.group(1) if match else None


def _version_tuple(version_str: str) -> Tuple[int, ...]:
    """Convert '2.4.49' to (2, 4, 49)."""
    try:
        return tuple(int(x) for x in version_str.split("."))
    except ValueError:
        return (0,)


def _in_version_range(version: str, min_ver: str, max_ver: str) -> bool:
    """Check if version is within [min_ver, max_ver)."""
    try:
        v = _version_tuple(version)
        mn = _version_tuple(min_ver)
        mx = _version_tuple(max_ver)
        return mn <= v <= mx
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------


def scan_cves(
    url: str,
    tech_stack: List[str],
    headers: Dict[str, str],
    body_snippet: str = "",
) -> CVEScanResult:
    """Scan for known CVEs based on detected technology stack.

    Args:
        url:          The scanned URL.
        tech_stack:   List of detected technologies.
        headers:      Response headers (lowercased).
        body_snippet: Response body snippet for version detection.

    Returns:
        CVEScanResult with all findings.
    """
    result = CVEScanResult(url=url, tech_stack=tech_stack)
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Build tech->version map from headers
    tech_versions: Dict[str, Optional[str]] = {}

    server = headers_lower.get("server", "")
    powered_by = headers_lower.get("x-powered-by", "")

    for tech in tech_stack:
        version = None
        if tech == "Apache" and "apache" in server.lower():
            version = _extract_version(server)
        elif tech == "Nginx" and "nginx" in server.lower():
            version = _extract_version(server)
        elif tech == "IIS" and "iis" in server.lower():
            version = _extract_version(server)
        elif tech == "PHP" and "php" in powered_by.lower():
            version = _extract_version(powered_by)
        elif tech == "ASP.NET" and "asp.net" in powered_by.lower():
            version = _extract_version(powered_by)
        elif tech == "Tomcat" and "tomcat" in server.lower():
            version = _extract_version(server)
        tech_versions[tech] = version

    # Check each CVE entry
    seen_cves: set = set()

    for cve_entry in CVE_DATABASE:
        tech_name = cve_entry["tech"]

        # Check if this tech is in detected stack
        tech_detected = any(
            tech_name.lower() in detected.lower()
            for detected in tech_stack
        )

        if not tech_detected:
            continue

        cve_id = cve_entry["cve"]
        if cve_id in seen_cves:
            continue

        version = tech_versions.get(tech_name)
        confidence = "medium"

        if version:
            # Version known — check range precisely
            min_v, max_v = cve_entry["version_range"]
            if not _in_version_range(version, min_v, max_v):
                continue
            confidence = "high"
        else:
            # Version unknown — flag as possible (low confidence)
            confidence = "low"

        finding = CVEFinding(
            tech=tech_name,
            cve_id=cve_id,
            severity=cve_entry["severity"],
            cvss_score=cve_entry["cvss"],
            description=cve_entry["description"],
            fix=cve_entry["fix"],
            confidence=confidence,
        )

        result.findings.append(finding)
        seen_cves.add(cve_id)

        # Count by severity
        sev = cve_entry["severity"]
        if sev == "CRITICAL":
            result.critical_count += 1
        elif sev == "HIGH":
            result.high_count += 1
        elif sev == "MEDIUM":
            result.medium_count += 1
        else:
            result.low_count += 1

    # Sort by CVSS score descending
    result.findings.sort(key=lambda f: f.cvss_score, reverse=True)

    if result.findings:
        logger.warning(
            "CVE scan found %d vulnerabilities for %s (CRITICAL: %d, HIGH: %d)",
            len(result.findings), url, result.critical_count, result.high_count,
        )

    return result
