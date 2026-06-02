"""Email harvesting and JavaScript secrets detection.

Finds:
- Email addresses from HTML/JS content
- API keys, tokens, secrets in JavaScript files
- Sensitive comments in source code
- Social media links
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(
    r"(?:\+92|0092|0)?[0-9]{3}[-.\s]?[0-9]{7}|"
    r"(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
)

SOCIAL_PATTERNS: Dict[str, re.Pattern] = {
    "Facebook": re.compile(r"facebook\.com/([a-zA-Z0-9._\-]+)", re.IGNORECASE),
    "Twitter/X": re.compile(r"(?:twitter|x)\.com/([a-zA-Z0-9_]+)", re.IGNORECASE),
    "LinkedIn": re.compile(r"linkedin\.com/(?:in|company)/([a-zA-Z0-9._\-]+)", re.IGNORECASE),
    "Instagram": re.compile(r"instagram\.com/([a-zA-Z0-9._]+)", re.IGNORECASE),
    "YouTube": re.compile(r"youtube\.com/(?:c|channel|user)/([a-zA-Z0-9._\-]+)", re.IGNORECASE),
    "GitHub": re.compile(r"github\.com/([a-zA-Z0-9._\-]+)", re.IGNORECASE),
}

SECRET_PATTERNS: List[Dict[str, Any]] = [
    {"name": "AWS Access Key", "pattern": re.compile(r"AKIA[0-9A-Z]{16}"), "severity": "CRITICAL"},
    {"name": "AWS Secret Key", "pattern": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"), "severity": "CRITICAL"},
    {"name": "Google API Key", "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "severity": "HIGH"},
    {"name": "Google OAuth", "pattern": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "severity": "HIGH"},
    {"name": "GitHub Token", "pattern": re.compile(r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}"), "severity": "CRITICAL"},
    {"name": "Stripe Secret Key", "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "severity": "CRITICAL"},
    {"name": "Stripe Publishable Key", "pattern": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "severity": "MEDIUM"},
    {"name": "Slack Token", "pattern": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"), "severity": "HIGH"},
    {"name": "Slack Webhook", "pattern": re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]+"), "severity": "HIGH"},
    {"name": "Twilio API Key", "pattern": re.compile(r"SK[0-9a-fA-F]{32}"), "severity": "HIGH"},
    {"name": "SendGrid API Key", "pattern": re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"), "severity": "HIGH"},
    {"name": "JWT Token", "pattern": re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"), "severity": "MEDIUM"},
    {"name": "Private Key", "pattern": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "severity": "CRITICAL"},
    {"name": "Password in URL", "pattern": re.compile(r"(?i)(?:password|passwd|pwd)=[^&\s]{3,}"), "severity": "HIGH"},
    {"name": "Basic Auth in URL", "pattern": re.compile(r"https?://[^:]+:[^@]+@"), "severity": "HIGH"},
    {"name": "Database URL", "pattern": re.compile(r"(?i)(?:mysql|postgres|mongodb|redis)://[^\s\"']+"), "severity": "CRITICAL"},
    {"name": "Firebase URL", "pattern": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"), "severity": "MEDIUM"},
    {"name": "Mailchimp API", "pattern": re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"), "severity": "HIGH"},
    {"name": "PayPal Token", "pattern": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), "severity": "CRITICAL"},
    {"name": "Generic Secret", "pattern": re.compile(r"(?i)(?:secret|api_key|apikey|token|password)\s*[=:]\s*['\"][a-zA-Z0-9+/=_\-]{16,}['\"]"), "severity": "MEDIUM"},
]

SENSITIVE_COMMENTS = re.compile(
    r"(?i)(?://|/\*|<!--)\s*(?:todo|fixme|hack|bug|password|secret|key|token|credentials?|auth|debug|remove|temp|temporary)[^\n]*",
    re.IGNORECASE,
)

JS_FILE_PATTERN = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    secret_type: str
    value: str
    severity: str
    location: str = "page"

    def to_dict(self) -> Dict[str, Any]:
        masked = self.value[:6] + "***" + self.value[-4:] if len(self.value) > 12 else "***"
        return {
            "type": self.secret_type,
            "value_masked": masked,
            "severity": self.severity,
            "location": self.location,
        }


@dataclass
class HarvesterResult:
    url: str
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    social_links: Dict[str, List[str]] = field(default_factory=dict)
    secrets: List[SecretFinding] = field(default_factory=list)
    sensitive_comments: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "emails": self.emails,
            "phones": self.phones,
            "social_links": self.social_links,
            "secrets": [s.to_dict() for s in self.secrets],
            "sensitive_comments": self.sensitive_comments[:10],
            "js_files_found": len(self.js_files),
            "summary": {
                "emails_found": len(self.emails),
                "phones_found": len(self.phones),
                "secrets_found": len(self.secrets),
                "comments_found": len(self.sensitive_comments),
            },
        }


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def harvest_from_text(text: str, url: str = "", location: str = "page") -> HarvesterResult:
    result = HarvesterResult(url=url)
    seen_emails: Set[str] = set()
    seen_phones: Set[str] = set()

    # Emails
    for match in EMAIL_PATTERN.finditer(text):
        email = match.group(0).lower()
        skip_domains = {"example.com", "domain.com", "email.com", "test.com", "sentry.io"}
        if email not in seen_emails and not any(d in email for d in skip_domains):
            seen_emails.add(email)
            result.emails.append(email)

    # Phones
    for match in PHONE_PATTERN.finditer(text):
        phone = match.group(0).strip()
        if len(phone) >= 10 and phone not in seen_phones:
            seen_phones.add(phone)
            result.phones.append(phone)

    # Social links
    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            result.social_links[platform] = list(set(matches))

    # Secrets
    for secret_def in SECRET_PATTERNS:
        for match in secret_def["pattern"].finditer(text):
            value = match.group(0)
            result.secrets.append(SecretFinding(
                secret_type=secret_def["name"],
                value=value,
                severity=secret_def["severity"],
                location=location,
            ))

    # Sensitive comments
    for match in SENSITIVE_COMMENTS.finditer(text):
        comment = match.group(0).strip()[:200]
        if comment not in result.sensitive_comments:
            result.sensitive_comments.append(comment)

    # JS files
    for match in JS_FILE_PATTERN.finditer(text):
        js_url = match.group(1)
        if js_url not in result.js_files:
            result.js_files.append(js_url)

    return result


async def harvest_url(
    url: str,
    user_agent: str = "Mozilla/5.0",
    timeout: float = 15.0,
    verify_ssl: bool = True,
    scan_js: bool = True,
) -> HarvesterResult:
    """Full harvesting — page + JS files."""
    result = HarvesterResult(url=url)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": user_agent},
            verify=verify_ssl,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            body = resp.text[:50000]

        page_result = harvest_from_text(body, url=url, location="main_page")
        result.emails = page_result.emails
        result.phones = page_result.phones
        result.social_links = page_result.social_links
        result.secrets = page_result.secrets
        result.sensitive_comments = page_result.sensitive_comments
        result.js_files = page_result.js_files

        # Scan JS files
        if scan_js and result.js_files:
            base = url.rstrip("/")
            sem = asyncio.Semaphore(5)

            async def _scan_js(js_path: str) -> None:
                js_url = js_path if js_path.startswith("http") else f"{base}/{js_path.lstrip('/')}"
                async with sem:
                    try:
                        async with httpx.AsyncClient(
                            timeout=10.0,
                            headers={"User-Agent": user_agent},
                            verify=verify_ssl,
                        ) as jclient:
                            jr = await jclient.get(js_url)
                            if jr.status_code == 200:
                                js_result = harvest_from_text(jr.text[:30000], url=js_url, location=f"js:{js_path}")
                                result.secrets.extend(js_result.secrets)
                                result.sensitive_comments.extend(js_result.sensitive_comments)
                                for email in js_result.emails:
                                    if email not in result.emails:
                                        result.emails.append(email)
                    except Exception:
                        pass

            tasks = [asyncio.create_task(_scan_js(js)) for js in result.js_files[:10]]
            await asyncio.gather(*tasks, return_exceptions=True)

        if result.emails or result.secrets:
            logger.info(
                "Harvester found %d emails, %d secrets on %s",
                len(result.emails), len(result.secrets), url,
            )

    except Exception as exc:
        logger.warning("Harvester failed for %s: %s", url, exc)

    return result
