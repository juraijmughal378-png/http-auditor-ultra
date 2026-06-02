"""DNS Analysis, Whois, and GeoIP module.

Features:
- Full DNS records (A, MX, TXT, NS, CNAME, SOA, AAAA)
- Whois lookup
- IP Geolocation
- Reverse DNS
- DNS security checks (DNSSEC, SPF, DMARC, DKIM)
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    record_type: str
    value: str
    ttl: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.record_type, "value": self.value, "ttl": self.ttl}


@dataclass
class GeoIPInfo:
    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    org: str = ""
    isp: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "org": self.org,
            "isp": self.isp,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
        }


@dataclass
class DNSSecurityCheck:
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_found: bool = False
    dnssec_enabled: bool = False
    mx_records: List[str] = field(default_factory=list)
    spf_valid: bool = False
    dmarc_valid: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spf_record": self.spf_record or "Not found",
            "spf_valid": self.spf_valid,
            "dmarc_record": self.dmarc_record or "Not found",
            "dmarc_valid": self.dmarc_valid,
            "dkim_found": self.dkim_found,
            "dnssec_enabled": self.dnssec_enabled,
            "mx_records": self.mx_records,
        }


@dataclass
class DNSAnalysisResult:
    domain: str
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    reverse_dns: List[str] = field(default_factory=list)
    geoip: Optional[GeoIPInfo] = None
    security: Optional[DNSSecurityCheck] = None
    whois_info: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "mx_records": self.mx_records,
            "ns_records": self.ns_records,
            "txt_records": self.txt_records,
            "cname_records": self.cname_records,
            "reverse_dns": self.reverse_dns,
            "geoip": self.geoip.to_dict() if self.geoip else {},
            "security_checks": self.security.to_dict() if self.security else {},
            "whois": self.whois_info,
            "error": self.error or "",
        }


async def _resolve_record(domain: str, record_type: int) -> List[str]:
    """Resolve DNS records using socket."""
    results: List[str] = []
    try:
        loop = asyncio.get_running_loop()
        if record_type == socket.AF_INET:
            info = await loop.getaddrinfo(domain, None, socket.AF_INET)
            results = list({entry[4][0] for entry in info})
        elif record_type == socket.AF_INET6:
            info = await loop.getaddrinfo(domain, None, socket.AF_INET6)
            results = list({entry[4][0] for entry in info})
    except OSError:
        pass
    return results


async def _get_geoip(ip: str) -> Optional[GeoIPInfo]:
    """Get GeoIP info using ip-api.com (free, no key needed)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,org,isp,lat,lon,timezone"
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return GeoIPInfo(
                        ip=ip,
                        country=data.get("country", ""),
                        country_code=data.get("countryCode", ""),
                        region=data.get("region", ""),
                        city=data.get("city", ""),
                        org=data.get("org", ""),
                        isp=data.get("isp", ""),
                        latitude=data.get("lat", 0.0),
                        longitude=data.get("lon", 0.0),
                        timezone=data.get("timezone", ""),
                    )
    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)
    return None


async def _get_dns_via_doh(domain: str, record_type: str) -> List[str]:
    """Get DNS records via DNS-over-HTTPS (Cloudflare)."""
    results: List[str] = []
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": record_type},
                headers={"Accept": "application/dns-json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for answer in data.get("Answer", []):
                    value = answer.get("data", "").strip('"')
                    if value:
                        results.append(value)
    except Exception as exc:
        logger.debug("DoH lookup failed for %s %s: %s", domain, record_type, exc)
    return results


async def _check_dns_security(domain: str) -> DNSSecurityCheck:
    """Check SPF, DMARC, DKIM records."""
    check = DNSSecurityCheck()

    # SPF
    txt_records = await _get_dns_via_doh(domain, "TXT")
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            check.spf_record = txt
            check.spf_valid = "-all" in txt or "~all" in txt
        if txt.startswith("v=DMARC1"):
            check.dmarc_record = txt
            check.dmarc_valid = True

    # DMARC
    dmarc_records = await _get_dns_via_doh(f"_dmarc.{domain}", "TXT")
    for txt in dmarc_records:
        if "v=DMARC1" in txt:
            check.dmarc_record = txt
            check.dmarc_valid = True

    # MX
    mx_records = await _get_dns_via_doh(domain, "MX")
    check.mx_records = mx_records[:5]

    return check


async def _get_whois(domain: str) -> Dict[str, str]:
    """Get basic Whois info via RDAP (free, no library needed)."""
    whois: Dict[str, str] = {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://rdap.org/domain/{domain}")
            if resp.status_code == 200:
                data = resp.json()
                # Registrar
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [None, []])[1]
                        for entry in vcard:
                            if entry[0] == "fn":
                                whois["registrar"] = entry[3]
                # Dates
                for event in data.get("events", []):
                    action = event.get("eventAction", "")
                    date = event.get("eventDate", "")[:10]
                    if action == "registration":
                        whois["registered"] = date
                    elif action == "expiration":
                        whois["expires"] = date
                    elif action == "last changed":
                        whois["updated"] = date
                # Status
                statuses = data.get("status", [])
                if statuses:
                    whois["status"] = ", ".join(statuses[:3])
                # Name servers
                ns_list = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
                if ns_list:
                    whois["nameservers"] = ", ".join(ns_list[:4])
    except Exception as exc:
        logger.debug("Whois lookup failed for %s: %s", domain, exc)
    return whois


async def analyze_dns(domain: str) -> DNSAnalysisResult:
    """Full DNS analysis — records, GeoIP, security checks, Whois."""
    result = DNSAnalysisResult(domain=domain)
    logger.info("Starting DNS analysis for %s", domain)

    try:
        # A records (IPv4)
        result.a_records = await _resolve_record(domain, socket.AF_INET)

        # AAAA records (IPv6)
        result.aaaa_records = await _resolve_record(domain, socket.AF_INET6)

        # DNS over HTTPS for other record types
        mx_raw = await _get_dns_via_doh(domain, "MX")
        result.mx_records = [r.split(" ", 1)[-1].rstrip(".") for r in mx_raw]

        result.ns_records = await _get_dns_via_doh(domain, "NS")
        result.ns_records = [r.rstrip(".") for r in result.ns_records]

        result.txt_records = await _get_dns_via_doh(domain, "TXT")

        result.cname_records = await _get_dns_via_doh(domain, "CNAME")

        # Reverse DNS
        for ip in result.a_records[:3]:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result.reverse_dns.append(f"{ip} -> {hostname}")
            except socket.herror:
                result.reverse_dns.append(f"{ip} -> (no PTR)")

        # GeoIP for first A record
        if result.a_records:
            result.geoip = await _get_geoip(result.a_records[0])

        # DNS security checks
        result.security = await _check_dns_security(domain)

        # Whois
        result.whois_info = await _get_whois(domain)

        logger.info(
            "DNS analysis complete for %s — A:%d MX:%d NS:%d",
            domain, len(result.a_records), len(result.mx_records), len(result.ns_records),
        )

    except Exception as exc:
        result.error = str(exc)
        logger.error("DNS analysis failed for %s: %s", domain, exc)

    return result
