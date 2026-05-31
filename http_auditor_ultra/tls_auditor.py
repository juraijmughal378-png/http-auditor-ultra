"""TLS/SSL certificate deep inspection module."""

from __future__ import annotations

import asyncio
import logging
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_STRONG_CIPHERS: Tuple[str, ...] = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
)

_WEAK_CIPHERS: Tuple[str, ...] = ("RC4", "DES", "3DES", "CBC-SHA", "IDEA", "SEED")

_TLS_VERSIONS: Dict[str, str] = {
    "TLSv1.3": "TLS 1.3 (strong)",
    "TLSv1.2": "TLS 1.2 (acceptable)",
    "TLSv1.1": "TLS 1.1 (deprecated)",
    "TLSv1": "TLS 1.0 (deprecated)",
    "SSLv3": "SSL 3.0 (insecure)",
    "SSLv2": "SSL 2.0 (insecure)",
}

_WEAK_SIGNATURE_ALGORITHMS: Tuple[str, ...] = ("md5", "sha1", "sha-1")


@dataclass
class TLSInfo:
    """Results from TLS/SSL certificate inspection."""

    hostname: str
    port: int = 443
    tls_version: str = ""
    cipher_suite: str = ""
    cipher_strength: str = "unknown"
    certificate_valid: bool = False
    not_before: str = ""
    not_after: str = ""
    days_remaining: int = 0
    issuer: str = ""
    subject: str = ""
    common_name: str = ""
    subject_alt_names: List[str] = field(default_factory=list)
    signature_algorithm: str = ""
    weak_signature: bool = False
    self_signed: bool = False
    chain_length: int = 0
    error: Optional[str] = None

    @property
    def is_expiring_soon(self) -> bool:
        return 0 < self.days_remaining <= 30

    @property
    def is_expired(self) -> bool:
        return self.days_remaining <= 0 and self.not_after != ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "tls_version": self.tls_version,
            "tls_version_assessment": _TLS_VERSIONS.get(self.tls_version, "unknown"),
            "cipher_suite": self.cipher_suite,
            "cipher_strength": self.cipher_strength,
            "certificate_valid": self.certificate_valid,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_remaining": self.days_remaining,
            "expiring_soon": self.is_expiring_soon,
            "expired": self.is_expired,
            "issuer": self.issuer,
            "subject": self.subject,
            "common_name": self.common_name,
            "subject_alt_names": self.subject_alt_names,
            "signature_algorithm": self.signature_algorithm,
            "weak_signature": self.weak_signature,
            "self_signed": self.self_signed,
            "chain_length": self.chain_length,
            "error": self.error or "",
        }


async def audit_tls(hostname: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    """Perform deep TLS/SSL certificate inspection on a host."""
    info = TLSInfo(hostname=hostname, port=port)

    try:
        loop = asyncio.get_running_loop()

        def _connect() -> TLSInfo:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    info.tls_version = ssock.version() or ""
                    cipher_info = ssock.cipher()
                    info.cipher_suite = cipher_info[0] if cipher_info else ""

                    if any(s in info.cipher_suite for s in _STRONG_CIPHERS):
                        info.cipher_strength = "strong"
                    elif any(s in info.cipher_suite for s in _WEAK_CIPHERS):
                        info.cipher_strength = "weak"
                    else:
                        info.cipher_strength = "unknown"

                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                            info.not_before = cert.not_valid_before_utc.isoformat()
                            info.not_after = cert.not_valid_after_utc.isoformat()
                            now = datetime.now(timezone.utc)
                            info.certificate_valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
                            info.days_remaining = (cert.not_valid_after_utc - now).days

                            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                            info.common_name = cn[0].value if cn else ""

                            org = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
                            country = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)
                            parts = []
                            if country:
                                parts.append(f"C={country[0].value}")
                            if org:
                                parts.append(f"O={org[0].value}")
                            if cn:
                                parts.append(f"CN={cn[0].value}")
                            info.subject = ", ".join(parts)

                            i_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                            i_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
                            i_parts = []
                            if i_org:
                                i_parts.append(f"O={i_org[0].value}")
                            if i_cn:
                                i_parts.append(f"CN={i_cn[0].value}")
                            info.issuer = ", ".join(i_parts)
                            info.self_signed = info.subject == info.issuer

                            try:
                                san_ext = cert.extensions.get_extension_for_oid(
                                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                                )
                                info.subject_alt_names = [str(name.value) for name in san_ext.value]
                            except x509.ExtensionNotFound:
                                pass

                            try:
                                sig_alg = cert.signature_hash_algorithm
                                info.signature_algorithm = sig_alg.name if sig_alg else ""
                            except Exception:
                                info.signature_algorithm = ""

                            info.weak_signature = any(
                                w in info.signature_algorithm.lower()
                                for w in _WEAK_SIGNATURE_ALGORITHMS
                            )
                        except Exception as exc:
                            logger.warning("Certificate parsing failed for %s: %s", hostname, exc)

            return info

        info = await loop.run_in_executor(None, _connect)

    except ssl.SSLError as exc:
        info.error = f"SSL error: {exc}"
        logger.warning("TLS audit SSL error for %s:%d: %s", hostname, port, exc)
    except socket.timeout:
        info.error = f"Connection timed out after {timeout}s"
    except OSError as exc:
        info.error = f"Connection error: {exc}"
    except Exception as exc:
        info.error = f"Unexpected error: {exc}"
        logger.exception("TLS audit failed for %s:%d", hostname, port)

    return info


async def audit_tls_multi(
    hostname: str,
    ports: Optional[List[int]] = None,
    timeout: float = 10.0,
) -> List[TLSInfo]:
    """Audit TLS on multiple ports for the same hostname."""
    if ports is None:
        ports = [443]
    results: List[TLSInfo] = []
    for port in ports:
        result = await audit_tls(hostname, port, timeout)
        results.append(result)
    return results
