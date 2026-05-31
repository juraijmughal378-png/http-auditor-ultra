"""
HTTP Auditor Ultra — Advanced HTTP auditing & reconnaissance framework.

Features:
  - Full HTTP/S request auditing with retry and backoff
  - WAF fingerprinting and detection (40+ signatures)
  - Technology stack identification
  - TLS/SSL certificate deep inspection
  - Security header analysis with OWASP scoring
  - Subdomain enumeration (DNS brute-force + Certificate Transparency)
  - Port scanning on common HTTP/S ports
  - Path/directory discovery with wordlist
  - Concurrent async architecture
  - JSON, CSV, and HTML report output
"""

from http_auditor_ultra._version import __version__ as _ver

__version__: str = _ver
__author__: str = "HackerAI"

__all__: list[str] = ["__version__", "__author__"]
