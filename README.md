# 🛡️ HTTP Auditor Ultra v2.0.0

> Advanced HTTP auditing & reconnaissance framework for authorized security assessments.

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-95%20passed-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0.0-orange?style=flat-square)

---

## ✨ Features

| Module | Capability |
|--------|-----------|
| 🔍 **HTTP Auditing** | Concurrent async requests, retry with exponential backoff |
| 🧱 **WAF Detection** | 30+ signatures — Cloudflare, AWS, ModSecurity, Akamai, Imperva & more |
| 🖥️ **Tech Fingerprinting** | Nginx, Apache, PHP, WordPress, React, CDNs and more |
| 🔒 **TLS/SSL Audit** | Certificate expiry, cipher strength, weak signatures, SANs |
| 📋 **Security Headers** | OWASP scoring — CSP, HSTS, X-Frame-Options, and 7 more |
| 🌐 **Subdomain Enum** | DNS brute-force + Certificate Transparency logs (crt.sh) |
| 🔌 **Port Scanning** | Async TCP scan on common HTTP/S ports |
| 📂 **Path Discovery** | Wordlist-based directory/file brute-force |
| 📊 **Reports** | JSON, CSV, and dark-themed HTML dashboard |

---

## 📁 Project Structure

```
http_auditor_ultra/
├── http_auditor_ultra/
│   ├── __main__.py        # Entry point & orchestrator
│   ├── config.py          # Configuration management (YAML/JSON)
│   ├── client.py          # Async HTTP client with retry logic
│   ├── fingerprint.py     # WAF detection & tech fingerprinting
│   ├── scanner.py         # Port scan, subdomain & path discovery
│   ├── tls_auditor.py     # TLS/SSL certificate inspection
│   ├── reporter.py        # JSON, CSV, HTML report generation
│   ├── cli.py             # Argparse CLI
│   ├── utils.py           # Shared utilities
│   └── data/
│       ├── subdomains.txt # 80+ subdomain wordlist
│       └── paths.txt      # 70+ path discovery wordlist
├── tests/                 # 95 tests — full coverage
└── pyproject.toml
```

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/juraijmughal378-png/http-auditor-ultra.git
cd http-auditor-ultra

# Install (Python 3.12+ required)
pip install -e .

# Install with dev/test dependencies
pip install -e ".[dev]"
```

---

## 🚀 Usage

### Basic scan
```bash
python -m http_auditor_ultra https://example.com
```

### Full Ultra scan
```bash
python -m http_auditor_ultra example.com \
  --subdomains \
  --scan-ports \
  --discover-paths \
  --html report.html \
  --json report.json
```

### Scan from URL list
```bash
python -m http_auditor_ultra urls.txt --max-concurrent 20 --timeout 60
```

### TLS + fingerprinting only
```bash
python -m http_auditor_ultra https://example.com --no-subdomains --json tls_report.json
```

### Custom ports + wordlist
```bash
python -m http_auditor_ultra example.com \
  --scan-ports \
  --custom-ports 80,443,8080,8443,3000 \
  --path-wordlist mypaths.txt
```

### With config file
```bash
python -m http_auditor_ultra target.com --config ultra.yaml --log-level DEBUG
```

---

## 🛠️ CLI Options

```
positional arguments:
  target                Target URL, domain, or path to URL list file

Connection settings:
  --timeout SECONDS     Request timeout (default: 30)
  --max-retries N       Max retry attempts (default: 3)
  --backoff-factor S    Exponential backoff base in seconds
  --max-concurrent N    Max concurrent requests (default: 10)
  --no-verify-ssl       Disable SSL certificate verification
  --no-follow-redirects Do not follow HTTP redirects

Ultra scanning modules:
  --subdomains          Enable subdomain enumeration (DNS + CT logs)
  --scan-ports          Enable port scanning
  --custom-ports PORTS  Custom port list e.g. 80,443,8080
  --discover-paths      Enable path/directory discovery
  --subdomain-wordlist  Custom subdomain wordlist file
  --path-wordlist       Custom path wordlist file
  --no-fingerprint      Disable WAF/tech fingerprinting
  --no-tls              Disable TLS/SSL audit

Output settings:
  -j, --json FILE       Write JSON report
  --csv FILE            Write CSV report
  --html FILE           Write HTML dashboard report
  --log-level LEVEL     DEBUG / INFO / WARNING / ERROR
```

---

## 📄 Config File (YAML)

```yaml
timeout: 30.0
max_retries: 3
max_concurrent: 15
rate_limit_delay: 0.5
verify_ssl: true
follow_redirects: true
log_level: INFO
fingerprint_enabled: true
tls_audit_enabled: true
subdomain_enum_enabled: false
port_scan_enabled: false
path_discovery_enabled: false
common_ports: [80, 443, 8080, 8443, 8000]
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
# 95 passed in < 1s
```

---

## ⚠️ Legal Disclaimer

> This tool is intended **only for authorized security assessments**.  
> Always obtain written permission before scanning any target.  
> Unauthorized use may violate laws. The authors are not responsible for misuse.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  Made with ❤️ by <a href="https://github.com/juraijmughal378-png">juraijmughal378-png</a>
</div>
