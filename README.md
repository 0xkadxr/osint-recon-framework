![CI](https://github.com/kadirou12333/osint-recon-framework/actions/workflows/ci.yml/badge.svg?branch=master)

# OSINTRecon

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

**Lightweight OSINT reconnaissance framework for CTF competitions and security research.**
Modular, extensible, and async -- built for speed and flexibility.

---

## Features

| Module | Description |
|--------|-------------|
| **Username Lookup** | Check 50+ platforms for username registration (GitHub, Twitter/X, Reddit, Instagram, HackTheBox, TryHackMe, etc.) |
| **Domain Recon** | WHOIS, DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA), subdomain brute-force, technology detection, SSL certificate analysis |
| **Email OSINT** | Email validation, MX record check, breach lookup (HIBP-style), Gravatar detection, related account discovery |
| **Metadata Extraction** | EXIF data from images (GPS, camera, timestamps), PDF metadata (author, creator, dates), Office document metadata |
| **Geolocation** | IP-to-location mapping, image GPS extraction, timezone estimation, Haversine distance calculation |
| **Social Discovery** | Cross-platform profile search via public APIs (GitHub, Reddit, GitLab, Keybase, HackerNews, etc.) |
| **Web Archive** | Wayback Machine snapshot lookup, date-range queries, cached page retrieval |

## Quick Start

### Installation

```bash
git clone https://github.com/kadirou12333/osint-recon-framework.git
cd osint-recon-framework
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

### Basic Usage (Python)

```python
import asyncio
from osintrecon import ReconEngine

async def main():
    engine = ReconEngine()

    # Username investigation
    result = await engine.investigate_username("johndoe")
    for p in result.findings["username_platforms"]:
        if p["exists"]:
            print(f"[+] {p['name']}: {p['profile_url']}")

    # Domain reconnaissance
    result = await engine.investigate_domain("example.com")
    print(result.findings["dns"])

    # Email OSINT
    result = await engine.investigate_email("user@example.com")
    print(result.findings)

asyncio.run(main())
```

## CLI Usage

OSINTRecon ships with a feature-rich CLI powered by [Rich](https://github.com/Textualize/rich):

```bash
# Username lookup across 50+ platforms
python cli.py username johndoe

# Domain reconnaissance
python cli.py domain example.com

# Email investigation
python cli.py email user@example.com

# File metadata extraction
python cli.py metadata photo.jpg

# Full auto-detect investigation
python cli.py full johndoe

# With options
python cli.py username johndoe --output markdown --save
python cli.py domain example.com --output html --timeout 30
python cli.py email user@example.com --threads 50 --proxy socks5://127.0.0.1:9050
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Report format: `json`, `markdown`, `html` (default: `json`) |
| `--timeout`, `-t` | HTTP timeout in seconds (default: 15) |
| `--threads` | Max concurrent requests (default: 30) |
| `--proxy` | Proxy URL (e.g., `socks5://127.0.0.1:9050`) |
| `--save`, `-s` | Save report to `./reports/` directory |
| `--verbose`, `-v` | Enable verbose output |

## Module Documentation

### ReconEngine

The central orchestrator that wires all modules together:

```python
from osintrecon import ReconEngine, Config

config = Config(
    timeout=20,
    max_concurrent=50,
    proxy="socks5://127.0.0.1:9050",
    verbose=True,
)
engine = ReconEngine(config)

# All investigation methods are async
result = await engine.investigate_username("target")
result = await engine.investigate_domain("example.com")
result = await engine.investigate_email("user@example.com")
result = await engine.extract_metadata("file.jpg")
result = await engine.run_all("target", target_type="auto")

# Generate reports
report = await engine.generate_report(result, fmt="html")
```

### Username Module

```python
from osintrecon.modules.username import UsernameModule

mod = UsernameModule()
results = await mod.check_all("johndoe")
variations = mod.generate_variations("johndoe")
```

### Domain Module

```python
from osintrecon.modules.domain import DomainModule

mod = DomainModule()
whois = await mod.whois_lookup("example.com")
dns = await mod.dns_records("example.com")
subs = await mod.subdomain_enum("example.com")
tech = await mod.technology_detection("example.com")
ssl = await mod.ssl_info("example.com")
```

### Metadata Module

```python
from osintrecon.modules.metadata import MetadataModule

mod = MetadataModule()
exif = mod.extract_exif("photo.jpg")
pdf = mod.extract_pdf_metadata("document.pdf")
office = mod.extract_office_metadata("report.docx")
location = mod.gps_to_location(48.8566, 2.3522)
```

## Adding Custom Modules

Create a new module in `osintrecon/modules/`:

```python
# osintrecon/modules/my_module.py
from typing import Any, Dict

class MyModule:
    """Custom OSINT module."""

    def __init__(self, config=None):
        self.config = config

    async def investigate(self, target: str) -> Dict[str, Any]:
        # Your investigation logic here
        return {"target": target, "findings": {...}}
```

Then wire it into the engine or use it standalone:

```python
from osintrecon.modules.my_module import MyModule

mod = MyModule()
result = await mod.investigate("target")
```

## CTF Tips

- **Username pivoting**: Found a username? Run it through the username module to find other platforms. Cross-reference bios and linked accounts.
- **Image metadata**: Challenge gives you an image? Extract EXIF for GPS coordinates, camera model, timestamps, and software used.
- **Domain recon**: Look at DNS TXT records for flags, check SSL certificate SANs for hidden subdomains, brute-force subdomains.
- **Email trails**: Derive usernames from email local parts, check Gravatar for profile photos, look for breach data.
- **Wayback Machine**: Check for old versions of pages that may contain removed content or flags.
- **Proxy through Tor**: Use `--proxy socks5://127.0.0.1:9050` to route requests through Tor for anonymity.

## Ethical Use & Legal Disclaimer

This tool is designed for **authorized security research**, **CTF competitions**, and **educational purposes only**.

- Only use this tool against targets you have explicit permission to test.
- Respect rate limits and terms of service of third-party platforms.
- Do not use this tool for harassment, stalking, or any illegal activity.
- The authors are not responsible for misuse of this tool.

**Always obtain proper authorization before conducting any reconnaissance.**

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-module`)
3. Write tests for new functionality
4. Ensure all tests pass (`pytest`)
5. Submit a pull request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
