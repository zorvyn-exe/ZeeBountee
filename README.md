# ZeeBountee

**ZeeBountee** is a professional, highly modular, asynchronous Python CLI Reconnaissance and Asset Discovery Tool designed for vulnerability assessments and bug bounty hunting. Built natively on `asyncio` and `httpx`, it guarantees high-performance asynchronous networking, customizable scope validation, and robust reporting.

## 🚀 Key Features

- **Asynchronous Engine**: Non-blocking I/O operations for incredibly fast asset discovery and vulnerability scanning using `httpx` and `asyncio`.
- **Strict Scope Validation**: Configurable `config.json` backend to enforce strict "in-scope" / "out-of-scope" rules. Never accidentally scan out-of-bounds targets again!
- **Concurrency Control**: Intelligently handles concurrency limits via `asyncio.Semaphore` to prevent resource exhaustion and connection dropping.
- **Vulnerability Scanning**: Modular `SecurityCheck` architecture out-of-the-box for:
  - Security Headers (HSTS, CSP, X-Frame-Options)
  - Cookie Security (Secure, HttpOnly, SameSite)
  - TLS/SSL Configuration Flags
  - Information Disclosure (Server Tokens, Frameworks)
- **Advanced Reporting**: Jinja2-powered dynamic HTML reporting and machine-readable JSON exports containing executive summaries, automatic risk scoring, and severity distributions.
- **Beautiful CLI**: Gorgeous terminal outputs using `rich`.

## 📦 Installation

Ensure you have Python 3.10+ installed.

```bash
# Clone the repository
git clone https://github.com/yourusername/ZeeBountee.git
cd ZeeBountee

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install the tool in development mode with all dependencies
pip install -e .[dev]
```

## 🛠️ Usage

ZeeBountee operates using subcommands for isolated module execution or a unified `scan` command for full automation.

### Full Automated Scan
Run the entire assessment lifecycle (Recon -> Ports -> Subdomains -> Vulnerabilities) and generate a comprehensive HTML report.

```bash
zeebountee scan example.com
```

*Options:*
- `--timeout 10.0` : Specify network timeout limits.
- `--format json` : Generate a machine-readable JSON report instead of HTML.
- `--output report.html` : Specify the output file path.

### Isolated Modules
Run specific engine modules independently for targeted tasks:

- **Liveness Probing**: Check if a target is reachable and identify the underlying server.
  ```bash
  zeebountee recon example.com
  ```
- **Port Scanning**: Scan common ports (80, 443, 8080, 8443) to discover active services.
  ```bash
  zeebountee ports example.com
  ```
- **Subdomain Discovery**: Brute-force/enumerate subdomains using a common wordlist.
  ```bash
  zeebountee discover example.com
  ```
- **Web Discovery**: Perform safe checks for standard endpoints like `robots.txt` and `sitemap.xml`.
  ```bash
  zeebountee discover-web example.com
  ```
- **Vulnerability Assessment**: Run active security checks against the target.
  ```bash
  zeebountee vuln example.com
  ```

## 🧪 Testing and Verification

ZeeBountee is fully tested (100% module coverage) with `pytest`. It enforces strict static typing with `mypy` and linting standards with `ruff`.

```bash
# Run the entire test suite
pytest

# Verify static typing
mypy zeebountee tests

# Check linting and formatting
ruff check zeebountee tests
```

## 📄 License

This project is licensed under the MIT License. Use responsibly and only on targets you have explicit permission to assess.
