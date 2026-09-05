# OWASP + Burp Automation Suite v2.0

A Python desktop/CLI framework for **authorized** web-application security assessments.

## Features

- Tkinter desktop dashboard
- Exact-host authorization allowlist
- Same-host, rate-limited reconnaissance
- DNS resolution
- `robots.txt` and sitemap discovery
- Same-host endpoint crawler
- Form and parameter inventory
- Lightweight technology identification
- OWASP Top 10:2025-oriented evidence mapping
- TLS/certificate checks
- Security-header, cookie, CORS and mixed-content checks
- Access-control, injection, SSRF, logging and secure-design **review workflows**
- External-script integrity review
- OpenAPI 3.x / Swagger 2.0 parsing
- Postman Collection parsing
- SOAP WSDL parsing
- GraphQL introspection
- Burp Suite REST API scan orchestration
- Optional Burp JAR launch
- Burp project/config loading
- Live scan status in the GUI log
- Burp issue extraction from returned scan data
- JSON, HTML, CSV and PDF reports
- Text sitemap export

## Safety model

This tool is designed for systems you own or are explicitly authorized to assess.

It deliberately does **not** automate:
- password brute forcing
- credential stuffing
- exploit chaining
- destructive payloads
- denial of service
- arbitrary file upload exploitation
- automated IDOR/access-control manipulation
- persistence
- stealth/evasion

The target hostname must exactly match the configured allowlist.

## Requirements

Python 3.10+ recommended.

Install:

```bash
python -m pip install -r requirements.txt
```

Tkinter is included with most Python distributions. On some Linux distributions it is packaged separately.

## Start the GUI

macOS / Linux:

```bash
python3 app.py
```

Windows:

```powershell
python app.py
```

### GUI workflow

1. Enter the target URL.
2. Click **Use target host**.
3. Check the explicit authorization checkbox.
4. Optionally select an OpenAPI/Postman/WSDL file or GraphQL endpoint.
5. Configure Burp under **Settings** if you want Scanner orchestration.
6. Click **Start Assessment**.
7. Review findings in **Results**.
8. Open the generated HTML/PDF/JSON/CSV reports.

## CLI example — local checks only

```bash
python app.py --no-gui \
  --target https://app.example.test \
  --allow-host app.example.test \
  --authorized \
  --output-dir reports
```

## CLI example — Burp Scanner

First enable Burp's REST API, preferably on loopback, and create an API key.

```bash
python app.py --no-gui \
  --target https://app.example.test \
  --allow-host app.example.test \
  --authorized \
  --burp-scan \
  --burp-api http://127.0.0.1:1337 \
  --burp-api-key YOUR_KEY \
  --burp-scan-configuration "Audit checks - light active"
```

## Launch Burp automatically

```bash
python app.py --no-gui \
  --target https://app.example.test \
  --allow-host app.example.test \
  --authorized \
  --burp-jar /path/to/burpsuite_pro.jar \
  --burp-project ./assessment.burp \
  --burp-config ./project-options.json \
  --burp-scan \
  --burp-api http://127.0.0.1:1337 \
  --burp-api-key YOUR_KEY
```

Add `--headless` if desired.

## API definitions

Supported parsing/import assistance:

- OpenAPI 3.x JSON/YAML
- Swagger 2.0 JSON/YAML
- Postman Collection v2.1 JSON
- SOAP WSDL
- GraphQL endpoint introspection

For OpenAPI/Postman/WSDL, the application extracts concrete in-scope endpoint URLs and can add them as Burp scan seeds. It does not invent values for templated path parameters.

## Burp profiles exposed in the GUI

- Audit checks - passive
- Audit checks - light active
- Crawl and Audit - Lightweight
- Crawl and Audit - CICD Optimized
- Crawl and Audit - Fast

The default is **Audit checks - light active**.

## Reports

Every run can generate:

- JSON — complete machine-readable assessment
- HTML — printable human-readable report
- CSV — findings table
- PDF — direct report when `reportlab` is installed
- Sitemap TXT — discovered in-scope endpoints

## OWASP coverage note

This project maps evidence to the current OWASP Top 10:2025 categories, but does not claim complete automated OWASP coverage. Some categories inherently require architecture, business-logic, authorization, source-code, logging, identity, or manual workflow review.

## OWASP Top 10:2025 mapping

The report uses the current released categories:

1. A01 Broken Access Control
2. A02 Security Misconfiguration
3. A03 Software Supply Chain Failures
4. A04 Cryptographic Failures
5. A05 Injection
6. A06 Insecure Design
7. A07 Authentication Failures
8. A08 Software or Data Integrity Failures
9. A09 Security Logging and Alerting Failures
10. A10 Mishandling of Exceptional Conditions

SSRF candidate inputs are still surfaced as a specialized review item, but they are not incorrectly labeled as A10:2025.
