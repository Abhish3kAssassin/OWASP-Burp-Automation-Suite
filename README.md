# OWASP + Burp Automation Suite

A Python-based web application security assessment framework that combines custom OWASP Top 10:2025-oriented checks with Burp Suite automation.

The project provides both a graphical interface and command-line mode for authorized web application assessments. It performs reconnaissance, security configuration analysis, API definition analysis, Burp Scanner orchestration, vulnerability collection, and automated report generation.

> This project is intended only for authorized security testing, cybersecurity laboratories, academic projects, and educational use.

## Features

* Python Tkinter graphical interface
* Command-line interface
* Authorized target allowlist
* Exact-host scope validation
* Rate-limited web crawling
* DNS resolution
* `robots.txt` discovery
* Sitemap discovery
* Endpoint discovery
* Form discovery
* Parameter discovery
* Technology identification
* Security header analysis
* TLS and certificate analysis
* Cookie security checks
* CORS analysis
* Mixed-content detection
* Clickjacking protection review
* Technology disclosure checks
* External JavaScript integrity review
* Authentication workflow discovery
* Access-control review candidates
* Injection/input-validation surface discovery
* SSRF candidate parameter discovery
* Exceptional-condition review
* Secure-design review areas
* Logging and alerting review areas
* OWASP Top 10:2025 mapping
* OpenAPI 3.x parsing
* Swagger 2.0 parsing
* Postman Collection parsing
* SOAP/WSDL parsing
* GraphQL introspection
* Burp Suite REST API integration
* Automatic Burp scan creation
* Burp scan status monitoring
* Burp findings collection
* Optional Burp Suite JAR launching
* Burp project loading
* Burp configuration loading
* Headless Burp support
* JSON reporting
* HTML reporting
* PDF reporting
* CSV reporting
* Sitemap export

## Project Architecture

```text
                     User
                      │
                      ▼
             ┌──────────────────┐
             │  Tkinter GUI /   │
             │       CLI        │
             └────────┬─────────┘
                      │
                      ▼
             ┌──────────────────┐
             │ Authorization &  │
             │ Scope Validation │
             └────────┬─────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │ Reconnaissance Engine│
           │ Crawl / Forms / APIs │
           └──────────┬───────────┘
                      │
          ┌───────────┴────────────┐
          │                        │
          ▼                        ▼
┌──────────────────┐     ┌──────────────────┐
│ OWASP Assessment │     │   API Analyzer   │
│      Engine      │     │ OpenAPI / WSDL   │
└────────┬─────────┘     │ Postman / GraphQL│
         │               └────────┬─────────┘
         └────────────┬───────────┘
                      │
                      ▼
             ┌──────────────────┐
             │ Burp REST API    │
             └────────┬─────────┘
                      │
                      ▼
             ┌──────────────────┐
             │  Burp Scanner    │
             └────────┬─────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │ Findings Processor   │
           └──────────┬───────────┘
                      │
                      ▼
             ┌──────────────────┐
             │ Report Generator │
             ├──────────────────┤
             │ PDF HTML JSON CSV│
             └──────────────────┘
```

## OWASP Top 10:2025 Mapping

The framework maps observable findings and review areas to the OWASP Top 10:2025 categories:

1. A01 – Broken Access Control
2. A02 – Security Misconfiguration
3. A03 – Software Supply Chain Failures
4. A04 – Cryptographic Failures
5. A05 – Injection
6. A06 – Insecure Design
7. A07 – Authentication Failures
8. A08 – Software or Data Integrity Failures
9. A09 – Security Logging and Alerting Failures
10. A10 – Mishandling of Exceptional Conditions

The tool does not claim complete automated OWASP coverage.

Some categories require architecture review, authenticated testing, business-logic analysis, source-code review, logging verification, or manual security testing.

## Reconnaissance Module

The reconnaissance engine performs controlled, same-host discovery.

It can identify:

* DNS information
* Web pages
* Internal endpoints
* Forms
* Input parameters
* Query parameters
* Technologies
* `robots.txt`
* Sitemap entries

The crawler is rate-limited and restricted to the explicitly authorized hostname.

## Security Checks

The framework performs non-destructive checks for areas such as:

### Transport Security

* HTTPS usage
* TLS certificate validity
* Certificate expiry
* TLS protocol information

### Security Headers

* Content-Security-Policy
* Strict-Transport-Security
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy
* Clickjacking protection

### Cookie Security

The application checks for:

* `Secure`
* `HttpOnly`
* `SameSite`

### Other Checks

* CORS configuration
* Mixed HTTP/HTTPS resources
* Technology disclosure
* External script integrity
* Authentication surface discovery
* Input-validation attack surface
* Object identifier candidates
* URL-like parameters that may require SSRF review
* Server-side exception behavior

## API Security Analysis

The application can analyze common API definition formats.

Supported formats include:

* OpenAPI 3.x
* Swagger 2.0
* Postman Collection
* SOAP WSDL
* GraphQL

The API analyzer extracts endpoints and can use appropriate in-scope URLs as Burp scan seeds.

## Burp Suite Integration

The project integrates with Burp Suite through its REST API.

The application can:

* Connect to the Burp REST API
* Start a scan
* Select a scan configuration
* Monitor scan status
* Retrieve results
* Collect Burp findings
* Add Burp findings to the final assessment report

## Supported Burp Scan Profiles

The graphical interface exposes scan profiles including:

```text
Audit checks - passive
Audit checks - light active
Crawl and Audit - Lightweight
Crawl and Audit - CICD Optimized
Crawl and Audit - Fast
```

The default profile is:

```text
Audit checks - light active
```

This provides a safer default for authorized testing.

## Automatic Burp Launch

If a Burp Suite JAR file is supplied, the framework can launch Burp automatically.

The application supports:

* Burp JAR path
* Burp project file
* Burp configuration file
* Headless mode
* REST API connection
* Automatic scan startup

Example architecture:

```text
Python Application
        │
        ▼
Launch Burp Suite
        │
        ▼
Load Project / Config
        │
        ▼
Burp REST API
        │
        ▼
Scanner
        │
        ▼
Results
```

## Requirements

Recommended:

* Python 3.10+
* Burp Suite Professional or Burp Suite DAST for Scanner functionality
* Tkinter

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Or manually:

```bash
python -m pip install requests PyYAML reportlab
```

## Running the Application

Clone the repository:

```bash
git clone https://github.com/Abhish3kAssassin/OWASP-Burp-Automation-Suite.git
```

Enter the project directory:

```bash
cd owasp-burp-automation-suite
```

Start the graphical interface:

```bash
python app.py
```

On Linux or macOS:

```bash
python3 app.py
```

## GUI Workflow

1. Enter the target URL.
2. Enter or automatically use the authorized hostname.
3. Confirm that you own the target or have permission to test it.
4. Optionally select an API definition.
5. Configure Burp Suite if Scanner automation is required.
6. Select the desired Burp scan profile.
7. Click **Start Assessment**.
8. Monitor assessment progress.
9. Review findings in the Results tab.
10. Export or open the generated reports.

## Command-Line Usage

The framework can also run without the GUI.

Example:

```bash
python app.py --no-gui \
  --target https://app.example.test \
  --allow-host app.example.test \
  --authorized \
  --output-dir reports
```

## Burp Scanner Example

```bash
python app.py --no-gui \
  --target https://app.example.test \
  --allow-host app.example.test \
  --authorized \
  --burp-scan \
  --burp-api http://127.0.0.1:1337 \
  --burp-api-key YOUR_API_KEY
```

## Automatic Burp Launch Example

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
  --burp-api-key YOUR_API_KEY
```

## Project Structure

```text
owasp-burp-automation-suite/
│
├── app.py
├── README.md
├── requirements.txt
├── sample_config.json
├── run.sh
├── run.bat
├── LICENSE
├── screenshots/
└── reports/
```

## Reports

Each assessment can generate multiple output formats.

### JSON

Contains the complete machine-readable assessment.

### HTML

Provides a browser-friendly security assessment report.

### PDF

Provides a professional printable report containing:

* Target information
* Assessment summary
* Findings
* Severity
* OWASP mapping
* Evidence
* Remediation guidance

### CSV

Provides findings in a spreadsheet-compatible format.

### Sitemap

Exports discovered in-scope endpoints.

## Security and Safety Model

The application is designed around authorized testing.

It intentionally avoids automatically performing activities such as:

* Password brute forcing
* Credential stuffing
* Destructive testing
* Denial-of-service attacks
* Exploit chaining
* Automated privilege escalation
* Automated IDOR manipulation
* Persistence
* Security-control evasion

The target hostname must exactly match the configured authorized-host allowlist.

## Use Cases

This project can be used for:

* Web application security assessment
* Cybersecurity education
* Ethical hacking laboratories
* OWASP security testing
* Burp Suite automation
* API security assessment
* Security automation research
* Academic cybersecurity projects
* Python security-tool integration

## Technologies Used

* Python
* Tkinter
* Requests
* PyYAML
* ReportLab
* OWASP Top 10:2025
* Burp Suite Professional / DAST
* Burp REST API
* OpenAPI
* Swagger
* Postman
* GraphQL
* SOAP/WSDL

## Current Limitations

Automated tools cannot fully evaluate every security problem.

Some areas still require manual review, including:

* Business logic vulnerabilities
* Complex authorization issues
* Multi-user access-control testing
* Secure architecture
* Threat modeling
* Authentication design
* Security logging effectiveness
* Incident-response monitoring
* Source-code vulnerabilities

The framework marks these areas as review workflows instead of presenting them as confirmed vulnerabilities.

## Future Scope

Planned improvements may include:

* Authentication profile support
* Session-aware crawling
* More advanced API assessment workflows
* CVSS scoring
* CVE enrichment
* Vulnerability deduplication
* Historical scan comparison
* Dashboard analytics
* Project saving and loading
* Scheduled assessments
* Burp issue comparison
* Unified OWASP + Burp + Metasploit dashboard
* Centralized vulnerability database
* Scan history
* Risk trend visualization

## Disclaimer

This software is intended only for educational purposes, cybersecurity laboratories, and authorized security testing.

Do not use this application against systems without explicit permission.

The developer is not responsible for misuse of this software.

Users are responsible for ensuring that all security testing complies with applicable laws, policies, and authorization requirements.

## Author

**Abhishek Rahang**

Cybersecurity / Cloud Technology / Information Security

## License

This project can be released under the MIT License.
