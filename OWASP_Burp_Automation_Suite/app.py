#!/usr/bin/env python3
"""
OWASP + Burp Automation Suite
=============================

Authorized web-security assessment framework with:
- Desktop GUI (Tkinter) and CLI mode
- Exact-host authorization allowlist
- Same-host, rate-limited reconnaissance
- OWASP Top 10-oriented evidence mapping
- API definition parsing (OpenAPI/Swagger, Postman, WSDL, GraphQL introspection)
- Burp Suite Professional/DAST REST orchestration
- Optional Burp JAR launch with project/config files
- JSON, HTML, CSV and PDF reporting
- Sitemap export

This tool is intended only for systems you own or are explicitly authorized to test.
It deliberately avoids brute forcing, exploit chaining, destructive payloads, and
automatic privilege/access-control attacks.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
import xml.etree.ElementTree as ET
from collections import Counter, deque
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import (
    parse_qsl,
    quote,
    urljoin,
    urlparse,
    urlunparse,
)

import requests

try:
    import yaml
except Exception:
    yaml = None

APP_NAME = "OWASP + Burp Automation Suite"
APP_VERSION = "2.0"
DEFAULT_TIMEOUT = 15
DEFAULT_USER_AGENT = f"Authorized-OWASP-Burp-Automation/{APP_VERSION}"
DEFAULT_MAX_PAGES = 30
DEFAULT_DELAY = 0.25

OWASP = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

SEVERITY_SCORE = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_host(host: str) -> str:
    return host.lower().rstrip(".")


def safe_filename(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._")
    return value or "assessment"


def parse_target(url: str):
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a complete http:// or https:// URL.")
    return parsed


def same_host(url: str, host: str) -> bool:
    try:
        return clean_host(urlparse(url).hostname or "") == clean_host(host)
    except Exception:
        return False


def normalize_url(url: str) -> str:
    p = urlparse(url)
    # Fragments are not sent to servers.
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def require_authorized_target(
    target: str,
    allowed_hosts: list[str],
    authorized: bool,
) -> str:
    parsed = parse_target(target)
    host = clean_host(parsed.hostname)
    allowed = {clean_host(h) for h in allowed_hosts if h.strip()}

    if not authorized:
        raise PermissionError(
            "Authorization checkbox/--authorized is required. Use this tool only "
            "on systems you own or have explicit permission to test."
        )

    if host not in allowed:
        raise PermissionError(
            f"Target host {host!r} is not an exact match in the authorized host allowlist."
        )
    return host


@dataclass
class Finding:
    title: str
    severity: str
    status: str
    evidence: str
    remediation: str = ""
    owasp: str = ""
    url: str = ""
    source: str = "Local"
    confidence: str = "firm"
    kind: str = "automated"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReconResult:
    resolved_ips: list[str] = field(default_factory=list)
    pages: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    robots_url: str = ""
    robots_text: str = ""
    sitemap_urls: list[str] = field(default_factory=list)


class Logger:
    def __init__(self, callback: Callable[[str], None] | None = None):
        self.callback = callback

    def log(self, message: str):
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
        print(line)
        if self.callback:
            self.callback(line)


class AuthorizedSession:
    """Requests wrapper that refuses requests outside the authorized exact host."""

    def __init__(
        self,
        allowed_host: str,
        timeout: int = DEFAULT_TIMEOUT,
        delay: float = DEFAULT_DELAY,
    ):
        self.allowed_host = clean_host(allowed_host)
        self.timeout = timeout
        self.delay = max(0.0, delay)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "*/*",
            }
        )
        self._last_request = 0.0

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        if not same_host(url, self.allowed_host):
            raise PermissionError(
                f"Blocked out-of-scope request to {url!r}; authorized host is "
                f"{self.allowed_host!r}."
            )

        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        response = self.session.request(method, url, **kwargs)
        self._last_request = time.time()
        return response

    def get_following_in_scope(
        self,
        url: str,
        max_redirects: int = 5,
        **kwargs,
    ) -> requests.Response:
        current = url
        for _ in range(max_redirects + 1):
            response = self.request("GET", current, **kwargs)
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    return response
                nxt = urljoin(current, location)
                if not same_host(nxt, self.allowed_host):
                    # Do not follow out-of-scope redirects.
                    return response
                current = nxt
                continue
            return response
        return response


def header_list(response: requests.Response, name: str) -> list[str]:
    try:
        values = response.raw.headers.getlist(name)
        if values:
            return list(values)
    except Exception:
        pass
    value = response.headers.get(name)
    return [value] if value else []


def detect_technologies(response: requests.Response, body: str) -> list[str]:
    tech = set()
    server = response.headers.get("Server")
    powered = response.headers.get("X-Powered-By")
    if server:
        tech.add(f"Server: {server}")
    if powered:
        tech.add(f"X-Powered-By: {powered}")

    patterns = [
        (r"wp-content|wp-includes", "WordPress"),
        (r"__next|/_next/", "Next.js"),
        (r"data-reactroot|react-dom|react\.development", "React"),
        (r"ng-version=", "Angular"),
        (r"__nuxt|/_nuxt/", "Nuxt"),
        (r"vue(\.min)?\.js|data-v-[a-f0-9]", "Vue.js"),
        (r"bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap"),
        (r"jquery(?:-|\.)(\d[\d.]*)", "jQuery"),
        (r"/static/admin/|csrfmiddlewaretoken", "Django"),
        (r"laravel_session", "Laravel"),
        (r"ASP\.NET|__VIEWSTATE", "ASP.NET"),
        (r"JSESSIONID", "Java/JSP"),
        (r"PHPSESSID", "PHP"),
    ]
    haystack = body[:1_500_000]
    cookies = " ".join(header_list(response, "Set-Cookie"))
    combined = haystack + "\n" + cookies
    for pattern, name in patterns:
        if re.search(pattern, combined, flags=re.I):
            tech.add(name)

    generator = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        haystack,
        flags=re.I,
    )
    if generator:
        tech.add(f"Generator: {generator.group(1).strip()}")

    return sorted(tech)


def extract_links(base_url: str, body: str) -> list[str]:
    candidates = []
    for attr in ("href", "src", "action"):
        for match in re.finditer(
            rf'{attr}\s*=\s*["\']([^"\']+)["\']',
            body,
            flags=re.I,
        ):
            raw = html.unescape(match.group(1).strip())
            if raw.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            candidates.append(urljoin(base_url, raw))
    return list(dict.fromkeys(normalize_url(u) for u in candidates if urlparse(u).scheme in {"http", "https"}))


def extract_forms(base_url: str, body: str) -> list[dict[str, Any]]:
    forms = []
    for form_match in re.finditer(
        r"<form\b([^>]*)>(.*?)</form\s*>",
        body,
        flags=re.I | re.S,
    ):
        attrs = form_match.group(1)
        inner = form_match.group(2)
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, flags=re.I)
        method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, flags=re.I)
        action = urljoin(base_url, action_match.group(1)) if action_match else base_url
        method = (method_match.group(1) if method_match else "GET").upper()

        fields = []
        for input_match in re.finditer(r"<(?:input|textarea|select)\b([^>]*)>", inner, flags=re.I | re.S):
            a = input_match.group(1)
            name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', a, flags=re.I)
            type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', a, flags=re.I)
            if name_match:
                fields.append(
                    {
                        "name": name_match.group(1),
                        "type": (type_match.group(1) if type_match else "text").lower(),
                    }
                )
        forms.append({"url": base_url, "action": action, "method": method, "fields": fields})
    return forms


def parse_sitemap_xml(text: str) -> list[str]:
    urls = []
    try:
        root = ET.fromstring(text)
        for elem in root.iter():
            if elem.tag.lower().endswith("loc") and elem.text:
                value = elem.text.strip()
                if value:
                    urls.append(value)
    except Exception:
        pass
    return list(dict.fromkeys(urls))


def perform_recon(
    target: str,
    auth_session: AuthorizedSession,
    logger: Logger,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> ReconResult:
    parsed = parse_target(target)
    host = parsed.hostname
    result = ReconResult()

    logger.log(f"Recon: resolving {host}")
    try:
        addrinfo = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
        result.resolved_ips = sorted({item[4][0] for item in addrinfo})
    except Exception as exc:
        logger.log(f"DNS resolution warning: {exc}")

    base = f"{parsed.scheme}://{parsed.netloc}"

    # robots.txt
    robots_url = urljoin(base, "/robots.txt")
    result.robots_url = robots_url
    try:
        r = auth_session.get_following_in_scope(robots_url)
        if r.status_code == 200 and "text" in r.headers.get("Content-Type", "").lower():
            result.robots_text = r.text[:250_000]
            for line in result.robots_text.splitlines():
                if ":" not in line:
                    continue
                key, value = [x.strip() for x in line.split(":", 1)]
                if key.lower() in {"allow", "disallow"} and value.startswith("/"):
                    result.endpoints.append(normalize_url(urljoin(base, value)))
                if key.lower() == "sitemap" and value:
                    if same_host(value, host):
                        result.sitemap_urls.append(value)
    except Exception as exc:
        logger.log(f"robots.txt check: {exc}")

    default_sitemap = urljoin(base, "/sitemap.xml")
    if default_sitemap not in result.sitemap_urls:
        result.sitemap_urls.append(default_sitemap)

    sitemap_discovered = []
    for sitemap_url in list(result.sitemap_urls)[:5]:
        if not same_host(sitemap_url, host):
            continue
        try:
            r = auth_session.get_following_in_scope(sitemap_url)
            if r.status_code == 200:
                sitemap_discovered.extend(parse_sitemap_xml(r.text[:2_000_000]))
        except Exception as exc:
            logger.log(f"Sitemap check warning for {sitemap_url}: {exc}")

    for u in sitemap_discovered:
        if same_host(u, host):
            result.endpoints.append(normalize_url(u))

    # Small, rate-limited same-host crawl.
    logger.log(f"Recon: same-host crawl (max {max_pages} pages)")
    q = deque([normalize_url(target)] + result.endpoints[:20])
    seen = set()
    parameters = set()
    technologies = set()

    while q and len(seen) < max_pages:
        url = normalize_url(q.popleft())
        if url in seen or not same_host(url, host):
            continue
        seen.add(url)

        try:
            r = auth_session.get_following_in_scope(url)
        except Exception as exc:
            logger.log(f"Crawl warning {url}: {exc}")
            continue

        ctype = r.headers.get("Content-Type", "")
        page = {
            "url": url,
            "status": r.status_code,
            "content_type": ctype,
            "length": len(r.content),
        }
        result.pages.append(page)
        result.endpoints.append(url)

        for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
            parameters.add(key)

        if "text/html" not in ctype.lower():
            continue

        body = r.text[:1_500_000]
        technologies.update(detect_technologies(r, body))
        forms = extract_forms(url, body)
        result.forms.extend(forms)
        for form in forms:
            for field_item in form["fields"]:
                parameters.add(field_item["name"])

        for link in extract_links(url, body):
            if not same_host(link, host):
                continue
            result.endpoints.append(link)
            if len(seen) + len(q) < max_pages * 4:
                q.append(link)

    result.endpoints = sorted(set(result.endpoints))
    result.parameters = sorted(parameters)
    result.technologies = sorted(technologies)
    return result


def tls_finding(host: str, port: int = 443) -> Finding:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                version = sock.version()

        expiry_text = cert.get("notAfter")
        expiry = (
            datetime.strptime(expiry_text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            if expiry_text
            else None
        )
        days = (expiry - datetime.now(timezone.utc)).days if expiry else None
        evidence = f"TLS={version}; cipher={cipher[0] if cipher else 'unknown'}; certificate_days_remaining={days}"

        if days is not None and days < 0:
            return Finding(
                "Expired TLS certificate", "high", "fail", evidence,
                "Renew and deploy a valid TLS certificate.", "A04"
            )
        if days is not None and days < 30:
            return Finding(
                "TLS certificate nearing expiry", "medium", "warn", evidence,
                "Renew the TLS certificate before expiry.", "A04"
            )
        return Finding("TLS certificate and protocol", "info", "pass", evidence, owasp="A04")
    except Exception as exc:
        return Finding(
            "TLS validation", "medium", "fail", f"TLS validation failed: {exc}",
            "Review the certificate chain, hostname, expiry and TLS configuration.", "A04"
        )


def run_owasp_checks(
    target: str,
    auth_session: AuthorizedSession,
    recon: ReconResult,
    logger: Logger,
) -> list[Finding]:
    findings: list[Finding] = []
    parsed = parse_target(target)

    logger.log("OWASP checks: fetching target response")
    try:
        response = auth_session.get_following_in_scope(target)
    except Exception as exc:
        return [
            Finding(
                "Target connection",
                "high",
                "fail",
                str(exc),
                "Verify the target is reachable and within the authorized scope.",
                "A02",
                target,
            )
        ]

    final_url = response.url or target
    final_parsed = urlparse(final_url)

    findings.append(
        Finding(
            "HTTP response",
            "info" if response.status_code < 500 else "medium",
            "pass" if response.status_code < 500 else "warn",
            f"status={response.status_code}; url={final_url}",
            owasp="A02",
            url=final_url,
        )
    )

    # A04
    if final_parsed.scheme == "https":
        findings.append(
            Finding("HTTPS transport", "info", "pass", "Application responded over HTTPS.", owasp="A04", url=final_url)
        )
        findings.append(tls_finding(final_parsed.hostname, final_parsed.port or 443))
    else:
        findings.append(
            Finding(
                "HTTPS transport",
                "high",
                "fail",
                "The assessed response is served over plain HTTP.",
                "Redirect HTTP to HTTPS and serve sensitive application traffic only over TLS.",
                "A04",
                final_url,
            )
        )

    # A02 Security Misconfiguration headers
    security_headers = {
        "Content-Security-Policy": (
            "medium", "Define a restrictive Content-Security-Policy appropriate for the application."
        ),
        "X-Content-Type-Options": ("low", "Set X-Content-Type-Options: nosniff."),
        "Referrer-Policy": ("low", "Set an appropriate Referrer-Policy."),
        "Permissions-Policy": ("low", "Disable browser capabilities the application does not require."),
    }
    if final_parsed.scheme == "https":
        security_headers["Strict-Transport-Security"] = (
            "medium", "Enable HSTS after confirming intended HTTPS/subdomain behavior."
        )

    for header, (severity, remediation) in security_headers.items():
        value = response.headers.get(header)
        findings.append(
            Finding(
                f"Security header: {header}",
                "info" if value else severity,
                "pass" if value else "warn",
                f"{header}: {value}" if value else f"{header} is missing.",
                "" if value else remediation,
                "A02",
                final_url,
            )
        )

    xfo = response.headers.get("X-Frame-Options", "")
    csp = response.headers.get("Content-Security-Policy", "")
    frame_ancestors = "frame-ancestors" in csp.lower()
    findings.append(
        Finding(
            "Clickjacking protection",
            "info" if (xfo or frame_ancestors) else "medium",
            "pass" if (xfo or frame_ancestors) else "warn",
            f"X-Frame-Options={xfo!r}; CSP frame-ancestors={frame_ancestors}",
            "" if (xfo or frame_ancestors) else "Use CSP frame-ancestors and/or X-Frame-Options.",
            "A02",
            final_url,
        )
    )

    # Cookie/session flags: A07/A02
    cookies = header_list(response, "Set-Cookie")
    if not cookies:
        findings.append(
            Finding("Cookie security flags", "info", "pass", "No Set-Cookie header observed on initial response.", owasp="A07", url=final_url)
        )
    for idx, cookie in enumerate(cookies, 1):
        lower = cookie.lower()
        missing = []
        if final_parsed.scheme == "https" and "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite=" not in lower:
            missing.append("SameSite")
        findings.append(
            Finding(
                f"Cookie security flags #{idx}",
                "medium" if missing else "info",
                "warn" if missing else "pass",
                f"Missing {', '.join(missing)}; cookie={cookie[:220]}" if missing else f"Secure/HttpOnly/SameSite observed; cookie={cookie[:220]}",
                "Set Secure, HttpOnly and an appropriate SameSite policy for sensitive cookies." if missing else "",
                "A07",
                final_url,
            )
        )

    # CORS observation
    acao = response.headers.get("Access-Control-Allow-Origin")
    acac = response.headers.get("Access-Control-Allow-Credentials")
    if acao == "*" and str(acac).lower() == "true":
        findings.append(
            Finding(
                "CORS response headers",
                "medium",
                "warn",
                "Access-Control-Allow-Origin=* and Access-Control-Allow-Credentials=true were observed.",
                "Review credentialed CORS behavior and use an explicit trusted-origin allowlist.",
                "A02",
                final_url,
            )
        )
    else:
        findings.append(
            Finding(
                "CORS response headers",
                "info",
                "pass",
                f"ACAO={acao!r}; ACAC={acac!r}",
                owasp="A02",
                url=final_url,
            )
        )

    # Technology disclosure / component inventory: A02 / A03
    server = response.headers.get("Server")
    powered = response.headers.get("X-Powered-By")
    if server or powered:
        findings.append(
            Finding(
                "Technology disclosure headers",
                "low",
                "warn",
                f"Server={server!r}; X-Powered-By={powered!r}",
                "Remove unnecessary product/version disclosure where practical.",
                "A02",
                final_url,
            )
        )

    if recon.technologies:
        findings.append(
            Finding(
                "Detected technology inventory",
                "info",
                "review",
                "; ".join(recon.technologies),
                "Compare detected components against your supported-version, provenance, SBOM and vulnerability-management inventory.",
                "A03",
                final_url,
                kind="workflow",
            )
        )

    # A08: third-party script integrity heuristic.
    if "text/html" in response.headers.get("Content-Type", "").lower():
        body = response.text[:1_500_000]
        external_scripts = re.findall(
            r'<script\b[^>]*src=["\'](https?://[^"\']+)["\'][^>]*>',
            body,
            flags=re.I,
        )
        unsigned = []
        for src in external_scripts[:100]:
            # Locate the actual script tag and check for integrity attribute.
            tag_match = re.search(
                rf'<script\b[^>]*src=["\']{re.escape(src)}["\'][^>]*>',
                body,
                flags=re.I,
            )
            if tag_match and "integrity=" not in tag_match.group(0).lower():
                unsigned.append(src)

        if unsigned:
            findings.append(
                Finding(
                    "External script integrity review",
                    "low",
                    "review",
                    f"{len(unsigned)} external script(s) without an observed integrity attribute; sample={unsigned[:5]}",
                    "Where compatible with your deployment model, consider Subresource Integrity for externally hosted static scripts.",
                    "A08",
                    final_url,
                    kind="workflow",
                )
            )

        mixed = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', body, flags=re.I)
        if final_parsed.scheme == "https" and mixed:
            findings.append(
                Finding(
                    "Mixed-content references",
                    "medium",
                    "warn",
                    f"HTTPS page references HTTP resources; sample={mixed[:5]}",
                    "Serve all active and passive resources over HTTPS.",
                    "A04",
                    final_url,
                )
            )

    # A01 access-control workflow — enumerate candidate object identifiers, don't manipulate them.
    candidate_names = re.compile(
        r"(^id$|_id$|userid|user_id|account|account_id|order|order_id|invoice|document|file_id|profile_id)",
        flags=re.I,
    )
    access_candidates = sorted({p for p in recon.parameters if candidate_names.search(p)})
    if access_candidates:
        findings.append(
            Finding(
                "Access-control review candidates",
                "info",
                "review",
                f"Identifier-like parameters observed: {', '.join(access_candidates[:30])}",
                "Manually verify authorization for object access using separate authorized test accounts and server-side checks.",
                "A01",
                target,
                kind="workflow",
            )
        )

    # A05 Injection input-validation workflow — map input surface, no injection payloads.
    if recon.parameters:
        findings.append(
            Finding(
                "Input-validation attack surface",
                "info",
                "review",
                f"{len(recon.parameters)} input parameter(s) observed: {', '.join(recon.parameters[:50])}",
                "Review server-side validation, parameterization and contextual output encoding for each trust boundary.",
                "A05",
                target,
                kind="workflow",
            )
        )

    # A06 Insecure Design review
    findings.append(
        Finding(
            "Secure-design review",
            "info",
            "review",
            "Automated HTTP testing cannot establish whether business rules, abuse cases and trust boundaries are securely designed.",
            "Perform threat modeling and abuse-case review for sensitive workflows.",
            "A06",
            target,
            kind="manual",
        )
    )

    # A07 login surface
    password_forms = [
        f for f in recon.forms
        if any(x.get("type") == "password" for x in f.get("fields", []))
    ]
    if password_forms:
        if final_parsed.scheme != "https":
            findings.append(
                Finding(
                    "Authentication form transport",
                    "high",
                    "fail",
                    f"{len(password_forms)} password form(s) observed while target is not HTTPS.",
                    "Protect all authentication pages and submissions with HTTPS.",
                    "A07",
                    target,
                )
            )
        else:
            findings.append(
                Finding(
                    "Authentication workflow identified",
                    "info",
                    "review",
                    f"{len(password_forms)} password form(s) observed.",
                    "Review MFA, rate limiting, account recovery, session rotation and lockout behavior with authorized test accounts.",
                    "A07",
                    target,
                    kind="workflow",
                )
            )

    # A09 cannot be proven externally.
    findings.append(
        Finding(
            "Security logging and alerting review",
            "info",
            "review",
            "External scanning cannot verify that security-relevant events are logged, retained, alerted on and monitored.",
            "Verify server-side security logging, alerting, retention, incident-response integration and sensitive-data redaction.",
            "A09",
            target,
            kind="manual",
        )
    )

    # Specialized SSRF candidate surface review (not labeled A10:2025).
    ssrf_names = re.compile(
        r"(url|uri|callback|webhook|redirect|next|return|dest|destination|feed|image|avatar|remote|proxy|fetch|link)",
        flags=re.I,
    )
    ssrf_candidates = sorted({p for p in recon.parameters if ssrf_names.search(p)})
    if ssrf_candidates:
        findings.append(
            Finding(
                "Server-side request candidate inputs",
                "info",
                "review",
                f"URL-like parameter names observed: {', '.join(ssrf_candidates[:30])}",
                "Manually review whether these inputs can cause server-side network requests and enforce allowlists/network egress controls.",
                "",
                target,
                kind="workflow",
            )
        )

    # A10:2025 Exceptional Conditions. Normal crawl evidence can reveal unhandled
    # server failures, but deliberately sending malformed/destructive input is out
    # of scope for this conservative automation profile.
    server_errors = [p for p in recon.pages if int(p.get("status", 0) or 0) >= 500]
    if server_errors:
        findings.append(
            Finding(
                "Server errors observed during normal crawl",
                "medium",
                "warn",
                f"{len(server_errors)} page(s) returned 5xx responses; sample={server_errors[:5]}",
                "Review exception boundaries, fail-safe behavior, error handling and sensitive information exposure.",
                "A10",
                target,
            )
        )
    else:
        findings.append(
            Finding(
                "Exceptional-condition handling review",
                "info",
                "review",
                "No 5xx response was observed during the normal crawl. Robust exceptional-condition handling cannot be established without broader application-specific testing.",
                "Review fail-safe defaults, transaction rollback, resource cleanup, error boundaries and safe handling of unexpected conditions.",
                "A10",
                target,
                kind="workflow",
            )
        )

    return findings


def load_structured_file(path: str) -> Any:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    suffix = Path(path).suffix.lower()
    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML API definitions.")
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if yaml is not None:
            return yaml.safe_load(text)
        raise


def parse_openapi(data: dict[str, Any]) -> dict[str, Any]:
    version = data.get("openapi") or data.get("swagger")
    paths = data.get("paths") or {}
    endpoints = []

    servers = []
    if data.get("openapi"):
        servers = [x.get("url") for x in data.get("servers", []) if isinstance(x, dict) and x.get("url")]
    elif data.get("swagger"):
        scheme = (data.get("schemes") or ["https"])[0]
        host = data.get("host")
        base_path = data.get("basePath", "")
        if host:
            servers = [f"{scheme}://{host}{base_path}"]

    methods = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() in methods:
                endpoints.append(
                    {
                        "method": method.upper(),
                        "path": path,
                        "operation_id": op.get("operationId", "") if isinstance(op, dict) else "",
                    }
                )
    return {
        "type": "OpenAPI/Swagger",
        "version": str(version),
        "servers": servers,
        "endpoints": endpoints,
    }


def walk_postman_items(items: list[Any], out: list[dict[str, Any]]):
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if "item" in item:
            walk_postman_items(item.get("item") or [], out)
            continue
        req = item.get("request")
        if not isinstance(req, dict):
            continue
        method = req.get("method", "GET")
        url = req.get("url")
        if isinstance(url, dict):
            raw = url.get("raw", "")
        else:
            raw = str(url or "")
        out.append({"name": item.get("name", ""), "method": method, "url": raw})


def parse_postman(data: dict[str, Any]) -> dict[str, Any]:
    out = []
    walk_postman_items(data.get("item", []), out)
    schema = ((data.get("info") or {}).get("schema") or "")
    return {
        "type": "Postman Collection",
        "version": "2.1" if "v2.1" in schema else "unknown",
        "requests": out,
    }


def parse_wsdl(path: str) -> dict[str, Any]:
    root = ET.parse(path).getroot()
    operations = []
    addresses = []
    for elem in root.iter():
        tag = elem.tag.lower()
        if tag.endswith("operation"):
            name = elem.attrib.get("name")
            if name:
                operations.append(name)
        if tag.endswith("address"):
            location = elem.attrib.get("location")
            if location:
                addresses.append(location)
    return {
        "type": "SOAP WSDL",
        "addresses": sorted(set(addresses)),
        "operations": sorted(set(operations)),
    }


GRAPHQL_INTROSPECTION = {
    "query": """
    query AuthorizedIntrospection {
      __schema {
        queryType { name }
        mutationType { name }
        types { name kind }
      }
    }
    """
}


def introspect_graphql(
    url: str,
    auth_session: AuthorizedSession,
) -> dict[str, Any]:
    r = auth_session.request(
        "POST",
        url,
        json=GRAPHQL_INTROSPECTION,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    data = r.json()
    schema = ((data.get("data") or {}).get("__schema") or {})
    types = schema.get("types") or []
    return {
        "type": "GraphQL",
        "url": url,
        "http_status": r.status_code,
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "type_count": len(types),
        "errors": data.get("errors"),
    }


def analyze_api_definition(
    api_path: str | None,
    graphql_url: str | None,
    auth_session: AuthorizedSession,
    allowed_host: str,
    logger: Logger,
) -> dict[str, Any] | None:
    if graphql_url:
        if not same_host(graphql_url, allowed_host):
            raise PermissionError("GraphQL endpoint is outside the authorized exact host.")
        logger.log("API: running GraphQL introspection")
        return introspect_graphql(graphql_url, auth_session)

    if not api_path:
        return None

    p = Path(api_path)
    if not p.exists():
        raise FileNotFoundError(api_path)

    if p.suffix.lower() in {".wsdl", ".xml"}:
        logger.log("API: parsing SOAP/WSDL definition")
        return parse_wsdl(api_path)

    data = load_structured_file(api_path)
    if not isinstance(data, dict):
        raise ValueError("Unsupported API definition structure.")

    if "openapi" in data or "swagger" in data:
        logger.log("API: parsing OpenAPI/Swagger definition")
        return parse_openapi(data)

    schema = ((data.get("info") or {}).get("schema") or "")
    if "postman" in schema.lower() or "item" in data:
        logger.log("API: parsing Postman collection")
        return parse_postman(data)

    raise ValueError("Could not identify OpenAPI/Swagger/Postman/WSDL format.")


def api_seed_urls(api_info: dict[str, Any] | None, allowed_host: str) -> list[str]:
    """Return in-scope URLs useful for Burp crawling; no requests are sent here."""
    if not api_info:
        return []

    urls = []

    if api_info.get("type") == "OpenAPI/Swagger":
        servers = api_info.get("servers") or []
        endpoints = api_info.get("endpoints") or []
        for server in servers[:5]:
            # Skip templates such as {host} rather than guessing.
            if "{" in server or "}" in server:
                continue
            for ep in endpoints[:100]:
                # Only seed concrete paths. Burp will decide how to crawl/audit.
                path = ep.get("path", "")
                if "{" in path or "}" in path:
                    # Keep templated path out of URL seed rather than inventing IDs.
                    continue
                u = urljoin(server.rstrip("/") + "/", path.lstrip("/"))
                if same_host(u, allowed_host):
                    urls.append(normalize_url(u))

    elif api_info.get("type") == "Postman Collection":
        for req in api_info.get("requests", [])[:100]:
            raw = req.get("url", "")
            if "{{" in raw or "}}" in raw:
                continue
            if raw.startswith(("http://", "https://")) and same_host(raw, allowed_host):
                urls.append(normalize_url(raw))

    elif api_info.get("type") == "SOAP WSDL":
        for u in api_info.get("addresses", []):
            if same_host(u, allowed_host):
                urls.append(normalize_url(u))

    elif api_info.get("type") == "GraphQL":
        u = api_info.get("url")
        if u and same_host(u, allowed_host):
            urls.append(normalize_url(u))

    return list(dict.fromkeys(urls))


class BurpClient:
    def __init__(self, service_url: str, api_key: str | None = None):
        root = service_url.rstrip("/")
        if api_key:
            root += "/" + quote(api_key, safe="")
        self.root = root
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": DEFAULT_USER_AGENT,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def _url(self, path: str) -> str:
        return f"{self.root}/{path.lstrip('/')}"

    def wait_until_ready(self, timeout_seconds: int = 90):
        deadline = time.time() + timeout_seconds
        last_error = None
        while time.time() < deadline:
            try:
                r = self.session.get(
                    self._url("/v0.1/knowledge_base/issue_definitions"),
                    timeout=5,
                )
                if r.status_code < 500:
                    r.raise_for_status()
                    return
            except requests.RequestException as exc:
                last_error = exc
            time.sleep(2)
        raise RuntimeError(f"Burp REST API did not become ready: {last_error}")

    def start_scan(
        self,
        urls: list[str],
        scan_configuration: str = "Audit checks - light active",
        name: str | None = None,
    ) -> str:
        payload = {
            "name": name or f"Authorized automation - {urlparse(urls[0]).hostname}",
            "urls": urls,
            "scan_configurations": [
                {"name": scan_configuration, "type": "NamedConfiguration"}
            ],
        }
        r = self.session.post(self._url("/v0.1/scan"), json=payload, timeout=30)
        r.raise_for_status()

        location = r.headers.get("Location", "").strip().rstrip("/")
        if location:
            return location.split("/")[-1]

        try:
            body = r.json()
        except Exception:
            body = {}
        for key in ("task_id", "scan_id", "id"):
            if body.get(key):
                return str(body[key])
        raise RuntimeError("Burp accepted the scan but did not return a task identifier.")

    def get_scan(self, task_id: str) -> dict[str, Any]:
        r = self.session.get(
            self._url(f"/v0.1/scan/{quote(task_id, safe='')}"),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def wait_for_scan(
        self,
        task_id: str,
        logger: Logger,
        poll_seconds: int = 10,
        max_minutes: int = 60,
    ) -> dict[str, Any]:
        deadline = time.time() + max_minutes * 60
        last = {}
        while time.time() < deadline:
            last = self.get_scan(task_id)
            status = str(last.get("scan_status", "")).lower()
            logger.log(f"Burp scan {task_id}: {status or 'status unavailable'}")
            if status in {"succeeded", "failed", "cancelled", "canceled"}:
                return last
            time.sleep(max(2, poll_seconds))
        return {
            **last,
            "automation_timeout": True,
            "automation_message": f"Polling stopped after {max_minutes} minutes.",
        }


def launch_burp(
    jar_path: str,
    project_file: str | None,
    config_files: list[str],
    headless: bool,
    logger: Logger,
) -> subprocess.Popen:
    cmd = ["java"]
    if headless:
        cmd.append("-Djava.awt.headless=true")
    cmd.extend(["-Xmx2g", "-jar", jar_path])
    if project_file:
        cmd.extend(["--project-file", project_file])
    for config in config_files:
        if config:
            cmd.extend(["--config-file", config])

    logger.log("Launching Burp Suite")
    logger.log("Command: " + " ".join(cmd))
    return subprocess.Popen(cmd)


def flatten_burp_issues(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Burp versions can add fields over time. This extracts issue-like objects
    without assuming a single rigid response shape.
    """
    issues = []

    def walk(obj: Any):
        if isinstance(obj, dict):
            keys = {str(k).lower() for k in obj}
            looks_like_issue = (
                ("severity" in keys and ("name" in keys or "type_index" in keys or "issue_type" in keys))
                or "issue" in keys
            )
            if looks_like_issue:
                issues.append(obj)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(scan_result)
    # Deduplicate serialized representations.
    dedup = []
    seen = set()
    for issue in issues:
        marker = json.dumps(issue, sort_keys=True, default=str)[:5000]
        if marker not in seen:
            seen.add(marker)
            dedup.append(issue)
    return dedup


def burp_issues_to_findings(issues: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for i, issue in enumerate(issues, 1):
        name = issue.get("name") or issue.get("issue_name") or issue.get("issue") or f"Burp issue {i}"
        if isinstance(name, dict):
            name = name.get("name") or name.get("title") or f"Burp issue {i}"
        severity = str(issue.get("severity", "info")).lower()
        if severity not in SEVERITY_SCORE:
            severity = "info"
        confidence = str(issue.get("confidence", "tentative")).lower()
        path = issue.get("path") or issue.get("url") or issue.get("origin") or ""
        evidence = issue.get("description") or issue.get("detail") or issue.get("evidence") or ""
        if isinstance(evidence, (dict, list)):
            evidence = json.dumps(evidence, default=str)[:2000]

        findings.append(
            Finding(
                title=str(name),
                severity=severity,
                status="issue",
                evidence=str(evidence)[:4000] or "Issue reported by Burp Scanner.",
                remediation=str(issue.get("remediation") or issue.get("remediation_detail") or "")[:4000],
                owasp="",
                url=str(path),
                source="Burp",
                confidence=confidence,
                kind="automated",
            )
        )
    return findings


def build_summary(findings: list[Finding]) -> dict[str, Any]:
    severities = Counter(f.severity for f in findings if f.status in {"warn", "fail", "issue"})
    statuses = Counter(f.status for f in findings)
    owasp = Counter(f.owasp for f in findings if f.owasp)
    risk_score = sum(SEVERITY_SCORE.get(f.severity, 1) for f in findings if f.status in {"warn", "fail", "issue"})
    return {
        "finding_count": len(findings),
        "risk_score": risk_score,
        "severity_counts": dict(severities),
        "status_counts": dict(statuses),
        "owasp_counts": dict(owasp),
    }


def export_csv(path: Path, findings: list[Finding]):
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=list(Finding.__dataclass_fields__.keys()),
        )
        writer.writeheader()
        for f in findings:
            writer.writerow(f.to_dict())


def export_html(
    path: Path,
    report: dict[str, Any],
):
    findings = report["findings"]
    summary = report["summary"]
    target = html.escape(report["target"])

    rows = []
    for f in findings:
        row = f"""
        <tr>
          <td>{html.escape(f['severity'].upper())}</td>
          <td>{html.escape(f['status'])}</td>
          <td>{html.escape(f['title'])}</td>
          <td>{html.escape(f.get('owasp',''))}</td>
          <td>{html.escape(f.get('source',''))}</td>
          <td>{html.escape(f.get('url',''))}</td>
          <td>{html.escape(f.get('evidence',''))}</td>
          <td>{html.escape(f.get('remediation',''))}</td>
        </tr>
        """
        rows.append(row)

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Security Assessment - {target}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; color: #222; }}
h1,h2 {{ margin-bottom: 8px; }}
.summary {{ display:flex; gap:16px; flex-wrap:wrap; margin:16px 0 24px; }}
.card {{ border:1px solid #bbb; border-radius:8px; padding:12px 16px; min-width:150px; }}
table {{ border-collapse:collapse; width:100%; font-size:12px; }}
th,td {{ border:1px solid #ccc; padding:7px; vertical-align:top; text-align:left; }}
th {{ background:#eee; }}
small {{ color:#666; }}
@media print {{
  body {{ margin: 12mm; }}
  .no-print {{ display:none; }}
  table {{ font-size:9px; }}
}}
</style>
</head>
<body>
<h1>{APP_NAME}</h1>
<p><strong>Target:</strong> {target}<br>
<strong>Generated:</strong> {html.escape(report['finished_at'])}<br>
<strong>Version:</strong> {APP_VERSION}</p>

<div class="summary">
  <div class="card"><strong>Findings</strong><br>{summary['finding_count']}</div>
  <div class="card"><strong>Risk score</strong><br>{summary['risk_score']}</div>
  <div class="card"><strong>High/Critical</strong><br>{summary['severity_counts'].get('high',0) + summary['severity_counts'].get('critical',0)}</div>
  <div class="card"><strong>Manual/Workflow</strong><br>{sum(1 for f in findings if f.get('kind') in ('manual','workflow'))}</div>
</div>

<h2>Assessment scope and limitations</h2>
<p>This report maps observable evidence to OWASP Top 10 categories. It does not claim complete OWASP coverage.
Design, authorization, business logic, logging/monitoring and authenticated workflows often require manual verification.</p>

<h2>Findings</h2>
<table>
<thead><tr>
<th>Severity</th><th>Status</th><th>Finding</th><th>OWASP</th><th>Source</th>
<th>URL</th><th>Evidence</th><th>Remediation</th>
</tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>

<h2>Reconnaissance</h2>
<pre>{html.escape(json.dumps(report.get('recon',{}), indent=2, default=str)[:100000])}</pre>

<h2>API analysis</h2>
<pre>{html.escape(json.dumps(report.get('api',{}), indent=2, default=str)[:100000])}</pre>

<h2>Burp metadata</h2>
<pre>{html.escape(json.dumps(report.get('burp',{}), indent=2, default=str)[:100000])}</pre>

</body>
</html>"""
    path.write_text(html_doc, encoding="utf-8")


def export_pdf(path: Path, report: dict[str, Any]) -> tuple[bool, str]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        )
    except Exception as exc:
        return False, f"reportlab unavailable: {exc}"

    styles = getSampleStyleSheet()
    tiny = ParagraphStyle(
        "Tiny",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
        alignment=TA_LEFT,
        wordWrap="CJK",
    )
    small = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    )

    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=10*mm,
        leftMargin=10*mm,
        topMargin=10*mm,
        bottomMargin=10*mm,
        title=f"Security Assessment - {report['target']}",
        author=APP_NAME,
    )

    story = [
        Paragraph(APP_NAME, styles["Title"]),
        Paragraph(f"<b>Target:</b> {html.escape(report['target'])}", styles["BodyText"]),
        Paragraph(f"<b>Generated:</b> {html.escape(report['finished_at'])}", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("Summary", styles["Heading2"]),
        Paragraph(
            f"Findings: {report['summary']['finding_count']} &nbsp;&nbsp; "
            f"Risk score: {report['summary']['risk_score']} &nbsp;&nbsp; "
            f"Severity counts: {html.escape(str(report['summary']['severity_counts']))}",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph("Scope and limitations", styles["Heading2"]),
        Paragraph(
            "This automated report maps observable evidence to OWASP Top 10 categories. "
            "It does not claim complete OWASP coverage. Design, business logic, authorization, "
            "logging/monitoring and authenticated workflows can require manual verification.",
            styles["BodyText"],
        ),
        Spacer(1, 10),
        Paragraph("Findings", styles["Heading2"]),
    ]

    data = [[
        Paragraph("<b>Severity</b>", small),
        Paragraph("<b>Status</b>", small),
        Paragraph("<b>Finding</b>", small),
        Paragraph("<b>OWASP</b>", small),
        Paragraph("<b>Source</b>", small),
        Paragraph("<b>Evidence</b>", small),
        Paragraph("<b>Remediation</b>", small),
    ]]

    for f in report["findings"]:
        data.append([
            Paragraph(html.escape(f["severity"].upper()), tiny),
            Paragraph(html.escape(f["status"]), tiny),
            Paragraph(html.escape(f["title"]), tiny),
            Paragraph(html.escape(f.get("owasp", "")), tiny),
            Paragraph(html.escape(f.get("source", "")), tiny),
            Paragraph(html.escape(f.get("evidence", ""))[:5000], tiny),
            Paragraph(html.escape(f.get("remediation", ""))[:5000], tiny),
        ])

    table = Table(
        data,
        repeatRows=1,
        colWidths=[16*mm, 16*mm, 35*mm, 14*mm, 18*mm, 85*mm, 75*mm],
    )
    table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 3),
        ("RIGHTPADDING", (0,0), (-1,-1), 3),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
    ]))
    story.append(table)
    story.append(PageBreak())
    story.append(Paragraph("OWASP mapping", styles["Heading2"]))
    mapping_lines = []
    for key, name in OWASP.items():
        count = sum(1 for f in report["findings"] if f.get("owasp") == key)
        mapping_lines.append(f"{key}: {name} — {count} mapped item(s)")
    story.append(Paragraph("<br/>".join(map(html.escape, mapping_lines)), styles["BodyText"]))

    doc.build(story)
    return True, ""


def save_reports(
    output_dir: str,
    report: dict[str, Any],
    logger: Logger,
) -> dict[str, str]:
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    host = safe_filename(urlparse(report["target"]).hostname or "target")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{host}_{stamp}"

    json_path = outdir / f"{base}.json"
    html_path = outdir / f"{base}.html"
    csv_path = outdir / f"{base}.csv"
    pdf_path = outdir / f"{base}.pdf"
    sitemap_path = outdir / f"{base}_sitemap.txt"

    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    export_html(html_path, report)
    export_csv(csv_path, [Finding(**f) for f in report["findings"]])
    sitemap_path.write_text("\n".join(report.get("recon", {}).get("endpoints", [])), encoding="utf-8")

    pdf_ok, pdf_error = export_pdf(pdf_path, report)
    if not pdf_ok:
        logger.log(f"PDF export skipped: {pdf_error}")
        if pdf_path.exists():
            pdf_path.unlink()

    paths = {
        "json": str(json_path),
        "html": str(html_path),
        "csv": str(csv_path),
        "sitemap": str(sitemap_path),
    }
    if pdf_ok:
        paths["pdf"] = str(pdf_path)

    logger.log(f"Reports saved in {outdir.resolve()}")
    return paths


@dataclass
class AssessmentConfig:
    target: str
    allowed_hosts: list[str]
    authorized: bool
    output_dir: str = "reports"
    max_pages: int = DEFAULT_MAX_PAGES
    delay: float = DEFAULT_DELAY

    api_path: str | None = None
    graphql_url: str | None = None

    burp_enabled: bool = False
    burp_api: str = "http://127.0.0.1:1337"
    burp_api_key: str | None = None
    burp_scan_configuration: str = "Audit checks - light active"
    burp_poll: int = 10
    burp_max_minutes: int = 60
    burp_jar: str | None = None
    burp_project: str | None = None
    burp_config_files: list[str] = field(default_factory=list)
    burp_headless: bool = False


def run_assessment(
    config: AssessmentConfig,
    log_callback: Callable[[str], None] | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    logger = Logger(log_callback)
    host = require_authorized_target(config.target, config.allowed_hosts, config.authorized)
    session = AuthorizedSession(host, delay=config.delay)

    report: dict[str, Any] = {
        "application": APP_NAME,
        "version": APP_VERSION,
        "target": config.target,
        "authorized_host": host,
        "started_at": utc_now(),
        "scope": {
            "exact_host_only": True,
            "authorized_hosts": config.allowed_hosts,
            "max_pages": config.max_pages,
            "request_delay_seconds": config.delay,
            "active_safety": "No brute force, exploit chaining, destructive payloads, or automated access-control manipulation.",
        },
        "recon": {},
        "api": None,
        "burp": None,
        "findings": [],
    }

    def stage(name: str):
        logger.log(name)
        if progress_callback:
            progress_callback(name)

    stage("Stage 1/5 — Reconnaissance")
    recon = perform_recon(config.target, session, logger, config.max_pages)
    report["recon"] = asdict(recon)

    stage("Stage 2/5 — OWASP-oriented checks")
    findings = run_owasp_checks(config.target, session, recon, logger)

    stage("Stage 3/5 — API analysis")
    try:
        report["api"] = analyze_api_definition(
            config.api_path,
            config.graphql_url,
            session,
            host,
            logger,
        )
    except Exception as exc:
        report["api"] = {"error": str(exc)}
        findings.append(
            Finding(
                "API definition analysis",
                "low",
                "warn",
                str(exc),
                "Verify the supplied API definition or GraphQL endpoint.",
                "A02",
                config.target,
                source="API parser",
            )
        )

    stage("Stage 4/5 — Burp orchestration")
    burp_process = None
    if config.burp_jar:
        burp_process = launch_burp(
            config.burp_jar,
            config.burp_project,
            config.burp_config_files,
            config.burp_headless,
            logger,
        )
        report["burp_process_pid"] = burp_process.pid

    if config.burp_enabled:
        try:
            client = BurpClient(config.burp_api, config.burp_api_key)
            logger.log("Waiting for Burp REST API")
            client.wait_until_ready()

            urls = [normalize_url(config.target)]
            urls.extend(api_seed_urls(report.get("api"), host))
            # Keep request manageable and exact-host only.
            urls = [u for u in dict.fromkeys(urls) if same_host(u, host)][:25]

            logger.log(
                f"Starting Burp scan with configuration: {config.burp_scan_configuration}"
            )
            task_id = client.start_scan(
                urls,
                config.burp_scan_configuration,
                name=f"Authorized assessment - {host}",
            )
            logger.log(f"Burp task ID: {task_id}")
            scan_result = client.wait_for_scan(
                task_id,
                logger,
                config.burp_poll,
                config.burp_max_minutes,
            )
            burp_issues = flatten_burp_issues(scan_result)
            burp_findings = burp_issues_to_findings(burp_issues)
            findings.extend(burp_findings)
            report["burp"] = {
                "task_id": task_id,
                "scan_configuration": config.burp_scan_configuration,
                "seed_urls": urls,
                "issue_objects_detected": len(burp_issues),
                "result": scan_result,
            }
        except Exception as exc:
            logger.log(f"Burp integration error: {exc}")
            report["burp"] = {"error": str(exc)}
            findings.append(
                Finding(
                    "Burp integration",
                    "low",
                    "warn",
                    str(exc),
                    "Verify Burp Professional/DAST is running, REST API is enabled, and the API key/service URL are correct.",
                    "A02",
                    config.target,
                    source="Burp controller",
                )
            )
    else:
        report["burp"] = {"enabled": False}

    stage("Stage 5/5 — Reporting")
    report["findings"] = [f.to_dict() for f in findings]
    report["summary"] = build_summary(findings)
    report["finished_at"] = utc_now()
    report["reports"] = save_reports(config.output_dir, report, logger)

    logger.log("Assessment complete")
    return report


def build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=APP_NAME)
    p.add_argument("--no-gui", action="store_true", help="Run in CLI mode.")
    p.add_argument("--target")
    p.add_argument("--allow-host", action="append", default=[])
    p.add_argument("--authorized", action="store_true")
    p.add_argument("--output-dir", default="reports")
    p.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY)

    p.add_argument("--api-file")
    p.add_argument("--graphql-url")

    p.add_argument("--burp-scan", action="store_true")
    p.add_argument("--burp-api", default="http://127.0.0.1:1337")
    p.add_argument("--burp-api-key")
    p.add_argument(
        "--burp-scan-configuration",
        default="Audit checks - light active",
    )
    p.add_argument("--burp-poll", type=int, default=10)
    p.add_argument("--burp-max-minutes", type=int, default=60)
    p.add_argument("--burp-jar")
    p.add_argument("--burp-project")
    p.add_argument("--burp-config", action="append", default=[])
    p.add_argument("--headless", action="store_true")
    return p


def cli_main(args: argparse.Namespace) -> int:
    if not args.target:
        print("--target is required in --no-gui mode.", file=sys.stderr)
        return 2
    config = AssessmentConfig(
        target=args.target,
        allowed_hosts=args.allow_host,
        authorized=args.authorized,
        output_dir=args.output_dir,
        max_pages=args.max_pages,
        delay=args.delay,
        api_path=args.api_file,
        graphql_url=args.graphql_url,
        burp_enabled=args.burp_scan,
        burp_api=args.burp_api,
        burp_api_key=args.burp_api_key,
        burp_scan_configuration=args.burp_scan_configuration,
        burp_poll=args.burp_poll,
        burp_max_minutes=args.burp_max_minutes,
        burp_jar=args.burp_jar,
        burp_project=args.burp_project,
        burp_config_files=args.burp_config,
        burp_headless=args.headless,
    )
    try:
        report = run_assessment(config)
        print(json.dumps(report["summary"], indent=2))
        print("\nReports:")
        for key, value in report["reports"].items():
            print(f"  {key}: {value}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


# ---------------- GUI ----------------

def gui_main():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title(f"{APP_NAME} v{APP_VERSION}")
    root.geometry("1180x780")
    root.minsize(1000, 680)

    event_q: queue.Queue[tuple[str, Any]] = queue.Queue()
    state = {"report": None, "thread": None}

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    tab_dashboard = ttk.Frame(notebook)
    tab_results = ttk.Frame(notebook)
    tab_log = ttk.Frame(notebook)
    tab_settings = ttk.Frame(notebook)
    notebook.add(tab_dashboard, text="Dashboard")
    notebook.add(tab_results, text="Results")
    notebook.add(tab_log, text="Log")
    notebook.add(tab_settings, text="Settings")

    # Variables
    target_var = tk.StringVar()
    allow_var = tk.StringVar()
    auth_var = tk.BooleanVar(value=False)
    output_var = tk.StringVar(value=str(Path.cwd() / "reports"))
    max_pages_var = tk.IntVar(value=DEFAULT_MAX_PAGES)
    delay_var = tk.DoubleVar(value=DEFAULT_DELAY)

    api_file_var = tk.StringVar()
    graphql_var = tk.StringVar()

    burp_enabled_var = tk.BooleanVar(value=False)
    burp_api_var = tk.StringVar(value="http://127.0.0.1:1337")
    burp_key_var = tk.StringVar()
    burp_profile_var = tk.StringVar(value="Audit checks - light active")
    burp_jar_var = tk.StringVar()
    burp_project_var = tk.StringVar()
    burp_config_var = tk.StringVar()
    headless_var = tk.BooleanVar(value=False)

    status_var = tk.StringVar(value="Ready")

    def add_labeled_entry(parent, row, label, var, width=76, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=8, pady=6)
        e = ttk.Entry(parent, textvariable=var, width=width, show=show)
        e.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        return e

    # Dashboard
    dash = ttk.Frame(tab_dashboard, padding=12)
    dash.pack(fill="both", expand=True)
    dash.columnconfigure(1, weight=1)

    ttk.Label(dash, text="Authorized Web Security Assessment", font=("TkDefaultFont", 16, "bold")).grid(
        row=0, column=0, columnspan=3, sticky="w", pady=(0, 12)
    )

    add_labeled_entry(dash, 1, "Target URL", target_var)
    add_labeled_entry(dash, 2, "Authorized host(s)", allow_var)

    def use_target_host():
        try:
            p = parse_target(target_var.get())
            allow_var.set(p.hostname or "")
        except Exception as exc:
            messagebox.showerror("Target URL", str(exc))

    ttk.Button(dash, text="Use target host", command=use_target_host).grid(row=2, column=2, padx=8, pady=6)

    auth_check = ttk.Checkbutton(
        dash,
        text="I own this target or have explicit authorization to test it",
        variable=auth_var,
    )
    auth_check.grid(row=3, column=1, sticky="w", padx=8, pady=6)

    ttk.Separator(dash).grid(row=4, column=0, columnspan=3, sticky="ew", pady=10)
    ttk.Label(dash, text="API definition (optional)", font=("TkDefaultFont", 11, "bold")).grid(
        row=5, column=0, columnspan=3, sticky="w", padx=8, pady=4
    )
    add_labeled_entry(dash, 6, "OpenAPI/Postman/WSDL", api_file_var)

    def browse_api():
        p = filedialog.askopenfilename(
            title="Select API definition",
            filetypes=[
                ("API definitions", "*.json *.yaml *.yml *.xml *.wsdl"),
                ("All files", "*.*"),
            ],
        )
        if p:
            api_file_var.set(p)

    ttk.Button(dash, text="Browse", command=browse_api).grid(row=6, column=2, padx=8, pady=6)
    add_labeled_entry(dash, 7, "GraphQL endpoint", graphql_var)

    ttk.Separator(dash).grid(row=8, column=0, columnspan=3, sticky="ew", pady=10)
    ttk.Checkbutton(
        dash,
        text="Enable Burp Scanner orchestration",
        variable=burp_enabled_var,
    ).grid(row=9, column=1, sticky="w", padx=8, pady=6)

    ttk.Label(dash, text="Burp scan profile").grid(row=10, column=0, sticky="w", padx=8, pady=6)
    profile_box = ttk.Combobox(
        dash,
        textvariable=burp_profile_var,
        values=[
            "Audit checks - passive",
            "Audit checks - light active",
            "Crawl and Audit - Lightweight",
            "Crawl and Audit - CICD Optimized",
            "Crawl and Audit - Fast",
        ],
        state="readonly",
        width=48,
    )
    profile_box.grid(row=10, column=1, sticky="w", padx=8, pady=6)

    ttk.Label(
        dash,
        text="Default is light-active: passive plus a small number of benign active requests.",
    ).grid(row=11, column=1, sticky="w", padx=8, pady=(0, 10))

    button_bar = ttk.Frame(dash)
    button_bar.grid(row=12, column=0, columnspan=3, sticky="ew", pady=14)

    progress = ttk.Progressbar(button_bar, mode="indeterminate", length=260)
    progress.pack(side="left", padx=(0, 12))
    ttk.Label(button_bar, textvariable=status_var).pack(side="left", padx=4)

    # Results
    result_frame = ttk.Frame(tab_results, padding=10)
    result_frame.pack(fill="both", expand=True)
    columns = ("severity", "status", "owasp", "source", "title", "url")
    tree = ttk.Treeview(result_frame, columns=columns, show="headings")
    for col, text, width in [
        ("severity", "Severity", 80),
        ("status", "Status", 80),
        ("owasp", "OWASP", 70),
        ("source", "Source", 90),
        ("title", "Finding", 320),
        ("url", "URL", 320),
    ]:
        tree.heading(col, text=text)
        tree.column(col, width=width, anchor="w")
    tree.pack(fill="both", expand=True, side="left")
    scroll = ttk.Scrollbar(result_frame, orient="vertical", command=tree.yview)
    scroll.pack(side="right", fill="y")
    tree.configure(yscrollcommand=scroll.set)

    detail = tk.Text(tab_results, height=10, wrap="word")
    detail.pack(fill="x", padx=10, pady=(0, 10))

    def show_detail(_event=None):
        sel = tree.selection()
        if not sel or not state["report"]:
            return
        idx = int(tree.item(sel[0], "tags")[0])
        f = state["report"]["findings"][idx]
        detail.delete("1.0", "end")
        detail.insert(
            "end",
            f"{f['title']}\n\n"
            f"Severity: {f['severity']}\n"
            f"Status: {f['status']}\n"
            f"OWASP: {f.get('owasp','')} {OWASP.get(f.get('owasp',''),'')}\n"
            f"Source: {f.get('source','')}\n"
            f"Confidence: {f.get('confidence','')}\n"
            f"URL: {f.get('url','')}\n\n"
            f"Evidence:\n{f.get('evidence','')}\n\n"
            f"Remediation:\n{f.get('remediation','')}"
        )

    tree.bind("<<TreeviewSelect>>", show_detail)

    # Log
    log_text = tk.Text(tab_log, wrap="word")
    log_text.pack(fill="both", expand=True, padx=10, pady=10)

    # Settings
    settings = ttk.Frame(tab_settings, padding=12)
    settings.pack(fill="both", expand=True)
    settings.columnconfigure(1, weight=1)

    add_labeled_entry(settings, 0, "Output directory", output_var)
    def browse_output():
        p = filedialog.askdirectory(title="Select report output directory")
        if p:
            output_var.set(p)
    ttk.Button(settings, text="Browse", command=browse_output).grid(row=0, column=2, padx=8)

    ttk.Label(settings, text="Max crawl pages").grid(row=1, column=0, sticky="w", padx=8, pady=6)
    ttk.Spinbox(settings, from_=1, to=250, textvariable=max_pages_var, width=10).grid(row=1, column=1, sticky="w", padx=8)

    ttk.Label(settings, text="Request delay (sec)").grid(row=2, column=0, sticky="w", padx=8, pady=6)
    ttk.Spinbox(settings, from_=0.0, to=10.0, increment=0.05, textvariable=delay_var, width=10).grid(row=2, column=1, sticky="w", padx=8)

    ttk.Separator(settings).grid(row=3, column=0, columnspan=3, sticky="ew", pady=10)
    ttk.Label(settings, text="Burp REST API", font=("TkDefaultFont", 11, "bold")).grid(
        row=4, column=0, columnspan=3, sticky="w", padx=8
    )
    add_labeled_entry(settings, 5, "REST API URL", burp_api_var)
    add_labeled_entry(settings, 6, "REST API key", burp_key_var, show="*")
    add_labeled_entry(settings, 7, "Burp JAR (optional)", burp_jar_var)
    def browse_burp_jar():
        p = filedialog.askopenfilename(title="Select Burp Suite JAR", filetypes=[("JAR", "*.jar"), ("All", "*.*")])
        if p:
            burp_jar_var.set(p)
    ttk.Button(settings, text="Browse", command=browse_burp_jar).grid(row=7, column=2, padx=8)

    add_labeled_entry(settings, 8, "Burp project (.burp)", burp_project_var)
    def browse_project():
        p = filedialog.asksaveasfilename(
            title="Select/create Burp project",
            defaultextension=".burp",
            filetypes=[("Burp project", "*.burp"), ("All", "*.*")],
        )
        if p:
            burp_project_var.set(p)
    ttk.Button(settings, text="Browse", command=browse_project).grid(row=8, column=2, padx=8)

    add_labeled_entry(settings, 9, "Burp config JSON", burp_config_var)
    def browse_config():
        p = filedialog.askopenfilename(title="Select Burp config", filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if p:
            burp_config_var.set(p)
    ttk.Button(settings, text="Browse", command=browse_config).grid(row=9, column=2, padx=8)
    ttk.Checkbutton(settings, text="Launch Burp headless", variable=headless_var).grid(row=10, column=1, sticky="w", padx=8, pady=6)

    ttk.Label(
        settings,
        text="Security note: keep Burp REST API on loopback (127.0.0.1) and use an API key.",
    ).grid(row=11, column=1, sticky="w", padx=8, pady=8)

    def append_log(line: str):
        event_q.put(("log", line))

    def progress_msg(line: str):
        event_q.put(("status", line))

    def build_config_from_gui() -> AssessmentConfig:
        allowed = [x.strip() for x in re.split(r"[,;\s]+", allow_var.get()) if x.strip()]
        configs = [burp_config_var.get().strip()] if burp_config_var.get().strip() else []
        return AssessmentConfig(
            target=target_var.get().strip(),
            allowed_hosts=allowed,
            authorized=auth_var.get(),
            output_dir=output_var.get().strip() or "reports",
            max_pages=max_pages_var.get(),
            delay=delay_var.get(),
            api_path=api_file_var.get().strip() or None,
            graphql_url=graphql_var.get().strip() or None,
            burp_enabled=burp_enabled_var.get(),
            burp_api=burp_api_var.get().strip() or "http://127.0.0.1:1337",
            burp_api_key=burp_key_var.get().strip() or None,
            burp_scan_configuration=burp_profile_var.get().strip(),
            burp_jar=burp_jar_var.get().strip() or None,
            burp_project=burp_project_var.get().strip() or None,
            burp_config_files=configs,
            burp_headless=headless_var.get(),
        )

    def start_assessment():
        if state["thread"] and state["thread"].is_alive():
            messagebox.showinfo("Assessment", "An assessment is already running.")
            return
        try:
            cfg = build_config_from_gui()
            require_authorized_target(cfg.target, cfg.allowed_hosts, cfg.authorized)
        except Exception as exc:
            messagebox.showerror("Cannot start", str(exc))
            return

        tree.delete(*tree.get_children())
        detail.delete("1.0", "end")
        state["report"] = None
        status_var.set("Starting...")
        progress.start(10)
        notebook.select(tab_log)

        def worker():
            try:
                report = run_assessment(cfg, append_log, progress_msg)
                event_q.put(("done", report))
            except Exception as exc:
                event_q.put(("error", f"{exc}\n\n{traceback.format_exc()}"))

        state["thread"] = threading.Thread(target=worker, daemon=True)
        state["thread"].start()

    def open_reports():
        report = state.get("report")
        if not report:
            messagebox.showinfo("Reports", "Run an assessment first.")
            return
        html_path = report.get("reports", {}).get("html")
        if html_path:
            webbrowser.open(Path(html_path).resolve().as_uri())

    ttk.Button(button_bar, text="Start Assessment", command=start_assessment).pack(side="right", padx=4)
    ttk.Button(button_bar, text="Open HTML Report", command=open_reports).pack(side="right", padx=4)

    def populate_results(report: dict[str, Any]):
        tree.delete(*tree.get_children())
        for idx, f in enumerate(report.get("findings", [])):
            tree.insert(
                "",
                "end",
                values=(
                    f.get("severity", ""),
                    f.get("status", ""),
                    f.get("owasp", ""),
                    f.get("source", ""),
                    f.get("title", ""),
                    f.get("url", ""),
                ),
                tags=(str(idx),),
            )

    def poll_events():
        try:
            while True:
                kind, payload = event_q.get_nowait()
                if kind == "log":
                    log_text.insert("end", payload + "\n")
                    log_text.see("end")
                elif kind == "status":
                    status_var.set(payload)
                elif kind == "done":
                    progress.stop()
                    state["report"] = payload
                    status_var.set(
                        f"Complete — {payload['summary']['finding_count']} report items"
                    )
                    populate_results(payload)
                    notebook.select(tab_results)
                    messagebox.showinfo(
                        "Assessment complete",
                        "Reports:\n" + "\n".join(
                            f"{k.upper()}: {v}" for k, v in payload.get("reports", {}).items()
                        ),
                    )
                elif kind == "error":
                    progress.stop()
                    status_var.set("Error")
                    log_text.insert("end", payload + "\n")
                    log_text.see("end")
                    messagebox.showerror("Assessment error", payload.split("\n\n")[0])
        except queue.Empty:
            pass
        root.after(150, poll_events)

    root.after(150, poll_events)
    root.mainloop()


def main() -> int:
    parser = build_cli_parser()
    args = parser.parse_args()
    if args.no_gui:
        return cli_main(args)
    gui_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
