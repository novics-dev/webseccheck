"""
A10 — Server-Side Request Forgery (SSRF) scanner.
"""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

from app.services.scanner.base import BaseScanner


class A10SSRFScanner(BaseScanner):
    category = "A10"
    name = "Server-Side Request Forgery (SSRF)"
    description = (
        "Checks URL parameters that fetch remote content, webhook/callback params, "
        "open redirects, and SSRF-prone functionality."
    )

    SSRF_PARAMS = [
        "url", "uri", "link", "src", "source", "dest", "destination",
        "target", "redirect", "next", "return", "returnTo", "return_to",
        "goto", "go", "callback", "webhook", "fetch", "load", "include",
        "file", "path", "resource", "page", "site",
    ]

    OPEN_REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "returnTo", "return_to",
        "goto", "go", "forward", "redir", "location",
    ]

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []
        self.log(scan_id, "Starting A10 SSRF checks", "info", "A10", db_session)
        checks.extend(self._check_ssrf_params(target_url, scan_id, db_session))
        checks.extend(self._check_open_redirect(target_url, scan_id, db_session))
        checks.extend(self._check_import_by_url(target_url, scan_id, db_session))
        self.log(scan_id, f"A10 checks complete — {len(checks)} results", "info", "A10", db_session)
        return checks

    def _check_ssrf_params(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking for SSRF-prone URL parameters", "info", "A10:params", db_session)
        start = time.time()
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        # Look for SSRF-prone parameter names in query string
        found_params = [k for k in params if k.lower() in self.SSRF_PARAMS]

        # Also check the HTML for forms that might have these params
        resp = self.make_request(target_url)
        form_params = []
        if resp:
            for param in self.SSRF_PARAMS:
                if re.search(
                    r'<input[^>]+name=["\']' + re.escape(param) + r'["\']',
                    resp.text, re.IGNORECASE
                ):
                    form_params.append(param)

        all_found = list(set(found_params + form_params))
        duration_ms = int((time.time() - start) * 1000)

        if all_found:
            return [self.create_check(
                "A10", "SSRF-Prone Parameters", "warning", "high",
                f"URL or form parameters that may enable SSRF: {all_found}",
                details={"params_in_url": found_params, "params_in_form": form_params},
                remediation=(
                    "Validate and whitelist allowed URLs/hosts for any parameter that accepts URLs. "
                    "Block requests to internal network ranges and cloud metadata endpoints."
                ),
                evidence=f"SSRF-prone params: {all_found}",
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A10", "SSRF-Prone Parameters", "pass", "info",
            "No obvious SSRF-prone parameters detected.",
            duration_ms=duration_ms,
        )]

    def _check_open_redirect(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking for open redirect vulnerabilities", "info", "A10:redirect", db_session)
        start = time.time()
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        redirect_params = [k for k in params if k.lower() in self.OPEN_REDIRECT_PARAMS]
        findings = []

        for param in redirect_params[:3]:  # Limit probes
            # Inject an external URL
            test_params = dict(params)
            test_params[param] = ["https://evil-redirect-test.example.com"]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            resp = self.make_request(test_url, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil-redirect-test.example.com" in location:
                    findings.append({"param": param, "location": location})

        duration_ms = int((time.time() - start) * 1000)
        if findings:
            return [self.create_check(
                "A10", "Open Redirect", "fail", "medium",
                f"Open redirect vulnerability detected via parameters: {[f['param'] for f in findings]}",
                details={"findings": findings},
                remediation=(
                    "Validate redirect destinations against an allowlist. "
                    "Never redirect to arbitrary external URLs based on user input."
                ),
                evidence=str(findings[0]),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A10", "Open Redirect", "pass", "info",
            "No open redirect detected.",
            duration_ms=duration_ms,
        )]

    def _check_import_by_url(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking for URL import/upload functionality", "info", "A10:import", db_session)
        start = time.time()
        resp = self.make_request(target_url)
        duration_ms = int((time.time() - start) * 1000)
        if not resp:
            return []

        # Look for form fields or links suggesting URL-based import
        import_patterns = [
            r'import.*from.*url', r'upload.*from.*url', r'fetch.*url',
            r'<input[^>]+placeholder=["\'][^"\']*url[^"\']*["\']',
            r'enter.*url.*import', r'url.*import',
        ]
        found = []
        for pattern in import_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                found.append(pattern)

        if found:
            return [self.create_check(
                "A10", "URL Import Functionality", "warning", "high",
                "URL-based import or upload functionality detected — potential SSRF vector.",
                details={"patterns": found},
                remediation=(
                    "Validate and sanitize URLs accepted for import. "
                    "Block access to internal network ranges. "
                    "Consider using a separate sandboxed service for URL fetching."
                ),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A10", "URL Import Functionality", "pass", "info",
            "No URL-based import functionality detected.",
            duration_ms=duration_ms,
        )]
