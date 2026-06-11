"""
A03 — Injection scanner.

All checks are passive detection tests. Limited to 2-3 params from URL.
No more than 5 requests per check.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from app.services.scanner.base import BaseScanner


class A03InjectionScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A03'

    @property
    def name(self) -> str:
        return 'Injection'

    @property
    def description(self) -> str:
        return (
            'Passive detection of injection vulnerabilities including XSS reflection, '
            'SQL injection error messages, HTML injection, CRLF injection, '
            'and path traversal via parameters.'
        )

    def _inject_param(self, url: str, payload: str, max_params: int = 2) -> list[str]:
        """Return list of URLs with payload injected into each of the first max_params params."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        urls = []

        if params:
            for key in list(params.keys())[:max_params]:
                modified = dict(params)
                modified[key] = [payload]
                new_query = urlencode(modified, doseq=True)
                urls.append(urlunparse(parsed._replace(query=new_query)))
        else:
            # No existing params — inject a new one
            new_query = urlencode({'test': payload})
            urls.append(urlunparse(parsed._replace(query=new_query)))

        return urls

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def check_xss_reflection(self, url: str) -> dict:
        """Inject safe XSS probes and check if they are reflected unescaped."""
        start = time.time()
        probes = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
        ]
        try:
            for probe in probes:
                test_urls = self._inject_param(url, probe, max_params=2)
                for test_url in test_urls[:3]:
                    response = self.make_request(test_url, timeout=10)
                    if response is None:
                        continue
                    body = response.text
                    if probe in body:
                        duration_ms = int((time.time() - start) * 1000)
                        return self.create_check(
                            owasp_category='A03',
                            check_name='XSS Reflection',
                            status='fail',
                            severity='high',
                            description='XSS probe reflected unescaped in response.',
                            details=f"Probe '{probe[:50]}' found verbatim in response body.",
                            remediation=(
                                'Encode all user-supplied input before rendering in HTML. '
                                'Implement a Content-Security-Policy. Use a templating engine with auto-escaping.'
                            ),
                            evidence=f'Unescaped reflection of: {probe[:50]}',
                            duration_ms=duration_ms,
                        )
                    # Partial reflection
                    if 'alert(1)' in body and '<script>' not in body:
                        duration_ms = int((time.time() - start) * 1000)
                        return self.create_check(
                            owasp_category='A03',
                            check_name='XSS Reflection',
                            status='warning',
                            severity='high',
                            description='Partial XSS reflection: script tag filtered but inner content reflected.',
                            details='alert(1) found in body without enclosing script tag.',
                            remediation='Implement proper output encoding. Use context-aware escaping.',
                            evidence='alert(1) reflected without script tags',
                            duration_ms=duration_ms,
                        )

            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='XSS Reflection',
                status='pass',
                severity='high',
                description='XSS probes were not reflected unescaped in responses.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='XSS Reflection',
                status='info',
                severity='high',
                description='Error during XSS reflection check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_sql_injection_errors(self, url: str) -> dict:
        """Inject SQL characters and check response for SQL error messages."""
        start = time.time()
        sql_payloads = ["'", '"', "1' OR '1'='1"]
        sql_error_patterns = [
            r'syntax error',
            r'mysql_fetch',
            r'ORA-\d{5}',
            r'sqlite.*error',
            r'pg_query',
            r'Microsoft OLE DB Provider for SQL Server',
            r'Unclosed quotation mark',
            r'mysql.*error',
            r'SQLSTATE',
            r'Warning.*mysql_',
            r'valid MySQL result',
            r'MySqlException',
            r'SQL syntax.*MySQL',
            r'PostgreSQL.*ERROR',
            r'Microsoft SQL',
        ]
        found_errors = []

        try:
            for payload in sql_payloads:
                test_urls = self._inject_param(url, payload, max_params=2)
                for test_url in test_urls[:2]:
                    response = self.make_request(test_url, timeout=10)
                    if response is None:
                        continue
                    body = response.text
                    for pattern in sql_error_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            found_errors.append(
                                f"Payload '{payload}' triggered pattern: {pattern}"
                            )
                            break
                # Stop after 5 total requests
                if len(found_errors) >= 1 or (sql_payloads.index(payload) + 1) * 2 >= 5:
                    break

            duration_ms = int((time.time() - start) * 1000)

            if found_errors:
                return self.create_check(
                    owasp_category='A03',
                    check_name='SQL Injection',
                    status='fail',
                    severity='critical',
                    description='SQL error messages detected — possible SQL injection vulnerability.',
                    details='; '.join(found_errors),
                    remediation=(
                        'Use parameterised queries or prepared statements. '
                        'Never concatenate user input into SQL strings. '
                        'Suppress detailed database error messages in production.'
                    ),
                    evidence='; '.join(found_errors[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A03',
                check_name='SQL Injection',
                status='pass',
                severity='critical',
                description='No SQL error messages detected from injection payloads.',
                details='Common SQL injection payloads did not trigger database error messages.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='SQL Injection',
                status='info',
                severity='critical',
                description='Error during SQL injection check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_html_injection(self, url: str) -> dict:
        """Check if HTML tags are reflected unescaped in the response."""
        start = time.time()
        probe = '<b>webseccheck_test</b>'
        try:
            test_urls = self._inject_param(url, probe, max_params=2)
            for test_url in test_urls[:2]:
                response = self.make_request(test_url, timeout=10)
                if response is None:
                    continue
                if probe in response.text:
                    duration_ms = int((time.time() - start) * 1000)
                    return self.create_check(
                        owasp_category='A03',
                        check_name='HTML Injection',
                        status='fail',
                        severity='medium',
                        description='HTML injection probe reflected unescaped in response.',
                        details=f"Probe '{probe}' found verbatim in response body.",
                        remediation=(
                            'Encode HTML special characters in all user-supplied output. '
                            'Use a templating engine with automatic HTML escaping.'
                        ),
                        evidence=f'Reflected: {probe}',
                        duration_ms=int((time.time() - start) * 1000),
                    )

            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='HTML Injection',
                status='pass',
                severity='medium',
                description='HTML injection probe was not reflected unescaped.',
                details='HTML tags appear to be escaped or stripped from output.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='HTML Injection',
                status='info',
                severity='medium',
                description='Error during HTML injection check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_crlf_injection(self, url: str) -> dict:
        """Test CRLF injection via %0d%0a sequences in params."""
        start = time.time()
        crlf_payload = 'webseccheck%0d%0aX-Injected-Header%3a%20injected'
        try:
            test_urls = self._inject_param(url, crlf_payload, max_params=1)
            for test_url in test_urls[:2]:
                response = self.make_request(test_url, allow_redirects=False, timeout=10)
                if response is None:
                    continue
                injected_in_headers = 'x-injected-header' in {k.lower() for k in response.headers.keys()}
                injected_in_body = 'X-Injected-Header' in response.text
                if injected_in_headers or injected_in_body:
                    duration_ms = int((time.time() - start) * 1000)
                    return self.create_check(
                        owasp_category='A03',
                        check_name='CRLF Injection',
                        status='fail',
                        severity='high',
                        description='CRLF injection detected: injected header appeared in response.',
                        details='X-Injected-Header was found in response headers or body.',
                        remediation=(
                            'Strip or encode CR (\\r) and LF (\\n) characters from all user inputs '
                            'before using them in HTTP headers or responses.'
                        ),
                        evidence='X-Injected-Header found in response',
                        duration_ms=duration_ms,
                    )

            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='CRLF Injection',
                status='pass',
                severity='high',
                description='CRLF injection probe did not produce injected headers.',
                details='No injected headers detected from CRLF payload.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='CRLF Injection',
                status='info',
                severity='high',
                description='Error during CRLF injection check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_path_traversal(self, url: str) -> dict:
        """Test path traversal via URL parameters."""
        start = time.time()
        traversal_payloads = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//etc/passwd',
        ]
        passwd_indicators = ['root:x:', 'root:0:', '/bin/bash', '/bin/sh', 'nobody:']
        found_evidence = []

        try:
            for payload in traversal_payloads:
                test_urls = self._inject_param(url, payload, max_params=2)
                for test_url in test_urls[:2]:
                    response = self.make_request(test_url, timeout=10)
                    if response is None:
                        continue
                    body = response.text
                    for indicator in passwd_indicators:
                        if indicator in body:
                            found_evidence.append(f"Payload '{payload[:40]}' returned passwd-like content")
                            break
                if found_evidence:
                    break

            duration_ms = int((time.time() - start) * 1000)

            if found_evidence:
                return self.create_check(
                    owasp_category='A03',
                    check_name='Path Traversal via Parameters',
                    status='fail',
                    severity='critical',
                    description='Path traversal payload in parameters returned file system content.',
                    details='; '.join(found_evidence),
                    remediation=(
                        'Validate all file path inputs. Resolve to canonical path and verify it '
                        'remains within the allowed base directory. Use a whitelist of allowed files.'
                    ),
                    evidence='; '.join(found_evidence),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A03',
                check_name='Path Traversal via Parameters',
                status='pass',
                severity='critical',
                description='No path traversal file content detected via URL parameters.',
                details='Traversal payloads in URL parameters did not return /etc/passwd content.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A03',
                check_name='Path Traversal via Parameters',
                status='info',
                severity='critical',
                description='Error during path traversal parameter check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A03 Injection checks', 'info', 'a03_start', db_session)

        self.log(scan_id, 'Checking XSS reflection', 'info', 'a03_xss', db_session)
        checks.append(self.check_xss_reflection(target_url))

        self.log(scan_id, 'Checking SQL injection errors', 'info', 'a03_sqli', db_session)
        checks.append(self.check_sql_injection_errors(target_url))

        self.log(scan_id, 'Checking HTML injection', 'info', 'a03_html', db_session)
        checks.append(self.check_html_injection(target_url))

        self.log(scan_id, 'Checking CRLF injection', 'info', 'a03_crlf', db_session)
        checks.append(self.check_crlf_injection(target_url))

        self.log(scan_id, 'Checking path traversal via parameters', 'info', 'a03_path', db_session)
        checks.append(self.check_path_traversal(target_url))

        self.log(scan_id, 'Completed A03 Injection checks', 'info', 'a03_done', db_session)
        return checks
