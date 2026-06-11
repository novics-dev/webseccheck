"""
A04 — Insecure Design scanner.
"""

from __future__ import annotations

import re
import time
import uuid
from urllib.parse import urlparse, urljoin

from app.services.scanner.base import BaseScanner


class A04InsecureDesignScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A04'

    @property
    def name(self) -> str:
        return 'Insecure Design'

    @property
    def description(self) -> str:
        return (
            'Checks for insecure design issues including absent rate limiting, '
            'verbose error messages, debug mode exposure, and default error pages.'
        )

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f'{parsed.scheme}://{parsed.netloc}'

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def check_rate_limiting(self, url: str) -> dict:
        """Make 6 rapid GET requests and check for throttling signals."""
        start = time.time()
        rate_limit_headers = [
            'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
            'x-rate-limit-limit', 'x-rate-limit-remaining', 'retry-after',
            'ratelimit-limit', 'ratelimit-remaining',
        ]
        throttle_found = False
        throttle_evidence = []
        status_codes = []

        try:
            for i in range(6):
                response = self.make_request(url, timeout=8)
                if response is None:
                    continue
                status_codes.append(response.status_code)
                if response.status_code == 429:
                    throttle_found = True
                    throttle_evidence.append(f'Request {i + 1}: HTTP 429 Too Many Requests')
                    break
                for header in rate_limit_headers:
                    val = response.headers.get(header)
                    if val:
                        throttle_found = True
                        throttle_evidence.append(f'{header}: {val}')

            duration_ms = int((time.time() - start) * 1000)

            if throttle_found:
                return self.create_check(
                    owasp_category='A04',
                    check_name='Rate Limiting',
                    status='pass',
                    severity='medium',
                    description='Rate limiting signals detected.',
                    details='; '.join(throttle_evidence),
                    evidence='; '.join(throttle_evidence),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A04',
                check_name='Rate Limiting',
                status='warning',
                severity='medium',
                description='No rate limiting signals detected after 6 rapid requests.',
                details=f'6 requests made; status codes: {status_codes}. No 429 or rate-limit headers.',
                remediation=(
                    'Implement rate limiting on all public endpoints. '
                    'Return HTTP 429 with Retry-After header when limits are exceeded.'
                ),
                evidence='No rate limit headers or 429 responses observed',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04',
                check_name='Rate Limiting',
                status='info',
                severity='medium',
                description='Error during rate limiting check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_error_verbosity(self, url: str) -> dict:
        """Probe nonexistent paths and check for stack traces or system info."""
        start = time.time()
        base_url = self._get_base_url(url)
        probe_paths = [
            f'/{uuid.uuid4().hex}',
            '/error-test',
        ]
        verbose_patterns = [
            r'Traceback \(most recent call last\)',
            r'File ".*\.py", line \d+',
            r'at .+\(.+\.java:\d+\)',
            r'System\.Web\.HttpException',
            r'Internal Server Error.*line \d+',
            r'raise \w+Exception',
            r'Exception in',
            r'Fatal error',
            r'NullPointerException',
            r'Caused by:',
        ]

        try:
            found_patterns = []
            for path in probe_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=10)
                if response is None:
                    continue
                body = response.text
                for pattern in verbose_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        found_patterns.append(pattern)

            duration_ms = int((time.time() - start) * 1000)

            if found_patterns:
                return self.create_check(
                    owasp_category='A04',
                    check_name='Error Verbosity',
                    status='fail',
                    severity='medium',
                    description='Verbose error information exposed in HTTP responses.',
                    details=f"Matched patterns: {', '.join(found_patterns)}",
                    remediation=(
                        'Configure custom error pages for all error codes. '
                        'Suppress stack traces and system information in production. '
                        'Log errors server-side rather than exposing them to clients.'
                    ),
                    evidence=f"Patterns: {', '.join(found_patterns[:3])}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A04',
                check_name='Error Verbosity',
                status='pass',
                severity='medium',
                description='Error responses do not expose verbose system information.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04',
                check_name='Error Verbosity',
                status='info',
                severity='medium',
                description='Error during error verbosity check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_debug_mode(self, url: str) -> dict:
        """Check response headers/body for debug indicators."""
        start = time.time()
        debug_header_names = ['x-debug', 'x-debug-token', 'x-debug-token-link', 'x-symfony-debug']
        debug_body_patterns = [
            r'Werkzeug Debugger',
            r'Interactive Console',
            r'DEBUG\s*=\s*True',
            r'debug_toolbar',
            r'Django Debug Toolbar',
            r'Application Traceback',
            r'Symfony Profiler',
            r'laravel-debugbar',
            r'_debugbar',
            r'DEV_MODE',
        ]

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A04',
                    check_name='Debug Mode Exposure',
                    status='info',
                    severity='high',
                    description='Could not retrieve response to check for debug mode.',
                    duration_ms=duration_ms,
                )

            found_debug = []
            for header_name in debug_header_names:
                val = response.headers.get(header_name)
                if val:
                    found_debug.append(f'Header {header_name}: {val}')

            body = response.text
            for pattern in debug_body_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    found_debug.append(f'Body pattern: {pattern}')

            if found_debug:
                return self.create_check(
                    owasp_category='A04',
                    check_name='Debug Mode Exposure',
                    status='fail',
                    severity='high',
                    description='Debug mode indicators found in response.',
                    details='; '.join(found_debug),
                    remediation=(
                        'Disable debug mode in production. Set DEBUG=False in framework configuration. '
                        'Remove debug toolbars and ensure error details are not exposed publicly.'
                    ),
                    evidence='; '.join(found_debug[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A04',
                check_name='Debug Mode Exposure',
                status='pass',
                severity='high',
                description='No debug mode indicators found in response.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04',
                check_name='Debug Mode Exposure',
                status='info',
                severity='high',
                description='Error during debug mode check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_default_error_pages(self, url: str) -> dict:
        """Check if default framework error pages are shown."""
        start = time.time()
        base_url = self._get_base_url(url)
        probe_url = urljoin(base_url, f'/wsc-probe-{uuid.uuid4().hex[:8]}')
        framework_patterns = [
            (r'Werkzeug.*Debugger', 'Werkzeug/Flask debug page'),
            (r'Django.*debug.*page|Traceback.*Django', 'Django debug page'),
            (r'Laravel.*Whoops|Whoops.*Laravel', 'Laravel debug page'),
            (r'Whitelabel Error Page', 'Spring Whitelabel error page'),
            (r'Application Error.*Rails|Rails.*error', 'Rails error page'),
            (r'<title>Error.*Apache|Server at.*port', 'Apache default error page'),
            (r'nginx.*error|<title>.*nginx', 'nginx default error page'),
        ]

        try:
            response = self.make_request(probe_url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A04',
                    check_name='Default Error Pages',
                    status='info',
                    severity='low',
                    description='Could not retrieve error response to test default error pages.',
                    duration_ms=duration_ms,
                )

            body = response.text
            for pattern, description in framework_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return self.create_check(
                        owasp_category='A04',
                        check_name='Default Error Pages',
                        status='fail',
                        severity='low',
                        description=f'Default framework error page detected: {description}.',
                        details=f'Pattern matched: {pattern}',
                        remediation=(
                            'Configure custom error pages that do not reveal framework or technology information. '
                            'Disable debug mode in production environments.'
                        ),
                        evidence=f'Framework error page: {description}',
                        duration_ms=duration_ms,
                    )

            return self.create_check(
                owasp_category='A04',
                check_name='Default Error Pages',
                status='pass',
                severity='low',
                description='No default framework error pages detected.',
                details=f'HTTP {response.status_code} for non-existent path; no framework error signatures found.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04',
                check_name='Default Error Pages',
                status='info',
                severity='low',
                description='Error during default error pages check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A04 Insecure Design checks', 'info', 'a04_start', db_session)

        self.log(scan_id, 'Checking rate limiting', 'info', 'a04_rate_limit', db_session)
        checks.append(self.check_rate_limiting(target_url))

        self.log(scan_id, 'Checking error verbosity', 'info', 'a04_error', db_session)
        checks.append(self.check_error_verbosity(target_url))

        self.log(scan_id, 'Checking debug mode exposure', 'info', 'a04_debug', db_session)
        checks.append(self.check_debug_mode(target_url))

        self.log(scan_id, 'Checking default error pages', 'info', 'a04_error_pages', db_session)
        checks.append(self.check_default_error_pages(target_url))

        self.log(scan_id, 'Completed A04 Insecure Design checks', 'info', 'a04_done', db_session)
        return checks
