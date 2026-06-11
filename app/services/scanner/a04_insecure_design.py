import time
import re
import uuid
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


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
            'verbose error messages, debug mode exposure, default credential forms, '
            'and account enumeration risks.'
        )

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def check_rate_limiting(self, url: str) -> dict:
        """Make 10 rapid requests and check for throttling signals."""
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
            for i in range(10):
                response = self.make_request(url, timeout=8)
                if response is None:
                    continue
                status_codes.append(response.status_code)
                if response.status_code == 429:
                    throttle_found = True
                    throttle_evidence.append(f"Request {i+1}: HTTP 429 Too Many Requests")
                    break
                for header in rate_limit_headers:
                    val = response.headers.get(header)
                    if val:
                        throttle_found = True
                        throttle_evidence.append(f"{header}: {val}")

            duration_ms = int((time.time() - start) * 1000)

            if throttle_found:
                return self.create_check(
                    owasp_category='A04:2021',
                    check_name='Rate Limiting',
                    status='pass',
                    severity='medium',
                    description='Rate limiting signals detected.',
                    details='; '.join(throttle_evidence),
                    remediation='Continue enforcing rate limiting and monitor for abuse.',
                    evidence='; '.join(throttle_evidence),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A04:2021',
                check_name='Rate Limiting',
                status='warning',
                severity='medium',
                description='No rate limiting signals detected after 10 rapid requests.',
                details=f"10 requests made; status codes: {status_codes}. No 429 or rate-limit headers found.",
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
                owasp_category='A04:2021',
                check_name='Rate Limiting',
                status='error',
                severity='medium',
                description='Error during rate limiting check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_error_verbosity(self, url: str) -> dict:
        """Append random UUID path and check for stack traces or system info."""
        start = time.time()
        random_path = f"/webseccheck-probe-{uuid.uuid4().hex}"
        base_url = self._get_base_url(url)
        test_url = urljoin(base_url, random_path)

        verbose_patterns = [
            r'Traceback \(most recent call last\)',
            r'File ".*\.py", line \d+',
            r'at .+\(.+\.java:\d+\)',
            r'System\.Web\.HttpException',
            r'Microsoft\.AspNet',
            r'Internal Server Error.*line \d+',
            r'DEBUG\s*=\s*True',
            r'raise \w+Exception',
            r'Exception in thread',
            r'NullPointerException',
            r'undefined method',
            r'NoMethodError',
            r'stack overflow',
            r'Caused by:',
        ]

        try:
            response = self.make_request(test_url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A04:2021',
                    check_name='Error Verbosity',
                    status='error',
                    severity='medium',
                    description='Could not retrieve error response.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            body = response.text
            found_patterns = []
            for pattern in verbose_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    found_patterns.append(pattern)

            if found_patterns or response.status_code == 500:
                status = 'fail' if found_patterns else 'warning'
                return self.create_check(
                    owasp_category='A04:2021',
                    check_name='Error Verbosity',
                    status=status,
                    severity='medium',
                    description='Verbose error information exposed in HTTP response.',
                    details=f"HTTP {response.status_code}; matched patterns: {', '.join(found_patterns)}",
                    remediation=(
                        'Configure custom error pages for all error codes. '
                        'Suppress stack traces and system information in production. '
                        'Log errors server-side rather than exposing them to clients.'
                    ),
                    evidence=f"Status {response.status_code}; patterns: {', '.join(found_patterns[:3])}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A04:2021',
                check_name='Error Verbosity',
                status='pass',
                severity='medium',
                description='Error response does not expose verbose system information.',
                details=f"HTTP {response.status_code} returned without stack trace or system details.",
                remediation='Ensure all error pages are generic and reveal no internal details.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04:2021',
                check_name='Error Verbosity',
                status='error',
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
        ]

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A04:2021',
                    check_name='Debug Mode Exposure',
                    status='error',
                    severity='high',
                    description='Could not retrieve response to check for debug mode.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            found_debug = []
            for header_name in debug_header_names:
                val = response.headers.get(header_name)
                if val:
                    found_debug.append(f"Header {header_name}: {val}")

            body = response.text
            for pattern in debug_body_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    found_debug.append(f"Body pattern: {pattern}")

            if found_debug:
                return self.create_check(
                    owasp_category='A04:2021',
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
                owasp_category='A04:2021',
                check_name='Debug Mode Exposure',
                status='pass',
                severity='high',
                description='No debug mode indicators found in response.',
                details='No debug headers or debug framework content detected.',
                remediation='Ensure DEBUG is disabled in all production deployments.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04:2021',
                check_name='Debug Mode Exposure',
                status='error',
                severity='high',
                description='Error during debug mode check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_default_credentials(self, url: str) -> dict:
        """Detect login pages and note their presence as a default credentials risk."""
        start = time.time()
        login_paths = ['/login', '/signin', '/admin/login', '/wp-login.php', '/user/login']
        base_url = self._get_base_url(url)
        found_login_pages = []

        login_form_patterns = [
            r'<input[^>]+type=["\']password["\']',
            r'<form[^>]+action=["\'][^"\']*login',
            r'id=["\']login',
            r'name=["\']login',
        ]

        try:
            for path in login_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=8)
                if response is None or response.status_code not in (200, 301, 302):
                    continue
                body = response.text
                for pattern in login_form_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        found_login_pages.append(path)
                        break

            duration_ms = int((time.time() - start) * 1000)

            if found_login_pages:
                return self.create_check(
                    owasp_category='A04:2021',
                    check_name='Default Credentials Risk',
                    status='warning',
                    severity='medium',
                    description='Login page(s) detected — risk of default credential use.',
                    details=f"Login forms found at: {', '.join(found_login_pages)}",
                    remediation=(
                        'Ensure default credentials are changed before deployment. '
                        'Implement account lockout, CAPTCHA, and MFA on login pages. '
                        'Audit for default admin accounts.'
                    ),
                    evidence=f"Login pages: {', '.join(found_login_pages)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A04:2021',
                check_name='Default Credentials Risk',
                status='info',
                severity='medium',
                description='No login pages found at common paths.',
                details=f"Checked paths: {', '.join(login_paths)}",
                remediation='Ensure any login interfaces require strong, non-default credentials.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04:2021',
                check_name='Default Credentials Risk',
                status='error',
                severity='medium',
                description='Error during default credentials check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_account_enumeration(self, url: str) -> dict:
        """Probe /register and /forgot-password for account enumeration risks."""
        start = time.time()
        base_url = self._get_base_url(url)
        enumeration_paths = ['/register', '/signup', '/forgot-password', '/reset-password', '/forgot']
        found_endpoints = []

        try:
            for path in enumeration_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=8)
                if response is not None and response.status_code == 200:
                    body = response.text.lower()
                    if any(kw in body for kw in ['email', 'username', 'password', 'register', 'forgot', 'reset']):
                        found_endpoints.append(path)

            duration_ms = int((time.time() - start) * 1000)

            if found_endpoints:
                return self.create_check(
                    owasp_category='A04:2021',
                    check_name='Account Enumeration',
                    status='warning',
                    severity='medium',
                    description='Account-related endpoints found that may be vulnerable to enumeration.',
                    details=f"Endpoints with account forms: {', '.join(found_endpoints)}",
                    remediation=(
                        'Ensure error messages on registration and password reset are generic '
                        '(e.g. "If this email exists, you will receive a reset link"). '
                        'Use identical response times and messages for valid and invalid accounts.'
                    ),
                    evidence=f"Accessible endpoints: {', '.join(found_endpoints)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A04:2021',
                check_name='Account Enumeration',
                status='info',
                severity='medium',
                description='No obvious account enumeration endpoints found at common paths.',
                details=f"Checked: {', '.join(enumeration_paths)}",
                remediation='Ensure registration and password reset flows do not leak account existence.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A04:2021',
                check_name='Account Enumeration',
                status='error',
                severity='medium',
                description='Error during account enumeration check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A04 Insecure Design checks', 'info', 'a04_start', db_session)

        self.log(scan_id, 'Checking rate limiting', 'info', 'a04_rate_limit', db_session)
        checks.append(self.check_rate_limiting(target_url))

        self.log(scan_id, 'Checking error verbosity', 'info', 'a04_error', db_session)
        checks.append(self.check_error_verbosity(target_url))

        self.log(scan_id, 'Checking debug mode exposure', 'info', 'a04_debug', db_session)
        checks.append(self.check_debug_mode(target_url))

        self.log(scan_id, 'Checking default credentials risk', 'info', 'a04_creds', db_session)
        checks.append(self.check_default_credentials(target_url))

        self.log(scan_id, 'Checking account enumeration', 'info', 'a04_enum', db_session)
        checks.append(self.check_account_enumeration(target_url))

        self.log(scan_id, 'Completed A04 Insecure Design checks', 'info', 'a04_done', db_session)
        return checks
