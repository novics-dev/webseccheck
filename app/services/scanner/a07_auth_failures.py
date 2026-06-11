import time
import re
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


class A07AuthFailuresScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A07'

    @property
    def name(self) -> str:
        return 'Identification and Authentication Failures'

    @property
    def description(self) -> str:
        return (
            'Checks for authentication weaknesses including absent brute-force protection, '
            'passwords in URLs, insecure session cookies, missing MFA, '
            'and password reset mechanism presence.'
        )

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def check_brute_force_protection(self, url: str) -> dict:
        """Find /login, make 5 POST requests with wrong creds, check for lockout/rate-limit signals."""
        start = time.time()
        base_url = self._get_base_url(url)
        login_paths = ['/login', '/signin', '/admin/login', '/wp-login.php', '/user/login']
        login_url = None

        lockout_patterns = [
            r'account.{0,20}locked',
            r'too many.{0,20}attempt',
            r'temporarily.{0,20}disabled',
            r'captcha',
            r'recaptcha',
            r'please.{0,20}wait',
            r'blocked',
            r'exceeded.{0,20}limit',
        ]

        try:
            # Find a login page
            for path in login_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=8)
                if response and response.status_code == 200:
                    body = response.text.lower()
                    if re.search(r'<input[^>]+type=["\']password["\']', body, re.IGNORECASE):
                        login_url = test_url
                        break

            if not login_url:
                duration_ms = int((time.time() - start) * 1000)
                return self.create_check(
                    owasp_category='A07',
                    check_name='Brute Force Protection',
                    status='info',
                    severity='high',
                    description='No login page found at common paths to test brute force protection.',
                    details=f"Checked paths: {', '.join(login_paths)}",
                    remediation=(
                        'Implement account lockout, CAPTCHA, and rate limiting on all login endpoints.'
                    ),
                    duration_ms=duration_ms,
                )

            protection_signals = []
            status_codes = []

            for attempt in range(1, 6):
                post_data = {
                    'username': 'admin',
                    'email': 'admin@example.com',
                    'password': f'wrongpassword{attempt}',
                    'user': 'admin',
                    'pass': f'wrongpassword{attempt}',
                }
                response = self.make_request(
                    login_url, method='POST', data=post_data, timeout=8
                )
                if response is None:
                    continue

                status_codes.append(response.status_code)

                if response.status_code == 429:
                    protection_signals.append(f"Attempt {attempt}: HTTP 429 rate limiting")
                    break

                body = response.text.lower()
                for pattern in lockout_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        protection_signals.append(
                            f"Attempt {attempt}: lockout/captcha signal '{pattern}'"
                        )
                        break

                for header in ['x-ratelimit-remaining', 'retry-after']:
                    val = response.headers.get(header)
                    if val:
                        protection_signals.append(f"Attempt {attempt}: header {header}={val}")

            duration_ms = int((time.time() - start) * 1000)

            if protection_signals:
                return self.create_check(
                    owasp_category='A07',
                    check_name='Brute Force Protection',
                    status='pass',
                    severity='high',
                    description='Brute force protection signals detected on login endpoint.',
                    details=f"Login URL: {login_url}; Signals: {'; '.join(protection_signals)}",
                    remediation='Continue enforcing lockout, CAPTCHA, and rate limiting.',
                    evidence='; '.join(protection_signals),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A07',
                check_name='Brute Force Protection',
                status='fail',
                severity='high',
                description='No brute force protection detected after 5 failed login attempts.',
                details=f"Login URL: {login_url}; Status codes: {status_codes}; No lockout/CAPTCHA detected.",
                remediation=(
                    'Implement account lockout after N failed attempts. '
                    'Add CAPTCHA after repeated failures. '
                    'Apply rate limiting on the login endpoint.'
                ),
                evidence=f"5 attempts to {login_url} without lockout signal",
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A07',
                check_name='Brute Force Protection',
                status='warning',
                severity='high',
                description='Error during brute force protection check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_password_in_url(self, url: str) -> dict:
        """Check if 'password' appears in URL query params."""
        start = time.time()
        try:
            parsed = urlparse(url)
            query_lower = parsed.query.lower()
            password_params = re.findall(
                r'(?:^|&)(password|passwd|pass|pwd)[^&]*', query_lower
            )
            duration_ms = int((time.time() - start) * 1000)

            if password_params:
                return self.create_check(
                    owasp_category='A07',
                    check_name='Password in URL',
                    status='fail',
                    severity='high',
                    description='Password parameter detected in URL query string.',
                    details=f"Password-like params: {', '.join(set(password_params))}",
                    remediation=(
                        'Never transmit passwords in URL query parameters. '
                        'Use POST request body or secure headers instead.'
                    ),
                    evidence=f"URL query contains: {', '.join(set(password_params))}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A07',
                check_name='Password in URL',
                status='pass',
                severity='high',
                description='No password parameters detected in URL query string.',
                details='URL does not contain password, passwd, pass, or pwd query parameters.',
                remediation='Ensure authentication credentials are never placed in URLs.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A07',
                check_name='Password in URL',
                status='warning',
                severity='high',
                description='Error checking for password in URL.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_session_security(self, url: str) -> dict:
        """Check session/auth cookie attributes."""
        start = time.time()
        session_cookie_names = ['session', 'sessionid', 'sess', 'sid', 'phpsessid',
                                  'jsessionid', 'auth', 'token', 'access_token', 'jwt']
        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A07',
                    check_name='Session Cookie Security',
                    status='warning',
                    severity='high',
                    description='Could not retrieve response to check session cookies.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            # Collect all Set-Cookie headers
            set_cookie_raw = []
            for key, val in response.headers.items():
                if key.lower() == 'set-cookie':
                    set_cookie_raw.append(val)

            session_cookies = []
            for cookie_str in set_cookie_raw:
                name_match = re.match(r'([^=;]+)=([^;]*)', cookie_str)
                if name_match:
                    name = name_match.group(1).strip().lower()
                    value = name_match.group(2).strip()
                    if any(s in name for s in session_cookie_names):
                        session_cookies.append((name, value, cookie_str))

            if not session_cookies:
                return self.create_check(
                    owasp_category='A07',
                    check_name='Session Cookie Security',
                    status='info',
                    severity='high',
                    description='No session or authentication cookies found in response.',
                    details='No cookies matching known session cookie name patterns were set.',
                    remediation='When setting session cookies, use Secure, HttpOnly, and SameSite flags.',
                    duration_ms=duration_ms,
                )

            issues = []
            for name, value, cookie_str in session_cookies:
                cookie_lower = cookie_str.lower()
                flags_missing = []

                if len(value) < 16:
                    issues.append(f"Cookie '{name}' has short value (len={len(value)}, min recommended=16)")

                if 'secure' not in cookie_lower:
                    flags_missing.append('Secure')
                if 'httponly' not in cookie_lower:
                    flags_missing.append('HttpOnly')
                if flags_missing:
                    issues.append(f"Cookie '{name}' missing flags: {', '.join(flags_missing)}")

            if issues:
                return self.create_check(
                    owasp_category='A07',
                    check_name='Session Cookie Security',
                    status='fail',
                    severity='high',
                    description='Session cookie security issues detected.',
                    details='; '.join(issues),
                    remediation=(
                        'Set session cookies with Secure and HttpOnly flags. '
                        'Ensure session IDs are at least 128 bits (16 bytes) of random data. '
                        'Add SameSite=Strict or SameSite=Lax.'
                    ),
                    evidence='; '.join(issues[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A07',
                check_name='Session Cookie Security',
                status='pass',
                severity='high',
                description='Session cookies appear to have adequate security attributes.',
                details=f"Checked {len(session_cookies)} session cookie(s); Secure and HttpOnly present.",
                remediation='Continue using Secure, HttpOnly, and SameSite flags on all session cookies.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A07',
                check_name='Session Cookie Security',
                status='warning',
                severity='high',
                description='Error checking session cookie security.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_mfa_presence(self, url: str) -> dict:
        """Check /login response HTML for MFA keywords."""
        start = time.time()
        base_url = self._get_base_url(url)
        login_paths = ['/login', '/signin', '/admin/login']
        mfa_keywords = [
            r'two.factor', r'2fa', r'mfa', r'multi.factor',
            r'authenticator', r'verification code', r'one.time.password',
            r'otp', r'totp', r'second.factor',
        ]

        try:
            login_url = None
            for path in login_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=8)
                if response and response.status_code == 200:
                    if re.search(r'<input[^>]+type=["\']password["\']',
                                  response.text, re.IGNORECASE):
                        login_url = test_url
                        login_html = response.text
                        break

            if not login_url:
                duration_ms = int((time.time() - start) * 1000)
                return self.create_check(
                    owasp_category='A07',
                    check_name='Multi-Factor Authentication',
                    status='info',
                    severity='medium',
                    description='No login page found to check for MFA.',
                    details=f"Checked: {', '.join(login_paths)}",
                    remediation='Implement MFA on all user and admin authentication flows.',
                    duration_ms=duration_ms,
                )

            mfa_found = []
            for pattern in mfa_keywords:
                if re.search(pattern, login_html, re.IGNORECASE):
                    mfa_found.append(pattern.replace(r'\.', ' ').replace(r'.', ' '))

            duration_ms = int((time.time() - start) * 1000)

            if mfa_found:
                return self.create_check(
                    owasp_category='A07',
                    check_name='Multi-Factor Authentication',
                    status='pass',
                    severity='medium',
                    description='MFA-related keywords found on login page.',
                    details=f"MFA indicators at {login_url}: {', '.join(mfa_found)}",
                    remediation='Ensure MFA is enforced rather than merely available.',
                    evidence=f"MFA keywords: {', '.join(mfa_found)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A07',
                check_name='Multi-Factor Authentication',
                status='warning',
                severity='medium',
                description='No MFA indicators found on login page.',
                details=f"Login page at {login_url} does not appear to mention MFA/2FA.",
                remediation=(
                    'Implement multi-factor authentication for all accounts, '
                    'especially admin and privileged users.'
                ),
                evidence='No MFA/2FA keywords on login page',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A07',
                check_name='Multi-Factor Authentication',
                status='warning',
                severity='medium',
                description='Error checking for MFA presence.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_password_reset(self, url: str) -> dict:
        """Probe /forgot-password and /reset-password for mechanism existence."""
        start = time.time()
        base_url = self._get_base_url(url)
        reset_paths = ['/forgot-password', '/reset-password', '/forgot', '/password-reset',
                       '/account/forgot-password', '/users/password/new']
        found_endpoints = []

        try:
            for path in reset_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=8)
                if response and response.status_code == 200:
                    body = response.text.lower()
                    if any(kw in body for kw in ['email', 'reset', 'forgot', 'password']):
                        found_endpoints.append(path)

            duration_ms = int((time.time() - start) * 1000)

            if found_endpoints:
                return self.create_check(
                    owasp_category='A07',
                    check_name='Password Reset Mechanism',
                    status='info',
                    severity='medium',
                    description='Password reset mechanism found.',
                    details=f"Reset endpoints: {', '.join(found_endpoints)}",
                    remediation=(
                        'Ensure password reset tokens are single-use, expire quickly (≤15 min), '
                        'are securely random, and are delivered only to the registered email.'
                    ),
                    evidence=f"Reset pages: {', '.join(found_endpoints)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A07',
                check_name='Password Reset Mechanism',
                status='info',
                severity='medium',
                description='No password reset page found at common paths.',
                details=f"Checked: {', '.join(reset_paths)}",
                remediation='Ensure a secure password reset mechanism is available.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A07',
                check_name='Password Reset Mechanism',
                status='warning',
                severity='medium',
                description='Error checking password reset mechanism.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A07 Authentication Failures checks', 'info',
                 'a07_start', db_session)

        self.log(scan_id, 'Checking brute force protection', 'info', 'a07_brute', db_session)
        checks.append(self.check_brute_force_protection(target_url))

        self.log(scan_id, 'Checking password in URL', 'info', 'a07_pwd_url', db_session)
        checks.append(self.check_password_in_url(target_url))

        self.log(scan_id, 'Checking session cookie security', 'info', 'a07_session', db_session)
        checks.append(self.check_session_security(target_url))

        self.log(scan_id, 'Checking MFA presence', 'info', 'a07_mfa', db_session)
        checks.append(self.check_mfa_presence(target_url))

        self.log(scan_id, 'Checking password reset mechanism', 'info', 'a07_reset', db_session)
        checks.append(self.check_password_reset(target_url))

        self.log(scan_id, 'Completed A07 Authentication Failures checks', 'info',
                 'a07_done', db_session)
        return checks
