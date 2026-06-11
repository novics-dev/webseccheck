"""
A02 — Cryptographic Failures scanner.
"""

from __future__ import annotations

import re
import ssl
import socket
import time
from urllib.parse import urlparse, parse_qs, urlunparse

from app.services.scanner.base import BaseScanner


class A02CryptoScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A02'

    @property
    def name(self) -> str:
        return 'Cryptographic Failures'

    @property
    def description(self) -> str:
        return (
            'Checks for cryptographic weaknesses including missing HTTPS enforcement, '
            'weak HSTS configuration, outdated TLS versions, insecure cookie flags, '
            'mixed content, and sensitive data in URLs.'
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_https_enforcement(self, url: str) -> dict:
        """Check if HTTP redirects to HTTPS."""
        start = time.time()
        try:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                http_url = urlunparse(parsed._replace(scheme='http'))
            else:
                http_url = url

            response = self.make_request(http_url, allow_redirects=False, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A02',
                    check_name='HTTPS Enforcement',
                    status='warning',
                    severity='high',
                    description='Could not connect via HTTP to check redirect.',
                    details='No response from HTTP endpoint.',
                    remediation='Ensure HTTP traffic is redirected to HTTPS.',
                    duration_ms=duration_ms,
                )

            if response.status_code in (301, 302, 307, 308):
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    return self.create_check(
                        owasp_category='A02',
                        check_name='HTTPS Enforcement',
                        status='pass',
                        severity='high',
                        description='HTTP correctly redirects to HTTPS.',
                        details=f'HTTP {response.status_code} redirect to: {location}',
                        remediation='Continue enforcing HTTPS via HTTP-to-HTTPS redirect.',
                        evidence=f'Redirect: {http_url} -> {location}',
                        duration_ms=duration_ms,
                    )

            return self.create_check(
                owasp_category='A02',
                check_name='HTTPS Enforcement',
                status='fail',
                severity='high',
                description='HTTP does not redirect to HTTPS.',
                details=f'HTTP request returned status {response.status_code} without HTTPS redirect.',
                remediation=(
                    'Configure your web server to redirect all HTTP traffic to HTTPS '
                    'using a 301 permanent redirect.'
                ),
                evidence=f'HTTP {response.status_code} with no HTTPS redirect',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A02',
                check_name='HTTPS Enforcement',
                status='info',
                severity='high',
                description='Error checking HTTPS enforcement.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_hsts_header(self, url: str) -> dict:
        """Check Strict-Transport-Security header and validate max-age."""
        start = time.time()
        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A02',
                    check_name='HTTP Strict Transport Security (HSTS)',
                    status='info',
                    severity='medium',
                    description='Could not retrieve response to check HSTS.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            hsts = response.headers.get('Strict-Transport-Security', '')
            if not hsts:
                return self.create_check(
                    owasp_category='A02',
                    check_name='HTTP Strict Transport Security (HSTS)',
                    status='fail',
                    severity='medium',
                    description='Strict-Transport-Security header is missing.',
                    details='The server does not send an HSTS header.',
                    remediation='Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    evidence='Header absent',
                    duration_ms=duration_ms,
                )

            max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
            max_age = int(max_age_match.group(1)) if max_age_match else 0

            if max_age < 31536000:
                return self.create_check(
                    owasp_category='A02',
                    check_name='HTTP Strict Transport Security (HSTS)',
                    status='warning',
                    severity='medium',
                    description=f'HSTS max-age is too short: {max_age} seconds (minimum: 31536000).',
                    details=f'HSTS header value: {hsts}',
                    remediation='Set max-age to at least 31536000 (1 year). Add includeSubDomains and preload.',
                    evidence=f'max-age={max_age}',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A02',
                check_name='HTTP Strict Transport Security (HSTS)',
                status='pass',
                severity='medium',
                description='HSTS header present with adequate max-age.',
                details=f'Strict-Transport-Security: {hsts}',
                evidence=f'max-age={max_age}',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A02',
                check_name='HTTP Strict Transport Security (HSTS)',
                status='info',
                severity='medium',
                description='Error checking HSTS header.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_ssl_tls_protocol(self, url: str) -> dict:
        """Check TLS version, detect TLS 1.0/1.1 support."""
        start = time.time()
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            if parsed.scheme != 'https':
                duration_ms = int((time.time() - start) * 1000)
                return self.create_check(
                    owasp_category='A02',
                    check_name='TLS/SSL Configuration',
                    status='fail',
                    severity='high',
                    description='Site does not use HTTPS; TLS is not in use at all.',
                    details='URL scheme is HTTP, not HTTPS.',
                    remediation='Migrate the application to HTTPS with a valid TLS certificate.',
                    evidence='Scheme: http',
                    duration_ms=duration_ms,
                )

            weak_protocols = []
            supported_version = None

            for proto_name, min_ver, max_ver in [
                ('TLSv1.0', ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
                ('TLSv1.1', ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            ]:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = min_ver
                    ctx.maximum_version = max_ver
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=hostname):
                            weak_protocols.append(proto_name)
                except (ssl.SSLError, OSError, AttributeError):
                    pass

            # Get negotiated TLS version
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported_version = ssock.version()
            except Exception:
                supported_version = 'Unknown'

            duration_ms = int((time.time() - start) * 1000)

            if weak_protocols:
                return self.create_check(
                    owasp_category='A02',
                    check_name='TLS/SSL Configuration',
                    status='fail',
                    severity='high',
                    description=f"Weak TLS versions supported: {', '.join(weak_protocols)}",
                    details=f"Weak protocols: {', '.join(weak_protocols)}. Negotiated: {supported_version}",
                    remediation=(
                        'Disable TLS 1.0 and TLS 1.1. Support only TLS 1.2 and TLS 1.3. '
                        'Update your server TLS configuration accordingly.'
                    ),
                    evidence=f"Supported weak protocols: {', '.join(weak_protocols)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A02',
                check_name='TLS/SSL Configuration',
                status='pass',
                severity='high',
                description='TLS configuration acceptable; no weak protocol versions detected.',
                details=f'Negotiated TLS version: {supported_version}',
                evidence=f'Negotiated: {supported_version}',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A02',
                check_name='TLS/SSL Configuration',
                status='info',
                severity='high',
                description='Error checking TLS/SSL configuration.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_cookie_security(self, url: str) -> dict:
        """Check Set-Cookie headers for Secure, HttpOnly, SameSite flags."""
        start = time.time()
        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A02',
                    check_name='Cookie Security Flags',
                    status='info',
                    severity='medium',
                    description='Could not retrieve response to check cookies.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            # Collect all Set-Cookie header values (requests only exposes the last one
            # via response.headers; use raw to get all)
            set_cookie_headers = []
            if hasattr(response.raw, 'headers'):
                raw_headers = response.raw.headers
                if hasattr(raw_headers, 'getlist'):
                    set_cookie_headers = raw_headers.getlist('Set-Cookie')
            if not set_cookie_headers:
                for key, value in response.headers.items():
                    if key.lower() == 'set-cookie':
                        set_cookie_headers.append(value)

            if not set_cookie_headers:
                return self.create_check(
                    owasp_category='A02',
                    check_name='Cookie Security Flags',
                    status='info',
                    severity='medium',
                    description='No Set-Cookie headers found in response.',
                    details='The endpoint did not set any cookies.',
                    remediation='When setting cookies, always include Secure, HttpOnly, and SameSite=Strict flags.',
                    duration_ms=duration_ms,
                )

            issues = []
            for cookie_header in set_cookie_headers:
                cookie_lower = cookie_header.lower()
                name_match = re.match(r'([^=;]+)=', cookie_header)
                cookie_name = name_match.group(1).strip() if name_match else 'unknown'

                missing = []
                if 'secure' not in cookie_lower:
                    missing.append('Secure')
                if 'httponly' not in cookie_lower:
                    missing.append('HttpOnly')
                if 'samesite' not in cookie_lower:
                    missing.append('SameSite')

                if missing:
                    issues.append(f"Cookie '{cookie_name}' missing: {', '.join(missing)}")

            if issues:
                return self.create_check(
                    owasp_category='A02',
                    check_name='Cookie Security Flags',
                    status='fail',
                    severity='medium',
                    description='Cookies are missing security flags.',
                    details='; '.join(issues),
                    remediation=(
                        'Set all cookies with Secure, HttpOnly, and SameSite=Strict (or Lax) flags. '
                        'Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict'
                    ),
                    evidence='; '.join(issues),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A02',
                check_name='Cookie Security Flags',
                status='pass',
                severity='medium',
                description='All cookies have required security flags.',
                details=f'Checked {len(set_cookie_headers)} cookie(s); all have Secure, HttpOnly, SameSite.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A02',
                check_name='Cookie Security Flags',
                status='info',
                severity='medium',
                description='Error checking cookie security flags.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_sensitive_data_in_url(self, url: str) -> dict:
        """Detect sensitive data (password, token, key, secret) in URL query params."""
        start = time.time()
        try:
            parsed = urlparse(url)
            query = parsed.query.lower()
            sensitive_keywords = [
                'password', 'passwd', 'pwd', 'token', 'secret', 'key',
                'apikey', 'api_key', 'auth', 'credential', 'private', 'pass',
            ]
            found = []

            for keyword in sensitive_keywords:
                pattern = rf'(?:^|&){re.escape(keyword)}[^&]*'
                if re.search(pattern, query):
                    found.append(keyword)

            duration_ms = int((time.time() - start) * 1000)

            if found:
                return self.create_check(
                    owasp_category='A02',
                    check_name='Sensitive Data in URL',
                    status='fail',
                    severity='high',
                    description='Sensitive parameters detected in URL query string.',
                    details=f"Sensitive parameters found: {', '.join(found)}",
                    remediation=(
                        'Never transmit passwords, tokens, or secrets in URL query parameters. '
                        'Use POST body or Authorization headers instead.'
                    ),
                    evidence=f"URL contains: {', '.join(found)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A02',
                check_name='Sensitive Data in URL',
                status='pass',
                severity='high',
                description='No sensitive data keywords detected in URL query parameters.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A02',
                check_name='Sensitive Data in URL',
                status='info',
                severity='high',
                description='Error checking for sensitive data in URL.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_mixed_content(self, url: str) -> dict:
        """Parse HTML for http:// resources on an https page."""
        start = time.time()
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                duration_ms = int((time.time() - start) * 1000)
                return self.create_check(
                    owasp_category='A02',
                    check_name='Mixed Content',
                    status='info',
                    severity='medium',
                    description='Mixed content check only applies to HTTPS pages.',
                    details='Target URL is not HTTPS.',
                    duration_ms=duration_ms,
                )

            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A02',
                    check_name='Mixed Content',
                    status='info',
                    severity='medium',
                    description='Could not retrieve page to check for mixed content.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            html = response.text
            mixed = []

            patterns = [
                (r'src=["\']http://[^"\']+["\']', 'src'),
                (r'href=["\']http://[^"\']+["\']', 'href'),
                (r'action=["\']http://[^"\']+["\']', 'action'),
            ]

            for pattern, attr_type in patterns:
                for m in re.findall(pattern, html, re.IGNORECASE)[:5]:
                    mixed.append(f'{attr_type}: {m[:80]}')

            if mixed:
                return self.create_check(
                    owasp_category='A02',
                    check_name='Mixed Content',
                    status='fail',
                    severity='medium',
                    description='Mixed content detected: HTTP resources loaded on HTTPS page.',
                    details='; '.join(mixed),
                    remediation=(
                        'Replace all HTTP resource URLs with HTTPS equivalents. '
                        'Use protocol-relative URLs (//) or enforce HTTPS for all sub-resources.'
                    ),
                    evidence='; '.join(mixed[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A02',
                check_name='Mixed Content',
                status='pass',
                severity='medium',
                description='No obvious mixed content found.',
                details='No HTTP resources detected in src/href/action attributes on HTTPS page.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A02',
                check_name='Mixed Content',
                status='info',
                severity='medium',
                description='Error checking for mixed content.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A02 Cryptographic Failures checks', 'info', 'a02_start', db_session)

        self.log(scan_id, 'Checking HTTPS enforcement', 'info', 'a02_https', db_session)
        checks.append(self.check_https_enforcement(target_url))

        self.log(scan_id, 'Checking HSTS header', 'info', 'a02_hsts', db_session)
        checks.append(self.check_hsts_header(target_url))

        self.log(scan_id, 'Checking TLS/SSL configuration', 'info', 'a02_tls', db_session)
        checks.append(self.check_ssl_tls_protocol(target_url))

        self.log(scan_id, 'Checking cookie security flags', 'info', 'a02_cookies', db_session)
        checks.append(self.check_cookie_security(target_url))

        self.log(scan_id, 'Checking for sensitive data in URL', 'info', 'a02_sensitive_url', db_session)
        checks.append(self.check_sensitive_data_in_url(target_url))

        self.log(scan_id, 'Checking for mixed content', 'info', 'a02_mixed', db_session)
        checks.append(self.check_mixed_content(target_url))

        self.log(scan_id, 'Completed A02 Cryptographic Failures checks', 'info', 'a02_done', db_session)
        return checks
