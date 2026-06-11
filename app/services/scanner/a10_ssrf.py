import time
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

from .base import BaseScanner


class A10SSRFScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A10'

    @property
    def name(self) -> str:
        return 'Server-Side Request Forgery (SSRF)'

    @property
    def description(self) -> str:
        return (
            'Checks for SSRF vulnerabilities including URL-like parameters, '
            'open redirect behaviour, webhook callback parameters, '
            'and form fields that may accept URLs for import.'
        )

    def check_url_params(self, url: str) -> dict:
        """Detect URL parameters with SSRF-susceptible names."""
        start = time.time()
        ssrf_param_names = [
            'url', 'uri', 'fetch', 'load', 'src', 'path', 'target',
            'dest', 'destination', 'redirect', 'return', 'link', 'href',
            'callback', 'next', 'goto', 'image', 'img', 'page', 'file',
            'document', 'feed', 'host', 'server', 'endpoint', 'resource',
        ]

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            param_names_lower = {k.lower(): k for k in params.keys()}
            found_params = []

            for ssrf_name in ssrf_param_names:
                if ssrf_name in param_names_lower:
                    original_name = param_names_lower[ssrf_name]
                    value = params[original_name][0] if params[original_name] else ''
                    found_params.append(f"'{original_name}'={value[:40]!r}")

            duration_ms = int((time.time() - start) * 1000)

            if found_params:
                return self.create_check(
                    owasp_category='A10',
                    check_name='SSRF-Susceptible URL Parameters',
                    status='warning',
                    severity='high',
                    description='URL parameters with SSRF-susceptible names detected.',
                    details=f"Susceptible params: {', '.join(found_params)}",
                    remediation=(
                        'Validate and sanitise all URL-like parameter values. '
                        'Use an allowlist of permitted schemes (https only) and domains. '
                        'Block requests to internal/private IP ranges from these parameters.'
                    ),
                    evidence=f"Params: {', '.join(found_params)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A10',
                check_name='SSRF-Susceptible URL Parameters',
                status='info',
                severity='high',
                description='No SSRF-susceptible parameter names detected in URL query string.',
                details=f"Checked {len(ssrf_param_names)} known SSRF param names against URL params.",
                remediation='If URL-accepting parameters are added, implement strict validation.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A10',
                check_name='SSRF-Susceptible URL Parameters',
                status='warning',
                severity='high',
                description='Error checking URL parameters for SSRF.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_open_redirect(self, url: str) -> dict:
        """Test common redirect parameters for open redirect behaviour."""
        start = time.time()
        evil_target = 'https://evil.example.com/ssrf-test'
        redirect_params = ['url', 'next', 'redirect', 'return', 'goto', 'dest',
                            'destination', 'return_to', 'returnUrl', 'callback']

        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)
        found_redirects = []

        try:
            for param_name in redirect_params:
                test_params = dict(base_params)
                test_params[param_name] = [evil_target]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                response = self.make_request(test_url, allow_redirects=False, timeout=8)
                if response is None:
                    continue

                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location', '')
                    if evil_target in location or 'evil.example.com' in location:
                        found_redirects.append(
                            f"Param '{param_name}' redirected to: {location[:80]}"
                        )

            duration_ms = int((time.time() - start) * 1000)

            if found_redirects:
                return self.create_check(
                    owasp_category='A10',
                    check_name='Open Redirect',
                    status='fail',
                    severity='medium',
                    description='Open redirect vulnerability detected.',
                    details='; '.join(found_redirects),
                    remediation=(
                        'Validate redirect URLs against a strict allowlist of permitted destinations. '
                        'Never redirect to user-supplied URLs without validation. '
                        'Use relative paths for internal redirects.'
                    ),
                    evidence='; '.join(found_redirects[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A10',
                check_name='Open Redirect',
                status='pass',
                severity='medium',
                description='No open redirect behaviour detected from tested parameters.',
                details=f"Tested {len(redirect_params)} redirect parameter names; none redirected to evil URL.",
                remediation='Validate all redirect URLs against a strict allowlist.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A10',
                check_name='Open Redirect',
                status='warning',
                severity='medium',
                description='Error during open redirect check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_webhook_params(self, url: str) -> dict:
        """Detect query parameters named after webhook/callback patterns."""
        start = time.time()
        webhook_param_names = [
            'webhook', 'callback', 'notify', 'ping', 'hook',
            'notification_url', 'notify_url', 'callback_url',
            'webhook_url', 'hook_url', 'event_url',
        ]

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            param_names_lower = {k.lower(): k for k in params.keys()}

            found_webhook_params = []
            for wh_name in webhook_param_names:
                if wh_name in param_names_lower:
                    original_name = param_names_lower[wh_name]
                    value = params[original_name][0] if params[original_name] else ''
                    found_webhook_params.append(f"'{original_name}'={value[:40]!r}")

            duration_ms = int((time.time() - start) * 1000)

            if found_webhook_params:
                return self.create_check(
                    owasp_category='A10',
                    check_name='Webhook/Callback Parameters',
                    status='warning',
                    severity='high',
                    description='Webhook or callback URL parameters detected.',
                    details=f"Webhook params: {', '.join(found_webhook_params)}",
                    remediation=(
                        'Validate webhook/callback URLs against an allowlist of permitted endpoints. '
                        'Require authentication for webhook registration. '
                        'Block internal/private IP ranges in webhook destinations.'
                    ),
                    evidence=f"Webhook params: {', '.join(found_webhook_params)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A10',
                check_name='Webhook/Callback Parameters',
                status='info',
                severity='high',
                description='No webhook or callback parameters detected in URL.',
                details=f"Checked {len(webhook_param_names)} webhook parameter name patterns.",
                remediation='If webhook functionality is added, validate destinations strictly.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A10',
                check_name='Webhook/Callback Parameters',
                status='warning',
                severity='high',
                description='Error checking for webhook parameters.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_import_by_url(self, url: str) -> dict:
        """Look for form inputs that may accept URLs for import functionality."""
        start = time.time()
        url_input_patterns = [
            r'<input[^>]+name=["\'](?:url|link|import|fetch|src|uri|source|feed)["\'][^>]*>',
            r'<input[^>]+placeholder=["\'][^"\']*(?:url|http|https|link)[^"\']*["\'][^>]*>',
            r'<input[^>]+id=["\'](?:url|link|import|fetch|src|uri|source|feed)["\'][^>]*>',
            r'import.{0,30}(?:url|link)',
            r'fetch.{0,20}(?:url|link)',
            r'load.{0,20}from.{0,20}url',
            r'<input[^>]+type=["\']url["\'][^>]*>',
        ]

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A10',
                    check_name='URL Import Functionality',
                    status='warning',
                    severity='medium',
                    description='Could not retrieve page to check for URL import inputs.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            html = response.text
            found_inputs = []
            for pattern in url_input_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches[:3]:
                    found_inputs.append(match[:100])

            if found_inputs:
                return self.create_check(
                    owasp_category='A10',
                    check_name='URL Import Functionality',
                    status='warning',
                    severity='medium',
                    description='Form input(s) that may accept URLs for import detected.',
                    details='Found inputs: ' + '; '.join(found_inputs[:5]),
                    remediation=(
                        'Validate any user-supplied URLs before fetching. '
                        'Use an allowlist of permitted schemes and domains. '
                        'Block requests to internal IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x). '
                        'Do not follow redirects to internal resources.'
                    ),
                    evidence='; '.join(found_inputs[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A10',
                check_name='URL Import Functionality',
                status='info',
                severity='medium',
                description='No URL import form inputs detected on the page.',
                details='No input fields matching URL import patterns found in page HTML.',
                remediation='If URL import features are added, validate destinations against an allowlist.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A10',
                check_name='URL Import Functionality',
                status='warning',
                severity='medium',
                description='Error checking for URL import functionality.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A10 SSRF checks', 'info', 'a10_start', db_session)

        self.log(scan_id, 'Checking SSRF-susceptible URL parameters', 'info', 'a10_params', db_session)
        checks.append(self.check_url_params(target_url))

        self.log(scan_id, 'Checking for open redirect', 'info', 'a10_redirect', db_session)
        checks.append(self.check_open_redirect(target_url))

        self.log(scan_id, 'Checking webhook/callback parameters', 'info', 'a10_webhook', db_session)
        checks.append(self.check_webhook_params(target_url))

        self.log(scan_id, 'Checking URL import functionality', 'info', 'a10_import', db_session)
        checks.append(self.check_import_by_url(target_url))

        self.log(scan_id, 'Completed A10 SSRF checks', 'info', 'a10_done', db_session)
        return checks
