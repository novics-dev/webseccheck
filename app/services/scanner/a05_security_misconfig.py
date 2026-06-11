import time
import re
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


class A05SecurityMisconfigScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A05'

    @property
    def name(self) -> str:
        return 'Security Misconfiguration'

    @property
    def description(self) -> str:
        return (
            'Audits for security misconfigurations including missing security headers, '
            'server version disclosure, exposed default files, TRACE method, '
            'directory listing, and permissive CORS policies.'
        )

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def check_security_headers(self, url: str) -> dict:
        """Audit critical security response headers."""
        start = time.time()
        required_headers = {
            'X-Content-Type-Options': {
                'expected': 'nosniff',
                'description': 'Prevents MIME-type sniffing',
                'severity': 'medium',
            },
            'X-Frame-Options': {
                'expected': ['DENY', 'SAMEORIGIN'],
                'description': 'Prevents clickjacking',
                'severity': 'medium',
            },
            'Content-Security-Policy': {
                'expected': None,
                'description': 'Restricts resource loading to prevent XSS',
                'severity': 'high',
            },
            'Referrer-Policy': {
                'expected': None,
                'description': 'Controls referrer information leakage',
                'severity': 'low',
            },
            'Permissions-Policy': {
                'expected': None,
                'description': 'Controls browser feature access',
                'severity': 'low',
            },
        }

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Security Headers',
                    status='error',
                    severity='high',
                    description='Could not retrieve response to check security headers.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            missing = []
            misconfigured = []
            present = []

            for header_name, config in required_headers.items():
                value = response.headers.get(header_name, '')
                if not value:
                    missing.append(f"{header_name} ({config['description']})")
                else:
                    expected = config['expected']
                    if expected is None:
                        present.append(f"{header_name}: {value[:60]}")
                    elif isinstance(expected, list):
                        if value.upper() not in [e.upper() for e in expected]:
                            misconfigured.append(
                                f"{header_name}='{value}' (expected one of: {', '.join(expected)})"
                            )
                        else:
                            present.append(f"{header_name}: {value}")
                    else:
                        if value.lower() != expected.lower():
                            misconfigured.append(
                                f"{header_name}='{value}' (expected: {expected})"
                            )
                        else:
                            present.append(f"{header_name}: {value}")

            issues = missing + misconfigured
            if issues:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Security Headers',
                    status='fail',
                    severity='high',
                    description=f"{len(missing)} missing and {len(misconfigured)} misconfigured security header(s).",
                    details='Missing: ' + '; '.join(missing) + ' | Misconfigured: ' + '; '.join(misconfigured),
                    remediation=(
                        'Add all missing security headers to your server or application configuration. '
                        'Recommended: X-Content-Type-Options: nosniff; '
                        'X-Frame-Options: DENY; Content-Security-Policy: <policy>; '
                        'Referrer-Policy: no-referrer; Permissions-Policy: <policy>'
                    ),
                    evidence='Missing: ' + ', '.join(missing[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05',
                check_name='Security Headers',
                status='pass',
                severity='high',
                description='All audited security headers are present.',
                details='; '.join(present),
                remediation='Review CSP policy for tightness; avoid unsafe-inline/unsafe-eval.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A05',
                check_name='Security Headers',
                status='error',
                severity='high',
                description='Error checking security headers.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_server_disclosure(self, url: str) -> dict:
        """Check for server version and technology disclosure in headers."""
        start = time.time()
        disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version',
                               'X-AspNetMvc-Version', 'X-Generator']
        version_pattern = re.compile(r'\d+\.\d+')

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Server Version Disclosure',
                    status='error',
                    severity='low',
                    description='Could not retrieve response to check server disclosure.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            disclosures = []
            for header_name in disclosure_headers:
                value = response.headers.get(header_name, '')
                if value:
                    disclosures.append(f"{header_name}: {value}")

            version_disclosures = [d for d in disclosures if version_pattern.search(d)]

            if version_disclosures:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Server Version Disclosure',
                    status='fail',
                    severity='low',
                    description='Server is disclosing version information in HTTP headers.',
                    details='; '.join(disclosures),
                    remediation=(
                        'Remove or suppress Server, X-Powered-By, and framework version headers. '
                        'In Apache: ServerTokens Prod. In nginx: server_tokens off. '
                        'In IIS: remove X-Powered-By and X-AspNet-Version headers.'
                    ),
                    evidence='; '.join(version_disclosures),
                    duration_ms=duration_ms,
                )
            elif disclosures:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Server Version Disclosure',
                    status='warning',
                    severity='low',
                    description='Server technology disclosed but no version numbers found.',
                    details='; '.join(disclosures),
                    remediation='Remove Server and X-Powered-By headers to minimise information disclosure.',
                    evidence='; '.join(disclosures),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05',
                check_name='Server Version Disclosure',
                status='pass',
                severity='low',
                description='No server version or technology information disclosed in headers.',
                details='Server, X-Powered-By and related headers are absent or suppressed.',
                remediation='Continue suppressing server version information.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A05',
                check_name='Server Version Disclosure',
                status='error',
                severity='low',
                description='Error checking server disclosure.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_default_files(self, url: str) -> dict:
        """Probe for default/sensitive files that should not be publicly accessible."""
        start = time.time()
        sensitive_paths = [
            '/.git/HEAD', '/.svn/entries', '/robots.txt', '/sitemap.xml',
            '/.env', '/web.config', '/phpinfo.php', '/crossdomain.xml',
            '/.htaccess', '/.htpasswd', '/wp-config.php', '/config.php',
        ]
        base_url = self._get_base_url(url)
        exposed = []
        informational = []

        try:
            for path in sensitive_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=8)
                if response is None or response.status_code != 200:
                    continue
                body = response.text[:500]
                path_lower = path.lower()
                if any(s in path_lower for s in ['.git', '.env', '.htpasswd', 'wp-config',
                                                   'config.php', 'phpinfo', '.svn', 'web.config']):
                    exposed.append(f"{path} (HTTP 200, {len(response.text)} bytes)")
                elif path in ['/robots.txt', '/sitemap.xml', '/crossdomain.xml']:
                    informational.append(f"{path} accessible (HTTP 200)")

            duration_ms = int((time.time() - start) * 1000)

            if exposed:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Default/Sensitive Files Exposed',
                    status='fail',
                    severity='high',
                    description='Sensitive default files are publicly accessible.',
                    details='Exposed files: ' + '; '.join(exposed),
                    remediation=(
                        'Remove or restrict access to .git/, .env, web.config, phpinfo.php, '
                        'wp-config.php, and other sensitive files. '
                        'Configure your web server to deny access to these paths.'
                    ),
                    evidence='Exposed: ' + ', '.join(exposed[:3]),
                    duration_ms=duration_ms,
                )
            elif informational:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Default/Sensitive Files Exposed',
                    status='info',
                    severity='low',
                    description='Standard files accessible (robots.txt / sitemap.xml).',
                    details='; '.join(informational),
                    remediation='Review robots.txt for information disclosure about hidden paths.',
                    evidence='; '.join(informational),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05',
                check_name='Default/Sensitive Files Exposed',
                status='pass',
                severity='high',
                description='No sensitive default files found accessible.',
                details=f"Tested {len(sensitive_paths)} common sensitive paths.",
                remediation='Continue restricting access to configuration and source control files.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A05',
                check_name='Default/Sensitive Files Exposed',
                status='error',
                severity='high',
                description='Error checking for default/sensitive files.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_http_trace(self, url: str) -> dict:
        """Check if TRACE HTTP method is enabled."""
        start = time.time()
        try:
            response = self.make_request(url, method='TRACE', timeout=8)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A05',
                    check_name='HTTP TRACE Method',
                    status='error',
                    severity='low',
                    description='Could not connect to check TRACE method.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            if response.status_code == 200 and ('TRACE' in response.text.upper() or
                                                  'User-Agent' in response.text):
                return self.create_check(
                    owasp_category='A05',
                    check_name='HTTP TRACE Method',
                    status='fail',
                    severity='low',
                    description='HTTP TRACE method is enabled.',
                    details=f"TRACE returned HTTP 200 and echoed request content.",
                    remediation=(
                        'Disable the TRACE method in your web server configuration. '
                        'In Apache: TraceEnable Off. In nginx: add "if ($request_method = TRACE)" block.'
                    ),
                    evidence=f"TRACE HTTP {response.status_code}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05',
                check_name='HTTP TRACE Method',
                status='pass',
                severity='low',
                description='HTTP TRACE method does not appear to be enabled.',
                details=f"TRACE returned HTTP {response.status_code}.",
                remediation='Continue disabling TRACE in your web server configuration.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A05',
                check_name='HTTP TRACE Method',
                status='error',
                severity='low',
                description='Error checking HTTP TRACE method.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_directory_listing(self, url: str) -> dict:
        """Check for directory listing in the response."""
        start = time.time()
        listing_patterns = [
            r'Index of /',
            r'<title>Index of',
            r'Directory listing for',
            r'<h1>Directory Listing',
            r'Parent Directory</a>',
        ]

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A05',
                    check_name='Directory Listing',
                    status='error',
                    severity='medium',
                    description='Could not retrieve response to check directory listing.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            body = response.text
            for pattern in listing_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return self.create_check(
                        owasp_category='A05',
                        check_name='Directory Listing',
                        status='fail',
                        severity='medium',
                        description='Directory listing is enabled.',
                        details=f"Pattern '{pattern}' found in response body.",
                        remediation=(
                            'Disable directory listing in your web server. '
                            'In Apache: Options -Indexes. In nginx: autoindex off.'
                        ),
                        evidence=f"Directory listing indicator: {pattern}",
                        duration_ms=duration_ms,
                    )

            return self.create_check(
                owasp_category='A05',
                check_name='Directory Listing',
                status='pass',
                severity='medium',
                description='Directory listing does not appear to be enabled.',
                details='No directory listing patterns found in response.',
                remediation='Ensure directory listing (autoindex) is disabled across all directories.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A05',
                check_name='Directory Listing',
                status='error',
                severity='medium',
                description='Error checking for directory listing.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_cors(self, url: str) -> dict:
        """Check CORS policy by sending a malicious Origin header."""
        start = time.time()
        evil_origin = 'https://evil-attacker.com'

        try:
            response = self.make_request(
                url,
                headers={'Origin': evil_origin},
                timeout=10,
            )
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A05',
                    check_name='CORS Policy',
                    status='error',
                    severity='high',
                    description='Could not retrieve response to check CORS.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                severity = 'medium'
                if acac.lower() == 'true':
                    severity = 'high'
                return self.create_check(
                    owasp_category='A05',
                    check_name='CORS Policy',
                    status='fail',
                    severity=severity,
                    description='CORS policy allows all origins (Access-Control-Allow-Origin: *).',
                    details=f"ACAO: {acao}; ACAC: {acac or 'not set'}",
                    remediation=(
                        'Restrict Access-Control-Allow-Origin to specific trusted domains. '
                        'Never use * with Access-Control-Allow-Credentials: true.'
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    duration_ms=duration_ms,
                )

            if acao == evil_origin:
                return self.create_check(
                    owasp_category='A05',
                    check_name='CORS Policy',
                    status='fail',
                    severity='high',
                    description='CORS policy reflects arbitrary Origin header.',
                    details=f"Server echoed evil origin: {acao}; Credentials: {acac or 'not set'}",
                    remediation=(
                        'Validate Origin against a strict allowlist. '
                        'Do not reflect arbitrary Origin values in Access-Control-Allow-Origin.'
                    ),
                    evidence=f"Reflected origin: {acao}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05',
                check_name='CORS Policy',
                status='pass',
                severity='high',
                description='CORS policy does not reflect arbitrary origins.',
                details=f"Access-Control-Allow-Origin: {acao or 'not set'}",
                remediation='Continue using a strict Origin allowlist for CORS.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A05',
                check_name='CORS Policy',
                status='error',
                severity='high',
                description='Error checking CORS policy.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A05 Security Misconfiguration checks', 'info',
                 'a05_start', db_session)

        self.log(scan_id, 'Checking security headers', 'info', 'a05_headers', db_session)
        checks.append(self.check_security_headers(target_url))

        self.log(scan_id, 'Checking server disclosure', 'info', 'a05_server', db_session)
        checks.append(self.check_server_disclosure(target_url))

        self.log(scan_id, 'Checking default/sensitive files', 'info', 'a05_files', db_session)
        checks.append(self.check_default_files(target_url))

        self.log(scan_id, 'Checking HTTP TRACE method', 'info', 'a05_trace', db_session)
        checks.append(self.check_http_trace(target_url))

        self.log(scan_id, 'Checking directory listing', 'info', 'a05_dirlist', db_session)
        checks.append(self.check_directory_listing(target_url))

        self.log(scan_id, 'Checking CORS policy', 'info', 'a05_cors', db_session)
        checks.append(self.check_cors(target_url))

        self.log(scan_id, 'Completed A05 Security Misconfiguration checks', 'info',
                 'a05_done', db_session)
        return checks
