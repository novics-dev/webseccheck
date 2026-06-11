import time
import re
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


class A06ComponentsScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A06'

    @property
    def name(self) -> str:
        return 'Vulnerable and Outdated Components'

    @property
    def description(self) -> str:
        return (
            'Detects known JavaScript libraries, CMS platforms, framework versions, '
            'and outdated server banners that may indicate the use of vulnerable components.'
        )

    def check_js_libraries(self, url: str) -> dict:
        """Parse HTML for JavaScript library versions."""
        start = time.time()
        findings = []
        warnings = []

        js_patterns = [
            # jQuery
            (r'jquery[.-](\d+\.\d+[\.\d]*)(\.min)?\.js', 'jQuery', '3.0'),
            (r'jquery/(\d+\.\d+[\.\d]*)/jquery', 'jQuery', '3.0'),
            # Angular
            (r'angular(?:js)?[/.-](\d+\.\d+[\.\d]*)', 'AngularJS/Angular', '8.0'),
            # React
            (r'react[/.-](\d+\.\d+[\.\d]*)', 'React', '16.0'),
            # Vue
            (r'vue[/.-](\d+\.\d+[\.\d]*)', 'Vue.js', '3.0'),
            # Bootstrap
            (r'bootstrap[/.-](\d+\.\d+[\.\d]*)', 'Bootstrap', '5.0'),
            # Lodash
            (r'lodash[/.-](\d+\.\d+[\.\d]*)', 'Lodash', '4.0'),
            # Moment.js
            (r'moment[/.-](\d+\.\d+[\.\d]*)', 'Moment.js', None),
        ]

        # Inline version markers
        inline_patterns = [
            (r'jQuery\s+v?(\d+\.\d+[\.\d]*)', 'jQuery', '3.0'),
            (r'React\s+v?(\d+\.\d+[\.\d]*)', 'React', '16.0'),
            (r'angular:\s*["\'](\d+\.\d+[\.\d]*)', 'Angular', '8.0'),
            (r'Vue\.version\s*=\s*["\'](\d+\.\d+[\.\d]*)', 'Vue.js', '3.0'),
        ]

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='JavaScript Library Versions',
                    status='error',
                    severity='medium',
                    description='Could not retrieve page to check JS libraries.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            html = response.text

            for pattern, lib_name, min_version in js_patterns + inline_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    version = match if isinstance(match, str) else match
                    findings.append(f"{lib_name} v{version}")
                    if min_version:
                        try:
                            ver_parts = [int(x) for x in version.split('.')[:2]]
                            min_parts = [int(x) for x in min_version.split('.')[:2]]
                            if ver_parts < min_parts:
                                warnings.append(
                                    f"{lib_name} v{version} is outdated (recommend >= {min_version})"
                                )
                        except (ValueError, IndexError):
                            pass

            if warnings:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='JavaScript Library Versions',
                    status='fail',
                    severity='medium',
                    description='Outdated JavaScript libraries detected.',
                    details='Outdated: ' + '; '.join(warnings) + ' | All found: ' + '; '.join(findings),
                    remediation=(
                        'Update JavaScript libraries to their latest stable versions. '
                        'Use a dependency management tool and monitor for CVEs.'
                    ),
                    evidence='; '.join(warnings[:3]),
                    duration_ms=duration_ms,
                )
            elif findings:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='JavaScript Library Versions',
                    status='info',
                    severity='medium',
                    description='JavaScript libraries detected; versions appear current.',
                    details='; '.join(findings),
                    remediation='Continue monitoring library versions against known CVEs.',
                    evidence='; '.join(findings),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A06:2021',
                check_name='JavaScript Library Versions',
                status='info',
                severity='medium',
                description='No recognisable JavaScript library version strings found in page source.',
                details='Library detection relies on filename/inline version patterns.',
                remediation='Subresource Integrity (SRI) and regular dependency audits are recommended.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A06:2021',
                check_name='JavaScript Library Versions',
                status='error',
                severity='medium',
                description='Error checking JavaScript libraries.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_cms_detection(self, url: str) -> dict:
        """Detect common CMS platforms from HTML and headers."""
        start = time.time()
        cms_signatures = {
            'WordPress': [
                r'wp-content', r'wp-includes', r'/wp-json/', r'wordpress',
                r'<meta name=["\']generator["\'] content=["\']WordPress',
            ],
            'Drupal': [
                r'sites/all/', r'Drupal\.settings', r'/sites/default/',
                r'<meta name=["\']generator["\'] content=["\']Drupal',
                r'drupal\.js',
            ],
            'Joomla': [
                r'/administrator/', r'com_content', r'Joomla!',
                r'<meta name=["\']generator["\'] content=["\']Joomla',
            ],
            'Magento': [
                r'Mage\.Cookies', r'/skin/frontend/', r'magento',
            ],
            'Shopify': [
                r'cdn\.shopify\.com', r'Shopify\.theme',
            ],
        }

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='CMS Detection',
                    status='error',
                    severity='low',
                    description='Could not retrieve page for CMS detection.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            html = response.text
            generator = response.headers.get('X-Generator', '')
            detected_cms = []

            for cms_name, patterns in cms_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.IGNORECASE) or re.search(pattern, generator, re.IGNORECASE):
                        detected_cms.append(cms_name)
                        break

            if detected_cms:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='CMS Detection',
                    status='info',
                    severity='low',
                    description=f"CMS platform(s) detected: {', '.join(detected_cms)}",
                    details=f"Detected: {', '.join(detected_cms)}. Ensure CMS and plugins are fully updated.",
                    remediation=(
                        'Keep CMS core and all plugins/themes updated. '
                        'Remove unused plugins. Subscribe to CMS security advisories.'
                    ),
                    evidence=f"CMS detected: {', '.join(detected_cms)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A06:2021',
                check_name='CMS Detection',
                status='info',
                severity='low',
                description='No common CMS platform detected.',
                details='WordPress, Drupal, Joomla, Magento, Shopify signatures not found.',
                remediation='If using a CMS, ensure it and its components are kept up to date.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A06:2021',
                check_name='CMS Detection',
                status='error',
                severity='low',
                description='Error during CMS detection.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_framework_version(self, url: str) -> dict:
        """Check headers that disclose framework and version information."""
        start = time.time()
        version_headers = [
            'X-Powered-By', 'X-Generator', 'X-AspNet-Version',
            'X-AspNetMvc-Version', 'X-Drupal-Cache', 'X-Joomla-Version',
        ]
        version_pattern = re.compile(r'\d+\.\d+')

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='Framework Version Disclosure',
                    status='error',
                    severity='medium',
                    description='Could not retrieve response to check framework versions.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            found_versions = []
            for header_name in version_headers:
                value = response.headers.get(header_name, '')
                if value and version_pattern.search(value):
                    found_versions.append(f"{header_name}: {value}")

            if found_versions:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='Framework Version Disclosure',
                    status='fail',
                    severity='medium',
                    description='Framework or runtime version information disclosed in HTTP headers.',
                    details='; '.join(found_versions),
                    remediation=(
                        'Remove or suppress framework version headers. '
                        'These disclosures assist attackers in targeting known CVEs.'
                    ),
                    evidence='; '.join(found_versions),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A06:2021',
                check_name='Framework Version Disclosure',
                status='pass',
                severity='medium',
                description='No framework version numbers found in HTTP headers.',
                details=f"Checked: {', '.join(version_headers)}",
                remediation='Continue suppressing version information from HTTP response headers.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A06:2021',
                check_name='Framework Version Disclosure',
                status='error',
                severity='medium',
                description='Error checking framework version disclosure.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_outdated_headers(self, url: str) -> dict:
        """Check Server header for Apache/nginx version numbers."""
        start = time.time()
        version_pattern = re.compile(r'(Apache|nginx|IIS|lighttpd|LiteSpeed)[/\s]+(\d+\.\d+[\.\d]*)',
                                      re.IGNORECASE)
        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='Web Server Version Disclosure',
                    status='error',
                    severity='low',
                    description='Could not retrieve response to check server version.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            server_header = response.headers.get('Server', '')
            match = version_pattern.search(server_header)

            if match:
                server_software = match.group(1)
                server_version = match.group(2)
                return self.create_check(
                    owasp_category='A06:2021',
                    check_name='Web Server Version Disclosure',
                    status='fail',
                    severity='low',
                    description=f"Web server version disclosed: {server_software}/{server_version}",
                    details=f"Server header: {server_header}",
                    remediation=(
                        f"Configure {server_software} to suppress version information. "
                        'Apache: ServerTokens Prod; ServerSignature Off. '
                        'nginx: server_tokens off.'
                    ),
                    evidence=f"Server: {server_header}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A06:2021',
                check_name='Web Server Version Disclosure',
                status='pass',
                severity='low',
                description='Server header does not disclose a version number.',
                details=f"Server header: {server_header or 'not present'}",
                remediation='Continue suppressing version information from the Server header.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A06:2021',
                check_name='Web Server Version Disclosure',
                status='error',
                severity='low',
                description='Error checking web server version disclosure.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A06 Vulnerable Components checks', 'info',
                 'a06_start', db_session)

        self.log(scan_id, 'Checking JavaScript library versions', 'info', 'a06_js', db_session)
        checks.append(self.check_js_libraries(target_url))

        self.log(scan_id, 'Checking CMS detection', 'info', 'a06_cms', db_session)
        checks.append(self.check_cms_detection(target_url))

        self.log(scan_id, 'Checking framework version disclosure', 'info', 'a06_framework', db_session)
        checks.append(self.check_framework_version(target_url))

        self.log(scan_id, 'Checking web server version disclosure', 'info', 'a06_server', db_session)
        checks.append(self.check_outdated_headers(target_url))

        self.log(scan_id, 'Completed A06 Vulnerable Components checks', 'info',
                 'a06_done', db_session)
        return checks
