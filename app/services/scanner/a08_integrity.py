import time
import re
from urllib.parse import urlparse

from .base import BaseScanner


class A08IntegrityScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A08'

    @property
    def name(self) -> str:
        return 'Software and Data Integrity Failures'

    @property
    def description(self) -> str:
        return (
            'Checks for integrity failures including missing Subresource Integrity (SRI) '
            'on external scripts and stylesheets, missing Content-Type charset, '
            'and suspicious auto-update patterns in page source.'
        )

    def check_sri(self, url: str) -> dict:
        """Check for external script/link tags missing integrity= attribute."""
        start = time.time()
        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A08',
                    check_name='Subresource Integrity (SRI)',
                    status='error',
                    severity='medium',
                    description='Could not retrieve page to check SRI.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            html = response.text
            missing_sri = []

            # External scripts without integrity attribute
            script_tags = re.findall(
                r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>',
                html, re.IGNORECASE
            )
            for tag in script_tags:
                if 'integrity=' not in tag.lower():
                    src_match = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                    src = src_match.group(1) if src_match else 'unknown'
                    missing_sri.append(f"<script src=\"{src[:80]}\"> (no integrity)")

            # External link/stylesheet tags without integrity attribute
            link_tags = re.findall(
                r'<link[^>]+href=["\']https?://[^"\']+["\'][^>]*>',
                html, re.IGNORECASE
            )
            for tag in link_tags:
                tag_lower = tag.lower()
                if 'stylesheet' in tag_lower or 'preload' in tag_lower:
                    if 'integrity=' not in tag_lower:
                        href_match = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                        href = href_match.group(1) if href_match else 'unknown'
                        missing_sri.append(f"<link href=\"{href[:80]}\"> (no integrity)")

            if missing_sri:
                return self.create_check(
                    owasp_category='A08',
                    check_name='Subresource Integrity (SRI)',
                    status='fail',
                    severity='medium',
                    description=f"{len(missing_sri)} external resource(s) loaded without SRI.",
                    details='; '.join(missing_sri[:10]),
                    remediation=(
                        'Add integrity= and crossorigin= attributes to all external <script> and <link> tags. '
                        'Generate SRI hashes at: https://www.srihash.org/'
                    ),
                    evidence='; '.join(missing_sri[:3]),
                    duration_ms=duration_ms,
                )

            # Check if there are any external resources at all
            if script_tags or link_tags:
                return self.create_check(
                    owasp_category='A08',
                    check_name='Subresource Integrity (SRI)',
                    status='pass',
                    severity='medium',
                    description='All detected external resources have SRI integrity attributes.',
                    details=f"Checked {len(script_tags)} script tag(s) and {len(link_tags)} link tag(s).",
                    remediation='Continue using SRI for all externally hosted resources.',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A08',
                check_name='Subresource Integrity (SRI)',
                status='info',
                severity='medium',
                description='No external script or stylesheet resources detected.',
                details='Page does not appear to load scripts or stylesheets from external origins.',
                remediation='If adding external resources in future, include SRI integrity hashes.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A08',
                check_name='Subresource Integrity (SRI)',
                status='error',
                severity='medium',
                description='Error checking SRI.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_content_type(self, url: str) -> dict:
        """Check Content-Type has charset and X-Content-Type-Options is set."""
        start = time.time()
        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A08',
                    check_name='Content-Type Configuration',
                    status='error',
                    severity='low',
                    description='Could not retrieve response to check Content-Type.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            content_type = response.headers.get('Content-Type', '')
            xcto = response.headers.get('X-Content-Type-Options', '')
            issues = []

            if not content_type:
                issues.append('Content-Type header is missing')
            elif 'text/html' in content_type.lower() and 'charset' not in content_type.lower():
                issues.append(f"Content-Type missing charset: {content_type}")

            if not xcto:
                issues.append('X-Content-Type-Options header is missing')
            elif xcto.lower() != 'nosniff':
                issues.append(f"X-Content-Type-Options should be 'nosniff', got: '{xcto}'")

            if issues:
                return self.create_check(
                    owasp_category='A08',
                    check_name='Content-Type Configuration',
                    status='fail',
                    severity='low',
                    description='Content-Type configuration issues detected.',
                    details='; '.join(issues),
                    remediation=(
                        'Set Content-Type with charset (e.g. text/html; charset=utf-8). '
                        'Add X-Content-Type-Options: nosniff to prevent MIME sniffing.'
                    ),
                    evidence='; '.join(issues),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A08',
                check_name='Content-Type Configuration',
                status='pass',
                severity='low',
                description='Content-Type header includes charset and X-Content-Type-Options is set.',
                details=f"Content-Type: {content_type}; X-Content-Type-Options: {xcto}",
                remediation='Continue setting Content-Type with charset and X-Content-Type-Options: nosniff.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A08',
                check_name='Content-Type Configuration',
                status='error',
                severity='low',
                description='Error checking Content-Type configuration.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_update_mechanisms(self, url: str) -> dict:
        """Look for auto-update links or download patterns in HTML."""
        start = time.time()
        update_patterns = [
            r'auto.?update',
            r'auto.?upgrade',
            r'download\.php\?.*(?:version|update|upgrade)',
            r'update\.php',
            r'upgrade\.php',
            r'href=["\'][^"\']*download\.[^"\']*["\']',
            r'window\.location.*update',
            r'auto.?patch',
        ]

        try:
            response = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A08',
                    check_name='Auto-Update Mechanisms',
                    status='error',
                    severity='low',
                    description='Could not retrieve page to check for update mechanisms.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            html = response.text
            found_patterns = []
            for pattern in update_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    found_patterns.append(f"Pattern '{pattern}': {len(matches)} match(es)")

            if found_patterns:
                return self.create_check(
                    owasp_category='A08',
                    check_name='Auto-Update Mechanisms',
                    status='warning',
                    severity='low',
                    description='Potential auto-update or download mechanism patterns found in page.',
                    details='; '.join(found_patterns),
                    remediation=(
                        'Ensure any update or download mechanisms verify the integrity of '
                        'downloaded files using cryptographic signatures or hashes. '
                        'Use HTTPS for all update endpoints.'
                    ),
                    evidence='; '.join(found_patterns[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A08',
                check_name='Auto-Update Mechanisms',
                status='info',
                severity='low',
                description='No obvious auto-update or download mechanism patterns detected.',
                details='Page source does not contain common auto-update URL patterns.',
                remediation='Ensure any software update mechanisms verify file integrity.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A08',
                check_name='Auto-Update Mechanisms',
                status='error',
                severity='low',
                description='Error checking for auto-update mechanisms.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A08 Software/Data Integrity checks', 'info',
                 'a08_start', db_session)

        self.log(scan_id, 'Checking Subresource Integrity (SRI)', 'info', 'a08_sri', db_session)
        checks.append(self.check_sri(target_url))

        self.log(scan_id, 'Checking Content-Type configuration', 'info', 'a08_ctype', db_session)
        checks.append(self.check_content_type(target_url))

        self.log(scan_id, 'Checking auto-update mechanisms', 'info', 'a08_update', db_session)
        checks.append(self.check_update_mechanisms(target_url))

        self.log(scan_id, 'Completed A08 Software/Data Integrity checks', 'info',
                 'a08_done', db_session)
        return checks
