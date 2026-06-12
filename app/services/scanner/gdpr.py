"""
GDPR — Technical Measures scanner.

Checks for GDPR Article 5, 13, 25, and 32 compliance indicators
that are detectable through passive HTTP/HTML analysis.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


# Known third-party tracking/analytics script domains
TRACKING_DOMAINS = [
    ('Google Analytics',  ['google-analytics.com', 'googletagmanager.com', 'gtag/js']),
    ('Meta Pixel',        ['connect.facebook.net', 'fbevents.js', 'facebook.com/tr']),
    ('LinkedIn Insight',  ['snap.licdn.com', 'linkedin.com/insight']),
    ('HotJar',            ['static.hotjar.com', 'vars.hotjar.com']),
    ('Matomo',            ['matomo.js', 'piwik.js']),
    ('Mixpanel',          ['cdn.mxpnl.com', 'mixpanel.com']),
    ('Intercom',          ['widget.intercom.io', 'intercomcdn.com']),
    ('Hubspot',           ['js.hs-scripts.com', 'hubspot.com/conversations']),
    ('TikTok Pixel',      ['analytics.tiktok.com']),
    ('Twitter/X Pixel',   ['static.ads-twitter.com', 'analytics.twitter.com']),
    ('Clarity',           ['clarity.ms']),
    ('FullStory',         ['fullstory.com/s/fs.js']),
]

# Google Fonts patterns (loads from Google servers = GDPR-sensitive)
GOOGLE_FONTS_PATTERNS = [
    'fonts.googleapis.com',
    'fonts.gstatic.com',
]

# Privacy/DPO-related keywords to search for
PRIVACY_LINK_PATTERNS = [
    r'href=["\'][^"\']*privac[^"\']*["\']',
    r'href=["\'][^"\']*cookie[^"\']*["\']',
    r'href=["\'][^"\']*gdpr[^"\']*["\']',
    r'href=["\'][^"\']*privacy[^"\']*["\']',
]

DPO_EMAIL_PATTERNS = [
    r'privacy@[\w.-]+',
    r'dpo@[\w.-]+',
    r'functionaris@[\w.-]+',
    r'avg@[\w.-]+',
    r'data[.-]?protection@[\w.-]+',
]

CONSENT_PATTERNS = [
    'cookieconsent', 'cookie-consent', 'cookie_consent',
    'cookiebanner', 'cookie-banner', 'cookie_banner',
    'cookienotice', 'gdpr', 'consent-manager', 'consentmanager',
    'tarteaucitron', 'cookiebot', 'onetrust', 'axeptio',
    'cookieinformation', 'usercentrics', 'didomi',
]


class GDPRScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'GDPR'

    @property
    def name(self) -> str:
        return 'GDPR Technical Measures'

    @property
    def description(self) -> str:
        return (
            'Checks for GDPR technical compliance indicators: cookie consent, '
            'privacy policy, DPO contact, third-party trackers, and data minimisation.'
        )

    def _fetch_html(self, url: str) -> tuple[str, object]:
        """Return (html_text, response). html is empty string on failure."""
        resp = self.make_request(url, timeout=12)
        if resp and resp.status_code == 200:
            return resp.text, resp
        return '', resp

    def check_cookie_consent(self, url: str) -> dict:
        """Detect presence of cookie consent mechanism."""
        start = time.time()
        try:
            html, _ = self._fetch_html(url)
            duration_ms = int((time.time() - start) * 1000)
            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                    status='warning', severity='high',
                    description='Could not fetch page to check cookie consent.',
                    duration_ms=duration_ms,
                )

            html_lower = html.lower()
            found = [p for p in CONSENT_PATTERNS if p in html_lower]

            if found:
                return self.create_check(
                    owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                    status='pass', severity='high',
                    description='Cookie consent mechanism detected on the page.',
                    details=f"Detected consent tool indicators: {', '.join(found[:3])}",
                    evidence=', '.join(found[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                status='fail', severity='high',
                description='No cookie consent mechanism detected.',
                details='No known consent management platform or cookie banner detected in HTML.',
                remediation=(
                    'Implement a cookie consent banner (e.g. CookieBot, OneTrust, or open-source '
                    'alternatives). Obtain explicit consent before setting non-essential cookies. '
                    'Required under GDPR Article 7 and ePrivacy Directive.'
                ),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                status='warning', severity='high',
                description='Error checking cookie consent.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_privacy_policy(self, url: str) -> dict:
        """Check for accessible privacy policy link."""
        start = time.time()
        try:
            html, _ = self._fetch_html(url)
            duration_ms = int((time.time() - start) * 1000)
            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='Privacy Policy',
                    status='warning', severity='high',
                    description='Could not fetch page to check privacy policy.',
                    duration_ms=duration_ms,
                )

            found_links = []
            for pattern in PRIVACY_LINK_PATTERNS:
                matches = re.findall(pattern, html, re.IGNORECASE)
                found_links.extend(matches[:2])

            # Also probe common paths
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            probed_paths = []
            for path in ['/privacy', '/privacy-policy', '/privacybeleid',
                         '/privacyverklaring', '/cookie-policy', '/gdpr']:
                resp = self.make_request(urljoin(base, path), timeout=6)
                if resp and resp.status_code == 200 and len(resp.text) > 200:
                    probed_paths.append(path)

            if found_links or probed_paths:
                return self.create_check(
                    owasp_category='GDPR', check_name='Privacy Policy',
                    status='pass', severity='high',
                    description='Privacy policy link or page found.',
                    details=(
                        f"Links in HTML: {len(found_links)}. "
                        f"Accessible paths: {', '.join(probed_paths) or 'none probed'}."
                    ),
                    evidence=', '.join(probed_paths) or found_links[0] if found_links else '',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Privacy Policy',
                status='fail', severity='high',
                description='No privacy policy link or page found.',
                details='No privacy/cookie policy link found in HTML and common paths returned no content.',
                remediation=(
                    'Publish a privacy policy and link to it in the footer. '
                    'Required under GDPR Article 13/14. Include: data categories, purposes, '
                    'legal basis, retention periods, data subject rights, and DPO contact.'
                ),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Privacy Policy',
                status='warning', severity='high',
                description='Error checking privacy policy.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_dpo_contact(self, url: str) -> dict:
        """Look for DPO or privacy contact information."""
        start = time.time()
        try:
            html, _ = self._fetch_html(url)

            # Also check /privacy and /contact pages
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for path in ['/privacy', '/privacy-policy', '/privacybeleid', '/contact']:
                extra, _ = self._fetch_html(urljoin(base, path))
                html += extra

            duration_ms = int((time.time() - start) * 1000)
            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='DPO / Privacy Contact',
                    status='warning', severity='medium',
                    description='Could not fetch pages to check DPO contact.',
                    duration_ms=duration_ms,
                )

            found = []
            for pattern in DPO_EMAIL_PATTERNS:
                matches = re.findall(pattern, html, re.IGNORECASE)
                found.extend(matches[:2])

            # Also look for "Functionaris Gegevensbescherming" or "Data Protection Officer"
            dpo_keywords = [
                'functionaris gegevensbescherming', 'data protection officer',
                'dpo', 'privacyfunctionaris', 'fg ',
            ]
            keyword_found = [k for k in dpo_keywords if k in html.lower()]

            if found or keyword_found:
                return self.create_check(
                    owasp_category='GDPR', check_name='DPO / Privacy Contact',
                    status='pass', severity='medium',
                    description='DPO or privacy contact information found.',
                    details=(
                        f"Emails: {', '.join(found[:3]) or 'none'}. "
                        f"Keywords: {', '.join(keyword_found[:3]) or 'none'}."
                    ),
                    evidence=', '.join(found[:2]) or ', '.join(keyword_found[:2]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='DPO / Privacy Contact',
                status='warning', severity='medium',
                description='No DPO or privacy contact information found.',
                details='No DPO email (privacy@, dpo@) or "Data Protection Officer" text detected.',
                remediation=(
                    'Publish a privacy contact email or DPO contact in your privacy policy. '
                    'Required under GDPR Article 13(1)(b) and Article 37-39 where a DPO is mandatory.'
                ),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='DPO / Privacy Contact',
                status='warning', severity='medium',
                description='Error checking DPO contact.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_third_party_trackers(self, url: str) -> dict:
        """Detect third-party tracking scripts in page HTML."""
        start = time.time()
        try:
            html, _ = self._fetch_html(url)
            duration_ms = int((time.time() - start) * 1000)
            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='Third-Party Trackers',
                    status='warning', severity='high',
                    description='Could not fetch page to check trackers.',
                    duration_ms=duration_ms,
                )

            found_trackers = []
            for service, patterns in TRACKING_DOMAINS:
                if any(p in html for p in patterns):
                    found_trackers.append(service)

            if found_trackers:
                return self.create_check(
                    owasp_category='GDPR', check_name='Third-Party Trackers',
                    status='fail', severity='high',
                    description=f'{len(found_trackers)} third-party tracker(s) detected in page source.',
                    details=f"Trackers found: {', '.join(found_trackers)}",
                    remediation=(
                        'Load third-party tracking scripts only after explicit user consent. '
                        'Use a tag manager that supports conditional loading based on consent. '
                        'Required under GDPR Article 6 and ePrivacy Directive.'
                    ),
                    evidence=', '.join(found_trackers),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Third-Party Trackers',
                status='pass', severity='high',
                description='No known third-party tracking scripts detected in page source.',
                details=f'Checked {len(TRACKING_DOMAINS)} known tracking services.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Third-Party Trackers',
                status='warning', severity='high',
                description='Error checking third-party trackers.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_google_fonts(self, url: str) -> dict:
        """Detect Google Fonts loaded without local hosting (sends visitor IP to Google)."""
        start = time.time()
        try:
            html, _ = self._fetch_html(url)
            duration_ms = int((time.time() - start) * 1000)
            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='Google Fonts (External)',
                    status='warning', severity='low',
                    description='Could not fetch page to check Google Fonts.',
                    duration_ms=duration_ms,
                )

            found = [p for p in GOOGLE_FONTS_PATTERNS if p in html]
            if found:
                return self.create_check(
                    owasp_category='GDPR', check_name='Google Fonts (External)',
                    status='warning', severity='low',
                    description='Google Fonts loaded from external Google servers.',
                    details=(
                        'External Google Fonts requests transmit visitor IP addresses to Google '
                        'without explicit consent. German courts have ruled this a GDPR violation.'
                    ),
                    remediation=(
                        'Self-host the required fonts or use system fonts. '
                        'Download fonts from fonts.google.com and serve them from your own domain.'
                    ),
                    evidence=', '.join(found),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Google Fonts (External)',
                status='pass', severity='low',
                description='No external Google Fonts requests detected.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Google Fonts (External)',
                status='warning', severity='low',
                description='Error checking Google Fonts.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_sensitive_data_in_urls(self, url: str) -> dict:
        """Check if the target URL or linked URLs expose personal data in query strings."""
        start = time.time()
        try:
            from urllib.parse import parse_qs
            personal_data_params = [
                'email', 'mail', 'naam', 'name', 'firstname', 'lastname',
                'voornaam', 'achternaam', 'telefoon', 'phone', 'mobile',
                'bsn', 'postcode', 'zipcode', 'geboortedatum', 'birthdate',
                'userid', 'user_id', 'klant_id', 'customer_id',
            ]

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            found = [k for k in params if k.lower() in personal_data_params]
            duration_ms = int((time.time() - start) * 1000)

            if found:
                return self.create_check(
                    owasp_category='GDPR', check_name='Personal Data in URL',
                    status='fail', severity='high',
                    description='Personal data parameters detected in URL query string.',
                    details=f"Parameters: {', '.join(found)}",
                    remediation=(
                        'Never transmit personal data (names, emails, BSN, etc.) in URL query strings. '
                        'Use POST requests or encrypted session storage. '
                        'URLs are logged in server logs, browser history, and referrer headers — '
                        'a GDPR data minimisation violation under Article 5(1)(c).'
                    ),
                    evidence=f"URL contains: {', '.join(found)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Personal Data in URL',
                status='pass', severity='high',
                description='No personal data parameters detected in URL query string.',
                details=f'Checked {len(personal_data_params)} known personal data parameter names.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Personal Data in URL',
                status='warning', severity='high',
                description='Error checking personal data in URL.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_error_page_leakage(self, url: str) -> dict:
        """Check if error pages leak stack traces or personal data."""
        start = time.time()
        try:
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            test_paths = [
                '/thispagedoesnotexist12345',
                '/admin/../../../../etc/passwd',
                "/?id=1'",
            ]

            leaks = []
            stack_patterns = [
                r'Traceback \(most recent call last\)',
                r'at \w+\.\w+\([\w.]+:\d+\)',
                r'SQLException|PDOException|NullPointerException',
                r'Warning:.*on line \d+',
                r'Fatal error:',
                r'Parse error:',
                r'System\.Exception',
                r'django\.core\.exceptions',
                r'flask\.exceptions',
            ]

            for path in test_paths:
                resp = self.make_request(urljoin(base, path), timeout=8)
                if resp and resp.text:
                    for pat in stack_patterns:
                        if re.search(pat, resp.text, re.IGNORECASE):
                            leaks.append(f'{path}: {pat[:40]}')
                            break

            duration_ms = int((time.time() - start) * 1000)

            if leaks:
                return self.create_check(
                    owasp_category='GDPR', check_name='Error Page Data Leakage',
                    status='fail', severity='medium',
                    description='Error pages expose technical details (stack traces, framework info).',
                    details='; '.join(leaks),
                    remediation=(
                        'Configure custom error pages that show only a generic message. '
                        'Disable debug mode in production. Stack traces may expose file paths, '
                        'database queries, or internal logic — a GDPR data minimisation issue.'
                    ),
                    evidence='; '.join(leaks[:2]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Error Page Data Leakage',
                status='pass', severity='medium',
                description='No stack traces or technical leakage detected on error pages.',
                details=f'Tested {len(test_paths)} error-triggering paths.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Error Page Data Leakage',
                status='warning', severity='medium',
                description='Error checking error page leakage.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_referrer_policy(self, url: str) -> dict:
        """Check Referrer-Policy header to prevent personal data leakage in Referer."""
        start = time.time()
        try:
            resp = self.make_request(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)
            if not resp:
                return self.create_check(
                    owasp_category='GDPR', check_name='Referrer Policy',
                    status='warning', severity='low',
                    description='Could not fetch response to check Referrer-Policy.',
                    duration_ms=duration_ms,
                )

            policy = resp.headers.get('Referrer-Policy', '').lower()
            safe_policies = [
                'no-referrer', 'no-referrer-when-downgrade',
                'same-origin', 'strict-origin', 'strict-origin-when-cross-origin',
            ]
            unsafe_policies = ['unsafe-url', 'origin-when-cross-origin']

            if not policy:
                return self.create_check(
                    owasp_category='GDPR', check_name='Referrer Policy',
                    status='warning', severity='low',
                    description='No Referrer-Policy header set.',
                    details='Without a Referrer-Policy, full URLs (which may contain personal data) are sent as Referer headers to third parties.',
                    remediation='Add: Referrer-Policy: strict-origin-when-cross-origin',
                    duration_ms=duration_ms,
                )

            if any(p in policy for p in unsafe_policies):
                return self.create_check(
                    owasp_category='GDPR', check_name='Referrer Policy',
                    status='fail', severity='low',
                    description=f'Unsafe Referrer-Policy: {policy}',
                    details='This policy sends full URLs to third parties, potentially leaking personal data in query strings.',
                    remediation='Change to: Referrer-Policy: strict-origin-when-cross-origin',
                    evidence=f'Referrer-Policy: {policy}',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Referrer Policy',
                status='pass', severity='low',
                description=f'Referrer-Policy is set to a safe value: {policy}',
                evidence=f'Referrer-Policy: {policy}',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Referrer Policy',
                status='warning', severity='low',
                description='Error checking Referrer-Policy.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []
        checks.append(self.check_cookie_consent(target_url))
        checks.append(self.check_privacy_policy(target_url))
        checks.append(self.check_dpo_contact(target_url))
        checks.append(self.check_third_party_trackers(target_url))
        checks.append(self.check_google_fonts(target_url))
        checks.append(self.check_sensitive_data_in_urls(target_url))
        checks.append(self.check_error_page_leakage(target_url))
        checks.append(self.check_referrer_policy(target_url))
        return checks
