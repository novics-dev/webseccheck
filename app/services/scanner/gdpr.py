"""
GDPR — Technical Measures scanner.

Checks for GDPR Article 5, 13, 25, and 32 compliance indicators
that are detectable through passive HTTP/HTML analysis.

Design principle: every check MUST produce a meaningful result even
when the main page cannot be fetched (WAF/CDN blocking). Checks fall
through to direct path probing so they never just say "could not fetch".
"""

from __future__ import annotations

import re
import time
import requests
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


# Browser-like session headers — avoids WAF/CDN blocking of scanner UAs
BROWSER_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
}

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

GOOGLE_FONTS_PATTERNS = ['fonts.googleapis.com', 'fonts.gstatic.com']

DPO_EMAIL_PATTERNS = [
    r'privacy@[\w.-]+',
    r'dpo@[\w.-]+',
    r'functionaris@[\w.-]+',
    r'avg@[\w.-]+',
    r'data[.-]?protection@[\w.-]+',
]

CONSENT_PATTERNS = [
    # Generic
    'cookieconsent', 'cookie-consent', 'cookie_consent',
    'cookiebanner', 'cookie-banner', 'cookie_banner',
    'cookienotice', 'cookie-notice', 'cookie_notice',
    'gdpr', 'consent-manager', 'consentmanager',
    # Major CMPs
    'tarteaucitron', 'cookiebot', 'onetrust', 'axeptio',
    'cookieinformation', 'usercentrics', 'didomi',
    'cookiefirst', 'cookieyes', 'iubenda', 'klaro',
    'borlabs-cookie', 'complianz', 'cookie-law-info',
    'nc_cookies', 'moove_gdpr',
    # CMP-blocked scripts pattern
    'type="text/plain"', "type='text/plain'",
    # Data attributes
    'data-cookieconsent', 'data-cookie-consent', 'data-cmp',
]

# Privacy-path candidates (Dutch + English), sorted by likelihood
PRIVACY_PATHS = [
    '/privacy', '/privacy-policy', '/privacybeleid', '/privacyverklaring',
    '/privacy-statement', '/privacystatement', '/cookie-policy', '/cookiebeleid',
    '/gdpr', '/avg', '/legal', '/disclaimer', '/algemene-voorwaarden',
    '/voorwaarden', '/privacybeleid--algemene-voorwaarden',
]

# Privacy-related href terms (Dutch + English)
PRIVACY_HREF_TERMS = [
    'privac', 'cookie', 'gdpr', 'avg', 'beleid', 'voorwaarden',
    'legal', 'disclaimer', 'terms', 'datenschutz', 'datapolicy',
    'gegevensbescherming',
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

    # ------------------------------------------------------------------ #
    # Shared HTTP session with browser headers                             #
    # ------------------------------------------------------------------ #

    def _get_session(self) -> requests.Session:
        """Return a requests Session with browser-like headers."""
        if not hasattr(self, '_session'):
            self._session = requests.Session()
            self._session.headers.update(BROWSER_HEADERS)
        return self._session

    def _get(self, url: str, timeout: int = 12) -> requests.Response | None:
        """GET with browser headers; returns Response or None on error."""
        try:
            resp = self._get_session().get(
                url, timeout=timeout, allow_redirects=True, verify=True
            )
            return resp
        except requests.exceptions.SSLError:
            try:
                resp = self._get_session().get(
                    url, timeout=timeout, allow_redirects=True, verify=False
                )
                return resp
            except Exception:
                return None
        except Exception:
            return None

    def _html(self, url: str, timeout: int = 12) -> str:
        """Fetch URL, return HTML text or '' on failure."""
        resp = self._get(url, timeout=timeout)
        if resp is None:
            return ''
        # Accept 200 and also non-200 with substantial HTML content
        if resp.status_code == 200:
            return resp.text
        if resp.status_code not in (301, 302, 404, 410) and len(resp.text) > 500:
            return resp.text
        return ''

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _base(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _extract_privacy_links(self, html: str, base: str) -> list[str]:
        """Extract hrefs that look like privacy/cookie policy links."""
        hrefs = re.findall(r'href=["\']([^"\'#?][^"\']*)["\']', html, re.IGNORECASE)
        found = []
        for href in hrefs:
            if any(term in href.lower() for term in PRIVACY_HREF_TERMS):
                if href.startswith('http'):
                    found.append(href)
                elif href.startswith('//'):
                    found.append('https:' + href)
                elif href.startswith('/'):
                    found.append(base + href)
        return list(dict.fromkeys(found))

    def _probe_url(self, url: str) -> bool:
        """Return True if URL returns HTTP 200 with substantial content."""
        resp = self._get(url, timeout=8)
        return bool(resp and resp.status_code == 200 and len(resp.text) > 200)

    # ------------------------------------------------------------------ #
    # run() — fetch main page once, share across all checks               #
    # ------------------------------------------------------------------ #

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        self._main_html = self._html(target_url)
        self._main_resp = self._get(target_url) if not self._main_html else None

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

    # ------------------------------------------------------------------ #
    # Individual checks                                                    #
    # ------------------------------------------------------------------ #

    def check_cookie_consent(self, url: str) -> dict:
        start = time.time()
        try:
            html = self._main_html
            if not html:
                # Try fetching directly as last resort
                html = self._html(url)
            duration_ms = int((time.time() - start) * 1000)

            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                    status='warning', severity='high',
                    description='Pagina kon niet worden opgehaald; cookie consent kon niet worden gecontroleerd.',
                    details='De scanner kon de HTML van de pagina niet ophalen (mogelijke WAF/CDN blokkering).',
                    duration_ms=duration_ms,
                )

            html_lower = html.lower()
            found = [p for p in CONSENT_PATTERNS if p in html_lower]

            if found:
                return self.create_check(
                    owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                    status='pass', severity='high',
                    description='Cookie consent mechanisme aangetroffen op de pagina.',
                    details=f"Herkende CMP-indicatoren: {', '.join(found[:3])}",
                    evidence=', '.join(found[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                status='fail', severity='high',
                description='Geen cookie consent mechanisme aangetroffen.',
                details='Geen bekende CMP of cookiebanner gevonden in de HTML.',
                remediation=(
                    'Implementeer een cookiebanner (bijv. Complianz, CookieBot of OneTrust). '
                    'Verkrijg expliciete toestemming vóór het plaatsen van niet-essentiële cookies. '
                    'Vereist op grond van GDPR Artikel 7 en de ePrivacy Richtlijn.'
                ),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Cookie Consent Mechanism',
                status='warning', severity='high',
                description='Fout bij controle cookie consent.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_privacy_policy(self, url: str) -> dict:
        """Check for accessible privacy policy — always probes paths, never fails on HTML fetch."""
        start = time.time()
        try:
            base = self._base(url)
            html = self._main_html

            # Step 1: extract links from HTML (best effort — skip if HTML unavailable)
            candidate_links = self._extract_privacy_links(html, base) if html else []

            # Step 2: verify extracted links actually resolve to real pages
            verified_links = []
            for link_url in candidate_links[:8]:
                if self._probe_url(link_url):
                    verified_links.append(link_url)
                    break  # one confirmed link is enough

            # Step 3: probe common paths (always runs, not just as fallback)
            probed_paths = []
            for path in PRIVACY_PATHS:
                resp = self._get(urljoin(base, path), timeout=7)
                if resp and resp.status_code == 200 and len(resp.text) > 200:
                    probed_paths.append(path)
                    break  # one confirmed path is enough

            duration_ms = int((time.time() - start) * 1000)

            if verified_links or probed_paths:
                evidence = verified_links[0] if verified_links else (base + probed_paths[0])
                html_note = f"{len(candidate_links)} link(s) in HTML." if html else "Hoofdpagina niet bereikbaar; directe padcontrole gebruikt."
                return self.create_check(
                    owasp_category='GDPR', check_name='Privacy Policy',
                    status='pass', severity='high',
                    description='Privacypagina gevonden en bereikbaar.',
                    details=f"{html_note} Bereikbaar via: {evidence}",
                    evidence=evidence,
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Privacy Policy',
                status='fail', severity='high',
                description='Geen privacypagina gevonden.',
                details=(
                    f"Geen privacy-link in HTML en {len(PRIVACY_PATHS)} gangbare paden "
                    f"gaven geen bereikbare pagina terug."
                ),
                remediation=(
                    'Publiceer een privacyverklaring en link er vanuit de footer naartoe. '
                    'Vereist op grond van GDPR Artikel 13/14. Vermeld: gegevenscategorieën, '
                    'doeleinden, rechtsgrond, bewaartermijnen, rechten van betrokkenen en DPO-contactgegevens.'
                ),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Privacy Policy',
                status='warning', severity='high',
                description='Fout bij controle privacybeleid.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_dpo_contact(self, url: str) -> dict:
        start = time.time()
        try:
            base = self._base(url)
            html = self._main_html

            # Collect HTML from multiple relevant pages
            pages_to_check = [
                '/privacy', '/privacy-policy', '/privacybeleid', '/privacyverklaring',
                '/privacystatement', '/contact', '/contact-us', '/over-ons',
            ]
            for path in pages_to_check:
                html += self._html(urljoin(base, path))

            # Also follow any privacy links found on main page
            if self._main_html:
                for link_url in self._extract_privacy_links(self._main_html, base)[:3]:
                    html += self._html(link_url)

            duration_ms = int((time.time() - start) * 1000)

            found_emails = []
            for pattern in DPO_EMAIL_PATTERNS:
                found_emails.extend(re.findall(pattern, html, re.IGNORECASE)[:2])

            dpo_keywords = [
                'functionaris gegevensbescherming', 'data protection officer',
                'privacyfunctionaris', 'fg ', 'dpo',
            ]
            keyword_found = [k for k in dpo_keywords if k in html.lower()]

            if found_emails or keyword_found:
                return self.create_check(
                    owasp_category='GDPR', check_name='DPO / Privacy Contact',
                    status='pass', severity='medium',
                    description='DPO of privacy contactgegevens gevonden.',
                    details=(
                        f"E-mails: {', '.join(found_emails[:3]) or 'geen'}. "
                        f"Trefwoorden: {', '.join(keyword_found[:3]) or 'geen'}."
                    ),
                    evidence=', '.join(found_emails[:2]) or ', '.join(keyword_found[:2]),
                    duration_ms=duration_ms,
                )

            if not html.strip():
                return self.create_check(
                    owasp_category='GDPR', check_name='DPO / Privacy Contact',
                    status='warning', severity='medium',
                    description='Pagina\'s konden niet worden opgehaald om DPO-contact te controleren.',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='DPO / Privacy Contact',
                status='warning', severity='medium',
                description='Geen DPO of privacy contactgegevens gevonden.',
                details='Geen DPO-e-mailadres (privacy@, dpo@) of "Functionaris Gegevensbescherming" tekst aangetroffen.',
                remediation=(
                    'Vermeld een privacy-contactadres of DPO-contactgegevens in de privacyverklaring. '
                    'Vereist op grond van GDPR Artikel 13(1)(b) en Artikelen 37-39 waar een FG verplicht is.'
                ),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='DPO / Privacy Contact',
                status='warning', severity='medium',
                description='Fout bij controle DPO-contact.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_third_party_trackers(self, url: str) -> dict:
        start = time.time()
        try:
            html = self._main_html or self._html(url)
            duration_ms = int((time.time() - start) * 1000)

            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='Third-Party Trackers',
                    status='warning', severity='high',
                    description='Pagina kon niet worden opgehaald om trackers te controleren.',
                    duration_ms=duration_ms,
                )

            found_trackers = [
                service for service, patterns in TRACKING_DOMAINS
                if any(p in html for p in patterns)
            ]

            if found_trackers:
                return self.create_check(
                    owasp_category='GDPR', check_name='Third-Party Trackers',
                    status='fail', severity='high',
                    description=f'{len(found_trackers)} derde-partij tracker(s) aangetroffen in paginabron.',
                    details=f"Gevonden trackers: {', '.join(found_trackers)}",
                    remediation=(
                        'Laad tracking-scripts alleen na expliciete toestemming van de gebruiker. '
                        'Gebruik een tag manager die conditioneel laden op basis van consent ondersteunt. '
                        'Vereist op grond van GDPR Artikel 6 en de ePrivacy Richtlijn.'
                    ),
                    evidence=', '.join(found_trackers),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Third-Party Trackers',
                status='pass', severity='high',
                description='Geen bekende derde-partij tracking-scripts aangetroffen in paginabron.',
                details=f'Gecontroleerd op {len(TRACKING_DOMAINS)} bekende trackingdiensten.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Third-Party Trackers',
                status='warning', severity='high',
                description='Fout bij controle third-party trackers.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_google_fonts(self, url: str) -> dict:
        start = time.time()
        try:
            html = self._main_html or self._html(url)
            duration_ms = int((time.time() - start) * 1000)

            if not html:
                return self.create_check(
                    owasp_category='GDPR', check_name='Google Fonts (Extern)',
                    status='warning', severity='low',
                    description='Pagina kon niet worden opgehaald om Google Fonts te controleren.',
                    duration_ms=duration_ms,
                )

            found = [p for p in GOOGLE_FONTS_PATTERNS if p in html]
            if found:
                return self.create_check(
                    owasp_category='GDPR', check_name='Google Fonts (Extern)',
                    status='warning', severity='low',
                    description='Google Fonts worden geladen vanaf externe Google-servers.',
                    details=(
                        'Externe Google Fonts-verzoeken sturen het IP-adres van de bezoeker naar Google '
                        'zonder expliciete toestemming. Duitse rechtbanken hebben dit als GDPR-overtreding aangemerkt.'
                    ),
                    remediation=(
                        'Host de benodigde lettertypes zelf of gebruik systeemlettertypes. '
                        'Download fonts van fonts.google.com en serveer ze vanaf uw eigen domein.'
                    ),
                    evidence=', '.join(found),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Google Fonts (Extern)',
                status='pass', severity='low',
                description='Geen externe Google Fonts-verzoeken aangetroffen.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Google Fonts (Extern)',
                status='warning', severity='low',
                description='Fout bij controle Google Fonts.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_sensitive_data_in_urls(self, url: str) -> dict:
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
                    owasp_category='GDPR', check_name='Persoonsgegevens in URL',
                    status='fail', severity='high',
                    description='Persoonsgegevens aangetroffen in URL-querystring.',
                    details=f"Parameters: {', '.join(found)}",
                    remediation=(
                        'Stuur persoonsgegevens (namen, e-mailadressen, BSN, etc.) nooit via URL-parameters. '
                        'Gebruik POST-verzoeken of versleutelde sessieopslag. '
                        'URL\'s worden opgeslagen in serverlogs, browsergeschiedenis en Referer-headers — '
                        'een GDPR-schending van gegevensminimalisatie (Artikel 5(1)(c)).'
                    ),
                    evidence=f"URL bevat: {', '.join(found)}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Persoonsgegevens in URL',
                status='pass', severity='high',
                description='Geen persoonsgegevens aangetroffen in URL-querystring.',
                details=f'Gecontroleerd op {len(personal_data_params)} bekende persoonsgegevensparameters.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Persoonsgegevens in URL',
                status='warning', severity='high',
                description='Fout bij controle persoonsgegevens in URL.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_error_page_leakage(self, url: str) -> dict:
        start = time.time()
        try:
            base = self._base(url)
            test_paths = [
                '/thispagedoesnotexist12345',
                '/admin/../../../../etc/passwd',
                "/?id=1'",
            ]
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
            leaks = []
            for path in test_paths:
                resp = self._get(urljoin(base, path), timeout=8)
                if resp and resp.text:
                    for pat in stack_patterns:
                        if re.search(pat, resp.text, re.IGNORECASE):
                            leaks.append(f'{path}: {pat[:40]}')
                            break

            duration_ms = int((time.time() - start) * 1000)

            if leaks:
                return self.create_check(
                    owasp_category='GDPR', check_name='Foutpagina Informatielek',
                    status='fail', severity='medium',
                    description='Foutpagina\'s tonen technische details (stack traces, frameworkinfo).',
                    details='; '.join(leaks),
                    remediation=(
                        'Configureer aangepaste foutpagina\'s die alleen een generieke melding tonen. '
                        'Schakel debug-modus uit in productie. Stack traces kunnen bestandspaden, '
                        'databasequery\'s of interne logica blootleggen — een GDPR-gegevensminimalisatieprobleem.'
                    ),
                    evidence='; '.join(leaks[:2]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Foutpagina Informatielek',
                status='pass', severity='medium',
                description='Geen stack traces of technisch informatielek op foutpagina\'s.',
                details=f'Getest via {len(test_paths)} fout-triggerende paden.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Foutpagina Informatielek',
                status='warning', severity='medium',
                description='Fout bij controle foutpagina informatielek.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_referrer_policy(self, url: str) -> dict:
        start = time.time()
        try:
            # Use cached response if available, otherwise fetch
            resp = getattr(self, '_main_resp', None)
            if resp is None:
                resp = self._get(url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if not resp:
                return self.create_check(
                    owasp_category='GDPR', check_name='Referrer Policy',
                    status='warning', severity='low',
                    description='Kon geen response ophalen om Referrer-Policy te controleren.',
                    duration_ms=duration_ms,
                )

            policy = resp.headers.get('Referrer-Policy', '').lower()
            unsafe_policies = ['unsafe-url', 'origin-when-cross-origin']

            if not policy:
                return self.create_check(
                    owasp_category='GDPR', check_name='Referrer Policy',
                    status='warning', severity='low',
                    description='Geen Referrer-Policy header ingesteld.',
                    details='Zonder Referrer-Policy worden volledige URL\'s (mogelijk met persoonsgegevens) als Referer-header naar derden verstuurd.',
                    remediation='Voeg toe: Referrer-Policy: strict-origin-when-cross-origin',
                    duration_ms=duration_ms,
                )

            if any(p in policy for p in unsafe_policies):
                return self.create_check(
                    owasp_category='GDPR', check_name='Referrer Policy',
                    status='fail', severity='low',
                    description=f'Onveilige Referrer-Policy: {policy}',
                    details='Dit beleid stuurt volledige URL\'s naar derden, wat persoonsgegevens in querystrings kan lekken.',
                    remediation='Wijzig naar: Referrer-Policy: strict-origin-when-cross-origin',
                    evidence=f'Referrer-Policy: {policy}',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='GDPR', check_name='Referrer Policy',
                status='pass', severity='low',
                description=f'Referrer-Policy is ingesteld op een veilige waarde: {policy}',
                evidence=f'Referrer-Policy: {policy}',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='GDPR', check_name='Referrer Policy',
                status='warning', severity='low',
                description='Fout bij controle Referrer-Policy.', details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )
