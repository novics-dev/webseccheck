"""
A05 — Subdomain Takeover scanner.

Checks if CNAME records point to unclaimed cloud/SaaS services
that could be taken over by a third party.
"""

from __future__ import annotations

import time
from urllib.parse import urlparse

from .base import BaseScanner


# Fingerprints: (service_name, CNAME suffix, response body pattern for unclaimed)
TAKEOVER_FINGERPRINTS = [
    ('GitHub Pages',        'github.io',             "There isn't a GitHub Pages site here"),
    ('Heroku',              'herokuapp.com',          'No such app'),
    ('AWS S3',              's3.amazonaws.com',       'NoSuchBucket'),
    ('AWS CloudFront',      'cloudfront.net',         'Bad request'),
    ('Fastly',              'fastly.net',             'Fastly error: unknown domain'),
    ('Shopify',             'myshopify.com',          'Sorry, this shop is currently unavailable'),
    ('Tumblr',              'tumblr.com',             "There's nothing here"),
    ('Ghost',               'ghost.io',               "The thing you were looking for is no longer here"),
    ('Surge.sh',            'surge.sh',               "project not found"),
    ('Bitbucket',           'bitbucket.io',           'Repository not found'),
    ('Azure Websites',      'azurewebsites.net',      '404 Web Site not found'),
    ('Azure CloudApp',      'cloudapp.net',           ''),
    ('Pantheon',            'pantheonsite.io',        '404 error unknown site'),
    ('Readme.io',           'readme.io',              'Project doesnt exist'),
    ('Statuspage',          'statuspage.io',          'You are being redirected'),
    ('UserVoice',           'uservoice.com',          'This UserVoice subdomain is currently available'),
    ('Zendesk',             'zendesk.com',            "Help Center Closed"),
]


class A05SubdomainTakeoverScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A05'

    @property
    def name(self) -> str:
        return 'Subdomain Takeover'

    @property
    def description(self) -> str:
        return (
            'Checks if the target domain or its CNAME chain points to an unclaimed '
            'cloud/SaaS service that could be taken over by a third party.'
        )

    def _resolve_cname(self, hostname: str) -> list[str]:
        """Return CNAME chain targets for hostname."""
        try:
            import dns.resolver
            cnames = []
            target = hostname
            for _ in range(5):
                try:
                    answers = dns.resolver.resolve(target, 'CNAME', lifetime=5)
                    cname = str(answers[0].target).rstrip('.')
                    cnames.append(cname)
                    target = cname
                except Exception:
                    break
            return cnames
        except ImportError:
            return []

    def check_subdomain_takeover(self, url: str) -> dict:
        start = time.time()
        try:
            hostname = urlparse(url).hostname or ''

            cnames = self._resolve_cname(hostname)
            if not cnames:
                # No CNAME — check direct response for known fingerprints anyway
                cnames_to_check = [hostname]
            else:
                cnames_to_check = cnames

            vulnerable = []
            for cname in cnames_to_check:
                for service, suffix, body_pattern in TAKEOVER_FINGERPRINTS:
                    if cname.endswith(suffix):
                        # Probe the CNAME target
                        probe_url = f'https://{cname}' if not cname.startswith('http') else cname
                        resp = self.make_request(probe_url, timeout=8)
                        if resp and body_pattern and body_pattern.lower() in resp.text.lower():
                            vulnerable.append(f'{cname} → {service} (unclaimed)')
                        elif resp is None and body_pattern == '':
                            vulnerable.append(f'{cname} → {service} (no response, may be unclaimed)')

            duration_ms = int((time.time() - start) * 1000)

            if vulnerable:
                return self.create_check(
                    owasp_category='A05', check_name='Subdomain Takeover',
                    status='fail', severity='high',
                    description=f'Potential subdomain takeover: {len(vulnerable)} vulnerable CNAME(s) detected.',
                    details='; '.join(vulnerable),
                    remediation=(
                        'Remove dangling CNAME records pointing to unclaimed services, or '
                        'reclaim the service. Audit all DNS CNAME records regularly.'
                    ),
                    evidence='; '.join(vulnerable),
                    duration_ms=duration_ms,
                )

            if cnames:
                cname_info = ', '.join(cnames[:3])
                return self.create_check(
                    owasp_category='A05', check_name='Subdomain Takeover',
                    status='pass', severity='high',
                    description='No subdomain takeover vulnerability detected.',
                    details=f'CNAME chain: {hostname} → {cname_info}',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05', check_name='Subdomain Takeover',
                status='pass', severity='high',
                description='No CNAME records found; subdomain takeover not applicable.',
                details=f'No CNAME chain detected for {hostname}.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='A05', check_name='Subdomain Takeover',
                status='warning', severity='high',
                description='Error checking subdomain takeover.',
                details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        return [self.check_subdomain_takeover(target_url)]
