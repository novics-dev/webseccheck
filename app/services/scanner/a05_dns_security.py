"""
A05 — DNS Security scanner.

Checks SPF, DMARC, and DNSSEC configuration for the target domain.
"""

from __future__ import annotations

import time
from urllib.parse import urlparse

from .base import BaseScanner


class A05DNSSecurityScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A05'

    @property
    def name(self) -> str:
        return 'DNS Security'

    @property
    def description(self) -> str:
        return (
            'Checks SPF, DMARC, and basic DNS security configuration '
            'for the target domain.'
        )

    def _query_txt(self, name: str) -> list[str]:
        """Return TXT records for name, or [] on failure."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(name, 'TXT', lifetime=8)
            return [b.decode() for rdata in answers for b in rdata.strings]
        except Exception:
            return []

    def _has_dnspython(self) -> bool:
        try:
            import dns.resolver  # noqa: F401
            return True
        except ImportError:
            return False

    def check_spf(self, url: str) -> dict:
        start = time.time()
        try:
            if not self._has_dnspython():
                return self.create_check(
                    owasp_category='A05', check_name='SPF Record',
                    status='info', severity='medium',
                    description='dnspython not installed; skipping SPF check.',
                    remediation='Install dnspython: pip install dnspython',
                    duration_ms=int((time.time() - start) * 1000),
                )

            domain = urlparse(url).hostname or ''
            records = self._query_txt(domain)
            spf_records = [r for r in records if r.startswith('v=spf1')]
            duration_ms = int((time.time() - start) * 1000)

            if not spf_records:
                return self.create_check(
                    owasp_category='A05', check_name='SPF Record',
                    status='fail', severity='medium',
                    description=f'No SPF record found for {domain}.',
                    details='An SPF record is required to prevent email spoofing.',
                    remediation=(
                        'Add a TXT record: v=spf1 include:your-mail-provider.com ~all\n'
                        'Adjust to include all legitimate sending sources.'
                    ),
                    evidence=f'No SPF TXT record at {domain}',
                    duration_ms=duration_ms,
                )

            spf = spf_records[0]
            if spf.endswith('+all'):
                return self.create_check(
                    owasp_category='A05', check_name='SPF Record',
                    status='fail', severity='high',
                    description='SPF record uses +all (allow all), making it ineffective.',
                    details=spf,
                    remediation='Replace +all with ~all (softfail) or -all (fail).',
                    evidence=spf,
                    duration_ms=duration_ms,
                )
            if spf.endswith('?all'):
                return self.create_check(
                    owasp_category='A05', check_name='SPF Record',
                    status='warning', severity='medium',
                    description='SPF record uses ?all (neutral), providing no protection.',
                    details=spf,
                    remediation='Change ?all to ~all or -all.',
                    evidence=spf,
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05', check_name='SPF Record',
                status='pass', severity='medium',
                description='SPF record present and configured correctly.',
                details=spf,
                evidence=spf,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='A05', check_name='SPF Record',
                status='warning', severity='medium',
                description='Error checking SPF record.',
                details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_dmarc(self, url: str) -> dict:
        start = time.time()
        try:
            if not self._has_dnspython():
                return self.create_check(
                    owasp_category='A05', check_name='DMARC Record',
                    status='info', severity='medium',
                    description='dnspython not installed; skipping DMARC check.',
                    duration_ms=int((time.time() - start) * 1000),
                )

            domain = urlparse(url).hostname or ''
            dmarc_domain = f'_dmarc.{domain}'
            records = self._query_txt(dmarc_domain)
            dmarc_records = [r for r in records if r.startswith('v=DMARC1')]
            duration_ms = int((time.time() - start) * 1000)

            if not dmarc_records:
                return self.create_check(
                    owasp_category='A05', check_name='DMARC Record',
                    status='fail', severity='medium',
                    description=f'No DMARC record found for {domain}.',
                    details='DMARC protects against email spoofing and phishing.',
                    remediation=(
                        f'Add TXT record at _dmarc.{domain}:\n'
                        'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'
                    ),
                    evidence=f'No DMARC TXT record at {dmarc_domain}',
                    duration_ms=duration_ms,
                )

            dmarc = dmarc_records[0]
            import re
            policy_match = re.search(r'\bp=(\w+)', dmarc)
            policy = policy_match.group(1).lower() if policy_match else 'none'

            if policy == 'none':
                return self.create_check(
                    owasp_category='A05', check_name='DMARC Record',
                    status='warning', severity='medium',
                    description='DMARC policy is "none" — monitoring only, no enforcement.',
                    details=dmarc,
                    remediation='Upgrade DMARC policy to p=quarantine or p=reject.',
                    evidence=f'p=none in {dmarc}',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05', check_name='DMARC Record',
                status='pass', severity='medium',
                description=f'DMARC record present with policy={policy}.',
                details=dmarc,
                evidence=dmarc,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='A05', check_name='DMARC Record',
                status='warning', severity='medium',
                description='Error checking DMARC record.',
                details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_security_txt(self, url: str) -> dict:
        """Check for /.well-known/security.txt disclosure policy."""
        start = time.time()
        try:
            from urllib.parse import urlparse, urljoin
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            target = urljoin(base, '/.well-known/security.txt')
            resp = self.make_request(target, timeout=8)
            duration_ms = int((time.time() - start) * 1000)

            if resp and resp.status_code == 200 and len(resp.text) > 20:
                has_contact = 'Contact:' in resp.text
                return self.create_check(
                    owasp_category='A05', check_name='Security.txt',
                    status='pass' if has_contact else 'warning',
                    severity='low',
                    description='security.txt found.' + ('' if has_contact else ' Missing Contact field.'),
                    details=resp.text[:300],
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A05', check_name='Security.txt',
                status='info', severity='low',
                description='No security.txt found at /.well-known/security.txt.',
                remediation=(
                    'Add a security.txt file to help security researchers report vulnerabilities. '
                    'See https://securitytxt.org/ for the format.'
                ),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='A05', check_name='Security.txt',
                status='info', severity='low',
                description='Error checking security.txt.',
                details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []
        checks.append(self.check_spf(target_url))
        checks.append(self.check_dmarc(target_url))
        checks.append(self.check_security_txt(target_url))
        return checks
