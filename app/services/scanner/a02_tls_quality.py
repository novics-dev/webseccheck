"""
A02 — TLS/Certificate Quality scanner.

Checks certificate expiry, self-signed certs, hostname mismatch,
and overall TLS quality beyond basic protocol version.
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from .base import BaseScanner


class A02TLSQualityScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A02'

    @property
    def name(self) -> str:
        return 'TLS Certificate Quality'

    @property
    def description(self) -> str:
        return (
            'Checks TLS certificate expiry, self-signed certificates, '
            'hostname validation, and certificate chain quality.'
        )

    def _get_cert_info(self, hostname: str, port: int) -> tuple[dict | None, str | None]:
        """Return (cert_dict, error_string). cert_dict is None on failure."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert(), None
        except Exception as exc:
            return None, str(exc)

    def check_certificate_expiry(self, url: str) -> dict:
        start = time.time()
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Expiry',
                    status='info', severity='high',
                    description='Certificate expiry check requires HTTPS.',
                    duration_ms=int((time.time() - start) * 1000),
                )

            hostname = parsed.hostname
            port = parsed.port or 443
            cert, err = self._get_cert_info(hostname, port)
            duration_ms = int((time.time() - start) * 1000)

            if cert is None:
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Expiry',
                    status='warning', severity='high',
                    description='Could not retrieve TLS certificate.',
                    details=err or 'No certificate returned.',
                    duration_ms=duration_ms,
                )

            not_after = cert.get('notAfter', '')
            if not not_after:
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Expiry',
                    status='warning', severity='high',
                    description='Could not read certificate expiry date.',
                    duration_ms=duration_ms,
                )

            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (expiry - now).days

            if days_remaining < 0:
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Expiry',
                    status='fail', severity='critical',
                    description=f'TLS certificate has EXPIRED ({abs(days_remaining)} days ago).',
                    details=f'Expired: {not_after}',
                    remediation='Renew the TLS certificate immediately.',
                    evidence=f'notAfter: {not_after}',
                    duration_ms=duration_ms,
                )
            if days_remaining < 14:
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Expiry',
                    status='fail', severity='critical',
                    description=f'TLS certificate expires in {days_remaining} days.',
                    details=f'Expires: {not_after}',
                    remediation='Renew the TLS certificate immediately.',
                    evidence=f'notAfter: {not_after}, days_remaining: {days_remaining}',
                    duration_ms=duration_ms,
                )
            if days_remaining < 30:
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Expiry',
                    status='warning', severity='high',
                    description=f'TLS certificate expires soon: {days_remaining} days remaining.',
                    details=f'Expires: {not_after}',
                    remediation='Plan certificate renewal within the next week.',
                    evidence=f'notAfter: {not_after}',
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A02', check_name='Certificate Expiry',
                status='pass', severity='high',
                description=f'TLS certificate valid for {days_remaining} days.',
                details=f'Expires: {not_after}',
                evidence=f'days_remaining: {days_remaining}',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='A02', check_name='Certificate Expiry',
                status='warning', severity='high',
                description='Error checking certificate expiry.',
                details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def check_certificate_validity(self, url: str) -> dict:
        """Check for self-signed cert and hostname mismatch."""
        start = time.time()
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Validity',
                    status='info', severity='high',
                    description='Certificate validity check requires HTTPS.',
                    duration_ms=int((time.time() - start) * 1000),
                )

            hostname = parsed.hostname
            port = parsed.port or 443
            issues = []

            # Check with full verification to detect real issues
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=8) as sock:
                    ctx.wrap_socket(sock, server_hostname=hostname)
            except ssl.SSLCertVerificationError as e:
                issues.append(f'Certificate verification failed: {e.reason}')
            except ssl.CertificateError as e:
                issues.append(f'Certificate error: {e}')
            except Exception:
                pass

            # Get cert to check subject vs issuer (self-signed)
            cert, _ = self._get_cert_info(hostname, port)
            duration_ms = int((time.time() - start) * 1000)

            if cert:
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                if subject == issuer:
                    issues.append('Certificate appears self-signed (subject == issuer)')

                san = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
                if san and not any(
                    hostname == s or (s.startswith('*.') and hostname.endswith(s[1:]))
                    for s in san
                ):
                    issues.append(f'Hostname {hostname!r} not in SAN: {san}')

            if issues:
                return self.create_check(
                    owasp_category='A02', check_name='Certificate Validity',
                    status='fail', severity='high',
                    description='TLS certificate has validity issues.',
                    details='; '.join(issues),
                    remediation='Use a certificate from a trusted CA. Ensure the hostname matches the certificate SAN.',
                    evidence='; '.join(issues),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A02', check_name='Certificate Validity',
                status='pass', severity='high',
                description='TLS certificate is valid, trusted, and matches hostname.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return self.create_check(
                owasp_category='A02', check_name='Certificate Validity',
                status='warning', severity='high',
                description='Error checking certificate validity.',
                details=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []
        checks.append(self.check_certificate_expiry(target_url))
        checks.append(self.check_certificate_validity(target_url))
        return checks
