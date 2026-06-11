"""
A05 — Exposed Sensitive Files scanner.

Probes for commonly exposed files and directories that reveal
credentials, source code, configuration, or backups.
"""

from __future__ import annotations

import time
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


# Paths grouped by risk level
SENSITIVE_PATHS = {
    'critical': [
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.backup',
        '/config.php',
        '/wp-config.php',
        '/configuration.php',
        '/settings.php',
        '/database.yml',
        '/config/database.yml',
        '/config/secrets.yml',
        '/.git/config',
        '/.git/HEAD',
        '/id_rsa',
        '/.ssh/id_rsa',
    ],
    'high': [
        '/backup.zip',
        '/backup.tar.gz',
        '/backup.sql',
        '/db.sql',
        '/dump.sql',
        '/site.tar.gz',
        '/www.zip',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/adminer.php',
        '/phpmyadmin/',
        '/pma/',
        '/.htpasswd',
        '/web.config.bak',
        '/app.config',
    ],
    'medium': [
        '/robots.txt',
        '/sitemap.xml',
        '/.DS_Store',
        '/CHANGELOG',
        '/CHANGELOG.md',
        '/README.md',
        '/composer.json',
        '/package.json',
        '/package-lock.json',
        '/yarn.lock',
        '/Gemfile',
        '/requirements.txt',
        '/.well-known/security.txt',
        '/server-status',
        '/server-info',
    ],
}


class A05SensitiveFilesScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A05'

    @property
    def name(self) -> str:
        return 'Exposed Sensitive Files'

    @property
    def description(self) -> str:
        return (
            'Probes for exposed configuration files, credentials, backups, '
            'source control metadata, and other sensitive paths.'
        )

    def _base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f'{parsed.scheme}://{parsed.netloc}'

    def check_sensitive_files(self, url: str) -> list[dict]:
        base = self._base_url(url)
        found_critical = []
        found_high = []
        found_medium = []
        start = time.time()

        for severity, paths in SENSITIVE_PATHS.items():
            for path in paths:
                target = urljoin(base, path)
                try:
                    resp = self.make_request(target, timeout=6, verify_ssl=False)
                    if resp is None:
                        continue
                    # Only flag 200 responses (not redirects to login pages etc.)
                    if resp.status_code == 200:
                        size = len(resp.content)
                        # Ignore empty responses and obvious error pages
                        if size < 50:
                            continue
                        content_type = resp.headers.get('Content-Type', '')
                        # Skip HTML responses for non-HTML paths (likely custom 404)
                        if 'html' in content_type and not path.endswith(('.html', '.php', '/')):
                            continue
                        entry = f'{path} ({size} bytes)'
                        if severity == 'critical':
                            found_critical.append(entry)
                        elif severity == 'high':
                            found_high.append(entry)
                        else:
                            found_medium.append(entry)
                except Exception:
                    continue

        duration_ms = int((time.time() - start) * 1000)
        checks = []

        if found_critical:
            checks.append(self.create_check(
                owasp_category='A05',
                check_name='Exposed Critical Files',
                status='fail',
                severity='critical',
                description=f'{len(found_critical)} critical file(s) publicly accessible.',
                details='; '.join(found_critical),
                remediation=(
                    'Immediately restrict access to these files. '
                    'Remove them from the web root or block via web server config. '
                    'Rotate any credentials that may have been exposed.'
                ),
                evidence='; '.join(found_critical[:5]),
                duration_ms=duration_ms,
            ))
        else:
            checks.append(self.create_check(
                owasp_category='A05',
                check_name='Exposed Critical Files',
                status='pass',
                severity='critical',
                description='No critical sensitive files found accessible.',
                details=f'Checked {len(SENSITIVE_PATHS["critical"])} critical paths.',
                duration_ms=duration_ms,
            ))

        if found_high:
            checks.append(self.create_check(
                owasp_category='A05',
                check_name='Exposed High-Risk Files',
                status='fail',
                severity='high',
                description=f'{len(found_high)} high-risk file(s) publicly accessible.',
                details='; '.join(found_high),
                remediation=(
                    'Remove or restrict access to backup files, diagnostic scripts, '
                    'and admin tools from the public web root.'
                ),
                evidence='; '.join(found_high[:5]),
                duration_ms=duration_ms,
            ))
        else:
            checks.append(self.create_check(
                owasp_category='A05',
                check_name='Exposed High-Risk Files',
                status='pass',
                severity='high',
                description='No high-risk files found accessible.',
                details=f'Checked {len(SENSITIVE_PATHS["high"])} high-risk paths.',
                duration_ms=duration_ms,
            ))

        if found_medium:
            checks.append(self.create_check(
                owasp_category='A05',
                check_name='Exposed Informational Files',
                status='warning',
                severity='medium',
                description=f'{len(found_medium)} informational file(s) accessible (may aid attackers).',
                details='; '.join(found_medium),
                remediation=(
                    'Review whether these files need to be publicly accessible. '
                    'Restrict dependency manifests, changelogs, and .DS_Store files.'
                ),
                evidence='; '.join(found_medium[:5]),
                duration_ms=duration_ms,
            ))
        else:
            checks.append(self.create_check(
                owasp_category='A05',
                check_name='Exposed Informational Files',
                status='pass',
                severity='medium',
                description='No informational files found exposed.',
                details=f'Checked {len(SENSITIVE_PATHS["medium"])} medium-risk paths.',
                duration_ms=duration_ms,
            ))

        return checks

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        return self.check_sensitive_files(target_url)
