import time
import re
import uuid
from urllib.parse import urlparse, urljoin

from .base import BaseScanner


class A09LoggingScanner(BaseScanner):

    @property
    def category(self) -> str:
        return 'A09'

    @property
    def name(self) -> str:
        return 'Security Logging and Monitoring Failures'

    @property
    def description(self) -> str:
        return (
            'Checks for logging and monitoring failures including verbose error disclosure, '
            'exposed log files, and stack trace leakage from malformed input.'
        )

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def check_error_disclosure(self, url: str) -> dict:
        """Probe a nonexistent path and check if error response reveals server/framework info."""
        start = time.time()
        base_url = self._get_base_url(url)
        probe_path = f"/webseccheck-nonexistent-{uuid.uuid4().hex[:8]}"
        test_url = urljoin(base_url, probe_path)

        disclosure_patterns = [
            r'Apache/\d+\.\d+',
            r'nginx/\d+\.\d+',
            r'Microsoft-IIS/\d+\.\d+',
            r'PHP/\d+\.\d+',
            r'mod_\w+/\d+\.\d+',
            r'OpenSSL/\d+\.\d+',
            r'Python/\d+\.\d+',
            r'Werkzeug/\d+\.\d+',
            r'Express\s+\d+\.\d+',
            r'Server:.*\d+\.\d+',
            r'ASP\.NET Version',
            r'Ruby on Rails',
            r'Django \d+\.\d+',
        ]

        try:
            response = self.make_request(test_url, timeout=10)
            duration_ms = int((time.time() - start) * 1000)

            if response is None:
                return self.create_check(
                    owasp_category='A09',
                    check_name='Error Information Disclosure',
                    status='warning',
                    severity='medium',
                    description='Could not retrieve error page for analysis.',
                    details='No response from target.',
                    duration_ms=duration_ms,
                )

            body = response.text
            found_disclosures = []

            for pattern in disclosure_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    found_disclosures.append(pattern)

            # Also check Server header
            server_header = response.headers.get('Server', '')
            if re.search(r'\d+\.\d+', server_header):
                found_disclosures.append(f"Server header: {server_header}")

            if found_disclosures:
                return self.create_check(
                    owasp_category='A09',
                    check_name='Error Information Disclosure',
                    status='fail',
                    severity='medium',
                    description='Error page reveals server/framework version information.',
                    details=f"HTTP {response.status_code}; disclosures: {'; '.join(found_disclosures)}",
                    remediation=(
                        'Configure custom error pages that do not reveal version information. '
                        'Suppress server banners and framework identifiers in error responses.'
                    ),
                    evidence=f"Disclosures: {', '.join(found_disclosures[:3])}",
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A09',
                check_name='Error Information Disclosure',
                status='pass',
                severity='medium',
                description='Error page does not appear to reveal server or framework version details.',
                details=f"HTTP {response.status_code} returned without obvious version disclosure.",
                remediation='Continue using generic error pages without technical details.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A09',
                check_name='Error Information Disclosure',
                status='warning',
                severity='medium',
                description='Error during error disclosure check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_log_exposure(self, url: str) -> dict:
        """Probe common log file paths and check if they return log content."""
        start = time.time()
        base_url = self._get_base_url(url)
        log_paths = [
            '/logs/', '/log/', '/error.log', '/debug.log', '/access.log',
            '/app.log', '/application.log', '/server.log', '/var/log/',
            '/logs/error.log', '/logs/access.log', '/logs/app.log',
            '/storage/logs/laravel.log', '/log/production.log',
        ]

        log_content_patterns = [
            r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',  # ISO timestamp
            r'\[error\]', r'\[warn\]', r'\[info\]', r'\[debug\]',
            r'GET /', r'POST /', r'HTTP/1\.',
            r'Exception', r'Error:', r'Warning:',
            r'127\.0\.0\.1', r'::1',
        ]

        exposed_logs = []

        try:
            for path in log_paths:
                test_url = urljoin(base_url, path)
                response = self.make_request(test_url, timeout=8)
                if response is None or response.status_code != 200:
                    continue

                body = response.text[:2000]
                content_type = response.headers.get('Content-Type', '').lower()

                # Plain text or log-like content
                is_plain = 'text/plain' in content_type or 'application/octet-stream' in content_type
                has_log_content = any(
                    re.search(p, body, re.IGNORECASE) for p in log_content_patterns
                )

                if has_log_content or is_plain:
                    exposed_logs.append(f"{path} (HTTP 200, {len(response.text)} bytes)")

            duration_ms = int((time.time() - start) * 1000)

            if exposed_logs:
                return self.create_check(
                    owasp_category='A09',
                    check_name='Log File Exposure',
                    status='fail',
                    severity='high',
                    description='Log files are publicly accessible.',
                    details='Exposed logs: ' + '; '.join(exposed_logs),
                    remediation=(
                        'Move log files outside the web root or restrict access via web server configuration. '
                        'Log files should never be publicly accessible.'
                    ),
                    evidence='Exposed: ' + ', '.join(exposed_logs[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A09',
                check_name='Log File Exposure',
                status='pass',
                severity='high',
                description='No publicly accessible log files detected.',
                details=f"Tested {len(log_paths)} common log file paths.",
                remediation='Ensure log files are stored outside the web root.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A09',
                check_name='Log File Exposure',
                status='warning',
                severity='high',
                description='Error checking for log file exposure.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def check_stack_trace(self, url: str) -> dict:
        """Trigger errors with malformed input and look for stack trace keywords."""
        start = time.time()
        stack_trace_patterns = [
            r'Traceback \(most recent call last\)',
            r'File ["\'].+["\'], line \d+',
            r'at .+\(.+\.java:\d+\)',
            r'at .+\(.+\.cs:\d+\)',
            r'Exception in thread',
            r'stack trace:',
            r'StackTrace',
            r'NullPointerException',
            r'ArrayIndexOutOfBounds',
            r'Caused by:.*Exception',
            r'System\.Web\.HttpUnhandledException',
            r'Application Error.*line \d+',
            r'Fatal error:.*on line \d+',
            r'Parse error:.*on line \d+',
            r'Notice:.*on line \d+',
        ]

        malformed_probes = [
            "?id='",
            "?id=<script>",
            "?search=%%invalid%%",
            "?page=../../../etc",
            "?num=not-a-number",
        ]

        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            found_traces = []
            for probe in malformed_probes:
                test_url = base + probe
                response = self.make_request(test_url, timeout=8)
                if response is None:
                    continue
                body = response.text
                for pattern in stack_trace_patterns:
                    if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                        found_traces.append(
                            f"Probe '{probe[:30]}': matched '{pattern[:40]}'"
                        )
                        break

            duration_ms = int((time.time() - start) * 1000)

            if found_traces:
                return self.create_check(
                    owasp_category='A09',
                    check_name='Stack Trace Leakage',
                    status='fail',
                    severity='medium',
                    description='Stack trace or detailed error information leaked in response.',
                    details='; '.join(found_traces),
                    remediation=(
                        'Catch all exceptions and return generic error messages to clients. '
                        'Log full stack traces server-side only. '
                        'Disable debug mode in production.'
                    ),
                    evidence='; '.join(found_traces[:3]),
                    duration_ms=duration_ms,
                )

            return self.create_check(
                owasp_category='A09',
                check_name='Stack Trace Leakage',
                status='pass',
                severity='medium',
                description='No stack traces detected from malformed input probes.',
                details=f"Tested {len(malformed_probes)} malformed probes; no stack trace patterns found.",
                remediation='Continue using generic error handlers that do not expose stack traces.',
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return self.create_check(
                owasp_category='A09',
                check_name='Stack Trace Leakage',
                status='warning',
                severity='medium',
                description='Error during stack trace leakage check.',
                details=str(exc),
                duration_ms=duration_ms,
            )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []

        self.log(scan_id, 'Starting A09 Logging and Monitoring checks', 'info',
                 'a09_start', db_session)

        self.log(scan_id, 'Checking error information disclosure', 'info', 'a09_error', db_session)
        checks.append(self.check_error_disclosure(target_url))

        self.log(scan_id, 'Checking log file exposure', 'info', 'a09_logs', db_session)
        checks.append(self.check_log_exposure(target_url))

        self.log(scan_id, 'Checking stack trace leakage', 'info', 'a09_trace', db_session)
        checks.append(self.check_stack_trace(target_url))

        self.log(scan_id, 'Completed A09 Logging and Monitoring checks', 'info',
                 'a09_done', db_session)
        return checks
