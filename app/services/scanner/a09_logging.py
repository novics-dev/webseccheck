"""
A09 — Security Logging and Monitoring Failures scanner.
"""

from __future__ import annotations

import re
import time

from app.services.scanner.base import BaseScanner


class A09LoggingScanner(BaseScanner):
    category = "A09"
    name = "Security Logging and Monitoring Failures"
    description = (
        "Checks error page information disclosure, stack trace exposure, "
        "verbose errors, and log file accessibility."
    )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []
        self.log(scan_id, "Starting A09 Logging checks", "info", "A09", db_session)
        checks.extend(self._check_error_disclosure(target_url, scan_id, db_session))
        checks.extend(self._check_log_file_exposure(target_url, scan_id, db_session))
        self.log(scan_id, f"A09 checks complete — {len(checks)} results", "info", "A09", db_session)
        return checks

    def _check_error_disclosure(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking error page information disclosure", "info", "A09:errors", db_session)
        start = time.time()

        findings = []

        # Trigger various error conditions
        test_cases = [
            (target_url.rstrip("/") + "/wsc-404-test-path-xyz", "404"),
            (target_url.rstrip("/") + "/%00", "null byte"),
            (target_url.rstrip("/") + "/'", "quote"),
        ]

        stack_trace_patterns = [
            r"Traceback \(most recent call last\)",
            r"at \w[\w.]+\.\w+\([\w.]+:\d+\)",  # Java stack trace
            r"System\.Web\.",                     # .NET
            r"Fatal error:.*in.*on line \d+",     # PHP
            r"Warning:.*in.*on line \d+",          # PHP warning
            r"Exception in thread",
            r"org\.springframework\.",
            r"django\.core\.exceptions",
            r"ActiveRecord::",                    # Rails
        ]

        info_patterns = [
            r"(?:Python|Ruby|PHP|Java|Node|ASP\.NET)\s+[\d.]+",
            r"(?:Apache|nginx|IIS|Tomcat)/[\d.]+",
            r"(?:Ubuntu|Debian|CentOS|Windows Server)\s+[\d.]+",
        ]

        for url, label in test_cases:
            resp = self.make_request(url)
            if not resp:
                continue

            for pattern in stack_trace_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    findings.append({
                        "type": "stack_trace",
                        "trigger": label,
                        "pattern": pattern,
                        "status_code": resp.status_code,
                    })

            for pattern in info_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    findings.append({
                        "type": "system_info",
                        "trigger": label,
                        "pattern": pattern,
                        "status_code": resp.status_code,
                    })

        duration_ms = int((time.time() - start) * 1000)
        if any(f["type"] == "stack_trace" for f in findings):
            return [self.create_check(
                "A09", "Error Information Disclosure", "fail", "high",
                "Stack traces or verbose error information exposed in error responses.",
                details={"findings": findings},
                remediation="Configure custom error pages. Disable DEBUG mode. Log errors server-side only.",
                evidence=str(findings[:2]),
                duration_ms=duration_ms,
            )]
        if findings:
            return [self.create_check(
                "A09", "Error Information Disclosure", "warning", "medium",
                "System information potentially disclosed in error responses.",
                details={"findings": findings},
                remediation="Remove version information from error pages.",
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A09", "Error Information Disclosure", "pass", "info",
            "Error pages do not appear to disclose sensitive information.",
            duration_ms=duration_ms,
        )]

    def _check_log_file_exposure(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking for exposed log files", "info", "A09:logfiles", db_session)
        start = time.time()
        log_paths = [
            "/logs/", "/log/", "/error.log", "/debug.log", "/access.log",
            "/app.log", "/application.log", "/server.log",
            "/var/log/", "/logs/error.log", "/logs/access.log",
        ]
        found = []
        for path in log_paths:
            url = target_url.rstrip("/") + path
            resp = self.make_request(url)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                # Check for log-like content
                if re.search(r'\d{4}-\d{2}-\d{2}|\[ERROR\]|\[INFO\]|GET /|POST /', resp.text):
                    found.append({"path": path, "size": len(resp.content)})

        duration_ms = int((time.time() - start) * 1000)
        if found:
            return [self.create_check(
                "A09", "Log File Exposure", "fail", "high",
                f"Log files are publicly accessible: {[f['path'] for f in found]}",
                details={"found_logs": found},
                remediation="Move log files outside the web root or restrict access via web server configuration.",
                evidence=str(found),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A09", "Log File Exposure", "pass", "info",
            "No log files found publicly accessible.",
            duration_ms=duration_ms,
        )]
