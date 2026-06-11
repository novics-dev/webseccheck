"""
A01 — Broken Access Control scanner.
"""

from __future__ import annotations

import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

from app.services.scanner.base import BaseScanner


class A01AccessControlScanner(BaseScanner):
    category = "A01"
    name = "Broken Access Control"
    description = (
        "Checks for directory traversal, HTTP method enumeration, admin path discovery, "
        "IDOR probes, and forced browsing vulnerabilities."
    )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []
        self.log(scan_id, "Starting A01 Access Control checks", "info", "A01", db_session)

        checks.extend(self._check_directory_traversal(target_url, scan_id, db_session))
        checks.extend(self._check_http_methods(target_url, scan_id, db_session))
        checks.extend(self._check_admin_paths(target_url, scan_id, db_session))
        checks.extend(self._check_idor(target_url, scan_id, db_session))
        checks.extend(self._check_forced_browsing(target_url, scan_id, db_session))

        self.log(scan_id, f"A01 checks complete — {len(checks)} results", "info", "A01", db_session)
        return checks

    def _check_directory_traversal(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking directory traversal", "info", "A01:traversal", db_session)
        start = time.time()
        payloads = [
            "/../../../etc/passwd",
            "/..%2F..%2F..%2Fetc%2Fpasswd",
            "/%2e%2e/%2e%2e/etc/passwd",
        ]
        findings = []
        for payload in payloads:
            url = target_url.rstrip("/") + payload
            resp = self.make_request(url)
            if resp and resp.status_code == 200:
                if "root:" in resp.text or "/bin/bash" in resp.text:
                    findings.append(url)

        duration_ms = int((time.time() - start) * 1000)
        if findings:
            return [self.create_check(
                "A01", "Directory Traversal", "fail", "critical",
                "Directory traversal vulnerability detected — server returned /etc/passwd content.",
                details={"findings": findings},
                remediation="Validate and sanitize all file path inputs. Use chroot jails or allowlisted paths.",
                evidence=str(findings[0]),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A01", "Directory Traversal", "pass", "info",
            "No directory traversal vulnerability detected.",
            duration_ms=duration_ms,
        )]

    def _check_http_methods(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking HTTP method enumeration", "info", "A01:methods", db_session)
        start = time.time()
        dangerous_methods = ["TRACE", "PUT", "DELETE", "CONNECT", "PATCH"]
        allowed_dangerous = []

        for method in dangerous_methods:
            resp = self.make_request(target_url, method=method)
            if resp and resp.status_code not in (405, 501, 400, 403):
                allowed_dangerous.append(f"{method}:{resp.status_code}")

        # Also check OPTIONS for allowed methods
        options_resp = self.make_request(target_url, method="OPTIONS")
        allow_header = ""
        if options_resp:
            allow_header = options_resp.headers.get("Allow", "")

        duration_ms = int((time.time() - start) * 1000)
        if allowed_dangerous:
            return [self.create_check(
                "A01", "HTTP Method Enumeration", "warning", "medium",
                f"Dangerous HTTP methods may be enabled: {', '.join(allowed_dangerous)}",
                details={"allowed_dangerous": allowed_dangerous, "allow_header": allow_header},
                remediation="Disable unused HTTP methods in your web server configuration.",
                evidence=f"Methods returning non-405: {', '.join(allowed_dangerous)}",
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A01", "HTTP Method Enumeration", "pass", "info",
            "Dangerous HTTP methods appear to be disabled.",
            duration_ms=duration_ms,
        )]

    def _check_admin_paths(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking for exposed admin paths", "info", "A01:admin", db_session)
        start = time.time()
        admin_paths = [
            "/admin", "/administrator", "/wp-admin", "/dashboard",
            "/manage", "/console", "/.env", "/config", "/backup",
            "/phpmyadmin", "/cpanel", "/webadmin", "/admin.php",
            "/config.php", "/setup", "/install",
        ]
        exposed = []
        for path in admin_paths:
            url = target_url.rstrip("/") + path
            resp = self.make_request(url)
            if resp and resp.status_code in (200, 301, 302, 403):
                exposed.append({"path": path, "status": resp.status_code})

        duration_ms = int((time.time() - start) * 1000)
        if any(e["status"] == 200 for e in exposed):
            return [self.create_check(
                "A01", "Admin Path Discovery", "fail", "high",
                f"Admin or sensitive paths are accessible: {[e['path'] for e in exposed if e['status'] == 200]}",
                details={"exposed_paths": exposed},
                remediation="Restrict access to admin paths using IP allowlists or strong authentication.",
                evidence=str(exposed),
                duration_ms=duration_ms,
            )]
        elif exposed:
            return [self.create_check(
                "A01", "Admin Path Discovery", "warning", "medium",
                f"Some admin paths exist but may be restricted (403): {[e['path'] for e in exposed]}",
                details={"exposed_paths": exposed},
                remediation="Ensure admin paths are not discoverable or accessible without authentication.",
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A01", "Admin Path Discovery", "pass", "info",
            "No common admin paths found accessible.",
            duration_ms=duration_ms,
        )]

    def _check_idor(self, target_url, scan_id, db_session):
        self.log(scan_id, "Probing for IDOR vulnerabilities", "info", "A01:idor", db_session)
        start = time.time()
        parsed = urlparse(target_url)
        path = parsed.path

        # Look for numeric IDs in the path
        import re
        numeric_segments = re.findall(r'/(\d+)', path)
        idor_findings = []

        if numeric_segments:
            for seg in numeric_segments[:2]:  # Limit probes
                for probe_id in [str(int(seg) + 1), str(int(seg) - 1), "1", "0", "99999"]:
                    probe_url = target_url.replace(f"/{seg}", f"/{probe_id}", 1)
                    resp = self.make_request(probe_url)
                    if resp and resp.status_code == 200:
                        idor_findings.append({"original": seg, "probe": probe_id, "url": probe_url})
                        break

        duration_ms = int((time.time() - start) * 1000)
        if idor_findings:
            return [self.create_check(
                "A01", "IDOR Probe", "warning", "high",
                "Potential IDOR: incrementing numeric IDs in URLs returns valid responses.",
                details={"findings": idor_findings},
                remediation="Use indirect object references and validate authorization on every resource access.",
                evidence=str(idor_findings),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A01", "IDOR Probe", "info", "info",
            "No obvious IDOR patterns detected (limited URL probe).",
            duration_ms=duration_ms,
        )]

    def _check_forced_browsing(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking forced browsing paths", "info", "A01:forced", db_session)
        start = time.time()
        paths = [
            "/api/users", "/api/admin", "/internal", "/api/v1/users",
            "/api/v1/admin", "/private", "/secret", "/hidden",
        ]
        exposed = []
        for path in paths:
            url = target_url.rstrip("/") + path
            resp = self.make_request(url)
            if resp and resp.status_code == 200:
                exposed.append(path)

        duration_ms = int((time.time() - start) * 1000)
        if exposed:
            return [self.create_check(
                "A01", "Forced Browsing", "warning", "medium",
                f"Internal paths accessible without authentication: {exposed}",
                details={"exposed": exposed},
                remediation="Implement authentication and authorization on all sensitive API endpoints.",
                evidence=str(exposed),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A01", "Forced Browsing", "pass", "info",
            "No sensitive internal paths found accessible.",
            duration_ms=duration_ms,
        )]
