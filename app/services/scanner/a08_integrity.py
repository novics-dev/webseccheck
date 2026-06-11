"""
A08 — Software and Data Integrity Failures scanner.
"""

from __future__ import annotations

import re
import time

from app.services.scanner.base import BaseScanner


class A08IntegrityScanner(BaseScanner):
    category = "A08"
    name = "Software and Data Integrity Failures"
    description = (
        "Checks Subresource Integrity on external scripts/styles, Content-Type mismatches, "
        "and deserialization indicators."
    )

    def run(self, target_url: str, scan_id: int, db_session) -> list:
        checks = []
        self.log(scan_id, "Starting A08 Integrity Failures checks", "info", "A08", db_session)
        checks.extend(self._check_sri(target_url, scan_id, db_session))
        checks.extend(self._check_content_type_mismatch(target_url, scan_id, db_session))
        checks.extend(self._check_deserialization_indicators(target_url, scan_id, db_session))
        self.log(scan_id, f"A08 checks complete — {len(checks)} results", "info", "A08", db_session)
        return checks

    def _check_sri(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking Subresource Integrity (SRI)", "info", "A08:sri", db_session)
        start = time.time()
        resp = self.make_request(target_url)
        duration_ms = int((time.time() - start) * 1000)
        if not resp:
            return []

        # Find external scripts and stylesheets
        external_scripts = re.findall(
            r'<script[^>]+src=["\']https?://(?!(?:' + re.escape(re.sub(r'https?://', '', target_url).split('/')[0]) + r'))[^"\']+["\'][^>]*>',
            resp.text, re.IGNORECASE
        )
        external_styles = re.findall(
            r'<link[^>]+href=["\']https?://(?!(?:' + re.escape(re.sub(r'https?://', '', target_url).split('/')[0]) + r'))[^"\']+["\'][^>]*>',
            resp.text, re.IGNORECASE
        )

        missing_sri = []
        for tag in external_scripts + external_styles:
            if 'integrity=' not in tag.lower():
                # Extract src/href for evidence
                src = re.search(r'(?:src|href)=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                if src:
                    missing_sri.append(src.group(1))

        if missing_sri:
            return [self.create_check(
                "A08", "Subresource Integrity (SRI)", "warning", "medium",
                f"{len(missing_sri)} external resources loaded without SRI integrity attribute.",
                details={"missing_sri": missing_sri[:10]},
                remediation=(
                    "Add integrity and crossorigin attributes to external scripts/styles:\n"
                    '<script src="..." integrity="sha384-..." crossorigin="anonymous">'
                ),
                evidence=str(missing_sri[:3]),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A08", "Subresource Integrity (SRI)", "pass", "info",
            "All detected external resources use SRI integrity attributes (or no external resources).",
            duration_ms=duration_ms,
        )]

    def _check_content_type_mismatch(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking Content-Type consistency", "info", "A08:ctype", db_session)
        start = time.time()
        resp = self.make_request(target_url)
        duration_ms = int((time.time() - start) * 1000)
        if not resp:
            return []

        content_type = resp.headers.get("Content-Type", "")
        x_ct_options = resp.headers.get("X-Content-Type-Options", "")

        issues = []
        if not content_type:
            issues.append("Missing Content-Type header")
        if x_ct_options.lower() != "nosniff":
            issues.append(f"X-Content-Type-Options is '{x_ct_options}' — should be 'nosniff'")

        if issues:
            return [self.create_check(
                "A08", "Content-Type Mismatch", "warning", "medium",
                f"Content-Type issues: {issues}",
                details={"issues": issues, "content_type": content_type},
                remediation="Always set Content-Type headers and X-Content-Type-Options: nosniff.",
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A08", "Content-Type Mismatch", "pass", "info",
            f"Content-Type ({content_type}) and X-Content-Type-Options correctly set.",
            duration_ms=duration_ms,
        )]

    def _check_deserialization_indicators(self, target_url, scan_id, db_session):
        self.log(scan_id, "Checking deserialization indicators", "info", "A08:deser", db_session)
        start = time.time()
        resp = self.make_request(target_url)
        duration_ms = int((time.time() - start) * 1000)
        if not resp:
            return []

        # Look for serialized data patterns in cookies or visible params
        deser_patterns = [
            r'O:\d+:"[A-Za-z]',          # PHP object serialization
            r'rO0AB',                     # Java serialized base64 prefix
            r'Tzo\d+:',                   # PHP object
            r'YTox:',                     # PHP array
        ]

        indicators = []
        # Check cookies
        for cookie in resp.cookies:
            for pattern in deser_patterns:
                if re.search(pattern, cookie.value):
                    indicators.append(f"Cookie '{cookie.name}' contains serialized data pattern")

        if indicators:
            return [self.create_check(
                "A08", "Deserialization Indicators", "warning", "high",
                f"Potential unsafe deserialization: {indicators}",
                details={"indicators": indicators},
                remediation=(
                    "Avoid deserializing user-controlled data. Use signing/integrity checks. "
                    "Prefer JSON over binary serialization formats."
                ),
                evidence=str(indicators),
                duration_ms=duration_ms,
            )]
        return [self.create_check(
            "A08", "Deserialization Indicators", "pass", "info",
            "No unsafe deserialization patterns detected.",
            duration_ms=duration_ms,
        )]
