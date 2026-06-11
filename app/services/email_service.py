"""
Email service — sends permission confirmations and scan reports.
"""

from __future__ import annotations

import logging
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app

logger = logging.getLogger(__name__)


def _send_email(to: str, subject: str, html_body: str, attachments: list | None = None) -> bool:
    """Send an HTML email via SMTP.

    Args:
        to: Recipient email address.
        subject: Email subject.
        html_body: HTML content.
        attachments: List of (filename, bytes) tuples.

    Returns:
        True if sent, False on error.
    """
    try:
        smtp_server = current_app.config.get("MAIL_SERVER", "localhost")
        smtp_port = int(current_app.config.get("MAIL_PORT", 587))
        use_tls = current_app.config.get("MAIL_USE_TLS", True)
        username = current_app.config.get("MAIL_USERNAME", "")
        password = current_app.config.get("MAIL_PASSWORD", "")
        sender = current_app.config.get("MAIL_DEFAULT_SENDER", "noreply@webseccheck.local")

        msg = MIMEMultipart("mixed")
        msg["From"] = sender
        msg["To"] = to
        msg["Subject"] = subject

        # HTML body
        alt_part = MIMEMultipart("alternative")
        text_part = MIMEText("Please view this email in an HTML-capable client.", "plain")
        html_part = MIMEText(html_body, "html")
        alt_part.attach(text_part)
        alt_part.attach(html_part)
        msg.attach(alt_part)

        # Attachments
        for filename, data in (attachments or []):
            part = MIMEApplication(data, Name=filename)
            part["Content-Disposition"] = f'attachment; filename="{filename}"'
            msg.attach(part)

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if username and password:
                server.login(username, password)
            server.sendmail(sender, [to], msg.as_string())

        logger.info("Email sent to %s: %s", to, subject)
        return True

    except Exception as exc:
        logger.warning("Failed to send email to %s: %s", to, exc)
        return False


def send_permission_confirmation(permission) -> bool:
    """Send a confirmation email when a scan permission is recorded.

    Args:
        permission: ScanPermission model instance.
    """
    subject = f"WebSecCheck — Scan Permission Confirmed (#{permission.id})"
    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
    <div style="background:#1a1a2e;color:white;padding:15px;border-radius:8px;margin-bottom:20px">
        <h2 style="margin:0">WebSecCheck</h2>
    </div>
    <h3>Scan Permission Recorded</h3>
    <p>Dear {permission.requester_name},</p>
    <p>Your scan permission has been recorded. Here are the details:</p>
    <table style="width:100%;border-collapse:collapse">
        <tr><td style="padding:8px;font-weight:bold;background:#f8f9fa">Permission ID</td>
            <td style="padding:8px">#{permission.id}</td></tr>
        <tr><td style="padding:8px;font-weight:bold;background:#f8f9fa">Target URL</td>
            <td style="padding:8px">{permission.target_url}</td></tr>
        <tr><td style="padding:8px;font-weight:bold;background:#f8f9fa">Organization</td>
            <td style="padding:8px">{permission.organization}</td></tr>
        <tr><td style="padding:8px;font-weight:bold;background:#f8f9fa">Recorded At</td>
            <td style="padding:8px">{permission.created_at.strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
    </table>
    <p style="margin-top:20px">
        You consented to security testing of the target URL listed above.
        This record is retained for compliance purposes.
    </p>
    <p style="color:#6c757d;font-size:0.85em;margin-top:30px">
        This is an automated message from WebSecCheck. Do not reply to this email.
    </p>
</body>
</html>"""

    return _send_email(permission.requester_email, subject, html)


def send_scan_report(scan) -> bool:
    """Send the completed scan report to the requester.

    Args:
        scan: Scan model instance (must be completed).
    """
    permission = scan.permission
    if not permission:
        logger.warning("Scan %d has no permission record — cannot send report", scan.id)
        return False

    try:
        from app.services.report import generate_html_summary, generate_pdf_report
        html_summary = generate_html_summary(scan.id)
        pdf_bytes = generate_pdf_report(scan.id)
        attachments = [(f"webseccheck-report-{scan.id}.pdf", pdf_bytes)]
    except Exception as exc:
        logger.warning("Could not generate report for email: %s", exc)
        from app.services.report import generate_html_summary
        html_summary = generate_html_summary(scan.id)
        attachments = []

    subject = (
        f"WebSecCheck — Scan Report #{scan.id} "
        f"({scan.risk_score:.0f}/100 risk) — {permission.target_url[:50]}"
    )

    return _send_email(permission.requester_email, subject, html_summary, attachments)
