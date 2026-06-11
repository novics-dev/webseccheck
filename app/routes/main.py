"""
Main blueprint — public-facing scan workflow routes.
"""

from __future__ import annotations

import io
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import (
    Blueprint, abort, flash, jsonify, make_response,
    redirect, render_template, request, url_for
)
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, URL, ValidationError

from app import db, limiter
from app.models import Scan, ScanCheck, ScanLog, ScanPermission, ScanStatus

import logging

logger = logging.getLogger(__name__)

main_bp = Blueprint("main", __name__)


# ---------------------------------------------------------------------------
# SSRF-safe URL validator
# ---------------------------------------------------------------------------

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

BLOCKED_HOSTS = {
    "localhost", "metadata.google.internal", "169.254.169.254",
    "instance-data", "metadata",
}


def is_safe_url(url: str) -> bool:
    """Return False if URL points to a private/internal resource."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname_lower = hostname.lower().rstrip(".")
        if hostname_lower in BLOCKED_HOSTS:
            return False
        try:
            addr = ipaddress.ip_address(hostname)
            for net in PRIVATE_NETWORKS:
                if addr in net:
                    return False
        except ValueError:
            pass  # Not an IP, continue
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------

class ScanPermissionForm(FlaskForm):
    target_url = StringField(
        "Target URL",
        validators=[DataRequired(), Length(max=2048), URL(require_tld=False)],
    )
    requester_name = StringField(
        "Full Name",
        validators=[DataRequired(), Length(min=2, max=255)],
    )
    organization = StringField(
        "Organization",
        validators=[DataRequired(), Length(min=2, max=255)],
    )
    requester_email = StringField(
        "Email Address",
        validators=[DataRequired(), Email(), Length(max=254)],
    )
    scope_description = TextAreaField(
        "Scope Description",
        validators=[Length(max=2000)],
    )
    explicit_consent = BooleanField(
        "I confirm I am authorized to test this target and give explicit permission for security testing",
        validators=[DataRequired(message="You must provide explicit consent to proceed.")],
    )

    def validate_target_url(self, field):
        if not is_safe_url(field.data):
            raise ValidationError(
                "This URL is not allowed. Private, localhost, and cloud metadata endpoints are blocked."
            )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@main_bp.route("/")
def index():
    form = ScanPermissionForm()
    return render_template("index.html", form=form, title="New Security Scan")


@main_bp.route("/scan/permission", methods=["POST"])
@limiter.limit("5 per hour")
def scan_permission():
    form = ScanPermissionForm()
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "danger")
        return render_template("index.html", form=form, title="New Security Scan"), 400

    # Double-check SSRF safety server-side
    target_url = form.target_url.data.strip()
    if not is_safe_url(target_url):
        abort(400, "Unsafe target URL")

    ip_addr = request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr)
    if ip_addr:
        ip_addr = ip_addr.split(",")[0].strip()[:45]

    permission = ScanPermission(
        target_url=target_url,
        requester_name=form.requester_name.data.strip(),
        organization=form.organization.data.strip(),
        requester_email=form.requester_email.data.lower().strip(),
        explicit_consent=True,
        consent_timestamp=datetime.now(timezone.utc),
        ip_address=ip_addr,
    )
    db.session.add(permission)
    db.session.commit()

    # Send confirmation email (best-effort)
    try:
        from app.services.email_service import send_permission_confirmation
        send_permission_confirmation(permission)
    except Exception as exc:
        logger.warning("Could not send permission confirmation email: %s", exc)

    flash("Permission recorded. You may now start the scan.", "success")
    return redirect(url_for("main.scan_new", permission_id=permission.id))


@main_bp.route("/scan/new/<int:permission_id>")
def scan_new(permission_id: int):
    permission = ScanPermission.query.get_or_404(permission_id)
    return render_template(
        "permission_confirm.html",
        permission=permission,
        title="Confirm Scan",
    )


@main_bp.route("/scan/start/<int:permission_id>", methods=["POST"])
@limiter.limit("3 per hour")
def scan_start(permission_id: int):
    permission = ScanPermission.query.get_or_404(permission_id)

    # Prevent starting a new scan if one is already running for this permission
    running = Scan.query.filter_by(
        permission_id=permission_id, status=ScanStatus.RUNNING
    ).first()
    if running:
        flash("A scan is already running for this permission.", "warning")
        return redirect(url_for("main.scan_status", scan_id=running.id))

    scan = Scan(
        permission_id=permission_id,
        status=ScanStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )
    db.session.add(scan)
    db.session.commit()

    # Queue the Celery task
    try:
        from app.services.task_runner import run_scan
        run_scan.delay(scan.id)
    except Exception as exc:
        logger.error("Failed to queue scan task: %s", exc)
        scan.status = ScanStatus.FAILED
        db.session.commit()
        flash("Failed to start scan. Please try again.", "danger")
        return redirect(url_for("main.scan_new", permission_id=permission_id))

    return redirect(url_for("main.scan_status", scan_id=scan.id))


@main_bp.route("/scan/status/<int:scan_id>")
def scan_status(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    return render_template("scan_status.html", scan=scan, title="Scan Status")


@main_bp.route("/scan/report/<int:scan_id>")
def scan_report(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    if scan.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        flash("Scan is not yet complete.", "warning")
        return redirect(url_for("main.scan_status", scan_id=scan_id))

    checks = ScanCheck.query.filter_by(scan_id=scan_id).order_by(
        ScanCheck.owasp_category, ScanCheck.severity
    ).all()

    # Group checks by OWASP category
    categories = {}
    for check in checks:
        categories.setdefault(check.owasp_category, []).append(check)

    return render_template(
        "scan_report.html",
        scan=scan,
        checks=checks,
        categories=categories,
        title=f"Scan Report #{scan_id}",
    )


@main_bp.route("/scan/report/<int:scan_id>/pdf")
def scan_report_pdf(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    try:
        from app.services.report import generate_pdf_report
        pdf_bytes = generate_pdf_report(scan_id)
    except Exception as exc:
        logger.error("PDF generation failed for scan %d: %s", scan_id, exc)
        abort(500, "Could not generate PDF report")

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="webseccheck-report-{scan_id}.pdf"'
    )
    return response


@main_bp.route("/scan/logs/<int:scan_id>")
def scan_logs(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    return render_template("scan_logs.html", scan=scan, title=f"Scan Logs #{scan_id}")


# ---------------------------------------------------------------------------
# JSON API endpoints
# ---------------------------------------------------------------------------

@main_bp.route("/api/scan/status/<int:scan_id>")
def api_scan_status(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({
        "id": scan.id,
        "status": scan.status,
        "total_checks": scan.total_checks,
        "passed_checks": scan.passed_checks,
        "failed_checks": scan.failed_checks,
        "warning_checks": scan.warning_checks,
        "risk_score": scan.risk_score,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "report_url": url_for("main.scan_report", scan_id=scan_id) if scan.status == ScanStatus.COMPLETED else None,
    })


@main_bp.route("/api/scan/logs/<int:scan_id>")
def api_scan_logs(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    offset = request.args.get("offset", 0, type=int)
    limit = min(request.args.get("limit", 100, type=int), 500)
    level_filter = request.args.get("level", "")

    query = ScanLog.query.filter_by(scan_id=scan_id).order_by(ScanLog.id)
    if level_filter:
        query = query.filter(ScanLog.level == level_filter)
    query = query.offset(offset).limit(limit)
    logs = query.all()

    return jsonify({
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "level": log.level,
                "message": log.message,
                "step": log.step,
            }
            for log in logs
        ],
        "offset": offset,
        "count": len(logs),
    })
