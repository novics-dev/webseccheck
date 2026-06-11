from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify, make_response, flash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, URL, Length, ValidationError
from app import db
from app.models import ScanPermission, Scan, ScanCheck, ScanLog
from app.services.email_service import send_permission_confirmation
from app.services.report import generate_pdf_report
import ipaddress
import urllib.parse
import re
from datetime import datetime

main = Blueprint('main', __name__)
main_bp = main  # alias used by app factory


# ---------------------------------------------------------------------------
# Permission form
# ---------------------------------------------------------------------------

class PermissionForm(FlaskForm):
    target_url = StringField('Target URL', validators=[
        DataRequired(message='Target URL is required.'),
        Length(max=2048),
    ])
    requester_name = StringField('Full Name', validators=[
        DataRequired(message='Full name is required.'),
        Length(max=200),
    ])
    organization = StringField('Organization', validators=[
        DataRequired(message='Organization is required.'),
        Length(max=200),
    ])
    requester_email = StringField('Email Address', validators=[
        DataRequired(message='Email address is required.'),
        Email(message='Enter a valid email address.'),
        Length(max=320),
    ])
    scope_description = TextAreaField('Scope Description', validators=[Length(max=2000)])
    explicit_consent = BooleanField(
        'I confirm that I am the owner of or have explicit written authorization to conduct '
        'security testing on the target URL above. I accept full legal responsibility for this test.',
        validators=[DataRequired(message='You must confirm explicit authorization before testing.')]
    )

    def validate_target_url(self, field):
        url = field.data.strip()
        if not url.startswith(('http://', 'https://')):
            raise ValidationError('URL must start with http:// or https://')
        if _is_private_or_localhost(url):
            raise ValidationError('Scanning localhost or private/internal IP ranges is not permitted.')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_private_or_localhost(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True
        if hostname.lower() in ('localhost', 'localhost.localdomain'):
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
        except ValueError:
            pass
        return False
    except Exception:
        return True


def _requester_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or ''


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@main.route('/')
def index():
    form = PermissionForm()
    return render_template('index.html', form=form)


@main.route('/scan/permission', methods=['POST'])
def scan_permission():
    from flask import current_app
    form = PermissionForm()
    if not form.validate_on_submit():
        return render_template('index.html', form=form), 400

    permission = ScanPermission(
        target_url=form.target_url.data.strip(),
        requester_name=form.requester_name.data.strip(),
        organization=form.organization.data.strip(),
        requester_email=form.requester_email.data.strip(),
        explicit_consent=True,
        ip_address=_requester_ip(),
    )
    db.session.add(permission)
    db.session.commit()

    try:
        send_permission_confirmation(permission)
    except Exception as e:
        current_app.logger.error('Failed to send permission confirmation email: %s', e)

    return redirect(url_for('main.scan_new', permission_id=permission.id))


@main.route('/scan/new/<int:permission_id>')
def scan_new(permission_id):
    permission = ScanPermission.query.get_or_404(permission_id)
    return render_template('permission_confirm.html', permission=permission)


@main.route('/scan/start/<int:permission_id>', methods=['POST'])
def scan_start(permission_id):
    from flask import current_app
    from app.services.task_runner import run_scan
    permission = ScanPermission.query.get_or_404(permission_id)

    scan = Scan(
        permission_id=permission.id,
        status='pending',
        created_at=datetime.utcnow(),
    )
    db.session.add(scan)
    db.session.commit()

    try:
        run_scan.delay(scan.id)
    except Exception as e:
        current_app.logger.error('Failed to queue scan task (Redis/Celery unavailable): %s', e)
        scan.status = 'failed'
        db.session.commit()
        flash(
            'Could not queue the scan — the background worker is unavailable. '
            'Please ensure Redis and the Celery worker are running, then try again.',
            'error'
        )
        return redirect(url_for('main.scan_new', permission_id=permission_id))

    return redirect(url_for('main.scan_status', scan_id=scan.id))


@main.route('/scan/status/<int:scan_id>')
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    permission = ScanPermission.query.get(scan.permission_id)
    return render_template('scan_status.html', scan=scan, permission=permission)


@main.route('/scan/report/<int:scan_id>')
def scan_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    permission = ScanPermission.query.get(scan.permission_id)
    checks = ScanCheck.query.filter_by(scan_id=scan_id).all()

    categories = {}
    for check in checks:
        cat = check.owasp_category or 'Uncategorized'
        categories.setdefault(cat, []).append(check)

    failed_checks = [c for c in checks if c.status in ('failed', 'warning', 'fail')]

    return render_template(
        'scan_report.html',
        scan=scan,
        permission=permission,
        checks=checks,
        categories=categories,
        failed_checks=failed_checks,
    )


@main.route('/scan/report/<int:scan_id>/pdf')
def scan_report_pdf(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    pdf_bytes = generate_pdf_report(scan_id)
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="security_report_{scan_id}.pdf"'
    return response


@main.route('/scan/logs/<int:scan_id>')
def scan_logs(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    permission = ScanPermission.query.get(scan.permission_id)
    logs = ScanLog.query.filter_by(scan_id=scan_id).order_by(ScanLog.id.asc()).all()
    return render_template('scan_logs.html', scan=scan, permission=permission, logs=logs)


# ---------------------------------------------------------------------------
# API endpoints (polled by scan_status.js)
# ---------------------------------------------------------------------------

@main.route('/api/scan/status/<int:scan_id>')
def api_scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({
        'scan_id': scan.id,
        'status': scan.status,
        'total_checks': scan.total_checks or 0,
        'passed_checks': scan.passed_checks or 0,
        'failed_checks': scan.failed_checks or 0,
        'warning_checks': scan.warning_checks or 0,
        'risk_score': scan.risk_score,
    })


@main.route('/api/scan/logs/<int:scan_id>')
def api_scan_logs(scan_id):
    Scan.query.get_or_404(scan_id)
    offset = request.args.get('offset', 0, type=int)
    logs_query = ScanLog.query.filter_by(scan_id=scan_id).order_by(ScanLog.id.asc())
    total = logs_query.count()
    logs = logs_query.offset(offset).all()
    return jsonify({
        'logs': [
            {
                'id': log.id,
                'timestamp': log.timestamp.strftime('%H:%M:%S') if log.timestamp else '',
                'level': log.level,
                'message': log.message,
                'step': log.step,
            }
            for log in logs
        ],
        'total': total,
    })
