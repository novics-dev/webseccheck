from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app import db
from app.models import ScanPermission, Scan, ScanCheck, ScanLog
from app.services.email_service import send_permission_confirmation
from app.services.report import generate_pdf_report
import re
from datetime import datetime

main = Blueprint('main', __name__)
main_bp = main  # alias used by app factory


def is_private_or_localhost(url):
    """Returns True if URL points to localhost or private IP ranges."""
    import ipaddress
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True
        # Check for localhost
        if hostname.lower() in ('localhost', 'localhost.localdomain'):
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
                return True
        except ValueError:
            # It's a hostname, not an IP - check common private hostnames
            pass
        return False
    except Exception:
        return True


def validate_target_url(url):
    """Validate URL scheme and that it's not private."""
    if not url:
        return False, "Target URL is required."
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    if is_private_or_localhost(url):
        return False, "Scanning localhost or private IP ranges is not allowed."
    return True, None


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/scan/permission', methods=['POST'])
def scan_permission():
    from flask import current_app
    target_url = request.form.get('target_url', '').strip()
    requester_name = request.form.get('requester_name', '').strip()
    organization = request.form.get('organization', '').strip()
    requester_email = request.form.get('requester_email', '').strip()
    scope_description = request.form.get('scope_description', '').strip()
    consent = request.form.get('consent')

    errors = []

    valid, err = validate_target_url(target_url)
    if not valid:
        errors.append(err)

    if not requester_email:
        errors.append("Requester email is required.")
    elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', requester_email):
        errors.append("Invalid email address.")

    if not consent:
        errors.append("You must confirm you have permission to test the target.")

    if errors:
        return render_template('index.html', errors=errors, form_data=request.form), 400

    requester_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if requester_ip and ',' in requester_ip:
        requester_ip = requester_ip.split(',')[0].strip()

    permission = ScanPermission(
        target_url=target_url,
        requester_name=requester_name,
        organization=organization,
        requester_email=requester_email,
        scope_description=scope_description,
        consent_given=True,
        requester_ip=requester_ip,
    )
    db.session.add(permission)
    db.session.commit()

    try:
        send_permission_confirmation(permission)
    except Exception as e:
        current_app.logger.error(f"Failed to send permission confirmation email: {e}")

    return redirect(url_for('main.scan_new', permission_id=permission.id))


@main.route('/scan/new/<int:permission_id>')
def scan_new(permission_id):
    permission = ScanPermission.query.get_or_404(permission_id)
    return render_template('permission_confirm.html', permission=permission)


@main.route('/scan/start/<int:permission_id>', methods=['POST'])
def scan_start(permission_id):
    from app.services.task_runner import run_scan
    permission = ScanPermission.query.get_or_404(permission_id)

    scan = Scan(
        permission_id=permission.id,
        status='pending',
        created_at=datetime.utcnow(),
    )
    db.session.add(scan)
    db.session.commit()

    run_scan.delay(scan.id)

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

    # Group checks by OWASP category
    categories = {}
    for check in checks:
        cat = check.owasp_category or 'Uncategorized'
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(check)

    failed_checks = [c for c in checks if c.status in ('failed', 'warning')]

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


@main.route('/api/scan/status/<int:scan_id>')
def api_scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    data = {
        'scan_id': scan.id,
        'status': scan.status,
        'progress_pct': scan.progress_pct or 0,
        'total_checks': scan.total_checks or 0,
        'passed': scan.passed_checks or 0,
        'failed': scan.failed_checks or 0,
        'warnings': scan.warning_checks or 0,
        'risk_score': scan.risk_score,
        'current_step': scan.current_step or '',
    }
    return jsonify(data)


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
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'level': log.level,
                'message': log.message,
                'step': log.step,
            }
            for log in logs
        ],
        'total': total,
    })
