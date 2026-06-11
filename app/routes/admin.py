"""
Admin blueprint — protected management interface.
"""

from __future__ import annotations

from flask import (
    Blueprint, abort, flash, redirect, render_template, request, url_for
)
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length

from app import db, limiter
from app.models import Scan, ScanPermission, User, ScanCheck, ScanLog, ScanStatus

import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, template_folder="../templates/admin")


def admin_required(f):
    """Decorator that requires login and admin role."""
    from functools import wraps

    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


class CreateUserForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    is_admin = BooleanField("Admin privileges")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@admin_bp.route("/")
@admin_required
def dashboard():
    from sqlalchemy import func
    from datetime import date, timedelta, timezone
    import datetime as dt

    today = dt.datetime.now(dt.timezone.utc).date()
    total_scans = Scan.query.count()
    today_scans = Scan.query.filter(
        db.func.date(Scan.created_at) == today
    ).count()

    completed_scans = Scan.query.filter_by(status=ScanStatus.COMPLETED).all()
    failed_scans = Scan.query.filter_by(status=ScanStatus.FAILED).count()
    avg_risk = 0.0
    if completed_scans:
        scores = [s.risk_score for s in completed_scans if s.risk_score is not None]
        avg_risk = sum(scores) / len(scores) if scores else 0.0

    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()

    return render_template(
        "admin/dashboard.html",
        total_scans=total_scans,
        today_scans=today_scans,
        failed_scans=failed_scans,
        avg_risk=round(avg_risk, 1),
        recent_scans=recent_scans,
        title="Admin Dashboard",
    )


@admin_bp.route("/scans")
@admin_required
def scans():
    page = request.args.get("page", 1, type=int)
    status_filter = request.args.get("status", "")
    per_page = 20

    query = Scan.query.order_by(Scan.created_at.desc())
    if status_filter:
        query = query.filter(Scan.status == status_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "admin/scans.html",
        pagination=pagination,
        scans=pagination.items,
        status_filter=status_filter,
        title="All Scans",
    )


@admin_bp.route("/scan/<int:scan_id>")
@admin_required
def scan_detail(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    checks = ScanCheck.query.filter_by(scan_id=scan_id).order_by(
        ScanCheck.owasp_category
    ).all()
    return render_template(
        "admin/scan_detail.html",
        scan=scan,
        checks=checks,
        title=f"Scan #{scan_id}",
    )


@admin_bp.route("/scan/<int:scan_id>/delete", methods=["POST"])
@admin_required
def scan_delete(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash(f"Scan #{scan_id} deleted.", "success")
    return redirect(url_for("admin.scans"))


@admin_bp.route("/permissions")
@admin_required
def permissions():
    page = request.args.get("page", 1, type=int)
    permissions = ScanPermission.query.order_by(
        ScanPermission.created_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    return render_template(
        "admin/permissions.html",
        pagination=permissions,
        permissions=permissions.items,
        title="Scan Permissions",
    )


@admin_bp.route("/users")
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    form = CreateUserForm()
    return render_template(
        "admin/users.html",
        users=all_users,
        form=form,
        title="Users",
    )


@admin_bp.route("/users/create", methods=["POST"])
@admin_required
@limiter.limit("10 per hour")
def users_create():
    form = CreateUserForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(email=form.email.data.lower()).first()
        if existing:
            flash("A user with that email already exists.", "danger")
        else:
            user = User(
                email=form.email.data.lower().strip(),
                is_admin=form.is_admin.data,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash(f"User {user.email} created.", "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "danger")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def users_delete(user_id: int):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.users"))
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.email} deleted.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/logs")
@admin_required
def logs():
    page = request.args.get("page", 1, type=int)
    scan_id_filter = request.args.get("scan_id", type=int)
    level_filter = request.args.get("level", "")

    query = ScanLog.query.order_by(ScanLog.timestamp.desc())
    if scan_id_filter:
        query = query.filter(ScanLog.scan_id == scan_id_filter)
    if level_filter:
        query = query.filter(ScanLog.level == level_filter)

    pagination = query.paginate(page=page, per_page=50, error_out=False)
    return render_template(
        "admin/logs.html",
        pagination=pagination,
        logs=pagination.items,
        level_filter=level_filter,
        title="System Logs",
    )


@admin_bp.route("/settings")
@admin_required
def settings():
    return render_template("admin/settings.html", title="Settings")
