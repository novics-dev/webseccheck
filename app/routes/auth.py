"""
Authentication blueprint — login and logout.
"""

from __future__ import annotations

from datetime import datetime, timezone
from flask import (
    Blueprint, flash, redirect, render_template, request, url_for
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired, Email, Length

from app import db, limiter
from app.models import User
from app.models.user import AuthenticatedUser

import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, template_folder="../templates/auth")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=1, max=128)])
    remember_me = BooleanField("Remember me")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute;30 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(form.password.data):
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            auth_user = AuthenticatedUser(user)
            login_user(auth_user, remember=form.remember_me.data)
            logger.info("Successful login: %s from %s", email, request.remote_addr)
            next_page = request.args.get("next")
            # Validate next URL to prevent open redirect
            if next_page and next_page.startswith("/") and not next_page.startswith("//"):
                return redirect(next_page)
            return redirect(url_for("admin.dashboard"))
        else:
            logger.warning("Failed login attempt for: %s from %s", email, request.remote_addr)
            flash("Invalid email or password.", "danger")

    return render_template("auth/login.html", form=form, title="Login")


@auth_bp.route("/logout")
@login_required
def logout():
    logger.info("Logout: %s", current_user.email if current_user.is_authenticated else "unknown")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.index"))
