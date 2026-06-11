"""
Flask application factory for WebSecCheck.
"""

from __future__ import annotations

import logging
import os

from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# ---------------------------------------------------------------------------
# Extension instances (created outside the factory so models can import db)
# ---------------------------------------------------------------------------

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=None,  # set in init_app from RATELIMIT_STORAGE_URL config
)
mail = Mail()
talisman = Talisman()


def create_app(config_name: str | None = None) -> Flask:
    """Application factory.

    Args:
        config_name: Key into ``app.config.config`` dict.
                     Defaults to the ``FLASK_ENV`` env-var or 'development'.
    """
    app = Flask(__name__, instance_relative_config=False)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    from app.config import config as config_map

    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    cfg = config_map.get(config_name, config_map["default"])
    app.config.from_object(cfg)

    # Run per-config init_app if defined
    if hasattr(cfg, "init_app"):
        cfg.init_app(app)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    from app.models.user import load_user
    login_manager.user_loader(load_user)

    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)

    # Talisman — security headers
    csp = app.config.get("CSP_POLICY", False)
    talisman.init_app(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=["script-src"],
        force_https=app.config.get("SESSION_COOKIE_SECURE", True),
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
    )

    # ------------------------------------------------------------------
    # Blueprints
    # ------------------------------------------------------------------
    from app.routes.main import main_bp
    from app.routes.admin import admin_bp
    from app.routes.auth import auth_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(auth_bp, url_prefix="/auth")

    # ------------------------------------------------------------------
    # Celery — configure broker URL from Flask config
    # ------------------------------------------------------------------
    from app.services.task_runner import init_celery
    init_celery(app)

    # ------------------------------------------------------------------
    # Database — create tables
    # ------------------------------------------------------------------
    with app.app_context():
        # Import models so SQLAlchemy sees them before create_all()
        from app.models import (  # noqa: F401
            User, ScanPermission, Scan, ScanCheck, ScanLog,
        )
        db.create_all()

    # ------------------------------------------------------------------
    # Template globals / filters
    # ------------------------------------------------------------------
    @app.template_filter("severity_class")
    def severity_class(severity: str) -> str:
        mapping = {
            "critical": "danger",
            "high": "warning",
            "medium": "warning",
            "low": "info",
            "info": "secondary",
        }
        return mapping.get(severity, "secondary")

    @app.template_filter("status_class")
    def status_class(status: str) -> str:
        mapping = {
            "pass": "success",
            "fail": "danger",
            "warning": "warning",
            "info": "info",
            "pending": "secondary",
            "running": "primary",
            "completed": "success",
            "failed": "danger",
        }
        return mapping.get(status, "secondary")

    return app
