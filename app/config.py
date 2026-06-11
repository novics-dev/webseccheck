"""
Application configuration classes for WebSecCheck.
Settings are loaded from environment variables with sensible defaults for development.
"""

import os
from datetime import timedelta


class BaseConfig:
    """Base configuration shared across all environments."""

    # -------------------------------------------------------------------------
    # Core Flask settings
    # -------------------------------------------------------------------------
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-me-in-production-use-a-long-random-string")
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # 1 hour

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    _db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "webseccheck.db")
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.normpath(_db_path)}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # -------------------------------------------------------------------------
    # Mail
    # -------------------------------------------------------------------------
    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS: bool = os.environ.get("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes")
    MAIL_USE_SSL: bool = False
    MAIL_USERNAME: str | None = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD: str | None = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER: str = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@webseccheck.local")
    ADMIN_EMAIL: str = os.environ.get("ADMIN_EMAIL", "admin@webseccheck.local")

    # -------------------------------------------------------------------------
    # Celery / Redis
    # -------------------------------------------------------------------------
    CELERY_BROKER_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CELERY_TASK_SERIALIZER: str = "json"
    CELERY_RESULT_SERIALIZER: str = "json"
    CELERY_ACCEPT_CONTENT: list = ["json"]
    CELERY_TIMEZONE: str = "UTC"
    CELERY_ENABLE_UTC: bool = True
    CELERY_TASK_SOFT_TIME_LIMIT: int = 300   # 5 minutes
    CELERY_TASK_TIME_LIMIT: int = 360        # 6 minutes hard limit

    # -------------------------------------------------------------------------
    # Upload / request limits
    # -------------------------------------------------------------------------
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16 MB

    # -------------------------------------------------------------------------
    # Session / cookie security
    # -------------------------------------------------------------------------
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    SESSION_COOKIE_NAME: str = "webseccheck_session"
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=8)
    REMEMBER_COOKIE_SECURE: bool = True
    REMEMBER_COOKIE_HTTPONLY: bool = True
    REMEMBER_COOKIE_DURATION: timedelta = timedelta(days=7)

    # -------------------------------------------------------------------------
    # Allowed hosts (used by middleware / Talisman)
    # -------------------------------------------------------------------------
    ALLOWED_HOSTS: list = [
        h.strip()
        for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
        if h.strip()
    ]
    APP_DOMAIN: str = os.environ.get("APP_DOMAIN", "localhost")

    # -------------------------------------------------------------------------
    # Rate limiting (Flask-Limiter)
    # -------------------------------------------------------------------------
    RATELIMIT_STORAGE_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/1")
    RATELIMIT_DEFAULT: str = "200 per day;50 per hour"
    RATELIMIT_HEADERS_ENABLED: bool = True

    # -------------------------------------------------------------------------
    # Content Security Policy (passed to Flask-Talisman)
    # -------------------------------------------------------------------------
    CSP_POLICY: dict = {
        "default-src": "'self'",
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "font-src": ["'self'", "https://cdn.jsdelivr.net"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'", "https://cdn.jsdelivr.net"],
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    }

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")


class DevelopmentConfig(BaseConfig):
    """Development configuration — relaxes security constraints for local work."""

    DEBUG: bool = True
    TESTING: bool = False

    # Allow non-HTTPS cookies locally
    SESSION_COOKIE_SECURE: bool = False
    REMEMBER_COOKIE_SECURE: bool = False

    # Use in-memory rate limiter so Redis is optional during development
    RATELIMIT_STORAGE_URL: str = "memory://"

    # Less strict CSP during development to ease debugging
    CSP_POLICY: dict = {
        "default-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        "img-src": ["'self'", "data:", "http:", "https:"],
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
    }

    LOG_LEVEL: str = "DEBUG"


class TestingConfig(BaseConfig):
    """Testing configuration used by the test suite."""

    TESTING: bool = True
    DEBUG: bool = True
    WTF_CSRF_ENABLED: bool = False

    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    SESSION_COOKIE_SECURE: bool = False
    REMEMBER_COOKIE_SECURE: bool = False
    RATELIMIT_STORAGE_URL: str = "memory://"
    RATELIMIT_ENABLED: bool = False

    # Suppress mail sending during tests
    MAIL_SUPPRESS_SEND: bool = True


class ProductionConfig(BaseConfig):
    """Production configuration — all security settings enforced."""

    DEBUG: bool = False
    TESTING: bool = False

    # Require a real SECRET_KEY to be set in the environment
    @classmethod
    def init_app(cls, app):  # type: ignore[override]
        BaseConfig.init_app(app) if hasattr(BaseConfig, "init_app") else None
        secret = app.config.get("SECRET_KEY", "")
        if not secret or secret == "change-me-in-production-use-a-long-random-string":
            raise RuntimeError(
                "SECRET_KEY must be set to a strong random value in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )


# -------------------------------------------------------------------------
# Config registry — used by create_app()
# -------------------------------------------------------------------------
config: dict = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
