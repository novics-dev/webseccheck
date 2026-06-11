"""
SQLAlchemy ORM models for WebSecCheck.

Models
------
User            — application accounts (admin + regular users)
ScanPermission  — explicit consent record required before any scan
Scan            — a single scan execution tied to a permission record
ScanCheck       — individual OWASP check result within a scan
ScanLog         — structured log entries produced during a scan
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import bcrypt
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app import db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(db.Model):
    """Application user account.

    Passwords are stored as bcrypt hashes; plain-text passwords are never
    persisted to the database.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(
        String(254),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------

    def set_password(self, plain_password: str) -> None:
        """Hash *plain_password* with bcrypt and store the result.

        Args:
            plain_password: The raw password supplied by the user.

        Raises:
            ValueError: If an empty password is provided.
        """
        if not plain_password:
            raise ValueError("Password must not be empty.")
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(
            plain_password.encode("utf-8"), salt
        ).decode("utf-8")

    def check_password(self, plain_password: str) -> bool:
        """Return True if *plain_password* matches the stored hash.

        Args:
            plain_password: The raw password to verify.
        """
        if not plain_password or not self.password_hash:
            return False
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            self.password_hash.encode("utf-8"),
        )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    scan_permissions: Mapped[list["ScanPermission"]] = relationship(
        "ScanPermission",
        back_populates="requester_user",
        lazy="dynamic",
        foreign_keys="ScanPermission.requester_email",
        primaryjoin="User.email == ScanPermission.requester_email",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} email={self.email!r} admin={self.is_admin}>"


# ---------------------------------------------------------------------------
# ScanPermission
# ---------------------------------------------------------------------------

class ScanPermission(db.Model):
    """Explicit authorisation record required before a scan may be started.

    A scan must never be initiated without a corresponding ScanPermission row
    where ``explicit_consent`` is ``True``.  The database-level
    ``CheckConstraint`` enforces this invariant independently of application
    logic.
    """

    __tablename__ = "scan_permissions"
    __table_args__ = (
        CheckConstraint("explicit_consent = 1", name="ck_scan_permissions_consent_required"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    requester_email: Mapped[str] = mapped_column(
        String(254),
        nullable=False,
        index=True,
    )
    requester_name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization: Mapped[str] = mapped_column(String(255), nullable=False)
    explicit_consent: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    consent_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv6 max = 39 chars
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="permission",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # Back-reference to User via email (no FK so external requesters are allowed)
    requester_user: Mapped["User | None"] = relationship(
        "User",
        back_populates="scan_permissions",
        foreign_keys=[requester_email],
        primaryjoin="ScanPermission.requester_email == User.email",
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @validates("explicit_consent")
    def _validate_consent(self, _key: str, value: bool) -> bool:
        if value is False:
            raise ValueError(
                "explicit_consent must be True — scans require explicit authorisation."
            )
        return value

    @validates("consent_timestamp")
    def _auto_timestamp(self, _key: str, value: datetime | None) -> datetime:
        # If a timestamp was not provided, default to now when consent is given.
        return value or _utcnow()

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ScanPermission id={self.id} target={self.target_url!r} "
            f"requester={self.requester_email!r}>"
        )


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

    ALL = (PENDING, RUNNING, COMPLETED, FAILED)


class Scan(db.Model):
    """A single scan execution.

    Each scan is associated with a ``ScanPermission`` record and transitions
    through the states defined in ``ScanStatus``.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    permission_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scan_permissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=ScanStatus.PENDING,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    total_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    passed_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warning_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    permission: Mapped["ScanPermission"] = relationship(
        "ScanPermission",
        back_populates="scans",
    )
    checks: Mapped[list["ScanCheck"]] = relationship(
        "ScanCheck",
        back_populates="scan",
        lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="ScanCheck.owasp_category",
    )
    logs: Mapped[list["ScanLog"]] = relationship(
        "ScanLog",
        back_populates="scan",
        lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="ScanLog.timestamp",
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        if value not in ScanStatus.ALL:
            raise ValueError(
                f"Invalid status {value!r}. Must be one of: {ScanStatus.ALL}"
            )
        return value

    @validates("risk_score")
    def _validate_risk_score(self, _key: str, value: float) -> float:
        if not (0.0 <= float(value) <= 100.0):
            raise ValueError("risk_score must be between 0 and 100.")
        return float(value)

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration in seconds, or None if the scan has not finished."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def target_url(self) -> str | None:
        """Shortcut to the permission's target URL."""
        return self.permission.target_url if self.permission else None

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Scan id={self.id} status={self.status!r} "
            f"risk_score={self.risk_score} permission_id={self.permission_id}>"
        )


# ---------------------------------------------------------------------------
# ScanCheck
# ---------------------------------------------------------------------------

class CheckStatus:
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    INFO = "info"

    ALL = (PASS, FAIL, WARNING, INFO)


class CheckSeverity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ALL = (CRITICAL, HIGH, MEDIUM, LOW, INFO)


# OWASP Top 10 2021 category identifiers
OWASP_CATEGORIES = (
    "A01", "A02", "A03", "A04", "A05",
    "A06", "A07", "A08", "A09", "A10",
)


class ScanCheck(db.Model):
    """An individual security check result within a scan.

    ``details`` is stored as JSON text to accommodate arbitrary structured
    evidence without requiring a JSON column (keeps SQLite compatibility).
    """

    __tablename__ = "scan_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    owasp_category: Mapped[str] = mapped_column(
        String(3),
        nullable=False,
        index=True,
    )
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default=CheckStatus.INFO,
    )
    severity: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default=CheckSeverity.INFO,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    _details: Mapped[str | None] = mapped_column(
        "details",
        Text,
        nullable=True,
    )
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    scan: Mapped["Scan"] = relationship("Scan", back_populates="checks")

    # ------------------------------------------------------------------
    # JSON details property
    # ------------------------------------------------------------------

    @property
    def details(self) -> dict | list | None:
        """Deserialise ``details`` from JSON text."""
        if self._details is None:
            return None
        try:
            return json.loads(self._details)
        except (json.JSONDecodeError, TypeError):
            return {"raw": self._details}

    @details.setter
    def details(self, value: dict | list | str | None) -> None:
        """Serialise *value* to JSON text for storage."""
        if value is None:
            self._details = None
        elif isinstance(value, str):
            # Accept pre-serialised JSON strings
            self._details = value
        else:
            self._details = json.dumps(value, default=str)

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        if value not in CheckStatus.ALL:
            raise ValueError(
                f"Invalid check status {value!r}. Must be one of: {CheckStatus.ALL}"
            )
        return value

    @validates("severity")
    def _validate_severity(self, _key: str, value: str) -> str:
        if value not in CheckSeverity.ALL:
            raise ValueError(
                f"Invalid severity {value!r}. Must be one of: {CheckSeverity.ALL}"
            )
        return value

    @validates("owasp_category")
    def _validate_owasp_category(self, _key: str, value: str) -> str:
        if value not in OWASP_CATEGORIES:
            raise ValueError(
                f"Invalid OWASP category {value!r}. Must be one of: {OWASP_CATEGORIES}"
            )
        return value

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ScanCheck id={self.id} category={self.owasp_category!r} "
            f"name={self.check_name!r} status={self.status!r} severity={self.severity!r}>"
        )


# ---------------------------------------------------------------------------
# ScanLog
# ---------------------------------------------------------------------------

class LogLevel:
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    DEBUG = "debug"

    ALL = (INFO, WARNING, ERROR, DEBUG)


class ScanLog(db.Model):
    """Structured log entry produced during a scan execution.

    These entries are written by the Celery task and can be streamed to the
    front-end to provide real-time progress feedback.
    """

    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        index=True,
    )
    level: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default=LogLevel.INFO,
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    step: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    scan: Mapped["Scan"] = relationship("Scan", back_populates="logs")

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @validates("level")
    def _validate_level(self, _key: str, value: str) -> str:
        if value not in LogLevel.ALL:
            raise ValueError(
                f"Invalid log level {value!r}. Must be one of: {LogLevel.ALL}"
            )
        return value

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ScanLog id={self.id} scan_id={self.scan_id} "
            f"level={self.level!r} step={self.step!r} message={self.message[:60]!r}>"
        )
