"""
Celery application and scan task runner.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from celery import Celery

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Celery app — configured lazily from Flask app config
# ---------------------------------------------------------------------------

celery_app = Celery("webseccheck")


def init_celery(flask_app):
    """Configure Celery using Flask app settings."""
    celery_app.conf.update(
        broker_url=flask_app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=flask_app.config.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
        task_serializer=flask_app.config.get("CELERY_TASK_SERIALIZER", "json"),
        result_serializer=flask_app.config.get("CELERY_RESULT_SERIALIZER", "json"),
        accept_content=flask_app.config.get("CELERY_ACCEPT_CONTENT", ["json"]),
        timezone=flask_app.config.get("CELERY_TIMEZONE", "UTC"),
        enable_utc=flask_app.config.get("CELERY_ENABLE_UTC", True),
        task_soft_time_limit=flask_app.config.get("CELERY_TASK_SOFT_TIME_LIMIT", 300),
        task_time_limit=flask_app.config.get("CELERY_TASK_TIME_LIMIT", 360),
        # Match the queue name the worker listens on (--queues=default)
        task_default_queue="default",
    )

    class ContextTask(celery_app.Task):
        def __call__(self, *args, **kwargs):
            with flask_app.app_context():
                return self.run(*args, **kwargs)

    celery_app.Task = ContextTask
    return celery_app


# ---------------------------------------------------------------------------
# Helper: calculate risk score
# ---------------------------------------------------------------------------

def _calculate_risk_score(checks) -> float:
    """Calculate 0-100 risk score weighted by severity of failed/warning checks."""
    weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 0,
    }
    total_weight = 0
    for check in checks:
        if check.status in ("fail", "warning"):
            severity = check.severity or "info"
            total_weight += weights.get(severity, 0)

    # Normalise to 0-100 (cap at 100)
    return min(total_weight, 100)


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------

@celery_app.task(bind=True, name="webseccheck.run_scan", max_retries=1)
def run_scan(self, scan_id: int):
    """Main scan execution task.

    1. Marks scan as 'running'
    2. Runs all OWASP scanners
    3. Saves ScanCheck results
    4. Calculates risk score
    5. Updates scan status to 'completed' (or 'failed')
    6. Sends report email
    """
    from app import db
    from app.models import Scan, ScanCheck, ScanLog, ScanStatus
    from app.services.scanner import get_all_scanners

    try:
        scan = Scan.query.get(scan_id)
        if not scan:
            logger.error("Scan %d not found", scan_id)
            return

        # Mark as running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()

        target_url = scan.permission.target_url
        logger.info("Starting scan %d for %s", scan_id, target_url)

        scanners = get_all_scanners()
        all_check_dicts = []

        for scanner in scanners:
            logger.info("Running scanner: %s (%s)", scanner.name, scanner.category)
            try:
                check_dicts = scanner.run(target_url, scan_id, db.session)
                all_check_dicts.extend(check_dicts or [])
            except Exception as exc:
                logger.exception("Scanner %s failed: %s", scanner.category, exc)
                # Log the failure but continue with other scanners
                try:
                    from app.models import ScanLog, LogLevel
                    error_log = ScanLog(
                        scan_id=scan_id,
                        level=LogLevel.ERROR,
                        message=f"Scanner {scanner.category} failed: {exc}",
                        step=scanner.category,
                        timestamp=datetime.now(timezone.utc),
                    )
                    db.session.add(error_log)
                    db.session.commit()
                except Exception:
                    db.session.rollback()

        # Save all ScanCheck results
        saved_checks = []
        for check_dict in all_check_dicts:
            try:
                check = ScanCheck(
                    scan_id=scan_id,
                    owasp_category=check_dict["owasp_category"],
                    check_name=check_dict["check_name"],
                    status=check_dict["status"],
                    severity=check_dict["severity"],
                    description=check_dict["description"],
                    remediation=check_dict.get("remediation", ""),
                    evidence=check_dict.get("evidence", ""),
                    duration_ms=check_dict.get("duration_ms", 0),
                )
                check.details = check_dict.get("details")
                db.session.add(check)
                saved_checks.append(check)
            except Exception as exc:
                logger.warning("Failed to save check %s: %s", check_dict.get("check_name"), exc)
                db.session.rollback()

        db.session.commit()

        # Update scan statistics
        total = len(saved_checks)
        passed = sum(1 for c in saved_checks if c.status == "pass")
        failed = sum(1 for c in saved_checks if c.status == "fail")
        warnings = sum(1 for c in saved_checks if c.status == "warning")
        risk = _calculate_risk_score(saved_checks)

        scan.total_checks = total
        scan.passed_checks = passed
        scan.failed_checks = failed
        scan.warning_checks = warnings
        scan.risk_score = risk
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        db.session.commit()

        logger.info(
            "Scan %d completed: %d checks, %d failed, risk=%.1f",
            scan_id, total, failed, risk
        )

        # Send report email (best-effort)
        try:
            from app.services.email_service import send_scan_report
            send_scan_report(scan)
        except Exception as exc:
            logger.warning("Could not send scan report email: %s", exc)

    except Exception as exc:
        logger.exception("Scan %d failed with exception: %s", scan_id, exc)
        try:
            from app import db
            from app.models import Scan, ScanStatus, ScanLog, LogLevel
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.now(timezone.utc)
                error_log = ScanLog(
                    scan_id=scan_id,
                    level=LogLevel.ERROR,
                    message=f"Scan failed with error: {exc}",
                    step="task_runner",
                    timestamp=datetime.now(timezone.utc),
                )
                db.session.add(error_log)
                db.session.commit()
        except Exception as inner_exc:
            logger.exception("Could not mark scan as failed: %s", inner_exc)
        raise
