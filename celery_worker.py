"""
Celery worker entry point for WebSecCheck.

Start the worker with::

    celery -A celery_worker.celery worker --loglevel=info

The Flask app is created here so that init_celery() configures the broker
URL from the environment before any tasks are registered.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Load .env before importing Flask app so config picks up REDIS_URL etc.
load_dotenv()

from app import create_app  # noqa: E402
from app.services.task_runner import celery_app as celery  # noqa: E402

# Create Flask app — this calls init_celery() inside create_app(), which
# sets the broker_url on celery_app from CELERY_BROKER_URL / REDIS_URL.
flask_app = create_app(config_name=os.environ.get("FLASK_ENV", "production"))

# Push app context so tasks can use db, current_app, etc.
flask_app.app_context().push()
