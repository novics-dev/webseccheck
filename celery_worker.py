"""
Celery worker entry point for WebSecCheck.

Start the worker with::

    celery -A celery_worker.celery worker --loglevel=info

Or with concurrency tuning::

    celery -A celery_worker.celery worker --loglevel=info --concurrency=4

The Flask application context is pushed before tasks run, giving Celery
tasks access to ``db``, ``app.config``, and all Flask extensions.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Load environment variables before anything else.
load_dotenv()

from app import create_app  # noqa: E402
from app.services.task_runner import celery  # noqa: E402  — imports the Celery instance

# Create the Flask app so all extensions (db, mail, etc.) are configured.
# The Celery instance in task_runner is already bound to this app via the
# factory pattern — we just need to ensure the app is created once here.
flask_app = create_app(config_name=os.environ.get("FLASK_ENV", "production"))

# Push an application context so tasks that touch the database work correctly
# when the worker process starts up.
flask_app.app_context().push()
