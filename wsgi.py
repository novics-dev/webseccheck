"""
WSGI entry point for WebSecCheck.

Used by Gunicorn in production::

    gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:app

or during development::

    flask --app wsgi:app run
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Load .env file before the app is created so all env vars are available.
load_dotenv()

from app import create_app  # noqa: E402 — must come after load_dotenv

app = create_app(config_name=os.environ.get("FLASK_ENV", "production"))

if __name__ == "__main__":
    # Allows `python wsgi.py` for quick local testing (not for production).
    app.run(host="127.0.0.1", port=5000, debug=False)
