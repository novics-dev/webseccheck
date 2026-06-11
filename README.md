# WebSecCheck — OWASP Top 10 Security Testing Platform

A self-hosted web application for conducting authorized OWASP Top 10 security assessments. Built with security-first principles, explicit consent enforcement, and full audit trails.

---

## Features

- **OWASP Top 10 Coverage** — Automated checks for A01–A10 (2021 edition)
- **Consent-First Workflow** — Permission form with explicit authorization required before any test runs
- **Audit Trail** — Every permission, scan, and log step is persisted to the database
- **Reports** — In-browser HTML report + downloadable PDF + email delivery
- **Admin Interface** — Full dashboard for managing scans, permissions, and users
- **Extensible** — Add new scanners by dropping a module into `app/services/scanner/`
- **Hardened Deployment** — Nginx reverse proxy, TLS 1.2/1.3, security headers, rate limiting, systemd services

---

## Requirements

- Ubuntu 24.04 LTS
- Python 3.12
- Redis (for Celery async worker)
- Nginx
- SSL certificate (self-signed or CA-issued)

---

## Quick Install

```bash
git clone https://github.com/novics-dev/webseccheck.git
cd webseccheck
sudo bash install.sh
```

The installer will:
1. Install system dependencies (Python 3.12, Redis, Nginx)
2. Create a dedicated `webseccheck` system user
3. Set up the Python virtual environment
4. Initialize the SQLite database
5. Prompt you to create the first admin user
6. Install and enable systemd services
7. Configure Nginx

---

## SSL Certificate Setup

Generate a self-signed certificate (or use your own CA-signed certificate):

```bash
mkdir -p /etc/ssl/webseccheck

openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/ssl/webseccheck/key.pem \
  -out    /etc/ssl/webseccheck/cert.pem \
  -subj   "/CN=YOUR_DOMAIN_OR_IP"

chown root:webseccheck /etc/ssl/webseccheck/key.pem
chmod 640 /etc/ssl/webseccheck/key.pem
```

---

## Environment Variables

Edit `/opt/webseccheck/.env` after installation:

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Flask secret key (auto-generated on install) |
| `FLASK_ENV` | Yes | `production` or `development` |
| `DATABASE_URL` | No | SQLite path (default: `sqlite:///webseccheck.db`) |
| `REDIS_URL` | No | Redis URL (default: `redis://localhost:6379/0`) |
| `MAIL_SERVER` | Yes (for email) | SMTP server hostname |
| `MAIL_PORT` | No | SMTP port (default: 587) |
| `MAIL_USE_TLS` | No | `true` / `false` (default: `true`) |
| `MAIL_USERNAME` | Yes (for email) | SMTP username |
| `MAIL_PASSWORD` | Yes (for email) | SMTP password |
| `MAIL_DEFAULT_SENDER` | No | From address for outgoing emails |
| `APP_DOMAIN` | No | Public domain name for links in emails |
| `ALLOWED_HOSTS` | No | Comma-separated allowed hostnames |
| `LOG_LEVEL` | No | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Starting Services

```bash
systemctl start webseccheck webseccheck-celery
systemctl status webseccheck
```

Access the application at `https://YOUR_DOMAIN`.

---

## Usage

1. **New Scan** — Navigate to the home page, fill in the target URL, your details, and check the explicit consent box.
2. **Permission Saved** — A confirmation email is sent. The permission record is stored with timestamp and IP.
3. **Start Test** — Click "Start Security Scan" to queue the scan.
4. **Monitor** — The status page shows live progress and log output.
5. **Report** — View the HTML report or download the PDF. The report is also emailed.

---

## Admin Interface

Access `/admin/` with your admin credentials.

- **Dashboard** — Stats and recent scans
- **Scans** — Browse and manage all scan records
- **Permissions** — Audit trail of all consent records
- **Users** — Manage admin accounts
- **Logs** — System-wide log viewer with filtering
- **Settings** — Configuration overview and scanner module list

---

## Adding New Scanners

WebSecCheck is designed to be extensible. To add a new scanner:

1. Create `app/services/scanner/aXX_your_scanner.py`
2. Extend `BaseScanner` from `app/services/scanner/base.py`
3. Implement the `run(target_url, scan_id, db_session)` method
4. Register it in `app/services/scanner/__init__.py` → `_SCANNER_CLASSES`

```python
# app/services/scanner/aXX_example.py
from .base import BaseScanner

class AXXExampleScanner(BaseScanner):
    category = "AXX"
    name = "Example Check"
    description = "Demonstrates how to add a new scanner."

    def run(self, target_url, scan_id, db_session):
        self.log(scan_id, "Starting example check", "info", "AXX", db_session)
        resp = self.make_request(target_url)
        # ... perform check ...
        return [self.create_check(
            owasp_category="AXX",
            check_name="Example Check",
            status="pass",
            severity="info",
            description="The example check passed.",
            remediation="No action required.",
        )]
```

---

## Security Design Notes

- All user inputs validated server-side; Jinja2 autoescaping prevents XSS
- CSRF protection on all state-changing forms (Flask-WTF)
- Rate limiting on all endpoints (Flask-Limiter + Nginx)
- SSRF prevention: target URL is validated to block internal/private IP ranges
- Passwords hashed with bcrypt (min 12 characters enforced)
- Security headers set via Flask-Talisman and Nginx
- Sensitive `.env` file is `chmod 600`, owned by service user
- Systemd services run as non-root with `NoNewPrivileges=true`

---

## License

This project is intended for authorized security testing only. Users are solely responsible for ensuring they have proper authorization before testing any target.
