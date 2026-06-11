import time
import requests
from abc import ABC, abstractmethod
from datetime import datetime, timezone


class BaseScanner(ABC):

    @property
    @abstractmethod
    def category(self) -> str:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @abstractmethod
    def run(self, target_url: str, scan_id: int, db_session) -> list:
        pass

    def log(self, scan_id: int, message: str, level: str = 'info', step: str = '', db_session=None):
        """Save a ScanLog entry to DB."""
        if db_session is None:
            return
        try:
            from app.models import ScanLog
            log_entry = ScanLog(
                scan_id=scan_id,
                level=level,
                message=message,
                step=step,
                timestamp=datetime.now(timezone.utc)
            )
            db_session.add(log_entry)
            db_session.commit()
        except Exception:
            try:
                db_session.rollback()
            except Exception:
                pass

    def make_request(self, url: str, method: str = 'GET', timeout: int = 10,
                     headers: dict = None, verify_ssl: bool = True,
                     data=None, allow_redirects: bool = True):
        """Make a safe HTTP request. Returns response or None."""
        default_headers = {
            'User-Agent': 'WebSecCheck Security Scanner/1.0'
        }
        if headers:
            default_headers.update(headers)
        try:
            response = requests.request(
                method=method,
                url=url,
                timeout=timeout,
                headers=default_headers,
                verify=verify_ssl,
                data=data,
                allow_redirects=allow_redirects
            )
            return response
        except requests.exceptions.SSLError:
            # Retry without SSL verification
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    timeout=timeout,
                    headers=default_headers,
                    verify=False,
                    data=data,
                    allow_redirects=allow_redirects
                )
                return response
            except Exception:
                return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.TooManyRedirects:
            return None
        except Exception:
            return None

    def create_check(self, owasp_category: str, check_name: str, status: str,
                     severity: str, description: str, details: str = None,
                     remediation: str = '', evidence: str = '',
                     duration_ms: int = 0) -> dict:
        """Create a dict matching ScanCheck model fields."""
        return {
            'owasp_category': owasp_category,
            'check_name': check_name,
            'status': status,           # 'pass', 'fail', 'warning', 'info', 'error'
            'severity': severity,       # 'critical', 'high', 'medium', 'low', 'info'
            'description': description,
            'details': details or '',
            'remediation': remediation,
            'evidence': evidence,
            'duration_ms': duration_ms,
        }
