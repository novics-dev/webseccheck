"""
Scanner service — extensibility entry point.

Importing ``get_all_scanners`` returns a fresh list of all registered scanner
instances.  To add a new scanner, create a module in this package and add it
to ``_SCANNER_CLASSES`` below.
"""

from __future__ import annotations

from app.services.scanner.base import BaseScanner
from app.services.scanner.a01_access_control import A01AccessControlScanner
from app.services.scanner.a02_crypto import A02CryptoScanner
from app.services.scanner.a03_injection import A03InjectionScanner
from app.services.scanner.a04_insecure_design import A04InsecureDesignScanner
from app.services.scanner.a05_security_misconfig import A05SecurityMisconfigScanner
from app.services.scanner.a06_components import A06ComponentsScanner
from app.services.scanner.a07_auth_failures import A07AuthFailuresScanner
from app.services.scanner.a08_integrity import A08IntegrityScanner
from app.services.scanner.a09_logging import A09LoggingScanner
from app.services.scanner.a10_ssrf import A10SSRFScanner

_SCANNER_CLASSES = [
    A01AccessControlScanner,
    A02CryptoScanner,
    A03InjectionScanner,
    A04InsecureDesignScanner,
    A05SecurityMisconfigScanner,
    A06ComponentsScanner,
    A07AuthFailuresScanner,
    A08IntegrityScanner,
    A09LoggingScanner,
    A10SSRFScanner,
]


def get_all_scanners() -> list[BaseScanner]:
    """Return a fresh list of all scanner instances."""
    return [cls() for cls in _SCANNER_CLASSES]


__all__ = ["get_all_scanners", "BaseScanner"]
