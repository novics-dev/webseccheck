"""
Flask-Login integration for the User model.

Provides:
- ``AuthenticatedUser`` — a ``UserMixin`` wrapper around the ``User`` ORM model
  that satisfies Flask-Login's interface.
- ``load_user`` — the user-loader callback registered with the ``LoginManager``.

Usage in the app factory::

    from app.models.user import load_user
    login_manager.user_loader(load_user)
"""

from __future__ import annotations

from flask_login import UserMixin

from app.models.models import User


class AuthenticatedUser(UserMixin):
    """Thin Flask-Login ``UserMixin`` wrapper around the ``User`` ORM model.

    Flask-Login requires ``is_authenticated``, ``is_active``,
    ``is_anonymous``, and ``get_id()``; ``UserMixin`` provides sensible
    defaults for all of them.  This class delegates every attribute lookup
    to the underlying ``User`` instance so that templates and views can use
    ``current_user.email``, ``current_user.is_admin``, etc., directly.
    """

    def __init__(self, user: User) -> None:
        self._user = user

    # ------------------------------------------------------------------
    # Flask-Login required interface
    # ------------------------------------------------------------------

    def get_id(self) -> str:
        """Return the user's primary key as a string (Flask-Login contract)."""
        return str(self._user.id)

    @property
    def is_active(self) -> bool:
        """All User records are considered active (no soft-delete yet)."""
        return True

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    # ------------------------------------------------------------------
    # Delegate attribute access to the underlying ORM model
    # ------------------------------------------------------------------

    def __getattr__(self, name: str):
        # Avoid infinite recursion for private/dunder names
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._user, name)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuthenticatedUser {self._user!r}>"


# ---------------------------------------------------------------------------
# Flask-Login user loader
# ---------------------------------------------------------------------------

def load_user(user_id: str) -> AuthenticatedUser | None:
    """Load a user from the database by primary key.

    Flask-Login calls this callback on every request that requires an
    authenticated user.  The *user_id* argument is the string returned by
    ``AuthenticatedUser.get_id()``.

    Args:
        user_id: String representation of the user's integer primary key.

    Returns:
        An ``AuthenticatedUser`` instance if found, otherwise ``None``.
    """
    try:
        pk = int(user_id)
    except (TypeError, ValueError):
        return None

    user = User.query.get(pk)
    if user is None:
        return None
    return AuthenticatedUser(user)
