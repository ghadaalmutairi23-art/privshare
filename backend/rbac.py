"""Access-control decorators.

The session (server-side), the user's role and active flag are re-read from the database
on every request, so logout, a role change or deactivation take effect immediately.
"""
from functools import wraps

from flask import g, jsonify, session

from . import sessions, users
from .db import get_db
from .events import log_event
from .roles import has_permission


def _current_user():
    """The logged-in user (password AND MFA done, still active), or None."""
    row = g.get("session_row")
    if row is None or row["stage"] != sessions.ACTIVE:
        return None
    db = get_db()
    user = users.get_by_id(db, row["user_id"])
    if user is None or not user["active"]:
        sessions.delete(db, session.pop("sid", None))
        return None
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if user is None:
            msg = "Session expired" if g.get("session_expired") else "Authentication required"
            return jsonify(error=msg), 401
        g.user = user
        return fn(*args, **kwargs)
    return wrapper


def require(permission: str):
    """Allow the call only if the user's role has `permission` (otherwise 403)."""
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if not has_permission(g.user["role"], permission):
                log_event(get_db(), "access_denied", g.user["id"], g.user["username"], permission)
                return jsonify(error="Forbidden"), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
