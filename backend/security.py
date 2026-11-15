"""Web hardening: rate limiting, CSRF, body-size caps, server-side session check (15-minute idle timeout), headers."""
import io

from flask import Flask, Request, current_app, g, jsonify, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect

from . import sessions
from .db import get_db

LOGIN_LIMIT = "5 per minute"
QUERY_LIMIT = "30 per minute"
UPLOAD_LIMIT = "10 per minute"
MAX_BODY_BYTES = 64 * 1024            # everything except the owner's file import
UPLOAD_ENDPOINTS = {"owner.import_file"}

limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()


class InMemoryRequest(Request):
    """Keep uploaded files in memory (bounded by MAX_CONTENT_LENGTH) so they never touch the disk."""

    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return io.BytesIO()


def init_app(app: Flask) -> None:
    app.request_class = InMemoryRequest
    limiter.init_app(app)
    csrf.init_app(app)  # every POST/PUT/PATCH/DELETE needs the X-CSRFToken header
    app.before_request(_limit_body_size)
    app.before_request(_load_session)
    app.after_request(_security_headers)
    app.register_error_handler(CSRFError, lambda e: (jsonify(error="CSRF token missing or invalid"), 400))


def _limit_body_size():
    """Small cap for JSON requests; only the upload endpoint gets the larger MAX_CONTENT_LENGTH."""
    length = request.content_length or 0
    if length > MAX_BODY_BYTES and request.endpoint not in UPLOAD_ENDPOINTS:
        return jsonify(error="Request too large"), 413


def _load_session():
    """Resolve the cookie's token to its server-side row (g.session_row), enforcing expiry."""
    g.session_row = None
    token = session.get("sid")
    if not token:
        return
    db = get_db()
    row = sessions.get(db, token)
    if row is None:  # logged out, deactivated or purged: the cookie is dead
        session.pop("sid", None)
        return
    if sessions.is_expired(row):
        sessions.delete(db, token)
        session.pop("sid", None)
        g.session_expired = row["stage"] == sessions.ACTIVE  # login_required reports "Session expired"
        return
    if row["stage"] == sessions.ACTIVE:
        sessions.touch(db, token)
    g.session_row = row


def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    resp.headers.setdefault("Cache-Control", "no-store")
    if current_app.config.get("SESSION_COOKIE_SECURE"):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp
