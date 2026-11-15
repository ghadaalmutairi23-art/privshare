"""Login in two steps: password (/login) then TOTP code (/mfa).

Every failure returns the same 401 message so an attacker can't tell which part was wrong.
Each step issues a NEW server-side session token (no session fixation) and a new CSRF token.
"""
from flask import Blueprint, g, jsonify, request, session
from flask_wtf.csrf import generate_csrf

from .. import auth, sessions, users
from ..config import IDLE_TIMEOUT_SECONDS
from ..db import get_db
from ..events import log_event
from ..rbac import login_required
from ..roles import PERMISSIONS
from ..security import LOGIN_LIMIT, limiter
from . import json_body

bp = Blueprint("auth", __name__)

FAIL_MESSAGE = "Invalid credentials"
MAX_MFA_ATTEMPTS = 5


def _start_session(db, user_id: int, stage: str) -> str:
    """End the current session (if any), start a new one and return a fresh CSRF token."""
    sessions.delete(db, session.get("sid"))
    session.clear()
    session.permanent = True
    session["sid"] = sessions.create(db, user_id, stage, request.remote_addr)
    g.pop("csrf_token", None)  # drop the cached token so one is made for the new session
    return generate_csrf()


def _user_info(user) -> dict:
    return {"username": user["username"], "role": user["role"],
            "permissions": sorted(PERMISSIONS[user["role"]]),
            "idle_timeout_seconds": IDLE_TIMEOUT_SECONDS}


@bp.get("/csrf")
def csrf_token():
    return jsonify(csrf_token=generate_csrf())


@bp.post("/login")
@limiter.limit(LOGIN_LIMIT)
def login():
    body = json_body()
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    db = get_db()

    user = users.get_by_username(db, username) if username else None
    if user is None:
        auth.burn_verify(password)
        ok = False
    else:
        ok = auth.verify_password(user["pw_hash"], password) and bool(user["active"])
    if not ok:
        log_event(db, "login_failed", user["id"] if user else None, username)
        return jsonify(error=FAIL_MESSAGE), 401

    token = _start_session(db, user["id"], sessions.PENDING)
    log_event(db, "login_password_ok", user["id"], user["username"])
    return jsonify(mfa_required=True, csrf_token=token)


@bp.post("/mfa")
@limiter.limit(LOGIN_LIMIT)
def mfa():
    body = json_body()
    row = g.get("session_row")
    if row is None or row["stage"] != sessions.PENDING:  # no password step, or it expired
        return jsonify(error=FAIL_MESSAGE), 401

    db = get_db()
    sid = session["sid"]
    user = users.get_by_id(db, row["user_id"])
    if (user is None or not user["active"]
            or not auth.verify_totp(users.totp_secret(user), str(body.get("code", "")))):
        log_event(db, "mfa_failed", row["user_id"], user["username"] if user else None)
        if sessions.add_mfa_failure(db, sid) >= MAX_MFA_ATTEMPTS:
            sessions.delete(db, sid)  # must start again with the password
            session.clear()
        return jsonify(error=FAIL_MESSAGE), 401

    token = _start_session(db, user["id"], sessions.ACTIVE)
    log_event(db, "login_success", user["id"], user["username"])
    return jsonify(user=_user_info(user), csrf_token=token)


@bp.post("/logout")
def logout():
    row = g.get("session_row")
    db = get_db()
    if row is not None:
        log_event(db, "logout", row["user_id"])
    sessions.delete(db, session.get("sid"))
    session.clear()
    return jsonify(ok=True)


@bp.get("/me")
@login_required
def me():
    return jsonify(user=_user_info(g.user))
