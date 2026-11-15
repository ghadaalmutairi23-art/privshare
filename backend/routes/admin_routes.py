"""User management for the System Administrator (no access to student data).

Budgets are shown read-only; the university data owner sets them (/api/owner/analysts/...).
"""
from flask import Blueprint, current_app, g, jsonify

from .. import auth, budget, sessions, users
from ..db import get_db
from ..events import log_event
from ..rbac import require
from . import json_body

bp = Blueprint("admin", __name__)


def _with_budget(db, user: dict) -> dict:
    user["budget"] = budget.get(db, user["id"]) if user["role"] == "analyst" else None
    return user


@bp.get("/users")
@require("manage_users")
def list_users():
    db = get_db()
    return jsonify(users=[_with_budget(db, u) for u in users.list_users(db)])


@bp.post("/users")
@require("manage_users")
def create_user():
    body = json_body()
    username = str(body.get("username", ""))
    role = str(body.get("role", ""))
    db = get_db()
    try:
        user_id, secret = users.create_user(db, username, str(body.get("password", "")), role,
                                            current_app.config["EPSILON_TOTAL_DEFAULT"])
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    log_event(db, "user_created", g.user["id"], g.user["username"], f"user_id={user_id} role={role}")
    # The TOTP URI is returned once so the new user can enrol their authenticator app
    return jsonify(user=_with_budget(db, users.public(users.get_by_id(db, user_id))),
                   totp_uri=auth.totp_uri(secret, username)), 201


@bp.patch("/users/<int:user_id>")
@require("manage_users")
def update_user(user_id: int):
    body = json_body()
    db = get_db()
    target = users.get_by_id(db, user_id)
    if target is None:
        return jsonify(error="User not found"), 404
    if user_id == g.user["id"]:
        return jsonify(error="Administrators cannot change their own role or status"), 400
    if "role" not in body and "active" not in body:
        return jsonify(error="Nothing to update (role, active)"), 400
    if "active" in body and not isinstance(body["active"], bool):
        return jsonify(error="active must be true or false"), 400

    if "role" in body:
        try:
            users.set_role(db, user_id, str(body["role"]), current_app.config["EPSILON_TOTAL_DEFAULT"])
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        log_event(db, "user_role_changed", g.user["id"], g.user["username"],
                  f"user_id={user_id} {target['role']}->{body['role']}")
    if "active" in body:
        users.set_active(db, user_id, body["active"])
        if not body["active"]:
            sessions.delete_for_user(db, user_id)  # log the user out everywhere
        log_event(db, "user_activated" if body["active"] else "user_deactivated",
                  g.user["id"], g.user["username"], f"user_id={user_id}")
    return jsonify(user=_with_budget(db, users.public(users.get_by_id(db, user_id))))
