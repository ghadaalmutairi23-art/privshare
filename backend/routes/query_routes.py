"""Analyst endpoints: query options, remaining budget, and running whitelisted queries."""
import json

from flask import Blueprint, current_app, g, jsonify

from .. import analytics, budget, permissions, settings
from ..catalog import QUERY_TYPES
from ..chain import get_chain
from ..config import K_MIN
from ..db import get_db
from ..events import log_event
from ..rbac import require
from ..security import QUERY_LIMIT, limiter
from . import json_body

bp = Blueprint("query", __name__)


def _policy(db) -> analytics.Policy:
    cfg = current_app.config
    return analytics.Policy(k_min=K_MIN, epsilon_min=cfg["EPSILON_MIN"], epsilon_max=cfg["EPSILON_MAX"],
                            gpa_scale=settings.gpa_scale(db, cfg["GPA_SCALE"]))


@bp.get("/options")
@require("run_query")
def options():
    """What this analyst may ask: the whitelist and filter values narrowed by their permissions."""
    db = get_db()
    policy = _policy(db)
    perm = permissions.get(db, g.user["id"]) or {"query_types": [], "majors": [], "years": []}
    filters = analytics.available_filters(db)
    if perm["majors"]:
        filters["major"] = [m for m in filters["major"] if m in perm["majors"]]
    if perm["years"]:
        filters["grad_year"] = [y for y in filters["grad_year"] if y in perm["years"]]
    return jsonify(
        query_types=[{"name": n, "label": label} for n, label in QUERY_TYPES.items()
                     if not perm["query_types"] or n in perm["query_types"]],
        filters=filters,
        # With a restriction the filter is required (a query over "all" would include disallowed groups)
        required_filters=[f for f, key in (("major", "majors"), ("grad_year", "years")) if perm[key]],
        epsilon={"min": policy.epsilon_min, "max": policy.epsilon_max},
        gpa_scale=policy.gpa_scale,
    )


@bp.get("/permissions")
@require("view_own_permissions")
def my_permissions():
    db = get_db()
    perm = permissions.get(db, g.user["id"])
    return jsonify(permissions=permissions.public(perm) if perm else None, budget=budget.get(db, g.user["id"]))


@bp.get("/budget")
@require("view_budget")
def get_budget():
    b = budget.get(get_db(), g.user["id"])
    if b is None:
        return jsonify(error="No privacy budget assigned"), 404
    return jsonify(budget=b)


@bp.post("")
@limiter.limit(QUERY_LIMIT)
@require("run_query")
def run():
    body = json_body()
    db = get_db()
    try:
        result = analytics.run_query(db, get_chain(), _policy(db), g.user["id"],
                                     body.get("query_type"), body.get("filters"), body.get("epsilon"))
    except analytics.QueryRefused as exc:
        # Kept for anomaly detection (Phase 4): what was asked and why it was refused, no data
        detail = json.dumps({"query_type": str(body.get("query_type"))[:40], "filters": body.get("filters"),
                             "epsilon": body.get("epsilon"), "reason": exc.reason}, default=str)[:500]
        log_event(db, "query_rejected", g.user["id"], g.user["username"], detail)
        return jsonify(error=exc.message), exc.status
    return jsonify(result)
