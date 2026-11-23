"""Dual-party approval of query types (university owner + partner representative).

Each side approves or revokes only its own side. The change is written to the chain first
(the contract is the authority); the query_types table is a mirror for the dashboard.
Fails closed if the chain is down.
"""
from flask import Blueprint, g, jsonify

from ..catalog import QUERY_TYPES
from ..chain import ChainError, ChainUnavailable, get_chain
from ..db import get_db
from ..events import log_event
from ..rbac import login_required, require
from ..roles import has_permission

bp = Blueprint("approvals", __name__)

# permission -> (party name on-chain, mirror column). Column names are fixed, never user input.
SIDES = {
    "approve_query_type_uni": ("university", "approved_uni"),
    "approve_query_type_partner": ("partner", "approved_partner"),
}


def _row(r) -> dict:
    return {"name": r["name"], "label": QUERY_TYPES.get(r["name"], r["name"]),
            "approved_uni": bool(r["approved_uni"]), "approved_partner": bool(r["approved_partner"]),
            "approved": bool(r["approved_uni"] and r["approved_partner"])}


@bp.get("/query-types")
@require("view_query_types")
def list_query_types():
    """Approval status read from the contract (the authority); the DB mirror is refreshed from it.
    If the node is down, the last known mirror is shown and `chain_available` is false."""
    db = get_db()
    chain_available = True
    try:
        for name in QUERY_TYPES:
            uni, partner = get_chain().approval_status(name)
            db.execute("UPDATE query_types SET approved_uni = ?, approved_partner = ? WHERE name = ?",
                       (int(uni), int(partner), name))
        db.commit()
    except ChainUnavailable:
        chain_available = False
    rows = db.execute("SELECT * FROM query_types ORDER BY id").fetchall()
    return jsonify(query_types=[_row(r) for r in rows if r["name"] in QUERY_TYPES],
                   chain_available=chain_available)


def _set_approval(name: str, approve: bool):
    """Approve or revoke the caller's own side, on-chain first, then in the mirror table."""
    db = get_db()
    side = next((s for perm, s in SIDES.items() if has_permission(g.user["role"], perm)), None)
    if side is None:
        log_event(db, "access_denied", g.user["id"], g.user["username"], "approve_query_type")
        return jsonify(error="Forbidden"), 403
    if name not in QUERY_TYPES:
        return jsonify(error="Unknown query type"), 404

    party, column = side
    chain = get_chain()
    try:
        tx_hash = chain.approve(name, party) if approve else chain.revoke(name, party)
    except ChainUnavailable:
        return jsonify(error="Blockchain unavailable; change not recorded"), 503
    except ChainError:
        return jsonify(error="Rejected by the smart contract"), 403
    db.execute(f"UPDATE query_types SET {column} = ? WHERE name = ?", (1 if approve else 0, name))
    db.commit()
    action = "query_type_approved" if approve else "query_type_revoked"
    log_event(db, action, g.user["id"], g.user["username"], f"{name} by {party} tx={tx_hash}")
    row = db.execute("SELECT * FROM query_types WHERE name = ?", (name,)).fetchone()
    return jsonify(query_type=_row(row), tx_hash=tx_hash)


@bp.post("/query-types/<name>/approve")
@login_required
def approve(name: str):
    return _set_approval(name, approve=True)


@bp.post("/query-types/<name>/revoke")
@login_required
def revoke(name: str):
    return _set_approval(name, approve=False)
