"""Auditor endpoints: the off-chain audit log, the chain status, and integrity verification."""
from flask import Blueprint, g, jsonify, request

from .. import audit
from ..chain import ChainUnavailable, get_chain
from ..db import get_db
from ..events import log_event
from ..rbac import require

bp = Blueprint("audit", __name__)

MAX_PER_PAGE = 100


@bp.get("/records")
@require("view_audit")
def records():
    page_raw, per_raw = request.args.get("page", "1"), request.args.get("per_page", "25")
    if not (page_raw.isdigit() and per_raw.isdigit()) or int(page_raw) < 1 or not 1 <= int(per_raw) <= MAX_PER_PAGE:
        return jsonify(error="Invalid page"), 400
    rows, total = audit.list_records(get_db(), int(page_raw), int(per_raw))
    return jsonify(records=rows, total=total, page=int(page_raw), per_page=int(per_raw))


@bp.get("/chain")
@require("view_audit")
def chain_info():
    return jsonify(chain=get_chain().info())


@bp.post("/verify")
@require("verify_audit")
def verify():
    """Compare every off-chain record with its on-chain fingerprint."""
    db = get_db()
    try:
        report = audit.verify_all(db, get_chain())
    except ChainUnavailable as exc:
        return jsonify(error=f"Cannot verify: {exc}"), 503
    log_event(db, "audit_verified", g.user["id"], g.user["username"],
              f"checked={report['records_checked']} tampered={report['counts']['tampered']} "
              f"not_on_chain={report['counts']['not_on_chain']} "
              f"orphans={len(report['on_chain_without_record'])}")
    return jsonify(report=report)
