"""Administrator: anomaly alerts and the security event log (no student data in either)."""
import json
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from .. import anomaly
from ..db import get_db
from ..events import log_event
from ..rbac import require
from . import json_body

bp = Blueprint("alerts", __name__)

STATUSES = ("open", "reviewed", "dismissed")
MAX_PER_PAGE = 100


def _alert(r) -> dict:
    return {"id": r["id"], "analyst": r["username"], "analyst_id": r["user_id"], "score": r["score"],
            "threshold": anomaly.threshold(), "detected_by": (r["detected_by"] or "").split(",") if r["detected_by"] else [],
            "reason": r["reason"], "timestamp": r["timestamp"],
            "status": r["status"], "features": json.loads(r["features_json"]) if r["features_json"] else None,
            "reviewed_by": r["reviewer"], "reviewed_at": r["reviewed_at"]}


def _page_args(default_per_page: int):
    page, per = request.args.get("page", "1"), request.args.get("per_page", str(default_per_page))
    if not (page.isdigit() and per.isdigit()) or int(page) < 1 or not 1 <= int(per) <= MAX_PER_PAGE:
        return None
    return int(page), int(per)


@bp.get("/alerts")
@require("view_alerts")
def list_alerts():
    status = request.args.get("status")
    if status is not None and status not in STATUSES:
        return jsonify(error=f"status must be one of {list(STATUSES)}"), 400
    sql = ("SELECT a.*, u.username, r.username AS reviewer FROM alerts a LEFT JOIN users u ON u.id = a.user_id"
           " LEFT JOIN users r ON r.id = a.reviewed_by")
    args = []
    if status:
        sql += " WHERE a.status = ?"
        args.append(status)
    rows = get_db().execute(sql + " ORDER BY a.id DESC LIMIT 200", args).fetchall()
    open_count = get_db().execute("SELECT COUNT(*) FROM alerts WHERE status = 'open'").fetchone()[0]
    return jsonify(alerts=[_alert(r) for r in rows], open=open_count)


@bp.patch("/alerts/<int:alert_id>")
@require("view_alerts")
def update_alert(alert_id: int):
    status = json_body().get("status")
    if status not in ("reviewed", "dismissed"):
        return jsonify(error="status must be 'reviewed' or 'dismissed'"), 400
    db = get_db()
    if db.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        return jsonify(error="Alert not found"), 404
    db.execute("UPDATE alerts SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?",
               (status, g.user["id"], datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), alert_id))
    db.commit()
    log_event(db, f"alert_{status}", g.user["id"], g.user["username"], f"alert_id={alert_id}")
    row = db.execute("SELECT a.*, u.username, r.username AS reviewer FROM alerts a LEFT JOIN users u"
                     " ON u.id = a.user_id LEFT JOIN users r ON r.id = a.reviewed_by WHERE a.id = ?",
                     (alert_id,)).fetchone()
    return jsonify(alert=_alert(row))


@bp.post("/alerts/scan")
@require("view_alerts")
def scan():
    """Check every active analyst's recent behaviour now."""
    db = get_db()
    raised = anomaly.scan_all(db, current_app.config["ANOMALY_WINDOW_MINUTES"])
    log_event(db, "alerts_scanned", g.user["id"], g.user["username"], f"raised={len(raised)}")
    return jsonify(raised=len(raised))


@bp.get("/security-events")
@require("view_alerts")
def security_events():
    paging = _page_args(50)
    if paging is None:
        return jsonify(error="Invalid page"), 400
    page, per_page = paging
    action = request.args.get("action")
    sql, args = "SELECT * FROM security_events", []
    if action:
        sql += " WHERE action = ?"
        args.append(action[:40])
    db = get_db()
    total = db.execute(sql.replace("SELECT *", "SELECT COUNT(*)"), args).fetchone()[0]
    rows = db.execute(sql + " ORDER BY id DESC LIMIT ? OFFSET ?", (*args, per_page, (page - 1) * per_page))
    return jsonify(events=[{"id": r["id"], "timestamp": r["timestamp"], "username": r["username"],
                            "action": r["action"], "detail": r["detail"], "ip": r["ip"]} for r in rows],
                   total=total, page=page, per_page=per_page)
