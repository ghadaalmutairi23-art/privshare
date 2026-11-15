"""University data owner: data sync/import, the student record view, analyst permissions and budgets.

The record view is the ONLY place individual student data leaves the server, and only to
uni_owner. Every view and every revealed national ID is logged (without the data itself).
"""
import io
import math
import os

from flask import Blueprint, current_app, g, jsonify, request, send_file

from .. import budget, crypto, import_templates, ingest, permissions, sis_client, student_store, users
from ..catalog import MAJORS
from ..db import get_db
from ..events import log_event
from ..rbac import require
from ..security import UPLOAD_LIMIT, limiter
from . import json_body

bp = Blueprint("owner", __name__)

MAX_PER_PAGE = 50


# --- getting data in ---

@bp.post("/sync")
@limiter.limit(UPLOAD_LIMIT)
@require("manage_student_data")
def sync():
    cfg = current_app.config
    try:
        rows = sis_client.fetch_all(cfg["SIS_URL"], cfg["SIS_API_KEY"], cfg["SIS_CA_FILE"])
    except sis_client.SISUnavailable as exc:
        log_event(get_db(), "data_sync_failed", g.user["id"], g.user["username"], str(exc))
        return jsonify(error=str(exc)), 502
    db = get_db()
    report = ingest.import_rows(db, rows, "api", None, g.user["id"], cfg["GPA_SCALE"], first_row_number=1)
    log_event(db, "data_sync", g.user["id"], g.user["username"],
              f"ok={report['rows_ok']} rejected={report['rows_rejected']}")
    return jsonify(report=report)


@bp.post("/import")
@limiter.limit(UPLOAD_LIMIT)
@require("manage_student_data")
def import_file():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify(error="Choose a .csv or .xlsx file"), 400
    filename = os.path.basename(upload.filename.replace("\\", "/"))[:100]
    data = upload.stream.read(ingest.MAX_UPLOAD_BYTES + 1)  # in memory only; never saved
    upload.close()
    db = get_db()
    try:
        source, rows = ingest.parse_upload(filename, data)
    except ingest.ImportRejected as exc:
        log_event(db, "data_import_rejected", g.user["id"], g.user["username"], str(exc))
        return jsonify(error=str(exc)), 400
    finally:
        del data
    report = ingest.import_rows(db, rows, source, filename, g.user["id"], current_app.config["GPA_SCALE"])
    log_event(db, "data_import", g.user["id"], g.user["username"],
              f"{source} ok={report['rows_ok']} rejected={report['rows_rejected']}")
    return jsonify(report=report)


@bp.get("/import/template.<fmt>")
@require("manage_student_data")
def template(fmt: str):
    if fmt == "csv":
        return send_file(io.BytesIO(import_templates.csv_bytes()), mimetype="text/csv",
                         as_attachment=True, download_name="sample_students.csv")
    if fmt == "xlsx":
        return send_file(io.BytesIO(import_templates.xlsx_bytes()), as_attachment=True,
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         download_name="sample_students.xlsx")
    return jsonify(error="Unknown template format"), 404


@bp.get("/imports")
@require("manage_student_data")
def import_history():
    db = get_db()
    return jsonify(imports=ingest.history(db), students_total=student_store.count(db))


# --- record view (personal data: owner only, every access logged) ---

def _int_arg(name: str, default: int, lo: int, hi: int) -> int | None:
    raw = request.args.get(name)
    if raw is None:
        return default
    return int(raw) if raw.isdigit() and lo <= int(raw) <= hi else None


@bp.get("/students")
@require("view_student_records")
def students():
    page = _int_arg("page", 1, 1, 100_000)
    per_page = _int_arg("per_page", 20, 1, MAX_PER_PAGE)
    major = request.args.get("major") or None
    year_raw = request.args.get("grad_year")
    grad_year = int(year_raw) if year_raw and year_raw.isdigit() else None
    search = (request.args.get("q") or "").strip()[:100]
    if page is None or per_page is None or (major is not None and major not in MAJORS) \
            or (year_raw and grad_year is None):
        return jsonify(error="Invalid page or filter"), 400

    db = get_db()
    rows, total = student_store.list_page(db, crypto.load_key(), page, per_page, search, major, grad_year)
    # Logged without names, IDs or the search text itself
    log_event(db, "student_records_viewed", g.user["id"], g.user["username"],
              f"page={page} per_page={per_page} major={major or 'all'} year={grad_year or 'all'} "
              f"search={'yes' if search else 'no'} shown={len(rows)}")
    return jsonify(students=rows, page=page, per_page=per_page, total=total)


@bp.get("/students/<int:student_id>/national-id")
@require("view_student_records")
def reveal_national_id(student_id: int):
    db = get_db()
    value = student_store.national_id(db, crypto.load_key(), student_id)
    if value is None:
        return jsonify(error="Student not found"), 404
    log_event(db, "national_id_revealed", g.user["id"], g.user["username"], f"student_id={student_id}")
    return jsonify(national_id=value)


# --- analyst permissions and budgets ---

def _analyst_or_error(db, analyst_id: int):
    user = users.get_by_id(db, analyst_id)
    if user is None:
        return None, (jsonify(error="User not found"), 404)
    if user["role"] != "analyst":
        return None, (jsonify(error="User is not an analyst"), 400)
    return user, None


def _analyst_view(db, user) -> dict:
    perm = permissions.get(db, user["id"])
    return {"id": user["id"], "username": user["username"], "active": bool(user["active"]),
            "permissions": permissions.public(perm) if perm else None, "budget": budget.get(db, user["id"])}


@bp.get("/analysts")
@require("manage_analyst_permissions")
def list_analysts():
    db = get_db()
    rows = db.execute("SELECT * FROM users WHERE role = 'analyst' ORDER BY id").fetchall()
    return jsonify(analysts=[_analyst_view(db, u) for u in rows])


@bp.put("/analysts/<int:analyst_id>/permissions")
@require("manage_analyst_permissions")
def set_permissions(analyst_id: int):
    body = json_body()
    db = get_db()
    user, error = _analyst_or_error(db, analyst_id)
    if error:
        return error
    try:
        clean = permissions.validate(body)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    permissions.save(db, analyst_id, clean)
    log_event(db, "permissions_changed", g.user["id"], g.user["username"],
              f"analyst_id={analyst_id} types={clean['query_types'] or 'all'} majors={len(clean['majors']) or 'all'} "
              f"years={clean['years'] or 'all'} max={clean['max_queries']}")
    return jsonify(analyst=_analyst_view(db, user))


@bp.patch("/analysts/<int:analyst_id>/budget")
@require("manage_analyst_permissions")
def set_budget(analyst_id: int):
    """Set an analyst's total epsilon. Spent epsilon can't be reset (that would undo privacy loss)."""
    body = json_body()
    total = body.get("epsilon_total")
    if isinstance(total, bool) or not isinstance(total, (int, float)) or not math.isfinite(total) \
            or not 0 <= total <= budget.MAX_TOTAL:
        return jsonify(error=f"epsilon_total must be a number between 0 and {budget.MAX_TOTAL:g}"), 400
    db = get_db()
    user, error = _analyst_or_error(db, analyst_id)
    if error:
        return error
    before = budget.get(db, analyst_id)
    budget.set_total(db, analyst_id, float(total))
    log_event(db, "budget_changed", g.user["id"], g.user["username"],
              f"analyst_id={analyst_id} total {before['total'] if before else 0:g}->{float(total):g}")
    return jsonify(analyst=_analyst_view(db, user))
