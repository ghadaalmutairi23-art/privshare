"""Bringing student data in: row validation, CSV/Excel parsing and the import transaction.

Used by both the file import and the university-system sync. Bad rows are skipped and
reported (row, column, problem); good rows are encrypted and upserted by student number.
Uploaded files are parsed from memory and never written to disk.
"""
import io
import math
import re
import sqlite3
import zipfile

import pandas as pd

from . import crypto, settings, student_store
from .catalog import MAJORS, MAX_GRAD_YEAR, MIN_GRAD_YEAR

COLUMNS = ("student_no", "name", "national_id", "major", "gpa", "grad_year", "coop_completed")
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_UNZIPPED_BYTES = 50 * 1024 * 1024   # zip-bomb guard for .xlsx
MAX_ROWS = 20_000
MAX_REPORTED = 200                      # rejected rows listed in one report

STUDENT_NO_RE = re.compile(r"^[A-Za-z0-9-]{4,20}$")
NATIONAL_ID_RE = re.compile(r"^[12]\d{9}$")      # Saudi ID: 10 digits, starts with 1 or 2
TRUE_WORDS, FALSE_WORDS = {"1", "true", "yes", "y"}, {"0", "false", "no", "n"}


class ImportRejected(Exception):
    """The whole file is unusable (wrong type, missing columns, too big ...)."""


def _text(value) -> str:
    return "" if value is None else str(value).strip()


def _intlike(value: str) -> str:
    """Excel may hand back 2024 as '2024.0'."""
    return value[:-2] if value.endswith(".0") else value


def validate_row(raw: dict, gpa_scale: float) -> tuple[dict | None, list[tuple[str, str]]]:
    """Return (clean student, []) or (None, [(column, problem), ...]). Problems never echo IDs or names."""
    errors = []
    student_no = _intlike(_text(raw.get("student_no")))
    if not STUDENT_NO_RE.match(student_no):
        errors.append(("student_no", "Must be 4-20 letters, digits or '-'"))

    name = " ".join(_text(raw.get("name")).split())
    if not 2 <= len(name) <= 100 or any(ord(c) < 32 for c in name):
        errors.append(("name", "Must be 2-100 characters"))

    national_id = _intlike(_text(raw.get("national_id")))
    if not NATIONAL_ID_RE.match(national_id):
        errors.append(("national_id", "Must be 10 digits starting with 1 or 2"))

    major = _text(raw.get("major"))
    if major not in MAJORS:
        errors.append(("major", "Unknown major" if major else "Missing"))

    gpa = None
    try:
        gpa = float(_text(raw.get("gpa")).replace(",", "."))
        if not math.isfinite(gpa) or not 0 <= gpa <= gpa_scale:
            errors.append(("gpa", f"Must be between 0 and {gpa_scale:g} (current GPA scale)"))
    except ValueError:
        errors.append(("gpa", "Not a number"))

    grad_year = None
    try:
        grad_year = int(_intlike(_text(raw.get("grad_year"))))
        if not MIN_GRAD_YEAR <= grad_year <= MAX_GRAD_YEAR:
            errors.append(("grad_year", f"Must be between {MIN_GRAD_YEAR} and {MAX_GRAD_YEAR}"))
    except ValueError:
        errors.append(("grad_year", "Not a year"))

    coop_word = _intlike(_text(raw.get("coop_completed"))).lower()
    if coop_word not in TRUE_WORDS | FALSE_WORDS:
        errors.append(("coop_completed", "Must be yes/no, true/false or 1/0"))

    if errors:
        return None, errors
    return {"student_no": student_no, "name": name, "national_id": national_id, "major": major,
            "gpa": round(gpa, 2), "grad_year": grad_year, "coop_completed": coop_word in TRUE_WORDS}, []


def parse_upload(filename: str, data: bytes) -> tuple[str, list[dict]]:
    """Read a .csv or .xlsx upload from memory. Returns (source, rows as dicts with COLUMNS keys)."""
    name = (filename or "").lower()
    if len(data) > MAX_UPLOAD_BYTES:
        raise ImportRejected(f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if not data:
        raise ImportRejected("File is empty")

    try:
        if name.endswith(".csv"):
            source = "csv"
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = data.decode("cp1256")  # Arabic Windows Excel exports
            frame = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False)
        elif name.endswith(".xlsx"):
            source = "excel"
            if not data.startswith(b"PK\x03\x04"):
                raise ImportRejected("Not a valid .xlsx file")
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if sum(i.file_size for i in zf.infolist()) > MAX_UNZIPPED_BYTES:
                    raise ImportRejected("Workbook is too large when unpacked")
            frame = pd.read_excel(io.BytesIO(data), dtype=str, engine="openpyxl", keep_default_na=False)
        else:
            raise ImportRejected("Only .csv and .xlsx files are accepted")
    except ImportRejected:
        raise
    except Exception as exc:  # malformed CSV / workbook
        raise ImportRejected("The file could not be read") from exc

    frame.columns = [str(c).strip().lower() for c in frame.columns]
    missing = [c for c in COLUMNS if c not in frame.columns]
    if missing:
        raise ImportRejected("Missing columns: " + ", ".join(missing))
    if len(frame) > MAX_ROWS:
        raise ImportRejected(f"More than {MAX_ROWS} rows")
    return source, frame[list(COLUMNS)].to_dict(orient="records")


def import_rows(db: sqlite3.Connection, rows: list[dict], source: str, filename: str | None,
                user_id: int, fallback_scale: float, first_row_number: int = 2) -> dict:
    """Validate, encrypt and upsert rows in one transaction, record a data_imports entry.

    `first_row_number` maps list index 0 to a spreadsheet row (2 = first row under the header).
    Returns the report shown to the owner.
    """
    key = crypto.load_key()
    scale = settings.gpa_scale(db, fallback_scale)
    report = {"rows_total": 0, "added": 0, "updated": 0, "rows_rejected": 0, "rejected": []}
    seen = set()

    db.execute("BEGIN IMMEDIATE")
    try:
        for i, raw in enumerate(rows):
            if not any(_text(v) for v in raw.values()):
                continue  # blank line
            report["rows_total"] += 1
            clean, errors = validate_row(raw, scale)
            if clean and clean["student_no"] in seen:
                errors = [("student_no", "Duplicate student number in this file")]
            if errors:
                report["rows_rejected"] += 1
                if len(report["rejected"]) < MAX_REPORTED:
                    report["rejected"].extend({"row": i + first_row_number, "column": c, "problem": p}
                                              for c, p in errors)
                continue
            seen.add(clean["student_no"])
            report[student_store.upsert(db, clean, key)] += 1

        if settings.get(db, settings.GPA_SCALE_KEY) is None:
            settings.put(db, settings.GPA_SCALE_KEY, str(scale))
        report["rows_ok"] = report["added"] + report["updated"]
        cur = db.execute("INSERT INTO data_imports (source, filename, rows_ok, rows_rejected, imported_by)"
                         " VALUES (?, ?, ?, ?, ?)",
                         (source, filename[-100:] if filename else None, report["rows_ok"],
                          report["rows_rejected"], user_id))
        report["import_id"] = cur.lastrowid
        db.commit()
    except BaseException:
        db.rollback()
        raise
    report["gpa_scale"] = scale
    return report


def history(db: sqlite3.Connection, limit: int = 50) -> list[dict]:
    rows = db.execute("SELECT d.*, u.username FROM data_imports d LEFT JOIN users u ON u.id = d.imported_by"
                      " ORDER BY d.id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "source": r["source"], "filename": r["filename"], "rows_ok": r["rows_ok"],
             "rows_rejected": r["rows_rejected"], "imported_by": r["username"], "timestamp": r["timestamp"]}
            for r in rows]
