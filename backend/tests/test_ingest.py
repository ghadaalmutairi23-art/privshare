"""Row validation, CSV/Excel parsing and the import transaction (no HTTP here)."""
import io
import zipfile

import pytest
from openpyxl import Workbook

from backend import crypto, ingest, settings, student_store
from backend.db import get_db

GOOD = {"student_no": "400123", "name": "Test Student", "national_id": "1234567890", "major": "Cybersecurity",
        "gpa": "3.5", "grad_year": "2024", "coop_completed": "yes"}


def csv_bytes(rows, header=ingest.COLUMNS):
    lines = [",".join(header)] + [",".join(str(r.get(c, "")) for c in header) for r in rows]
    return ("\n".join(lines) + "\n").encode("utf-8")


def xlsx_bytes(rows, header=ingest.COLUMNS):
    wb = Workbook()
    ws = wb.active
    ws.append(list(header))
    for r in rows:
        ws.append([r.get(c) for c in header])
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


# --- validate_row ---

def test_valid_row_is_cleaned():
    clean, errors = ingest.validate_row({**GOOD, "name": "  Test   Student ", "coop_completed": "No"}, 4.0)
    assert errors == []
    assert clean == {"student_no": "400123", "name": "Test Student", "national_id": "1234567890",
                     "major": "Cybersecurity", "gpa": 3.5, "grad_year": 2024, "coop_completed": False}


@pytest.mark.parametrize("field,value,column", [
    ("student_no", "4", "student_no"),
    ("student_no", "40 01", "student_no"),
    ("name", "", "name"),
    ("national_id", "123456789", "national_id"),          # 9 digits
    ("national_id", "3234567890", "national_id"),         # must start with 1 or 2
    ("major", "Data Sci", "major"),
    ("gpa", "4.6", "gpa"),                                # above the 4-point scale
    ("gpa", "-0.1", "gpa"),
    ("gpa", "abc", "gpa"),
    ("grad_year", "1990", "grad_year"),
    ("grad_year", "next", "grad_year"),
    ("coop_completed", "maybe", "coop_completed"),
])
def test_invalid_values_are_reported(field, value, column):
    clean, errors = ingest.validate_row({**GOOD, field: value}, 4.0)
    assert clean is None and [c for c, _ in errors] == [column]


def test_gpa_checked_against_the_stored_scale():
    assert ingest.validate_row({**GOOD, "gpa": "4.6"}, 5.0)[1] == []
    assert ingest.validate_row({**GOOD, "gpa": "4.6"}, 4.0)[1] != []


def test_excel_style_numbers_accepted():
    clean, errors = ingest.validate_row({**GOOD, "student_no": "400123.0", "national_id": "1234567890.0",
                                         "grad_year": "2024.0", "coop_completed": "1.0", "gpa": "3,25"}, 4.0)
    assert errors == [] and clean["grad_year"] == 2024 and clean["gpa"] == 3.25 and clean["coop_completed"]


def test_problems_never_echo_personal_values():
    _, errors = ingest.validate_row({**GOOD, "national_id": "99887766", "name": "x"}, 4.0)
    text = repr(errors)
    assert "99887766" not in text


# --- parse_upload ---

def test_parse_csv_and_xlsx():
    for name, data, source in (("s.csv", csv_bytes([GOOD]), "csv"), ("s.xlsx", xlsx_bytes([GOOD]), "excel")):
        got_source, rows = ingest.parse_upload(name, data)
        assert got_source == source and len(rows) == 1
        assert ingest.validate_row(rows[0], 4.0)[1] == []


def test_csv_header_is_case_insensitive_and_extra_columns_ignored():
    header = ("Student_No", "NAME", "national_id", "major", "gpa", "grad_year", "coop_completed", "notes")
    data = ",".join(header) + "\n400123,Test Student,1234567890,Cybersecurity,3.5,2024,yes,hello\n"
    _, rows = ingest.parse_upload("s.csv", data.encode())
    assert set(rows[0]) == set(ingest.COLUMNS)


def test_leading_zeros_kept():
    _, rows = ingest.parse_upload("s.csv", csv_bytes([{**GOOD, "student_no": "000123"}]))
    assert rows[0]["student_no"] == "000123"


@pytest.mark.parametrize("name,data,message", [
    ("s.txt", b"a,b", "Only .csv and .xlsx"),
    ("s.csv", b"", "empty"),
    ("s.xlsx", b"not a zip at all", "Not a valid .xlsx"),
    ("s.csv", b"student_no,name\n1,a\n", "Missing columns"),
    ("s.csv", b"x" * (ingest.MAX_UPLOAD_BYTES + 1), "larger than"),
])
def test_unusable_files_rejected(name, data, message):
    with pytest.raises(ingest.ImportRejected, match=message):
        ingest.parse_upload(name, data)


def test_xlsx_zip_bomb_rejected(monkeypatch):
    monkeypatch.setattr(ingest, "MAX_UNZIPPED_BYTES", 1000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.xml", "0" * 100_000)   # compresses to almost nothing
    with pytest.raises(ingest.ImportRejected, match="too large"):
        ingest.parse_upload("bomb.xlsx", buf.getvalue())


# --- import_rows ---

def test_import_adds_then_updates_by_student_number(app, accounts):
    owner = accounts["uni_owner"].id
    with app.app_context():
        db = get_db()
        r1 = ingest.import_rows(db, [GOOD, {**GOOD, "student_no": "400124", "national_id": "1234567891"}],
                                "csv", "a.csv", owner, 4.0)
        assert (r1["added"], r1["updated"], r1["rows_rejected"]) == (2, 0, 0)
        r2 = ingest.import_rows(db, [{**GOOD, "gpa": "2.0"}], "csv", "b.csv", owner, 4.0)
        assert (r2["added"], r2["updated"]) == (0, 1)
        assert student_store.count(db) == 2
        rows, _ = student_store.list_page(db, crypto.load_key(), 1, 10)
        assert next(r for r in rows if r["student_no"] == "400123")["gpa"] == 2.0
        assert db.execute("SELECT COUNT(*) FROM data_imports").fetchone()[0] == 2


def test_import_report_lists_bad_rows_with_spreadsheet_row_numbers(app, accounts):
    rows = [GOOD, {**GOOD, "student_no": "400200", "gpa": "9"}, {}, {**GOOD}]  # blank line, then duplicate
    with app.app_context():
        report = ingest.import_rows(get_db(), rows, "csv", "c.csv", accounts["uni_owner"].id, 4.0)
    assert report["rows_ok"] == 1 and report["rows_rejected"] == 2
    assert {(r["row"], r["column"]) for r in report["rejected"]} == {(3, "gpa"), (5, "student_no")}


def test_sensitive_fields_stored_encrypted(app, accounts):
    with app.app_context():
        db = get_db()
        ingest.import_rows(db, [GOOD], "csv", "a.csv", accounts["uni_owner"].id, 4.0)
        raw = db.execute("SELECT * FROM students").fetchone()
    stored = " ".join(str(raw[c]) for c in raw.keys())
    for plain in ("400123", "Test Student", "1234567890", "3.50"):
        assert plain not in stored
    assert raw["student_no_hash"] == crypto.blind_index("400123", crypto.load_key())


def test_first_import_records_the_gpa_scale(app, accounts):
    with app.app_context():
        db = get_db()
        report = ingest.import_rows(db, [GOOD], "csv", "a.csv", accounts["uni_owner"].id, 4.0)
        assert report["gpa_scale"] == 4.0 and settings.get(db, settings.GPA_SCALE_KEY) == "4.0"
