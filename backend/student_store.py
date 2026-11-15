"""Encrypted student records: write (insert / upsert by student number) and the owner's read view.

Only this module turns plaintext student fields into ciphertext and back. Decrypted values
live in memory only and are returned solely to the uni_owner record view.
"""
import sqlite3

from . import crypto

# Columns written for every student (encrypted ones carry the _enc suffix)
INSERT_SQL = ("INSERT INTO students (student_no_enc, student_no_hash, name_enc, national_id_enc, gpa_enc,"
              " major, grad_year, coop_completed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")


def encrypt_row(s: dict, key: bytes) -> tuple:
    """Clean student dict -> values for INSERT_SQL (fresh nonce per field)."""
    return (
        crypto.encrypt(s["student_no"], key, crypto.AAD_STUDENT_NO),
        crypto.blind_index(s["student_no"], key),
        crypto.encrypt(s["name"], key, crypto.AAD_NAME),
        crypto.encrypt(s["national_id"], key, crypto.AAD_NATIONAL_ID),
        crypto.encrypt(f"{s['gpa']:.2f}", key, crypto.AAD_GPA),
        s["major"], s["grad_year"], 1 if s["coop_completed"] else 0,
    )


def upsert(db: sqlite3.Connection, s: dict, key: bytes) -> str:
    """Insert, or update the student with the same number. Returns 'added' or 'updated'. No commit."""
    values = encrypt_row(s, key)
    row = db.execute("SELECT id FROM students WHERE student_no_hash = ?", (values[1],)).fetchone()
    if row is None:
        db.execute(INSERT_SQL, values)
        return "added"
    db.execute("UPDATE students SET student_no_enc = ?, name_enc = ?, national_id_enc = ?, gpa_enc = ?,"
               " major = ?, grad_year = ?, coop_completed = ? WHERE id = ?",
               (values[0], *values[2:], row["id"]))
    return "updated"


def count(db: sqlite3.Connection) -> int:
    return db.execute("SELECT COUNT(*) FROM students").fetchone()[0]


def mask_national_id(value: str) -> str:
    return value[:1] + "••••••" + value[-3:] if len(value) >= 4 else "••••"


def _decrypt_row(r: sqlite3.Row, key: bytes) -> dict:
    student_no = crypto.decrypt(r["student_no_enc"], key, crypto.AAD_STUDENT_NO) if r["student_no_enc"] else None
    return {
        "id": r["id"],
        "student_no": student_no,
        "name": crypto.decrypt(r["name_enc"], key, crypto.AAD_NAME),
        "national_id_masked": mask_national_id(crypto.decrypt(r["national_id_enc"], key, crypto.AAD_NATIONAL_ID)),
        "major": r["major"],
        "grad_year": r["grad_year"],
        "gpa": float(crypto.decrypt(r["gpa_enc"], key, crypto.AAD_GPA)),
        "coop_completed": bool(r["coop_completed"]),
    }


def list_page(db: sqlite3.Connection, key: bytes, page: int, per_page: int, search: str = "",
              major: str | None = None, grad_year: int | None = None) -> tuple[list[dict], int]:
    """One page of decrypted students for the owner view, and the total number matching.

    Major / year filter in SQL. Name and student number are encrypted, so a text search
    decrypts the filtered rows in memory (fine for a university-sized table).
    """
    where, args = [], []
    if major is not None:
        where.append("major = ?")
        args.append(major)
    if grad_year is not None:
        where.append("grad_year = ?")
        args.append(grad_year)
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    offset = (page - 1) * per_page

    if not search:
        total = db.execute("SELECT COUNT(*) FROM students" + sql_where, args).fetchone()[0]
        rows = db.execute("SELECT * FROM students" + sql_where + " ORDER BY id LIMIT ? OFFSET ?",
                          (*args, per_page, offset)).fetchall()
        return [_decrypt_row(r, key) for r in rows], total

    needle = search.casefold()
    matches = []
    for r in db.execute("SELECT * FROM students" + sql_where + " ORDER BY id", args):
        d = _decrypt_row(r, key)
        if needle in d["name"].casefold() or (d["student_no"] and needle in d["student_no"].casefold()):
            matches.append(d)
    return matches[offset:offset + per_page], len(matches)


def national_id(db: sqlite3.Connection, key: bytes, student_id: int) -> str | None:
    """Full national ID of one student (owner 'reveal' action)."""
    r = db.execute("SELECT national_id_enc FROM students WHERE id = ?", (student_id,)).fetchone()
    return crypto.decrypt(r["national_id_enc"], key, crypto.AAD_NATIONAL_ID) if r else None
