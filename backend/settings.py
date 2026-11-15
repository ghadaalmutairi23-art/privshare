"""Small key/value settings stored with the data (e.g. the GPA scale used when it was generated)."""
import sqlite3

GPA_SCALE_KEY = "gpa_scale"


def get(db: sqlite3.Connection, key: str) -> str | None:
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def put(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute("INSERT INTO settings (key, value) VALUES (?, ?)"
               " ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))


def gpa_scale(db: sqlite3.Connection, fallback: float) -> float:
    """The GPA scale of the stored data; `fallback` if no data was generated yet."""
    value = get(db, GPA_SCALE_KEY)
    return float(value) if value is not None else fallback
