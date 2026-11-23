"""SQLite connection and schema.

Parameterized queries only. Column types and defaults are kept portable so the
schema can move to PostgreSQL later (INTEGER PRIMARY KEY -> SERIAL/IDENTITY).
"""
import sqlite3
from contextlib import closing
from pathlib import Path

from flask import Flask, current_app, g

from .catalog import QUERY_TYPES
from .roles import ROLES

_ROLE_LIST = ", ".join(f"'{r}'" for r in ROLES)

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS students (
    id              INTEGER PRIMARY KEY,
    name_enc        TEXT    NOT NULL,
    national_id_enc TEXT    NOT NULL,
    gpa_enc         TEXT    NOT NULL,
    major           TEXT    NOT NULL,
    grad_year       INTEGER NOT NULL,
    coop_completed  INTEGER NOT NULL CHECK (coop_completed IN (0, 1)),
    student_no_enc  TEXT,
    student_no_hash TEXT    -- blind index (HMAC) for upserts by student number
);
CREATE INDEX IF NOT EXISTS idx_students_filter ON students (major, grad_year);

-- Per-analyst limits set by the university owner. JSON lists; NULL or [] = all
CREATE TABLE IF NOT EXISTS analyst_permissions (
    analyst_id          INTEGER PRIMARY KEY REFERENCES users (id),
    allowed_query_types TEXT,
    allowed_majors      TEXT,
    allowed_years       TEXT,
    max_queries         INTEGER CHECK (max_queries IS NULL OR max_queries >= 0),
    queries_used        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS data_imports (
    id            INTEGER PRIMARY KEY,
    source        TEXT    NOT NULL CHECK (source IN ('csv', 'excel', 'api')),
    filename      TEXT,
    rows_ok       INTEGER NOT NULL,
    rows_rejected INTEGER NOT NULL,
    imported_by   INTEGER REFERENCES users (id),
    timestamp     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    pw_hash         TEXT    NOT NULL,
    totp_secret_enc TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ({_ROLE_LIST})),
    active          INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS privacy_budget (
    user_id       INTEGER PRIMARY KEY REFERENCES users (id),
    epsilon_total REAL    NOT NULL CHECK (epsilon_total >= 0),
    epsilon_spent REAL    NOT NULL DEFAULT 0 CHECK (epsilon_spent >= 0)
);

CREATE TABLE IF NOT EXISTS query_types (
    id               INTEGER PRIMARY KEY,
    name             TEXT    NOT NULL UNIQUE,
    approved_uni     INTEGER NOT NULL DEFAULT 0 CHECK (approved_uni IN (0, 1)),
    approved_partner INTEGER NOT NULL DEFAULT 0 CHECK (approved_partner IN (0, 1))
);

CREATE TABLE IF NOT EXISTS audit_records (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id),
    query_type   TEXT    NOT NULL,
    params_json  TEXT    NOT NULL,
    epsilon      REAL    NOT NULL,
    group_size   INTEGER NOT NULL,
    result_noisy REAL    NOT NULL,
    timestamp    TEXT    NOT NULL,
    sha256       TEXT    NOT NULL,
    tx_hash      TEXT,
    chain_index  INTEGER          -- position of this record's fingerprint in the on-chain log
);

-- Anomaly alerts for the admin (Isolation Forest). status: open -> reviewed / dismissed
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER REFERENCES users (id),
    score         REAL    NOT NULL,
    reason        TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status        TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewed', 'dismissed')),
    features_json TEXT,
    detected_by   TEXT,            -- "model", "far_beyond_normal" or both
    reviewed_by   INTEGER REFERENCES users (id),
    reviewed_at   TEXT
);

-- Security log: logins, MFA, admin actions, access denials (never passwords or codes)
CREATE TABLE IF NOT EXISTS security_events (
    id        INTEGER PRIMARY KEY,
    timestamp TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id   INTEGER REFERENCES users (id),
    username  TEXT,
    action    TEXT    NOT NULL,
    detail    TEXT,
    ip        TEXT
);

-- Server-side sessions: id = SHA-256 of the cookie token, times are Unix seconds
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id),
    stage        TEXT    NOT NULL CHECK (stage IN ('mfa_pending', 'active')),
    created_at   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    mfa_attempts INTEGER NOT NULL DEFAULT 0,
    ip           TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    _migrate(conn)
    # Whitelisted query types start unapproved by both parties
    conn.executemany("INSERT OR IGNORE INTO query_types (name) VALUES (?)", [(n,) for n in QUERY_TYPES])
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases created by earlier phases up to date (adds columns, never drops data)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(students)")}
    for col in ("student_no_enc", "student_no_hash"):
        if col not in cols:
            conn.execute(f"ALTER TABLE students ADD COLUMN {col} TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_students_no ON students (student_no_hash)")
    if "chain_index" not in {r[1] for r in conn.execute("PRAGMA table_info(audit_records)")}:
        conn.execute("ALTER TABLE audit_records ADD COLUMN chain_index INTEGER")
    alert_cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    for col, decl in (("status", "TEXT NOT NULL DEFAULT 'open'"), ("features_json", "TEXT"),
                      ("detected_by", "TEXT"), ("reviewed_by", "INTEGER"), ("reviewed_at", "TEXT")):
        if col not in alert_cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {decl}")


def get_db() -> sqlite3.Connection:
    """One connection per request/app context."""
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    with closing(connect(app.config["DB_PATH"])) as conn:
        init_db(conn)
