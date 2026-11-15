"""Server-side login sessions.

The cookie holds only a random session token; the state lives in the `sessions` table,
keyed by the token's SHA-256 (a database leak does not reveal usable tokens). Deleting
the row ends the session for good, so logout, deactivation and idle timeout can't be
undone by replaying an old cookie, and the MFA attempt counter can't be reset that way.
"""
import hashlib
import secrets
import sqlite3
import time

from .config import IDLE_TIMEOUT_SECONDS, MFA_PENDING_SECONDS

PENDING, ACTIVE = "mfa_pending", "active"


def _key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create(db: sqlite3.Connection, user_id: int, stage: str, ip: str | None = None) -> str:
    """Create a session row and return the token to put in the cookie."""
    purge_expired(db)
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute("INSERT INTO sessions (id, user_id, stage, created_at, last_seen, mfa_attempts, ip)"
               " VALUES (?, ?, ?, ?, ?, 0, ?)", (_key(token), user_id, stage, now, now, ip))
    db.commit()
    return token


def get(db: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    return db.execute("SELECT * FROM sessions WHERE id = ?", (_key(token),)).fetchone()


def is_expired(row: sqlite3.Row, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    if row["stage"] == PENDING:
        return now - row["created_at"] > MFA_PENDING_SECONDS
    return now - row["last_seen"] > IDLE_TIMEOUT_SECONDS


def touch(db: sqlite3.Connection, token: str) -> None:
    db.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (int(time.time()), _key(token)))
    db.commit()


def add_mfa_failure(db: sqlite3.Connection, token: str) -> int:
    """Count a wrong MFA code; returns the new number of failures."""
    db.execute("UPDATE sessions SET mfa_attempts = mfa_attempts + 1 WHERE id = ?", (_key(token),))
    db.commit()
    row = get(db, token)
    return row["mfa_attempts"] if row else 0


def delete(db: sqlite3.Connection, token: str | None) -> None:
    if token:
        db.execute("DELETE FROM sessions WHERE id = ?", (_key(token),))
        db.commit()


def delete_for_user(db: sqlite3.Connection, user_id: int) -> None:
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    db.commit()


def purge_expired(db: sqlite3.Connection) -> None:
    now = int(time.time())
    db.execute("DELETE FROM sessions WHERE (stage = ? AND created_at < ?) OR (stage = ? AND last_seen < ?)",
               (PENDING, now - MFA_PENDING_SECONDS, ACTIVE, now - IDLE_TIMEOUT_SECONDS))
    db.commit()
