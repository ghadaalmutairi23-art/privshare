"""User accounts: creation, lookup and admin updates (database access only)."""
import re
import sqlite3

from . import auth, crypto, permissions
from .roles import ROLES

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
TOTP_AAD = b"users.totp_secret"


def _validate(username: str, password: str, role: str) -> None:
    if not USERNAME_RE.match(username):
        raise ValueError("Username must be 3-32 characters: letters, digits, _ . -")
    if role not in ROLES:
        raise ValueError("Unknown role")
    problem = auth.password_problem(password)
    if problem:
        raise ValueError(problem)


def create_user(db: sqlite3.Connection, username: str, password: str, role: str,
                epsilon_total: float) -> tuple[int, str]:
    """Create a user; returns (id, plain TOTP secret). The secret is stored encrypted."""
    _validate(username, password, role)
    secret = auth.new_totp_secret()
    try:
        cur = db.execute(
            "INSERT INTO users (username, pw_hash, totp_secret_enc, role, active) VALUES (?, ?, ?, ?, 1)",
            (username, auth.hash_password(password),
             crypto.encrypt(secret, crypto.load_key(), TOTP_AAD), role))
    except sqlite3.IntegrityError as exc:
        raise ValueError("Username already exists") from exc
    if role == "analyst":
        _ensure_analyst_rows(db, cur.lastrowid, epsilon_total)
    db.commit()
    return cur.lastrowid, secret


def reset_credentials(db: sqlite3.Connection, user_id: int, password: str) -> str:
    """Set a new password and TOTP secret; returns the new plain TOTP secret."""
    problem = auth.password_problem(password)
    if problem:
        raise ValueError(problem)
    secret = auth.new_totp_secret()
    db.execute("UPDATE users SET pw_hash = ?, totp_secret_enc = ? WHERE id = ?",
               (auth.hash_password(password), crypto.encrypt(secret, crypto.load_key(), TOTP_AAD), user_id))
    db.commit()
    return secret


def get_by_username(db: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_by_id(db: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def totp_secret(user: sqlite3.Row) -> str:
    return crypto.decrypt(user["totp_secret_enc"], crypto.load_key(), TOTP_AAD)


def public(user: sqlite3.Row) -> dict:
    """Fields safe to return from the API (no hashes, no secrets)."""
    return {"id": user["id"], "username": user["username"], "role": user["role"],
            "active": bool(user["active"]), "created_at": user["created_at"]}


def list_users(db: sqlite3.Connection) -> list[dict]:
    return [public(u) for u in db.execute("SELECT * FROM users ORDER BY id")]


def set_role(db: sqlite3.Connection, user_id: int, role: str, epsilon_total: float) -> None:
    if role not in ROLES:
        raise ValueError("Unknown role")
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    if role == "analyst":
        _ensure_analyst_rows(db, user_id, epsilon_total)
    db.commit()


def set_active(db: sqlite3.Connection, user_id: int, active: bool) -> None:
    db.execute("UPDATE users SET active = ? WHERE id = ?", (1 if active else 0, user_id))
    db.commit()


def _ensure_analyst_rows(db: sqlite3.Connection, user_id: int, epsilon_total: float) -> None:
    """Every analyst has a privacy budget and a permissions row."""
    db.execute("INSERT OR IGNORE INTO privacy_budget (user_id, epsilon_total, epsilon_spent) VALUES (?, ?, 0)",
               (user_id, epsilon_total))
    permissions.ensure_row(db, user_id)
