"""Security event log (logins, MFA, admin actions, denials). Never pass passwords or codes here."""
import sqlite3

from flask import has_request_context, request


def log_event(db: sqlite3.Connection, action: str, user_id: int | None = None,
              username: str | None = None, detail: str | None = None) -> None:
    ip = request.remote_addr if has_request_context() else None
    db.execute("INSERT INTO security_events (user_id, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
               (user_id, (username or "")[:64] or None, action, detail, ip))
    db.commit()
