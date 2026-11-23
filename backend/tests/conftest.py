"""Shared fixtures: every test gets random keys and its own temporary database."""
import base64
import os
from dataclasses import dataclass

# Set before any backend import so tests never touch the real .env keys
os.environ["DATA_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["SECRET_KEY"] = os.urandom(32).hex()
os.environ["GPA_SCALE"] = "4"
os.environ["CHAIN_BACKEND"] = "stub"

import pyotp  # noqa: E402
import pytest  # noqa: E402

from backend import crypto, users  # noqa: E402
from backend.app import create_app  # noqa: E402
from backend.db import get_db  # noqa: E402
from backend.roles import ROLES  # noqa: E402


@dataclass
class Account:
    id: int
    username: str
    password: str
    totp_secret: str

    def code(self) -> str:
        return pyotp.TOTP(self.totp_secret).now()


def make_app(tmp_path, **overrides):
    config = {"TESTING": True, "DB_PATH": str(tmp_path / "test.db"),
              "SESSION_COOKIE_SECURE": False, "RATELIMIT_ENABLED": False}
    config.update(overrides)
    return create_app(config)


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def accounts(app) -> dict[str, Account]:
    """One account per role, keyed by role."""
    return make_accounts(app)


@pytest.fixture
def accounts_factory():
    """For tests that build their own app (e.g. on a real chain)."""
    return make_accounts


def make_accounts(app) -> dict[str, Account]:
    out = {}
    with app.app_context():
        for role in ROLES:
            username, password = f"{role}_user", f"Test-{role}-Passw0rd!"
            user_id, secret = users.create_user(get_db(), username, password, role, 5.0)
            out[role] = Account(user_id, username, password, secret)
    return out


def insert_students(db, major: str, grad_year: int, gpas: list[float], coop: list[int]) -> None:
    """Insert a controlled group of (encrypted) students for pipeline tests."""
    key = crypto.load_key()
    db.executemany(
        "INSERT INTO students (name_enc, national_id_enc, gpa_enc, major, grad_year, coop_completed)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [(crypto.encrypt(f"Student {i}", key, crypto.AAD_NAME),
          crypto.encrypt(f"1{i:09d}", key, crypto.AAD_NATIONAL_ID),
          crypto.encrypt(f"{gpa:.2f}", key, crypto.AAD_GPA), major, grad_year, c)
         for i, (gpa, c) in enumerate(zip(gpas, coop))])
    db.commit()


def age_sessions(app, seconds: int) -> None:
    """Pretend every server-side session was created / last used `seconds` earlier."""
    with app.app_context():
        db = get_db()
        db.execute("UPDATE sessions SET created_at = created_at - ?, last_seen = last_seen - ?",
                   (seconds, seconds))
        db.commit()


def get_csrf(client) -> str:
    return client.get("/api/auth/csrf").get_json()["csrf_token"]


def login(client, account: Account) -> str:
    """Full login (password + MFA). Returns the CSRF token for the new session."""
    resp = client.post("/api/auth/login", json={"username": account.username, "password": account.password},
                       headers={"X-CSRFToken": get_csrf(client)})
    assert resp.status_code == 200, resp.get_json()
    resp = client.post("/api/auth/mfa", json={"code": account.code()},
                       headers={"X-CSRFToken": resp.get_json()["csrf_token"]})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["csrf_token"]
