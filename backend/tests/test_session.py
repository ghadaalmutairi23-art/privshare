from backend.config import IDLE_TIMEOUT_SECONDS
from backend.db import get_db

from .conftest import age_sessions, get_csrf, login, make_app


def test_idle_timeout_ends_session(app, client, accounts):
    login(client, accounts["analyst"])
    assert client.get("/api/auth/me").status_code == 200
    age_sessions(app, IDLE_TIMEOUT_SECONDS + 1)
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401 and resp.get_json()["error"] == "Session expired"
    assert client.get("/api/auth/me").status_code == 401
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_activity_keeps_session_alive(app, client, accounts):
    login(client, accounts["analyst"])
    age_sessions(app, IDLE_TIMEOUT_SECONDS - 60)  # 14 minutes idle: still valid
    assert client.get("/api/auth/me").status_code == 200
    age_sessions(app, IDLE_TIMEOUT_SECONDS - 60)  # the request above reset the idle clock
    assert client.get("/api/auth/me").status_code == 200


def test_post_without_csrf_token_is_rejected(client, accounts):
    acct = accounts["analyst"]
    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password})
    assert resp.status_code == 400
    assert "CSRF" in resp.get_json()["error"]
    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                       headers={"X-CSRFToken": "forged"})
    assert resp.status_code == 400


def test_login_is_rate_limited(tmp_path):
    client = make_app(tmp_path, RATELIMIT_ENABLED=True).test_client()
    token = get_csrf(client)
    codes = [client.post("/api/auth/login", json={"username": "x", "password": "y"},
                         headers={"X-CSRFToken": token}).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429


def test_cookie_flags(tmp_path):
    client = make_app(tmp_path, SESSION_COOKIE_SECURE=True).test_client()
    cookie = client.get("/api/auth/csrf").headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_security_headers(client):
    resp = client.get("/api/health")
    assert resp.get_json() == {"status": "ok"}
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Cache-Control"] == "no-store"


def test_errors_are_json(client):
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404 and resp.get_json() == {"error": "Not Found"}
