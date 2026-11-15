import time

import pyotp

from backend import auth, users
from backend.db import get_db

from .conftest import age_sessions, get_csrf, login

COOKIE = "privshare_session"


# --- unit: password hashing and TOTP ---

def test_password_is_hashed_with_argon2id():
    h = auth.hash_password("Correct-Horse-9")
    assert h.startswith("$argon2id$") and "Correct-Horse-9" not in h
    assert auth.verify_password(h, "Correct-Horse-9")
    assert not auth.verify_password(h, "wrong")
    assert not auth.verify_password("not-a-hash", "Correct-Horse-9")


def test_password_policy():
    assert auth.password_problem("short1!A") is not None
    assert auth.password_problem("alllowercaseletters") is not None
    assert auth.password_problem("Long-Enough-Pass1") is None


def test_totp_accepts_current_and_adjacent_step_only():
    secret = auth.new_totp_secret()
    totp = pyotp.TOTP(secret)
    assert auth.verify_totp(secret, totp.now())
    assert auth.verify_totp(secret, totp.at(time.time() - 30))   # valid_window=1
    assert not auth.verify_totp(secret, totp.at(time.time() - 120))
    assert not auth.verify_totp(secret, "abcdef")
    assert not auth.verify_totp(secret, "")


def test_totp_secret_stored_encrypted(app, accounts):
    with app.app_context():
        row = users.get_by_username(get_db(), accounts["analyst"].username)
        assert accounts["analyst"].totp_secret not in row["totp_secret_enc"]
        assert users.totp_secret(row) == accounts["analyst"].totp_secret


# --- API: two-step login ---

def test_full_login_flow(client, accounts):
    login(client, accounts["analyst"])
    me = client.get("/api/auth/me").get_json()["user"]
    assert me["username"] == accounts["analyst"].username
    assert me["role"] == "analyst"
    assert "run_query" in me["permissions"]


def test_all_failures_give_the_same_error(client, accounts):
    acct = accounts["analyst"]
    bodies = [{"username": "nobody", "password": acct.password},
              {"username": acct.username, "password": "Wrong-Password-1"}]
    for body in bodies:
        resp = client.post("/api/auth/login", json=body, headers={"X-CSRFToken": get_csrf(client)})
        assert resp.status_code == 401
        assert resp.get_json() == {"error": "Invalid credentials"}

    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                       headers={"X-CSRFToken": get_csrf(client)})
    resp = client.post("/api/auth/mfa", json={"code": "000000"},
                       headers={"X-CSRFToken": resp.get_json()["csrf_token"]})
    assert resp.status_code == 401
    assert resp.get_json() == {"error": "Invalid credentials"}


def test_password_alone_does_not_log_in(client, accounts):
    acct = accounts["admin"]
    client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                headers={"X-CSRFToken": get_csrf(client)})
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/admin/users").status_code == 401


def test_mfa_without_password_step_fails(client, accounts):
    resp = client.post("/api/auth/mfa", json={"code": accounts["admin"].code()},
                       headers={"X-CSRFToken": get_csrf(client)})
    assert resp.status_code == 401


def test_mfa_locked_after_too_many_wrong_codes(client, accounts):
    acct = accounts["analyst"]
    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                       headers={"X-CSRFToken": get_csrf(client)})
    token = resp.get_json()["csrf_token"]
    for _ in range(5):
        client.post("/api/auth/mfa", json={"code": "000000"}, headers={"X-CSRFToken": token})
    # The pending login was discarded: even the right code fails now
    resp = client.post("/api/auth/mfa", json={"code": acct.code()}, headers={"X-CSRFToken": get_csrf(client)})
    assert resp.status_code == 401


def test_mfa_step_expires(app, client, accounts):
    acct = accounts["analyst"]
    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                       headers={"X-CSRFToken": get_csrf(client)})
    age_sessions(app, 301)
    resp = client.post("/api/auth/mfa", json={"code": acct.code()},
                       headers={"X-CSRFToken": resp.get_json()["csrf_token"]})
    assert resp.status_code == 401


def test_deactivated_user_cannot_log_in(app, client, accounts):
    with app.app_context():
        users.set_active(get_db(), accounts["auditor"].id, False)
    acct = accounts["auditor"]
    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                       headers={"X-CSRFToken": get_csrf(client)})
    assert resp.status_code == 401


def test_logout(client, accounts):
    token = login(client, accounts["auditor"])
    assert client.post("/api/auth/logout", headers={"X-CSRFToken": token}).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


# --- server-side sessions ---

def test_copied_cookie_is_dead_after_logout(client, accounts):
    token = login(client, accounts["analyst"])
    stolen = client.get_cookie(COOKIE).value
    client.post("/api/auth/logout", headers={"X-CSRFToken": token})
    client.set_cookie(COOKIE, stolen)                       # replay the old cookie
    assert client.get("/api/auth/me").status_code == 401


def test_mfa_counter_cannot_be_reset_by_replaying_cookie(client, accounts):
    acct = accounts["analyst"]
    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                       headers={"X-CSRFToken": get_csrf(client)})
    token, pending_cookie = resp.get_json()["csrf_token"], client.get_cookie(COOKIE).value
    for _ in range(4):
        client.post("/api/auth/mfa", json={"code": "000000"}, headers={"X-CSRFToken": token})
        client.set_cookie(COOKIE, pending_cookie)           # try to roll the counter back
    client.post("/api/auth/mfa", json={"code": "000000"}, headers={"X-CSRFToken": token})  # 5th
    client.set_cookie(COOKIE, pending_cookie)
    resp = client.post("/api/auth/mfa", json={"code": acct.code()}, headers={"X-CSRFToken": token})
    assert resp.status_code == 401                          # pending login is gone for good


def test_session_token_rotated_after_mfa(client, accounts):
    acct = accounts["analyst"]
    resp = client.post("/api/auth/login", json={"username": acct.username, "password": acct.password},
                       headers={"X-CSRFToken": get_csrf(client)})
    pending_cookie = client.get_cookie(COOKIE).value
    client.post("/api/auth/mfa", json={"code": acct.code()}, headers={"X-CSRFToken": resp.get_json()["csrf_token"]})
    assert client.get_cookie(COOKIE).value != pending_cookie
    client.set_cookie(COOKIE, pending_cookie)               # the pre-MFA session is gone
    assert client.get("/api/auth/me").status_code == 401


def test_only_token_hash_is_stored(app, client, accounts):
    import hashlib
    login(client, accounts["analyst"])
    with client.session_transaction() as s:
        token = s["sid"]
    with app.app_context():
        ids = [r[0] for r in get_db().execute("SELECT id FROM sessions")]
    assert token not in ids and hashlib.sha256(token.encode()).hexdigest() in ids


def test_deactivation_deletes_sessions(app, client, accounts):
    admin = app.test_client()
    token = login(admin, accounts["admin"])
    login(client, accounts["analyst"])
    admin.patch(f"/api/admin/users/{accounts['analyst'].id}", headers={"X-CSRFToken": token},
                json={"active": False})
    with app.app_context():
        n = get_db().execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?",
                             (accounts["analyst"].id,)).fetchone()[0]
    assert n == 0


def test_security_events_logged_without_secrets(app, client, accounts):
    acct = accounts["analyst"]
    client.post("/api/auth/login", json={"username": acct.username, "password": "Wrong-Password-1"},
                headers={"X-CSRFToken": get_csrf(client)})
    login(client, acct)
    with app.app_context():
        rows = get_db().execute("SELECT action, username, detail FROM security_events").fetchall()
    actions = [r["action"] for r in rows]
    assert "login_failed" in actions and "login_success" in actions
    dump = repr([tuple(r) for r in rows])
    assert acct.password not in dump and "Wrong-Password-1" not in dump
