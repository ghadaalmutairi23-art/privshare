import pytest

from backend.db import get_db
from backend.roles import PERMISSIONS, ROLES

from .conftest import login


def test_every_role_has_permissions_and_admin_cannot_see_data():
    assert set(PERMISSIONS) == set(ROLES)
    assert "run_query" not in PERMISSIONS["admin"]
    assert "view_audit" not in PERMISSIONS["admin"]


def test_unauthenticated_gets_401(client):
    assert client.get("/api/admin/users").status_code == 401
    assert client.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize("role", [r for r in ROLES if r != "admin"])
def test_non_admin_roles_cannot_manage_users(client, accounts, role):
    token = login(client, accounts[role])
    assert client.get("/api/admin/users").status_code == 403
    resp = client.post("/api/admin/users", headers={"X-CSRFToken": token},
                       json={"username": "x_user", "password": "Strong-Passw0rd!", "role": "admin"})
    assert resp.status_code == 403


def test_admin_lists_users_without_secrets(client, accounts):
    login(client, accounts["admin"])
    resp = client.get("/api/admin/users")
    assert resp.status_code == 200
    listed = resp.get_json()["users"]
    assert all(set(u) == {"id", "username", "role", "active", "created_at", "budget"} for u in listed)
    by_role = {u["role"]: u for u in listed}
    assert by_role["analyst"]["budget"]["total"] == 5.0 and by_role["auditor"]["budget"] is None


def test_admin_cannot_set_budgets_or_permissions(client, accounts):
    """Budgets and analyst permissions belong to the university data owner."""
    token = login(client, accounts["admin"])
    uid = accounts["analyst"].id
    assert client.patch(f"/api/owner/analysts/{uid}/budget", headers={"X-CSRFToken": token},
                        json={"epsilon_total": 50}).status_code == 403
    assert client.put(f"/api/owner/analysts/{uid}/permissions", headers={"X-CSRFToken": token},
                      json={}).status_code == 403
    assert client.patch(f"/api/admin/users/{uid}/budget", headers={"X-CSRFToken": token},
                        json={"epsilon_total": 50}).status_code == 404   # old admin route removed


def test_admin_creates_user(app, client, accounts):
    token = login(client, accounts["admin"])
    resp = client.post("/api/admin/users", headers={"X-CSRFToken": token},
                       json={"username": "analyst2", "password": "Strong-Passw0rd!", "role": "analyst"})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["user"]["role"] == "analyst"
    assert data["totp_uri"].startswith("otpauth://totp/")
    with app.app_context():
        budget = get_db().execute("SELECT epsilon_total, epsilon_spent FROM privacy_budget WHERE user_id = ?",
                                  (data["user"]["id"],)).fetchone()
    assert tuple(budget) == (5.0, 0.0)


@pytest.mark.parametrize("body", [
    {"username": "weak_user", "password": "short", "role": "analyst"},
    {"username": "bad_role", "password": "Strong-Passw0rd!", "role": "superuser"},
    {"username": "analyst_user", "password": "Strong-Passw0rd!", "role": "analyst"},  # duplicate
    {"username": "a b; DROP TABLE users", "password": "Strong-Passw0rd!", "role": "analyst"},
])
def test_admin_create_user_validation(client, accounts, body):
    token = login(client, accounts["admin"])
    assert client.post("/api/admin/users", headers={"X-CSRFToken": token}, json=body).status_code == 400


def test_role_change_applies_immediately(app, accounts):
    admin, auditor = app.test_client(), app.test_client()
    token = login(admin, accounts["admin"])
    login(auditor, accounts["auditor"])
    assert auditor.get("/api/auth/me").get_json()["user"]["role"] == "auditor"

    resp = admin.patch(f"/api/admin/users/{accounts['auditor'].id}", headers={"X-CSRFToken": token},
                       json={"role": "analyst"})
    assert resp.status_code == 200
    assert auditor.get("/api/auth/me").get_json()["user"]["role"] == "analyst"


def test_deactivation_ends_existing_session(app, accounts):
    admin, analyst = app.test_client(), app.test_client()
    token = login(admin, accounts["admin"])
    login(analyst, accounts["analyst"])
    admin.patch(f"/api/admin/users/{accounts['analyst'].id}", headers={"X-CSRFToken": token},
                json={"active": False})
    assert analyst.get("/api/auth/me").status_code == 401


def test_admin_cannot_change_self(client, accounts):
    token = login(client, accounts["admin"])
    resp = client.patch(f"/api/admin/users/{accounts['admin'].id}", headers={"X-CSRFToken": token},
                        json={"active": False})
    assert resp.status_code == 400


def test_access_denial_is_logged(app, client, accounts):
    login(client, accounts["analyst"])
    client.get("/api/admin/users")
    with app.app_context():
        row = get_db().execute("SELECT * FROM security_events WHERE action = 'access_denied'").fetchone()
    assert row["username"] == accounts["analyst"].username and row["detail"] == "manage_users"
