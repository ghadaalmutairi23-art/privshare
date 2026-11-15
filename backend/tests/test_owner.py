"""Owner features over HTTP: import, templates, record view (owner only), permissions and budgets."""
import io
import json

import pytest

from backend.db import get_db

from .conftest import login
from .test_ingest import GOOD, csv_bytes, xlsx_bytes

OTHER_ROLES = ["partner_rep", "analyst", "admin", "auditor"]


@pytest.fixture
def owner(client, accounts):
    return client, login(client, accounts["uni_owner"])


def upload(client, token, name, data):
    return client.post("/api/owner/import", headers={"X-CSRFToken": token},
                       data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")


def events(app, action):
    with app.app_context():
        return get_db().execute("SELECT * FROM security_events WHERE action = ?", (action,)).fetchall()


# --- import ---

def test_owner_imports_csv_and_xlsx(app, owner):
    client, token = owner
    resp = upload(client, token, "a.csv", csv_bytes([GOOD, {**GOOD, "student_no": "400999", "gpa": "7"}]))
    assert resp.status_code == 200
    report = resp.get_json()["report"]
    assert report["rows_ok"] == 1 and report["rows_rejected"] == 1
    resp = upload(client, token, "b.xlsx", xlsx_bytes([{**GOOD, "student_no": "400555",
                                                        "national_id": "2234567890"}]))
    assert resp.get_json()["report"]["added"] == 1
    hist = client.get("/api/owner/imports").get_json()
    assert hist["students_total"] == 2
    assert [h["source"] for h in hist["imports"]] == ["excel", "csv"]
    assert len(events(app, "data_import")) == 2


def test_bad_file_rejected_with_reason(owner):
    client, token = owner
    resp = upload(client, token, "a.exe", b"MZ...")
    assert resp.status_code == 400 and "Only .csv and .xlsx" in resp.get_json()["error"]
    assert client.post("/api/owner/import", headers={"X-CSRFToken": token}).status_code == 400


def test_upload_over_limit_refused(owner):
    client, token = owner
    resp = upload(client, token, "big.csv", b"x" * (6 * 1024 * 1024))
    assert resp.status_code == 413


def test_json_endpoints_keep_small_body_limit(owner):
    client, token = owner
    resp = client.put("/api/owner/analysts/1/permissions", headers={"X-CSRFToken": token,
                      "Content-Type": "application/json"}, data=json.dumps({"x": "a" * 70_000}))
    assert resp.status_code == 413


def test_uploads_stay_in_memory(app):
    from backend.security import InMemoryRequest
    assert app.request_class is InMemoryRequest
    assert isinstance(InMemoryRequest({})._get_file_stream(10, "text/csv"), io.BytesIO)


@pytest.mark.parametrize("fmt", ["csv", "xlsx"])
def test_templates_download_and_reimport(owner, fmt):
    client, token = owner
    resp = client.get(f"/api/owner/import/template.{fmt}")
    assert resp.status_code == 200 and "sample_students" in resp.headers["Content-Disposition"]
    report = upload(client, token, f"sample_students.{fmt}", resp.data).get_json()["report"]
    assert report["rows_ok"] == 2 and report["rows_rejected"] == 0


# --- record view: owner only ---

@pytest.fixture
def with_students(owner):
    client, token = owner
    rows = [{**GOOD, "student_no": f"40{i:04d}", "name": f"Person {i}", "national_id": f"1{i:09d}"}
            for i in range(25)]
    assert upload(client, token, "s.csv", csv_bytes(rows)).status_code == 200
    return owner


def test_owner_sees_decrypted_records_with_masked_ids(app, with_students):
    client, _ = with_students
    body = client.get("/api/owner/students?page=2&per_page=10").get_json()
    assert body["total"] == 25 and len(body["students"]) == 10
    s = body["students"][0]
    assert s["name"].startswith("Person") and s["student_no"].startswith("40")
    assert "national_id" not in s and s["national_id_masked"].startswith("1") and "•" in s["national_id_masked"]
    logged = events(app, "student_records_viewed")
    assert len(logged) == 1 and "Person" not in logged[0]["detail"]


def test_search_by_name_or_number_is_logged_without_the_text(app, with_students):
    client, _ = with_students
    assert client.get("/api/owner/students?q=person 7").get_json()["total"] == 1
    assert client.get("/api/owner/students?q=400012").get_json()["total"] == 1
    for e in events(app, "student_records_viewed"):
        assert "person" not in e["detail"].lower() and "400012" not in e["detail"]


def test_reveal_national_id_is_logged(app, with_students):
    client, _ = with_students
    sid = client.get("/api/owner/students").get_json()["students"][0]["id"]
    resp = client.get(f"/api/owner/students/{sid}/national-id")
    assert resp.status_code == 200 and len(resp.get_json()["national_id"]) == 10
    logged = events(app, "national_id_revealed")
    assert len(logged) == 1 and resp.get_json()["national_id"] not in logged[0]["detail"]
    assert client.get("/api/owner/students/999999/national-id").status_code == 404


@pytest.mark.parametrize("query", ["page=0", "per_page=500", "major=Physics", "grad_year=abc"])
def test_record_view_rejects_bad_parameters(owner, query):
    client, _ = owner
    assert client.get(f"/api/owner/students?{query}").status_code == 400


@pytest.mark.parametrize("role", OTHER_ROLES)
def test_partner_and_other_roles_can_never_see_records(app, client, accounts, role):
    """CLAUDE.md: partner roles can never call the record view (and neither can admin or auditor)."""
    token = login(client, accounts[role])
    assert client.get("/api/owner/students").status_code == 403
    assert client.get("/api/owner/students/1/national-id").status_code == 403
    assert upload(client, token, "a.csv", csv_bytes([GOOD])).status_code == 403
    assert client.post("/api/owner/sync", headers={"X-CSRFToken": token}).status_code == 403
    assert client.get("/api/owner/analysts").status_code == 403
    assert client.get("/api/owner/import/template.csv").status_code == 403


def test_record_view_needs_login(client):
    assert client.get("/api/owner/students").status_code == 401


# --- analyst permissions and budgets (owner) ---

def test_owner_lists_and_sets_permissions(app, owner, accounts):
    client, token = owner
    aid = accounts["analyst"].id
    listed = client.get("/api/owner/analysts").get_json()["analysts"]
    assert [a["username"] for a in listed] == ["analyst_user"]
    assert listed[0]["permissions"]["majors"] == "all"
    resp = client.put(f"/api/owner/analysts/{aid}/permissions", headers={"X-CSRFToken": token},
                      json={"query_types": ["avg_gpa"], "majors": ["Cybersecurity"], "years": [2024],
                            "max_queries": 3})
    assert resp.status_code == 200
    perm = resp.get_json()["analyst"]["permissions"]
    assert perm == {"query_types": ["avg_gpa"], "majors": ["Cybersecurity"], "years": [2024],
                    "max_queries": 3, "queries_used": 0}
    assert len(events(app, "permissions_changed")) == 1


@pytest.mark.parametrize("body", [
    {"query_types": ["raw_records"]},
    {"majors": ["Physics"]},
    {"years": ["2024"]},
    {"years": [1800]},
    {"max_queries": -1},
    {"max_queries": "10"},
    {"majors": "Cybersecurity"},
])
def test_invalid_permissions_rejected(owner, accounts, body):
    client, token = owner
    resp = client.put(f"/api/owner/analysts/{accounts['analyst'].id}/permissions",
                      headers={"X-CSRFToken": token}, json=body)
    assert resp.status_code == 400


def test_permissions_only_for_analysts(owner, accounts):
    client, token = owner
    assert client.put(f"/api/owner/analysts/{accounts['auditor'].id}/permissions",
                      headers={"X-CSRFToken": token}, json={}).status_code == 400
    assert client.put("/api/owner/analysts/9999/permissions",
                      headers={"X-CSRFToken": token}, json={}).status_code == 404


def test_owner_sets_budget_and_spent_is_kept(app, owner, accounts):
    from backend import budget
    client, token = owner
    aid = accounts["analyst"].id
    with app.app_context():
        db = get_db()
        budget.charge(db, aid, 2.0)
        db.commit()
    resp = client.patch(f"/api/owner/analysts/{aid}/budget", headers={"X-CSRFToken": token},
                        json={"epsilon_total": 8})
    assert resp.get_json()["analyst"]["budget"] == {"total": 8.0, "spent": 2.0, "remaining": 6.0}
    resp = client.patch(f"/api/owner/analysts/{aid}/budget", headers={"X-CSRFToken": token},
                        json={"epsilon_total": 1})
    assert resp.get_json()["analyst"]["budget"]["remaining"] == 0.0
    assert len(events(app, "budget_changed")) == 2


@pytest.mark.parametrize("value", [-1, 101, "5", None, True, float("inf")])
def test_budget_validation(owner, accounts, value):
    client, token = owner
    resp = client.patch(f"/api/owner/analysts/{accounts['analyst'].id}/budget",
                        headers={"X-CSRFToken": token, "Content-Type": "application/json"},
                        data=json.dumps({"epsilon_total": value}))
    assert resp.status_code == 400


def test_analyst_sees_own_permissions(app, client, accounts):
    owner_client = app.test_client()
    token = login(owner_client, accounts["uni_owner"])
    owner_client.put(f"/api/owner/analysts/{accounts['analyst'].id}/permissions", headers={"X-CSRFToken": token},
                     json={"majors": ["Data Science"]})
    login(client, accounts["analyst"])
    body = client.get("/api/query/permissions").get_json()
    assert body["permissions"]["majors"] == ["Data Science"] and body["permissions"]["query_types"] == "all"
    assert body["budget"]["total"] == 5.0
