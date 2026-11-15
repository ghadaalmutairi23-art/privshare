"""Simulated university system and PrivShare's sync from it."""
import urllib.error

import pytest

from backend import sis_client
from backend.db import get_db
from university_sim.app import create_app as create_sim

from .conftest import login

API_KEY = "test-sis-key-0123456789"


@pytest.fixture
def sim():
    return create_sim(api_key=API_KEY, n=250, seed=7, gpa_scale=4.0, bad_rows=2).test_client()


@pytest.fixture
def wired(app, sim, monkeypatch):
    """Point PrivShare's SIS client at the simulator's test client instead of the network."""
    app.config.update(SIS_URL="https://sis.test", SIS_API_KEY=API_KEY)

    def fake_get_page(base_url, api_key, page, ca_file, timeout):
        resp = sim.get(f"/api/students?page={page}", headers={"X-API-Key": api_key})
        if resp.status_code != 200:
            raise urllib.error.HTTPError(base_url, resp.status_code, "error", {}, None)
        return resp.get_json()
    monkeypatch.setattr(sis_client, "_get_page", fake_get_page)
    return sim


# --- the simulator itself ---

def test_sim_requires_api_key(sim):
    assert sim.get("/api/students").status_code == 401
    assert sim.get("/api/students", headers={"X-API-Key": "wrong-key-wrong-key"}).status_code == 401
    assert sim.get("/api/health").status_code == 200


def test_sim_paginates(sim):
    first = sim.get("/api/students?page=1", headers={"X-API-Key": API_KEY}).get_json()
    last = sim.get("/api/students?page=3", headers={"X-API-Key": API_KEY}).get_json()
    assert first["total"] == 250 and len(first["students"]) == 100 and len(last["students"]) == 50
    assert set(first["students"][0]) == {"student_no", "name", "national_id", "major", "gpa",
                                         "grad_year", "coop_completed"}


def test_sim_refuses_short_key():
    with pytest.raises(RuntimeError):
        create_sim(api_key="short")


# --- sync ---

def test_owner_sync_imports_and_reports_bad_rows(app, client, accounts, wired):
    token = login(client, accounts["uni_owner"])
    resp = client.post("/api/owner/sync", headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    report = resp.get_json()["report"]
    assert report["rows_total"] == 250 and report["rows_ok"] == 248 and report["rows_rejected"] == 2
    assert {r["column"] for r in report["rejected"]} == {"gpa", "national_id"}

    again = client.post("/api/owner/sync", headers={"X-CSRFToken": token}).get_json()["report"]
    assert again["added"] == 0 and again["updated"] == 248          # upsert by student number
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 248
        assert db.execute("SELECT source FROM data_imports").fetchall()[0]["source"] == "api"


def test_sync_reports_unreachable_system(app, client, accounts, monkeypatch):
    app.config.update(SIS_URL="https://sis.test", SIS_API_KEY=API_KEY)

    def down(*_args):
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr(sis_client, "_get_page", down)
    token = login(client, accounts["uni_owner"])
    resp = client.post("/api/owner/sync", headers={"X-CSRFToken": token})
    assert resp.status_code == 502 and resp.get_json()["error"] == "University system unreachable"


def test_sync_with_wrong_key(app, client, accounts, wired):
    app.config.update(SIS_API_KEY="not-the-right-key-123")
    token = login(client, accounts["uni_owner"])
    resp = client.post("/api/owner/sync", headers={"X-CSRFToken": token})
    assert resp.status_code == 502 and "API key" in resp.get_json()["error"]


def test_sync_not_configured(app, client, accounts):
    app.config.update(SIS_API_KEY="")
    token = login(client, accounts["uni_owner"])
    assert client.post("/api/owner/sync", headers={"X-CSRFToken": token}).status_code == 502
