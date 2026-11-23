"""Auditor endpoints with the in-memory chain: audit log, verification, tamper detection, access."""
import pytest

from backend.db import get_db

from .conftest import login
from .test_pipeline import BIG, analyst, approved, ask, data  # noqa: F401  (fixtures)


@pytest.fixture
def auditor(app, accounts):
    client = app.test_client()
    return client, login(client, accounts["auditor"])


def verify(auditor):
    client, token = auditor
    return client.post("/api/audit/verify", headers={"X-CSRFToken": token})


def run_queries(analyst, n=3):  # noqa: F811
    for _ in range(n):
        assert ask(analyst, "avg_gpa", BIG).status_code == 200


def test_auditor_lists_records_without_student_data(analyst, auditor, data, approved):  # noqa: F811
    run_queries(analyst, 2)
    client, _ = auditor
    body = client.get("/api/audit/records").get_json()
    assert body["total"] == 2
    rec = body["records"][0]
    assert rec["analyst"] == "analyst_user" and rec["filters"] == BIG and rec["chain_index"] == 1
    assert set(rec) == {"id", "timestamp", "analyst", "query_type", "filters", "epsilon", "group_size",
                        "result_noisy", "sha256", "tx_hash", "chain_index"}


def test_verify_all_ok(app, analyst, auditor, data, approved):  # noqa: F811
    run_queries(analyst)
    report = verify(auditor).get_json()["report"]
    assert report["all_ok"] and report["counts"] == {"verified": 3, "tampered": 0, "not_on_chain": 0}
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM security_events WHERE action='audit_verified'").fetchone()[0] == 1


@pytest.mark.parametrize("sql", [
    "UPDATE audit_records SET result_noisy = result_noisy + 0.01 WHERE id = 2",
    "UPDATE audit_records SET epsilon = 0.1 WHERE id = 2",
    "UPDATE audit_records SET params_json = '{\"major\":\"Data Science\"}' WHERE id = 2",
])
def test_tampered_record_is_detected(app, analyst, auditor, data, approved, sql):  # noqa: F811
    run_queries(analyst)
    with app.app_context():
        db = get_db()
        db.execute(sql)
        db.commit()
    report = verify(auditor).get_json()["report"]
    assert not report["all_ok"]
    assert [r["id"] for r in report["results"] if r["status"] == "tampered"] == [2]


def test_rewriting_the_stored_hash_does_not_hide_tampering(app, analyst, auditor, data, approved):  # noqa: F811
    """An attacker who edits a record AND recomputes its sha256 column is still caught by the chain."""
    from backend import audit
    run_queries(analyst, 1)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE audit_records SET result_noisy = 9.99")
        row = db.execute("SELECT * FROM audit_records").fetchone()
        db.execute("UPDATE audit_records SET sha256 = ?", (audit.fingerprint(row),))
        db.commit()
    assert verify(auditor).get_json()["report"]["counts"]["tampered"] == 1


def test_deleted_record_is_detected(app, analyst, auditor, data, approved):  # noqa: F811
    run_queries(analyst)
    with app.app_context():
        db = get_db()
        db.execute("DELETE FROM audit_records WHERE id = 2")
        db.commit()
    report = verify(auditor).get_json()["report"]
    assert not report["all_ok"] and report["on_chain_without_record"] == [1]


def test_verify_fails_closed_when_chain_down(app, auditor):
    app.extensions["chain"].available = False
    assert verify(auditor).status_code == 503


def test_chain_info(auditor):
    client, _ = auditor
    assert client.get("/api/audit/chain").get_json()["chain"]["backend"] == "stub"


@pytest.mark.parametrize("role", ["uni_owner", "partner_rep", "analyst", "admin"])
def test_only_auditor_can_audit(client, accounts, role):
    token = login(client, accounts[role])
    assert client.get("/api/audit/records").status_code == 403
    assert client.post("/api/audit/verify", headers={"X-CSRFToken": token}).status_code == 403
