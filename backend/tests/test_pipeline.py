"""End-to-end query pipeline through the API (with the stub chain)."""
import json
import time

import numpy as np
import pytest

from backend import audit
from backend.catalog import QUERY_TYPES
from backend.db import get_db

from .conftest import insert_students, login

BIG = {"major": "Cybersecurity", "grad_year": 2024}     # 120 students
SMALL = {"major": "Data Science", "grad_year": 2024}    # 5 students (< k)
BIG_GPAS = list(np.random.default_rng(1).uniform(2.5, 4.0, 120).round(2))
BIG_COOP = [1] * 90 + [0] * 30                           # 75 %


@pytest.fixture
def data(app):
    with app.app_context():
        insert_students(get_db(), "Cybersecurity", 2024, BIG_GPAS, BIG_COOP)
        insert_students(get_db(), "Data Science", 2024, [3.0] * 5, [1] * 5)


@pytest.fixture
def approved(app):
    chain = app.extensions["chain"]
    for name in QUERY_TYPES:
        chain.approve(name, "university")
        chain.approve(name, "partner")


@pytest.fixture
def analyst(client, accounts):
    return client, login(client, accounts["analyst"])


def ask(analyst, query_type, filters, epsilon=0.5):
    client, token = analyst
    return client.post("/api/query", headers={"X-CSRFToken": token},
                       json={"query_type": query_type, "filters": filters, "epsilon": epsilon})


def audit_rows(app):
    with app.app_context():
        return get_db().execute("SELECT * FROM audit_records ORDER BY id").fetchall()


def spent(app, user_id):
    with app.app_context():
        return get_db().execute("SELECT epsilon_spent FROM privacy_budget WHERE user_id = ?",
                                (user_id,)).fetchone()[0]


# --- happy path ---

def test_count_query(analyst, data, approved):
    resp = ask(analyst, "graduates_count", BIG, 1.0)
    assert resp.status_code == 200
    body = resp.get_json()
    assert isinstance(body["result"], int) and abs(body["result"] - 120) < 30
    assert body["budget"] == {"total": 5.0, "spent": 1.0, "remaining": 4.0}


def test_avg_gpa_query(analyst, data, approved):
    body = ask(analyst, "avg_gpa", BIG, 1.0).get_json()
    assert abs(body["result"] - float(np.mean(BIG_GPAS))) < 0.3   # b = 4/120 = 0.033


def test_coop_rate_query(analyst, data, approved):
    body = ask(analyst, "coop_rate", BIG, 1.0).get_json()
    assert 0.0 <= body["result"] <= 1.0 and abs(body["result"] - 0.75) < 0.15


def test_response_contains_only_the_aggregate(analyst, data, approved):
    body = ask(analyst, "avg_gpa", BIG).get_json()
    assert set(body) == {"query_type", "label", "filters", "epsilon", "result", "budget", "tx_hash"}
    text = json.dumps({k: v for k, v in body.items() if k != "tx_hash"})  # random hex could contain "120"
    assert "120" not in text and "Student" not in text   # no group size, no records


def test_executed_query_is_fingerprinted_on_chain(app, analyst, data, approved):
    for qt in QUERY_TYPES:
        assert ask(analyst, qt, BIG).status_code == 200
    rows = audit_rows(app)
    chain = app.extensions["chain"]
    assert len(rows) == chain.count() == 3            # 100 % of executed queries logged
    for i, row in enumerate(rows):
        assert audit.fingerprint(row) == row["sha256"]
        assert row["chain_index"] == i and row["tx_hash"].startswith("0x")
        entry = chain.get_entry(row["chain_index"])
        assert entry.record_hash == row["sha256"] and chain.query_type_matches(entry, row["query_type"])
        assert row["group_size"] == 120      # exact size kept off-chain for the auditor
    assert chain.group_sizes == [10, 10, 10]  # chain only learns "at least k"


def test_tampered_record_no_longer_matches(app, analyst, data, approved):
    ask(analyst, "avg_gpa", BIG)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE audit_records SET result_noisy = result_noisy + 1")
        db.commit()
    row = audit_rows(app)[0]
    assert audit.fingerprint(row) != app.extensions["chain"].get_entry(0).record_hash


def test_revoked_query_type_is_refused(app, analyst, data, approved):
    assert ask(analyst, "avg_gpa", BIG).status_code == 200
    app.extensions["chain"].revoke("avg_gpa", "university")
    assert ask(analyst, "avg_gpa", BIG).status_code == 403


def test_whole_population_query(analyst, data, approved):
    assert ask(analyst, "graduates_count", {}).status_code == 200


def test_query_under_3_seconds_for_500_records(app, analyst, approved):
    from backend import crypto, data_gen
    with app.app_context():
        data_gen.seed(get_db(), 500, crypto.load_key(), rng_seed=3)
    start = time.perf_counter()
    assert ask(analyst, "avg_gpa", {}).status_code == 200
    assert time.perf_counter() - start < 3.0


# --- refusals ---

def test_not_approved(app, analyst, data):
    resp = ask(analyst, "avg_gpa", BIG)
    assert resp.status_code == 403 and "not approved" in resp.get_json()["error"]
    app.extensions["chain"].approve("avg_gpa", "university")      # one side only
    assert ask(analyst, "avg_gpa", BIG).status_code == 403


def test_small_group_rejected_with_unified_message(app, analyst, accounts, data, approved):
    for qt in QUERY_TYPES:
        resp = ask(analyst, qt, SMALL)
        assert resp.status_code == 403
        assert resp.get_json() == {"error": "Query rejected by privacy policy"}
    assert spent(app, accounts["analyst"].id) == 0.0
    assert audit_rows(app) == []


def test_budget_exhausted(app, analyst, accounts, data, approved):
    for _ in range(5):
        assert ask(analyst, "graduates_count", BIG, 1.0).status_code == 200
    resp = ask(analyst, "graduates_count", BIG, 0.1)
    assert resp.status_code == 403 and resp.get_json()["error"] == "Privacy budget exhausted"
    client, _ = analyst
    assert client.get("/api/query/budget").get_json()["budget"]["remaining"] == 0.0


def test_fail_closed_when_chain_down(app, analyst, accounts, data, approved):
    app.extensions["chain"].available = False
    resp = ask(analyst, "avg_gpa", BIG)
    assert resp.status_code == 503
    assert spent(app, accounts["analyst"].id) == 0.0 and audit_rows(app) == []


def test_chain_failure_during_logging_rolls_back(app, analyst, accounts, data, approved, monkeypatch):
    chain = app.extensions["chain"]
    original = chain.log_query

    def node_dies(*args):  # node goes down between the approval check and the logging write
        chain.available = False
        return original(*args)
    monkeypatch.setattr(chain, "log_query", node_dies)
    assert ask(analyst, "avg_gpa", BIG).status_code == 503
    assert spent(app, accounts["analyst"].id) == 0.0 and audit_rows(app) == []


@pytest.mark.parametrize("body", [
    {"query_type": "SELECT * FROM students", "filters": BIG, "epsilon": 0.5},
    {"query_type": "avg_gpa", "filters": {"major": "Cybersecurity' OR '1'='1"}, "epsilon": 0.5},
    {"query_type": "avg_gpa", "filters": {"name": "x"}, "epsilon": 0.5},
    {"query_type": "avg_gpa", "filters": {"grad_year": "2024"}, "epsilon": 0.5},
    {"query_type": "avg_gpa", "filters": BIG, "epsilon": 5},
    {"query_type": "avg_gpa", "filters": BIG, "epsilon": 0.01},
    {"query_type": "avg_gpa", "filters": BIG, "epsilon": "0.5"},
    {"query_type": "avg_gpa", "filters": BIG, "epsilon": float("nan")},
    {"query_type": "avg_gpa", "filters": "major=Cybersecurity", "epsilon": 0.5},
])
def test_invalid_requests(analyst, data, approved, body):
    client, token = analyst
    resp = client.post("/api/query", headers={"X-CSRFToken": token, "Content-Type": "application/json"},
                       data=json.dumps(body))
    assert resp.status_code == 400


@pytest.mark.parametrize("role", ["uni_owner", "partner_rep", "admin", "auditor"])
def test_only_analysts_can_query(client, accounts, data, approved, role):
    token = login(client, accounts[role])
    resp = client.post("/api/query", headers={"X-CSRFToken": token},
                       json={"query_type": "avg_gpa", "filters": BIG, "epsilon": 0.5})
    assert resp.status_code == 403


def test_rejections_logged_for_anomaly_detection(app, analyst, data, approved):
    ask(analyst, "avg_gpa", SMALL)
    with app.app_context():
        row = get_db().execute("SELECT detail FROM security_events WHERE action = 'query_rejected'").fetchone()
    assert json.loads(row["detail"])["reason"] == "privacy_policy"


def test_options(analyst, data):
    client, _ = analyst
    body = client.get("/api/query/options").get_json()
    assert body["filters"] == {"major": ["Cybersecurity", "Data Science"], "grad_year": [2024]}
    assert body["epsilon"] == {"min": 0.1, "max": 1.0}
    assert body["gpa_scale"] == 4.0


# --- step 3b: analyst permissions set by the owner ---

def set_perm(app, user_id, **perm):
    from backend import permissions
    with app.app_context():
        permissions.save(get_db(), user_id, permissions.validate(perm))


def used(app, user_id):
    with app.app_context():
        return get_db().execute("SELECT queries_used FROM analyst_permissions WHERE analyst_id = ?",
                                (user_id,)).fetchone()[0]


def test_query_type_outside_permissions(app, analyst, accounts, data, approved):
    set_perm(app, accounts["analyst"].id, query_types=["graduates_count"])
    resp = ask(analyst, "avg_gpa", BIG)
    assert resp.status_code == 403 and resp.get_json() == {"error": "Outside your permissions"}
    assert ask(analyst, "graduates_count", BIG).status_code == 200


def test_major_restriction_requires_an_allowed_major_filter(app, analyst, accounts, data, approved):
    set_perm(app, accounts["analyst"].id, majors=["Cybersecurity"])
    assert ask(analyst, "graduates_count", BIG).status_code == 200
    assert ask(analyst, "graduates_count", {"major": "Data Science"}).status_code == 403
    # No major filter = all majors, which includes disallowed ones
    assert ask(analyst, "graduates_count", {"grad_year": 2024}).status_code == 403


def test_year_restriction(app, analyst, accounts, data, approved):
    set_perm(app, accounts["analyst"].id, years=[2023])
    assert ask(analyst, "graduates_count", BIG).status_code == 403


def test_max_queries_counts_only_executed_queries(app, analyst, accounts, data, approved):
    uid = accounts["analyst"].id
    set_perm(app, uid, max_queries=2)
    assert ask(analyst, "avg_gpa", SMALL).status_code == 403          # k-rejection: not counted
    assert ask(analyst, "avg_gpa", BIG).status_code == 200
    assert ask(analyst, "avg_gpa", BIG).status_code == 200
    assert used(app, uid) == 2
    resp = ask(analyst, "avg_gpa", BIG)
    assert resp.status_code == 403 and resp.get_json()["error"] == "Outside your permissions"
    assert spent(app, uid) == 1.0                                    # third query charged nothing


def test_permission_check_comes_before_the_group_size_check(app, analyst, accounts, data, approved):
    """An analyst outside their permissions learns nothing about group sizes there."""
    set_perm(app, accounts["analyst"].id, majors=["Cybersecurity"])
    assert ask(analyst, "avg_gpa", SMALL).get_json()["error"] == "Outside your permissions"


def test_options_narrowed_to_permissions(app, analyst, accounts, data):
    set_perm(app, accounts["analyst"].id, query_types=["avg_gpa"], majors=["Data Science"])
    client, _ = analyst
    body = client.get("/api/query/options").get_json()
    assert [t["name"] for t in body["query_types"]] == ["avg_gpa"]
    assert body["filters"]["major"] == ["Data Science"] and body["required_filters"] == ["major"]
