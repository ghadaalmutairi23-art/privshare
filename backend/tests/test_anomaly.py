"""Anomaly detection: features, the Isolation Forest, live alerts after queries, admin endpoints."""
import random

import numpy as np
import pytest

from backend import anomaly
from backend.db import get_db

from .conftest import login
from .test_pipeline import BIG, analyst, approved, ask, data  # noqa: F401  (fixtures)


# --- features ---

def q(qt="avg_gpa", filters=None, eps=0.5, size=100, refused=False):
    return {"query_type": qt, "filters": filters or {}, "epsilon": eps, "group_size": None if refused else size,
            "refused": refused}


def test_window_features():
    queries = [q(filters={"major": "Cybersecurity"}), q(filters={"major": "Cybersecurity"}, size=120),
               q(qt="graduates_count", eps=1.0, size=None, refused=True), q(filters={"major": "Cybersecurity"})]
    f = anomaly.window_features(queries)
    assert f["n_queries"] == 4 and f["n_refused"] == 1 and f["distinct_filters"] == 2
    assert f["repeats"] == 2 and f["eps_spent"] == 1.5 and f["avg_group_size"] == pytest.approx(106.7)
    assert set(f) == set(anomaly.FEATURES)


def test_only_refusals_count_as_small_groups():
    assert anomaly.window_features([q(refused=True)])["avg_group_size"] == anomaly.SMALL_GROUP_DEFAULT


# --- the model ---

def test_false_alarm_rate_on_unseen_normal_behaviour():
    rng = random.Random(2026)
    X = [anomaly.window_features(anomaly.normal_session(rng)) for _ in range(1500)]
    flagged = sum(anomaly.score_many(X)[1])
    assert flagged / len(X) < 0.03            # trained for ~1 %


@pytest.mark.parametrize("kind", ["differencing", "averaging", "probing"])
def test_attacks_are_detected(kind):
    rng = random.Random(7)
    X = [anomaly.window_features(anomaly.attack_session(rng, kind)) for _ in range(200)]
    assert np.mean(anomaly.score_many(X)[1]) > 0.95


def test_explanation_names_the_unusual_behaviour():
    f = anomaly.window_features(anomaly.attack_session(random.Random(1), "averaging"))
    reason = anomaly.explain(f)
    assert "repeated" in reason and "normal" in reason


def test_far_beyond_normal_is_flagged_even_when_the_model_saturates():
    """25 narrow queries over 20 groups, none refused: the model alone may miss it, the hybrid check doesn't."""
    rng = random.Random(11)
    queries = [q(filters={"major": rng.choice(anomaly.MAJORS), "grad_year": rng.choice(anomaly.YEARS)},
                 eps=0.1, size=15) for _ in range(25)]
    result = anomaly.assess([anomaly.window_features(queries)])[0]
    assert result["flagged"] and "far_beyond_normal" in result["detected_by"]


def test_simulation_script_flags_only_the_attacker(capsys, monkeypatch):
    import importlib.util
    import os
    from pathlib import Path
    for name in ("DATA_KEY", "SECRET_KEY", "CHAIN_BACKEND", "GPA_SCALE"):  # the script sets its own; restore after
        monkeypatch.setenv(name, os.environ.get(name, ""))
    path = Path(__file__).resolve().parents[2] / "scripts" / "simulate_attack.py"
    spec = importlib.util.spec_from_file_location("simulate_attack", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--attack", "differencing", "--seed", "7"]) == 0
    assert "attacker flagged, normal analysts not flagged" in capsys.readouterr().out


def test_model_is_deterministic():
    f = anomaly.window_features(anomaly.attack_session(random.Random(3), "probing"))
    assert anomaly.score(f) == anomaly.score(f)


# --- live: alerts raised by real queries ---

def attack(analyst, n=25):  # noqa: F811  - one narrow query repeated to average the noise
    codes = [ask(analyst, "avg_gpa", BIG, 0.1).status_code for _ in range(n)]
    assert codes.count(200) == n


def alerts(app):
    with app.app_context():
        return get_db().execute("SELECT * FROM alerts").fetchall()


def test_attacking_analyst_gets_one_alert(app, analyst, accounts, data, approved):  # noqa: F811
    with app.app_context():
        from backend import budget
        budget.set_total(get_db(), accounts["analyst"].id, 20)
    attack(analyst)
    rows = alerts(app)
    assert len(rows) == 1                     # one alert per window, updated while the attack continues
    assert rows[0]["user_id"] == accounts["analyst"].id and rows[0]["status"] == "open"
    assert rows[0]["score"] >= anomaly.threshold() and "repeated" in rows[0]["reason"]


def test_normal_use_raises_no_alert(app, analyst, data, approved):  # noqa: F811
    for qt in ("graduates_count", "avg_gpa", "coop_rate"):
        assert ask(analyst, qt, BIG).status_code == 200
    assert alerts(app) == []


def test_detection_can_be_switched_off(app, analyst, accounts, data, approved):  # noqa: F811
    app.config["ANOMALY_ENABLED"] = False
    with app.app_context():
        from backend import budget
        budget.set_total(get_db(), accounts["analyst"].id, 20)
    attack(analyst)
    assert alerts(app) == []


def test_detection_failure_never_breaks_a_query(app, analyst, data, approved, monkeypatch):  # noqa: F811
    def boom(*_a, **_k):
        raise RuntimeError("model unavailable")
    monkeypatch.setattr(anomaly, "check_user", boom)
    assert ask(analyst, "avg_gpa", BIG).status_code == 200


# --- admin endpoints ---

@pytest.fixture
def admin(app, accounts):
    client = app.test_client()
    return client, login(client, accounts["admin"])


def test_admin_lists_and_reviews_alerts(app, analyst, accounts, data, approved, admin):  # noqa: F811
    with app.app_context():
        from backend import budget
        budget.set_total(get_db(), accounts["analyst"].id, 20)
    attack(analyst)
    client, token = admin
    body = client.get("/api/admin/alerts?status=open").get_json()
    assert body["open"] == 1
    alert = body["alerts"][0]
    assert alert["analyst"] == "analyst_user" and set(alert["features"]) == set(anomaly.FEATURES)
    resp = client.patch(f"/api/admin/alerts/{alert['id']}", headers={"X-CSRFToken": token}, json={"status": "reviewed"})
    assert resp.status_code == 200 and resp.get_json()["alert"]["reviewed_by"] == "admin_user"
    assert client.get("/api/admin/alerts?status=open").get_json()["open"] == 0
    assert client.patch(f"/api/admin/alerts/{alert['id']}", headers={"X-CSRFToken": token},
                        json={"status": "deleted"}).status_code == 400
    assert client.patch("/api/admin/alerts/999", headers={"X-CSRFToken": token},
                        json={"status": "reviewed"}).status_code == 404


def test_admin_scan_and_security_events(app, analyst, accounts, data, approved, admin):  # noqa: F811
    client, token = admin
    assert client.post("/api/admin/alerts/scan", headers={"X-CSRFToken": token}).get_json() == {"raised": 0}
    ask(analyst, "avg_gpa", {"major": "Data Science", "grad_year": 2024})       # refused (k)
    events = client.get("/api/admin/security-events?action=query_rejected").get_json()
    assert events["total"] == 1 and events["events"][0]["username"] == "analyst_user"
    assert client.get("/api/admin/security-events?page=0").status_code == 400


@pytest.mark.parametrize("role", ["uni_owner", "partner_rep", "analyst", "auditor"])
def test_only_admin_sees_alerts(client, accounts, role):
    token = login(client, accounts[role])
    assert client.get("/api/admin/alerts").status_code == 403
    assert client.get("/api/admin/security-events").status_code == 403
    assert client.post("/api/admin/alerts/scan", headers={"X-CSRFToken": token}).status_code == 403
