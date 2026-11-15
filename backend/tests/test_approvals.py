import pytest

from backend.catalog import QUERY_TYPES
from backend.chain import ChainRejected, StubChain

from .conftest import login, make_app


def _approve(client, token, name):
    return client.post(f"/api/approvals/query-types/{name}/approve", headers={"X-CSRFToken": token})


def _status(client, name):
    types = client.get("/api/approvals/query-types").get_json()["query_types"]
    return next(t for t in types if t["name"] == name)


def test_whitelist_seeded_unapproved(client, accounts):
    login(client, accounts["analyst"])
    types = client.get("/api/approvals/query-types").get_json()["query_types"]
    assert {t["name"] for t in types} == set(QUERY_TYPES)
    assert not any(t["approved"] for t in types)


def test_both_parties_needed(app, accounts):
    uni, partner = app.test_client(), app.test_client()
    resp = _approve(uni, login(uni, accounts["uni_owner"]), "avg_gpa")
    assert resp.status_code == 200 and resp.get_json()["tx_hash"].startswith("0x")
    s = _status(uni, "avg_gpa")
    assert s["approved_uni"] and not s["approved_partner"] and not s["approved"]
    assert not app.extensions["chain"].is_approved("avg_gpa")

    _approve(partner, login(partner, accounts["partner_rep"]), "avg_gpa")
    assert _status(uni, "avg_gpa")["approved"]
    assert app.extensions["chain"].is_approved("avg_gpa")


def test_either_party_can_revoke(app, accounts):
    uni, partner = app.test_client(), app.test_client()
    uni_token, partner_token = login(uni, accounts["uni_owner"]), login(partner, accounts["partner_rep"])
    _approve(uni, uni_token, "avg_gpa")
    _approve(partner, partner_token, "avg_gpa")
    assert _status(uni, "avg_gpa")["approved"]

    resp = partner.post("/api/approvals/query-types/avg_gpa/revoke", headers={"X-CSRFToken": partner_token})
    assert resp.status_code == 200
    s = _status(uni, "avg_gpa")
    assert s["approved_uni"] and not s["approved_partner"] and not s["approved"]
    assert not app.extensions["chain"].is_approved("avg_gpa")


def test_revoke_fails_closed_when_chain_down(app, client, accounts):
    token = login(client, accounts["uni_owner"])
    _approve(client, token, "avg_gpa")
    app.extensions["chain"].available = False
    assert client.post("/api/approvals/query-types/avg_gpa/revoke",
                       headers={"X-CSRFToken": token}).status_code == 503
    app.extensions["chain"].available = True
    assert _status(client, "avg_gpa")["approved_uni"]


def test_analyst_cannot_revoke(client, accounts):
    token = login(client, accounts["analyst"])
    assert client.post("/api/approvals/query-types/avg_gpa/revoke",
                       headers={"X-CSRFToken": token}).status_code == 403


@pytest.mark.parametrize("role", ["analyst", "admin", "auditor"])
def test_other_roles_cannot_approve(client, accounts, role):
    assert _approve(client, login(client, accounts[role]), "avg_gpa").status_code == 403


def test_admin_cannot_view_query_types(client, accounts):
    login(client, accounts["admin"])
    assert client.get("/api/approvals/query-types").status_code == 403


def test_unknown_query_type(client, accounts):
    assert _approve(client, login(client, accounts["uni_owner"]), "raw_records").status_code == 404


def test_approval_fails_closed_when_chain_down(app, client, accounts):
    token = login(client, accounts["uni_owner"])
    app.extensions["chain"].available = False
    assert _approve(client, token, "avg_gpa").status_code == 503
    app.extensions["chain"].available = True
    assert not _status(client, "avg_gpa")["approved_uni"]


def test_stub_reloads_approvals_after_restart(tmp_path, app, accounts):
    uni, partner = app.test_client(), app.test_client()
    _approve(uni, login(uni, accounts["uni_owner"]), "coop_rate")
    _approve(partner, login(partner, accounts["partner_rep"]), "coop_rate")
    assert make_app(tmp_path).extensions["chain"].is_approved("coop_rate")


def test_stub_contract_rules():
    chain = StubChain()
    with pytest.raises(ChainRejected):
        chain.log_query("avg_gpa", "ab" * 32, 50)    # not approved
    chain.approve("avg_gpa", "university")
    chain.approve("avg_gpa", "partner")
    with pytest.raises(ChainRejected):
        chain.log_query("avg_gpa", "ab" * 32, 9)     # group below k
    chain.log_query("avg_gpa", "ab" * 32, 10)
    assert chain.count() == 1
    with pytest.raises(ChainRejected):
        chain.approve("avg_gpa", "someone_else")
