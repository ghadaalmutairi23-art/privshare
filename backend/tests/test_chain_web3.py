"""The REAL PrivShareAudit contract on a real Anvil node (skipped if Anvil isn't installed).

Covers the contract's own rules, the full API flow on-chain, tamper detection, fail-closed
when the node stops, state surviving a node restart, and the <= 5 s logging target.
"""
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from web3 import Web3
from web3.exceptions import ContractLogicError

from backend import contract_deploy
from backend.chain import ChainRejected, ChainUnavailable, Web3Chain
from backend.db import get_db

from .conftest import insert_students, login, make_app

ROOT = Path(__file__).resolve().parents[2]
LOCAL_ANVIL = ROOT / "tools" / "foundry" / ("anvil.exe" if sys.platform == "win32" else "anvil")
ANVIL = str(LOCAL_ANVIL) if LOCAL_ANVIL.exists() else shutil.which("anvil")
pytestmark = pytest.mark.skipif(ANVIL is None, reason="Anvil not installed (python scripts/get_anvil.py)")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Node:
    """A throw-away Anvil process."""

    def __init__(self, state: Path | None = None, port: int | None = None):
        self.port = port or _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        cmd = [ANVIL, "--host", "127.0.0.1", "--port", str(self.port), "--silent"]
        if state:
            cmd += ["--state", str(state), "--state-interval", "1"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        w3 = Web3(Web3.HTTPProvider(self.url, request_kwargs={"timeout": 2}))
        for _ in range(100):
            if w3.is_connected():
                return
            time.sleep(0.1)
        self.stop()
        raise RuntimeError("Anvil did not start")

    def stop(self):
        self.proc.kill()
        self.proc.wait(timeout=10)


@pytest.fixture
def node():
    n = Node()
    yield n
    n.stop()


@pytest.fixture
def deployed(node, tmp_path):
    file = tmp_path / "deployment.json"
    contract_deploy.deploy(node.url, file)
    return node, file


@pytest.fixture
def chain_app(deployed, tmp_path):
    node, file = deployed
    app = make_app(tmp_path, CHAIN_BACKEND="web3", RPC_URL=node.url, CHAIN_DEPLOYMENT_FILE=str(file),
                   CHAIN_TIMEOUT=5.0)
    return app, node


# --- the contract itself ---

def test_contract_rules(deployed):
    node, file = deployed
    chain = Web3Chain(node.url, str(file))
    sha = "ab" * 32
    with pytest.raises(ChainRejected):
        chain.log_query("avg_gpa", sha, 50)                      # not approved by anyone
    chain.approve("avg_gpa", "university")
    assert chain.approval_status("avg_gpa") == (True, False) and not chain.is_approved("avg_gpa")
    with pytest.raises(ChainRejected):
        chain.log_query("avg_gpa", sha, 50)                      # partner hasn't approved
    chain.approve("avg_gpa", "partner")
    assert chain.is_approved("avg_gpa")
    with pytest.raises(ChainRejected):
        chain.log_query("avg_gpa", sha, 9)                       # k = 10 enforced on-chain
    receipt = chain.log_query("avg_gpa", sha, 10)
    assert receipt.index == 0 and chain.count() == 1
    entry = chain.get_entry(0)
    assert entry.record_hash == sha and chain.query_type_matches(entry, "avg_gpa")
    chain.revoke("avg_gpa", "partner")
    with pytest.raises(ChainRejected):
        chain.log_query("avg_gpa", sha, 50)                      # revoked


def test_only_parties_approve_and_only_backend_logs(deployed):
    node, file = deployed
    info = json.loads(file.read_text())
    w3 = Web3(Web3.HTTPProvider(node.url))
    c = w3.eth.contract(address=info["address"], abi=info["abi"])
    qid = Web3.keccak(text="avg_gpa")
    outsider = w3.eth.accounts[5]
    with pytest.raises(ContractLogicError):
        c.functions.approveQueryType(qid).transact({"from": outsider})
    c.functions.approveQueryType(qid).transact({"from": info["accounts"]["university"]})
    c.functions.approveQueryType(qid).transact({"from": info["accounts"]["partner"]})
    with pytest.raises(ContractLogicError):                     # the university can't log queries
        c.functions.logQuery(qid, b"\x01" * 32, 10).transact({"from": info["accounts"]["university"]})
    with pytest.raises(ContractLogicError):                     # empty hash refused
        c.functions.logQuery(qid, b"\x00" * 32, 10).transact({"from": info["accounts"]["logger"]})


def test_deploy_detects_live_contract(deployed):
    node, file = deployed
    w3 = Web3(Web3.HTTPProvider(node.url))
    assert contract_deploy.contract_is_live(w3, file)
    assert not contract_deploy.contract_is_live(w3, file.parent / "missing.json")


def test_logging_takes_under_5_seconds(deployed):
    node, file = deployed
    chain = Web3Chain(node.url, str(file))
    chain.approve("graduates_count", "university")
    chain.approve("graduates_count", "partner")
    start = time.perf_counter()
    chain.log_query("graduates_count", "cd" * 32, 10)
    assert time.perf_counter() - start < 5.0


# --- the whole system on the real chain ---

def test_full_flow_on_chain_with_tamper_detection(chain_app, accounts_factory):
    app, _ = chain_app
    acc = accounts_factory(app)
    with app.app_context():
        insert_students(get_db(), "Cybersecurity", 2024, [3.0 + (i % 10) / 10 for i in range(60)], [1] * 60)

    uni, partner, analyst, auditor = (app.test_client() for _ in range(4))
    for client, role in ((uni, "uni_owner"), (partner, "partner_rep")):
        token = login(client, acc[role])
        resp = client.post("/api/approvals/query-types/avg_gpa/approve", headers={"X-CSRFToken": token})
        assert resp.status_code == 200 and resp.get_json()["tx_hash"].startswith("0x")
    listed = uni.get("/api/approvals/query-types").get_json()
    assert listed["chain_available"] and next(t for t in listed["query_types"] if t["name"] == "avg_gpa")["approved"]

    token = login(analyst, acc["analyst"])
    for _ in range(2):
        resp = analyst.post("/api/query", headers={"X-CSRFToken": token},
                            json={"query_type": "avg_gpa", "filters": {"major": "Cybersecurity"}, "epsilon": 0.5})
        assert resp.status_code == 200

    a_token = login(auditor, acc["auditor"])
    assert auditor.get("/api/audit/chain").get_json()["chain"]["records"] == 2
    report = auditor.post("/api/audit/verify", headers={"X-CSRFToken": a_token}).get_json()["report"]
    assert report["all_ok"] and report["counts"]["verified"] == 2

    with app.app_context():
        db = get_db()
        db.execute("UPDATE audit_records SET result_noisy = 4.0 WHERE id = 1")
        db.commit()
    report = auditor.post("/api/audit/verify", headers={"X-CSRFToken": a_token}).get_json()["report"]
    assert [r["id"] for r in report["results"] if r["status"] == "tampered"] == [1]


def test_fail_closed_when_node_stops(chain_app, accounts_factory):
    app, node = chain_app
    acc = accounts_factory(app)
    with app.app_context():
        insert_students(get_db(), "Cybersecurity", 2024, [3.0] * 30, [1] * 30)
    chain = app.extensions["chain"]
    chain.approve("avg_gpa", "university")
    chain.approve("avg_gpa", "partner")
    node.stop()

    analyst = app.test_client()
    token = login(analyst, acc["analyst"])
    resp = analyst.post("/api/query", headers={"X-CSRFToken": token},
                        json={"query_type": "avg_gpa", "filters": {"major": "Cybersecurity"}, "epsilon": 0.5})
    assert resp.status_code == 503
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0] == 0
        assert db.execute("SELECT epsilon_spent FROM privacy_budget").fetchone()[0] == 0
    listed = analyst.get("/api/approvals/query-types").get_json()
    assert listed["chain_available"] is False
    with pytest.raises(ChainUnavailable):
        chain.count()


def test_missing_deployment_fails_closed(tmp_path):
    chain = Web3Chain("http://127.0.0.1:1", str(tmp_path / "nope.json"))
    with pytest.raises(ChainUnavailable):
        chain.is_approved("avg_gpa")
    assert chain.info()["available"] is False


def test_chain_state_survives_node_restart(tmp_path):
    state = tmp_path / "anvil-state.json"
    file = tmp_path / "deployment.json"
    first = Node(state=state)
    try:
        contract_deploy.deploy(first.url, file)
        chain = Web3Chain(first.url, str(file))
        chain.approve("coop_rate", "university")
        chain.approve("coop_rate", "partner")
        chain.log_query("coop_rate", "ef" * 32, 10)
        time.sleep(2.5)                      # let Anvil write its state file (--state-interval 1)
    finally:
        first.stop()

    second = Node(state=state, port=first.port)
    try:
        chain = Web3Chain(second.url, str(file))
        assert chain.is_approved("coop_rate") and chain.count() == 1
        assert chain.get_entry(0).record_hash == "ef" * 32
    finally:
        second.stop()
