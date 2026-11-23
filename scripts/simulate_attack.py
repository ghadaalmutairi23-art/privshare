"""Simulate normal analysts and an attacker against PrivShare and show who the AI flags.

Run: python scripts/simulate_attack.py [--attack differencing|averaging|probing] [--seed 7]

Everything runs in memory: a temporary database, random keys and the in-memory chain, so your
own data, keys and blockchain are never touched. Every query goes through the real pipeline
(permissions, k >= 10, privacy budget, DP noise, audit log); after each one the Isolation Forest
re-scores that analyst, exactly as in the live server.

Note: time is compressed (all queries land in one 30-minute window) and rate limiting is off,
so the session runs in seconds. A real attacker would also hit the 30-queries-per-minute limit.
"""
import argparse
import base64
import os
import random
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Throw-away secrets for this run only (set before the backend reads its config)
os.environ["DATA_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["SECRET_KEY"] = os.urandom(32).hex()
os.environ["CHAIN_BACKEND"] = "stub"
os.environ["GPA_SCALE"] = "4"

import pyotp  # noqa: E402

from backend import anomaly, budget, crypto, data_gen, users  # noqa: E402
from backend.app import create_app  # noqa: E402
from backend.catalog import QUERY_TYPES  # noqa: E402
from backend.db import get_db  # noqa: E402

PASSWORD = "Simulation-Passw0rd!"


def login(app, username: str, secret: str):
    client = app.test_client()
    token = client.get("/api/auth/csrf").get_json()["csrf_token"]
    token = client.post("/api/auth/login", json={"username": username, "password": PASSWORD},
                        headers={"X-CSRFToken": token}).get_json()["csrf_token"]
    token = client.post("/api/auth/mfa", json={"code": pyotp.TOTP(secret).now()},
                        headers={"X-CSRFToken": token}).get_json()["csrf_token"]
    return client, token


def run_session(client, token, queries) -> tuple[int, int]:
    ok = refused = 0
    for q in queries:
        resp = client.post("/api/query", headers={"X-CSRFToken": token},
                           json={"query_type": q["query_type"], "filters": q["filters"], "epsilon": q["epsilon"]})
        ok, refused = (ok + 1, refused) if resp.status_code == 200 else (ok, refused + 1)
    return ok, refused


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attack", choices=("differencing", "averaging", "probing"), default="differencing")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    rng = random.Random(args.seed)

    with tempfile.TemporaryDirectory() as tmp:
        app = create_app({"TESTING": True, "DB_PATH": str(Path(tmp) / "sim.db"),
                          "SESSION_COOKIE_SECURE": False, "RATELIMIT_ENABLED": False})
        names = ["analyst_normal_1", "analyst_normal_2", "analyst_normal_3", "analyst_attacker"]
        with app.app_context():
            db = get_db()
            data_gen.seed(db, 500, crypto.load_key(), rng_seed=args.seed)
            secrets = {}
            for name in names:
                uid, secrets[name] = users.create_user(db, name, PASSWORD, "analyst", 20.0)
                budget.set_total(db, uid, 20.0)
        chain = app.extensions["chain"]
        for qt in QUERY_TYPES:
            chain.approve(qt, "university")
            chain.approve(qt, "partner")

        print(f"Simulating 3 normal analysts and 1 attacker ({args.attack} attack), seed {args.seed}\n")
        for name in names:
            client, token = login(app, name, secrets[name])
            if name.endswith("attacker"):
                queries = anomaly.attack_session(rng, args.attack)
            else:
                queries = [q for _ in range(2) for q in anomaly.normal_session(rng)][:8]
            ok, refused = run_session(client, token, queries)
            print(f"  {name:<18} sent {len(queries):>2} queries: {ok:>2} answered, {refused:>2} refused")

        print(f"\nIsolation Forest score per analyst (alert threshold {anomaly.threshold()}):\n")
        print(f"  {'analyst':<18} " + " ".join(f"{f:>16}" for f in anomaly.FEATURES)
              + f" {'score':>7}  flagged by")
        with app.app_context():
            db = get_db()
            for name in names:
                uid = users.get_by_username(db, name)["id"]
                features = anomaly.window_features(anomaly.user_queries(
                    db, uid, anomaly._now() - timedelta(minutes=anomaly.WINDOW_MINUTES)))
                result = anomaly.assess([features])[0]
                print(f"  {name:<18} " + " ".join(f"{features[f]:>16g}" for f in anomaly.FEATURES)
                      + f" {result['score']:>7.3f}  {', '.join(result['detected_by']) or '-'}")
            alerts = db.execute("SELECT a.*, u.username FROM alerts a JOIN users u ON u.id = a.user_id").fetchall()

        print("\nAlerts raised for the administrator (during the session):")
        for a in alerts:
            print(f"  [{a['status']}] {a['username']}  score {a['score']}  detected by: {a['detected_by']}\n"
                  f"    reason: {a['reason']}")
        if not alerts:
            print("  (none)")

    alerted = {a["username"] for a in alerts}
    success = alerted == {"analyst_attacker"}
    print("\nResult:", "attacker flagged, normal analysts not flagged" if success else "UNEXPECTED - see scores above")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
