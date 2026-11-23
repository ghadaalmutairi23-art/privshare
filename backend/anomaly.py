"""AI anomaly detection on analyst query behaviour (Isolation Forest).

Each analyst's activity in a time window (default: the last 30 minutes) becomes six numbers:

    n_queries        queries asked (executed + refused)
    n_refused        queries refused by the pipeline (privacy policy, permissions, budget ...)
    avg_group_size   mean group size of the executed queries (small groups = narrow probing)
    distinct_filters different statistic+filter combinations used
    eps_spent        privacy budget spent in the window
    repeats          queries identical to an earlier one in the window (noise averaging)
    repeat_share     repeats / n_queries

Isolation Forest can't rank a value beyond everything it saw in training as "more abnormal",
so an attack must stand out in several features at once; repeat_share adds that second
dimension for differencing/averaging attacks (measured: realistic differencing detection
34 % -> 100 %, false alarms 1.0 % -> 0.9 %).

An Isolation Forest is trained on synthetic NORMAL behaviour only (unsupervised): it learns what
usual sessions look like and isolates sessions that don't fit, such as a differencing attack
(many narrow, near-identical queries, often refused). The model never sees student data.
"""
import json
import random
import sqlite3
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ("n_queries", "n_refused", "avg_group_size", "distinct_filters", "eps_spent", "repeats", "repeat_share")
WINDOW_MINUTES = 30
SMALL_GROUP_DEFAULT = 10.0     # avg_group_size when nothing ran (only refusals) - treated as narrow
MODEL_SEED = 42
TRAINING_WINDOWS = 3000
CONTAMINATION = 0.01           # ~1 % of normal windows end up above the threshold


# --- features ---

def window_features(queries: list[dict]) -> dict:
    """queries: [{query_type, filters (dict), epsilon, group_size (None if refused), refused}] in time order."""
    executed = [q for q in queries if not q["refused"]]
    seen, repeats, combos = set(), 0, set()
    for q in queries:
        key = (q["query_type"], json.dumps(q["filters"] or {}, sort_keys=True))
        repeats += key in seen
        seen.add(key)
        combos.add(key)
    sizes = [q["group_size"] for q in executed if q["group_size"] is not None]
    return {
        "n_queries": len(queries),
        "n_refused": len(queries) - len(executed),
        "avg_group_size": round(float(np.mean(sizes)), 1) if sizes else SMALL_GROUP_DEFAULT,
        "distinct_filters": len(combos),
        "eps_spent": round(sum(q["epsilon"] for q in executed), 3),
        "repeats": repeats,
        "repeat_share": round(repeats / len(queries), 3) if queries else 0.0,
    }


def _vector(features: dict) -> list[float]:
    return [float(features[f]) for f in FEATURES]


# --- synthetic behaviour (training data and evaluation) ---

MAJORS = ("Computer Science", "Cybersecurity", "Data Science", "Information Systems", "Software Engineering")
YEARS = tuple(range(2020, 2026))
TYPES = ("graduates_count", "avg_gpa", "coop_rate")


def normal_session(rng: random.Random) -> list[dict]:
    """One window of typical analyst work: a few broad questions, varied, rarely repeated or refused."""
    queries = []
    for _ in range(rng.choice((1, 1, 2, 2, 3, 3, 4, 4, 5, 6, 7, 8))):
        if queries and rng.random() < 0.08:                    # occasionally re-asks the same thing
            q = dict(queries[-1])
        else:
            shape = rng.random()
            if shape < 0.55:
                filters, size = {"major": rng.choice(MAJORS)}, rng.randint(80, 125)
            elif shape < 0.80:
                filters, size = {"major": rng.choice(MAJORS), "grad_year": rng.choice(YEARS)}, rng.randint(10, 28)
            elif shape < 0.92:
                filters, size = {"grad_year": rng.choice(YEARS)}, rng.randint(70, 100)
            else:
                filters, size = {}, rng.randint(480, 520)
            # honest analysts sometimes pick the most private ε (0.1) too, so low ε alone isn't suspicious
            q = {"query_type": rng.choice(TYPES), "filters": filters,
                 "epsilon": rng.choice((0.1, 0.3, 0.5, 0.5, 0.5, 0.8, 1.0)), "group_size": size, "refused": False}
        if rng.random() < 0.03:                                  # rare refusal
            q = {**q, "group_size": None, "refused": True}
        queries.append(q)
    return queries


def attack_session(rng: random.Random, kind: str = "differencing") -> list[dict]:
    """Synthetic attacker windows used for evaluation and tests."""
    major = rng.choice(MAJORS)
    if kind == "averaging":       # repeat one narrow query many times to average the noise away
        q = {"query_type": "avg_gpa", "filters": {"major": major, "grad_year": rng.choice(YEARS)},
             "epsilon": 0.1, "group_size": rng.randint(10, 15), "refused": False}
        return [dict(q) for _ in range(rng.randint(20, 40))]
    if kind == "probing":         # hunt for tiny groups: mostly refused by the k-threshold
        queries = []
        for _ in range(rng.randint(15, 30)):
            refused = rng.random() < 0.6
            queries.append({"query_type": "graduates_count",
                            "filters": {"major": rng.choice(MAJORS), "grad_year": rng.choice(YEARS)},
                            "epsilon": 0.1, "group_size": None if refused else rng.randint(10, 12),
                            "refused": refused})
        return queries
    # differencing: the same statistic for a group and its sub-groups, repeated, to subtract answers
    queries = []
    for _ in range(rng.randint(2, 4)):
        queries.append({"query_type": "avg_gpa", "filters": {"major": major}, "epsilon": 0.1,
                        "group_size": rng.randint(90, 110), "refused": False})
        for year in YEARS:
            refused = rng.random() < 0.3
            queries.append({"query_type": "avg_gpa", "filters": {"major": major, "grad_year": year},
                            "epsilon": 0.1, "group_size": None if refused else rng.randint(10, 20),
                            "refused": refused})
    return queries


# --- model ---

_model = None
_normal_limits = None
_far_limits = None

# Hybrid detection. An Isolation Forest can't score a session as "more abnormal" than the most
# extreme normal one, so a count far beyond anything seen in normal training (>= 1.5x the
# maximum) is flagged as well. The model still judges unusual combinations inside that range.
FAR_FEATURES = ("n_queries", "n_refused", "distinct_filters", "repeats")
FAR_FACTOR = 1.5


def get_model():
    """Isolation Forest trained on synthetic normal windows (deterministic, trained once per process)."""
    global _model, _normal_limits, _far_limits
    if _model is None:
        rng = random.Random(MODEL_SEED)
        X = np.array([_vector(window_features(normal_session(rng))) for _ in range(TRAINING_WINDOWS)])
        _model = IsolationForest(n_estimators=200, contamination=CONTAMINATION, random_state=MODEL_SEED).fit(X)
        _normal_limits = {f: (float(np.percentile(X[:, i], 1)), float(np.percentile(X[:, i], 99)))
                          for i, f in enumerate(FEATURES)}
        _far_limits = {f: max(np.ceil(X[:, FEATURES.index(f)].max() * FAR_FACTOR),
                              X[:, FEATURES.index(f)].max() + 2) for f in FAR_FEATURES}
    return _model


def far_beyond_normal(features: dict) -> list[str]:
    """Count features at or above FAR_FACTOR x the largest value seen in normal training."""
    get_model()
    return [f for f in FAR_FEATURES if features[f] >= _far_limits[f]]


def assess(feature_rows: list[dict]) -> list[dict]:
    """Per window: anomaly score (0..1, higher = stranger), flagged?, and which check fired."""
    model = get_model()
    X = np.array([_vector(f) for f in feature_rows])
    raw = model.score_samples(X)                               # sklearn: lower = more abnormal
    by_model = model.predict(X) == -1
    out = []
    for f, r, m in zip(feature_rows, raw, by_model):
        far = far_beyond_normal(f)
        detected_by = [name for name, hit in (("model", bool(m)), ("far_beyond_normal", bool(far))) if hit]
        out.append({"score": round(float(-r), 3), "flagged": bool(detected_by), "detected_by": detected_by})
    return out


def score_many(feature_rows: list[dict]) -> tuple[list[float], list[bool]]:
    """Batch scores and flags (used for evaluation)."""
    results = assess(feature_rows)
    return [r["score"] for r in results], [r["flagged"] for r in results]


def score(features: dict) -> tuple[float, bool]:
    """(anomaly score 0..1, higher = stranger; flagged?)."""
    r = assess([features])[0]
    return r["score"], r["flagged"]


def threshold() -> float:
    return round(float(-get_model().offset_), 3)


_LABELS = {
    "n_queries": "{v:g} queries in the window (normal ≤ {hi:g})",
    "n_refused": "{v:g} refused queries (normal ≤ {hi:g})",
    "distinct_filters": "{v:g} different filter combinations (normal ≤ {hi:g})",
    "eps_spent": "ε {v:g} spent in the window (normal ≤ {hi:g})",
    "repeats": "{v:g} repeated identical queries (normal ≤ {hi:g})",
    "repeat_share": "{v:.0%} of queries were repeats (normal ≤ {hi:.0%})",
}


def explain(features: dict) -> str:
    """Plain-language reason: which features are outside the normal range seen in training."""
    get_model()
    parts = [_LABELS[f].format(v=features[f], hi=_normal_limits[f][1])
             for f in _LABELS if features[f] > _normal_limits[f][1]]
    lo = _normal_limits["avg_group_size"][0]
    if features["n_queries"] and features["avg_group_size"] < lo:
        parts.append(f"very small groups (average {features['avg_group_size']:g}, normal ≥ {lo:g})")
    return "; ".join(parts) or "unusual combination of query behaviour"


# --- live data ---

def _now() -> datetime:
    return datetime.now(timezone.utc)


def user_queries(db: sqlite3.Connection, user_id: int, since: datetime) -> list[dict]:
    """The analyst's executed (audit_records) and refused (security_events) queries since `since`, in order."""
    out = []
    for r in db.execute("SELECT query_type, params_json, epsilon, group_size, timestamp FROM audit_records"
                        " WHERE user_id = ? AND timestamp >= ?", (user_id, since.isoformat(timespec="microseconds"))):
        out.append((datetime.fromisoformat(r["timestamp"]),
                    {"query_type": r["query_type"], "filters": json.loads(r["params_json"]),
                     "epsilon": r["epsilon"], "group_size": r["group_size"], "refused": False}))
    for r in db.execute("SELECT detail, timestamp FROM security_events WHERE user_id = ? AND action = 'query_rejected'"
                        " AND timestamp >= ?", (user_id, since.strftime("%Y-%m-%d %H:%M:%S"))):
        try:
            d = json.loads(r["detail"])
        except (TypeError, ValueError):
            d = {}
        filters = d.get("filters") if isinstance(d.get("filters"), dict) else {}
        eps = d.get("epsilon") if isinstance(d.get("epsilon"), (int, float)) else 0.0
        ts = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        out.append((ts, {"query_type": str(d.get("query_type")), "filters": filters,
                         "epsilon": float(eps), "group_size": None, "refused": True}))
    return [q for _, q in sorted(out, key=lambda x: x[0])]


def check_user(db: sqlite3.Connection, user_id: int, window_minutes: int = WINDOW_MINUTES) -> dict | None:
    """Score the analyst's recent window; open (or raise) an alert if it is anomalous.

    At most one open alert per analyst per window: a stronger score updates the existing alert.
    Returns the alert row as a dict when one was created or updated, else None.
    """
    since = _now() - timedelta(minutes=window_minutes)
    queries = user_queries(db, user_id, since)
    if not queries:
        return None
    features = window_features(queries)
    result = assess([features])[0]
    if not result["flagged"]:
        return None
    value, detected_by = result["score"], ",".join(result["detected_by"])
    reason = explain(features)
    if "model" not in result["detected_by"]:
        reason = "Far beyond anything seen in normal use: " + reason
    open_alert = db.execute("SELECT * FROM alerts WHERE user_id = ? AND status = 'open' AND timestamp >= ?"
                            " ORDER BY id DESC LIMIT 1",
                            (user_id, since.strftime("%Y-%m-%d %H:%M:%S"))).fetchone()
    if open_alert is not None:
        if value <= open_alert["score"] and detected_by == open_alert["detected_by"]:
            return None
        db.execute("UPDATE alerts SET score = MAX(score, ?), reason = ?, features_json = ?, detected_by = ?"
                   " WHERE id = ?", (value, reason, json.dumps(features), detected_by, open_alert["id"]))
        alert_id = open_alert["id"]
    else:
        alert_id = db.execute("INSERT INTO alerts (user_id, score, reason, features_json, detected_by, status)"
                              " VALUES (?, ?, ?, ?, ?, 'open')",
                              (user_id, value, reason, json.dumps(features), detected_by)).lastrowid
    db.commit()
    return dict(db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())


def scan_all(db: sqlite3.Connection, window_minutes: int = WINDOW_MINUTES) -> list[dict]:
    """Check every active analyst now (admin 'scan' button / scheduled job)."""
    ids = [r["id"] for r in db.execute("SELECT id FROM users WHERE role = 'analyst' AND active = 1")]
    return [a for a in (check_user(db, uid, window_minutes) for uid in ids) if a]
