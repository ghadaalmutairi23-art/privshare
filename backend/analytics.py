"""Query pipeline. Every query passes these steps in order:

1. (route) logged in with MFA, role analyst
2. query type in the whitelist, filters valid, epsilon within the allowed range
3. chain says the query type is approved by BOTH parties (fail closed if the node is down)
3b. the query is inside the analyst's permissions (type, major, year, max queries)
4. group size >= k, otherwise the unified "Query rejected by privacy policy"
5. enough privacy budget left
6. decrypt only the needed field in memory -> compute -> add Laplace noise (OpenDP)
7. one transaction: deduct epsilon + count the query + save audit record (exact group size, off-chain only)
   + write its SHA-256 on-chain together with min(group size, k);
   if the chain write fails everything is rolled back and the result is discarded
8. return only the noisy aggregate
"""
import math
import sqlite3
from dataclasses import dataclass

from . import audit, budget, crypto, dp, permissions
from .catalog import FILTERS, QUERY_TYPES
from .chain import ChainRejected, ChainUnavailable

OUTSIDE_PERMISSIONS = "Outside your permissions"
POLICY_REJECTED = "Query rejected by privacy policy"
NOT_APPROVED = "Query type is not approved by both the university and the partner"
BUDGET_EXHAUSTED = "Privacy budget exhausted"
AUDIT_UNAVAILABLE = "Audit service unavailable; query refused"


class QueryRefused(Exception):
    def __init__(self, message: str, status: int = 403, reason: str = "refused"):
        super().__init__(message)
        self.message, self.status, self.reason = message, status, reason


@dataclass(frozen=True)
class Policy:
    k_min: int
    epsilon_min: float
    epsilon_max: float
    gpa_scale: float


def available_filters(db: sqlite3.Connection) -> dict:
    """Allowed filter values (public metadata: majors and years, no counts)."""
    return {
        "major": [r[0] for r in db.execute("SELECT DISTINCT major FROM students ORDER BY major")],
        "grad_year": [r[0] for r in db.execute("SELECT DISTINCT grad_year FROM students ORDER BY grad_year")],
    }


def validate(db: sqlite3.Connection, policy: Policy, query_type, filters, epsilon) -> tuple[str, dict, float]:
    """Step 2. Returns cleaned (query_type, filters, epsilon) or raises QueryRefused(400)."""
    if query_type not in QUERY_TYPES:
        raise QueryRefused("Unknown query type", 400, "invalid")
    if filters is None:
        filters = {}
    if not isinstance(filters, dict) or set(filters) - set(FILTERS):
        raise QueryRefused(f"Filters must be an object with keys from {list(FILTERS)}", 400, "invalid")
    allowed = available_filters(db)
    clean = {}
    if filters.get("major") is not None:
        if filters["major"] not in allowed["major"]:
            raise QueryRefused("Unknown major", 400, "invalid")
        clean["major"] = filters["major"]
    if filters.get("grad_year") is not None:
        year = filters["grad_year"]
        if isinstance(year, bool) or not isinstance(year, int) or year not in allowed["grad_year"]:
            raise QueryRefused("Unknown graduation year", 400, "invalid")
        clean["grad_year"] = year
    if isinstance(epsilon, bool) or not isinstance(epsilon, (int, float)) or not math.isfinite(epsilon):
        raise QueryRefused("epsilon must be a number", 400, "invalid")
    if not policy.epsilon_min <= epsilon <= policy.epsilon_max:
        raise QueryRefused(f"epsilon must be between {policy.epsilon_min} and {policy.epsilon_max}",
                           400, "invalid")
    return query_type, clean, float(epsilon)


def _where(filters: dict) -> tuple[str, list]:
    # Column names come from the fixed whitelist above, values are bound parameters
    parts = [f"{col} = ?" for col in FILTERS if col in filters]
    return (" WHERE " + " AND ".join(parts)) if parts else "", [filters[c] for c in FILTERS if c in filters]


def _compute(db: sqlite3.Connection, policy: Policy, query_type: str, filters: dict,
             n: int, epsilon: float) -> float:
    """Step 6: decrypt in memory only, aggregate, add noise. Returns the rounded noisy value."""
    where, args = _where(filters)
    if query_type == "graduates_count":
        return float(dp.noisy_count(n, epsilon))
    if query_type == "avg_gpa":
        key = crypto.load_key()
        gpas = [float(crypto.decrypt(r[0], key, crypto.AAD_GPA))
                for r in db.execute("SELECT gpa_enc FROM students" + where, args)]
        value = dp.noisy_mean(gpas, epsilon, 0.0, policy.gpa_scale)
        del gpas
        return round(value, 2)
    flags = [r[0] for r in db.execute("SELECT coop_completed FROM students" + where, args)]
    return round(dp.noisy_mean(flags, epsilon, 0.0, 1.0), 3)  # coop_rate as a fraction 0..1


def run_query(db: sqlite3.Connection, chain, policy: Policy, user_id: int,
              query_type, filters, epsilon) -> dict:
    query_type, filters, epsilon = validate(db, policy, query_type, filters, epsilon)

    try:  # step 3
        approved = chain.is_approved(query_type)
    except ChainUnavailable as exc:
        raise QueryRefused(AUDIT_UNAVAILABLE, 503, "chain_unavailable") from exc
    if not approved:
        raise QueryRefused(NOT_APPROVED, 403, "not_approved")

    if not permissions.allows(permissions.get(db, user_id), query_type, filters):  # step 3b
        raise QueryRefused(OUTSIDE_PERMISSIONS, 403, "permissions")

    where, args = _where(filters)  # step 4
    n = db.execute("SELECT COUNT(*) FROM students" + where, args).fetchone()[0]
    if n < policy.k_min:
        raise QueryRefused(POLICY_REJECTED, 403, "privacy_policy")

    if not budget.can_spend(db, user_id, epsilon):  # step 5
        raise QueryRefused(BUDGET_EXHAUSTED, 403, "budget")

    value = _compute(db, policy, query_type, filters, n, epsilon)  # step 6

    record = audit.build(user_id, query_type, filters, epsilon, n, value)  # step 7
    sha = audit.fingerprint(record)
    db.execute("BEGIN IMMEDIATE")
    try:
        if not budget.charge(db, user_id, epsilon):
            raise QueryRefused(BUDGET_EXHAUSTED, 403, "budget")
        if not permissions.count_use(db, user_id):  # max_queries reached meanwhile
            raise QueryRefused(OUTSIDE_PERMISSIONS, 403, "permissions")
        record_id = audit.insert(db, record, sha)
        # The contract only needs to know n >= k; min() keeps the exact count off the public chain
        receipt = chain.log_query(query_type, sha, min(n, policy.k_min))
        audit.set_chain_ref(db, record_id, receipt.tx_hash, receipt.index)
        db.commit()
    except ChainUnavailable as exc:
        db.rollback()
        raise QueryRefused(AUDIT_UNAVAILABLE, 503, "chain_unavailable") from exc
    except ChainRejected as exc:
        db.rollback()
        raise QueryRefused(POLICY_REJECTED, 403, "contract_rejected") from exc
    except BaseException:
        db.rollback()
        raise

    return {  # step 8: the noisy aggregate only (no group size, no records)
        "query_type": query_type,
        "label": QUERY_TYPES[query_type],
        "filters": filters,
        "epsilon": epsilon,
        "result": int(value) if query_type == "graduates_count" else value,
        "budget": budget.get(db, user_id),
        "tx_hash": receipt.tx_hash,
    }
