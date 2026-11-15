"""Per-analyst permissions set by the university owner (pipeline step 3b).

They limit what an analyst may calculate on: query types, majors, graduation years and the
number of queries. An empty list (or NULL) means "all". Analysts never see records either way.
"""
import json
import sqlite3

from .catalog import MAJORS, MAX_GRAD_YEAR, MIN_GRAD_YEAR, QUERY_TYPES

MAX_QUERIES_LIMIT = 100_000


def ensure_row(db: sqlite3.Connection, analyst_id: int) -> None:
    """New analysts start with no restrictions ("all"), as the data model specifies. No commit."""
    db.execute("INSERT OR IGNORE INTO analyst_permissions (analyst_id) VALUES (?)", (analyst_id,))


def _list(value: str | None) -> list:
    return json.loads(value) if value else []


def get(db: sqlite3.Connection, analyst_id: int) -> dict | None:
    r = db.execute("SELECT * FROM analyst_permissions WHERE analyst_id = ?", (analyst_id,)).fetchone()
    if r is None:
        return None
    return {"query_types": _list(r["allowed_query_types"]), "majors": _list(r["allowed_majors"]),
            "years": _list(r["allowed_years"]), "max_queries": r["max_queries"],
            "queries_used": r["queries_used"]}


def validate(body: dict) -> dict:
    """Clean a permissions update from the owner, or raise ValueError with a readable reason."""
    def as_list(key, allowed, kind):
        value = body.get(key, [])
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError(f"{key} must be a list (empty = all)")
        for v in value:
            if kind is int and (isinstance(v, bool) or not isinstance(v, int)):
                raise ValueError(f"{key} must contain years as numbers")
            if v not in allowed:
                raise ValueError(f"{key}: '{v}' is not allowed")
        return sorted(set(value))

    max_q = body.get("max_queries")
    if max_q is not None and (isinstance(max_q, bool) or not isinstance(max_q, int)
                              or not 0 <= max_q <= MAX_QUERIES_LIMIT):
        raise ValueError(f"max_queries must be empty (no limit) or 0-{MAX_QUERIES_LIMIT}")
    return {
        "query_types": as_list("query_types", set(QUERY_TYPES), str),
        "majors": as_list("majors", set(MAJORS), str),
        "years": as_list("years", set(range(MIN_GRAD_YEAR, MAX_GRAD_YEAR + 1)), int),
        "max_queries": max_q,
    }


def save(db: sqlite3.Connection, analyst_id: int, clean: dict) -> None:
    ensure_row(db, analyst_id)
    db.execute("UPDATE analyst_permissions SET allowed_query_types = ?, allowed_majors = ?, allowed_years = ?,"
               " max_queries = ? WHERE analyst_id = ?",
               (json.dumps(clean["query_types"]), json.dumps(clean["majors"]), json.dumps(clean["years"]),
                clean["max_queries"], analyst_id))
    db.commit()


def allows(perm: dict | None, query_type: str, filters: dict) -> bool:
    """True if the query stays inside the analyst's permissions.

    With a major (or year) restriction the query MUST filter on an allowed value:
    a query without that filter would cover disallowed majors (years) too.
    """
    if perm is None:
        return False
    if perm["query_types"] and query_type not in perm["query_types"]:
        return False
    if perm["majors"] and filters.get("major") not in perm["majors"]:
        return False
    if perm["years"] and filters.get("grad_year") not in perm["years"]:
        return False
    return perm["max_queries"] is None or perm["queries_used"] < perm["max_queries"]


def count_use(db: sqlite3.Connection, analyst_id: int) -> bool:
    """Add one used query unless the maximum is reached (single conditional UPDATE). No commit."""
    cur = db.execute("UPDATE analyst_permissions SET queries_used = queries_used + 1 WHERE analyst_id = ?"
                     " AND (max_queries IS NULL OR queries_used < max_queries)", (analyst_id,))
    return cur.rowcount == 1


def public(perm: dict) -> dict:
    """Shape shown to the owner and to the analyst ("all" instead of an empty list)."""
    return {"query_types": perm["query_types"] or "all", "majors": perm["majors"] or "all",
            "years": perm["years"] or "all", "max_queries": perm["max_queries"],
            "queries_used": perm["queries_used"]}
