"""Persistent per-analyst privacy budget (epsilon)."""
import sqlite3

# Float tolerance so that e.g. 10 x 0.1 can spend exactly 1.0
_EPS_TOLERANCE = 1e-9


def get(db: sqlite3.Connection, user_id: int) -> dict | None:
    row = db.execute("SELECT epsilon_total, epsilon_spent FROM privacy_budget WHERE user_id = ?",
                     (user_id,)).fetchone()
    if row is None:
        return None
    total, spent = row["epsilon_total"], row["epsilon_spent"]
    return {"total": total, "spent": round(spent, 6), "remaining": round(max(0.0, total - spent), 6)}


MAX_TOTAL = 100.0


def set_total(db: sqlite3.Connection, user_id: int, epsilon_total: float) -> None:
    """Change an analyst's total budget. Spent epsilon is never reduced: privacy loss
    already released can't be taken back, so lowering the total below `spent` just blocks queries."""
    db.execute("INSERT INTO privacy_budget (user_id, epsilon_total, epsilon_spent) VALUES (?, ?, 0)"
               " ON CONFLICT (user_id) DO UPDATE SET epsilon_total = excluded.epsilon_total",
               (user_id, epsilon_total))
    db.commit()


def can_spend(db: sqlite3.Connection, user_id: int, epsilon: float) -> bool:
    b = get(db, user_id)
    return b is not None and epsilon <= b["remaining"] + _EPS_TOLERANCE


def charge(db: sqlite3.Connection, user_id: int, epsilon: float) -> bool:
    """Deduct epsilon only if enough remains (single conditional UPDATE, so no overspend).

    Does not commit: the caller commits together with the audit record.
    """
    cur = db.execute(
        "UPDATE privacy_budget SET epsilon_spent = epsilon_spent + ?"
        " WHERE user_id = ? AND epsilon_spent + ? <= epsilon_total + ?",
        (epsilon, user_id, epsilon, _EPS_TOLERANCE))
    return cur.rowcount == 1
