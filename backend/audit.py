"""Off-chain audit records and their SHA-256 fingerprints (the fingerprint goes on-chain)."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

# Exactly these fields (as stored in the database) are fingerprinted
FINGERPRINT_FIELDS = ("user_id", "query_type", "params_json", "epsilon", "group_size",
                      "result_noisy", "timestamp")


def build(user_id: int, query_type: str, params: dict, epsilon: float, group_size: int,
          result_noisy: float) -> dict:
    return {
        "user_id": user_id,
        "query_type": query_type,
        "params_json": json.dumps(params, sort_keys=True, separators=(",", ":")),
        "epsilon": float(epsilon),
        "group_size": int(group_size),
        "result_noisy": float(result_noisy),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
    }


def fingerprint(record) -> str:
    """SHA-256 (hex) over the canonical JSON of the fingerprinted fields."""
    canonical = json.dumps({f: record[f] for f in FINGERPRINT_FIELDS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def insert(db: sqlite3.Connection, record: dict, sha256: str) -> int:
    """Insert without committing (the caller commits after the on-chain write succeeds)."""
    cur = db.execute(
        "INSERT INTO audit_records (user_id, query_type, params_json, epsilon, group_size,"
        " result_noisy, timestamp, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (*(record[f] for f in FINGERPRINT_FIELDS), sha256))
    return cur.lastrowid


def set_chain_ref(db: sqlite3.Connection, record_id: int, tx_hash: str, chain_index: int) -> None:
    """Remember where the fingerprint landed on-chain. No commit."""
    db.execute("UPDATE audit_records SET tx_hash = ?, chain_index = ? WHERE id = ?",
               (tx_hash, chain_index, record_id))


def list_records(db: sqlite3.Connection, page: int, per_page: int) -> tuple[list[dict], int]:
    """Audit records for the auditor, newest first (no student data: aggregates and parameters only)."""
    total = db.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0]
    rows = db.execute("SELECT a.*, u.username FROM audit_records a LEFT JOIN users u ON u.id = a.user_id"
                      " ORDER BY a.id DESC LIMIT ? OFFSET ?", (per_page, (page - 1) * per_page)).fetchall()
    return [{"id": r["id"], "timestamp": r["timestamp"], "analyst": r["username"], "query_type": r["query_type"],
             "filters": json.loads(r["params_json"]), "epsilon": r["epsilon"], "group_size": r["group_size"],
             "result_noisy": r["result_noisy"], "sha256": r["sha256"], "tx_hash": r["tx_hash"],
             "chain_index": r["chain_index"]} for r in rows], total


# Verification outcomes per off-chain record
VERIFIED = "verified"            # recomputed fingerprint == on-chain fingerprint
TAMPERED = "tampered"            # the stored record no longer matches what was logged
NOT_ON_CHAIN = "not_on_chain"    # no on-chain entry for this record (e.g. chain was reset)


def verify_all(db: sqlite3.Connection, chain) -> dict:
    """Recompute every record's SHA-256 from its stored fields and compare with the chain.

    The stored `sha256` column is NOT trusted (an attacker could rewrite it too); only the
    on-chain value counts. Also reports on-chain entries that no off-chain record points to
    (a deleted record). Raises ChainUnavailable if the node can't be read.
    """
    on_chain = chain.count()
    results, covered = [], set()
    for r in db.execute("SELECT * FROM audit_records ORDER BY id"):
        index = r["chain_index"]
        if index is None or not 0 <= index < on_chain:
            status = NOT_ON_CHAIN
        else:
            covered.add(index)
            entry = chain.get_entry(index)
            ok = entry.record_hash == fingerprint(r) and chain.query_type_matches(entry, r["query_type"])
            status = VERIFIED if ok else TAMPERED
        results.append({"id": r["id"], "chain_index": index, "status": status})

    missing_off_chain = sorted(set(range(on_chain)) - covered)
    counts = {s: sum(1 for x in results if x["status"] == s) for s in (VERIFIED, TAMPERED, NOT_ON_CHAIN)}
    return {
        "records_checked": len(results),
        "on_chain_entries": on_chain,
        "counts": counts,
        "on_chain_without_record": missing_off_chain,   # fingerprints whose off-chain record was deleted
        "all_ok": counts[TAMPERED] == 0 and counts[NOT_ON_CHAIN] == 0 and not missing_off_chain,
        "results": results,
    }
