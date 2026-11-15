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


def set_tx_hash(db: sqlite3.Connection, record_id: int, tx_hash: str) -> None:
    db.execute("UPDATE audit_records SET tx_hash = ? WHERE id = ?", (tx_hash, record_id))
