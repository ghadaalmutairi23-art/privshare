"""Blockchain client. Phase 2 ships an in-memory StubChain; Phase 3 adds the web3.py client.

Both follow the smart-contract rules: a query can be logged only if both parties approved
its type (either party can revoke its side) and the group has at least CONTRACT_K_MIN
students. Only hashes go on-chain, and the backend sends min(group size, k), so the chain
learns only "at least k", never the exact count.
"""
import secrets
import sqlite3
from dataclasses import dataclass

from flask import current_app

CONTRACT_K_MIN = 10
PARTIES = ("university", "partner")


class ChainError(Exception):
    pass


class ChainUnavailable(ChainError):
    """Node unreachable: callers must refuse the operation (fail closed)."""


class ChainRejected(ChainError):
    """The contract rejected the transaction (not approved, group too small, ...)."""


@dataclass(frozen=True)
class ChainEntry:
    query_type: str
    record_hash: str
    group_size: int
    tx_hash: str


class StubChain:
    """In-memory stand-in for the contract. Set `available = False` to simulate a dead node."""

    def __init__(self):
        self.available = True
        self._approvals: dict[str, set[str]] = {}
        self._entries: list[ChainEntry] = []

    def _require_node(self) -> None:
        if not self.available:
            raise ChainUnavailable("blockchain node unreachable")

    @staticmethod
    def _tx() -> str:
        return "0x" + secrets.token_hex(32)

    def approve(self, query_type: str, party: str) -> str:
        self._require_node()
        if party not in PARTIES:
            raise ChainRejected("not a party")
        self._approvals.setdefault(query_type, set()).add(party)
        return self._tx()

    def revoke(self, query_type: str, party: str) -> str:
        self._require_node()
        if party not in PARTIES:
            raise ChainRejected("not a party")
        self._approvals.get(query_type, set()).discard(party)
        return self._tx()

    def is_approved(self, query_type: str) -> bool:
        self._require_node()
        return set(PARTIES) <= self._approvals.get(query_type, set())

    def log_query(self, query_type: str, record_hash: str, group_size: int) -> str:
        self._require_node()
        if not self.is_approved(query_type):
            raise ChainRejected("not approved by both parties")
        if group_size < CONTRACT_K_MIN:
            raise ChainRejected("group too small")
        tx = self._tx()
        self._entries.append(ChainEntry(query_type, record_hash, group_size, tx))
        return tx

    def count(self) -> int:
        self._require_node()
        return len(self._entries)

    def get_entry(self, index: int) -> ChainEntry:
        self._require_node()
        return self._entries[index]

    def load_approvals(self, db: sqlite3.Connection) -> None:
        """Stub only: re-apply approvals saved in the DB mirror (a real chain keeps its own state)."""
        for row in db.execute("SELECT name, approved_uni, approved_partner FROM query_types"):
            if row["approved_uni"]:
                self.approve(row["name"], "university")
            if row["approved_partner"]:
                self.approve(row["name"], "partner")


def create(backend: str):
    if backend == "stub":
        return StubChain()
    raise RuntimeError(f"Unknown CHAIN_BACKEND '{backend}' (Phase 3 adds 'web3')")


def get_chain():
    return current_app.extensions["chain"]
