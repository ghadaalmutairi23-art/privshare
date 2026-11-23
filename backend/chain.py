"""Blockchain clients with one interface: Web3Chain (the real PrivShareAudit contract on a local
Anvil node) and StubChain (in-memory, for tests and for running without a node).

Both follow the contract's rules: a query can be logged only if both parties approved its
type (either party can revoke its side) and the group has at least CONTRACT_K_MIN students.
Only hashes go on-chain, and the backend sends min(group size, k), so the chain learns only
"at least k", never the exact count. Any connection problem raises ChainUnavailable so the
caller fails closed.
"""
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from flask import current_app

CONTRACT_K_MIN = 10
PARTIES = ("university", "partner")


class ChainError(Exception):
    pass


class ChainUnavailable(ChainError):
    """Node unreachable or contract missing: callers must refuse the operation (fail closed)."""


class ChainRejected(ChainError):
    """The contract rejected the transaction (not a party, not approved, group too small, ...)."""


@dataclass(frozen=True)
class ChainReceipt:
    tx_hash: str
    index: int          # position of the record in the on-chain log


@dataclass(frozen=True)
class ChainEntry:
    record_hash: str    # hex SHA-256 of the off-chain audit record
    query_type_id: str  # hex keccak256 of the query type name
    timestamp: int


def query_type_id(name: str) -> str:
    """bytes32 id of a query type as stored on-chain (keccak256 of its name), hex without 0x."""
    from web3 import Web3
    return Web3.keccak(text=name).hex().removeprefix("0x")


# --- in-memory stub ---

class StubChain:
    """In-memory stand-in for the contract. Set `available = False` to simulate a dead node."""

    def __init__(self):
        self.available = True
        self._approvals: dict[str, set[str]] = {}
        self._entries: list[ChainEntry] = []
        self.group_sizes: list[int] = []      # what the backend sent (tests check min(n, k))

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

    def approval_status(self, query_type: str) -> tuple[bool, bool]:
        self._require_node()
        sides = self._approvals.get(query_type, set())
        return "university" in sides, "partner" in sides

    def is_approved(self, query_type: str) -> bool:
        return all(self.approval_status(query_type))

    def log_query(self, query_type: str, record_hash: str, group_size: int) -> ChainReceipt:
        self._require_node()
        if not self.is_approved(query_type):
            raise ChainRejected("not approved by both parties")
        if group_size < CONTRACT_K_MIN:
            raise ChainRejected("group too small")
        self._entries.append(ChainEntry(record_hash, query_type_id(query_type), int(time.time())))
        self.group_sizes.append(group_size)
        return ChainReceipt(self._tx(), len(self._entries) - 1)

    def count(self) -> int:
        self._require_node()
        return len(self._entries)

    def get_entry(self, index: int) -> ChainEntry:
        self._require_node()
        return self._entries[index]

    def query_type_matches(self, entry: ChainEntry, query_type: str) -> bool:
        return entry.query_type_id == query_type_id(query_type)

    def info(self) -> dict:
        return {"backend": "stub", "available": self.available, "records": len(self._entries)}

    def load_approvals(self, db: sqlite3.Connection) -> None:
        """Stub only: re-apply approvals saved in the DB mirror (a real chain keeps its own state)."""
        for row in db.execute("SELECT name, approved_uni, approved_partner FROM query_types"):
            if row["approved_uni"]:
                self.approve(row["name"], "university")
            if row["approved_partner"]:
                self.approve(row["name"], "partner")


# --- real contract via web3.py ---

class Web3Chain:
    """PrivShareAudit on a local node. Accounts come from the deployment file; the local node
    holds their keys (Anvil dev accounts), so no private key is stored by PrivShare."""

    def __init__(self, rpc_url: str, deployment_file: str, timeout: float = 10.0):
        self.rpc_url = rpc_url
        self.deployment_file = Path(deployment_file)
        self.timeout = timeout
        self._w3 = None
        self._contract = None
        self._deployment = None

    # connection ---------------------------------------------------------
    def _connect(self):
        """Contract handle, or ChainUnavailable. Re-checks the code exists (node may have been reset)."""
        from web3 import Web3
        try:
            if self._deployment is None:
                if not self.deployment_file.exists():
                    raise ChainUnavailable("contract not deployed (run: python contracts/deploy.py)")
                self._deployment = json.loads(self.deployment_file.read_text(encoding="utf-8"))
            if self._w3 is None:
                self._w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": self.timeout}))
            if self._contract is None:
                address = Web3.to_checksum_address(self._deployment["address"])
                if self._w3.eth.get_code(address) in (b"", b"\x00"):
                    raise ChainUnavailable("contract not found on the chain (node reset? redeploy)")
                self._contract = self._w3.eth.contract(address=address, abi=self._deployment["abi"])
            return self._contract
        except (requests.exceptions.RequestException, OSError) as exc:
            self._contract = None
            raise ChainUnavailable("blockchain node unreachable") from exc

    def _call(self, fn):
        try:
            return fn(self._connect())
        except ChainError:
            raise
        except (requests.exceptions.RequestException, OSError) as exc:
            self._contract = None
            raise ChainUnavailable("blockchain node unreachable") from exc

    def _transact(self, build, sender: str):
        """Send a transaction from `sender`, wait for it; contract reverts become ChainRejected."""
        from web3.exceptions import ContractLogicError, TimeExhausted

        def run(contract):
            try:
                tx = build(contract).transact({"from": sender})
                receipt = self._w3.eth.wait_for_transaction_receipt(tx, timeout=self.timeout)
            except ContractLogicError as exc:
                raise ChainRejected("rejected by the smart contract") from exc
            except TimeExhausted as exc:
                raise ChainUnavailable("blockchain did not confirm in time") from exc
            if receipt["status"] != 1:
                raise ChainRejected("transaction reverted")
            return receipt
        return self._call(run)

    def _account(self, role: str) -> str:
        self._connect()
        return self._deployment["accounts"][role]

    @staticmethod
    def _id(query_type: str) -> bytes:
        return bytes.fromhex(query_type_id(query_type))

    # interface ----------------------------------------------------------
    def approve(self, query_type: str, party: str) -> str:
        if party not in PARTIES:
            raise ChainRejected("not a party")
        r = self._transact(lambda c: c.functions.approveQueryType(self._id(query_type)), self._account(party))
        return r["transactionHash"].to_0x_hex()

    def revoke(self, query_type: str, party: str) -> str:
        if party not in PARTIES:
            raise ChainRejected("not a party")
        r = self._transact(lambda c: c.functions.revokeQueryType(self._id(query_type)), self._account(party))
        return r["transactionHash"].to_0x_hex()

    def approval_status(self, query_type: str) -> tuple[bool, bool]:
        qid = self._id(query_type)
        return self._call(lambda c: (c.functions.approvedByUniversity(qid).call(),
                                     c.functions.approvedByPartner(qid).call()))

    def is_approved(self, query_type: str) -> bool:
        return self._call(lambda c: c.functions.isApproved(self._id(query_type)).call())

    def log_query(self, query_type: str, record_hash: str, group_size: int) -> ChainReceipt:
        receipt = self._transact(
            lambda c: c.functions.logQuery(self._id(query_type), bytes.fromhex(record_hash), group_size),
            self._account("logger"))
        event = self._contract.events.QueryLogged().process_receipt(receipt)[0]
        return ChainReceipt(receipt["transactionHash"].to_0x_hex(), int(event["args"]["index"]))

    def count(self) -> int:
        return self._call(lambda c: c.functions.count().call())

    def get_entry(self, index: int) -> ChainEntry:
        record_hash, qtype, ts = self._call(lambda c: c.functions.getRecord(index).call())
        return ChainEntry(record_hash.hex(), qtype.hex(), int(ts))

    def query_type_matches(self, entry: ChainEntry, query_type: str) -> bool:
        return entry.query_type_id == query_type_id(query_type)

    def info(self) -> dict:
        try:
            contract = self._connect()
            return {"backend": "web3", "available": True, "rpc_url": self.rpc_url,
                    "contract": contract.address, "chain_id": self._w3.eth.chain_id,
                    "block": self._w3.eth.block_number, "records": contract.functions.count().call()}
        except ChainError as exc:
            return {"backend": "web3", "available": False, "rpc_url": self.rpc_url, "error": str(exc)}


def create(config) -> "StubChain | Web3Chain":
    backend = config["CHAIN_BACKEND"]
    if backend == "stub":
        return StubChain()
    if backend == "web3":
        return Web3Chain(config["RPC_URL"], config["CHAIN_DEPLOYMENT_FILE"], config["CHAIN_TIMEOUT"])
    raise RuntimeError(f"Unknown CHAIN_BACKEND '{backend}' (use 'web3' or 'stub')")


def get_chain():
    return current_app.extensions["chain"]
