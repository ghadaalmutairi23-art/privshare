"""Compile PrivShareAudit.sol (py-solc-x) and deploy it to the local node (web3.py).

The deployment file records the contract address, its ABI and which node account plays
each role. Accounts are Anvil's unlocked dev accounts: 0 = PrivShare backend (logger),
1 = university, 2 = partner. In a real deployment each organisation would sign with its
own wallet on its own node.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import solcx
from web3 import Web3

from .config import ROOT

SOLC_VERSION = "0.8.28"
SOURCE = ROOT / "contracts" / "PrivShareAudit.sol"
ROLES = ("logger", "university", "partner")


def compile_contract() -> tuple[list, str]:
    """Return (abi, bytecode). Downloads the pinned solc on first use."""
    if SOLC_VERSION not in {str(v) for v in solcx.get_installed_solc_versions()}:
        solcx.install_solc(SOLC_VERSION)
    out = solcx.compile_standard({
        "language": "Solidity",
        "sources": {SOURCE.name: {"content": SOURCE.read_text(encoding="utf-8")}},
        "settings": {"optimizer": {"enabled": True, "runs": 200}, "evmVersion": "cancun",
                     "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}}},
    }, solc_version=SOLC_VERSION)
    c = out["contracts"][SOURCE.name]["PrivShareAudit"]
    return c["abi"], c["evm"]["bytecode"]["object"]


def contract_is_live(w3: Web3, deployment_file: Path) -> bool:
    if not deployment_file.exists():
        return False
    address = json.loads(deployment_file.read_text(encoding="utf-8")).get("address")
    return bool(address) and w3.eth.get_code(Web3.to_checksum_address(address)) not in (b"", b"\x00")


def deploy(rpc_url: str, deployment_file: Path) -> dict:
    """Deploy a fresh contract and write the deployment file. Returns its content."""
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
    accounts = w3.eth.accounts
    if len(accounts) < 3:
        raise RuntimeError("The node must expose at least 3 unlocked accounts (use Anvil)")
    roles = dict(zip(ROLES, accounts[:3]))
    abi, bytecode = compile_contract()
    tx = w3.eth.contract(abi=abi, bytecode=bytecode).constructor(
        roles["university"], roles["partner"], roles["logger"]).transact({"from": roles["logger"]})
    receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=30)
    data = {
        "address": receipt["contractAddress"],
        "abi": abi,
        "accounts": roles,
        "chain_id": w3.eth.chain_id,
        "block": receipt["blockNumber"],
        "solc": SOLC_VERSION,
        "deployed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    deployment_file.parent.mkdir(parents=True, exist_ok=True)
    deployment_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data
