"""Deploy PrivShareAudit to the local Anvil node and write contracts/deployment.json.

Run (with the node running: python scripts/run_chain.py):
    python contracts/deploy.py            deploy if no live contract exists
    python contracts/deploy.py --force    deploy a NEW contract even if one is live
                                          (existing audit records will then show as not_on_chain)
"""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from web3 import Web3  # noqa: E402

from backend import contract_deploy  # noqa: E402  (also loads .env)


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy the PrivShareAudit contract.")
    parser.add_argument("--force", action="store_true", help="deploy a new contract even if one is live")
    args = parser.parse_args()

    rpc_url = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
    deployment_file = Path(os.environ.get("CHAIN_DEPLOYMENT_FILE") or ROOT / "contracts" / "deployment.json")
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    if not w3.is_connected():
        print(f"No blockchain node at {rpc_url}. Start it first: python scripts/run_chain.py")
        return 1
    if contract_deploy.contract_is_live(w3, deployment_file) and not args.force:
        print(f"A contract is already live (see {deployment_file}). Use --force to deploy a new one.")
        return 0

    data = contract_deploy.deploy(rpc_url, deployment_file)
    print(f"PrivShareAudit deployed at {data['address']} (chain {data['chain_id']}, block {data['block']})")
    for role, address in data["accounts"].items():
        print(f"  {role:<10} {address}")
    print(f"Wrote {deployment_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
