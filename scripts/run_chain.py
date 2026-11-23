"""Start the local blockchain (Anvil) with its state saved to chain/anvil-state.json.

Run: python scripts/run_chain.py       (keep this terminal open; Ctrl+C to stop)

The state is loaded at start and saved every few seconds and on exit, so the contract,
approvals and logged fingerprints survive restarts. Listens on 127.0.0.1:8545 only.
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "chain" / "anvil-state.json"


def find_anvil() -> str | None:
    local = ROOT / "tools" / "foundry" / ("anvil.exe" if sys.platform == "win32" else "anvil")
    return str(local) if local.exists() else shutil.which("anvil")


def main() -> int:
    anvil = find_anvil()
    if anvil is None:
        print("Anvil not found. Install it with: python scripts/get_anvil.py")
        return 1
    STATE.parent.mkdir(exist_ok=True)
    cmd = [anvil, "--host", "127.0.0.1", "--port", "8545", "--chain-id", "31337",
           "--state", str(STATE), "--state-interval", "5"]
    print("Starting Anvil (state:", STATE, ")")
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
