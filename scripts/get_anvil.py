"""Download Anvil (Foundry's local blockchain node) into tools/foundry/ - Windows.

Run: python scripts/get_anvil.py
The version is pinned and the download is checked against a pinned SHA-256 before use.
On macOS/Linux install Foundry with `curl -L https://foundry.paradigm.xyz | bash && foundryup`.
"""
import hashlib
import io
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

VERSION = "v1.9.0"
URL = f"https://github.com/foundry-rs/foundry/releases/download/{VERSION}/foundry_{VERSION}_win32_amd64.zip"
SHA256 = "2b02444d46c9218fe2e6be66015265ce131fe6b7c384e33e630b00f9a0bff072"
DEST = Path(__file__).resolve().parent.parent / "tools" / "foundry"


def main() -> int:
    if platform.system() != "Windows":
        print("Not Windows: install Foundry with foundryup (see this file's docstring), then run `anvil`.")
        return 1
    target = DEST / "anvil.exe"
    if target.exists():
        print(f"Already installed: {target}")
        return 0
    print(f"Downloading Foundry {VERSION} (~120 MB) ...")
    with urllib.request.urlopen(URL, timeout=120) as resp:
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        print(f"Checksum mismatch - refusing to install.\n expected {SHA256}\n got      {digest}")
        return 1
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        member = next((n for n in zf.namelist() if n.lower().endswith("anvil.exe")), None)
        if member is None:
            print("anvil.exe not found in the archive")
            return 1
        DEST.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(member))
    print(f"Installed {target} (checksum verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
