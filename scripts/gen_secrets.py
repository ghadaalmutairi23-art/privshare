"""Print fresh secrets, create a new .env, or add newly introduced settings to an existing .env.

Run: python scripts/gen_secrets.py                (print only)
     python scripts/gen_secrets.py --write        (create .env from .env.example; refuses to overwrite)
     python scripts/gen_secrets.py --add-missing  (append keys from .env.example that .env lacks;
                                                   existing values - especially DATA_KEY - are never changed)
"""
import argparse
import base64
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _fresh_values() -> dict:
    return {
        "DATA_KEY": base64.b64encode(os.urandom(32)).decode(),
        "SECRET_KEY": secrets.token_hex(32),
        "SIS_API_KEY": secrets.token_urlsafe(32),
    }


def _example_lines() -> list[str]:
    return (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="create .env with new secrets")
    group.add_argument("--add-missing", action="store_true", help="add new settings to an existing .env")
    args = parser.parse_args()
    values = _fresh_values()
    env_file = ROOT / ".env"

    if args.add_missing:
        if not env_file.exists():
            print(".env does not exist yet - use --write.")
            return 1
        existing = {line.split("=", 1)[0].strip() for line in env_file.read_text(encoding="utf-8").splitlines()
                    if "=" in line and not line.lstrip().startswith("#")}
        added = []
        for line in _example_lines():
            name = line.split("=", 1)[0].strip()
            if "=" in line and not line.lstrip().startswith("#") and name not in existing:
                added.append(f"{name}={values[name]}" if name in values else line)
        if added:
            with env_file.open("a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(added) + "\n")
        print(f"Added {len(added)} setting(s): " + ", ".join(a.split("=", 1)[0] for a in added) if added
              else ".env already has every setting.")
        return 0

    if not args.write:
        for name, value in values.items():
            print(f"{name}={value}")
        return 0

    if env_file.exists():
        print(".env already exists - not overwritten (changing DATA_KEY makes existing data unreadable).")
        print("To add settings introduced by later phases, run: python scripts/gen_secrets.py --add-missing")
        return 1
    lines = []
    for line in _example_lines():
        name = line.split("=", 1)[0]
        lines.append(f"{name}={values[name]}" if name in values else line)
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {env_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
