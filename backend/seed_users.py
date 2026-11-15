"""Create one demo account per role and print its password and TOTP enrollment URI once.

Run: python -m backend.seed_users [--reset]
--reset gives existing demo accounts a new password and TOTP secret.
Prototype only: in a real deployment users enrol through the admin.
"""
import argparse
import os
import secrets
from contextlib import closing

from . import auth, users
from .config import db_path
from .db import connect, init_db

DEMO_USERS = [
    ("uni_owner1", "uni_owner"),
    ("partner_rep1", "partner_rep"),
    ("analyst1", "analyst"),
    ("admin1", "admin"),
    ("auditor1", "auditor"),
]


def _random_password() -> str:
    # token_urlsafe can lack a digit/symbol; the suffix guarantees the password policy
    return secrets.token_urlsafe(12) + "aA1!"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create demo users (one per role).")
    parser.add_argument("--reset", action="store_true", help="rotate password + TOTP of existing demo users")
    args = parser.parse_args(argv)
    epsilon_total = float(os.environ.get("EPSILON_TOTAL_DEFAULT", "5.0"))

    with closing(connect(db_path())) as conn:
        init_db(conn)
        for username, role in DEMO_USERS:
            existing = users.get_by_username(conn, username)
            password = _random_password()
            if existing is None:
                _, secret = users.create_user(conn, username, password, role, epsilon_total)
            elif args.reset:
                secret = users.reset_credentials(conn, existing["id"], password)
            else:
                print(f"{username:<13} exists (use --reset to rotate its credentials)")
                continue
            print(f"\n{username}  role={role}\n  password : {password}\n"
                  f"  TOTP key : {secret}\n  TOTP URI : {auth.totp_uri(secret, username)}")
    print("\nAdd each TOTP key to an authenticator app. These values are not shown again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
