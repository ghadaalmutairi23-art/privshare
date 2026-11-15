"""Password hashing (Argon2id) and TOTP multi-factor authentication."""
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

ISSUER = "PrivShare"
MIN_PASSWORD_LENGTH = 12

_ph = PasswordHasher()
# Verified against when the username is unknown, so response time doesn't reveal valid usernames
_DUMMY_HASH = _ph.hash("privshare-timing-equaliser")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def burn_verify(password: str) -> None:
    """Spend the same time as a real check (used for unknown usernames)."""
    verify_password(_DUMMY_HASH, password)


def password_problem(password: str) -> str | None:
    """Return why a password is too weak, or None if it is acceptable."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    classes = [any(c.islower() for c in password), any(c.isupper() for c in password),
               any(c.isdigit() for c in password), any(not c.isalnum() for c in password)]
    if sum(classes) < 3:
        return "Password must mix at least three of: lowercase, uppercase, digits, symbols"
    return None


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    """otpauth:// URI for enrolling in an authenticator app (shown once)."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip()
    if len(code) != 6 or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)  # +-30 s clock drift
