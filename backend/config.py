"""Configuration: loads secrets from the environment (.env) and validates them."""
import base64
import binascii
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")  # never overrides variables that are already set

IDLE_TIMEOUT_SECONDS = 15 * 60
MFA_PENDING_SECONDS = 5 * 60
ABSOLUTE_SESSION_SECONDS = 8 * 60 * 60  # re-login at least once per working day
K_MIN = 10  # minimum group size (also enforced by the smart contract)


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number") from exc


def gpa_scale_default() -> float:
    """GPA_SCALE from the environment (4 or 5 are typical). Used when generating data."""
    scale = _env_float("GPA_SCALE", 4.0)
    if not 1.0 <= scale <= 10.0:
        raise RuntimeError("GPA_SCALE must be between 1 and 10")
    return scale


def validate_data_key(value: str | None) -> bytes:
    """Decode DATA_KEY and make sure it is a 256-bit key."""
    if not value:
        raise RuntimeError("DATA_KEY is not set (run: python scripts/gen_secrets.py --write)")
    try:
        key = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("DATA_KEY must be base64") from exc
    if len(key) != 32:
        raise RuntimeError("DATA_KEY must decode to 32 bytes (AES-256)")
    return key


def db_path() -> str:
    """Database file path; relative values are resolved from the project root."""
    path = Path(os.environ.get("DB_PATH") or "instance/privshare.db")
    if not path.is_absolute():
        path = ROOT / path
    return str(path)


def load_config() -> dict:
    """Build the Flask config dict. Fails fast if a secret is missing or weak."""
    secret = os.environ.get("SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters")
    validate_data_key(os.environ.get("DATA_KEY"))

    return {
        "SECRET_KEY": secret,
        "DB_PATH": db_path(),
        # Uploads (owner import) up to 5 MB; every other request is capped at 64 KB in security.py
        "MAX_CONTENT_LENGTH": 5 * 1024 * 1024 + 64 * 1024,
        # Session cookie hardening
        "SESSION_COOKIE_NAME": "privshare_session",
        "SESSION_COOKIE_SECURE": _env_bool("SESSION_COOKIE_SECURE", True),
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Strict",
        "PERMANENT_SESSION_LIFETIME": timedelta(seconds=IDLE_TIMEOUT_SECONDS),
        # CSRF: token is tied to the session; the Referer check is off because API
        # clients (curl, the Vite proxy) don't send a matching Referer. The token check stays.
        "WTF_CSRF_TIME_LIMIT": None,
        "WTF_CSRF_SSL_STRICT": False,
        # Rate limiting (in-memory is enough for a single-process prototype)
        "RATELIMIT_ENABLED": _env_bool("RATELIMIT_ENABLED", True),
        "RATELIMIT_STORAGE_URI": "memory://",
        # Differential privacy policy
        "EPSILON_TOTAL_DEFAULT": _env_float("EPSILON_TOTAL_DEFAULT", 5.0),
        "EPSILON_MIN": _env_float("EPSILON_MIN", 0.1),
        "EPSILON_MAX": _env_float("EPSILON_MAX", 1.0),
        "GPA_SCALE": gpa_scale_default(),  # fallback only; the scale saved with the data wins
        # "stub" until Phase 3 adds the web3 client
        "CHAIN_BACKEND": os.environ.get("CHAIN_BACKEND", "stub"),
        # Simulated university information system (university_sim/)
        "SIS_URL": os.environ.get("SIS_URL", "https://127.0.0.1:5001"),
        "SIS_API_KEY": os.environ.get("SIS_API_KEY", ""),
        "SIS_CA_FILE": os.environ.get("SIS_CA_FILE") or str(ROOT / "certs" / "cert.pem"),
    }
