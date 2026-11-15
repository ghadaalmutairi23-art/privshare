"""AES-256-GCM encryption for sensitive fields at rest, plus keyed blind indexes.

Stored format: base64(nonce[12] || ciphertext || tag[16]). A fresh random nonce is used
for every value. The optional `aad` binds a ciphertext to its column, so a value copied
into another column fails to decrypt.

A blind index (HMAC-SHA256 with a key derived from DATA_KEY) lets the database find a
student by number without storing the number in clear text.
"""
import base64
import hashlib
import hmac
import os
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import validate_data_key

NONCE_SIZE = 12
TAG_SIZE = 16

# Additional authenticated data for the encrypted student columns
AAD_NAME = b"students.name"
AAD_NATIONAL_ID = b"students.national_id"
AAD_GPA = b"students.gpa"
AAD_STUDENT_NO = b"students.student_no"


def load_key() -> bytes:
    """Read the 256-bit data key from the DATA_KEY environment variable (never from code)."""
    return validate_data_key(os.environ.get("DATA_KEY"))


def encrypt(plain: str, key: bytes, aad: bytes | None = None) -> str:
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plain.encode("utf-8"), aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt(token: str, key: bytes, aad: bytes | None = None) -> str:
    """Raises cryptography.exceptions.InvalidTag if the value or key is wrong."""
    raw = base64.b64decode(token)
    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("ciphertext too short")
    nonce, ct = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, aad).decode("utf-8")


@lru_cache(maxsize=4)
def _index_key(key: bytes) -> bytes:
    """Separate key for blind indexes (HKDF), so the AES key is never used for hashing."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"privshare/blind-index/v1").derive(key)


def blind_index(value: str, key: bytes) -> str:
    """Deterministic keyed hash (hex) for exact-match lookups of an encrypted value."""
    return hmac.new(_index_key(key), value.encode("utf-8"), hashlib.sha256).hexdigest()
