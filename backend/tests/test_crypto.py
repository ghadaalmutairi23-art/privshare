import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from backend import crypto


def test_roundtrip():
    key = crypto.load_key()
    token = crypto.encrypt("Ahmad", key)
    assert "Ahmad" not in token
    assert crypto.decrypt(token, key) == "Ahmad"


def test_same_value_gives_different_ciphertext():
    key = crypto.load_key()
    a, b = crypto.encrypt("3.50", key), crypto.encrypt("3.50", key)
    assert a != b
    assert base64.b64decode(a)[:12] != base64.b64decode(b)[:12]  # fresh nonce each time


def test_tampered_ciphertext_is_rejected():
    key = crypto.load_key()
    raw = bytearray(base64.b64decode(crypto.encrypt("1234567890", key)))
    raw[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.decrypt(base64.b64encode(bytes(raw)).decode(), key)


def test_wrong_key_is_rejected():
    token = crypto.encrypt("secret", crypto.load_key())
    with pytest.raises(InvalidTag):
        crypto.decrypt(token, os.urandom(32))


def test_value_moved_to_another_column_is_rejected():
    key = crypto.load_key()
    token = crypto.encrypt("3.90", key, b"students.gpa")
    with pytest.raises(InvalidTag):
        crypto.decrypt(token, key, b"students.name")


@pytest.mark.parametrize("bad", ["", "not-base64!!", base64.b64encode(b"short").decode()])
def test_bad_data_key_is_refused(monkeypatch, bad):
    monkeypatch.setenv("DATA_KEY", bad)
    with pytest.raises(RuntimeError):
        crypto.load_key()
