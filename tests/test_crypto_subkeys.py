"""Subkey derivation: determinism + purpose isolation."""

from sleuthgraph.crypto import (
    _reset_caches,
    credential_encryption_key,
    jwt_signing_key,
    password_reset_token_key,
    verification_token_key,
)


def test_subkeys_are_deterministic():
    a = jwt_signing_key()
    _reset_caches()
    b = jwt_signing_key()
    assert a == b


def test_subkeys_differ_by_purpose():
    _reset_caches()
    jwt = jwt_signing_key()
    reset = password_reset_token_key()
    verify = verification_token_key()
    assert len({jwt, reset, verify}) == 3


def test_subkeys_differ_from_master_secret():
    from sleuthgraph.config import get_settings
    _reset_caches()
    master = get_settings().secret_key
    assert jwt_signing_key() != master
    assert password_reset_token_key() != master


def test_credential_encryption_key_is_bytes_32():
    _reset_caches()
    k = credential_encryption_key()
    assert isinstance(k, bytes)
    assert len(k) == 32


def test_rotation_master_secret_rotates_all_subkeys(monkeypatch):
    _reset_caches()
    original = jwt_signing_key()
    monkeypatch.setenv("SECRET_KEY", "z" * 32)
    _reset_caches()
    rotated = jwt_signing_key()
    assert original != rotated
