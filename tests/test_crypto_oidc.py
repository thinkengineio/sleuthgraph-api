"""Tests for the OIDC state signing subkey."""

from sleuthgraph.crypto import (
    jwt_signing_key,
    oidc_state_key,
    _reset_caches,
)


def test_oidc_state_key_is_distinct_from_jwt_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "x" * 64)
    from sleuthgraph.config import get_settings
    get_settings.cache_clear() if hasattr(get_settings, "cache_clear") else None
    _reset_caches()
    assert oidc_state_key() != jwt_signing_key()
    assert len(bytes.fromhex(oidc_state_key())) == 32


def test_oidc_state_key_is_deterministic():
    _reset_caches()
    a = oidc_state_key()
    _reset_caches()
    b = oidc_state_key()
    assert a == b
