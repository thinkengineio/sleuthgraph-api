"""Tests for UserManager password policy and token secret wiring."""

import pytest
from fastapi_users.exceptions import InvalidPasswordException

from sleuthgraph.auth.manager import UserManager


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "s" * 32)


@pytest.mark.asyncio
async def test_validate_password_rejects_short():
    mgr = UserManager(user_db=None)
    with pytest.raises(InvalidPasswordException):
        await mgr.validate_password("short", user=None)


@pytest.mark.asyncio
async def test_validate_password_rejects_under_12():
    """Passwords shorter than 12 characters are rejected."""
    mgr = UserManager(user_db=None)
    with pytest.raises(InvalidPasswordException):
        await mgr.validate_password("elevenchar!", user=None)  # 11 chars


@pytest.mark.asyncio
async def test_validate_password_accepts_12_or_more():
    mgr = UserManager(user_db=None)
    await mgr.validate_password("longenoughpw!", user=None)  # 13 chars, should not raise


@pytest.mark.asyncio
async def test_validate_password_rejects_breached(monkeypatch):
    """When HIBP reports the password as breached, reject it."""

    async def _always_pwned(_pw: str) -> bool:
        return True

    monkeypatch.setattr("sleuthgraph.auth.manager._is_password_pwned", _always_pwned)

    mgr = UserManager(user_db=None)
    with pytest.raises(InvalidPasswordException) as exc_info:
        await mgr.validate_password("longenoughpw!", user=None)
    assert "data breach" in exc_info.value.reason


@pytest.mark.asyncio
async def test_validate_password_allows_clean(monkeypatch):
    """When HIBP reports the password as clean, allow it."""

    async def _never_pwned(_pw: str) -> bool:
        return False

    monkeypatch.setattr("sleuthgraph.auth.manager._is_password_pwned", _never_pwned)

    mgr = UserManager(user_db=None)
    await mgr.validate_password("longenoughpw!", user=None)  # should not raise


def test_manager_token_secrets_use_derived_subkeys():
    from sleuthgraph.crypto import password_reset_token_key, verification_token_key, _reset_caches
    _reset_caches()
    mgr = UserManager(user_db=None)
    # Derived, not the raw master
    from sleuthgraph.config import get_settings
    assert mgr.reset_password_token_secret != get_settings().secret_key
    assert mgr.reset_password_token_secret == password_reset_token_key()
    assert mgr.verification_token_secret == verification_token_key()
    assert mgr.reset_password_token_secret != mgr.verification_token_secret
