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
async def test_validate_password_accepts_8_or_more():
    mgr = UserManager(user_db=None)
    await mgr.validate_password("longenough", user=None)  # should not raise


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
