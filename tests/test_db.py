"""Tests for async database engine wiring."""

import pytest
from sqlalchemy import text

from sleuthgraph.db import Base, get_engine, get_session_factory


@pytest.fixture
def sqlite_env(monkeypatch):
    """Force sqlite for this unit-level test — full postgres lives in integration tests."""
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    # Clear cache so new engine uses this sqlite URL
    get_engine.cache_clear()
    get_session_factory.cache_clear()


@pytest.mark.asyncio
async def test_engine_connects(sqlite_env):
    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT 1"))
        assert result.scalar() == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_session_roundtrip(sqlite_env):
    SessionLocal = get_session_factory()
    async with SessionLocal() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1


def test_base_is_declarative():
    # Base must exist so models can inherit it.
    assert hasattr(Base, "metadata")
