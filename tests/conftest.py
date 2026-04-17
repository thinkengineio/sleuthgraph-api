"""Shared pytest fixtures."""

import pytest
from httpx import ASGITransport, AsyncClient

from sleuthgraph.db import get_engine, get_session_factory


@pytest.fixture(autouse=True)
def _set_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    # Clear engine cache between tests so each gets a fresh in-memory DB.
    get_engine.cache_clear()
    get_session_factory.cache_clear()


@pytest.fixture
async def client():
    # Import here so env fixtures apply first.
    from sleuthgraph.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
