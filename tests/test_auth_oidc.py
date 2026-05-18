"""Tests for /auth/oidc-status endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.db import get_session


@pytest.mark.asyncio
async def test_oidc_status_disabled_when_unset(monkeypatch, test_engine):
    """When OIDC env vars are not set, endpoint returns {"enabled": false}."""
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_SECRET", raising=False)

    from sleuthgraph.config import get_settings

    get_settings.cache_clear()

    from sleuthgraph.main import create_app

    app = create_app()

    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_session():
        async with TestSession() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/auth/oidc-status")
    app.dependency_overrides.clear()

    assert r.status_code == 200
    assert r.json() == {"enabled": False}


@pytest.mark.asyncio
async def test_oidc_status_enabled_when_all_set(monkeypatch, test_engine):
    """When all OIDC env vars are set, endpoint returns {"enabled": true, "issuer": "..."}."""
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    from sleuthgraph.config import get_settings

    get_settings.cache_clear()

    from sleuthgraph.main import create_app

    app = create_app()

    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_session():
        async with TestSession() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/auth/oidc-status")
    app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body == {"enabled": True, "issuer": "https://id.example.com"}
    # Critical: never leak secrets
    assert "client_id" not in body
    assert "client_secret" not in body
