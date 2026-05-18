"""Guard: signup route is NOT mounted by default."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.db import get_session


@pytest.fixture
async def nosignup_client(monkeypatch, test_engine):
    """Fresh app with signup disabled (the default)."""
    monkeypatch.delenv("AUTH_ALLOW_SIGNUP", raising=False)

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
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_route_404_when_signup_disabled(nosignup_client: AsyncClient):
    r = await nosignup_client.post(
        "/auth/register",
        json={"email": "bob@example.com", "password": "hunter222hunt"},
    )
    assert r.status_code == 404, (
        f"Expected 404 for disabled signup route, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio
async def test_login_route_still_works_when_signup_disabled(nosignup_client: AsyncClient):
    # Without a valid user, login returns 400 (credentials bad) or 401 — but NOT 404.
    r = await nosignup_client.post(
        "/auth/login",
        data={"username": "nobody@example.com", "password": "hunter222hunt"},
    )
    assert r.status_code in (400, 401, 422), (
        f"Login should exist even when signup is disabled; got {r.status_code}"
    )
