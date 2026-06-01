"""Rate-limit guard on /auth/register.

Per issue #74: 5/minute per IP, ONLY when ``AUTH_ALLOW_SIGNUP=true``.
When signup is disabled the rate-limited router isn't mounted at all
(``main.py`` gates inclusion on the flag), so no slot is burned on a
4xx endpoint.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.db import get_session


@pytest.mark.asyncio
async def test_register_rate_limit_per_ip_fires_at_6th_request(signup_client: AsyncClient):
    """5/minute per IP cap: the 6th register from one IP is 429."""
    # Five distinct emails -> 5x 201 from one IP.
    for i in range(5):
        r = await signup_client.post(
            "/auth/register",
            json={
                "email": f"reg-ip-{i}@example.com",
                "password": "registerpass1",
                "name": "R",
            },
        )
        assert r.status_code == 201, f"attempt {i} got {r.status_code}: {r.text}"

    # Sixth from the same IP trips the limit.
    r = await signup_client.post(
        "/auth/register",
        json={
            "email": "reg-ip-final@example.com",
            "password": "registerpass1",
            "name": "R",
        },
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.fixture
async def nosignup_client(monkeypatch, test_engine):
    """Fresh app with signup disabled (the default).

    The default ``client`` fixture imports the module-level
    ``sleuthgraph.main.app`` -- a singleton built whenever
    ``sleuthgraph.main`` was first imported. If an earlier test built
    that singleton with ``AUTH_ALLOW_SIGNUP=true`` (e.g. via
    ``signup_client`` in this same file), the register router stays
    mounted even after the env flips back, and a 404 assertion below
    flips to a 201. Fix: build a fresh app via ``create_app()`` here so
    the assertion is independent of test ordering. Issue #86.
    """
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
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_rate_limited_only_when_signup_enabled(nosignup_client: AsyncClient):
    """When AUTH_ALLOW_SIGNUP=false, the rate-limited register router is
    NOT mounted; register is just 404."""
    r = await nosignup_client.post(
        "/auth/register",
        json={"email": "nope@example.com", "password": "anypass123456", "name": "N"},
    )
    # fastapi-users register router is also skipped, so the path doesn't exist.
    assert r.status_code == 404, r.text
