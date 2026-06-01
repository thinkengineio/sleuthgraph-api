"""Rate-limit guards on /auth/request-verify-token.

Covers issue #83: per-IP and per-email caps on the
``/auth/request-verify-token`` handler, mirroring the forgot-password
shape (PR #72 + #82). The endpoint only mounts when
``AUTH_ALLOW_EMAIL_VERIFY=true`` so the fixture below builds a fresh app
with that flag flipped on (the default ``client`` fixture has it off).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.db import get_session


@pytest.fixture
async def fake_email_sender(monkeypatch):
    """Swap the email sender so tests don't hit a real SMTP path."""

    class _Fake:
        def __init__(self):
            self.reset_calls: list[tuple[str, str]] = []
            self.verify_calls: list[tuple[str, str]] = []

        async def send_password_reset(self, to, token):
            self.reset_calls.append((to, token))

        async def send_email_verify(self, to, token):
            self.verify_calls.append((to, token))

    fake = _Fake()
    import sleuthgraph.auth.email as email_mod

    monkeypatch.setattr(email_mod, "_sender", fake)
    return fake


@pytest.fixture
async def verify_client(monkeypatch, test_engine):
    """Fresh app with email-verify mounted.

    Uses the ``create_app()`` factory so the verify routes pick up the
    flipped flag at construction time (the module-level ``app`` in
    ``sleuthgraph.main`` was built with the flag off).
    """
    monkeypatch.setenv("AUTH_ALLOW_EMAIL_VERIFY", "true")

    from sleuthgraph.config import get_settings

    get_settings.cache_clear()

    from sleuthgraph.main import create_app

    app = create_app()

    from sleuthgraph.auth.backend import cookie_transport

    original_secure = cookie_transport.cookie_secure
    cookie_transport.cookie_secure = False

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
        cookie_transport.cookie_secure = original_secure


@pytest.mark.asyncio
async def test_request_verify_token_ip_rate_limit_fires(
    verify_client: AsyncClient, fake_email_sender
):
    """The 6th request from the same IP within a minute gets 429."""
    for i in range(5):
        r = await verify_client.post(
            "/auth/request-verify-token",
            json={"email": f"verify-ip-{i}@example.com"},
        )
        assert r.status_code == 202, f"attempt {i} got {r.status_code}: {r.text}"

    r = await verify_client.post(
        "/auth/request-verify-token",
        json={"email": "verify-ip-final@example.com"},
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_request_verify_token_email_rate_limit_fires(
    verify_client: AsyncClient, fake_email_sender
):
    """The 4th request against the same email within an hour gets 429.

    Three hits from three different "real" IPs (so the per-IP bucket
    isn't what trips) all succeed; the 4th -- regardless of IP -- is
    rate-limited because the email-keyed bucket is exhausted.
    """
    for i, ip in enumerate(("203.0.113.1", "203.0.113.2", "203.0.113.3")):
        r = await verify_client.post(
            "/auth/request-verify-token",
            json={"email": "target@example.com"},
            headers={"cf-connecting-ip": ip},
        )
        assert r.status_code == 202, f"attempt {i} ip={ip} got {r.status_code}: {r.text}"

    r = await verify_client.post(
        "/auth/request-verify-token",
        json={"email": "target@example.com"},
        headers={"cf-connecting-ip": "203.0.113.4"},
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_request_verify_token_email_limit_case_insensitive(
    verify_client: AsyncClient, fake_email_sender
):
    """Casing shouldn't be a bypass for the per-email limit."""
    for i, variant in enumerate(("victim@example.com", "Victim@Example.com", "VICTIM@EXAMPLE.COM")):
        r = await verify_client.post(
            "/auth/request-verify-token",
            json={"email": variant},
            headers={"cf-connecting-ip": f"203.0.113.{i + 1}"},
        )
        assert r.status_code == 202, f"variant {variant} got {r.status_code}"

    r = await verify_client.post(
        "/auth/request-verify-token",
        json={"email": "vIcTiM@example.com"},
        headers={"cf-connecting-ip": "203.0.113.99"},
    )
    assert r.status_code == 429, r.text


@pytest.fixture
async def noverify_client(monkeypatch, test_engine):
    """Fresh app with email-verify disabled (the default).

    Mirrors ``nosignup_client`` in ``test_auth_signup_disabled.py`` so
    the 404 assertion below isn't order-dependent on whether some
    earlier test left the module-level ``sleuthgraph.main.app`` with
    verify mounted.
    """
    monkeypatch.delenv("AUTH_ALLOW_EMAIL_VERIFY", raising=False)

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
async def test_request_verify_token_not_mounted_when_flag_off(noverify_client: AsyncClient):
    """When AUTH_ALLOW_EMAIL_VERIFY=false (default), the path is 404."""
    r = await noverify_client.post(
        "/auth/request-verify-token",
        json={"email": "nobody@example.com"},
    )
    assert r.status_code == 404, r.text
