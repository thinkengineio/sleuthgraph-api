"""Tests for OIDC login + callback routes."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.auth.oidc_state import encode_state


@pytest.mark.asyncio
async def test_login_returns_404_when_oidc_disabled(client: AsyncClient, monkeypatch):
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_SECRET", raising=False)
    r = await client.get("/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_login_redirects_to_issuer(client: AsyncClient, monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    fake_client = AsyncMock()
    fake_client.get_authorization_url = AsyncMock(
        return_value="https://id.example.com/authorize?client_id=cid&state=abc"
    )
    with patch("sleuthgraph.auth.oidc.get_oidc_client", return_value=fake_client):
        r = await client.get("/auth/oidc/login?next=/cases", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith("https://id.example.com/authorize?")


@pytest.mark.asyncio
async def test_callback_invalid_state_returns_400(client: AsyncClient, monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    fake_client = AsyncMock()
    with patch("sleuthgraph.auth.oidc.get_oidc_client", return_value=fake_client):
        r = await client.get("/auth/oidc/callback?code=x&state=not-a-jwt")
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_state"


@pytest.mark.asyncio
async def test_callback_success_sets_cookie_and_redirects(
    client: AsyncClient, monkeypatch, test_engine
):
    """Happy-path: existing user with oidc_sub is found, session cookie is set, redirect to /."""
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    # Create user in the test DB.
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as session:
        u = User(
            id=uuid.uuid4(),
            email="happy@example.com",
            hashed_password="!",
            is_active=True,
            is_superuser=False,
            is_verified=True,
            oidc_sub="happy-sub",
        )
        session.add(u)
        await session.commit()

    # Build a valid state JWT.
    from sleuthgraph.crypto import _reset_caches

    _reset_caches()
    state = encode_state(code_verifier="v" * 64, next_path="/", oidc_nonce="test-nonce")

    fake_token = {"access_token": "tok", "id_token": "fake.id.token", "token_type": "bearer"}
    fake_client = AsyncMock()
    fake_client.get_access_token = AsyncMock(return_value=fake_token)
    fake_client.get_id_email = AsyncMock(return_value=("happy-sub", "happy@example.com"))

    fake_claims = {
        "sub": "happy-sub",
        "email": "happy@example.com",
        "email_verified": True,
        "nonce": "test-nonce",
    }
    with (
        patch("sleuthgraph.auth.oidc.get_oidc_client", return_value=fake_client),
        patch("sleuthgraph.auth.oidc.validate_id_token", return_value=fake_claims),
    ):
        r = await client.get(
            f"/auth/oidc/callback?code=authcode&state={state}",
            follow_redirects=False,
        )

    assert r.status_code == 302
    assert r.headers["location"] == "/"
    # Session cookie must be set.
    cookie_header = r.headers.get("set-cookie", "")
    assert "sleuthgraph_session" in cookie_header


@pytest.mark.asyncio
async def test_callback_rejects_missing_id_token(client: AsyncClient, monkeypatch):
    """Token response without id_token is a 400 — we refuse to trust userinfo alone."""
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    from sleuthgraph.crypto import _reset_caches

    _reset_caches()
    state = encode_state(code_verifier="v" * 64, next_path="/", oidc_nonce="test-nonce")

    fake_client = AsyncMock()
    fake_client.get_access_token = AsyncMock(
        return_value={"access_token": "tok", "token_type": "bearer"}
    )
    with patch("sleuthgraph.auth.oidc.get_oidc_client", return_value=fake_client):
        r = await client.get(
            f"/auth/oidc/callback?code=authcode&state={state}",
            follow_redirects=False,
        )
    assert r.status_code == 400
    assert r.json()["detail"] == "oidc_missing_id_token"


@pytest.mark.asyncio
async def test_callback_rejects_bad_id_token(client: AsyncClient, monkeypatch):
    """id_token that fails signature/claims validation -> 400."""
    from sleuthgraph.auth.oidc_id_token import IdTokenError

    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    from sleuthgraph.crypto import _reset_caches

    _reset_caches()
    state = encode_state(code_verifier="v" * 64, next_path="/", oidc_nonce="test-nonce")

    fake_client = AsyncMock()
    fake_client.get_access_token = AsyncMock(
        return_value={"access_token": "tok", "id_token": "bad.id.token", "token_type": "bearer"}
    )
    with (
        patch("sleuthgraph.auth.oidc.get_oidc_client", return_value=fake_client),
        patch("sleuthgraph.auth.oidc.validate_id_token", side_effect=IdTokenError("bad_signature")),
    ):
        r = await client.get(
            f"/auth/oidc/callback?code=authcode&state={state}",
            follow_redirects=False,
        )
    assert r.status_code == 400
    assert r.json()["detail"] == "oidc_invalid_id_token"
