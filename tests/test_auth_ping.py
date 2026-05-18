"""Tests for /auth/ping authed smoke endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_ping_unauthed_returns_401(client: AsyncClient):
    r = await client.get("/auth/ping")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_ping_authed_returns_user_email(signup_client: AsyncClient):
    # Register + login via existing fixture
    r = await signup_client.post(
        "/auth/register",
        json={"email": "pinguser@example.com", "password": "pingpass12345", "name": "Pinger"},
    )
    assert r.status_code == 201, r.text
    r = await signup_client.post(
        "/auth/login",
        data={"username": "pinguser@example.com", "password": "pingpass12345"},
    )
    assert r.status_code in (200, 204), r.text

    r = await signup_client.get("/auth/ping")
    assert r.status_code == 200
    body = r.json()
    assert body == {"user": "pinguser@example.com"}
