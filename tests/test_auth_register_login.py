"""End-to-end: register -> login -> /users/me -> logout against ASGI app."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_login_me_logout(signup_client: AsyncClient):
    # Register
    r = await signup_client.post(
        "/auth/register",
        json={"email": "alice@example.com", "password": "hunter222", "name": "Alice"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["name"] == "Alice"

    # Login (form-encoded, OAuth2 password flow)
    r = await signup_client.post(
        "/auth/login",
        data={"username": "alice@example.com", "password": "hunter222"},
    )
    assert r.status_code in (200, 204), r.text

    # /users/me — should be authenticated via cookie
    r = await signup_client.get("/users/me")
    assert r.status_code == 200, r.text
    me = r.json()
    assert me["email"] == "alice@example.com"
    assert me["name"] == "Alice"

    # Logout
    r = await signup_client.post("/auth/logout")
    assert r.status_code in (200, 204), r.text

    # After logout, /users/me is 401
    r = await signup_client.get("/users/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_with_wrong_password_rejected(signup_client: AsyncClient):
    # Register first
    r = await signup_client.post(
        "/auth/register",
        json={"email": "bob@example.com", "password": "correctpassword", "name": "Bob"},
    )
    assert r.status_code == 201

    # Wrong password
    r = await signup_client.post(
        "/auth/login",
        data={"username": "bob@example.com", "password": "wrongpassword"},
    )
    assert r.status_code == 400

    # /users/me is 401
    r = await signup_client.get("/users/me")
    assert r.status_code == 401
