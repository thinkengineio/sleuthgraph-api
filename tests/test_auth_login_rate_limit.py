"""Rate-limit guards on /auth/login.

Covers issue #74: credential stuffing (many IPs vs one username) AND
password spraying (one IP vs many usernames) both need bounded blast
radius. We assert BOTH axes fire at the configured cap and emit the
generic 429 body (no signal about whether the username exists).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


async def _register(client: AsyncClient, email: str, password: str = "originalpass1") -> None:
    r = await client.post(
        "/auth/register",
        json={"email": email, "password": password, "name": "T"},
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_login_rate_limit_per_ip_fires_at_11th_request(signup_client: AsyncClient):
    """10/minute per IP cap: the 11th attempt from the same IP is 429."""
    # Distinct usernames so the per-username limit isn't what trips first.
    # Bad passwords are fine -- the IP limit fires regardless of credential
    # validity. Each attempt is 400 until the 11th, which is 429.
    for i in range(10):
        r = await signup_client.post(
            "/auth/login",
            data={"username": f"login-ip-{i}@example.com", "password": "wrongpassword1"},
        )
        # Unknown username + bad password -> 400 (LOGIN_BAD_CREDENTIALS).
        assert r.status_code == 400, f"attempt {i} got {r.status_code}: {r.text}"

    r = await signup_client.post(
        "/auth/login",
        data={"username": "login-ip-final@example.com", "password": "wrongpassword1"},
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_login_rate_limit_per_username_fires_at_6th_request(signup_client: AsyncClient):
    """5/minute per username cap: the 6th attempt against one username is 429.

    Uses distinct ``cf-connecting-ip`` per request so the per-IP axis
    isn't what we're tripping. Proves the username axis stands on its
    own as a defense against credential stuffing from rotating IPs.
    """
    await _register(signup_client, "victim@example.com")

    for i in range(5):
        r = await signup_client.post(
            "/auth/login",
            data={"username": "victim@example.com", "password": "wrongpassword1"},
            headers={"cf-connecting-ip": f"203.0.113.{i + 1}"},
        )
        # Wrong password against existing user -> 400.
        assert r.status_code == 400, f"attempt {i} got {r.status_code}: {r.text}"

    r = await signup_client.post(
        "/auth/login",
        data={"username": "victim@example.com", "password": "wrongpassword1"},
        headers={"cf-connecting-ip": "203.0.113.99"},
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_login_username_rate_limit_does_not_leak_user_existence(
    signup_client: AsyncClient,
):
    """The 429 must be identical whether the target username exists or not.

    Otherwise the rate-limit channel itself becomes an enumeration oracle.
    """
    # Hit a username that does NOT exist five times -- it should accumulate
    # against the same bucket because we don't gate on existence.
    for i in range(5):
        r = await signup_client.post(
            "/auth/login",
            data={"username": "nobody@example.com", "password": "wrongpassword1"},
            headers={"cf-connecting-ip": f"203.0.113.{i + 1}"},
        )
        assert r.status_code == 400, f"attempt {i} got {r.status_code}: {r.text}"

    r = await signup_client.post(
        "/auth/login",
        data={"username": "nobody@example.com", "password": "wrongpassword1"},
        headers={"cf-connecting-ip": "203.0.113.99"},
    )
    # Generic 429 -- no enumeration signal.
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_login_rate_limit_username_case_insensitive(signup_client: AsyncClient):
    """Casing shouldn't be a bypass for the per-username limit."""
    await _register(signup_client, "case@example.com")

    for variant in (
        "case@example.com",
        "Case@Example.com",
        "CASE@EXAMPLE.COM",
        "cAsE@example.com",
        "case@EXAMPLE.com",
    ):
        r = await signup_client.post(
            "/auth/login",
            data={"username": variant, "password": "wrongpassword1"},
            headers={"cf-connecting-ip": f"203.0.113.{hash(variant) % 200 + 1}"},
        )
        assert r.status_code == 400, f"variant {variant} got {r.status_code}: {r.text}"

    r = await signup_client.post(
        "/auth/login",
        data={"username": "cAsE@EXAMPLE.com", "password": "wrongpassword1"},
        headers={"cf-connecting-ip": "203.0.113.250"},
    )
    assert r.status_code == 429, r.text


@pytest.mark.asyncio
async def test_login_successful_path_still_works(signup_client: AsyncClient):
    """Sanity: legitimate login still issues a session cookie."""
    await _register(signup_client, "good@example.com", password="legitpass1234")
    r = await signup_client.post(
        "/auth/login",
        data={"username": "good@example.com", "password": "legitpass1234"},
    )
    assert r.status_code in (200, 204), r.text
    # And the cookie works for /users/me.
    r = await signup_client.get("/users/me")
    assert r.status_code == 200, r.text
