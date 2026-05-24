"""Rate-limit guards on /auth/reset-password.

Per issue #74: 5/minute per IP + 5/hour per token. Token axis is the
real defense against bulk token-guessing (attacker can rotate IPs).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_reset_password_per_ip_limit_fires_at_6th_request(client: AsyncClient):
    """5/minute per IP: the 6th reset attempt from one IP is 429.

    Each request uses a distinct token so the per-token limit isn't what
    we trip first. Each individual attempt is 400 (bad-token) until the
    rate limit kicks in.
    """
    for i in range(5):
        r = await client.post(
            "/auth/reset-password",
            json={"token": f"not-a-real-token-{i}", "password": "newpassword1"},
        )
        assert r.status_code == 400, f"attempt {i} got {r.status_code}: {r.text}"

    # Sixth from the same IP trips the limit.
    r = await client.post(
        "/auth/reset-password",
        json={"token": "not-a-real-token-final", "password": "newpassword1"},
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_reset_password_per_token_limit_fires_at_6th_attempt(client: AsyncClient):
    """5/hour per token: 6th attempt against the SAME token from rotating IPs is 429.

    Demonstrates the per-token axis stands alone -- an attacker rotating
    CF-Connecting-IP can't bypass the token bucket.
    """
    SAME_TOKEN = "guess-attempt-token"
    for i in range(5):
        r = await client.post(
            "/auth/reset-password",
            json={"token": SAME_TOKEN, "password": "newpassword1"},
            headers={"cf-connecting-ip": f"203.0.113.{i + 1}"},
        )
        # Each 400 because the token is invalid.
        assert r.status_code == 400, f"attempt {i} got {r.status_code}: {r.text}"

    r = await client.post(
        "/auth/reset-password",
        json={"token": SAME_TOKEN, "password": "newpassword1"},
        headers={"cf-connecting-ip": "203.0.113.99"},
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_reset_password_valid_token_still_works(signup_client: AsyncClient, monkeypatch):
    """The rate-limited path is a faithful drop-in: real reset flow still works.

    Mirrors the existing test_reset_password_with_valid_token but routes
    through our new handler. Ensures we didn't regress the happy path.
    """

    class _Fake:
        def __init__(self):
            self.reset_calls: list[tuple[str, str]] = []

        async def send_password_reset(self, to, token):
            self.reset_calls.append((to, token))

        async def send_email_verify(self, to, token):
            pass

    fake = _Fake()
    import sleuthgraph.auth.email as email_mod

    monkeypatch.setattr(email_mod, "_sender", fake)

    r = await signup_client.post(
        "/auth/register",
        json={"email": "rl-reset@example.com", "password": "originalpass1", "name": "X"},
    )
    assert r.status_code == 201

    await signup_client.post("/auth/forgot-password", json={"email": "rl-reset@example.com"})
    assert fake.reset_calls, "forgot-password did not call email sender"
    _, token = fake.reset_calls[0]

    r = await signup_client.post(
        "/auth/reset-password",
        json={"token": token, "password": "newpassword1234"},
    )
    assert r.status_code == 200, r.text

    # Confirm the new password works.
    r = await signup_client.post(
        "/auth/login",
        data={"username": "rl-reset@example.com", "password": "newpassword1234"},
    )
    assert r.status_code in (200, 204)
