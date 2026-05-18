"""Password reset flow: request token -> email sender called -> reset with token."""

import pytest
from httpx import AsyncClient


@pytest.fixture
async def fake_email_sender(monkeypatch):
    """Swap the ConsoleEmailSender for an in-memory recorder."""

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


@pytest.mark.asyncio
async def test_forgot_password_triggers_email(signup_client: AsyncClient, fake_email_sender):
    # Register user first
    r = await signup_client.post(
        "/auth/register",
        json={"email": "reset@example.com", "password": "originalpass1", "name": "Reset"},
    )
    assert r.status_code == 201

    r = await signup_client.post(
        "/auth/forgot-password",
        json={"email": "reset@example.com"},
    )
    assert r.status_code == 202
    assert len(fake_email_sender.reset_calls) == 1
    to, token = fake_email_sender.reset_calls[0]
    assert to == "reset@example.com"
    assert token  # non-empty


@pytest.mark.asyncio
async def test_reset_password_with_valid_token(signup_client: AsyncClient, fake_email_sender):
    r = await signup_client.post(
        "/auth/register",
        json={"email": "reset2@example.com", "password": "originalpass1", "name": "X"},
    )
    assert r.status_code == 201

    # Request reset
    await signup_client.post("/auth/forgot-password", json={"email": "reset2@example.com"})
    _, token = fake_email_sender.reset_calls[0]

    # Submit new password
    r = await signup_client.post(
        "/auth/reset-password",
        json={"token": token, "password": "newpassword1"},
    )
    assert r.status_code == 200, r.text

    # Login with new password
    r = await signup_client.post(
        "/auth/login",
        data={"username": "reset2@example.com", "password": "newpassword1"},
    )
    assert r.status_code in (200, 204)

    # Old password rejected
    r = await signup_client.post(
        "/auth/login",
        data={"username": "reset2@example.com", "password": "originalpass1"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_reset_password_bad_token(signup_client: AsyncClient):
    r = await signup_client.post(
        "/auth/reset-password",
        json={"token": "not-a-real-token", "password": "newpassword1"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_forgot_password_nonexistent_email_still_202(client: AsyncClient, fake_email_sender):
    """No email enumeration: always 202 even for unknown addresses."""
    r = await client.post(
        "/auth/forgot-password",
        json={"email": "ghost@example.com"},
    )
    assert r.status_code == 202
    assert len(fake_email_sender.reset_calls) == 0  # no send for nonexistent user
