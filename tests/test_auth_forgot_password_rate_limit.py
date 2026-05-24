"""Rate-limit guards on /auth/forgot-password.

Covers issue #70: a single IP can't fire more than 5/minute and a single
target email can't be hit more than 3/hour. The endpoint must still
return 202 inside the budget (no user-enumeration regression) and 429
above it (with a generic body that doesn't leak whether the email
exists).
"""

import pytest
from httpx import AsyncClient


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


@pytest.mark.asyncio
async def test_forgot_password_ip_rate_limit_fires(client: AsyncClient, fake_email_sender):
    """The 6th request from the same IP within a minute gets 429."""
    # First 5 attempts -- distinct emails so the per-email limit isn't
    # what we're tripping. All should return 202.
    for i in range(5):
        r = await client.post(
            "/auth/forgot-password",
            json={"email": f"ip-test-{i}@example.com"},
        )
        assert r.status_code == 202, f"attempt {i} got {r.status_code}: {r.text}"

    # 6th attempt from same IP trips the 5/minute IP limit.
    r = await client.post(
        "/auth/forgot-password",
        json={"email": "ip-test-final@example.com"},
    )
    assert r.status_code == 429, r.text
    # Body must not hint at email existence.
    body = r.json()
    assert "ghost" not in r.text.lower()
    assert body == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_forgot_password_email_rate_limit_fires(
    signup_client: AsyncClient, fake_email_sender
):
    """The 4th request against the same email within an hour gets 429.

    Uses ``signup_client`` so we can register a real user and verify the
    rate-limited response is identical for existing and non-existing
    emails (no enumeration via the 429 body).
    """
    # Register an existing user so we can prove the limit applies
    # uniformly regardless of whether the target exists.
    r = await signup_client.post(
        "/auth/register",
        json={
            "email": "target@example.com",
            "password": "originalpass1",
            "name": "Target",
        },
    )
    assert r.status_code == 201

    # Three forgot-password hits against the same email succeed.
    for i in range(3):
        r = await signup_client.post(
            "/auth/forgot-password",
            json={"email": "target@example.com"},
        )
        assert r.status_code == 202, f"attempt {i} got {r.status_code}: {r.text}"

    # Fourth attempt against the same email is rate-limited.
    r = await signup_client.post(
        "/auth/forgot-password",
        json={"email": "target@example.com"},
    )
    assert r.status_code == 429, r.text
    assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_forgot_password_email_limit_case_insensitive(client: AsyncClient, fake_email_sender):
    """Casing shouldn't be a bypass for the per-email limit."""
    for variant in ("victim@example.com", "Victim@Example.com", "VICTIM@EXAMPLE.COM"):
        r = await client.post(
            "/auth/forgot-password",
            json={"email": variant},
        )
        assert r.status_code == 202, f"variant {variant} got {r.status_code}"

    # Fourth hit -- different casing again -- still trips the limit.
    r = await client.post(
        "/auth/forgot-password",
        json={"email": "vIcTiM@example.com"},
    )
    assert r.status_code == 429, r.text
