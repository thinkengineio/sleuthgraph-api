"""Rate-limit guard on /auth/register.

Per issue #74: 5/minute per IP, ONLY when ``AUTH_ALLOW_SIGNUP=true``.
When signup is disabled the rate-limited router isn't mounted at all
(``main.py`` gates inclusion on the flag), so no slot is burned on a
4xx endpoint.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


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


@pytest.mark.asyncio
async def test_register_rate_limited_only_when_signup_enabled(client: AsyncClient):
    """When AUTH_ALLOW_SIGNUP=false (default ``client`` fixture), the
    rate-limited register router is NOT mounted; register is just 404."""
    r = await client.post(
        "/auth/register",
        json={"email": "nope@example.com", "password": "anypass123456", "name": "N"},
    )
    # fastapi-users register router is also skipped, so the path doesn't exist.
    assert r.status_code == 404, r.text
