"""Rate-limit guard on /auth/oidc/callback.

Per issue #74: 30/minute per IP. The cap is generous because a legit
redirect flow is ~1 request per login; the limit just bounds blast
radius if an authorization code leaks.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_oidc_callback_rate_limit_fires_at_31st_request(client: AsyncClient, monkeypatch):
    """30/minute per IP: the 31st callback hit is 429."""
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    # Use an invalid state -- the handler will 400 on each attempt. That's
    # fine; the IP rate limit fires regardless of the eventual status
    # code (decorator wraps the whole handler).
    fake_client = AsyncMock()
    with patch("sleuthgraph.auth.oidc.get_oidc_client", return_value=fake_client):
        for i in range(30):
            r = await client.get("/auth/oidc/callback?code=x&state=bad")
            assert r.status_code == 400, f"attempt {i} got {r.status_code}: {r.text}"

        r = await client.get("/auth/oidc/callback?code=x&state=bad")
        assert r.status_code == 429, r.text
        assert r.json() == {"detail": "Too many requests. Please try again later."}


@pytest.mark.asyncio
async def test_oidc_callback_rate_limit_per_cf_ip(client: AsyncClient, monkeypatch):
    """Distinct CF-Connecting-IPs get distinct 30/minute buckets."""
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")

    fake_client = AsyncMock()
    with patch("sleuthgraph.auth.oidc.get_oidc_client", return_value=fake_client):
        # 30 attempts from one IP -> all 400 (still within budget).
        for _ in range(30):
            r = await client.get(
                "/auth/oidc/callback?code=x&state=bad",
                headers={"cf-connecting-ip": "203.0.113.7"},
            )
            assert r.status_code == 400

        # A different CF-Connecting-IP starts fresh -- this should be 400,
        # not 429, because it's a different bucket.
        r = await client.get(
            "/auth/oidc/callback?code=x&state=bad",
            headers={"cf-connecting-ip": "198.51.100.42"},
        )
        assert r.status_code == 400, r.text
