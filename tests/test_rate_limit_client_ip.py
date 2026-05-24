"""Unit tests for ``get_client_ip`` -- the key_func behind ip_limiter.

Covers issue #73: per-IP rate-limit key must use CF-Connecting-IP when
the API sits behind Cloudflare Tunnel, and MUST NOT trust proxy headers
when the API is reachable directly (``trust_cloudflare_edge=False``).

The unit-test stanzas import ``get_client_ip`` and ``get_settings``
inside the test functions rather than at module top -- the rate_limit
module evaluates ``Settings()`` at import time, which fails during
pytest collection if the autouse env fixture hasn't run yet.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def _request(
    headers: dict[str, str] | None = None, client_host: str | None = "10.0.0.1"
) -> MagicMock:
    """Build a minimal mock Request with the headers + client we care about."""
    req = MagicMock()
    req.headers = headers or {}
    if client_host is None:
        req.client = None
    else:
        req.client = MagicMock()
        req.client.host = client_host
    return req


def _get_client_ip_and_settings():
    """Lazy import after the autouse env fixture has populated DATABASE_URL etc."""
    from sleuthgraph.auth.rate_limit import get_client_ip
    from sleuthgraph.config import get_settings

    return get_client_ip, get_settings


def test_get_client_ip_honors_cf_connecting_ip_when_trust_flag_on(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(headers={"cf-connecting-ip": "203.0.113.7"})
    assert get_client_ip(req) == "203.0.113.7"


def test_get_client_ip_ignores_cf_connecting_ip_when_trust_flag_off(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "false")
    get_settings.cache_clear()
    req = _request(headers={"cf-connecting-ip": "203.0.113.7"}, client_host="10.0.0.1")
    # MUST NOT honor the (spoofable) header when not behind CF.
    assert get_client_ip(req) == "10.0.0.1"


def test_get_client_ip_ignores_xff_when_trust_flag_off(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "false")
    get_settings.cache_clear()
    req = _request(
        headers={"x-forwarded-for": "1.2.3.4, 5.6.7.8"},
        client_host="10.0.0.1",
    )
    assert get_client_ip(req) == "10.0.0.1"


def test_get_client_ip_falls_back_to_xff_rightmost_when_no_cf_header(monkeypatch):
    """When CF header is missing, use the **rightmost** XFF entry.

    Rationale: the rightmost is what the immediate upstream proxy
    observed; the leftmost is unauthenticated client-supplied data.
    """
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(headers={"x-forwarded-for": "1.2.3.4, 5.6.7.8"})
    assert get_client_ip(req) == "5.6.7.8"


def test_get_client_ip_xff_single_value(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(headers={"x-forwarded-for": "198.51.100.42"})
    assert get_client_ip(req) == "198.51.100.42"


def test_get_client_ip_falls_back_to_request_client_when_no_headers(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(headers={}, client_host="10.0.0.1")
    assert get_client_ip(req) == "10.0.0.1"


def test_get_client_ip_prefers_cf_over_xff(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(
        headers={
            "cf-connecting-ip": "203.0.113.7",
            "x-forwarded-for": "1.2.3.4, 5.6.7.8",
        },
    )
    # CF wins over XFF.
    assert get_client_ip(req) == "203.0.113.7"


def test_get_client_ip_returns_unknown_when_no_source(monkeypatch):
    """Conservative fallback: a single shared bucket if nothing else resolves."""
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(headers={}, client_host=None)
    assert get_client_ip(req) == "unknown"


def test_get_client_ip_strips_whitespace(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(headers={"cf-connecting-ip": "  203.0.113.7  "})
    assert get_client_ip(req) == "203.0.113.7"


def test_get_client_ip_xff_handles_extra_spaces(monkeypatch):
    get_client_ip, get_settings = _get_client_ip_and_settings()
    monkeypatch.setenv("TRUST_CLOUDFLARE_EDGE", "true")
    get_settings.cache_clear()
    req = _request(headers={"x-forwarded-for": " 1.2.3.4 ,  5.6.7.8 "})
    assert get_client_ip(req) == "5.6.7.8"


@pytest.mark.asyncio
async def test_forgot_password_limiter_keys_off_cf_header(client, monkeypatch):
    """End-to-end: with the CF header per request, each "IP" gets its own bucket.

    Before this fix all real users behind CF Tunnel shared one bucket
    because the limiter keyed off ``request.client.host`` (the tunnel
    upstream). With ``get_client_ip`` honoring ``CF-Connecting-IP`` each
    distinct value gets its own 5/minute budget.
    """

    # Three different "real" IPs each fire 5 requests = 15 total. If the
    # limiter were keyed off request.client.host (same for all) the 6th
    # would 429. With CF-Connecting-IP keying, all 15 are 202.
    for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        for i in range(5):
            r = await client.post(
                "/auth/forgot-password",
                json={"email": f"cf-{ip}-{i}@example.com"},
                headers={"cf-connecting-ip": ip},
            )
            assert r.status_code == 202, f"ip={ip} attempt={i} got {r.status_code}: {r.text}"

    # A 6th request from ip=203.0.113.1 should now trip its own bucket.
    r = await client.post(
        "/auth/forgot-password",
        json={"email": "cf-overflow@example.com"},
        headers={"cf-connecting-ip": "203.0.113.1"},
    )
    assert r.status_code == 429, r.text
