"""Health and readiness endpoints."""

import pytest


@pytest.mark.asyncio
async def test_health_returns_ok(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "sleuthgraph-api"}


@pytest.mark.asyncio
async def test_readiness_checks_db(client):
    resp = await client.get("/readiness")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["db"] == "ok"
