"""/auth/config endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_config_public(client: AsyncClient):
    r = await client.get("/auth/config")
    assert r.status_code == 200
    body = r.json()
    # Defaults
    assert body["signup_enabled"] is False
    assert body["password_reset_enabled"] is True
    assert body["email_verify_enabled"] is False
    assert body["oidc_enabled"] is False
