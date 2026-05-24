"""EXPOSE_API_DOCS env-toggle for /docs, /redoc, /openapi.json (issue #71).

The module-level ``sleuthgraph.main.app`` is built once at import time, so
these tests construct a fresh app via ``create_app()`` after flipping the
env var -- otherwise the cached app is returned and the assertions don't
exercise the new branch.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from sleuthgraph.config import get_settings


@pytest.mark.asyncio
async def test_docs_exposed_by_default():
    """Default behaviour preserves the OSS / dev experience."""
    get_settings.cache_clear()
    from sleuthgraph.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for path in ("/docs", "/redoc", "/openapi.json"):
            r = await ac.get(path)
            assert r.status_code == 200, f"{path} returned {r.status_code}"


@pytest.mark.asyncio
async def test_docs_hidden_when_disabled(monkeypatch):
    """EXPOSE_API_DOCS=false makes all three doc endpoints 404."""
    monkeypatch.setenv("EXPOSE_API_DOCS", "false")
    get_settings.cache_clear()

    from sleuthgraph.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for path in ("/docs", "/redoc", "/openapi.json"):
            r = await ac.get(path)
            assert r.status_code == 404, f"{path} returned {r.status_code}"
