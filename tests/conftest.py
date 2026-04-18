"""Shared pytest fixtures."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from sleuthgraph.db import Base, get_engine, get_session, get_session_factory


@pytest.fixture(autouse=True)
def _set_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    get_engine.cache_clear()
    get_session_factory.cache_clear()


@pytest.fixture
async def test_engine():
    """Shared in-memory sqlite engine using StaticPool so sessions share state."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        # Ensure auth models are imported so their tables register on metadata
        from sleuthgraph.auth import models as _auth_models  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def client(test_engine):
    """FastAPI test client wired to a shared in-memory DB."""
    from sleuthgraph.auth.backend import cookie_transport
    from sleuthgraph.main import app

    original_secure = cookie_transport.cookie_secure
    # Disable Secure flag so httpx over http://test sends cookies back.
    cookie_transport.cookie_secure = False

    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_session():
        async with TestSession() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()
        cookie_transport.cookie_secure = original_secure


@pytest.fixture
async def signup_client(monkeypatch, test_engine):
    """Variant of ``client`` that has AUTH_ALLOW_SIGNUP=true when the app is constructed."""
    monkeypatch.setenv("AUTH_ALLOW_SIGNUP", "true")

    # Force a fresh app so create_app() picks up the env change
    from importlib import reload
    import sleuthgraph.main as main_module
    reload(main_module)
    app = main_module.app

    # Disable Secure flag on the cookie transport so httpx over http://test
    # actually sends the session cookie back on subsequent requests.
    from sleuthgraph.auth.backend import cookie_transport
    original_secure = cookie_transport.cookie_secure
    cookie_transport.cookie_secure = False

    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_session():
        async with TestSession() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()
        # Restore the original value so other tests are not affected
        cookie_transport.cookie_secure = original_secure


@pytest.fixture
def enable_signup(monkeypatch):
    """Set AUTH_ALLOW_SIGNUP=true BEFORE app import so the register router mounts.

    Use together with ``fresh_app`` — this fixture only flips the env.
    """
    monkeypatch.setenv("AUTH_ALLOW_SIGNUP", "true")
