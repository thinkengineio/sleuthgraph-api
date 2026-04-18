"""Shared pytest fixtures."""

import os

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
        # Ensure all models are imported so their tables register on metadata
        # before create_all runs. Order matters: auth → cases → entities →
        # relationships (FK chain).
        from sleuthgraph.auth import models as _auth_models  # noqa: F401
        from sleuthgraph.cases import models as _cases_models  # noqa: F401
        from sleuthgraph.entities import models as _ent_models  # noqa: F401
        from sleuthgraph.relationships import models as _rel_models  # noqa: F401
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


@pytest.fixture
async def postgres_age_session():
    """Postgres session for AGE-requiring tests. Skips if no live db.

    Looks for SLEUTHGRAPH_TEST_POSTGRES_URL first, then falls back to the
    deploy-compose URL for convenience.
    """
    url = os.environ.get(
        "SLEUTHGRAPH_TEST_POSTGRES_URL",
        "postgresql+asyncpg://sleuthgraph:changeme_local_only@localhost:5432/sleuthgraph",
    )
    engine = create_async_engine(url)
    # Ensure connection works; skip otherwise
    try:
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception as e:
        await engine.dispose()
        pytest.skip(f"Postgres+AGE not available at {url}: {e}")

    # Ensure migrations applied — if not, skip (don't run alembic here)
    async with engine.connect() as conn:
        from sqlalchemy import text as _t
        try:
            await conn.execute(_t("SELECT 1 FROM entities LIMIT 1"))
        except Exception as e:
            await engine.dispose()
            pytest.skip(f"entities table missing — run 'alembic upgrade head': {e}")

    TestSession = async_sessionmaker(engine, expire_on_commit=False)
    async with TestSession() as session:
        yield session
    await engine.dispose()
