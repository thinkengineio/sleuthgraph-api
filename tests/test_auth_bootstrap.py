"""Tests for admin bootstrap: env-driven, idempotent."""

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.bootstrap import bootstrap_admin
from sleuthgraph.auth.models import User


@pytest.fixture
async def db_session(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as session:
        yield session


@pytest.mark.asyncio
async def test_bootstrap_skipped_when_env_missing(db_session, monkeypatch):
    monkeypatch.delenv("AUTH_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("AUTH_ADMIN_PASSWORD", raising=False)
    await bootstrap_admin(session=db_session)
    result = await db_session.execute(select(func.count()).select_from(User))
    assert result.scalar() == 0


@pytest.mark.asyncio
async def test_bootstrap_creates_admin(db_session, monkeypatch):
    monkeypatch.setenv("AUTH_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("AUTH_ADMIN_PASSWORD", "adminpass1234")

    await bootstrap_admin(session=db_session)

    result = await db_session.execute(
        select(User).where(User.email == "admin@example.com")
    )
    user = result.scalar_one()
    assert user.is_superuser is True
    assert user.is_active is True
    assert user.email == "admin@example.com"


@pytest.mark.asyncio
async def test_bootstrap_idempotent(db_session, monkeypatch):
    monkeypatch.setenv("AUTH_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("AUTH_ADMIN_PASSWORD", "adminpass1234")

    await bootstrap_admin(session=db_session)
    await bootstrap_admin(session=db_session)  # second call must not raise

    result = await db_session.execute(
        select(func.count())
        .select_from(User)
        .where(User.email == "admin@example.com")
    )
    assert result.scalar() == 1
