"""Tests for OIDC user resolution policy."""

import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sleuthgraph.auth.oidc_provision import (
    resolve_oidc_user,
    OidcAccountConflict,
    OidcAccountNotLinked,
)
from sleuthgraph.auth.models import User


@pytest.fixture
async def db_session(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as session:
        yield session


@pytest.mark.asyncio
async def test_existing_sub_match(db_session: AsyncSession):
    u = User(
        id=uuid.uuid4(),
        email="x@example.com",
        hashed_password="!",
        is_active=True,
        is_superuser=False,
        is_verified=True,
        oidc_sub="sub-1",
    )
    db_session.add(u)
    await db_session.commit()

    got = await resolve_oidc_user(db_session, sub="sub-1", email="x@example.com", name=None, allow_signup=False)
    assert got.id == u.id


@pytest.mark.asyncio
async def test_link_by_email(db_session: AsyncSession):
    u = User(
        id=uuid.uuid4(),
        email="link@example.com",
        hashed_password="bcrypt$xxx",
        is_active=True,
        is_superuser=False,
        is_verified=False,
        oidc_sub=None,
    )
    db_session.add(u)
    await db_session.commit()

    got = await resolve_oidc_user(db_session, sub="new-sub", email="LINK@example.com", name=None, allow_signup=False)
    assert got.id == u.id
    assert got.oidc_sub == "new-sub"
    assert got.is_verified is True  # IdP vouches


@pytest.mark.asyncio
async def test_email_match_but_sub_mismatch_raises(db_session: AsyncSession):
    u = User(
        id=uuid.uuid4(),
        email="conflict@example.com",
        hashed_password="!",
        is_active=True,
        is_superuser=False,
        is_verified=True,
        oidc_sub="existing-sub",
    )
    db_session.add(u)
    await db_session.commit()
    with pytest.raises(OidcAccountConflict):
        await resolve_oidc_user(db_session, sub="different-sub", email="conflict@example.com", name=None, allow_signup=True)


@pytest.mark.asyncio
async def test_no_match_signup_disabled_raises(db_session: AsyncSession):
    with pytest.raises(OidcAccountNotLinked):
        await resolve_oidc_user(db_session, sub="stranger", email="stranger@example.com", name="New", allow_signup=False)


@pytest.mark.asyncio
async def test_no_match_provisions_when_signup_enabled(db_session: AsyncSession):
    got = await resolve_oidc_user(db_session, sub="new", email="new@example.com", name="New", allow_signup=True)
    assert got.email == "new@example.com"
    assert got.oidc_sub == "new"
    assert got.is_verified is True
    assert got.hashed_password and got.hashed_password != "!"
