"""Tests for OIDC user resolution policy."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.auth.oidc_provision import (
    OidcAccountConflict,
    OidcAccountNotLinked,
    resolve_oidc_user,
)


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

    got = await resolve_oidc_user(
        db_session,
        sub="sub-1",
        email="x@example.com",
        email_verified=True,
        allow_signup=False,
    )
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

    got = await resolve_oidc_user(
        db_session,
        sub="new-sub",
        email="LINK@example.com",
        email_verified=True,
        allow_signup=False,
    )
    assert got.id == u.id
    assert got.oidc_sub == "new-sub"
    assert got.is_verified is True  # IdP vouches
    # H-2: pre-link password value is invalidated.
    assert got.hashed_password != "bcrypt$xxx"
    assert got.hashed_password  # non-empty (randomized replacement)


@pytest.mark.asyncio
async def test_link_by_email_rejects_unverified(db_session: AsyncSession):
    u = User(
        id=uuid.uuid4(),
        email="unverified@example.com",
        hashed_password="bcrypt$original",
        is_active=True,
        is_superuser=False,
        is_verified=False,
        oidc_sub=None,
    )
    db_session.add(u)
    await db_session.commit()
    with pytest.raises(OidcAccountNotLinked) as e:
        await resolve_oidc_user(
            db_session,
            sub="new-sub",
            email="unverified@example.com",
            email_verified=False,
            allow_signup=False,
        )
    assert "unverified_email" in str(e.value)
    # Password must NOT be rewritten on a refused link.
    await db_session.refresh(u)
    assert u.hashed_password == "bcrypt$original"
    assert u.oidc_sub is None


@pytest.mark.asyncio
async def test_link_by_email_requires_verified(db_session: AsyncSession):
    """Same scenario but email_verified=True -> link succeeds."""
    u = User(
        id=uuid.uuid4(),
        email="needsverify@example.com",
        hashed_password="bcrypt$original",
        is_active=True,
        is_superuser=False,
        is_verified=False,
        oidc_sub=None,
    )
    db_session.add(u)
    await db_session.commit()
    got = await resolve_oidc_user(
        db_session,
        sub="verify-sub",
        email="needsverify@example.com",
        email_verified=True,
        allow_signup=False,
    )
    assert got.oidc_sub == "verify-sub"


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
        await resolve_oidc_user(
            db_session,
            sub="different-sub",
            email="conflict@example.com",
            email_verified=True,
            allow_signup=True,
        )


@pytest.mark.asyncio
async def test_no_match_signup_disabled_raises(db_session: AsyncSession):
    with pytest.raises(OidcAccountNotLinked):
        await resolve_oidc_user(
            db_session,
            sub="stranger",
            email="stranger@example.com",
            email_verified=True,
            allow_signup=False,
        )


@pytest.mark.asyncio
async def test_no_match_provisions_when_signup_enabled(db_session: AsyncSession):
    got = await resolve_oidc_user(
        db_session,
        sub="new",
        email="new@example.com",
        email_verified=True,
        allow_signup=True,
    )
    assert got.email == "new@example.com"
    assert got.oidc_sub == "new"
    assert got.is_verified is True
    assert got.hashed_password and got.hashed_password != "!"


@pytest.mark.asyncio
async def test_provision_rejects_unverified(db_session: AsyncSession):
    with pytest.raises(OidcAccountNotLinked) as e:
        await resolve_oidc_user(
            db_session,
            sub="unv",
            email="unv@example.com",
            email_verified=False,
            allow_signup=True,
        )
    assert "unverified_email" in str(e.value)
