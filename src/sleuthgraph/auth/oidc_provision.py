"""Resolve an OIDC identity to a local User row.

Policy:
    1. sub match  → return user
    2. email match, no sub on row → link (set oidc_sub), return user
    3. email match, sub set but differs → conflict (operator must resolve)
    4. no match, signup disabled → not linked
    5. no match, signup enabled → provision with random password, verified=True
"""

from __future__ import annotations

import secrets
import uuid

from fastapi_users.password import PasswordHelper
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.models import User


class OidcAccountNotLinked(Exception):
    """IdP identity does not match any local account and signup is disabled."""


class OidcAccountConflict(Exception):
    """Email already belongs to a different OIDC subject — manual resolution required."""


_password_helper = PasswordHelper()


async def _find_by_sub(session: AsyncSession, sub: str) -> User | None:
    result = await session.execute(select(User).where(User.oidc_sub == sub))
    return result.scalar_one_or_none()


async def _find_by_email_ci(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(
        select(User).where(func.lower(User.email) == email.lower())
    )
    return result.scalar_one_or_none()


async def resolve_oidc_user(
    session: AsyncSession,
    *,
    sub: str,
    email: str,
    name: str | None,
    allow_signup: bool,
) -> User:
    if not sub:
        raise OidcAccountNotLinked("missing_sub")
    if not email:
        raise OidcAccountNotLinked("missing_email")

    # 1. sub match
    existing = await _find_by_sub(session, sub)
    if existing is not None:
        return existing

    # 2/3. email match
    by_email = await _find_by_email_ci(session, email)
    if by_email is not None:
        if by_email.oidc_sub is None:
            by_email.oidc_sub = sub
            by_email.is_verified = True
            if name and not by_email.name:
                by_email.name = name
            await session.commit()
            await session.refresh(by_email)
            return by_email
        if by_email.oidc_sub != sub:
            raise OidcAccountConflict("email_sub_mismatch")
        # Defensive — by_email.oidc_sub == sub but step 1 didn't catch it.
        return by_email

    # 4/5. no match
    if not allow_signup:
        raise OidcAccountNotLinked("no_matching_account")

    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=_password_helper.hash(secrets.token_urlsafe(32)),
        is_active=True,
        is_superuser=False,
        is_verified=True,
        name=name,
        oidc_sub=sub,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user
