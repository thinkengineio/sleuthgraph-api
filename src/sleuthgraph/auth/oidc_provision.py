"""Resolve an OIDC identity to a local User row.

Policy:
    1. sub match  → return user
    2. email match, no sub on row → link (set oidc_sub) ONLY IF
       email_verified=True; also invalidate the local password so a
       previously-squatted account cannot be used to log in by password
       after SSO linking (H-2).
    3. email match, sub set but differs → conflict (operator must resolve).
    4. no match, signup disabled → not linked.
    5. no match, signup enabled → provision ONLY IF email_verified=True.

Rationale for the email_verified gate (C-2): without it, an attacker
who can cause their IdP to assert any email they want (without proof
of ownership) would get automatic linkage to any local account
sharing that email string.
"""

from __future__ import annotations

import secrets
import uuid

from fastapi_users.password import PasswordHelper
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.models import User


class OidcAccountNotLinked(Exception):
    """IdP identity does not match any local account, or linkage refused.

    Refusal reasons: ``missing_sub``, ``missing_email``,
    ``no_matching_account``, ``unverified_email``.
    """


class OidcAccountConflict(Exception):
    """Email already belongs to a different OIDC subject — manual resolution required."""


_password_helper = PasswordHelper()


async def _find_by_sub(session: AsyncSession, sub: str) -> User | None:
    result = await session.execute(select(User).where(User.oidc_sub == sub))
    return result.scalar_one_or_none()


async def _find_by_email_ci(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(func.lower(User.email) == email.lower()))
    return result.scalar_one_or_none()


async def resolve_oidc_user(
    session: AsyncSession,
    *,
    sub: str,
    email: str,
    email_verified: bool,
    allow_signup: bool,
) -> User:
    if not sub:
        raise OidcAccountNotLinked("missing_sub")
    if not email:
        raise OidcAccountNotLinked("missing_email")

    # 1. sub match — user has logged in via SSO before; trust the binding.
    existing = await _find_by_sub(session, sub)
    if existing is not None:
        return existing

    # 2/3. email match
    by_email = await _find_by_email_ci(session, email)
    if by_email is not None:
        if by_email.oidc_sub is None:
            if not email_verified:
                raise OidcAccountNotLinked("unverified_email")
            by_email.oidc_sub = sub
            by_email.is_verified = True
            # H-2: invalidate the local password so whatever value the
            # (possibly squatting) previous password-user set cannot be
            # used to sign in after the account is now SSO-linked. The
            # legitimate owner can still recover via email-based reset.
            by_email.hashed_password = _password_helper.hash(secrets.token_urlsafe(32))
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
    if not email_verified:
        raise OidcAccountNotLinked("unverified_email")

    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=_password_helper.hash(secrets.token_urlsafe(32)),
        is_active=True,
        is_superuser=False,
        is_verified=True,
        oidc_sub=sub,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user
