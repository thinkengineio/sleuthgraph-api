"""Rate-limited ``/auth/login`` route.

fastapi-users ships its own login handler in ``get_auth_router()``; this
module mounts a replacement that is behaviour-equivalent but guarded by
two limits:

* per-source-IP -- bounds password spraying (one IP, many usernames);
* per-target-username -- bounds credential stuffing (many IPs, one
  username) which IP-only limits don't catch.

The username-keyed limit fires BEFORE ``user_manager.authenticate``, so
the rate-limit channel can't be turned into a timing oracle on user
existence: the response is the same generic 429 whether the username
maps to a real user or not.

We deliberately do NOT short-circuit before the IP decorator -- the
slowapi decorator runs first and returns 429 at the framework level,
which is consistent with /auth/forgot-password.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users.authentication.strategy.db import DatabaseStrategy
from fastapi_users.router.common import ErrorCode

from sleuthgraph.auth.backend import auth_backend, get_database_strategy
from sleuthgraph.auth.deps import get_user_manager
from sleuthgraph.auth.manager import UserManager
from sleuthgraph.auth.rate_limit import ip_limiter, username_rate_limit_hit
from sleuthgraph.config import get_settings

router = APIRouter()


@router.post(
    "/login",
    name="auth:cookie-db.login.rate_limited",
)
@ip_limiter.limit(lambda: get_settings().auth_login_ip_rate)
async def login(
    request: Request,
    credentials: OAuth2PasswordRequestForm = Depends(),
    user_manager: UserManager = Depends(get_user_manager),
    strategy: DatabaseStrategy = Depends(get_database_strategy),
):
    """Drop-in replacement for the fastapi-users login handler.

    Body-keyed username limit is checked BEFORE the DB lookup so the
    rate-limit decision doesn't depend on whether the user exists.
    """
    if not username_rate_limit_hit(credentials.username):
        # Same 429 the slowapi handler emits. We don't leak whether the
        # username exists -- the message is identical for any input.
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

    user = await user_manager.authenticate(credentials)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorCode.LOGIN_BAD_CREDENTIALS,
        )
    response = await auth_backend.login(strategy, user)
    await user_manager.on_after_login(user, request, response)
    return response
