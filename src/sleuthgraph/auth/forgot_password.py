"""Rate-limited ``/auth/forgot-password`` route.

fastapi-users ships its own forgot-password handler in
``get_reset_password_router()``; this module mounts a replacement that is
behaviour-equivalent (still 202, still no user-enumeration) but guarded
by two limits:

* per-source-IP -- protects the host from a single attacker;
* per-target-email -- protects an individual user from being spammed
  with reset links.

Both limits return 429 with a generic body. We deliberately use the same
429 response whether the email exists or not, so the rate-limit channel
cannot be turned into an enumeration oracle.

The companion ``/auth/reset-password`` route is left in the fastapi-users
router unchanged; it already requires a valid token so it isn't a useful
DoS surface.
"""

from __future__ import annotations

from contextlib import suppress

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi_users import exceptions
from pydantic import EmailStr

from sleuthgraph.auth.deps import get_user_manager
from sleuthgraph.auth.manager import UserManager
from sleuthgraph.auth.rate_limit import email_rate_limit_hit, ip_limiter
from sleuthgraph.config import get_settings


def _rate_limited_response() -> JSONResponse:
    """Uniform 429 body used by both IP and email limits.

    Carefully avoids any signal about whether the target email exists --
    same body, same status, same headers regardless.
    """
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Too many requests. Please try again later."},
    )


router = APIRouter()


@router.post(
    "/forgot-password",
    status_code=status.HTTP_202_ACCEPTED,
    name="reset:forgot_password_rate_limited",
)
@ip_limiter.limit(lambda: get_settings().auth_forgot_password_ip_rate)
async def forgot_password(
    request: Request,
    email: EmailStr = Body(..., embed=True),
    user_manager: UserManager = Depends(get_user_manager),
) -> None:
    """Drop-in replacement for the fastapi-users forgot-password handler.

    The ``request`` parameter is required by slowapi for IP extraction and
    is forwarded to ``user_manager.forgot_password`` as fastapi-users
    expects.
    """
    if not email_rate_limit_hit(email):
        # Surface as the same 429 the IP limiter would emit. We raise
        # rather than return so the slowapi exception handler (registered
        # at app level) renders a consistent body.
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

    try:
        user = await user_manager.get_by_email(email)
    except exceptions.UserNotExists:
        return

    with suppress(exceptions.UserInactive):
        await user_manager.forgot_password(user, request)

    return


def rate_limit_exceeded_handler(_: Request, __: Exception) -> JSONResponse:
    """App-level handler for slowapi's ``RateLimitExceeded``.

    The signature uses ``Exception`` (rather than the narrower
    ``RateLimitExceeded``) so it matches the type Starlette's
    ``add_exception_handler`` declares. Returns the same generic body as
    the email-limit branch so neither channel leaks information about
    the target.
    """
    return _rate_limited_response()
