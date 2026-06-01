"""Rate-limited ``/auth/request-verify-token`` route.

fastapi-users ships its own request-verify-token handler in
``get_verify_router()``; this module mounts a replacement guarded by two
limits:

* per-source-IP -- bounds DoS volume and scripted enumeration sweeps;
* per-target-email -- protects an individual user from being spammed
  with verification emails.

Both limits return 429 with the same generic body. The endpoint also
keeps the no-enumeration invariant: fastapi-users already swallows
``UserNotExists``/``UserInactive``/``UserAlreadyVerified`` silently
inside ``request_verify``, so the rate-limit channel must not be turned
into an existence oracle either. The email-bucket limit fires BEFORE the
DB lookup so the 429 response is identical whether the address is
registered or not.

The companion ``/auth/verify`` route is left unchanged in the
fastapi-users router; it already requires a valid token so it isn't a
useful email-spam DoS surface.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi_users import exceptions
from pydantic import EmailStr

from sleuthgraph.auth.deps import get_user_manager
from sleuthgraph.auth.manager import UserManager
from sleuthgraph.auth.rate_limit import ip_limiter, verify_email_rate_limit_hit
from sleuthgraph.config import get_settings

router = APIRouter()


@router.post(
    "/request-verify-token",
    status_code=status.HTTP_202_ACCEPTED,
    name="verify:request-token.rate_limited",
)
@ip_limiter.limit(lambda: get_settings().auth_verify_ip_rate)
async def request_verify_token(
    request: Request,
    email: EmailStr = Body(..., embed=True),
    user_manager: UserManager = Depends(get_user_manager),
) -> None:
    """Drop-in replacement for the fastapi-users request-verify-token handler.

    Body-keyed email limit fires BEFORE the DB lookup so the rate-limit
    decision doesn't depend on whether the user exists.
    """
    if not verify_email_rate_limit_hit(email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

    try:
        user = await user_manager.get_by_email(email)
        await user_manager.request_verify(user, request)
    except (
        exceptions.UserNotExists,
        exceptions.UserInactive,
        exceptions.UserAlreadyVerified,
    ):
        # Match the fastapi-users behaviour: swallow these silently so
        # the 202 response doesn't leak existence/state of the address.
        pass
