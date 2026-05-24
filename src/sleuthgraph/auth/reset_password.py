"""Rate-limited ``/auth/reset-password`` route.

fastapi-users ships its own reset-password handler in
``get_reset_password_router()``; this module mounts a replacement
guarded by two limits:

* per-source-IP -- bounds DoS / scripted-guessing volume;
* per-target-token -- bounds bulk token guessing even if the attacker
  rotates IPs. The token is the legitimate identifier for the reset
  attempt, so it's the natural second axis.

Both limits surface as the same generic 429 body. The token-key bucket
uses sha256(token) so the storage doesn't hold the raw token.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi_users import exceptions
from fastapi_users.router.common import ErrorCode

from sleuthgraph.auth.deps import get_user_manager
from sleuthgraph.auth.manager import UserManager
from sleuthgraph.auth.rate_limit import ip_limiter, reset_token_rate_limit_hit
from sleuthgraph.config import get_settings

router = APIRouter()


@router.post(
    "/reset-password",
    name="reset:reset_password.rate_limited",
)
@ip_limiter.limit(lambda: get_settings().auth_reset_password_ip_rate)
async def reset_password(
    request: Request,
    token: str = Body(...),
    password: str = Body(...),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Drop-in replacement for the fastapi-users reset-password handler.

    The token-keyed limit fires BEFORE ``user_manager.reset_password`` so
    bulk guessing burns rate-limit budget instead of doing real work.
    """
    if not reset_token_rate_limit_hit(token):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

    try:
        await user_manager.reset_password(token, password, request)
    except (
        exceptions.InvalidResetPasswordToken,
        exceptions.UserNotExists,
        exceptions.UserInactive,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorCode.RESET_PASSWORD_BAD_TOKEN,
        ) from exc
    except exceptions.InvalidPasswordException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": ErrorCode.RESET_PASSWORD_INVALID_PASSWORD,
                "reason": exc.reason,
            },
        ) from exc
