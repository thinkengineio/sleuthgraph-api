"""Rate-limited ``/auth/register`` route.

fastapi-users ships its own register handler in ``get_register_router()``;
this module mounts a replacement guarded by a per-source-IP limit so that
spam-registration / HIBP-probe loops can be capped cheaply.

The router is only mounted by ``main.py`` when ``AUTH_ALLOW_SIGNUP=true``.
When signup is disabled there is no point burning a rate-limit slot --
the endpoint just isn't there.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi_users import exceptions, schemas
from fastapi_users.router.common import ErrorCode

from sleuthgraph.auth.deps import get_user_manager
from sleuthgraph.auth.manager import UserManager
from sleuthgraph.auth.rate_limit import ip_limiter
from sleuthgraph.auth.schemas import UserCreate, UserRead
from sleuthgraph.config import get_settings

router = APIRouter()


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    name="register:register.rate_limited",
)
@ip_limiter.limit(lambda: get_settings().auth_register_ip_rate)
async def register(
    request: Request,
    user_create: UserCreate,
    user_manager: UserManager = Depends(get_user_manager),
):
    """Drop-in replacement for the fastapi-users register handler."""
    try:
        created_user = await user_manager.create(user_create, safe=True, request=request)
    except exceptions.UserAlreadyExists as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorCode.REGISTER_USER_ALREADY_EXISTS,
        ) from exc
    except exceptions.InvalidPasswordException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": ErrorCode.REGISTER_INVALID_PASSWORD,
                "reason": exc.reason,
            },
        ) from exc

    return schemas.model_validate(UserRead, created_user)
