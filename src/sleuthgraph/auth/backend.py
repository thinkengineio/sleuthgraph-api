"""Auth backend: cookie transport + JWT strategy.

Signs session JWTs with the shared ``secret_key``. Swap JWTStrategy for
``DatabaseStrategy`` later if session revocation is required.
"""

from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)

from sleuthgraph.config import get_settings

_settings = get_settings()

cookie_transport = CookieTransport(
    cookie_name=_settings.auth_cookie_name,
    cookie_max_age=_settings.auth_session_lifetime_seconds,
    cookie_secure=_settings.auth_cookie_secure,
    cookie_httponly=True,
    cookie_samesite="lax",
)


def get_jwt_strategy() -> JWTStrategy:
    s = get_settings()
    return JWTStrategy(secret=s.secret_key, lifetime_seconds=s.auth_session_lifetime_seconds)


auth_backend = AuthenticationBackend(
    name="cookie-jwt",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)
