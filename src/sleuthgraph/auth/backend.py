"""Auth backend: cookie transport + JWT strategy.

Signs session JWTs with a purpose-specific subkey derived from the master
``SECRET_KEY`` via HKDF. Swap JWTStrategy for ``DatabaseStrategy`` later if
session revocation is required.
"""

from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)

from sleuthgraph.config import get_settings
from sleuthgraph.crypto import jwt_signing_key

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
    return JWTStrategy(secret=jwt_signing_key(), lifetime_seconds=s.auth_session_lifetime_seconds)


auth_backend = AuthenticationBackend(
    name="cookie-jwt",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)
