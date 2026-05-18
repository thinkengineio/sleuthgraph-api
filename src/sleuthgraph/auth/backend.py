"""Auth backend: cookie transport + database-backed session strategy.

Uses ``DatabaseStrategy`` with an ``accesstoken`` table so that sessions
can be revoked (e.g. on logout or password change) without waiting for
JWT expiry.
"""

from fastapi import Depends
from fastapi_users.authentication import AuthenticationBackend, CookieTransport
from fastapi_users.authentication.strategy.db import DatabaseStrategy
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.access_token import AccessToken
from sleuthgraph.config import get_settings
from sleuthgraph.db import get_session

_settings = get_settings()

cookie_transport = CookieTransport(
    cookie_name=_settings.auth_cookie_name,
    cookie_max_age=_settings.auth_session_lifetime_seconds,
    cookie_secure=_settings.auth_cookie_secure,
    cookie_httponly=True,
    cookie_samesite="lax",
)


async def get_access_token_db(
    session: AsyncSession = Depends(get_session),
):
    yield SQLAlchemyAccessTokenDatabase(session, AccessToken)


def get_database_strategy(
    access_token_db: SQLAlchemyAccessTokenDatabase = Depends(get_access_token_db),
) -> DatabaseStrategy:
    s = get_settings()
    return DatabaseStrategy(access_token_db, lifetime_seconds=s.auth_session_lifetime_seconds)


auth_backend = AuthenticationBackend(
    name="cookie-db",
    transport=cookie_transport,
    get_strategy=get_database_strategy,
)
