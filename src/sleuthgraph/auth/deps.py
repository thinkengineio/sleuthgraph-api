"""FastAPI-Users wiring: dependencies and the FastAPIUsers instance.

Exposes:
  - ``fastapi_users``  — the configured FastAPIUsers[User, UUID] instance
  - ``current_active_user`` / ``current_superuser`` — route dependencies
  - ``get_user_db`` / ``get_user_manager`` — needed only for advanced wiring
"""

import uuid
from collections.abc import AsyncGenerator

from fastapi import Depends
from fastapi_users import FastAPIUsers
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.backend import auth_backend
from sleuthgraph.auth.manager import UserManager
from sleuthgraph.auth.models import User
from sleuthgraph.db import get_session


async def get_user_db(
    session: AsyncSession = Depends(get_session),
) -> AsyncGenerator[SQLAlchemyUserDatabase, None]:
    yield SQLAlchemyUserDatabase(session, User)


async def get_user_manager(
    user_db: SQLAlchemyUserDatabase = Depends(get_user_db),
) -> AsyncGenerator[UserManager, None]:
    yield UserManager(user_db)


fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

current_active_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)
