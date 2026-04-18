"""Admin bootstrap: create a superuser from env on startup (idempotent)."""

import logging

from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.manager import UserManager
from sleuthgraph.auth.models import User
from sleuthgraph.auth.schemas import UserCreate
from sleuthgraph.config import get_settings
from sleuthgraph.db import get_session_factory

log = logging.getLogger(__name__)


async def bootstrap_admin(session: AsyncSession | None = None) -> None:
    """Create admin superuser from AUTH_ADMIN_EMAIL / AUTH_ADMIN_PASSWORD if unset.

    Idempotent: if the email already exists, logs a warning and returns.
    If env vars are missing, logs at INFO and returns (the common dev case).
    """
    settings = get_settings()
    if not settings.auth_admin_email or not settings.auth_admin_password:
        log.info("Admin bootstrap skipped: AUTH_ADMIN_EMAIL / AUTH_ADMIN_PASSWORD not set")
        return

    # If caller didn't pass a session, open one from the factory
    own_session = session is None
    if own_session:
        SessionLocal = get_session_factory()
        session = SessionLocal()

    try:
        existing = await session.execute(
            select(User).where(User.email == settings.auth_admin_email)
        )
        if existing.scalar_one_or_none() is not None:
            log.warning(
                "Admin user %s already exists; not overwriting password",
                settings.auth_admin_email,
            )
            return

        user_db = SQLAlchemyUserDatabase(session, User)
        manager = UserManager(user_db)
        await manager.create(
            UserCreate(
                email=settings.auth_admin_email,
                password=settings.auth_admin_password,
                is_superuser=True,
                is_active=True,
                is_verified=True,
            ),
            safe=False,
        )
        await session.commit()
        log.info("Bootstrapped admin user %s", settings.auth_admin_email)
    finally:
        if own_session:
            await session.close()
