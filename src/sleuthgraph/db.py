"""Async SQLAlchemy engine + session factory.

Usage in endpoints:

    from fastapi import Depends
    from sleuthgraph.db import get_session

    @app.get("/things")
    async def list_things(session=Depends(get_session)):
        ...
"""

from collections.abc import AsyncIterator
from functools import cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from sleuthgraph.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


@cache
def get_engine() -> AsyncEngine:
    """One engine per process. `cache` makes this a singleton for the lifetime of the app."""
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_pre_ping=True,
        future=True,
    )


@cache
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields a session, rolls back on exception, always closes."""
    SessionLocal = get_session_factory()
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
