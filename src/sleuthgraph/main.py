"""FastAPI application factory.

Starlette/uvicorn imports `sleuthgraph.main:app`. Keep it minimal; mount
routers from this single file so startup/shutdown events are centralized.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sleuthgraph import __version__
from sleuthgraph.auth.backend import auth_backend
from sleuthgraph.auth.deps import fastapi_users
from sleuthgraph.auth.schemas import UserCreate, UserRead, UserUpdate
from sleuthgraph.config import get_settings
from sleuthgraph.db import get_engine
from sleuthgraph.routers import health


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()
    from sleuthgraph.auth.bootstrap import bootstrap_admin
    await bootstrap_admin()
    yield
    await engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)

    # Auth routers: login / logout always, register only when enabled
    app.include_router(
        fastapi_users.get_auth_router(auth_backend),
        prefix="/auth",
        tags=["auth"],
    )
    if settings.auth_allow_signup:
        app.include_router(
            fastapi_users.get_register_router(UserRead, UserCreate),
            prefix="/auth",
            tags=["auth"],
        )
    app.include_router(
        fastapi_users.get_users_router(UserRead, UserUpdate),
        prefix="/users",
        tags=["users"],
    )

    return app


app = create_app()
