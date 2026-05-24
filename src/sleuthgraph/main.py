"""FastAPI application factory.

Starlette/uvicorn imports `sleuthgraph.main:app`. Keep it minimal; mount
routers from this single file so startup/shutdown events are centralized.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from sleuthgraph import __version__
from sleuthgraph.auth.backend import auth_backend
from sleuthgraph.auth.deps import fastapi_users
from sleuthgraph.auth.forgot_password import (
    rate_limit_exceeded_handler,
)
from sleuthgraph.auth.forgot_password import (
    router as forgot_password_router,
)
from sleuthgraph.auth.oidc import router as oidc_router
from sleuthgraph.auth.ping import router as auth_ping_router
from sleuthgraph.auth.rate_limit import ip_limiter
from sleuthgraph.auth.schemas import UserCreate, UserRead, UserUpdate
from sleuthgraph.cases.router import router as cases_router
from sleuthgraph.config import get_settings
from sleuthgraph.credentials.router import router as credentials_router
from sleuthgraph.db import get_engine
from sleuthgraph.entities.router import router as entities_router
from sleuthgraph.evidence.export import router as evidence_export_router
from sleuthgraph.evidence.router import router as evidence_router
from sleuthgraph.graph.router import router as graph_router
from sleuthgraph.plugins.router import case_router as plugin_case_router
from sleuthgraph.plugins.router import registry_router as plugin_registry_router
from sleuthgraph.relationships.router import router as relationships_router
from sleuthgraph.routers import health


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()

    # Defense in depth: verify the import-time cookie transport snapshot
    # matches current settings. Divergence means env loaded late or a test
    # mutated the singleton.
    from sleuthgraph.auth.backend import cookie_transport

    settings = get_settings()
    if cookie_transport.cookie_secure != settings.auth_cookie_secure:
        raise RuntimeError(
            f"Cookie transport / settings drift: transport.cookie_secure="
            f"{cookie_transport.cookie_secure} but settings.auth_cookie_secure="
            f"{settings.auth_cookie_secure}. This usually means the env was "
            "loaded after sleuthgraph.auth.backend was imported, or a test "
            "fixture failed to restore state."
        )

    # Production guard: refuse to run plaintext cookies in non-debug mode.
    if not settings.debug and not settings.auth_cookie_secure:
        raise RuntimeError(
            "Refusing to start: AUTH_COOKIE_SECURE=false in non-debug mode. "
            "Set AUTH_COOKIE_SECURE=true behind HTTPS."
        )

    from sleuthgraph.auth.bootstrap import bootstrap_admin

    await bootstrap_admin()
    yield
    # Release the shared arq Redis pool before shutting down the DB engine
    # so outstanding enqueue operations drain cleanly.
    from sleuthgraph.queue.enqueue import close_pool

    await close_pool()
    await engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    docs_kwargs: dict = (
        {}
        if settings.expose_api_docs
        else {"docs_url": None, "redoc_url": None, "openapi_url": None}
    )
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        **docs_kwargs,
    )

    # Wire slowapi: the limiter instance + a handler that returns a
    # generic 429 body (no email-existence hint).
    app.state.limiter = ip_limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

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
    if settings.auth_allow_password_reset:
        # Our rate-limited /auth/forgot-password must mount BEFORE the
        # fastapi-users reset router so FastAPI's path matcher picks it
        # first; the underlying /auth/reset-password handler still comes
        # from fastapi-users below.
        app.include_router(forgot_password_router, prefix="/auth", tags=["auth"])
        app.include_router(
            fastapi_users.get_reset_password_router(),
            prefix="/auth",
            tags=["auth"],
        )
    if settings.auth_allow_email_verify:
        app.include_router(
            fastapi_users.get_verify_router(UserRead),
            prefix="/auth",
            tags=["auth"],
        )
    app.include_router(
        fastapi_users.get_users_router(UserRead, UserUpdate),
        prefix="/users",
        tags=["users"],
    )
    app.include_router(oidc_router, prefix="/auth", tags=["auth"])
    app.include_router(auth_ping_router, prefix="/auth", tags=["auth"])

    app.include_router(credentials_router)
    app.include_router(cases_router)
    app.include_router(entities_router)
    # evidence_export_router MUST be included BEFORE evidence_router so that
    # /cases/{case_id}/evidence/export is not swallowed by /{ev_id}.
    app.include_router(evidence_export_router)
    app.include_router(relationships_router)
    app.include_router(graph_router)
    app.include_router(plugin_registry_router)
    app.include_router(plugin_case_router)
    app.include_router(evidence_router)

    return app


app = create_app()
