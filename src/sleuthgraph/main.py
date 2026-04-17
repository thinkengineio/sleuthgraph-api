"""FastAPI application factory.

Starlette/uvicorn imports `sleuthgraph.main:app`. Keep it minimal; mount
routers from this single file so startup/shutdown events are centralized.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sleuthgraph import __version__
from sleuthgraph.config import get_settings
from sleuthgraph.db import get_engine
from sleuthgraph.routers import health


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    engine = get_engine()
    yield
    # Shutdown
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

    return app


app = create_app()
