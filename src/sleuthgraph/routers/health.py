"""Liveness and readiness endpoints.

/health    — cheap liveness check (no external deps)
/readiness — confirms the API can reach its critical dependencies (db for now)
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.db import get_session

router = APIRouter(tags=["meta"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def health():
    return {"status": "ok", "service": "sleuthgraph-api"}


@router.get("/readiness", status_code=status.HTTP_200_OK)
async def readiness(session: AsyncSession = Depends(get_session)):
    checks = {}
    try:
        result = await session.execute(text("SELECT 1"))
        checks["db"] = "ok" if result.scalar() == 1 else "unexpected"
    except Exception as e:
        checks["db"] = f"error: {type(e).__name__}"

    overall = "ready" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}
