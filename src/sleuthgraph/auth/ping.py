"""Authed smoke endpoint: /auth/ping returns {"user": email} when authenticated."""

from fastapi import APIRouter, Depends

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User

router = APIRouter()


@router.get("/ping")
async def auth_ping(user: User = Depends(current_active_user)) -> dict:
    return {"user": user.email}
