"""OIDC status endpoint (config stub).

Phase 2 scope: report whether OIDC is wired without exposing secrets. Full
login/callback flow lands in Phase 2.5.
"""

from fastapi import APIRouter

from sleuthgraph.config import get_settings

router = APIRouter()


@router.get("/oidc-status")
async def oidc_status() -> dict:
    s = get_settings()
    enabled = bool(s.oidc_issuer and s.oidc_client_id and s.oidc_client_secret)
    if not enabled:
        return {"enabled": False}
    return {"enabled": True, "issuer": s.oidc_issuer}
