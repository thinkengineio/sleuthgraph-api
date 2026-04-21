"""OIDC routes: status, config, login, callback.

Login/callback wire a standard Authorization-Code + PKCE flow and exchange
an IdP identity for our existing cookie session. See docs/auth-oidc.md.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.backend import auth_backend, get_jwt_strategy
from sleuthgraph.auth.oidc_client import get_oidc_client
from sleuthgraph.auth.oidc_provision import (
    OidcAccountConflict,
    OidcAccountNotLinked,
    resolve_oidc_user,
)
from sleuthgraph.auth.oidc_state import StateError, decode_state, encode_state
from sleuthgraph.config import get_settings
from sleuthgraph.db import get_session

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/oidc-status")
async def oidc_status() -> dict:
    s = get_settings()
    enabled = bool(s.oidc_issuer and s.oidc_client_id and s.oidc_client_secret)
    if not enabled:
        return {"enabled": False}
    return {"enabled": True, "issuer": s.oidc_issuer}


@router.get("/config")
async def auth_config() -> dict:
    s = get_settings()
    return {
        "signup_enabled": s.auth_allow_signup,
        "password_reset_enabled": s.auth_allow_password_reset,
        "email_verify_enabled": s.auth_allow_email_verify,
        "oidc_enabled": bool(s.oidc_issuer and s.oidc_client_id and s.oidc_client_secret),
    }


def _pkce_pair() -> tuple[str, str]:
    # 64 bytes → 86-ish url-safe chars.  Spec allows 43-128.
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _redirect_uri(request: Request) -> str:
    s = get_settings()
    if s.oidc_redirect_url:
        return s.oidc_redirect_url
    return str(request.url_for("oidc_callback"))


@router.get("/oidc/login")
async def oidc_login(
    request: Request,
    next: str = Query(default="/"),
) -> Response:
    client = get_oidc_client()
    if client is None:
        raise HTTPException(status_code=404, detail="oidc_not_configured")
    s = get_settings()

    verifier, challenge = _pkce_pair()
    state = encode_state(code_verifier=verifier, next_path=next)
    auth_url = await client.get_authorization_url(
        redirect_uri=_redirect_uri(request),
        state=state,
        scope=s.oidc_scopes,
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/oidc/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    session: AsyncSession = Depends(get_session),
) -> Response:
    client = get_oidc_client()
    if client is None:
        raise HTTPException(status_code=404, detail="oidc_not_configured")

    try:
        state_payload = decode_state(state)
    except StateError:
        raise HTTPException(status_code=400, detail="invalid_state")

    try:
        token = await client.get_access_token(
            code=code,
            redirect_uri=_redirect_uri(request),
            code_verifier=state_payload.code_verifier,
        )
    except Exception:
        logger.exception("OIDC token exchange failed")
        raise HTTPException(status_code=400, detail="oidc_exchange_failed")

    try:
        sub, email = await client.get_id_email(token["access_token"])
    except Exception:
        logger.exception("OIDC userinfo failed")
        raise HTTPException(status_code=400, detail="oidc_userinfo_failed")

    s = get_settings()
    try:
        user = await resolve_oidc_user(
            session,
            sub=sub,
            email=email,
            name=None,  # httpx-oauth's get_id_email doesn't return name; leave null
            allow_signup=s.auth_allow_signup,
        )
    except OidcAccountNotLinked:
        raise HTTPException(status_code=403, detail="oidc_account_not_linked")
    except OidcAccountConflict:
        raise HTTPException(status_code=409, detail="oidc_account_conflict")

    # Issue session cookie via existing JWT strategy + cookie transport.
    strategy = get_jwt_strategy()
    session_token = await strategy.write_token(user)

    response = RedirectResponse(url=state_payload.next_path, status_code=302)
    # CookieTransport stores cookie settings as instance attributes.
    # We attach the cookie directly since we're doing a redirect instead of
    # going through transport.get_login_response() which returns a Response body.
    response.set_cookie(
        key=auth_backend.transport.cookie_name,
        value=session_token,
        max_age=auth_backend.transport.cookie_max_age,
        secure=auth_backend.transport.cookie_secure,
        httponly=auth_backend.transport.cookie_httponly,
        samesite=auth_backend.transport.cookie_samesite,
    )
    return response
