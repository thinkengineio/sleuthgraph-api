"""OIDC routes: status, config, login, callback.

Login/callback wire a standard Authorization-Code + PKCE flow and exchange
an IdP identity for our existing cookie session. See docs/auth-oidc.md.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from httpx_oauth.exceptions import GetIdEmailError, HTTPXOAuthError
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.access_token import AccessToken
from sleuthgraph.auth.backend import cookie_transport
from fastapi_users.authentication.strategy.db import DatabaseStrategy
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from sleuthgraph.auth.oidc_client import get_oidc_client, is_oidc_configured
from sleuthgraph.auth.oidc_id_token import IdTokenError, validate_id_token
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
    if not is_oidc_configured(s):
        return {"enabled": False}
    return {"enabled": True, "issuer": s.oidc_issuer}


@router.get("/config")
async def auth_config() -> dict:
    s = get_settings()
    return {
        "signup_enabled": s.auth_allow_signup,
        "password_reset_enabled": s.auth_allow_password_reset,
        "email_verify_enabled": s.auth_allow_email_verify,
        "oidc_enabled": is_oidc_configured(s),
    }


def _pkce_pair() -> tuple[str, str]:
    # 64 random bytes -> ~86 url-safe chars. RFC 7636 allows 43-128.
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _redirect_uri(request: Request) -> str:
    # oidc_redirect_url is guaranteed non-None when oidc_issuer is set
    # (Settings model_validator enforces this). See H-3 in docs/auth-oidc.md.
    s = get_settings()
    assert s.oidc_redirect_url is not None, "OIDC_REDIRECT_URL must be set"
    return s.oidc_redirect_url


@router.get("/oidc/login")
async def oidc_login(
    request: Request,
    next: str = Query(default="/"),  # noqa: A002
) -> Response:
    client = get_oidc_client()
    if client is None:
        raise HTTPException(status_code=404, detail="oidc_not_configured")
    s = get_settings()

    verifier, challenge = _pkce_pair()
    # Per OIDC Core 1.0 §15.5.2, nonce is a per-request random value we also
    # assert against the id_token 'nonce' claim in the callback to prevent
    # replay of captured id_tokens across sessions.
    oidc_nonce = secrets.token_urlsafe(24)
    state = encode_state(code_verifier=verifier, next_path=next, oidc_nonce=oidc_nonce)
    auth_url = await client.get_authorization_url(
        redirect_uri=_redirect_uri(request),
        state=state,
        scope=s.oidc_scopes,
        code_challenge=challenge,
        code_challenge_method="S256",
        extras_params={"nonce": oidc_nonce},
    )
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/oidc/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> Response:
    client = get_oidc_client()
    if client is None:
        raise HTTPException(status_code=404, detail="oidc_not_configured")

    try:
        state_payload = decode_state(state)
    except StateError as exc:
        raise HTTPException(status_code=400, detail="invalid_state") from exc

    try:
        token = await client.get_access_token(
            code=code,
            redirect_uri=_redirect_uri(request),
            code_verifier=state_payload.code_verifier,
        )
    except (HTTPXOAuthError, httpx.HTTPError, KeyError) as exc:
        logger.exception("OIDC token exchange failed")
        raise HTTPException(status_code=400, detail="oidc_exchange_failed") from exc

    s = get_settings()

    # Extract + validate id_token per OIDC Core 1.0 §3.1.3.7. This replaces
    # the pre-C-1 behavior of trusting userinfo (get_id_email) alone.
    id_token = token.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="oidc_missing_id_token")

    assert s.oidc_issuer is not None  # guaranteed by is_oidc_configured gate
    assert s.oidc_client_id is not None
    try:
        claims = validate_id_token(
            id_token,
            issuer=s.oidc_issuer,
            client_id=s.oidc_client_id,
            nonce=state_payload.oidc_nonce,
        )
    except IdTokenError as exc:
        logger.warning("oidc id_token validation failed: %s", exc)
        raise HTTPException(status_code=400, detail="oidc_invalid_id_token") from exc

    sub = claims.get("sub")
    email = claims.get("email")
    # email_verified MUST come from the validated id_token. Some IdPs
    # (notably Auth0 with custom profile scopes) expose email only via
    # userinfo — fall back to userinfo for email STRING ONLY, but we
    # treat the userinfo-only email as unverified unless the id_token
    # asserted email_verified.
    email_verified = bool(claims.get("email_verified", False))

    if not sub:
        raise HTTPException(status_code=400, detail="oidc_missing_sub")

    if not email:
        # Last-resort fallback: some IdPs put email only in userinfo.
        try:
            _sub_ui, email_ui = await client.get_id_email(token["access_token"])
        except (GetIdEmailError, HTTPXOAuthError, httpx.HTTPError) as exc:
            logger.exception("OIDC userinfo failed")
            raise HTTPException(status_code=400, detail="oidc_userinfo_failed") from exc
        email = email_ui
        # email_verified stays whatever the id_token said (defaults False).

    if not email:
        raise HTTPException(status_code=400, detail="oidc_missing_email")

    try:
        user = await resolve_oidc_user(
            session,
            sub=sub,
            email=email,
            email_verified=email_verified,
            allow_signup=s.auth_allow_signup,
        )
    except OidcAccountNotLinked as exc:
        raise HTTPException(status_code=403, detail="oidc_account_not_linked") from exc
    except OidcAccountConflict as exc:
        raise HTTPException(status_code=409, detail="oidc_account_conflict") from exc

    # Issue session cookie via database strategy + cookie transport.
    access_token_db = SQLAlchemyAccessTokenDatabase(session, AccessToken)
    strategy = DatabaseStrategy(access_token_db, lifetime_seconds=s.auth_session_lifetime_seconds)
    session_token = await strategy.write_token(user)

    response = RedirectResponse(url=state_payload.next_path, status_code=302)
    # Use cookie_transport directly (typed as CookieTransport, not base Transport)
    # so mypy sees the concrete cookie_* attributes. We attach the cookie here
    # because transport.get_login_response() issues a 200 body response, not a
    # redirect.
    response.set_cookie(
        key=cookie_transport.cookie_name,
        value=session_token,
        max_age=cookie_transport.cookie_max_age,
        secure=cookie_transport.cookie_secure,
        httponly=cookie_transport.cookie_httponly,
        samesite=cookie_transport.cookie_samesite,
    )
    return response
