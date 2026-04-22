"""OIDC id_token signature + claims validation.

Per OpenID Connect Core 1.0 §3.1.3.7 the RP MUST validate the id_token:

    1. Signature via the IdP's JWKS (signing algorithm from metadata)
    2. iss == configured issuer
    3. aud contains the configured client_id
    4. exp is in the future, iat is not absurdly old
    5. nonce claim equals the value sent with the authorization request

Until C-1, Sleuthgraph trusted userinfo for (sub, email) without id_token
validation at all, so a stolen access_token from another client could
masquerade as the user. This module closes that gap.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

import httpx
import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
    PyJWKClient,
)

logger = logging.getLogger(__name__)


class IdTokenError(Exception):
    """Raised when id_token signature or claims fail validation."""


# Cache PyJWKClient per issuer (one JWKS fetch per issuer per process).
_jwks_lock = threading.Lock()
_jwks_clients: dict[str, PyJWKClient] = {}
# Cache discovery metadata (jwks_uri + id_token_signing_alg_values_supported).
_discovery_cache: dict[str, dict[str, Any]] = {}


def _fetch_discovery(issuer: str) -> dict[str, Any]:
    """Fetch and cache the OIDC discovery document for ``issuer``.

    Process-scoped cache. Rotations of the IdP's signing keys are handled
    by PyJWKClient's own JWKS cache (300 s lifespan); this cache only
    holds the jwks_uri itself, which is part of the IdP's stable config.
    """
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with httpx.Client(timeout=10.0) as http:
        r = http.get(url)
        r.raise_for_status()
        doc = r.json()
    _discovery_cache[issuer] = doc
    return doc


def _jwks_client_for(issuer: str) -> PyJWKClient:
    with _jwks_lock:
        client = _jwks_clients.get(issuer)
        if client is not None:
            return client
        doc = _fetch_discovery(issuer)
        jwks_uri = doc.get("jwks_uri")
        if not jwks_uri:
            raise IdTokenError("discovery_missing_jwks_uri")
        client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)
        _jwks_clients[issuer] = client
        return client


def _reset_caches() -> None:
    """Test helper: drop cached discovery + JWKS clients."""
    with _jwks_lock:
        _jwks_clients.clear()
        _discovery_cache.clear()


def _allowed_algs(issuer: str) -> list[str]:
    """Read id_token_signing_alg_values_supported from discovery; default RS256."""
    try:
        doc = _fetch_discovery(issuer)
    except Exception:
        return ["RS256"]
    algs = doc.get("id_token_signing_alg_values_supported") or ["RS256"]
    # Defense in depth: never accept 'none'.
    return [a for a in algs if a and a.lower() != "none"] or ["RS256"]


def validate_id_token(
    id_token: str,
    *,
    issuer: str,
    client_id: str,
    nonce: str,
    leeway_seconds: int = 60,
) -> dict[str, Any]:
    """Validate signature + claims. Return the decoded payload on success.

    Raises ``IdTokenError`` on any validation failure. Errors are deliberately
    coarse-grained — we do not echo the specific reason back to the user.
    """
    jwks_client = _jwks_client_for(issuer)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    except Exception as e:  # bad signature header, unknown kid, etc.
        logger.warning("oidc id_token: signing-key lookup failed: %s", e.__class__.__name__)
        raise IdTokenError("bad_signature") from e

    algorithms = _allowed_algs(issuer)

    try:
        payload: dict[str, Any] = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=algorithms,
            audience=client_id,
            issuer=issuer,
            leeway=leeway_seconds,
            options={
                "require": ["iss", "aud", "exp", "iat", "sub"],
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_iat": True,
            },
        )
    except ExpiredSignatureError as e:
        raise IdTokenError("expired") from e
    except InvalidIssuerError as e:
        raise IdTokenError("bad_issuer") from e
    except InvalidAudienceError as e:
        raise IdTokenError("bad_audience") from e
    except InvalidTokenError as e:
        raise IdTokenError("bad_signature") from e

    token_nonce = payload.get("nonce")
    if not token_nonce:
        raise IdTokenError("missing_nonce")
    if token_nonce != nonce:
        raise IdTokenError("bad_nonce")

    return payload
