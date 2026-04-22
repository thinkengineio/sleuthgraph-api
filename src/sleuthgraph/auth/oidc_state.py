"""Signed state payload for OIDC PKCE round-trip.

Contents:
    - csrf: random per-request CSRF token (RFC 6749 §10.12).
    - oidc_nonce: random per-request value also sent as the IdP's OIDC
      ``nonce`` parameter; the callback asserts the id_token's ``nonce``
      claim equals this (OIDC Core 1.0 §3.1.2.1 / §15.5.2 replay protection).
    - code_verifier: PKCE S256 verifier, RFC 7636 (43-128 url-safe chars).
    - next_path: relative post-login path, sanitized to start with "/".
    - iat / exp: standard JWT timestamps, 5-min TTL.

We sign with an HKDF subkey so a leak of session-signing keys does not
compromise state, and vice-versa.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import jwt
from jwt import InvalidTokenError

from sleuthgraph.crypto import oidc_state_key

STATE_TTL_SECONDS = 300  # 5 minutes
ALG = "HS256"


class StateError(Exception):
    """Raised when state is missing, expired, or tampered."""


@dataclass(frozen=True)
class OidcState:
    csrf: str
    oidc_nonce: str
    code_verifier: str
    next_path: str


def _sanitize_next(next_path: str | None) -> str:
    if not next_path:
        return "/"
    parsed = urlparse(next_path)
    # Reject absolute URLs and scheme-relative URLs — only in-app paths allowed.
    if parsed.scheme or parsed.netloc:
        return "/"
    if not next_path.startswith("/"):
        return "/"
    return next_path


def encode_state(*, code_verifier: str, next_path: str | None, oidc_nonce: str) -> str:
    now = int(time.time())
    payload = {
        "csrf": secrets.token_urlsafe(24),
        "oidc_nonce": oidc_nonce,
        "cv": code_verifier,
        "n": _sanitize_next(next_path),
        "iat": now,
        "exp": now + STATE_TTL_SECONDS,
    }
    return jwt.encode(payload, oidc_state_key(), algorithm=ALG)


def decode_state(token: str) -> OidcState:
    try:
        payload = jwt.decode(token, oidc_state_key(), algorithms=[ALG])
    except InvalidTokenError as e:
        raise StateError("invalid_state") from e
    try:
        return OidcState(
            csrf=payload["csrf"],
            oidc_nonce=payload["oidc_nonce"],
            code_verifier=payload["cv"],
            next_path=payload["n"],
        )
    except KeyError as e:
        raise StateError("invalid_state") from e
