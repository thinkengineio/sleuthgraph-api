"""Tests for OIDC id_token signature + claims validation."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from sleuthgraph.auth.oidc_id_token import (
    IdTokenError,
    _reset_caches,
    validate_id_token,
)

ISSUER = "https://id.example.com"
CLIENT_ID = "sleuthgraph"
NONCE = "per-request-nonce-value"
KID = "test-key-1"


@pytest.fixture
def rsa_keypair():
    """Fresh RSA keypair for signing fake id_tokens."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # JWK representation of the public key for the fake JWKS endpoint.
    jwk = RSAAlgorithm.to_jwk(pub, as_dict=True)
    jwk["kid"] = KID
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return priv_pem, jwk


@pytest.fixture(autouse=True)
def _patch_discovery_and_jwks(rsa_keypair):
    """Patch the discovery + JWKS network fetches with in-memory responses."""
    _, jwk = rsa_keypair
    discovery = {
        "issuer": ISSUER,
        "jwks_uri": ISSUER.rstrip("/") + "/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    jwks = {"keys": [jwk]}

    class _FakeResponse:
        def __init__(self, data: dict[str, Any]):
            self._data = data

        def json(self) -> dict[str, Any]:
            return self._data

        def raise_for_status(self) -> None:
            return None

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, *a, **kw):
            if url.endswith("/.well-known/openid-configuration"):
                return _FakeResponse(discovery)
            if url.endswith("/.well-known/jwks.json"):
                return _FakeResponse(jwks)
            raise AssertionError(f"unexpected URL: {url}")

    # Patch both the httpx.Client used by _fetch_discovery and the
    # urllib-based request PyJWKClient uses internally.
    with patch("sleuthgraph.auth.oidc_id_token.httpx.Client", _FakeClient):
        # PyJWKClient uses urllib.request.urlopen. Patch it to serve jwks.
        import io as _io
        import json
        from urllib import request as _urlreq

        original_urlopen = _urlreq.urlopen

        def fake_urlopen(url, *a, **kw):  # noqa: ARG001
            target = url if isinstance(url, str) else url.full_url
            if target.endswith("/.well-known/jwks.json"):
                return _io.BytesIO(json.dumps(jwks).encode("utf-8"))
            return original_urlopen(url, *a, **kw)

        with patch("urllib.request.urlopen", fake_urlopen):
            _reset_caches()
            yield
            _reset_caches()


def _sign(priv_pem: bytes, payload: dict[str, Any]) -> str:
    return jwt.encode(payload, priv_pem, algorithm="RS256", headers={"kid": KID})


def _base_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "nonce": NONCE,
        "email": "alice@example.com",
        "email_verified": True,
    }
    claims.update(overrides)
    return claims


def test_valid_token_accepted(rsa_keypair):
    priv_pem, _ = rsa_keypair
    token = _sign(priv_pem, _base_claims())
    payload = validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
    assert payload["sub"] == "user-123"
    assert payload["email"] == "alice@example.com"
    assert payload["email_verified"] is True


def test_wrong_iss_rejected(rsa_keypair):
    priv_pem, _ = rsa_keypair
    token = _sign(priv_pem, _base_claims(iss="https://evil.example.com"))
    with pytest.raises(IdTokenError) as e:
        validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
    assert "issuer" in str(e.value).lower() or "iss" in str(e.value).lower()


def test_wrong_aud_rejected(rsa_keypair):
    priv_pem, _ = rsa_keypair
    token = _sign(priv_pem, _base_claims(aud="other-client"))
    with pytest.raises(IdTokenError) as e:
        validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
    assert "audience" in str(e.value).lower() or "aud" in str(e.value).lower()


def test_expired_rejected(rsa_keypair):
    priv_pem, _ = rsa_keypair
    now = int(time.time())
    token = _sign(priv_pem, _base_claims(iat=now - 3600, exp=now - 1800))
    with pytest.raises(IdTokenError) as e:
        validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
    assert str(e.value) == "expired"


def test_bad_signature_rejected(rsa_keypair):
    priv_pem, _ = rsa_keypair
    token = _sign(priv_pem, _base_claims())
    # Flip the final 6 chars of the signature segment.
    head, body, sig = token.split(".")
    tampered = f"{head}.{body}.{sig[:-6]}AAAAAA"
    with pytest.raises(IdTokenError):
        validate_id_token(tampered, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)


def test_missing_nonce_rejected(rsa_keypair):
    priv_pem, _ = rsa_keypair
    claims = _base_claims()
    claims.pop("nonce")
    token = _sign(priv_pem, claims)
    with pytest.raises(IdTokenError) as e:
        validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
    assert str(e.value) == "missing_nonce"


def test_wrong_nonce_rejected(rsa_keypair):
    priv_pem, _ = rsa_keypair
    token = _sign(priv_pem, _base_claims(nonce="something-else"))
    with pytest.raises(IdTokenError) as e:
        validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
    assert str(e.value) == "bad_nonce"


def test_alg_none_rejected(rsa_keypair):
    """Even if the IdP metadata is tampered to include 'none', we reject."""
    # Forge an unsigned token claiming alg=none.
    token = jwt.encode(_base_claims(), key="", algorithm="none")
    # jwt.encode with alg='none' produces a 3-segment token with empty sig.
    with pytest.raises(IdTokenError):
        validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)


def test_aud_as_list_accepted(rsa_keypair):
    """aud may be a list per RFC 7519; if client_id is in it, accept."""
    priv_pem, _ = rsa_keypair
    token = _sign(priv_pem, _base_claims(aud=[CLIENT_ID, "other-client"]))
    payload = validate_id_token(token, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
    assert payload["sub"] == "user-123"
