"""Subkey derivation from the master SECRET_KEY.

Single operator-visible secret (``SECRET_KEY``) is fed through HKDF-SHA256
with purpose-specific context labels to produce independent subkeys. This
prevents cross-purpose key reuse: a leak of the JWT signing key does not
compromise credential encryption, and rotation semantics stay clean.
"""

from functools import cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sleuthgraph.config import get_settings

_SUBKEY_LENGTH = 32  # 256 bits, matches SECRET_KEY min_length


def _derive(info: bytes) -> str:
    """Return a hex-encoded 32-byte subkey for the given purpose label."""
    master = get_settings().secret_key.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_SUBKEY_LENGTH,
        salt=None,
        info=info,
    )
    return hkdf.derive(master).hex()


@cache
def jwt_signing_key() -> str:
    """Subkey used to sign session JWTs."""
    return _derive(b"sleuthgraph/jwt/v1")


@cache
def password_reset_token_key() -> str:
    """Subkey used for password reset tokens (reset flow lands Phase 2.5)."""
    return _derive(b"sleuthgraph/pw-reset/v1")


@cache
def verification_token_key() -> str:
    """Subkey used for email verification tokens (flow lands Phase 2.5)."""
    return _derive(b"sleuthgraph/verify/v1")


@cache
def credential_encryption_key() -> bytes:
    """Subkey for BYOK credential encryption (used in Phase 7)."""
    # Return raw bytes — Fernet/AES-GCM consumers want bytes not hex.
    master = get_settings().secret_key.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_SUBKEY_LENGTH,
        salt=None,
        info=b"sleuthgraph/creds/v1",
    )
    return hkdf.derive(master)


@cache
def oidc_state_key() -> str:
    """Subkey used to sign OIDC state JWTs (PKCE verifier + nonce)."""
    return _derive(b"sleuthgraph/oidc-state/v1")


def _reset_caches() -> None:
    """Test helper: clear all @cache'd subkeys."""
    jwt_signing_key.cache_clear()
    password_reset_token_key.cache_clear()
    verification_token_key.cache_clear()
    credential_encryption_key.cache_clear()
    oidc_state_key.cache_clear()
