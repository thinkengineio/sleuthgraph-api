"""Repository functions for BYOK credential storage.

Credentials are encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256).
The key is derived from the master SECRET_KEY via HKDF with purpose label
``sleuthgraph/creds/v1`` (see crypto.py).
"""

from __future__ import annotations

import base64
import uuid

from cryptography.fernet import Fernet
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.credentials.models import Credential
from sleuthgraph.credentials.schemas import CredentialRead
from sleuthgraph.crypto import credential_encryption_key


def _fernet() -> Fernet:
    """Build a Fernet instance from the HKDF-derived 32-byte key.

    Not cached: credential_encryption_key() is already @cache'd, and we
    want ``_reset_caches()`` in tests to take effect immediately.
    """
    key = base64.urlsafe_b64encode(credential_encryption_key())
    return Fernet(key)


async def store_credential(
    session: AsyncSession,
    user_id: uuid.UUID,
    plugin_name: str,
    api_key: str,
) -> Credential:
    """Encrypt and upsert a credential for (user_id, plugin_name)."""
    ciphertext = _fernet().encrypt(api_key.encode("utf-8")).decode("ascii")

    # Check for existing row to implement upsert
    stmt = select(Credential).where(
        Credential.user_id == user_id,
        Credential.plugin_name == plugin_name,
    )
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing is not None:
        existing.encrypted_key = ciphertext
        await session.flush()
        await session.refresh(existing)
        return existing

    cred = Credential(
        user_id=user_id,
        plugin_name=plugin_name,
        encrypted_key=ciphertext,
    )
    session.add(cred)
    await session.flush()
    await session.refresh(cred)
    return cred


async def get_credential(
    session: AsyncSession,
    user_id: uuid.UUID,
    plugin_name: str,
) -> str | None:
    """Decrypt and return the raw API key, or None if not stored."""
    stmt = select(Credential).where(
        Credential.user_id == user_id,
        Credential.plugin_name == plugin_name,
    )
    result = await session.execute(stmt)
    cred = result.scalar_one_or_none()
    if cred is None:
        return None
    return _fernet().decrypt(cred.encrypted_key.encode("ascii")).decode("utf-8")


async def list_credentials(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> list[CredentialRead]:
    """List stored plugin names + timestamps. Never returns keys."""
    stmt = (
        select(Credential)
        .where(Credential.user_id == user_id)
        .order_by(Credential.created_at.desc())
    )
    result = await session.execute(stmt)
    return [CredentialRead.model_validate(c) for c in result.scalars().all()]


async def delete_credential(
    session: AsyncSession,
    user_id: uuid.UUID,
    plugin_name: str,
) -> bool:
    """Delete a credential. Returns True if a row was deleted."""
    stmt = delete(Credential).where(
        Credential.user_id == user_id,
        Credential.plugin_name == plugin_name,
    )
    result = await session.execute(stmt)
    return result.rowcount > 0
