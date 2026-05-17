"""HTTP router for /credentials — BYOK API key management."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.credentials.repository import (
    delete_credential,
    list_credentials,
    store_credential,
)
from sleuthgraph.credentials.schemas import CredentialCreate, CredentialRead
from sleuthgraph.db import get_session

router = APIRouter(prefix="/credentials", tags=["credentials"])


@router.post(
    "/{plugin_name}",
    response_model=CredentialRead,
    status_code=status.HTTP_201_CREATED,
)
async def store_key(
    plugin_name: str,
    body: CredentialCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> CredentialRead:
    """Store (or replace) an API key for the given plugin."""
    cred = await store_credential(session, user.id, plugin_name, body.api_key)
    return CredentialRead.model_validate(cred)


@router.get("", response_model=list[CredentialRead])
async def list_keys(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> list[CredentialRead]:
    """List stored plugin names and creation timestamps. Never exposes keys."""
    return await list_credentials(session, user.id)


@router.delete("/{plugin_name}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_key(
    plugin_name: str,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Remove a stored API key."""
    deleted = await delete_credential(session, user.id, plugin_name)
    if not deleted:
        raise HTTPException(status_code=404, detail="credential not found")
