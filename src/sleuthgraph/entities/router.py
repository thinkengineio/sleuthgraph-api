"""HTTP router for /cases/{case_id}/entities CRUD (cookie-authed)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.db import get_session
from sleuthgraph.entities.repository import EntityRepository
from sleuthgraph.entities.schemas import EntityCreate, EntityRead, EntityUpdate

router = APIRouter(prefix="/cases/{case_id}/entities", tags=["entities"])


async def _verify_case_ownership(
    case_id: uuid.UUID,
    user: User,
    session: AsyncSession,
) -> None:
    """Raise 404 if the case doesn't exist or isn't owned by the user."""
    case_repo = CaseRepository(session)
    case = await case_repo.get(case_id, user.id)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")


def _entity_repo(session: AsyncSession = Depends(get_session)) -> EntityRepository:
    return EntityRepository(session)


@router.post("", response_model=EntityRead, status_code=status.HTTP_201_CREATED)
async def create_entity(
    case_id: uuid.UUID,
    data: EntityCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> EntityRead:
    await _verify_case_ownership(case_id, user, session)
    repo = EntityRepository(session)
    entity = await repo.create(case_id, user.id, data)
    return EntityRead.model_validate(entity)


@router.get("", response_model=list[EntityRead])
async def list_entities(
    case_id: uuid.UUID,
    type_filter: str | None = Query(default=None, alias="type"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> list[EntityRead]:
    await _verify_case_ownership(case_id, user, session)
    repo = EntityRepository(session)
    items = await repo.list_for_case(
        case_id,
        entity_type=type_filter,
        limit=limit,
        offset=offset,
    )
    return [EntityRead.model_validate(e) for e in items]


@router.get("/{entity_id}", response_model=EntityRead)
async def get_entity(
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> EntityRead:
    await _verify_case_ownership(case_id, user, session)
    repo = EntityRepository(session)
    entity = await repo.get(entity_id, case_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="not found")
    return EntityRead.model_validate(entity)


@router.patch("/{entity_id}", response_model=EntityRead)
async def update_entity(
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    data: EntityUpdate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> EntityRead:
    await _verify_case_ownership(case_id, user, session)
    repo = EntityRepository(session)
    entity = await repo.update(entity_id, case_id, data)
    if entity is None:
        raise HTTPException(status_code=404, detail="not found")
    return EntityRead.model_validate(entity)


@router.delete("/{entity_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_entity(
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    await _verify_case_ownership(case_id, user, session)
    repo = EntityRepository(session)
    ok = await repo.soft_delete(entity_id, case_id)
    if not ok:
        raise HTTPException(status_code=404, detail="not found")
