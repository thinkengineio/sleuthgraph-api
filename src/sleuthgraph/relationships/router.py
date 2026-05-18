"""HTTP router for /cases/{case_id}/relationships (cookie-authed, immutable)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.db import get_session
from sleuthgraph.relationships.repository import (
    EndpointNotInCaseError,
    RelationshipRepository,
)
from sleuthgraph.relationships.schemas import (
    RelationshipCreate,
    RelationshipRead,
)

router = APIRouter(
    prefix="/cases/{case_id}/relationships",
    tags=["relationships"],
)


async def _verify_case_ownership(
    case_id: uuid.UUID,
    user: User,
    session: AsyncSession,
) -> None:
    case_repo = CaseRepository(session)
    case = await case_repo.get(case_id, user.id)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")


@router.post("", response_model=RelationshipRead, status_code=status.HTTP_201_CREATED)
async def create_relationship(
    case_id: uuid.UUID,
    data: RelationshipCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> RelationshipRead:
    await _verify_case_ownership(case_id, user, session)
    repo = RelationshipRepository(session)
    try:
        rel = await repo.create(case_id, user.id, data)
    except EndpointNotInCaseError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    return RelationshipRead.model_validate(rel)


@router.get("", response_model=list[RelationshipRead])
async def list_relationships(
    case_id: uuid.UUID,
    rel_type: str | None = Query(default=None),
    src: uuid.UUID | None = Query(default=None),
    dst: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> list[RelationshipRead]:
    await _verify_case_ownership(case_id, user, session)
    repo = RelationshipRepository(session)
    items = await repo.list_for_case(
        case_id,
        rel_type=rel_type,
        src=src,
        dst=dst,
        limit=limit,
        offset=offset,
    )
    return [RelationshipRead.model_validate(r) for r in items]


@router.get("/{rel_id}", response_model=RelationshipRead)
async def get_relationship(
    case_id: uuid.UUID,
    rel_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> RelationshipRead:
    await _verify_case_ownership(case_id, user, session)
    repo = RelationshipRepository(session)
    rel = await repo.get(rel_id, case_id)
    if rel is None:
        raise HTTPException(status_code=404, detail="not found")
    return RelationshipRead.model_validate(rel)


@router.delete("/{rel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_relationship(
    case_id: uuid.UUID,
    rel_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    await _verify_case_ownership(case_id, user, session)
    repo = RelationshipRepository(session)
    ok = await repo.soft_delete(rel_id, case_id)
    if not ok:
        raise HTTPException(status_code=404, detail="not found")
