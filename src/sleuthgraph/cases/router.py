"""HTTP router for /cases — CRUD behind cookie auth."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.cases.schemas import CaseCreate, CaseRead, CaseUpdate
from sleuthgraph.db import get_session

router = APIRouter(prefix="/cases", tags=["cases"])


def _repo(session: AsyncSession = Depends(get_session)) -> CaseRepository:
    return CaseRepository(session)


@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
async def create_case(
    data: CaseCreate,
    user: User = Depends(current_active_user),
    repo: CaseRepository = Depends(_repo),
) -> CaseRead:
    case = await repo.create(user.id, data)
    return CaseRead.model_validate(case)


@router.get("", response_model=list[CaseRead])
async def list_cases(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_active_user),
    repo: CaseRepository = Depends(_repo),
) -> list[CaseRead]:
    items = await repo.list_for_owner(
        user.id,
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    return [CaseRead.model_validate(c) for c in items]


@router.get("/{case_id}", response_model=CaseRead)
async def get_case(
    case_id: uuid.UUID,
    user: User = Depends(current_active_user),
    repo: CaseRepository = Depends(_repo),
) -> CaseRead:
    case = await repo.get(case_id, user.id)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")
    return CaseRead.model_validate(case)


@router.patch("/{case_id}", response_model=CaseRead)
async def update_case(
    case_id: uuid.UUID,
    data: CaseUpdate,
    user: User = Depends(current_active_user),
    repo: CaseRepository = Depends(_repo),
) -> CaseRead:
    case = await repo.update(case_id, user.id, data)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")
    return CaseRead.model_validate(case)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_id: uuid.UUID,
    user: User = Depends(current_active_user),
    repo: CaseRepository = Depends(_repo),
) -> None:
    ok = await repo.soft_delete(case_id, user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="not found")
