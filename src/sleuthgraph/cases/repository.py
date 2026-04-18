"""CaseRepository: CRUD with ownership isolation + soft-delete."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.cases.models import Case
from sleuthgraph.cases.schemas import CaseCreate, CaseUpdate


class CaseRepository:
    """All methods scope queries to a given owner.

    Returning None on missing OR wrong-owner is intentional — we don't want
    existence-probing via HTTP status codes.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, owner_id: uuid.UUID, data: CaseCreate) -> Case:
        case = Case(owner_id=owner_id, name=data.name, tags=data.tags)
        self.session.add(case)
        await self.session.commit()
        await self.session.refresh(case)
        return case

    async def get(
        self, case_id: uuid.UUID, owner_id: uuid.UUID,
    ) -> Case | None:
        q = select(Case).where(
            Case.id == case_id,
            Case.owner_id == owner_id,
            Case.deleted_at.is_(None),
        )
        return (await self.session.execute(q)).scalar_one_or_none()

    async def list_for_owner(
        self,
        owner_id: uuid.UUID,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Case]:
        q = select(Case).where(
            Case.owner_id == owner_id,
            Case.deleted_at.is_(None),
        )
        if status:
            q = q.where(Case.status == status)
        q = q.order_by(Case.created_at.desc()).limit(limit).offset(offset)
        return list((await self.session.execute(q)).scalars())

    async def update(
        self,
        case_id: uuid.UUID,
        owner_id: uuid.UUID,
        data: CaseUpdate,
    ) -> Case | None:
        case = await self.get(case_id, owner_id)
        if case is None:
            return None
        payload = data.model_dump(exclude_unset=True)
        for k, v in payload.items():
            setattr(case, k, v)
        await self.session.commit()
        await self.session.refresh(case)
        return case

    async def soft_delete(
        self, case_id: uuid.UUID, owner_id: uuid.UUID,
    ) -> bool:
        case = await self.get(case_id, owner_id)
        if case is None:
            return False
        case.deleted_at = datetime.now(timezone.utc)
        await self.session.commit()
        return True
