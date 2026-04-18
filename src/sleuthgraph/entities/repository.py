"""EntityRepository: CRUD with case scoping, soft-delete, and AGE mirror.

SQL row is source of truth. Each create/update/delete also writes to AGE
in the same transaction so the graph view stays consistent.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.entities.age import delete_vertex, upsert_vertex
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.schemas import EntityCreate, EntityUpdate


class EntityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        case_id: uuid.UUID,
        created_by: uuid.UUID | None,
        data: EntityCreate,
    ) -> Entity:
        entity = Entity(
            case_id=case_id,
            type=data.type.value,
            label=data.label,
            attrs=data.attrs,
            confidence=data.confidence,
            created_by=created_by,
        )
        self.session.add(entity)
        await self.session.flush()  # populate id + row defaults
        try:
            await upsert_vertex(self.session, entity)
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise
        await self.session.refresh(entity)
        return entity

    async def get(
        self, entity_id: uuid.UUID, case_id: uuid.UUID,
    ) -> Entity | None:
        q = select(Entity).where(
            Entity.id == entity_id,
            Entity.case_id == case_id,
            Entity.deleted_at.is_(None),
        )
        return (await self.session.execute(q)).scalar_one_or_none()

    async def list_for_case(
        self,
        case_id: uuid.UUID,
        type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Entity]:
        q = select(Entity).where(
            Entity.case_id == case_id,
            Entity.deleted_at.is_(None),
        )
        if type:
            q = q.where(Entity.type == type)
        q = q.order_by(Entity.created_at.desc()).limit(limit).offset(offset)
        return list((await self.session.execute(q)).scalars())

    async def update(
        self,
        entity_id: uuid.UUID,
        case_id: uuid.UUID,
        data: EntityUpdate,
    ) -> Entity | None:
        entity = await self.get(entity_id, case_id)
        if entity is None:
            return None
        payload = data.model_dump(exclude_unset=True)
        for k, v in payload.items():
            setattr(entity, k, v)
        await self.session.flush()
        try:
            await upsert_vertex(self.session, entity)
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise
        await self.session.refresh(entity)
        return entity

    async def soft_delete(
        self, entity_id: uuid.UUID, case_id: uuid.UUID,
    ) -> bool:
        entity = await self.get(entity_id, case_id)
        if entity is None:
            return False
        entity.deleted_at = datetime.now(timezone.utc)
        await self.session.flush()
        try:
            await delete_vertex(self.session, entity.id)
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise
        return True
